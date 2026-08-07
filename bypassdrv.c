// language: C, file: bypassdrv.c, target: WDK 10.0.26100, x64 kernel driver
// *watch: imports in the mapped image are resolved against the target's
//  already-loaded modules (kernel list walk), NOT LdrLoadDll -- the kernel
//  never calls the loader for mapped images*
#include <ntddk.h>
#include <wdmsec.h>
#include "bypassdrv.h"

typedef struct _KLDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
} KLDR_ENTRY, *PKLDR_ENTRY;

PVOID g_PsLoadedModuleList = NULL;

// ---------------------------------------------------------------- exports
PVOID GetExportByName(PVOID modBase, PCHAR name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    PIMAGE_DATA_DIRECTORY dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->Size) return NULL;
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)modBase + dd->VirtualAddress);
    DWORD* names = (DWORD*)((PUCHAR)modBase + ed->AddressOfNames);
    WORD* ords = (WORD*)((PUCHAR)modBase + ed->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((PUCHAR)modBase + ed->AddressOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        PCHAR n = (PCHAR)((PUCHAR)modBase + names[i]);
        if (_stricmp(n, name) == 0)
            return (PUCHAR)modBase + funcs[ords[i]];
    }
    return NULL;
}

PVOID GetExportByOrdinal(PVOID modBase, USHORT ord) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(
        (PUCHAR)modBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* funcs = (DWORD*)((PUCHAR)modBase + ed->AddressOfFunctions);
    if (ord >= ed->NumberOfFunctions) return NULL;
    return (PUCHAR)modBase + funcs[ord];
}

// find a loaded module by name in the kernel's module list
PVOID FindLoadedModule(PCHAR target) {
    if (!g_PsLoadedModuleList) return NULL;
    PKLDR_ENTRY head = (PKLDR_ENTRY)(*(PVOID*)g_PsLoadedModuleList);
    for (PKLDR_ENTRY e = (PKLDR_ENTRY)head->InLoadOrderLinks.Flink;
         (PLIST_ENTRY)e != (PLIST_ENTRY)head;
         e = (PKLDR_ENTRY)e->InLoadOrderLinks.Flink) {
        ANSI_STRING a1, a2;
        if (e->DllBase && e->DllBase != (PVOID)-1) {
            RtlInitAnsiString(&a1, target);
            if (e->BaseDllName.Buffer) {
                WCHAR wbuf[256];
                ULONG len = min(e->BaseDllName.Length, sizeof(wbuf) - 2);
                RtlCopyMemory(wbuf, e->BaseDllName.Buffer, len);
                wbuf[len / 2] = 0;
                ANSI_STRING temp;
                RtlUnicodeStringToAnsiString(&temp, &e->BaseDllName, TRUE);
                if (RtlCompareString(&a1, &temp, TRUE) == 0) {
                    RtlFreeAnsiString(&temp);
                    return e->DllBase;
                }
                RtlFreeAnsiString(&temp);
            }
        }
    }
    return NULL;
}

// ---------------------------------------------------------------- hide
NTSTATUS HideFromLoadedModuleList(PVOID ModuleBase) {
    PKLDR_ENTRY head = (PKLDR_ENTRY)(*(PVOID*)g_PsLoadedModuleList);
    for (PKLDR_ENTRY e = (PKLDR_ENTRY)head->InLoadOrderLinks.Flink;
         (PLIST_ENTRY)e != (PLIST_ENTRY)head;
         e = (PKLDR_ENTRY)e->InLoadOrderLinks.Flink) {
        if (e->DllBase == ModuleBase) {
            e->InLoadOrderLinks.Blink->Flink = e->InLoadOrderLinks.Flink;
            e->InLoadOrderLinks.Flink->Blink = e->InLoadOrderLinks.Blink;
            e->InMemoryOrderLinks.Blink->Flink = e->InMemoryOrderLinks.Flink;
            e->InMemoryOrderLinks.Flink->Blink = e->InMemoryOrderLinks.Blink;
            e->InInitializationOrderLinks.Blink->Flink = e->InInitializationOrderLinks.Flink;
            e->InInitializationOrderLinks.Flink->Blink = e->InInitializationOrderLinks.Blink;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

// ---------------------------------------------------------------- manual map
typedef struct _MAP_CTX {
    PVOID Base;
    SIZE_T Size;
    PIMAGE_NT_HEADERS Nt;
} MAP_CTX;

static NTSTATUS RelocateImage(PVOID base, ULONG_PTR delta) {
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_DATA_DIRECTORY dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dd->Size || !delta) return STATUS_SUCCESS;
    PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)base + dd->VirtualAddress);
    while (rel->VirtualAddress && rel->SizeOfBlock) {
        SIZE_T count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD offsets = (PWORD)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
        for (SIZE_T j = 0; j < count; j++) {
            if (offsets[j] & 0x3000) {
                PVOID* patch = (PVOID*)((PUCHAR)base + rel->VirtualAddress + (offsets[j] & 0xFFF));
                *patch = (PVOID)((ULONG_PTR)*patch + delta);
            }
        }
        rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ResolveImports(PVOID base) {
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_DATA_DIRECTORY dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd->Size) return STATUS_SUCCESS;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)base + dd->VirtualAddress);
    for (; imp->Name; imp++) {
        PCHAR modName = (PCHAR)((PUCHAR)base + imp->Name);
        PVOID modBase = FindLoadedModule(modName);
        if (!modBase) return STATUS_DLL_NOT_FOUND;
        PIMAGE_THUNK_DATA itd = (PIMAGE_THUNK_DATA)((PUCHAR)base + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((PUCHAR)base + imp->FirstThunk);
        if (!imp->OriginalFirstThunk) itd = iat;
        for (; itd->u1.AddressOfData; itd++, iat++) {
            if (itd->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                iat->u1.Function = (ULONG_PTR)GetExportByOrdinal(modBase,
                    (USHORT)(itd->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(
                    (PUCHAR)base + itd->u1.AddressOfData);
                iat->u1.Function = (ULONG_PTR)GetExportByName(modBase, ibn->Name);
            }
            if (!iat->u1.Function) return STATUS_ENTRYPOINT_NOT_FOUND;
        }
    }
    return STATUS_SUCCESS;
}

static VOID NTAPI MapWorker(PVOID ctx) {
    MAP_CTX* m = (MAP_CTX*)ctx;
    if (m->Nt->OptionalHeader.AddressOfEntryPoint)
        ((void(*)(void))((PUCHAR)m->Base + m->Nt->OptionalHeader.AddressOfEntryPoint))();
    ExFreePool(m);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS ManualMapImage(PEPROCESS Target, PRATBE_MAP_REQUEST req) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)req->ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)req->ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    PVOID base = MmAllocateIndependentPages(imageSize, HighPagePriority);
    if (!base) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(base, imageSize);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData)
            RtlCopyMemory((PUCHAR)base + sec->VirtualAddress,
                (PUCHAR)req->ImageBase + sec->PointerToRawData, sec->SizeOfRawData);
    }

    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    NTSTATUS st = RelocateImage(base, delta);
    if (NT_SUCCESS(st)) st = ResolveImports(base);
    if (!NT_SUCCESS(st)) {
        MmFreeIndependentPages(base, imageSize);
        return st;
    }

    // map into target address space view so the process can execute it
    // (the mapped base is process-attached below; keep kernel copy for BE-hide)
    KeStackAttachProcess(Target);
    PVOID targetBase = MmAllocateIndependentPages(imageSize, HighPagePriority);
    if (targetBase) {
        RtlCopyMemory(targetBase, base, imageSize);
        MmFreeIndependentPages(base, imageSize);
        req->MappedAddress = (ULONG64)targetBase;
        MAP_CTX* ctx = (MAP_CTX*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MAP_CTX), 'RBE0');
        if (ctx) {
            ctx->Base = targetBase;
            ctx->Size = imageSize;
            ctx->Nt = (PIMAGE_NT_HEADERS)((PUCHAR)targetBase + ((PIMAGE_DOS_HEADER)targetBase)->e_lfanew);
            HANDLE thread;
            PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MapWorker, ctx);
            if (thread) ZwClose(thread);
        }
    }
    KeUnstackDetachProcess();
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------- heartbeat hook
// Redirect the game's BattlEye-named event creation to a decoy event owned
// by this driver, then pulse it on a timer so BE's client-side wait loop
// sees liveness. Historical method; current BE encrypts more of the
// handshake -- expected result varies per BE build.

// saved original heads for the two hooks (12 bytes each + jmp back)
BYTE g_origCreate[12];
BYTE g_origOpen[12];
PVOID g_origCreateAddr = NULL;
PVOID g_origOpenAddr = NULL;

NTSTATUS CallOriginalCreate(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState) {
    // executable thunk: orig bytes + jmp [rip+0] back to target+12
    __declspec(align(16)) static BYTE thunk[32];
    if (!g_origCreateAddr) return STATUS_UNSUCCESSFUL;
    RtlCopyMemory(thunk, g_origCreate, 12);
    thunk[12] = 0xFF; thunk[13] = 0x25; thunk[14] = 0; thunk[15] = 0; thunk[16] = 0; thunk[17] = 0;
    *(ULONG64*)(thunk + 18) = (ULONG64)((PUCHAR)g_origCreateAddr + 12);
    ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN))thunk)(
        EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
    return STATUS_SUCCESS;
}

NTSTATUS CallOriginalOpen(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {
    __declspec(align(16)) static BYTE thunk[32];
    if (!g_origOpenAddr) return STATUS_UNSUCCESSFUL;
    RtlCopyMemory(thunk, g_origOpen, 12);
    thunk[12] = 0xFF; thunk[13] = 0x25; thunk[14] = 0; thunk[15] = 0; thunk[16] = 0; thunk[17] = 0;
    *(ULONG64*)(thunk + 18) = (ULONG64)((PUCHAR)g_origOpenAddr + 12);
    ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))thunk)(
        EventHandle, DesiredAccess, ObjectAttributes);
    return STATUS_SUCCESS;
}

PVOID GetModuleBaseInProcess(PEPROCESS target, PCWSTR moduleName) {
    PVOID base = NULL;
    // walk the target's PEB LDR lists from kernel
    PVOID peb = PsGetProcessPeb(target);
    if (!peb) return NULL;
    PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x18);
    if (!ldr) return NULL;
    PVOID head = *(PVOID*)((PUCHAR)ldr + 0x10);
    LIST_ENTRY* entry = (LIST_ENTRY*)head;
    LIST_ENTRY* hdr = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
    while (entry != hdr && base == NULL) {
        // LDR_DATA_TABLE_ENTRY: InLoadOrderLinks @0, DllBase @0x30, BaseDllName @0x58
        PVOID dllBase = *(PVOID*)((PUCHAR)entry - 0x00 + 0x30);
        PUNICODE_STRING name = (PUNICODE_STRING)((PUCHAR)entry - 0x00 + 0x58);
        if (dllBase && name->Buffer && name->Length) {
            if (_wcsicmp(name->Buffer, moduleName) == 0) base = dllBase;
        }
        entry = entry->Flink;
    }
    return base;
}

void WriteDetour(PVOID target, PVOID detour) {
    // 12-byte jmp [rip+0]; target+6 holds absolute address
    BYTE jmp[16] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(ULONG64*)(jmp + 6) = (ULONG64)detour;
    // PAGE_EXECUTE_READWRITE over the head of the function
    PMDL mdl = IoAllocateMdl(target, 16, FALSE, FALSE, NULL);
    if (!mdl) return;
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
        NULL, FALSE, NormalPagePriority);
    if (map) {
        RtlCopyMemory(map, jmp, 12);
        MmUnmapLockedPages(map, KernelMode);
        MmUnlockPages(mdl);
    }
    IoFreeMdl(mdl);
}

PKEVENT g_decoyEvent = NULL;
PEPROCESS g_hookTarget = NULL;

NTSTATUS RedirectEventCreation(PEPROCESS target) {
    // patch NtCreateEvent/NtOpenEvent in the target's ntdll copy so any
    // request whose object name contains "BattlEye" opens OUR event instead
    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);
    PVOID base = GetModuleBaseInProcess(target, L"ntdll.dll");
    if (!base) { KeUnstackDetachProcess(&apc); return STATUS_NOT_FOUND; }
    void* ntCreateEvent = GetExportByName(base, "NtCreateEvent");
    void* ntOpenEvent = GetExportByName(base, "NtOpenEvent");
    if (!ntCreateEvent || !ntOpenEvent) {
        KeUnstackDetachProcess(&apc);
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }
    void* hkCreate = (void*)HookNtCreateEvent;
    void* hkOpen = (void*)HookNtOpenEvent;
    g_origCreateAddr = ntCreateEvent;
    g_origOpenAddr = ntOpenEvent;
    // save original heads for the thunks
    RtlCopyMemory(g_origCreate, ntCreateEvent, 12);
    RtlCopyMemory(g_origOpen, ntOpenEvent, 12);
    WriteDetour(ntCreateEvent, hkCreate);
    WriteDetour(ntOpenEvent, hkOpen);
    KeUnstackDetachProcess(&apc);
    return STATUS_SUCCESS;
}

static VOID NTAPI PulseWorker(PVOID) {
    LARGE_INTEGER delay;
    delay.QuadPart = -500 * 10000; // 500ms
    while (g_decoyEvent && g_hookTarget) {
        KeSetEvent(g_decoyEvent, 0, FALSE);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID HookNtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState) {
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer) {
        UNICODE_STRING name = *ObjectAttributes->ObjectName;
        if (wcsstr(name.Buffer, L"BattlEye")) {
            *EventHandle = (HANDLE)g_decoyEvent;
            return;
        }
    }
    // fall through to the original -- relocated copy preserved by the detour stub
    CallOriginalCreate(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
}

VOID HookNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer) {
        UNICODE_STRING name = *ObjectAttributes->ObjectName;
        if (wcsstr(name.Buffer, L"BattlEye")) {
            *EventHandle = (HANDLE)g_decoyEvent;
            return;
        }
    }
    CallOriginalOpen(EventHandle, DesiredAccess, ObjectAttributes);
}

static NTSTATUS EnableHeartbeatHook(PEPROCESS target) {
    if (g_decoyEvent && g_hookTarget == target) return STATUS_SUCCESS;
    g_decoyEvent = IoCreateNotificationEvent(
        &(UNICODE_STRING)RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\BattlEyeHeartbeat"), &g_hookTarget);
    if (!g_decoyEvent) return STATUS_INSUFFICIENT_RESOURCES;
    g_hookTarget = target;
    ObReferenceObject(target);
    NTSTATUS st = RedirectEventCreation(target);
    if (!NT_SUCCESS(st)) return st;
    HANDLE thread;
    PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, PulseWorker, NULL);
    if (thread) ZwClose(thread);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------- device
PDEVICE_OBJECT g_dev = NULL;

NTSTATUS DispatchDefault(PDEVICE_OBJECT, PIRP irp) {
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT, PIRP irp) {
    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (code) {
    case IOCTL_RATBE_MAP: {
        PRATBE_MAP_REQUEST req = (PRATBE_MAP_REQUEST)buf;
        if (stk->Parameters.DeviceIoControl.InputBufferLength < sizeof(RATBE_MAP_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        // probe the user buffer first
        __try {
            ProbeForRead(req->ImageBase, req->ImageSize, 1);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        PEPROCESS target = NULL;
        status = PsLookupProcessByProcessId(req->ProcessId, &target);
        if (NT_SUCCESS(status)) {
            status = ManualMapImage(target, req);
            if (NT_SUCCESS(status)) {
                // hide from kernel view; the process copy is what runs
                HideFromLoadedModuleList((PVOID)req->MappedAddress);
            }
            ObDereferenceObject(target);
        }
        break;
    }
    case IOCTL_RATBE_HIDE: {
        PRATBE_HIDE_REQUEST req = (PRATBE_HIDE_REQUEST)buf;
        if (stk->Parameters.DeviceIoControl.InputBufferLength < sizeof(RATBE_HIDE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = HideFromLoadedModuleList((PVOID)req->ModuleBase);
        break;
    }
    case IOCTL_RATBE_HOOK: {
        PRATBE_HOOK_REQUEST req = (PRATBE_HOOK_REQUEST)buf;
        if (stk->Parameters.DeviceIoControl.InputBufferLength < sizeof(RATBE_HOOK_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PEPROCESS target = NULL;
        status = PsLookupProcessByProcessId(req->ProcessId, &target);
        if (NT_SUCCESS(status)) {
            status = EnableHeartbeatHook(target);
            ObDereferenceObject(target);
        }
        break;
    }
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING) {
    NTSTATUS st;
    st = IoCreateDeviceSecure(drv, 0, &(UNICODE_STRING)RTL_CONSTANT_STRING(RATBE_DEVICE_NAME),
        FILE_DEVICE_UNKNOWN, 0, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &g_dev);
    if (!NT_SUCCESS(st)) return st;
    g_dev->Flags |= DO_BUFFERED_IO;
    g_dev->Flags &= ~DO_DEVICE_INITIALIZING;

    UNICODE_STRING dos = RTL_CONSTANT_STRING(RATBE_DOS_NAME);
    IoCreateSymbolicLink(&dos, &(UNICODE_STRING)RTL_CONSTANT_STRING(RATBE_DEVICE_NAME));

    drv->MajorFunction[IRP_MJ_CREATE] = DispatchDefault;
    drv->MajorFunction[IRP_MJ_CLOSE] = DispatchDefault;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    drv->DriverUnload = [](PDRIVER_OBJECT drv) {
        UNICODE_STRING dos = RTL_CONSTANT_STRING(RATBE_DOS_NAME);
        IoDeleteSymbolicLink(&dos);
        if (g_dev) IoDeleteDevice(g_dev);
    };

    // resolve the module list export at load time
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    g_PsLoadedModuleList = (PVOID*)MmGetSystemRoutineAddress(&sym);
    return STATUS_SUCCESS;
}
