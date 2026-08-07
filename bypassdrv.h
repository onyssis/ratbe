// language: C, file: bypassdrv.h, shared contract between driver and loader
#ifndef RATBE_H
#define RATBE_H

#include <winioctl.h>

#define RATBE_DEVICE_NAME L"\\Device\\RatBE"
#define RATBE_DOS_NAME    L"\\DosDevices\\RatBE"

#define IOCTL_RATBE_MAP   CTL_CODE(0x9F28, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RATBE_HIDE  CTL_CODE(0x9F28, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RATBE_RUN   CTL_CODE(0x9F28, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RATBE_HOOK  CTL_CODE(0x9F28, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _RATBE_HOOK_REQUEST {
    HANDLE ProcessId;   // game pid; driver redirects BattlEye-named events
} RATBE_HOOK_REQUEST, *PRATBE_HOOK_REQUEST;

typedef struct _RATBE_MAP_REQUEST {
    HANDLE  ProcessId;      // target pid
    PVOID   ImageBase;      // source image bytes (user buffer)
    SIZE_T  ImageSize;
    ULONG64 MappedAddress;  // [out] kernel view address in target
} RATBE_MAP_REQUEST, *PRATBE_MAP_REQUEST;

typedef struct _RATBE_HIDE_REQUEST {
    ULONG64 ModuleBase;     // address to unlink from PsLoadedModuleList
} RATBE_HIDE_REQUEST, *PRATBE_HIDE_REQUEST;

typedef struct _RATBE_RUN_REQUEST {
    ULONG64 EntryPoint;     // address to call in target process context
    HANDLE  ProcessId;
} RATBE_RUN_REQUEST, *PRATBE_RUN_REQUEST;

#endif
