# RatBE — cloud build

Driver source for the chain. GitHub Actions compiles
`RatBE.sys` on Microsoft runners (WDK preinstalled) — no local WDK install.

## Files
- `bypassdrv.c` / `bypassdrv.h` — the driver (kernel manual mapper + module hide + heartbeat hook)
- `.github/workflows/build.yml` — the cloud build


## After you have RatBE.sys
- Load unsigned without test-signing: KDMapper (GitHub, public)
- Then run the launcher:
  `oneclick.exe RatBE.sys yourmod.dll` (admin)
