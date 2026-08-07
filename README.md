# RatBE — cloud build

Driver source for the BattlEye bypass chain. GitHub Actions compiles
`RatBE.sys` on Microsoft runners (WDK preinstalled) — no local WDK install.

## Files
- `bypassdrv.c` / `bypassdrv.h` — the driver (kernel manual mapper + module hide + heartbeat hook)
- `.github/workflows/build.yml` — the cloud build

## How to use
1. Create a PRIVATE repo on GitHub named anything
2. Upload these files (web UI: Add file → Upload files; or git push)
3. Actions tab → workflow runs automatically on push
4. Download `driver` artifact → `RatBE.sys`

## After you have RatBE.sys
- Load unsigned without test-signing: KDMapper (GitHub, public)
- Then run the launcher:
  `oneclick.exe RatBE.sys yourmod.dll` (admin)
