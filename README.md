# Maxwell

Local-first security **workbench** (proxy + binary analysis + operator console).

**Author:** artofvector

## What's included

| Piece | Role |
|---|---|
| `max-core` | Shared contracts |
| `max-orchestrator` | Sessions + live event bus |
| `max-proxy` | HTTP(S) listener, MITM, replay |
| `max-binwalk` | PE/ELF/Mach-O parse + x86 disasm |
| `maxwell` | CLI (`maxwell proxy`) |
| `desktop/` | Tauri GUI — Proxy / Binary / Operator / Findings |

**Not included (by design):** Cobalt Strike–style C2 beacons, implants, or auto-exploitation. The Operator tab is a team engagement console with analyst-gated findings only.

## GUI (recommended)

Native desktop app (Tauri). Dev mode uses Vite only for hot reload; release builds produce real installers/executables.

Tabs:
- **Proxy** — start listener, history, inspect, replay
- **Binary** — path → functions + disassembly
- **Operator** — session / listener / seats
- **Findings** — queue + approve/reject (human-in-the-loop)

### Dev

**Windows**
```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
cd desktop
npm install
npm run desktop:dev
```

**Linux (Kali/Ubuntu)**
```bash
. "$HOME/.cargo/env"
sudo apt install -y libwebkit2gtk-4.1-dev librsvg2-dev patchelf \
  libssl-dev libayatana-appindicator3-dev
cd desktop
npm install
npm run desktop:dev
```

### Installable builds (`.exe` / `.deb` / AppImage)

Build **on each OS** (Tauri cannot cross-compile the GUI WebView stack).

**Windows → NSIS setup + MSI**
```powershell
cd desktop
npm install
npm run desktop:build:windows
```
Outputs:
- `desktop/src-tauri/target/release/bundle/nsis/*-setup.exe`
- `desktop/src-tauri/target/release/bundle/msi/*.msi`
- bare exe: `desktop/src-tauri/target/release/max-tauri.exe`

**Linux → `.deb` + AppImage**
```bash
cd desktop
npm install
npm run desktop:build:linux
```
Outputs:
- `desktop/src-tauri/target/release/bundle/deb/*.deb`
- `desktop/src-tauri/target/release/bundle/appimage/*.AppImage`

CI: push a `v*` tag or run **Desktop release** (`workflow_dispatch`) to build Windows + Linux artifacts.

### CLI only

```bash
cargo run -p maxwell -- proxy --listen 127.0.0.1:8888
```

## HTTPS MITM

Trust CA at `~/.local/share/Maxwell/ca/ca.pem` (Linux) or the path shown in the UI. Authorized targets only.
