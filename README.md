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

### Linux (Kali)

```bash
cd ~/Maxwell && git pull
. "$HOME/.cargo/env"
sudo apt install -y libwebkit2gtk-4.1-dev librsvg2-dev patchelf \
  libssl-dev libayatana-appindicator3-dev
cd desktop
npm install
npx tauri dev
```

Tabs:
- **Proxy** — start listener, history, inspect, replay
- **Binary** — path → functions + disassembly
- **Operator** — session / listener / seats
- **Findings** — queue + approve/reject (human-in-the-loop)

### CLI only

```bash
cargo run -p maxwell -- proxy --listen 127.0.0.1:8888
```

## HTTPS MITM

Trust CA at `~/.local/share/Maxwell/ca/ca.pem` (Linux) or the path shown in the UI. Authorized targets only.
