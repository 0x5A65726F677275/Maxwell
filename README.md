# Maxwell

Local-first, collaboration-first security platform (US-market MVP).

**Author:** artofvector

## Workspace

| Crate / app | Role |
|---|---|
| `max-core` | Shared data contracts and protocols |
| `max-orchestrator` | Session management + real-time event broadcast |
| `max-proxy` | HTTP/HTTPS intercepting proxy + anomaly heuristics |
| `maxwell` | CLI entrypoint (`maxwell proxy`) |
| `desktop/` | Tauri v2 + React GUI (`max-tauri`) |

## CLI

```bash
cargo test
cargo run -p maxwell -- proxy --listen 127.0.0.1:8888
```

## GUI (Tauri)

### Linux (Kali / Debian)

```bash
sudo apt install -y libwebkit2gtk-4.1-dev librsvg2-dev patchelf \
  libssl-dev libayatana-appindicator3-dev
cd ~/Maxwell   # or your clone path
git pull
. "$HOME/.cargo/env"
cd desktop
npm install
npm run tauri dev
```

In the window: **Start proxy** → point browser/curl at `127.0.0.1:8888` → events appear in the feed.

### Windows

Requires MSVC Build Tools + WebView2 (usually preinstalled). If Smart App Control blocks Rust build scripts, turn it Off, then:

```powershell
cd desktop
npm install
npm run tauri dev
```

## HTTPS MITM

Trust the CA printed/shown in the UI (Linux default: `~/.local/share/Maxwell/ca/ca.pem`). Only against authorized targets.

## MVP roadmap

1. `max-core` ✅
2. `max-orchestrator` ✅
3. `max-proxy` (+ HTTPS MITM) ✅
4. `maxwell` CLI ✅
5. `max-tauri` desktop UI ✅
