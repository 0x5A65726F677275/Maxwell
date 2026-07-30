# Maxwell

Local-first, collaboration-first security platform (US-market MVP).

**Author:** artofvector

## Workspace

| Crate | Role |
|---|---|
| `max-core` | Shared data contracts and protocols |
| `max-orchestrator` | Session management + real-time event broadcast |
| `max-proxy` | HTTP/HTTPS intercepting proxy + anomaly heuristics |
| `maxwell` | CLI entrypoint (`maxwell proxy`) |

## Build

Requires:
- Rust (`rustup`)
- Visual Studio Build Tools with MSVC + Windows SDK
- A shell where Windows Application Control allows local `target\debug\build\*` build scripts

From **x64 Native Tools Command Prompt** (or after `VsDevCmd.bat -arch=x64`):

```bash
cargo test
cargo run -p maxwell -- proxy --listen 127.0.0.1:8888
```

Point an HTTP client at that proxy. For **HTTPS MITM**, manually trust the generated CA:

- Default path: `%LOCALAPPDATA%\Maxwell\ca\ca.pem` (Windows) or the path logged at startup
- Override with `--ca-dir`
- Blind tunnel (no decryption): `--no-mitm`

Only use against **authorized** test targets.

## MVP roadmap

1. `max-core` — shared types ✅
2. `max-orchestrator` — internal broadcast + session fan-out ✅
3. `max-proxy` — HTTP + HTTPS MITM event producer ✅
4. `maxwell` CLI — runnable local session ✅
5. `max-tauri` — desktop collaboration UI
