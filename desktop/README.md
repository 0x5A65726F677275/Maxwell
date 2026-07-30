# Maxwell desktop

Tauri 2 + SvelteKit (Svelte 5) desktop workbench. Layout language inspired by
modern desktop clients such as GitButler (sidebar + dense panes), but the UI
implementation is original Maxwell code — **GitButler source is not vendored**
(see FSL-1.1-MIT license constraints).

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:USERPROFILE\.bun\bin;" + $env:Path
bun install
bun run desktop:dev
```

Tabs: Proxy · Binary · Operator · Findings
