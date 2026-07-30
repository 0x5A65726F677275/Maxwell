<script lang="ts">
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { api, bodyPreview } from "$lib/api";
  import type {
    BinaryInfo,
    CaptureRecord,
    Finding,
    OperatorSnapshot,
    ProxyEvent,
    ProxyStatus,
    Tab,
  } from "$lib/types";

  let tab = $state<Tab>("proxy");
  let status = $state<ProxyStatus | null>(null);
  let listenAddr = $state("127.0.0.1:8888");
  let mitm = $state(true);
  let captures = $state<CaptureRecord[]>([]);
  let selectedId = $state<string | null>(null);
  let events = $state<ProxyEvent[]>([]);
  let binaryPath = $state("");
  let binary = $state<BinaryInfo | null>(null);
  let selectedFn = $state<number | null>(null);
  let operator = $state<OperatorSnapshot | null>(null);
  let findings = $state<Finding[]>([]);
  let findingTarget = $state("");
  let findingWhy = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  const selected = $derived(captures.find((c) => c.id === selectedId) ?? null);
  const running = $derived(status?.running ?? false);
  const activeFn = $derived(
    binary?.functions.find((f) => f.address === selectedFn) ?? null,
  );

  async function refreshStatus() {
    status = await api.getStatus();
  }

  async function refreshCaptures() {
    captures = await api.listCaptures();
  }

  async function refreshOperator() {
    const snap = await api.operatorSnapshot();
    operator = snap;
    findings = snap.findings;
  }

  onMount(() => {
    let unsubs: (() => void)[] = [];

    (async () => {
      try {
        await refreshStatus();
        await refreshCaptures();
        await refreshOperator();
      } catch (e) {
        error = String(e);
      }

      unsubs = [
        await listen<ProxyEvent>("proxy-event", async (e) => {
          events = [e.payload, ...events].slice(0, 100);
          await Promise.allSettled([
            refreshCaptures(),
            refreshOperator(),
            refreshStatus(),
          ]);
        }),
        await listen<ProxyStatus>("proxy-status", (e) => {
          status = e.payload;
        }),
      ];
    })();

    return () => unsubs.forEach((u) => u());
  });

  async function onStart() {
    busy = true;
    error = null;
    try {
      await api.startProxy(listenAddr, mitm);
      await refreshStatus();
      await refreshOperator();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function onStop() {
    busy = true;
    error = null;
    try {
      await api.stopProxy();
      await refreshStatus();
      await refreshOperator();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function onReplay() {
    if (!selectedId) return;
    busy = true;
    error = null;
    try {
      const rec = await api.replayCapture(selectedId);
      await refreshCaptures();
      selectedId = rec.id;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function onAnalyze() {
    busy = true;
    error = null;
    try {
      const info = await api.analyzeBinary(binaryPath);
      binary = info;
      selectedFn = info.functions[0]?.address ?? null;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function onDecide(id: string, approved: boolean) {
    busy = true;
    error = null;
    try {
      await api.decideFinding(
        id,
        approved,
        approved ? "analyst approved" : "analyst rejected",
      );
      await refreshOperator();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function onAddFinding() {
    if (!findingTarget.trim() || !findingWhy.trim()) return;
    busy = true;
    error = null;
    try {
      await api.addFinding(findingTarget.trim(), findingWhy.trim());
      findingTarget = "";
      findingWhy = "";
      await refreshOperator();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "proxy", label: "Proxy" },
    { id: "binary", label: "Binary" },
    { id: "operator", label: "Operator" },
    { id: "findings", label: "Findings" },
  ];
</script>

<div class="app-shell">
  <header class="titlebar">
    <div class="brand-block">
      <p class="brand">Maxwell</p>
      <p class="brand-sub">
        Security workbench{status ? ` · v${status.version}` : ""}
      </p>
    </div>
    <div class={`pill ${running ? "on" : "off"}`}>
      {running ? "Listener up" : "Listener down"}
    </div>
  </header>

  <aside class="sidebar">
    <div class="nav-label">Workbench</div>
    {#each tabs as t}
      <button
        type="button"
        class={tab === t.id ? "nav-item active" : "nav-item"}
        onclick={() => (tab = t.id)}
      >
        <span>{t.label}</span>
        {#if t.id === "findings" && status?.pendingFindings}
          <span class="nav-badge">{status.pendingFindings}</span>
        {/if}
      </button>
    {/each}
    <div class="sidebar-foot">
      Local-first proxy · binary · operator console. No C2 beacons.
    </div>
  </aside>

  <main class="main">
    {#if error}
      <p class="banner-error">{error}</p>
    {/if}

    {#if tab === "proxy"}
      <section class="panel">
        <div class="toolbar">
          <label class="field">
            Listener
            <input bind:value={listenAddr} disabled={running || busy} />
          </label>
          <label class="field check">
            <input
              type="checkbox"
              bind:checked={mitm}
              disabled={running || busy}
            />
            HTTPS MITM
          </label>
          <div class="actions">
            {#if !running}
              <button disabled={busy} onclick={onStart}>Start listener</button>
            {:else}
              <button class="danger" disabled={busy} onclick={onStop}>Stop</button>
            {/if}
          </div>
        </div>

        <div class="workspace">
          <div class="pane">
            <div class="pane-head">
              <h2>History · {captures.length}</h2>
            </div>
            <div class="pane-body">
              <ul class="list">
                {#if captures.length === 0}
                  <li><p class="empty">No captures yet. Point traffic at the listener.</p></li>
                {/if}
                {#each captures as c}
                  <li class={selectedId === c.id ? "sel" : ""}>
                    <button
                      type="button"
                      class="row-btn"
                      onclick={() => (selectedId = c.id)}
                    >
                      <span class="sev">{c.response?.status ?? "—"}</span>
                      <span class="msg">
                        {c.request.method} {c.request.url}{c.anomalySignal
                          ? ` · ${c.anomalySignal}`
                          : ""}
                      </span>
                    </button>
                  </li>
                {/each}
              </ul>
            </div>
          </div>

          <div class="pane">
            <div class="pane-head">
              <h2>Inspector</h2>
              <button
                class="ghost"
                disabled={!selected || busy}
                onclick={onReplay}
              >
                Replay
              </button>
            </div>
            <div class="pane-body">
              {#if !selected}
                <p class="empty">Select a capture.</p>
              {:else}
                <div class="inspector selectable">
                  <h3>Request</h3>
                  <pre
                    >{`${selected.request.method} ${selected.request.url}\n${Object.entries(
                      selected.request.headers,
                    )
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}\n\n${bodyPreview(selected.request.body)}`}</pre
                  >
                  <h3>Response</h3>
                  <pre
                    >{selected.response
                      ? `${selected.response.status}\n${Object.entries(
                          selected.response.headers,
                        )
                          .map(([k, v]) => `${k}: ${v}`)
                          .join("\n")}\n\n${bodyPreview(selected.response.body)}`
                      : "(none)"}</pre
                  >
                </div>
              {/if}
            </div>
          </div>
        </div>

        <div class="pane bus">
          <div class="pane-head">
            <h2>Live bus</h2>
          </div>
          <div class="pane-body">
            <ul class="list">
              {#each events.slice(0, 20) as ev}
                <li>
                  <div class="row-btn" style="cursor: default;">
                    <span class="sev">{ev.severity}</span>
                    <span class="src">{ev.source}</span>
                    <span class="msg">{ev.kind.kind}</span>
                  </div>
                </li>
              {/each}
              {#if events.length === 0}
                <li><p class="empty">Waiting for events…</p></li>
              {/if}
            </ul>
          </div>
        </div>
      </section>
    {/if}

    {#if tab === "binary"}
      <section class="panel">
        <div class="toolbar">
          <label class="field grow">
            Binary path
            <input
              bind:value={binaryPath}
              placeholder="C:\path\to\sample.exe"
              disabled={busy}
            />
          </label>
          <div class="actions">
            <button disabled={busy || !binaryPath.trim()} onclick={onAnalyze}>
              Analyze
            </button>
          </div>
        </div>

        {#if binary}
          <p class="meta-line">
            {binary.format} · {binary.architecture ?? "?"} · entry{" "}
            {binary.entryPoint != null
              ? `0x${binary.entryPoint.toString(16)}`
              : "—"}
          </p>
          <div class="workspace">
            <div class="pane">
              <div class="pane-head">
                <h2>Functions · {binary.functions.length}</h2>
              </div>
              <div class="pane-body">
                <ul class="list">
                  {#each binary.functions as fn}
                    <li class={selectedFn === fn.address ? "sel" : ""}>
                      <button
                        type="button"
                        class="row-btn"
                        onclick={() => (selectedFn = fn.address)}
                      >
                        <span class="sev">0x{fn.address.toString(16)}</span>
                        <span class="msg">{fn.name ?? "(unnamed)"}</span>
                      </button>
                    </li>
                  {/each}
                </ul>
              </div>
            </div>
            <div class="pane">
              <div class="pane-head">
                <h2>Disassembly</h2>
              </div>
              <div class="pane-body">
                <pre class="asm selectable"
                  >{(activeFn?.disasm ?? [])
                    .map(
                      (ins) =>
                        `${ins.address.toString(16).padStart(8, "0")}  ${ins.bytes.padEnd(24, " ")}  ${ins.text}`,
                    )
                    .join("\n") ||
                    "(no disassembly — non-x86 or unmapped)"}</pre
                >
              </div>
            </div>
          </div>
        {:else}
          <p class="empty">Load a PE/ELF/Mach-O path to inspect functions.</p>
        {/if}
      </section>
    {/if}

    {#if tab === "operator"}
      <section class="panel">
        <div class="ops-grid">
          <div class="card">
            <h2>Engagement</h2>
            <p>Session: <code>{operator?.sessionId ?? "—"}</code></p>
            <p>
              Listener:
              <code>
                {operator?.running
                  ? `${operator.listen} (MITM=${operator.mitm})`
                  : "down"}
              </code>
            </p>
            <p>CA: <code>{operator?.caPath ?? "—"}</code></p>
            <p class="hint">
              Analyst console for authorized engagements — no implants or C2.
            </p>
          </div>
          <div class="card">
            <h2>Seats</h2>
            <ul class="plain">
              {#if (operator?.participants ?? []).length === 0}
                <li>Start the listener to open a local seat.</li>
              {/if}
              {#each operator?.participants ?? [] as p}
                <li><strong>{p.name}</strong> · {p.role}</li>
              {/each}
            </ul>
          </div>
        </div>
      </section>
    {/if}

    {#if tab === "findings"}
      <section class="panel">
        <div class="toolbar">
          <label class="field grow">
            Target
            <input
              bind:value={findingTarget}
              placeholder="https://authorized-target.example/api"
            />
          </label>
          <label class="field grow">
            Rationale
            <input
              bind:value={findingWhy}
              placeholder="error-based SQLi indicator"
            />
          </label>
          <div class="actions">
            <button disabled={busy} onclick={onAddFinding}>Queue finding</button>
          </div>
        </div>
        <ul class="findings">
          {#if findings.length === 0}
            <li><p class="empty">No findings yet. Anomalies queue here.</p></li>
          {/if}
          {#each findings as f}
            <li class={f.status}>
              <div>
                <strong>{f.status}</strong> · {f.target}
                <div class="why">{f.rationale}</div>
              </div>
              {#if f.status === "pending"}
                <div class="actions" style="margin-left: 0;">
                  <button disabled={busy} onclick={() => onDecide(f.id, true)}>
                    Approve
                  </button>
                  <button
                    class="danger"
                    disabled={busy}
                    onclick={() => onDecide(f.id, false)}
                  >
                    Reject
                  </button>
                </div>
              {/if}
            </li>
          {/each}
        </ul>
      </section>
    {/if}
  </main>
</div>
