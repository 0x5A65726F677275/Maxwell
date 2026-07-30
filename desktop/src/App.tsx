import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type Tab = "proxy" | "binary" | "operator" | "findings";

type ProxyStatus = {
  platform: string;
  version: string;
  running: boolean;
  sessionId: string | null;
  listen: string | null;
  caPath: string | null;
  mitm: boolean;
  captureCount: number;
  pendingFindings: number;
};

type CaptureRecord = {
  id: string;
  createdAt: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: number[];
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: number[];
  } | null;
  anomalySignal: string | null;
};

type Instruction = { address: number; bytes: string; text: string };
type FunctionInfo = {
  name: string | null;
  address: number;
  size: number | null;
  disasm: Instruction[];
};
type BinaryInfo = {
  path: string;
  format: string;
  entryPoint: number | null;
  architecture: string | null;
  functions: FunctionInfo[];
};

type Finding = {
  id: string;
  createdAt: string;
  target: string;
  rationale: string;
  status: "pending" | "approved" | "rejected";
  note: string | null;
};

type OperatorSnapshot = {
  sessionId: string | null;
  running: boolean;
  listen: string | null;
  caPath: string | null;
  mitm: boolean;
  participants: { name: string; role: string }[];
  findings: Finding[];
};

type ProxyEvent = {
  id: string;
  source: string;
  severity: string;
  kind: { kind: string; signal?: string; request?: { url: string } };
};

function bodyPreview(bytes: number[] | undefined, max = 400): string {
  if (!bytes || bytes.length === 0) return "";
  try {
    return new TextDecoder().decode(Uint8Array.from(bytes.slice(0, max)));
  } catch {
    return bytes
      .slice(0, 64)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }
}

function App() {
  const [tab, setTab] = useState<Tab>("proxy");
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [listenAddr, setListenAddr] = useState("127.0.0.1:8888");
  const [mitm, setMitm] = useState(true);
  const [captures, setCaptures] = useState<CaptureRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [events, setEvents] = useState<ProxyEvent[]>([]);
  const [binaryPath, setBinaryPath] = useState("");
  const [binary, setBinary] = useState<BinaryInfo | null>(null);
  const [selectedFn, setSelectedFn] = useState<number | null>(null);
  const [operator, setOperator] = useState<OperatorSnapshot | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingTarget, setFindingTarget] = useState("");
  const [findingWhy, setFindingWhy] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = useMemo(
    () => captures.find((c) => c.id === selectedId) ?? null,
    [captures, selectedId],
  );

  const refreshStatus = useCallback(async () => {
    setStatus(await invoke<ProxyStatus>("get_status"));
  }, []);

  const refreshCaptures = useCallback(async () => {
    const list = await invoke<CaptureRecord[]>("list_captures");
    setCaptures(list);
  }, []);

  const refreshOperator = useCallback(async () => {
    const snap = await invoke<OperatorSnapshot>("operator_snapshot");
    setOperator(snap);
    setFindings(snap.findings);
  }, []);

  useEffect(() => {
    refreshStatus().catch((e) => setError(String(e)));
    refreshCaptures().catch(() => undefined);
    refreshOperator().catch(() => undefined);
    const unsubs = Promise.all([
      listen<ProxyEvent>("proxy-event", (e) => {
        setEvents((prev) => [e.payload, ...prev].slice(0, 100));
        refreshCaptures().catch(() => undefined);
        refreshOperator().catch(() => undefined);
        refreshStatus().catch(() => undefined);
      }),
      listen<ProxyStatus>("proxy-status", (e) => setStatus(e.payload)),
    ]);
    return () => {
      unsubs.then((fns) => fns.forEach((u) => u()));
    };
  }, [refreshCaptures, refreshOperator, refreshStatus]);

  async function onStart() {
    setBusy(true);
    setError(null);
    try {
      await invoke("start_proxy", { listen: listenAddr, mitm });
      await refreshStatus();
      await refreshOperator();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onStop() {
    setBusy(true);
    setError(null);
    try {
      await invoke("stop_proxy");
      await refreshStatus();
      await refreshOperator();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onReplay() {
    if (!selectedId) return;
    setBusy(true);
    setError(null);
    try {
      const rec = await invoke<CaptureRecord>("replay_capture", { id: selectedId });
      await refreshCaptures();
      setSelectedId(rec.id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onAnalyze() {
    setBusy(true);
    setError(null);
    try {
      const info = await invoke<BinaryInfo>("analyze_binary", { path: binaryPath });
      setBinary(info);
      setSelectedFn(info.functions[0]?.address ?? null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onDecide(id: string, approved: boolean) {
    setBusy(true);
    setError(null);
    try {
      await invoke("decide_finding", {
        findingId: id,
        approved,
        note: approved ? "analyst approved" : "analyst rejected",
      });
      await refreshOperator();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onAddFinding() {
    if (!findingTarget.trim() || !findingWhy.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await invoke("add_finding", {
        target: findingTarget.trim(),
        rationale: findingWhy.trim(),
      });
      setFindingTarget("");
      setFindingWhy("");
      await refreshOperator();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const running = status?.running ?? false;
  const activeFn =
    binary?.functions.find((f) => f.address === selectedFn) ?? null;

  return (
    <div className="shell">
      <header className="top">
        <div>
          <p className="brand">Maxwell</p>
          <p className="sub">
            Security workbench · operator console
            {status ? ` · v${status.version}` : ""}
          </p>
        </div>
        <div className={`pill ${running ? "on" : "off"}`}>
          {running ? "LISTENER UP" : "LISTENER DOWN"}
        </div>
      </header>

      <nav className="tabs">
        {(
          [
            ["proxy", "Proxy"],
            ["binary", "Binary"],
            ["operator", "Operator"],
            ["findings", `Findings${status?.pendingFindings ? ` (${status.pendingFindings})` : ""}`],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            className={tab === id ? "tab active" : "tab"}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {error && <p className="error">{error}</p>}

      {tab === "proxy" && (
        <section className="panel">
          <div className="controls">
            <label>
              Listener
              <input
                value={listenAddr}
                onChange={(e) => setListenAddr(e.target.value)}
                disabled={running || busy}
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={mitm}
                onChange={(e) => setMitm(e.target.checked)}
                disabled={running || busy}
              />
              HTTPS MITM
            </label>
            <div className="actions">
              {!running ? (
                <button disabled={busy} onClick={onStart}>
                  Start listener
                </button>
              ) : (
                <button className="danger" disabled={busy} onClick={onStop}>
                  Stop
                </button>
              )}
            </div>
          </div>

          <div className="split">
            <div className="list">
              <div className="feed-head">
                <h2>History ({captures.length})</h2>
              </div>
              <ul>
                {captures.length === 0 && (
                  <li className="empty">No captures yet.</li>
                )}
                {captures.map((c) => (
                  <li
                    key={c.id}
                    className={selectedId === c.id ? "sel" : ""}
                    onClick={() => setSelectedId(c.id)}
                  >
                    <span className="sev">
                      {c.response?.status ?? "—"}
                    </span>
                    <span className="msg">
                      {c.request.method} {c.request.url}
                      {c.anomalySignal ? ` · ${c.anomalySignal}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="detail">
              <div className="feed-head">
                <h2>Inspector</h2>
                <button
                  className="ghost"
                  disabled={!selected || busy}
                  onClick={onReplay}
                >
                  Replay
                </button>
              </div>
              {!selected ? (
                <p className="empty-pad">Select a capture.</p>
              ) : (
                <div className="inspector">
                  <h3>Request</h3>
                  <pre>{`${selected.request.method} ${selected.request.url}\n${Object.entries(
                    selected.request.headers,
                  )
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n")}\n\n${bodyPreview(selected.request.body)}`}</pre>
                  <h3>Response</h3>
                  <pre>
                    {selected.response
                      ? `${selected.response.status}\n${Object.entries(
                          selected.response.headers,
                        )
                          .map(([k, v]) => `${k}: ${v}`)
                          .join("\n")}\n\n${bodyPreview(selected.response.body)}`
                      : "(none)"}
                  </pre>
                </div>
              )}
            </div>
          </div>

          <div className="feed tight">
            <div className="feed-head">
              <h2>Live bus</h2>
            </div>
            <ul>
              {events.slice(0, 20).map((ev, i) => (
                <li key={`${ev.id}-${i}`}>
                  <span className="sev">{ev.severity}</span>
                  <span className="src">{ev.source}</span>
                  <span className="msg">{ev.kind.kind}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      {tab === "binary" && (
        <section className="panel">
          <div className="controls">
            <label className="grow">
              Binary path
              <input
                value={binaryPath}
                onChange={(e) => setBinaryPath(e.target.value)}
                placeholder="/path/to/sample"
                disabled={busy}
              />
            </label>
            <div className="actions">
              <button disabled={busy || !binaryPath.trim()} onClick={onAnalyze}>
                Analyze
              </button>
            </div>
          </div>
          {binary && (
            <>
              <p className="meta-line">
                {binary.format} · {binary.architecture ?? "?"} · entry{" "}
                {binary.entryPoint != null
                  ? `0x${binary.entryPoint.toString(16)}`
                  : "—"}
              </p>
              <div className="split">
                <div className="list">
                  <div className="feed-head">
                    <h2>Functions ({binary.functions.length})</h2>
                  </div>
                  <ul>
                    {binary.functions.map((fn) => (
                      <li
                        key={fn.address}
                        className={selectedFn === fn.address ? "sel" : ""}
                        onClick={() => setSelectedFn(fn.address)}
                      >
                        <span className="sev">
                          0x{fn.address.toString(16)}
                        </span>
                        <span className="msg">{fn.name ?? "(unnamed)"}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="detail">
                  <div className="feed-head">
                    <h2>Disassembly</h2>
                  </div>
                  <pre className="asm">
                    {(activeFn?.disasm ?? [])
                      .map(
                        (ins) =>
                          `${ins.address.toString(16).padStart(8, "0")}  ${ins.bytes.padEnd(24, " ")}  ${ins.text}`,
                      )
                      .join("\n") || "(no disassembly — non-x86 or unmapped)"}
                  </pre>
                </div>
              </div>
            </>
          )}
        </section>
      )}

      {tab === "operator" && (
        <section className="panel">
          <div className="ops-grid">
            <div className="card">
              <h2>Engagement</h2>
              <p>
                Session: <code>{operator?.sessionId ?? "—"}</code>
              </p>
              <p>
                Listener:{" "}
                <code>
                  {operator?.running
                    ? `${operator.listen} (MITM=${operator.mitm})`
                    : "down"}
                </code>
              </p>
              <p>
                CA: <code>{operator?.caPath ?? "—"}</code>
              </p>
              <p className="hint">
                Cobalt Strike–style operator view for authorized engagements —
                no C2 beacons/implants.
              </p>
            </div>
            <div className="card">
              <h2>Operators</h2>
              <ul className="plain">
                {(operator?.participants ?? []).length === 0 && (
                  <li>Start listener to open a session seat.</li>
                )}
                {(operator?.participants ?? []).map((p) => (
                  <li key={p.name}>
                    <strong>{p.name}</strong> · {p.role}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {tab === "findings" && (
        <section className="panel">
          <div className="controls">
            <label className="grow">
              Target
              <input
                value={findingTarget}
                onChange={(e) => setFindingTarget(e.target.value)}
                placeholder="https://authorized-target.example/api"
              />
            </label>
            <label className="grow">
              Rationale
              <input
                value={findingWhy}
                onChange={(e) => setFindingWhy(e.target.value)}
                placeholder="error-based SQLi indicator"
              />
            </label>
            <div className="actions">
              <button disabled={busy} onClick={onAddFinding}>
                Queue finding
              </button>
            </div>
          </div>
          <ul className="findings">
            {findings.length === 0 && (
              <li className="empty">No findings. Anomalies auto-queue here.</li>
            )}
            {findings.map((f) => (
              <li key={f.id} className={f.status}>
                <div>
                  <strong>{f.status}</strong> · {f.target}
                  <div className="why">{f.rationale}</div>
                </div>
                {f.status === "pending" && (
                  <div className="actions">
                    <button disabled={busy} onClick={() => onDecide(f.id, true)}>
                      Approve
                    </button>
                    <button
                      className="danger"
                      disabled={busy}
                      onClick={() => onDecide(f.id, false)}
                    >
                      Reject
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

export default App;
