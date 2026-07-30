import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type ProxyStatus = {
  platform: string;
  version: string;
  running: boolean;
  sessionId: string | null;
  listen: string | null;
  caPath: string | null;
  mitm: boolean;
};

type ProxyEvent = {
  id: string;
  source: string;
  severity: string;
  kind: {
    kind: string;
    request?: { method: string; url: string };
    signal?: string;
    author?: string;
    text?: string;
  };
};

function summarize(ev: ProxyEvent): string {
  const k = ev.kind;
  switch (k.kind) {
    case "proxy_capture":
      return `${k.request?.method ?? "?"} ${k.request?.url ?? ""}`;
    case "anomaly":
      return `anomaly:${k.signal ?? "?"} ${k.request?.url ?? ""}`;
    case "annotation":
      return `${k.author}: ${k.text}`;
    default:
      return k.kind;
  }
}

function App() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [listenAddr, setListenAddr] = useState("127.0.0.1:8888");
  const [mitm, setMitm] = useState(true);
  const [events, setEvents] = useState<ProxyEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const s = await invoke<ProxyStatus>("get_status");
    setStatus(s);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(String(e)));
    const unsubs = Promise.all([
      listen<ProxyEvent>("proxy-event", (e) => {
        setEvents((prev) => [e.payload, ...prev].slice(0, 200));
      }),
      listen<ProxyStatus>("proxy-status", (e) => setStatus(e.payload)),
    ]);
    return () => {
      unsubs.then((fns) => fns.forEach((u) => u()));
    };
  }, [refresh]);

  async function onStart() {
    setBusy(true);
    setError(null);
    try {
      await invoke("start_proxy", { listen: listenAddr, mitm });
      await refresh();
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
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const running = status?.running ?? false;

  return (
    <div className="shell">
      <header className="top">
        <div>
          <p className="brand">Maxwell</p>
          <p className="sub">
            Local-first collaboration proxy
            {status ? ` · v${status.version}` : ""}
          </p>
        </div>
        <div className={`pill ${running ? "on" : "off"}`}>
          {running ? "PROXY ON" : "PROXY OFF"}
        </div>
      </header>

      <section className="controls">
        <label>
          Listen
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
              Start proxy
            </button>
          ) : (
            <button className="danger" disabled={busy} onClick={onStop}>
              Stop
            </button>
          )}
        </div>
      </section>

      {error && <p className="error">{error}</p>}

      <section className="meta">
        <div>
          <span>Session</span>
          <code>{status?.sessionId ?? "—"}</code>
        </div>
        <div>
          <span>CA</span>
          <code>{status?.caPath ?? "—"}</code>
        </div>
      </section>

      <section className="feed">
        <div className="feed-head">
          <h2>Live events</h2>
          <button
            className="ghost"
            onClick={() => setEvents([])}
            disabled={events.length === 0}
          >
            Clear
          </button>
        </div>
        <ul>
          {events.length === 0 && (
            <li className="empty">Start the proxy, then send traffic through it.</li>
          )}
          {events.map((ev, i) => (
            <li key={`${ev.id}-${i}`} className={ev.kind.kind}>
              <span className="sev">{ev.severity}</span>
              <span className="src">{ev.source}</span>
              <span className="msg">{summarize(ev)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export default App;
