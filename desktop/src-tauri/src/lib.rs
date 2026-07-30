//! Maxwell Tauri backend — workbench commands (proxy, binary, operator).

use std::net::SocketAddr;
use std::sync::Mutex;

use max_binwalk::analyze_path;
use max_core::{
    BinaryInfo, CaptureRecord, EventKind, Finding, FindingId, FindingStatus, SessionRole,
    PLATFORM_NAME, PLATFORM_VERSION,
};
use max_orchestrator::{Orchestrator, SessionHandle};
use max_proxy::{default_ca_dir, replay_request, ProxyConfig, ProxyServer};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::oneshot;
use uuid::Uuid;

struct AppState {
    orch: Orchestrator,
    inner: Mutex<InnerState>,
}

struct InnerState {
    session: Option<SessionHandle>,
    session_id: Option<String>,
    listen: Option<String>,
    ca_path: Option<String>,
    mitm: bool,
    running: bool,
    stop_tx: Option<oneshot::Sender<()>>,
    captures: Vec<CaptureRecord>,
    findings: Vec<Finding>,
    last_binary: Option<BinaryInfo>,
}

impl Default for InnerState {
    fn default() -> Self {
        Self {
            session: None,
            session_id: None,
            listen: None,
            ca_path: None,
            mitm: true,
            running: false,
            stop_tx: None,
            captures: Vec::new(),
            findings: Vec::new(),
            last_binary: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyStatus {
    platform: String,
    version: String,
    running: bool,
    session_id: Option<String>,
    listen: Option<String>,
    ca_path: Option<String>,
    mitm: bool,
    capture_count: usize,
    pending_findings: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartResult {
    session_id: String,
    listen: String,
    ca_path: String,
    mitm: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorSnapshot {
    session_id: Option<String>,
    running: bool,
    listen: Option<String>,
    ca_path: Option<String>,
    mitm: bool,
    participants: Vec<OperatorParticipant>,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorParticipant {
    name: String,
    role: SessionRole,
}

fn status_from(inner: &InnerState) -> ProxyStatus {
    ProxyStatus {
        platform: PLATFORM_NAME.into(),
        version: PLATFORM_VERSION.into(),
        running: inner.running,
        session_id: inner.session_id.clone(),
        listen: inner.listen.clone(),
        ca_path: inner.ca_path.clone(),
        mitm: inner.mitm,
        capture_count: inner.captures.len(),
        pending_findings: inner
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Pending)
            .count(),
    }
}

fn ingest_event(inner: &mut InnerState, event: &max_core::Event) {
    match &event.kind {
        EventKind::ProxyCapture { request, response } => {
            inner.captures.insert(
                0,
                CaptureRecord::new(request.clone(), response.clone(), None),
            );
            if inner.captures.len() > 500 {
                inner.captures.truncate(500);
            }
        }
        EventKind::Anomaly {
            request,
            response,
            signal,
        } => {
            if let Some(cap) = inner.captures.first_mut() {
                if cap.anomaly_signal.is_none() && cap.request.url == request.url {
                    cap.anomaly_signal = Some(signal.clone());
                    return;
                }
            }
            inner.captures.insert(
                0,
                CaptureRecord::new(
                    request.clone(),
                    Some(response.clone()),
                    Some(signal.clone()),
                ),
            );
            let finding = Finding::pending(
                request.url.clone(),
                format!("anomaly signal: {signal}"),
            );
            // Keep finding id aligned with event finding when present — use new id.
            inner.findings.insert(0, finding);
        }
        EventKind::ValidationCandidate {
            target,
            rationale,
            finding_id,
        } => {
            let mut finding = Finding::pending(target.clone(), rationale.clone());
            finding.id = FindingId(*finding_id);
            inner.findings.insert(0, finding);
        }
        EventKind::ValidationDecision {
            finding_id,
            approved,
            note,
        } => {
            if let Some(f) = inner
                .findings
                .iter_mut()
                .find(|f| f.id.0 == *finding_id)
            {
                f.status = if *approved {
                    FindingStatus::Approved
                } else {
                    FindingStatus::Rejected
                };
                f.note = note.clone();
            }
        }
        EventKind::BinaryAnalysis { info } => {
            inner.last_binary = Some(info.clone());
        }
        _ => {}
    }
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(status_from(&inner))
}

#[tauri::command]
async fn start_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    listen: String,
    mitm: bool,
) -> Result<StartResult, String> {
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        if inner.running {
            return Err("proxy already running".into());
        }
        if let Some(tx) = inner.stop_tx.take() {
            let _ = tx.send(());
        }
    }

    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid listen address: {e}"))?;

    let session = state
        .orch
        .create_session()
        .map_err(|e| e.to_string())?;
    session
        .join("local", SessionRole::Lead)
        .map_err(|e| e.to_string())?;

    let mut rx = session.bus().subscribe();
    let app_events = app.clone();
    let state_captures = state.inner.lock().map_err(|e| e.to_string())?;
    drop(state_captures);

    // Spawn event bridge that updates AppState + emits to UI.
    let app_for_state = app.clone();
    tauri::async_runtime::spawn({
        let app = app_events;
        async move {
            // We need AppState — get via app.try_state
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let Some(st) = app.try_state::<AppState>() {
                            if let Ok(mut inner) = st.inner.lock() {
                                ingest_event(&mut inner, &event);
                            }
                        }
                        let _ = app.emit("proxy-event", &event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            let _ = app_for_state;
        }
    });

    let server = ProxyServer::new(
        ProxyConfig {
            listen: addr,
            ca_dir: default_ca_dir(),
            mitm,
        },
        session.clone(),
    )
    .map_err(|e| e.to_string())?;

    let ca_path = server.ca_cert_path().display().to_string();
    let session_id = session.id.to_string();

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    tauri::async_runtime::spawn(async move {
        tokio::select! {
            result = server.serve() => {
                if let Err(err) = result {
                    tracing::error!(error = %err, "proxy server stopped");
                }
            }
            _ = stop_rx => {
                tracing::info!("proxy stop requested");
            }
        }
    });

    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.session = Some(session);
        inner.session_id = Some(session_id.clone());
        inner.listen = Some(addr.to_string());
        inner.ca_path = Some(ca_path.clone());
        inner.mitm = mitm;
        inner.running = true;
        inner.stop_tx = Some(stop_tx);
        let status = status_from(&inner);
        drop(inner);
        let _ = app.emit("proxy-status", &status);
    }

    Ok(StartResult {
        session_id,
        listen: addr.to_string(),
        ca_path,
        mitm,
    })
}

#[tauri::command]
fn stop_proxy(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    if let Some(tx) = inner.stop_tx.take() {
        let _ = tx.send(());
    }
    inner.running = false;
    let status = status_from(&inner);
    drop(inner);
    let _ = app.emit("proxy-status", &status);
    Ok(())
}

#[tauri::command]
fn list_captures(state: State<'_, AppState>) -> Result<Vec<CaptureRecord>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner.captures.clone())
}

#[tauri::command]
fn get_capture(state: State<'_, AppState>, id: String) -> Result<CaptureRecord, String> {
    let uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner
        .captures
        .iter()
        .find(|c| c.id.0 == uuid)
        .cloned()
        .ok_or_else(|| format!("capture {id} not found"))
}

#[tauri::command]
async fn replay_capture(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<CaptureRecord, String> {
    let uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let (request, session) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let cap = inner
            .captures
            .iter()
            .find(|c| c.id.0 == uuid)
            .cloned()
            .ok_or_else(|| format!("capture {id} not found"))?;
        let session = inner.session.clone();
        (cap.request, session)
    };

    let capture = replay_request(&request)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(session) = session {
        let _ = capture.emit(&session);
    }

    let record = CaptureRecord::new(
        capture.request,
        Some(capture.response),
        None,
    );

    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.captures.insert(0, record.clone());
        let status = status_from(&inner);
        drop(inner);
        let _ = app.emit("proxy-status", &status);
    }

    Ok(record)
}

#[tauri::command]
fn analyze_binary(state: State<'_, AppState>, path: String) -> Result<BinaryInfo, String> {
    let info = analyze_path(&path).map_err(|e| e.to_string())?;
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        if let Some(session) = inner.session.clone() {
            let _ = session.ingest(max_core::RawEvent {
                session_id: session.id,
                source: max_binwalk::CRATE_NAME.into(),
                kind: EventKind::BinaryAnalysis {
                    info: info.clone(),
                },
            });
        }
        inner.last_binary = Some(info.clone());
    }
    Ok(info)
}

#[tauri::command]
fn last_binary(state: State<'_, AppState>) -> Result<Option<BinaryInfo>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner.last_binary.clone())
}

#[tauri::command]
fn operator_snapshot(state: State<'_, AppState>) -> Result<OperatorSnapshot, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let participants = if let Some(session) = &inner.session {
        session
            .participants()
            .unwrap_or_default()
            .into_iter()
            .map(|p| OperatorParticipant {
                name: p.name,
                role: p.role,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(OperatorSnapshot {
        session_id: inner.session_id.clone(),
        running: inner.running,
        listen: inner.listen.clone(),
        ca_path: inner.ca_path.clone(),
        mitm: inner.mitm,
        participants,
        findings: inner.findings.clone(),
    })
}

#[tauri::command]
fn list_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner.findings.clone())
}

#[tauri::command]
fn decide_finding(
    app: AppHandle,
    state: State<'_, AppState>,
    finding_id: String,
    approved: bool,
    note: Option<String>,
) -> Result<Finding, String> {
    let uuid = Uuid::parse_str(&finding_id).map_err(|e| e.to_string())?;
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    let session = inner
        .session
        .clone()
        .ok_or_else(|| "start a session/proxy first".to_string())?;

    session
        .decide_validation("local", uuid, approved, note.clone())
        .map_err(|e| e.to_string())?;

    let finding = inner
        .findings
        .iter_mut()
        .find(|f| f.id.0 == uuid)
        .ok_or_else(|| format!("finding {finding_id} not found"))?;
    finding.status = if approved {
        FindingStatus::Approved
    } else {
        FindingStatus::Rejected
    };
    finding.note = note;
    let out = finding.clone();
    let status = status_from(&inner);
    drop(inner);
    let _ = app.emit("proxy-status", &status);
    Ok(out)
}

#[tauri::command]
fn add_finding(
    state: State<'_, AppState>,
    target: String,
    rationale: String,
) -> Result<Finding, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    let finding = Finding::pending(target.clone(), rationale.clone());
    if let Some(session) = &inner.session {
        let _ = session.ingest(max_core::RawEvent {
            session_id: session.id,
            source: "max-tauri".into(),
            kind: EventKind::ValidationCandidate {
                target,
                rationale,
                finding_id: finding.id.0,
            },
        });
    }
    inner.findings.insert(0, finding.clone());
    Ok(finding)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap_or_default()),
        )
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            orch: Orchestrator::new(),
            inner: Mutex::new(InnerState::default()),
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_proxy,
            stop_proxy,
            list_captures,
            get_capture,
            replay_capture,
            analyze_binary,
            last_binary,
            operator_snapshot,
            list_findings,
            decide_finding,
            add_finding
        ])
        .run(tauri::generate_context!())
        .expect("error while running Maxwell");
}
