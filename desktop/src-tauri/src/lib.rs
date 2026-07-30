//! Maxwell Tauri backend — proxy control + live event fan-out to the WebView.

use std::net::SocketAddr;
use std::sync::Mutex;

use max_core::{SessionRole, PLATFORM_NAME, PLATFORM_VERSION};
use max_orchestrator::Orchestrator;
use max_proxy::{default_ca_dir, ProxyConfig, ProxyServer};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::oneshot;

struct AppState {
    orch: Orchestrator,
    inner: Mutex<InnerState>,
}

#[derive(Default)]
struct InnerState {
    session_id: Option<String>,
    listen: Option<String>,
    ca_path: Option<String>,
    mitm: bool,
    running: bool,
    stop_tx: Option<oneshot::Sender<()>>,
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartResult {
    session_id: String,
    listen: String,
    ca_path: String,
    mitm: bool,
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(ProxyStatus {
        platform: PLATFORM_NAME.into(),
        version: PLATFORM_VERSION.into(),
        running: inner.running,
        session_id: inner.session_id.clone(),
        listen: inner.listen.clone(),
        ca_path: inner.ca_path.clone(),
        mitm: inner.mitm,
    })
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
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let _ = app_events.emit("proxy-event", &event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
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
        inner.session_id = Some(session_id.clone());
        inner.listen = Some(addr.to_string());
        inner.ca_path = Some(ca_path.clone());
        inner.mitm = mitm;
        inner.running = true;
        inner.stop_tx = Some(stop_tx);
    }

    let _ = app.emit(
        "proxy-status",
        &ProxyStatus {
            platform: PLATFORM_NAME.into(),
            version: PLATFORM_VERSION.into(),
            running: true,
            session_id: Some(session_id.clone()),
            listen: Some(addr.to_string()),
            ca_path: Some(ca_path.clone()),
            mitm,
        },
    );

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
    let status = ProxyStatus {
        platform: PLATFORM_NAME.into(),
        version: PLATFORM_VERSION.into(),
        running: false,
        session_id: inner.session_id.clone(),
        listen: inner.listen.clone(),
        ca_path: inner.ca_path.clone(),
        mitm: inner.mitm,
    };
    drop(inner);
    let _ = app.emit("proxy-status", &status);
    Ok(())
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
            stop_proxy
        ])
        .run(tauri::generate_context!())
        .expect("error while running Maxwell");
}
