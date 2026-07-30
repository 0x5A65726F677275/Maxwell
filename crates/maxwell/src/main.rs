//! Maxwell CLI entrypoint — spins up a collaboration session and HTTP(S) proxy.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use max_core::{EventKind, SessionRole, PLATFORM_NAME, PLATFORM_VERSION};
use max_orchestrator::Orchestrator;
use max_proxy::{default_ca_dir, ProxyConfig, ProxyServer};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "maxwell", version, about = "Maxwell — local-first security collaboration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start a live session + HTTP/HTTPS intercepting proxy.
    Proxy {
        /// Listen address (default 127.0.0.1:8888).
        #[arg(long, default_value = "127.0.0.1:8888")]
        listen: SocketAddr,
        /// Display name for the local analyst seat.
        #[arg(long, default_value = "local")]
        analyst: String,
        /// Directory for the local MITM CA (`ca.pem` / `ca.key.pem`).
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Disable HTTPS decryption (blind CONNECT tunnel only).
        #[arg(long, default_value_t = false)]
        no_mitm: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Proxy {
            listen,
            analyst,
            ca_dir,
            no_mitm,
        } => run_proxy(listen, analyst, ca_dir.unwrap_or_else(default_ca_dir), !no_mitm).await?,
    }
    Ok(())
}

async fn run_proxy(
    listen: SocketAddr,
    analyst: String,
    ca_dir: PathBuf,
    mitm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("{PLATFORM_NAME} v{PLATFORM_VERSION} — proxy session starting");

    let orch = Orchestrator::new();
    let session = orch.create_session()?;
    session.join(&analyst, SessionRole::Lead)?;

    let mut rx = session.bus().subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => log_event(&event),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("event subscriber lagged by {n} messages");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let server = ProxyServer::new(
        ProxyConfig {
            listen,
            ca_dir,
            mitm,
        },
        session.clone(),
    )?;

    tracing::info!(
        session = %session.id,
        %listen,
        mitm,
        ca = %server.ca_cert_path().display(),
        "configure your client HTTP proxy; for HTTPS MITM, manually trust the CA cert"
    );

    server.serve().await?;
    Ok(())
}

fn log_event(event: &max_core::Event) {
    match &event.kind {
        EventKind::ProxyCapture { request, response } => {
            let status = response.as_ref().map(|r| r.status).unwrap_or(0);
            tracing::info!(
                id = %event.id,
                method = %request.method,
                url = %request.url,
                status,
                "capture"
            );
        }
        EventKind::Anomaly {
            request, signal, ..
        } => {
            tracing::warn!(
                id = %event.id,
                url = %request.url,
                signal = %signal,
                "anomaly"
            );
        }
        EventKind::Annotation { author, text } => {
            tracing::info!(id = %event.id, %author, %text, "annotation");
        }
        EventKind::ValidationCandidate {
            target, rationale, ..
        } => {
            tracing::warn!(id = %event.id, %target, %rationale, "validation candidate (awaiting sign-off)");
        }
        EventKind::ValidationDecision {
            finding_id,
            approved,
            note,
        } => {
            tracing::info!(id = %event.id, %finding_id, approved, ?note, "validation decision");
        }
        EventKind::BinaryAnalysis { info } => {
            tracing::info!(id = %event.id, path = %info.path, "binary analysis");
        }
    }
}
