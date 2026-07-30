//! Intercepting HTTP/HTTPS proxy for Maxwell.
//!
//! Captures request/response pairs against authorized test targets and emits
//! [`max_core::RawEvent`] values into a collaboration session. HTTPS MITM uses a
//! local CA (Rustls + rcgen); the analyst must manually trust `ca.pem`.

pub mod anomaly;
pub mod capture;
pub mod replay;
pub mod server;
pub mod tls;

pub use anomaly::{detect_anomaly, AnomalyHit};
pub use capture::Capture;
pub use replay::replay_request;
pub use server::{ProxyConfig, ProxyError, ProxyServer};
pub use tls::{default_ca_dir, CertificateAuthority};

/// Crate identity used as the event `source` field.
pub const CRATE_NAME: &str = "max-proxy";
