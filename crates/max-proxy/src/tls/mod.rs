//! TLS helpers for authorized HTTPS interception (MITM).
//!
//! The local CA must be **manually** trusted by the analyst's browser/OS.
//! Maxwell never installs a system trust anchor automatically.

mod ca;
pub(crate) mod mitm;

pub use ca::{default_ca_dir, CertificateAuthority};
pub use mitm::intercept_https;

use std::sync::Once;

/// Install the rustls ring crypto provider exactly once.
pub fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
