//! Local Maxwell CA and per-host leaf certificates for HTTPS MITM.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::server::ProxyError;

const CA_CERT_FILE: &str = "ca.pem";
const CA_KEY_FILE: &str = "ca.key.pem";

/// Default on-disk location for the local CA material.
pub fn default_ca_dir() -> PathBuf {
    if let Some(base) = dirs::data_local_dir() {
        base.join("Maxwell").join("ca")
    } else {
        PathBuf::from(".maxwell").join("ca")
    }
}

/// Maxwell local CA used to mint short-lived host certificates.
pub struct CertificateAuthority {
    /// Original CA PEM (presented to clients / trusted by the analyst).
    cert_pem: String,
    cert_der: Vec<u8>,
    /// Issuer object used only for DN / AKI when signing leaves.
    issuer: Certificate,
    key_pair: KeyPair,
    cert_path: PathBuf,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// Load an existing CA from `dir`, or create one if missing.
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self, ProxyError> {
        crate::tls::ensure_crypto_provider();
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| ProxyError::Tls(format!("create ca dir: {e}")))?;

        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)
                .map_err(|e| ProxyError::Tls(format!("read ca cert: {e}")))?;
            let key_pem = fs::read_to_string(&key_path)
                .map_err(|e| ProxyError::Tls(format!("read ca key: {e}")))?;
            (cert_pem, key_pem)
        } else {
            let (cert_pem, key_pem) = generate_ca()?;
            fs::write(&cert_path, &cert_pem)
                .map_err(|e| ProxyError::Tls(format!("write ca cert: {e}")))?;
            fs::write(&key_path, &key_pem)
                .map_err(|e| ProxyError::Tls(format!("write ca key: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
            }
            tracing::info!(
                path = %cert_path.display(),
                "created Maxwell local CA — trust this cert in your browser/OS for HTTPS MITM"
            );
            (cert_pem, key_pem)
        };

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| ProxyError::Tls(format!("parse ca key: {e}")))?;
        let issuer_params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .map_err(|e| ProxyError::Tls(format!("parse ca cert: {e}")))?;
        let issuer = issuer_params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Tls(format!("rebuild issuer: {e}")))?;
        let cert_der = pem_to_der(&cert_pem)?;

        Ok(Self {
            cert_pem,
            cert_der,
            issuer,
            key_pair,
            cert_path,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Server TLS config presenting a leaf cert for `host`, signed by this CA.
    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(cfg) = cache.get(host) {
                return Ok(cfg.clone());
            }
        }

        let cfg = Arc::new(self.mint_server_config(host)?);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host.to_string(), cfg.clone());
        }
        Ok(cfg)
    }

    fn mint_server_config(&self, host: &str) -> Result<ServerConfig, ProxyError> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| ProxyError::Tls(format!("leaf params: {e}")))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(
            host.try_into()
                .map_err(|e| ProxyError::Tls(format!("san dns: {e}")))?,
        )];
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);

        let leaf_key =
            KeyPair::generate().map_err(|e| ProxyError::Tls(format!("leaf key: {e}")))?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key_pair)
            .map_err(|e| ProxyError::Tls(format!("sign leaf: {e}")))?;

        let certs = vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(self.cert_der.clone()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ProxyError::Tls(format!("server config: {e}")))
    }
}

fn generate_ca() -> Result<(String, String), ProxyError> {
    let key_pair =
        KeyPair::generate().map_err(|e| ProxyError::Tls(format!("ca key: {e}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| ProxyError::Tls(format!("ca params: {e}")))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Maxwell");
    params
        .distinguished_name
        .push(DnType::CommonName, "Maxwell Local CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProxyError::Tls(format!("self-sign ca: {e}")))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, ProxyError> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let parsed = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Tls(format!("parse pem: {e}")))?;
    parsed
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| ProxyError::Tls("no certificate in pem".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn creates_and_reloads_ca_and_mints_leaf() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("maxwell-ca-{stamp}"));
        let ca = CertificateAuthority::load_or_create(&dir).unwrap();
        assert!(ca.ca_cert_path().exists());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let cfg = ca.server_config_for_host("authorized-target.example").unwrap();
        let cfg2 = ca.server_config_for_host("authorized-target.example").unwrap();
        assert!(Arc::ptr_eq(&cfg, &cfg2));

        let reloaded = CertificateAuthority::load_or_create(&dir).unwrap();
        assert_eq!(ca.ca_cert_pem(), reloaded.ca_cert_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
