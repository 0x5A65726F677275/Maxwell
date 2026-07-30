//! Forward HTTP(S) proxy with optional HTTPS MITM.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use max_orchestrator::SessionHandle;
use tokio::net::TcpListener;

use crate::capture::{build_request, build_response, Capture};
use crate::tls::mitm::blind_tunnel;
use crate::tls::{default_ca_dir, intercept_https, CertificateAuthority};

/// Proxy listen / behavior configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    /// Directory for the local MITM CA (`ca.pem` / `ca.key.pem`).
    pub ca_dir: PathBuf,
    /// When true, CONNECT tunnels are decrypted with a local CA leaf.
    pub mitm: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8888)),
            ca_dir: default_ca_dir(),
            mitm: true,
        }
    }
}

/// Running proxy bound to a collaboration session.
#[derive(Clone)]
pub struct ProxyServer {
    config: ProxyConfig,
    session: SessionHandle,
    ca: Arc<CertificateAuthority>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig, session: SessionHandle) -> Result<Self, ProxyError> {
        let ca = Arc::new(CertificateAuthority::load_or_create(&config.ca_dir)?);
        Ok(Self {
            config,
            session,
            ca,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    pub fn ca_cert_path(&self) -> &std::path::Path {
        self.ca.ca_cert_path()
    }

    /// Accept connections until the listener fails. Intended to run on a Tokio task.
    pub async fn serve(self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.config.listen).await?;
        tracing::info!(
            addr = %self.config.listen,
            mitm = self.config.mitm,
            ca = %self.ca.ca_cert_path().display(),
            "max-proxy listening"
        );

        loop {
            let (stream, peer) = listener.accept().await?;
            let session = self.session.clone();
            let ca = self.ca.clone();
            let mitm = self.config.mitm;
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let session = session.clone();
                    let ca = ca.clone();
                    async move { handle_request(req, session, ca, mitm).await }
                });

                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!(%peer, error = %err, "connection closed with error");
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    session: SessionHandle,
    ca: Arc<CertificateAuthority>,
    mitm: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, session, ca, mitm));
    }

    match proxy_http(req, &session).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::warn!(error = %err, "proxy exchange failed");
            Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("max-proxy error: {err}"))))
                .expect("valid response"))
        }
    }
}

fn handle_connect(
    req: Request<Incoming>,
    session: SessionHandle,
    ca: Arc<CertificateAuthority>,
    mitm: bool,
) -> Response<Full<Bytes>> {
    let authority = match req.uri().authority() {
        Some(a) => a.clone(),
        None => {
            return Response::builder()
                .status(400)
                .body(Full::new(Bytes::from("CONNECT requires authority")))
                .expect("valid response");
        }
    };

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let result = if mitm {
                    intercept_https(upgraded, host.clone(), port, session, ca).await
                } else {
                    blind_tunnel(upgraded, &host, port).await
                };
                if let Err(err) = result {
                    tracing::debug!(%host, port, error = %err, "connect tunnel ended");
                }
            }
            Err(err) => tracing::warn!(error = %err, "CONNECT upgrade failed"),
        }
    });

    Response::builder()
        .status(200)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
}

async fn proxy_http(
    req: Request<Incoming>,
    session: &SessionHandle,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let method = req.method().clone();
    let (parts, incoming) = req.into_parts();
    let target = absolute_url(&parts.uri)?;
    let body_bytes = incoming
        .collect()
        .await
        .map_err(|e| ProxyError::Body(e.to_string()))?
        .to_bytes();

    let outbound = build_outbound(&method, &target, &parts.headers, body_bytes.clone())?;
    let upstream = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let upstream_resp = upstream
        .request(outbound)
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;

    let status = upstream_resp.status().as_u16();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = upstream_resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ProxyError::Body(e.to_string()))?
        .to_bytes();

    let capture = Capture {
        request: build_request(&parts.method, target, &parts.headers, body_bytes.to_vec()),
        response: build_response(status, &resp_headers, resp_body.to_vec()),
    };

    if let Err(err) = capture.emit(session) {
        tracing::warn!(error = %err, "failed to emit capture events");
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        builder = builder.header(name, value);
    }
    Ok(builder
        .body(Full::new(resp_body))
        .map_err(|e| ProxyError::Internal(e.to_string()))?)
}

fn absolute_url(uri: &http::Uri) -> Result<String, ProxyError> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.to_string());
    }
    Err(ProxyError::InvalidRequest(
        "absolute-form URI required (use as HTTP proxy, not reverse origin)".into(),
    ))
}

fn build_outbound(
    method: &http::Method,
    target: &str,
    headers: &http::HeaderMap,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, ProxyError> {
    let mut builder = Request::builder().method(method).uri(target);
    for (name, value) in headers.iter() {
        if name == http::header::HOST || name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Internal(e.to_string()))
}

/// Proxy-layer errors (not part of the shared max-core error taxonomy).
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("body error: {0}")]
    Body(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("internal error: {0}")]
    Internal(String),
}
