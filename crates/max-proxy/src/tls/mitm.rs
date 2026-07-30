//! HTTPS MITM over an upgraded CONNECT tunnel.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use max_orchestrator::SessionHandle;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

use crate::capture::{build_request, build_response, Capture};
use crate::server::ProxyError;
use crate::tls::CertificateAuthority;
use tokio_rustls::TlsAcceptor;

/// Terminate client TLS with a forged leaf, then forward HTTP to the real origin over TLS.
pub async fn intercept_https(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    port: u16,
    session: SessionHandle,
    ca: Arc<CertificateAuthority>,
) -> Result<(), ProxyError> {
    let server_config = ca.server_config_for_host(&host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(|e| ProxyError::Tls(format!("client tls accept: {e}")))?;

    let io = TokioIo::new(client_tls);
    let session = session.clone();
    let host = host.clone();

    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let session = session.clone();
                let host = host.clone();
                async move {
                    match forward_https(req, &host, port, &session).await {
                        Ok(resp) => Ok::<_, Infallible>(resp),
                        Err(err) => {
                            tracing::warn!(error = %err, host = %host, "https mitm exchange failed");
                            Ok(Response::builder()
                                .status(502)
                                .body(Full::new(Bytes::from(format!(
                                    "max-proxy mitm error: {err}"
                                ))))
                                .expect("valid response"))
                        }
                    }
                }
            }),
        )
        .await
        .map_err(|e| ProxyError::Tls(format!("mitm http: {e}")))?;

    Ok(())
}

async fn forward_https(
    req: Request<Incoming>,
    host: &str,
    port: u16,
    session: &SessionHandle,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target = if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    };

    let (parts, incoming) = req.into_parts();
    let body_bytes = incoming
        .collect()
        .await
        .map_err(|e| ProxyError::Body(e.to_string()))?
        .to_bytes();

    let outbound = build_origin_request(&method, &target, &headers, body_bytes.clone())?;
    let upstream_resp = send_rustls(host, outbound).await?;

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
        tracing::warn!(error = %err, "failed to emit https capture events");
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if name == http::header::TRANSFER_ENCODING || name == http::header::CONTENT_LENGTH {
            continue;
        }
        builder = builder.header(name, value);
    }
    Ok(builder
        .body(Full::new(resp_body))
        .map_err(|e| ProxyError::Internal(e.to_string()))?)
}

fn build_origin_request(
    method: &http::Method,
    target: &str,
    headers: &http::HeaderMap,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, ProxyError> {
    let uri: Uri = target
        .parse()
        .map_err(|e| ProxyError::InvalidRequest(format!("bad uri: {e}")))?;
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers.iter() {
        if name == http::header::HOST
            || name == http::header::CONNECTION
            || name == http::header::TRANSFER_ENCODING
            || name == http::header::CONTENT_LENGTH
            || name.as_str().eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Internal(e.to_string()))
}

async fn send_rustls(
    host: &str,
    req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, ProxyError> {
    let _ = ServerName::try_from(host.to_string())
        .map_err(|e| ProxyError::Tls(format!("server name: {e}")))?;

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);

    let mut req = req;
    if !req.headers().contains_key(http::header::HOST) {
        req.headers_mut().insert(
            http::header::HOST,
            host.parse()
                .map_err(|e| ProxyError::Internal(format!("host header: {e}")))?,
        );
    }

    client
        .request(req)
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))
}

/// Blind TCP tunnel (no interception) — used when MITM is disabled.
pub async fn blind_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: u16,
) -> Result<(), ProxyError> {
    let addr = format!("{host}:{port}");
    let mut upstream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ProxyError::Upstream(format!("connect {addr}: {e}")))?;
    let mut client = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(ProxyError::Io)?;
    Ok(())
}
