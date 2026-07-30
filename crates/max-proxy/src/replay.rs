//! Replay a stored HTTP request against an authorized target (plain HTTP).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use max_core::{HttpMethod, HttpRequest, HttpResponse};

use crate::capture::{build_response, Capture};
use crate::server::ProxyError;

/// Replay `request` and return a new capture pair. HTTPS replay uses hyper-rustls.
pub async fn replay_request(request: &HttpRequest) -> Result<Capture, ProxyError> {
    let method = method_to_http(&request.method);
    let body = Bytes::from(request.body.clone());

    let mut builder = Request::builder().method(method).uri(&request.url);
    for (k, v) in &request.headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let outbound = builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Internal(e.to_string()))?;

    let is_https = request.url.starts_with("https://");
    let upstream_resp = if is_https {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        client
            .request(outbound)
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?
    } else {
        let client = Client::builder(TokioExecutor::new()).build_http();
        client
            .request(outbound)
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?
    };

    let status = upstream_resp.status().as_u16();
    let headers = upstream_resp.headers().clone();
    let body = upstream_resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ProxyError::Body(e.to_string()))?
        .to_bytes();

    Ok(Capture {
        request: request.clone(),
        response: build_response(status, &headers, body.to_vec()),
    })
}

fn method_to_http(method: &HttpMethod) -> http::Method {
    match method {
        HttpMethod::Get => http::Method::GET,
        HttpMethod::Post => http::Method::POST,
        HttpMethod::Put => http::Method::PUT,
        HttpMethod::Patch => http::Method::PATCH,
        HttpMethod::Delete => http::Method::DELETE,
        HttpMethod::Head => http::Method::HEAD,
        HttpMethod::Options => http::Method::OPTIONS,
        HttpMethod::Trace => http::Method::TRACE,
        HttpMethod::Connect => http::Method::CONNECT,
    }
}

/// Helper so callers can turn a replay into an [`HttpResponse`] only.
pub fn response_only(capture: Capture) -> HttpResponse {
    capture.response
}
