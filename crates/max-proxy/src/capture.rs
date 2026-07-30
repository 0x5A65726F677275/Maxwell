//! Conversion from proxy I/O into Maxwell core HTTP contracts + events.

use std::collections::HashMap;

use max_core::{Event, EventKind, HttpMethod, HttpRequest, HttpResponse, RawEvent};
use max_orchestrator::SessionHandle;

use crate::anomaly::detect_anomaly;
use crate::CRATE_NAME;

/// One intercepted request/response pair ready for session ingest.
#[derive(Debug, Clone)]
pub struct Capture {
    pub request: HttpRequest,
    pub response: HttpResponse,
}

impl Capture {
    /// Emit a proxy-capture event, plus an anomaly event when heuristics fire.
    pub fn emit(&self, session: &SessionHandle) -> max_core::Result<Vec<Event>> {
        let mut out = Vec::new();

        out.push(session.ingest(RawEvent {
            session_id: session.id,
            source: CRATE_NAME.into(),
            kind: EventKind::ProxyCapture {
                request: self.request.clone(),
                response: Some(self.response.clone()),
            },
        })?);

        if let Some(hit) = detect_anomaly(&self.response.body) {
            out.push(session.ingest(RawEvent {
                session_id: session.id,
                source: CRATE_NAME.into(),
                kind: EventKind::Anomaly {
                    request: self.request.clone(),
                    response: self.response.clone(),
                    signal: hit.signal,
                },
            })?);
        }

        Ok(out)
    }
}

/// Map an HTTP method string into [`HttpMethod`].
pub fn parse_method(method: &http::Method) -> HttpMethod {
    match *method {
        http::Method::GET => HttpMethod::Get,
        http::Method::POST => HttpMethod::Post,
        http::Method::PUT => HttpMethod::Put,
        http::Method::PATCH => HttpMethod::Patch,
        http::Method::DELETE => HttpMethod::Delete,
        http::Method::HEAD => HttpMethod::Head,
        http::Method::OPTIONS => HttpMethod::Options,
        http::Method::TRACE => HttpMethod::Trace,
        http::Method::CONNECT => HttpMethod::Connect,
        _ => HttpMethod::Get,
    }
}

/// Build Maxwell [`HttpRequest`] from hyper/http pieces.
pub fn build_request(
    method: &http::Method,
    url: String,
    headers: &http::HeaderMap,
    body: Vec<u8>,
) -> HttpRequest {
    HttpRequest {
        method: parse_method(method),
        url,
        headers: header_map_to_hash(headers),
        body,
    }
}

/// Build Maxwell [`HttpResponse`] from status / headers / body.
pub fn build_response(
    status: u16,
    headers: &http::HeaderMap,
    body: Vec<u8>,
) -> HttpResponse {
    HttpResponse {
        status,
        headers: header_map_to_hash(headers),
        body,
    }
}

fn header_map_to_hash(headers: &http::HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.insert(name.as_str().to_string(), v.to_string());
        }
    }
    map
}
