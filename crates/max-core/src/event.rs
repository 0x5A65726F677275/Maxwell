//! Event types broadcast by the orchestrator.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::binary::BinaryInfo;
use crate::request::{HttpRequest, HttpResponse};
use crate::session::SessionId;

/// Unique identifier for a single event in a session stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Severity hint for UI highlighting and alert routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Discriminated payload kinds carried by [`Event`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// Raw proxy capture before enrichment.
    ProxyCapture {
        request: HttpRequest,
        response: Option<HttpResponse>,
    },
    /// Anomalous response flagged by the proxy (e.g. DB error string).
    Anomaly {
        request: HttpRequest,
        response: HttpResponse,
        signal: String,
    },
    /// Binary analysis result from max-binwalk.
    BinaryAnalysis { info: BinaryInfo },
    /// Validation / PoC candidate — requires analyst sign-off before execution.
    ValidationCandidate {
        target: String,
        rationale: String,
        /// Opaque finding id from the producing module.
        finding_id: Uuid,
    },
    /// Analyst approved or rejected a validation candidate.
    ValidationDecision {
        finding_id: Uuid,
        approved: bool,
        note: Option<String>,
    },
    /// Free-form collaboration annotation from a session participant.
    Annotation { author: String, text: String },
}

/// Enriched event fan-out to internal subscribers and external WebSocket clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub session_id: SessionId,
    pub severity: EventSeverity,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub kind: EventKind,
}

impl Event {
    pub fn new(session_id: SessionId, source: impl Into<String>, kind: EventKind) -> Self {
        let severity = match &kind {
            EventKind::Anomaly { .. } => EventSeverity::High,
            EventKind::ValidationCandidate { .. } => EventSeverity::Medium,
            EventKind::ValidationDecision { approved: true, .. } => EventSeverity::High,
            EventKind::ValidationDecision { approved: false, .. } => EventSeverity::Info,
            EventKind::BinaryAnalysis { .. } => EventSeverity::Info,
            EventKind::ProxyCapture { .. } => EventSeverity::Info,
            EventKind::Annotation { .. } => EventSeverity::Info,
        };

        Self {
            id: EventId::new(),
            session_id,
            severity,
            created_at: Utc::now(),
            source: source.into(),
            kind,
        }
    }
}

/// Lightweight envelope emitted by producers (e.g. max-proxy) before orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub session_id: SessionId,
    pub source: String,
    pub kind: EventKind,
}

impl RawEvent {
    pub fn into_event(self) -> Event {
        Event::new(self.session_id, self.source, self.kind)
    }
}
