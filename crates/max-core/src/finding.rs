//! Capture history and analyst findings shared across the workbench.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::request::{HttpRequest, HttpResponse};

/// Unique id for a stored proxy capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CaptureId(pub Uuid);

impl CaptureId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CaptureId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CaptureId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One intercepted exchange kept for history / replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRecord {
    pub id: CaptureId,
    pub created_at: DateTime<Utc>,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub anomaly_signal: Option<String>,
}

impl CaptureRecord {
    pub fn new(
        request: HttpRequest,
        response: Option<HttpResponse>,
        anomaly_signal: Option<String>,
    ) -> Self {
        Self {
            id: CaptureId::new(),
            created_at: Utc::now(),
            request,
            response,
            anomaly_signal,
        }
    }
}

/// Unique id for an analyst finding / validation candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub Uuid);

impl FindingId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for FindingId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle of a finding in the operator queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Pending,
    Approved,
    Rejected,
}

/// Operator-console finding (analyst-gated; never auto-executed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: FindingId,
    pub created_at: DateTime<Utc>,
    pub target: String,
    pub rationale: String,
    pub status: FindingStatus,
    pub note: Option<String>,
}

impl Finding {
    pub fn pending(target: impl Into<String>, rationale: impl Into<String>) -> Self {
        Self {
            id: FindingId::new(),
            created_at: Utc::now(),
            target: target.into(),
            rationale: rationale.into(),
            status: FindingStatus::Pending,
            note: None,
        }
    }
}
