//! Session identifiers and collaboration roles.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a live collaboration session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Role of a participant in a collaboration session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    /// Can observe and annotate; cannot issue commands.
    Observer,
    /// Can annotate and issue non-destructive commands.
    Analyst,
    /// Full control, including analyst-gated validation approvals.
    Lead,
}
