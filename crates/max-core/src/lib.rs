//! Shared data contracts and protocols for Maxwell.
//!
//! Every crate in the workspace depends on these types for cross-module
//! communication (proxy → orchestrator → analysis / UI).

pub mod binary;
pub mod error;
pub mod event;
pub mod finding;
pub mod request;
pub mod session;

pub use binary::{BinaryFormat, BinaryInfo, FunctionInfo, InstructionInfo};
pub use error::{Error, Result};
pub use event::{Event, EventKind, EventSeverity, RawEvent};
pub use finding::{CaptureId, CaptureRecord, Finding, FindingId, FindingStatus};
pub use request::{HttpMethod, HttpRequest, HttpResponse};
pub use session::{SessionId, SessionRole};

/// Platform crate identity — useful for logs and capability negotiation.
pub const PLATFORM_NAME: &str = "Maxwell";
pub const PLATFORM_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests;
