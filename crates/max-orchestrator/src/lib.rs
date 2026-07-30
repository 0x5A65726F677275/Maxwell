//! Collaboration core for Maxwell.
//!
//! Fans [`max_core::RawEvent`] values into enriched [`max_core::Event`] streams
//! for in-process subscribers (proxy, binwalk, exploit) and, later, external
//! WebSocket clients.

pub mod bus;
pub mod session;

pub use bus::{EventBus, EventReceiver, EventSender};
pub use session::{Orchestrator, SessionHandle};

/// Crate identity for event `source` fields and capability negotiation.
pub const CRATE_NAME: &str = "max-orchestrator";
