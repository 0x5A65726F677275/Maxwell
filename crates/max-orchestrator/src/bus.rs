//! In-process event broadcast bus built on `tokio::sync::broadcast`.

use max_core::{Event, RawEvent};
use tokio::sync::broadcast;

/// Default capacity for the broadcast channel (events retained for slow consumers).
pub const DEFAULT_CAPACITY: usize = 1024;

/// Producer handle — clone freely across modules.
pub type EventSender = broadcast::Sender<Event>;

/// Consumer handle — each subscriber gets its own receiver.
pub type EventReceiver = broadcast::Receiver<Event>;

/// Shared fan-out bus: ingest raw producer events, broadcast enriched events.
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: EventSender,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Subscribe to the live event stream.
    pub fn subscribe(&self) -> EventReceiver {
        self.tx.subscribe()
    }

    /// Promote a [`RawEvent`] and broadcast it. Returns the enriched event.
    pub fn publish_raw(&self, raw: RawEvent) -> Result<Event, PublishError> {
        let event = raw.into_event();
        self.publish(event)
    }

    /// Broadcast an already-enriched [`Event`].
    pub fn publish(&self, event: Event) -> Result<Event, PublishError> {
        match self.tx.send(event.clone()) {
            Ok(_subscriber_count) => {
                tracing::debug!(
                    event_id = %event.id,
                    source = %event.source,
                    "event published"
                );
                Ok(event)
            }
            // `SendError` only when there are zero active receivers — still fine
            // for producers that fire before anyone listens.
            Err(broadcast::error::SendError(event)) => {
                tracing::trace!(
                    event_id = %event.id,
                    "published with zero subscribers"
                );
                Ok(event)
            }
        }
    }

    /// Number of active subscribers (approximate; for diagnostics).
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

/// Errors that can occur when publishing (reserved for future backpressure policy).
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("event bus closed")]
    Closed,
}
