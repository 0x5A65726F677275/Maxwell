//! Live collaboration sessions managed by the orchestrator.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use max_core::{Event, EventKind, RawEvent, Result as CoreResult, SessionId, SessionRole};
use serde::{Deserialize, Serialize};

use crate::bus::EventBus;
use crate::CRATE_NAME;

/// Participant registered in a collaboration session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub name: String,
    pub role: SessionRole,
}

/// Handle to a single live session and its shared event bus.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    pub id: SessionId,
    bus: EventBus,
    participants: Arc<RwLock<HashMap<String, Participant>>>,
}

impl SessionHandle {
    fn new(id: SessionId, bus: EventBus) -> Self {
        Self {
            id,
            bus,
            participants: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    pub fn join(&self, name: impl Into<String>, role: SessionRole) -> CoreResult<()> {
        let name = name.into();
        let mut map = self
            .participants
            .write()
            .map_err(|_| max_core::Error::Internal("participants lock poisoned".into()))?;
        map.insert(
            name.clone(),
            Participant {
                name: name.clone(),
                role,
            },
        );
        tracing::info!(session = %self.id, participant = %name, ?role, "joined session");
        Ok(())
    }

    pub fn participants(&self) -> CoreResult<Vec<Participant>> {
        let map = self
            .participants
            .read()
            .map_err(|_| max_core::Error::Internal("participants lock poisoned".into()))?;
        Ok(map.values().cloned().collect())
    }

    /// Publish a producer event scoped to this session.
    pub fn ingest(&self, mut raw: RawEvent) -> CoreResult<Event> {
        raw.session_id = self.id;
        self.bus
            .publish_raw(raw)
            .map_err(|e| max_core::Error::Internal(e.to_string()))
    }

    /// Post a collaboration annotation (any role may annotate).
    pub fn annotate(&self, author: impl Into<String>, text: impl Into<String>) -> CoreResult<Event> {
        let author = author.into();
        self.require_participant(&author)?;
        self.ingest(RawEvent {
            session_id: self.id,
            source: CRATE_NAME.into(),
            kind: EventKind::Annotation {
                author,
                text: text.into(),
            },
        })
    }

    /// Analyst-gated validation decision. Only [`SessionRole::Lead`] or
    /// [`SessionRole::Analyst`] may approve/reject.
    pub fn decide_validation(
        &self,
        actor: &str,
        finding_id: uuid::Uuid,
        approved: bool,
        note: Option<String>,
    ) -> CoreResult<Event> {
        let role = self.require_participant(actor)?;
        match role {
            SessionRole::Analyst | SessionRole::Lead => {}
            SessionRole::Observer => {
                return Err(max_core::Error::PermissionDenied(
                    "observers cannot issue validation decisions".into(),
                ));
            }
        }

        self.ingest(RawEvent {
            session_id: self.id,
            source: CRATE_NAME.into(),
            kind: EventKind::ValidationDecision {
                finding_id,
                approved,
                note,
            },
        })
    }

    fn require_participant(&self, name: &str) -> CoreResult<SessionRole> {
        let map = self
            .participants
            .read()
            .map_err(|_| max_core::Error::Internal("participants lock poisoned".into()))?;
        map.get(name)
            .map(|p| p.role)
            .ok_or_else(|| max_core::Error::NotFound(format!("participant '{name}' not in session")))
    }
}

/// Top-level orchestrator: create/lookup sessions sharing a process-local bus topology.
#[derive(Clone, Default, Debug)]
pub struct Orchestrator {
    sessions: Arc<RwLock<HashMap<SessionId, SessionHandle>>>,
}

impl Orchestrator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new collaboration session with a dedicated event bus.
    pub fn create_session(&self) -> CoreResult<SessionHandle> {
        let id = SessionId::new();
        let handle = SessionHandle::new(id, EventBus::with_default_capacity());
        let mut map = self
            .sessions
            .write()
            .map_err(|_| max_core::Error::Internal("sessions lock poisoned".into()))?;
        map.insert(id, handle.clone());
        tracing::info!(session = %id, "session created");
        Ok(handle)
    }

    pub fn get_session(&self, id: SessionId) -> CoreResult<SessionHandle> {
        let map = self
            .sessions
            .read()
            .map_err(|_| max_core::Error::Internal("sessions lock poisoned".into()))?;
        map.get(&id)
            .cloned()
            .ok_or_else(|| max_core::Error::NotFound(format!("session {id}")))
    }

    pub fn session_count(&self) -> CoreResult<usize> {
        let map = self
            .sessions
            .read()
            .map_err(|_| max_core::Error::Internal("sessions lock poisoned".into()))?;
        Ok(map.len())
    }
}
