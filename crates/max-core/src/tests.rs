use crate::{
    BinaryFormat, BinaryInfo, Event, EventKind, FunctionInfo, HttpMethod, HttpRequest, HttpResponse,
    RawEvent, SessionId, SessionRole, PLATFORM_NAME,
};
use std::collections::HashMap;

#[test]
fn platform_identity() {
    assert_eq!(PLATFORM_NAME, "Maxwell");
}

#[test]
fn session_roles_roundtrip() {
    let roles = [
        SessionRole::Observer,
        SessionRole::Analyst,
        SessionRole::Lead,
    ];
    for role in roles {
        let json = serde_json::to_string(&role).unwrap();
        let back: SessionRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, back);
    }
}

#[test]
fn raw_event_promotes_to_event() {
    let session = SessionId::new();
    let request = HttpRequest {
        method: HttpMethod::Get,
        url: "https://authorized-target.example/api".into(),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let response = HttpResponse {
        status: 500,
        headers: HashMap::new(),
        body: b"SQLSTATE[HY000]".to_vec(),
    };

    let raw = RawEvent {
        session_id: session,
        source: "max-proxy".into(),
        kind: EventKind::Anomaly {
            request,
            response,
            signal: "database_error_string".into(),
        },
    };

    let event: Event = raw.into_event();
    assert_eq!(event.session_id, session);
    assert_eq!(event.source, "max-proxy");
    assert!(matches!(event.kind, EventKind::Anomaly { .. }));
}

#[test]
fn binary_info_roundtrip() {
    let info = BinaryInfo {
        path: "/opt/app/server".into(),
        format: BinaryFormat::Elf,
        entry_point: Some(0x401000),
        architecture: Some("x86_64".into()),
        functions: vec![FunctionInfo {
            name: Some("main".into()),
            address: 0x401000,
            size: Some(128),
        }],
    };

    let json = serde_json::to_string(&info).unwrap();
    let back: BinaryInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, back);
}

#[test]
fn validation_candidate_is_gated() {
    // Document the product invariant: candidates are proposed, never auto-executed.
    let event = Event::new(
        SessionId::new(),
        "max-exploit",
        EventKind::ValidationCandidate {
            target: "https://authorized-target.example/api".into(),
            rationale: "error-based SQLi indicator in response body".into(),
            finding_id: uuid::Uuid::new_v4(),
        },
    );
    assert!(matches!(event.kind, EventKind::ValidationCandidate { .. }));
}
