use max_core::{
    EventKind, HttpMethod, HttpRequest, HttpResponse, RawEvent, SessionRole,
};
use max_orchestrator::Orchestrator;
use std::collections::HashMap;

#[tokio::test]
async fn session_broadcasts_anomaly_to_subscribers() {
    let orch = Orchestrator::new();
    let session = orch.create_session().unwrap();
    let mut rx = session.bus().subscribe();

    session
        .join("alice", SessionRole::Analyst)
        .unwrap();

    let raw = RawEvent {
        session_id: session.id,
        source: "max-proxy".into(),
        kind: EventKind::Anomaly {
            request: HttpRequest {
                method: HttpMethod::Get,
                url: "https://authorized-target.example/api".into(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
            response: HttpResponse {
                status: 500,
                headers: HashMap::new(),
                body: b"SQLSTATE[HY000]".to_vec(),
            },
            signal: "database_error_string".into(),
        },
    };

    let published = session.ingest(raw).unwrap();
    let received = rx.recv().await.unwrap();

    assert_eq!(published.id.0, received.id.0);
    assert!(matches!(received.kind, EventKind::Anomaly { .. }));
}

#[tokio::test]
async fn observer_cannot_approve_validation() {
    let orch = Orchestrator::new();
    let session = orch.create_session().unwrap();
    session.join("viewer", SessionRole::Observer).unwrap();

    let err = session
        .decide_validation("viewer", uuid::Uuid::new_v4(), true, None)
        .unwrap_err();

    assert!(matches!(err, max_core::Error::PermissionDenied(_)));
}

#[tokio::test]
async fn lead_can_approve_validation() {
    let orch = Orchestrator::new();
    let session = orch.create_session().unwrap();
    let mut rx = session.bus().subscribe();

    session.join("lead", SessionRole::Lead).unwrap();
    let finding = uuid::Uuid::new_v4();

    session
        .decide_validation("lead", finding, true, Some("scoped lab only".into()))
        .unwrap();

    let event = rx.recv().await.unwrap();
    match event.kind {
        EventKind::ValidationDecision {
            finding_id,
            approved,
            ..
        } => {
            assert_eq!(finding_id, finding);
            assert!(approved);
        }
        other => panic!("unexpected kind: {other:?}"),
    }
}

#[tokio::test]
async fn annotation_requires_membership() {
    let orch = Orchestrator::new();
    let session = orch.create_session().unwrap();

    let err = session.annotate("ghost", "hello").unwrap_err();
    assert!(matches!(err, max_core::Error::NotFound(_)));
}
