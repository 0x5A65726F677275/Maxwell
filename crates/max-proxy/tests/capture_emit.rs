use max_core::{EventKind, HttpMethod, HttpRequest, HttpResponse, SessionRole};
use max_orchestrator::Orchestrator;
use max_proxy::Capture;
use std::collections::HashMap;

#[tokio::test]
async fn capture_emits_proxy_and_anomaly_events() {
    let orch = Orchestrator::new();
    let session = orch.create_session().unwrap();
    session.join("analyst", SessionRole::Analyst).unwrap();
    let mut rx = session.bus().subscribe();

    let capture = Capture {
        request: HttpRequest {
            method: HttpMethod::Get,
            url: "http://authorized-target.example/login".into(),
            headers: HashMap::new(),
            body: Vec::new(),
        },
        response: HttpResponse {
            status: 500,
            headers: HashMap::new(),
            body: b"SQLSTATE[HY000] dial error".to_vec(),
        },
    };

    let events = capture.emit(&session).unwrap();
    assert_eq!(events.len(), 2);

    let first = rx.recv().await.unwrap();
    let second = rx.recv().await.unwrap();

    assert!(matches!(first.kind, EventKind::ProxyCapture { .. }));
    assert!(matches!(second.kind, EventKind::Anomaly { .. }));
}
