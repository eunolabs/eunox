//! OTLP metrics export against a mock OTLP collector.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox::{Config, start};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value as Any;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value;
use opentelemetry_proto::tonic::metrics::v1::{AggregationTemporality, NumberDataPoint};
use tokio::net::{TcpListener, UdpSocket};
use tokio_stream::wrappers::TcpListenerStream;

#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<ExportMetricsServiceRequest>>>);

#[tonic::async_trait]
impl MetricsService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        self.0.lock().unwrap().push(request.into_inner());
        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

fn config(endpoint: &str) -> Config {
    let vars = HashMap::from([
        ("EUNOX_SYSLOG_UDP", "127.0.0.1:0".to_owned()),
        ("EUNOX_OTLP_GRPC", "off".to_owned()),
        ("EUNOX_KONG_HTTP", "off".to_owned()),
        ("EUNOX_HTTP", "127.0.0.1:0".to_owned()),
        ("EUNOX_RDNS", "off".to_owned()),
        ("EUNOX_SEED_SOURCES", "off".to_owned()),
        ("EUNOX_OTLP_METRICS_ENDPOINT", endpoint.to_owned()),
    ]);
    let mut c = Config::from_vars(|k| vars.get(k).cloned()).unwrap();
    // The config enforces at least 5s; tests go faster.
    c.otlp_metrics_interval = Duration::from_millis(100);
    c
}

const LINE: &str = r#"{"ts":"2025-01-01T00:01:00Z","method":"GET","host":"example.com","path":"/","ip":"203.0.113.7","ua":"Mozilla/5.0 (compatible; GPTBot/1.2)"}"#;
/// Its row label is the user-agent marker `curl/`, which a client chooses.
const CURL: &str = r#"{"ts":"2025-01-01T00:01:00Z","method":"GET","host":"example.com","path":"/","ip":"203.0.113.8","ua":"curl/8.5.0"}"#;

fn int(p: &NumberDataPoint) -> i64 {
    match p.value {
        Some(Value::AsInt(n)) => n,
        _ => panic!("not an int point: {p:?}"),
    }
}

fn attr<'a>(p: &'a NumberDataPoint, key: &str) -> Option<&'a str> {
    p.attributes.iter().find(|kv| kv.key == key).and_then(|kv| {
        match kv.value.as_ref()?.value.as_ref()? {
            Any::StringValue(s) => Some(s.as_str()),
            _ => None,
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn pushes_counters_and_gauges() {
    let collector = Collector::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = MetricsServiceServer::new(collector.clone());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    let running = start(&config(&format!("http://{addr}"))).await.unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for line in [LINE, CURL] {
        sock.send_to(line.as_bytes(), running.syslog_udp.unwrap())
            .await
            .unwrap();
    }

    // Wait for an export that includes the request.
    let mut found = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = collector.0.lock().unwrap().clone();
        if let Some(req) = got.into_iter().rev().find(|r| {
            r.resource_metrics[0].scope_metrics[0]
                .metrics
                .iter()
                .any(|m| m.name == "eunox.ingest.records" && matches!(&m.data, Some(Data::Sum(s)) if s.data_points.iter().any(|p| int(p) == 2)))
        }) {
            found = Some(req);
            break;
        }
    }
    let req = found.expect("an export with the request counted");
    let rm = &req.resource_metrics[0];
    let service = rm
        .resource
        .as_ref()
        .unwrap()
        .attributes
        .iter()
        .find(|kv| kv.key == "service.name")
        .unwrap();
    assert!(
        matches!(service.value.as_ref().unwrap().value, Some(Any::StringValue(ref s)) if s == "eunox")
    );

    let metrics = &rm.scope_metrics[0].metrics;
    let by_name = |name: &str| {
        metrics
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("no {name}"))
    };

    let Some(Data::Sum(requests)) = &by_name("eunox.requests").data else {
        panic!("requests is a sum")
    };
    assert!(requests.is_monotonic);
    assert_eq!(
        requests.aggregation_temporality,
        AggregationTemporality::Cumulative as i32
    );
    // No ranges loaded: a GPTBot claim is unverifiable, never spoofed.
    let point = |agent: &str| {
        requests
            .data_points
            .iter()
            .find(|p| attr(p, "agent") == Some(agent))
            .unwrap_or_else(|| panic!("no point for agent {agent}"))
    };
    let p = point("openai-gptbot");
    assert_eq!((attr(p, "class"), int(p)), (Some("unknown-bot"), 1));
    // A client-chosen label never becomes a series.
    assert_eq!(int(point("other")), 1);
    assert!(
        requests
            .data_points
            .iter()
            .all(|p| attr(p, "agent") != Some("curl/"))
    );
    assert!(p.start_time_unix_nano > 0 && p.time_unix_nano >= p.start_time_unix_nano);

    let Some(Data::Gauge(window)) = &by_name("eunox.window.requests").data else {
        panic!("window is a gauge")
    };
    assert_eq!(window.data_points.len(), 5, "one point per class");
    for name in [
        "eunox.ingest.lines",
        "eunox.ingest.parse_errors",
        "eunox.rdns.lookups",
        "eunox.rdns.skipped",
    ] {
        by_name(name);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_collector_does_not_affect_ingest() {
    // Nothing listens on this port.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let running = start(&config(&format!("http://127.0.0.1:{port}")))
        .await
        .unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(LINE.as_bytes(), running.syslog_udp.unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let records = running
        .app
        .pipeline
        .counters()
        .records
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(records, 1);
}
