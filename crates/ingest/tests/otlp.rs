//! The OTLP logs receiver over real gRPC.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox_core::{Catalog, Class, IpNet};
use eunox_directory::Snapshot;
use eunox_ingest::{ClassifiedRecord, NoDns, Pipeline, serve_otlp};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::common::v1::any_value::Value as Any;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use tokio::net::TcpListener;

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Any::StringValue(value.into())),
        }),
        ..Default::default()
    }
}

fn envoy(ip: &str, ua: &str) -> LogRecord {
    LogRecord {
        time_unix_nano: 1_735_689_660_000_000_000,
        attributes: vec![
            kv("method", "GET"),
            kv("scheme", "http"),
            kv("authority", "example.com"),
            kv("path", "/"),
            kv("ip", ip),
            kv("status", "200"),
            kv("ua", ua),
            kv("sig", "-"),
            kv("sig_input", "-"),
            kv("sig_agent", "-"),
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn envoy_style_records_over_grpc() {
    let ranges = HashMap::from([(
        "openai-gptbot".to_owned(),
        vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
    )]);
    let snap = Arc::new(Snapshot::new(vec![], ranges, vec![]));
    let got: Arc<Mutex<Vec<ClassifiedRecord>>> = Arc::default();
    let sink = got.clone();
    let pipeline: Arc<Pipeline<NoDns>> = Arc::new(Pipeline::new(
        Arc::new(Catalog::seed()),
        Arc::new(move || snap.clone()),
        None,
        Arc::new(move |r: ClassifiedRecord| sink.lock().unwrap().push(r)),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_otlp(listener, pipeline.clone()));

    let mut client = LogsServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let gptbot = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)";
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![
                    envoy("203.0.113.7", gptbot),
                    envoy("192.0.2.7", gptbot),
                    envoy("203.0.113.8", "curl/8.5.0"),
                    LogRecord::default(),
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    client
        .export(request)
        .await
        .expect("export succeeds even with a bad record");

    for _ in 0..100 {
        if got.lock().unwrap().len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let got = got.lock().unwrap().clone();
    let class = |ip: &str| {
        got.iter()
            .find(|r| r.record.client_ip.to_string() == ip)
            .map(|r| r.class)
    };
    assert_eq!(class("203.0.113.7"), Some(Class::Spoofed));
    assert_eq!(class("192.0.2.7"), Some(Class::IpVerified));
    assert_eq!(class("203.0.113.8"), Some(Class::UnknownBot));

    let c = pipeline.counters();
    assert_eq!(c.lines.load(Ordering::Relaxed), 4);
    assert_eq!(c.records.load(Ordering::Relaxed), 3);
    assert_eq!(c.parse_errors.load(Ordering::Relaxed), 1);
}
