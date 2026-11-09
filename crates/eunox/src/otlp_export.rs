//! OTLP metrics export: push the same series as `/metrics` to an OTLP gRPC
//! endpoint (an OpenTelemetry Collector, or any OTLP backend) on a timer.
//!
//! Counters are cumulative monotonic sums starting at process start; window
//! counts and source health are gauges. A failed export is logged and retried
//! on the next tick; it never affects ingest.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use opentelemetry_proto::tonic::common::v1::any_value::Value as Any;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value;
use opentelemetry_proto::tonic::metrics::v1::{
    AggregationTemporality, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use tonic::transport::Endpoint;

use crate::app::App;
use crate::render::ReportData;
use eunox_stats::CLASSES;

fn attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Any::StringValue(value.into())),
        }),
        ..Default::default()
    }
}

struct Times {
    start: u64,
    now: u64,
}

fn point(t: &Times, attrs: Vec<KeyValue>, value: u64) -> NumberDataPoint {
    NumberDataPoint {
        attributes: attrs,
        start_time_unix_nano: t.start,
        time_unix_nano: t.now,
        value: Some(Value::AsInt(i64::try_from(value).unwrap_or(i64::MAX))),
        ..Default::default()
    }
}

fn counter(name: &str, description: &str, points: Vec<NumberDataPoint>) -> Metric {
    Metric {
        name: name.into(),
        description: description.into(),
        unit: "1".into(),
        data: Some(Data::Sum(Sum {
            data_points: points,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        })),
        ..Default::default()
    }
}

fn gauge(name: &str, description: &str, points: Vec<NumberDataPoint>) -> Metric {
    Metric {
        name: name.into(),
        description: description.into(),
        unit: "1".into(),
        data: Some(Data::Gauge(Gauge {
            data_points: points,
        })),
        ..Default::default()
    }
}

/// The export request for the current counters. Agents are labelled by
/// catalog id only (`other` for everything else), as on `/metrics`.
pub fn build_request(
    d: &ReportData<'_>,
    start_unix_nano: u64,
    now_unix_nano: u64,
) -> ExportMetricsServiceRequest {
    let t = Times {
        start: start_unix_nano,
        now: now_unix_nano,
    };
    let mut by_agent: BTreeMap<(&'static str, &str), u64> = BTreeMap::new();
    for (key, n) in d.lifetime {
        *by_agent
            .entry((key.class.as_str(), key.agent.as_deref().unwrap_or("other")))
            .or_default() += n;
    }
    let i = d.ingest;
    let ingest = |name: &str, description: &str, n: u64| {
        counter(name, description, vec![point(&t, vec![], n)])
    };
    let mut metrics = vec![
        counter(
            "eunox.requests",
            "Requests classified, by class and catalog agent id (other for everything else).",
            by_agent
                .iter()
                .map(|((class, agent), n)| {
                    point(&t, vec![attr("class", class), attr("agent", agent)], *n)
                })
                .collect(),
        ),
        gauge(
            "eunox.window.requests",
            "Requests in the 24h window, by class.",
            CLASSES
                .iter()
                .map(|c| {
                    let n = d
                        .summary
                        .classes
                        .iter()
                        .find(|(k, _)| k == c)
                        .map_or(0, |(_, n)| *n);
                    point(&t, vec![attr("class", c.as_str())], n)
                })
                .collect(),
        ),
        ingest("eunox.ingest.lines", "Log lines received.", i.lines),
        ingest("eunox.ingest.records", "Log lines classified.", i.records),
        ingest(
            "eunox.ingest.parse_errors",
            "Log lines that couldn't be parsed.",
            i.parse_errors,
        ),
        ingest(
            "eunox.rdns.lookups",
            "Reverse-DNS lookups started.",
            i.rdns_lookups,
        ),
        ingest(
            "eunox.rdns.skipped",
            "Requests sent on without reverse DNS because too many lookups were in flight.",
            i.rdns_skipped,
        ),
    ];
    if !d.sources.is_empty() {
        metrics.push(gauge(
            "eunox.source.up",
            "Whether the last fetch of a key directory or range file succeeded.",
            d.sources
                .iter()
                .map(|s| {
                    let up = u64::from(s.last_error.is_none() && s.last_success.is_some());
                    point(&t, vec![attr("source", &s.id), attr("url", &s.url)], up)
                })
                .collect(),
        ));
    }
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    attr("service.name", "eunox"),
                    attr("service.version", env!("CARGO_PKG_VERSION")),
                ],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "eunox".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    ..Default::default()
                }),
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Export every `interval`, forever. The connection is made lazily and
/// re-established after failures; an error is logged once, then again only
/// after a success in between.
pub async fn run(app: Arc<App>, endpoint: String, interval: Duration) {
    let channel = match Endpoint::from_shared(endpoint.clone()) {
        Ok(e) => e.timeout(Duration::from_secs(10)).connect_lazy(),
        Err(e) => {
            eprintln!("eunox: OTLP metrics export disabled, bad endpoint {endpoint:?}: {e}");
            return;
        }
    };
    let mut client = MetricsServiceClient::new(channel);
    let start = unix_nanos();
    let mut failing = false;
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let request = app.render(|d| build_request(d, start, unix_nanos()));
        match client.export(request).await {
            Ok(_) => failing = false,
            Err(e) if !failing => {
                failing = true;
                eprintln!(
                    "eunox: OTLP metrics export to {endpoint} failed: {}",
                    e.message()
                );
            }
            Err(_) => {}
        }
    }
}
