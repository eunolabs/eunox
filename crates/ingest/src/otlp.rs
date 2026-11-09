//! OTLP logs over gRPC: Envoy's OpenTelemetry access logger, or an
//! OpenTelemetry Collector forwarding access logs.
//!
//! Each log record becomes one request record:
//! - **Attributes** named like the nginx JSON fields (`method`, `scheme`,
//!   `authority`, `path`, `ip`, `status`, `ua`, `sig`, `sig_input`,
//!   `sig_agent`, optionally `ts`) are read with the same rules. This is what
//!   the Envoy snippet in `docs/design.md` sends.
//! - **Without a `ts` attribute,** the record's own time is used; Envoy sets
//!   it to the request's start time.
//! - **A record with no recognized attributes** whose body is a JSON object
//!   string is parsed as an nginx JSON line.

use std::io;
use std::sync::Arc;

use eunox_directory::DnsLookup;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value as Any;
use opentelemetry_proto::tonic::logs::v1::LogRecord;
use serde_json::{Map, Value};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use crate::pipeline::Pipeline;
use crate::record::{RequestRecord, json_payload, parse_fields, parse_nginx_json};

/// The attribute names read from a log record.
pub const FIELDS: [&str; 12] = [
    "ts",
    "method",
    "scheme",
    "host",
    "authority",
    "path",
    "ip",
    "status",
    "ua",
    "sig",
    "sig_input",
    "sig_agent",
];

/// Turn one OTLP log record into a request record.
pub fn parse_log_record(record: &LogRecord) -> Result<RequestRecord, String> {
    let mut fields = Map::new();
    for kv in &record.attributes {
        if !FIELDS.contains(&kv.key.as_str()) {
            continue;
        }
        let value = match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
            Some(Any::StringValue(s)) => Value::String(s.clone()),
            Some(Any::IntValue(n)) => Value::from(*n),
            Some(Any::DoubleValue(n)) => Value::from(*n),
            _ => continue,
        };
        fields.insert(kv.key.clone(), value);
    }

    if fields.is_empty() {
        return match record.body.as_ref().and_then(|b| b.value.as_ref()) {
            Some(Any::StringValue(body)) => match json_payload(body.as_bytes()) {
                Some(json) => parse_nginx_json(json),
                None => Err("OTLP log record has no eunox attributes and no JSON body".into()),
            },
            _ => Err("OTLP log record has no eunox attributes and no JSON body".into()),
        };
    }

    if !fields.contains_key("ts") {
        let nanos = if record.time_unix_nano > 0 {
            record.time_unix_nano
        } else {
            record.observed_time_unix_nano
        };
        if nanos > 0 {
            let millis = nanos / 1_000_000;
            fields.insert(
                "ts".into(),
                Value::String(format!("{}.{:03}", millis / 1000, millis % 1000)),
            );
        }
    }
    parse_fields(&fields)
}

struct Logs<L> {
    pipeline: Arc<Pipeline<L>>,
}

#[tonic::async_trait]
impl<L: DnsLookup + 'static> LogsService for Logs<L> {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        for resource in &request.get_ref().resource_logs {
            for scope in &resource.scope_logs {
                for record in &scope.log_records {
                    self.pipeline.handle_parsed(parse_log_record(record));
                }
            }
        }
        // Records that can't be parsed are counted and reported on the report
        // page; rejecting them here would only make the sender retry.
        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: None,
        }))
    }
}

/// Serve the OTLP logs gRPC service on `listener` forever.
pub async fn serve_otlp<L: DnsLookup + 'static>(
    listener: TcpListener,
    pipeline: Arc<Pipeline<L>>,
) -> io::Result<()> {
    tonic::transport::Server::builder()
        .add_service(LogsServiceServer::new(Logs { pipeline }))
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};

    fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(AnyValue {
                value: Some(Any::StringValue(value.into())),
            }),
            ..Default::default()
        }
    }

    /// What the Envoy snippet sends: one attribute per field, `-` for a
    /// missing header, and the start time as the record time.
    fn envoy_record() -> LogRecord {
        LogRecord {
            time_unix_nano: 1_735_689_660_123_000_000,
            attributes: vec![
                kv("method", "GET"),
                kv("scheme", "https"),
                kv("authority", "example.com:8443"),
                kv("path", "/pricing?x=1"),
                kv("ip", "203.0.113.7"),
                kv("status", "200"),
                kv("ua", "Mozilla/5.0 (compatible; GPTBot/1.2)"),
                kv("sig", "-"),
                kv("sig_input", "-"),
                kv("sig_agent", "-"),
                kv("unrelated", "ignored"),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn envoy_attributes() {
        let r = parse_log_record(&envoy_record()).unwrap();
        assert_eq!(
            r.timestamp_ms, 1_735_689_660_123,
            "record time, to the millisecond"
        );
        assert_eq!(r.authority, "example.com:8443");
        assert_eq!(r.target, "/pricing?x=1");
        assert_eq!(r.client_ip.to_string(), "203.0.113.7");
        assert_eq!(r.status, Some(200));
        assert_eq!(r.signature, None, "`-` is a missing header");
        assert!(r.user_agent.contains("GPTBot"));
    }

    #[test]
    fn explicit_ts_attribute_wins() {
        let mut rec = envoy_record();
        rec.attributes.push(kv("ts", "2025-01-01T00:02:00Z"));
        assert_eq!(
            parse_log_record(&rec).unwrap().timestamp_ms,
            1_735_689_720_000
        );
    }

    #[test]
    fn falls_back_to_observed_time() {
        let mut rec = envoy_record();
        rec.time_unix_nano = 0;
        rec.observed_time_unix_nano = 1_735_689_661_000_000_000;
        assert_eq!(
            parse_log_record(&rec).unwrap().timestamp_ms,
            1_735_689_661_000
        );
    }

    #[test]
    fn json_body_from_a_collector() {
        let rec = LogRecord {
            body: Some(AnyValue {
                value: Some(Any::StringValue(
                    r#"{"ts":"1735689660","ip":"192.0.2.9","ua":"curl/8"}"#.into(),
                )),
            }),
            ..Default::default()
        };
        let r = parse_log_record(&rec).unwrap();
        assert_eq!(r.client_ip.to_string(), "192.0.2.9");
    }

    #[test]
    fn unusable_records_are_errors() {
        assert!(parse_log_record(&LogRecord::default()).is_err());
        let rec = LogRecord {
            attributes: vec![kv("ip", "203.0.113.7")],
            ..Default::default()
        };
        assert!(
            parse_log_record(&rec).unwrap_err().contains("ts"),
            "no time at all"
        );
    }
}
