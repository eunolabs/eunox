//! eunox ingest: gateway access logs in, classified request records out.
//!
//! Receivers ([`receive`]) normalize every log source into one
//! [`RequestRecord`]. The [`Pipeline`] verifies its signature at the log
//! timestamp, classifies it with `eunox-core`, and hands a
//! [`ClassifiedRecord`] to a [`RecordSink`]. Keys, IP ranges and reverse DNS
//! come from `eunox-directory`; nothing here sits in the request path.
//!
//! Sources so far: nginx JSON lines (see [`record::parse_nginx_json`] for the
//! `log_format`) over UDP syslog, TCP, or a replayed file; and OTLP logs over
//! gRPC ([`otlp`]), which Envoy's OpenTelemetry access logger sends; and Kong's
//! `http-log` plugin ([`kong`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod kong;
pub mod otlp;
pub mod pipeline;
pub mod receive;
pub mod record;

pub use kong::serve_kong;
pub use otlp::serve_otlp;
pub use pipeline::{
    ClassifiedRecord, DEFAULT_RDNS_IN_FLIGHT, IngestCounters, NoDns, Pipeline, RecordSink,
    SessionKey,
};
pub use receive::{MAX_LINE, read_lines, serve_tcp, serve_udp};
pub use record::{RequestRecord, parse_fields, parse_nginx_json};
