//! Kong's bundled `http-log` plugin: each request POSTed as JSON, or a JSON
//! array of requests when the plugin batches.
//!
//! Field mapping from Kong's log serializer:
//! - `started_at` (Unix milliseconds) is the timestamp.
//! - `request.uri` is the original path and query, before routing.
//! - `client_ip` is the client after Kong's `trusted_ips` / `real_ip_header`
//!   handling.
//! - `request.headers` (lowercase names; a repeated header is an array)
//!   gives `host`, `user-agent` and the three signature headers.
//! - `request.url` gives the scheme; `response.status` the status.

use std::convert::Infallible;
use std::io;
use std::sync::Arc;

use eunox_directory::DnsLookup;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value};
use tokio::net::TcpListener;

use crate::pipeline::Pipeline;
use crate::record::{RequestRecord, parse_fields};

/// Largest request body accepted. A batch of 100 entries is well under 1 MB.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// Parse one `http-log` body: a single entry, or an array of entries.
/// `Err` if it isn't JSON at all; otherwise one result per entry.
pub fn parse_kong_http_log(body: &[u8]) -> Result<Vec<Result<RequestRecord, String>>, String> {
    let json: Value =
        serde_json::from_slice(body).map_err(|e| format!("Kong http-log body is not JSON: {e}"))?;
    Ok(match json {
        Value::Array(entries) => entries.iter().map(entry).collect(),
        one => vec![entry(&one)],
    })
}

fn entry(v: &Value) -> Result<RequestRecord, String> {
    let request = v
        .get("request")
        .ok_or("Kong http-log entry has no \"request\"")?;
    let headers = request.get("headers").and_then(Value::as_object);
    // A repeated header arrives as an array; combine it as HTTP does.
    let header = |name: &str| -> Option<String> {
        match headers?.get(name)? {
            Value::String(s) => Some(s.clone()),
            Value::Array(parts) => {
                let parts: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
                (!parts.is_empty()).then(|| parts.join(", "))
            }
            _ => None,
        }
    };
    let url = request.get("url").and_then(Value::as_str).unwrap_or("");

    let mut f = Map::new();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(v) = value {
            f.insert(key.into(), Value::String(v));
        }
    };
    put(
        "ts",
        v.get("started_at")
            .and_then(Value::as_i64)
            .map(|ms| format!("{}.{:03}", ms.div_euclid(1000), ms.rem_euclid(1000))),
    );
    put(
        "method",
        request
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    put(
        "scheme",
        url.split_once("://").map(|(s, _)| s.to_ascii_lowercase()),
    );
    put(
        "authority",
        header("host").or_else(|| {
            url.split_once("://")
                .and_then(|(_, rest)| rest.split(['/', '?']).next())
                .map(str::to_owned)
        }),
    );
    put(
        "path",
        request
            .get("uri")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    put(
        "ip",
        v.get("client_ip")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    put(
        "status",
        v.get("response")
            .and_then(|r| r.get("status"))
            .and_then(Value::as_u64)
            .map(|s| s.to_string()),
    );
    put("ua", header("user-agent"));
    put("sig", header("signature"));
    put("sig_input", header("signature-input"));
    put("sig_agent", header("signature-agent"));
    parse_fields(&f)
}

/// Accept `http-log` POSTs on `listener` forever. Responds 200 once the body
/// is read (entries that can't be parsed are counted, not retried), 400 for a
/// body that isn't JSON, 413 for one over [`MAX_BODY`], 405 for anything but
/// POST.
pub async fn serve_kong<L: DnsLookup + 'static>(
    listener: TcpListener,
    pipeline: Arc<Pipeline<L>>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let pipeline = pipeline.clone();
                async move { Ok::<_, Infallible>(handle(&pipeline, req).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn handle<L: DnsLookup + 'static>(
    pipeline: &Pipeline<L>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "POST only\n");
    }
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            pipeline.reject_line(format!(
                "Kong http-log body over {MAX_BODY} bytes, or the connection broke"
            ));
            return reply(StatusCode::PAYLOAD_TOO_LARGE, "too large\n");
        }
    };
    match parse_kong_http_log(&body) {
        Ok(entries) => {
            for e in entries {
                pipeline.handle_parsed(e);
            }
            reply(StatusCode::OK, "ok\n")
        }
        Err(why) => {
            pipeline.reject_line(why);
            reply(StatusCode::BAD_REQUEST, "not JSON\n")
        }
    }
}

fn reply(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like Kong 3's log serializer output, trimmed.
    const ENTRY: &str = r#"{
        "request": {
            "method": "GET",
            "uri": "/pricing?ref=x",
            "url": "https://example.com:8443/pricing?ref=x",
            "headers": {
                "host": "example.com:8443",
                "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)",
                "signature-input": ["sig1=(\"@authority\");tag=\"web-bot-auth\"", "sig2=(\"@path\");tag=\"x\""],
                "signature": "sig1=:AAAA:"
            }
        },
        "response": { "status": 200 },
        "client_ip": "203.0.113.7",
        "started_at": 1735689660123
    }"#;

    #[test]
    fn one_entry() {
        let got = parse_kong_http_log(ENTRY.as_bytes()).unwrap();
        let r = got[0].as_ref().unwrap();
        assert_eq!(r.timestamp_ms, 1_735_689_660_123);
        assert_eq!(r.method, "GET");
        assert_eq!(r.scheme, "https");
        assert_eq!(r.authority, "example.com:8443");
        assert_eq!(r.target, "/pricing?ref=x");
        assert_eq!(r.client_ip.to_string(), "203.0.113.7");
        assert_eq!(r.status, Some(200));
        assert!(r.user_agent.contains("GPTBot"));
        assert_eq!(
            r.signature_input.as_deref(),
            Some(r#"sig1=("@authority");tag="web-bot-auth", sig2=("@path");tag="x""#),
            "repeated header lines are combined"
        );
        assert_eq!(r.signature.as_deref(), Some("sig1=:AAAA:"));
        assert_eq!(r.signature_agent, None);
    }

    #[test]
    fn batch_with_a_bad_entry() {
        let body = format!("[{ENTRY}, {{\"request\": {{}}}}, {{\"nope\": 1}}]");
        let got = parse_kong_http_log(body.as_bytes()).unwrap();
        assert_eq!(got.len(), 3);
        assert!(got[0].is_ok());
        assert!(got[1].as_ref().unwrap_err().contains("ts"), "{:?}", got[1]);
        assert!(got[2].as_ref().unwrap_err().contains("request"));
    }

    #[test]
    fn host_header_beats_the_url() {
        // Kong builds request.url from its own listener; signatures cover the
        // Host the client sent.
        let body = ENTRY.replace(
            "https://example.com:8443/pricing?ref=x",
            "http://kong.internal:8000/pricing?ref=x",
        );
        let got = parse_kong_http_log(body.as_bytes()).unwrap();
        assert_eq!(got[0].as_ref().unwrap().authority, "example.com:8443");
    }

    #[test]
    fn authority_falls_back_to_the_url() {
        let body = ENTRY.replace(r#""host": "example.com:8443","#, "");
        let got = parse_kong_http_log(body.as_bytes()).unwrap();
        assert_eq!(got[0].as_ref().unwrap().authority, "example.com:8443");
    }

    /// Captured from a live Kong 3.9.4 (testdata/kong-local.yaml plus a
    /// second route on `/edge` with `strip_path: true`), trimmed to the
    /// fields that matter. Kong logs the rewritten path as `upstream_uri`;
    /// a signature covers the path the client sent, `request.uri`.
    const LIVE_STRIPPED: &str = r#"[{
        "upstream_uri": "/healthz?x=1",
        "route": { "name": "stripped", "paths": ["/edge"], "strip_path": true },
        "client_ip": "127.0.0.1",
        "started_at": 1794182765484,
        "request": {
            "headers": { "host": "127.0.0.1:8000", "user-agent": "curl/8.5.0", "accept": "*/*" },
            "uri": "/edge/healthz?x=1",
            "method": "GET",
            "querystring": { "x": "1" },
            "url": "http://127.0.0.1:8000/edge/healthz?x=1"
        },
        "response": { "status": 200 }
    }]"#;

    #[test]
    fn live_kong_strip_path_keeps_the_client_path() {
        let got = parse_kong_http_log(LIVE_STRIPPED.as_bytes()).unwrap();
        let r = got[0].as_ref().unwrap();
        assert_eq!(r.target, "/edge/healthz?x=1", "not upstream_uri");
        assert_eq!(r.authority, "127.0.0.1:8000");
        assert_eq!(r.scheme, "http");
        assert_eq!(r.timestamp_ms, 1_794_182_765_484);
        assert_eq!(r.client_ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn not_json() {
        assert!(parse_kong_http_log(b"hello").is_err());
    }
}
