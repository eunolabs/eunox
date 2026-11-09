//! Configuration, from environment variables only.

use std::net::SocketAddr;
use std::time::Duration;

use eunox_directory::{KeySource, RangeSource, Sources};

/// Default UDP address for nginx syslog.
pub const DEFAULT_SYSLOG_UDP: &str = "0.0.0.0:5140";
/// Default address for OTLP logs over gRPC (Envoy's OpenTelemetry access
/// logger), the standard OTLP gRPC port.
pub const DEFAULT_OTLP_GRPC: &str = "0.0.0.0:4317";
/// Default address for Kong's `http-log` plugin to POST to.
pub const DEFAULT_KONG_HTTP: &str = "0.0.0.0:8041";
/// Default address for the report page and `/metrics`.
pub const DEFAULT_HTTP: &str = "0.0.0.0:8040";

/// Everything `eunox serve` needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `EUNOX_SYSLOG_UDP`: UDP syslog listener, or `off`.
    pub syslog_udp: Option<SocketAddr>,
    /// `EUNOX_LINES_TCP`: newline-delimited JSON over TCP, off unless set.
    pub lines_tcp: Option<SocketAddr>,
    /// `EUNOX_OTLP_GRPC`: OTLP logs over gRPC, or `off`.
    pub otlp_grpc: Option<SocketAddr>,
    /// `EUNOX_KONG_HTTP`: Kong `http-log` endpoint, or `off`.
    pub kong_http: Option<SocketAddr>,
    /// `EUNOX_HTTP`: report page, `/report.txt`, `/metrics`, `/healthz`.
    pub http: SocketAddr,
    /// `EUNOX_RDNS`: forward-confirmed reverse DNS, `on` (default) or `off`.
    pub rdns: bool,
    /// `EUNOX_REFRESH_SECS`: how often key directories and ranges are
    /// re-fetched (default 3600).
    pub refresh: Duration,
    /// `EUNOX_OTLP_METRICS_ENDPOINT`: push metrics to this OTLP gRPC
    /// endpoint (`http://collector:4317`), off unless set.
    pub otlp_metrics_endpoint: Option<String>,
    /// `EUNOX_OTLP_METRICS_INTERVAL_SECS`: export interval (default 60).
    pub otlp_metrics_interval: Duration,
    /// `EUNOX_SEED_SOURCES`: fetch the built-in operator sources, `on`
    /// (default) or `off`.
    pub seed_sources: bool,
    /// `EUNOX_KEY_DIRECTORIES`: extra key directories, `operator=url,...`.
    pub key_directories: Vec<KeySource>,
    /// `EUNOX_RANGES`: extra range files, `set-id=url,...`. The set id must
    /// match an agent's `ip_ranges` in the catalog to be used.
    pub ranges: Vec<RangeSource>,
}

impl Config {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// Read from any variable lookup (for tests).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |k: &str| {
            get(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let addr = |k: &str, default: Option<&str>| -> Result<Option<SocketAddr>, String> {
            match var(k).as_deref().or(default) {
                None | Some("off") => Ok(None),
                Some(v) => v
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("{k}: {v:?} is not an address like 0.0.0.0:5140")),
            }
        };
        let flag = |k: &str| -> Result<bool, String> {
            match var(k).as_deref() {
                None | Some("on" | "true" | "1") => Ok(true),
                Some("off" | "false" | "0") => Ok(false),
                Some(v) => Err(format!("{k}: {v:?} must be on or off")),
            }
        };
        let refresh = match var("EUNOX_REFRESH_SECS") {
            None => 3600,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n >= 60 => n,
                _ => {
                    return Err(format!(
                        "EUNOX_REFRESH_SECS: {v:?} must be a number of seconds, at least 60"
                    ));
                }
            },
        };
        let otlp_metrics_endpoint = match var("EUNOX_OTLP_METRICS_ENDPOINT") {
            None => None,
            Some(v) if v == "off" => None,
            Some(v) if v.starts_with("http://") || v.starts_with("https://") => Some(v),
            Some(v) => {
                return Err(format!(
                    "EUNOX_OTLP_METRICS_ENDPOINT: {v:?} must be an http(s) URL like http://collector:4317"
                ));
            }
        };
        let otlp_metrics_interval = match var("EUNOX_OTLP_METRICS_INTERVAL_SECS") {
            None => 60,
            Some(v) => match v.parse::<u64>() {
                Ok(n) if n >= 5 => n,
                _ => {
                    return Err(format!(
                        "EUNOX_OTLP_METRICS_INTERVAL_SECS: {v:?} must be a number of seconds, at least 5"
                    ));
                }
            },
        };
        let http = addr("EUNOX_HTTP", Some(DEFAULT_HTTP))?
            .ok_or("EUNOX_HTTP can't be off: it serves the report")?;
        Ok(Self {
            syslog_udp: addr("EUNOX_SYSLOG_UDP", Some(DEFAULT_SYSLOG_UDP))?,
            lines_tcp: addr("EUNOX_LINES_TCP", None)?,
            otlp_grpc: addr("EUNOX_OTLP_GRPC", Some(DEFAULT_OTLP_GRPC))?,
            kong_http: addr("EUNOX_KONG_HTTP", Some(DEFAULT_KONG_HTTP))?,
            http,
            rdns: flag("EUNOX_RDNS")?,
            otlp_metrics_endpoint,
            otlp_metrics_interval: Duration::from_secs(otlp_metrics_interval),
            refresh: Duration::from_secs(refresh),
            seed_sources: flag("EUNOX_SEED_SOURCES")?,
            key_directories: pairs("EUNOX_KEY_DIRECTORIES", var("EUNOX_KEY_DIRECTORIES"))?
                .into_iter()
                .map(|(operator, url)| KeySource { operator, url })
                .collect(),
            ranges: pairs("EUNOX_RANGES", var("EUNOX_RANGES"))?
                .into_iter()
                .map(|(id, url)| RangeSource { id, url })
                .collect(),
        })
    }

    /// The sources to fetch: the seed list (unless turned off) plus extras.
    pub fn sources(&self) -> Sources {
        let mut s = if self.seed_sources {
            Sources::seed()
        } else {
            Sources::default()
        };
        s.keys.extend(self.key_directories.iter().cloned());
        s.ranges.extend(self.ranges.iter().cloned());
        s
    }
}

/// Parse `id=url,id=url`. Ids are lowercase letters, digits, `-`, `_`, `.`;
/// URLs must be http(s).
fn pairs(name: &str, value: Option<String>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (id, url) = p
                .split_once('=')
                .ok_or_else(|| format!("{name}: {p:?} must look like id=https://..."))?;
            let (id, url) = (id.trim(), url.trim());
            let id_ok = !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
            if !id_ok {
                return Err(format!(
                    "{name}: id {id:?} must be lowercase letters, digits, - _ ."
                ));
            }
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(format!("{name}: {url:?} must be an http(s) URL"));
            }
            Ok((id.to_owned(), url.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with(vars: &[(&str, &str)]) -> Result<Config, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_vars(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = with(&[]).unwrap();
        assert_eq!(c.syslog_udp, Some(DEFAULT_SYSLOG_UDP.parse().unwrap()));
        assert_eq!(c.lines_tcp, None);
        assert_eq!(c.otlp_grpc, Some(DEFAULT_OTLP_GRPC.parse().unwrap()));
        assert_eq!(c.kong_http, Some(DEFAULT_KONG_HTTP.parse().unwrap()));
        assert_eq!(c.http, DEFAULT_HTTP.parse().unwrap());
        assert!(c.rdns && c.seed_sources);
        assert_eq!(c.refresh, Duration::from_secs(3600));
        assert_eq!(c.otlp_metrics_endpoint, None);
        assert_eq!(c.otlp_metrics_interval, Duration::from_secs(60));
        assert_eq!(c.sources(), Sources::seed());
    }

    #[test]
    fn everything_set() {
        let c = with(&[
            ("EUNOX_SYSLOG_UDP", "off"),
            ("EUNOX_LINES_TCP", "127.0.0.1:5141"),
            ("EUNOX_OTLP_GRPC", "off"),
            ("EUNOX_KONG_HTTP", "off"),
            ("EUNOX_HTTP", "127.0.0.1:9000"),
            ("EUNOX_RDNS", "off"),
            ("EUNOX_REFRESH_SECS", "600"),
            ("EUNOX_OTLP_METRICS_ENDPOINT", "http://collector:4317"),
            ("EUNOX_OTLP_METRICS_INTERVAL_SECS", "15"),
            ("EUNOX_SEED_SOURCES", "off"),
            ("EUNOX_KEY_DIRECTORIES", "demo=http://keys:8000/.well-known/http-message-signatures-directory, other=https://o.example/d"),
            ("EUNOX_RANGES", "openai-gptbot=https://mirror.example/gptbot.json"),
        ])
        .unwrap();
        assert_eq!(c.syslog_udp, None);
        assert_eq!(c.lines_tcp, Some("127.0.0.1:5141".parse().unwrap()));
        assert_eq!(c.otlp_grpc, None);
        assert_eq!(c.kong_http, None);
        assert!(!c.rdns && !c.seed_sources);
        assert_eq!(
            c.otlp_metrics_endpoint.as_deref(),
            Some("http://collector:4317")
        );
        assert_eq!(c.otlp_metrics_interval, Duration::from_secs(15));
        let s = c.sources();
        assert_eq!(s.keys.len(), 2);
        assert_eq!(s.keys[0].operator, "demo");
        assert_eq!(s.ranges.len(), 1);
        assert_eq!(s.ranges[0].id, "openai-gptbot");
    }

    #[test]
    fn rejects_bad_values() {
        for (k, v) in [
            ("EUNOX_SYSLOG_UDP", "5140"),
            ("EUNOX_HTTP", "off"),
            ("EUNOX_RDNS", "maybe"),
            ("EUNOX_REFRESH_SECS", "5"),
            ("EUNOX_OTLP_METRICS_ENDPOINT", "collector:4317"),
            ("EUNOX_OTLP_METRICS_INTERVAL_SECS", "1"),
            ("EUNOX_KEY_DIRECTORIES", "demo"),
            ("EUNOX_KEY_DIRECTORIES", "Demo=https://x"),
            ("EUNOX_RANGES", "a=file:///etc/passwd"),
        ] {
            let err = with(&[(k, v)]).unwrap_err();
            assert!(err.starts_with(k), "{k}={v}: {err}");
        }
    }
}
