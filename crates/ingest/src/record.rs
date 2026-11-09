//! One request, normalized from whatever the gateway logged.

use std::net::IpAddr;

use serde_json::{Map, Value};

/// The fields every log source is normalized into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    /// When the gateway handled the request, in Unix milliseconds. Signatures
    /// are verified at this time, not when the line arrived.
    pub timestamp_ms: i64,
    /// Request method.
    pub method: String,
    /// `http` or `https`. `https` when the source didn't log it.
    pub scheme: String,
    /// Host header (or `:authority`) as the client sent it, port included.
    pub authority: String,
    /// Request target as the client sent it: path and query, before rewrites.
    pub target: String,
    /// Client IP after trusted-proxy resolution.
    pub client_ip: IpAddr,
    /// `User-Agent`, empty if absent.
    pub user_agent: String,
    /// Response status, if logged.
    pub status: Option<u16>,
    /// `Signature`, verbatim.
    pub signature: Option<String>,
    /// `Signature-Input`, verbatim.
    pub signature_input: Option<String>,
    /// `Signature-Agent`, verbatim.
    pub signature_agent: Option<String>,
}

impl RequestRecord {
    /// The timestamp in whole seconds, as signatures' `created`/`expires` use.
    pub fn timestamp_secs(&self) -> i64 {
        self.timestamp_ms.div_euclid(1000)
    }
}

/// Parse one nginx JSON log line written with this `log_format` (the field
/// names are the contract; order doesn't matter):
///
/// ```nginx
/// log_format eunox escape=json
///   '{"ts":"$time_iso8601",'
///   '"method":"$request_method",'
///   '"scheme":"$scheme",'
///   '"host":"$host",'
///   '"authority":"$http_host",'
///   '"path":"$request_uri",'
///   '"ip":"$remote_addr",'
///   '"ua":"$http_user_agent",'
///   '"sig":"$http_signature",'
///   '"sig_input":"$http_signature_input",'
///   '"sig_agent":"$http_signature_agent"}';
///
/// access_log syslog:server=127.0.0.1:5140 eunox;
/// ```
///
/// - `ts` and `ip` are required; `status` is optional. `ts` may be ISO 8601 (`$time_iso8601`),
///   seconds with a fraction (`$msec`), or a JSON number of seconds.
/// - `authority` (`$http_host`) is preferred over `host` (`$host`), because
///   `$host` drops a non-default port, which a signature over `@authority`
///   includes.
/// - Empty strings, which nginx writes for absent headers, read as absent.
pub fn parse_nginx_json(line: &[u8]) -> Result<RequestRecord, String> {
    let fields: Map<String, Value> =
        serde_json::from_slice(line).map_err(|e| format!("not a JSON object: {e}"))?;
    parse_fields(&fields)
}

/// Build a record from named fields, whatever carried them (an nginx JSON
/// line, OTLP log attributes). Field names and rules are those of
/// [`parse_nginx_json`]. `-`, which Envoy and nginx's default escaping write
/// for a missing header, reads as absent, like an empty string.
pub fn parse_fields(fields: &Map<String, Value>) -> Result<RequestRecord, String> {
    let text = |key: &str| -> Option<&str> {
        match fields.get(key)? {
            Value::String(s) if !s.is_empty() && s != "-" => Some(s.as_str()),
            _ => None,
        }
    };
    let owned = |key: &str| text(key).map(str::to_owned);

    let timestamp_ms = match fields.get("ts") {
        Some(Value::String(s)) => parse_timestamp_ms(s)?,
        Some(Value::Number(n)) => n
            .as_f64()
            .map(|secs| (secs * 1000.0).round() as i64)
            .ok_or("ts is not a finite number")?,
        _ => return Err("missing \"ts\"".into()),
    };
    let ip = text("ip").ok_or("missing \"ip\"")?;
    let client_ip = ip
        .parse::<IpAddr>()
        .map_err(|_| format!("\"ip\" is not an IP address: {ip:?}"))?;
    let status = match fields.get("status") {
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };

    Ok(RequestRecord {
        timestamp_ms,
        method: owned("method").unwrap_or_default(),
        scheme: owned("scheme").unwrap_or_else(|| "https".into()),
        authority: text("authority")
            .or_else(|| text("host"))
            .unwrap_or_default()
            .to_owned(),
        target: owned("path").unwrap_or_else(|| "/".into()),
        client_ip,
        user_agent: owned("ua").unwrap_or_default(),
        status,
        signature: owned("sig"),
        signature_input: owned("sig_input"),
        signature_agent: owned("sig_agent"),
    })
}

/// `$msec` (`1735689660.123`) or ISO 8601 with an offset
/// (`2026-11-08T12:34:56+01:00`, `...Z`, optional fraction).
pub fn parse_timestamp_ms(s: &str) -> Result<i64, String> {
    let bad = || format!("unrecognized timestamp {s:?}");
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
        let secs: i64 = secs.parse().map_err(|_| bad())?;
        let millis = fraction_millis(frac).ok_or_else(bad)?;
        return Ok(secs * 1000 + millis);
    }
    iso8601_ms(s).ok_or_else(bad)
}

fn fraction_millis(frac: &str) -> Option<i64> {
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits: String = frac.chars().chain("000".chars()).take(3).collect();
    digits.parse().ok()
}

fn iso8601_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, minute, second) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }

    let mut rest = &s[19..];
    let mut millis = 0;
    if let Some(after) = rest.strip_prefix('.') {
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        millis = fraction_millis(&after[..end])?;
        rest = &after[end..];
    }
    let offset_secs = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let tz = rest[1..].replace(':', "");
            if tz.len() != 4 || !tz.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let (h, m): (i64, i64) = (tz[..2].parse().ok()?, tz[2..].parse().ok()?);
            sign * (h * 3600 + m * 60)
        }
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    Some(secs * 1000 + millis)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The JSON object in a log line: everything from the first `{`. Strips a
/// syslog header (`<190>Nov  8 12:00:00 host nginx: `) if there is one, and
/// trailing whitespace.
pub fn json_payload(line: &[u8]) -> Option<&[u8]> {
    let start = line.iter().position(|&b| b == b'{')?;
    let end = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    (end > start).then(|| &line[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{"ts":"2025-01-01T00:01:00+00:00","method":"GET","scheme":"https","host":"example.com","authority":"Example.com:8443","path":"/a?b=1","ip":"203.0.113.9","status":"200","ua":"Mozilla/5.0 (compatible; GPTBot/1.2)","sig":"sig1=:AAAA:","sig_input":"sig1=(\"@authority\");tag=\"web-bot-auth\"","sig_agent":""}"#;

    #[test]
    fn parses_every_field() {
        let r = parse_nginx_json(FULL.as_bytes()).unwrap();
        assert_eq!(r.timestamp_ms, 1_735_689_660_000);
        assert_eq!(r.timestamp_secs(), 1_735_689_660);
        assert_eq!(r.method, "GET");
        assert_eq!(r.authority, "Example.com:8443", "authority beats host");
        assert_eq!(r.target, "/a?b=1");
        assert_eq!(r.client_ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(r.status, Some(200));
        assert_eq!(r.signature.as_deref(), Some("sig1=:AAAA:"));
        assert_eq!(
            r.signature_input.as_deref(),
            Some(r#"sig1=("@authority");tag="web-bot-auth""#)
        );
        assert_eq!(r.signature_agent, None, "empty means absent");
    }

    #[test]
    fn minimal_line_from_the_published_snippet() {
        // The field set on eunolabs.ai before scheme and authority were added.
        let line = r#"{"ts":"2026-11-08T12:00:00+01:00","method":"GET","host":"example.com","path":"/","ip":"::ffff:192.0.2.1","ua":"","sig":"","sig_input":"","sig_agent":""}"#;
        let r = parse_nginx_json(line.as_bytes()).unwrap();
        assert_eq!(r.authority, "example.com", "falls back to host");
        assert_eq!(r.scheme, "https");
        assert_eq!(r.signature, None);
        assert_eq!(r.status, None);
        assert_eq!(
            r.timestamp_ms,
            parse_timestamp_ms("2026-11-08T11:00:00Z").unwrap()
        );
    }

    #[test]
    fn dash_means_absent() {
        let line = r#"{"ts":"1735689660","ip":"192.0.2.1","ua":"-","sig":"-","sig_input":"-","sig_agent":"-","authority":"-","host":"example.com"}"#;
        let r = parse_nginx_json(line.as_bytes()).unwrap();
        assert_eq!(
            (r.signature, r.signature_input, r.signature_agent),
            (None, None, None)
        );
        assert_eq!(r.user_agent, "");
        assert_eq!(r.authority, "example.com");
    }

    #[test]
    fn rejects_lines_it_cant_use() {
        for (line, why) in [
            (r#"{"ip":"1.2.3.4"}"#, "missing \"ts\""),
            (r#"{"ts":"1735689660.5"}"#, "missing \"ip\""),
            (r#"{"ts":"1735689660.5","ip":"unix:"}"#, "not an IP"),
            (
                r#"{"ts":"yesterday","ip":"1.2.3.4"}"#,
                "unrecognized timestamp",
            ),
            (r#"{"ts":"1735689660","ip":"1.2"#, "not a JSON object"),
        ] {
            let err = parse_nginx_json(line.as_bytes()).unwrap_err();
            assert!(err.contains(why), "{line}: {err}");
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(
            parse_timestamp_ms("1735689660.123").unwrap(),
            1_735_689_660_123
        );
        assert_eq!(
            parse_timestamp_ms("1735689660.1").unwrap(),
            1_735_689_660_100
        );
        assert_eq!(parse_timestamp_ms("1735689660").unwrap(), 1_735_689_660_000);
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_timestamp_ms("2025-01-01T00:01:00Z").unwrap(),
            1_735_689_660_000
        );
        assert_eq!(
            parse_timestamp_ms("2025-01-01T01:01:00+01:00").unwrap(),
            1_735_689_660_000
        );
        assert_eq!(
            parse_timestamp_ms("2024-12-31T19:01:00-0500").unwrap(),
            1_735_689_660_000
        );
        assert_eq!(
            parse_timestamp_ms("2025-01-01T00:01:00.250Z").unwrap(),
            1_735_689_660_250
        );
        assert_eq!(
            parse_timestamp_ms("2024-02-29T00:00:00Z").unwrap(),
            1_709_164_800_000
        );
        for bad in [
            "2025-13-01T00:00:00Z",
            "2025-01-01T00:00:00",
            "2025-01-01T00:00:00+1",
            "1.2.3",
        ] {
            assert!(parse_timestamp_ms(bad).is_err(), "{bad}");
        }
        let n = parse_nginx_json(br#"{"ts":1735689660.5,"ip":"1.2.3.4"}"#).unwrap();
        assert_eq!(n.timestamp_ms, 1_735_689_660_500);
    }

    #[test]
    fn syslog_header_and_whitespace_are_stripped() {
        let line = b"<190>Nov  8 12:00:00 web-1 nginx: {\"ts\":\"1\"}\n";
        assert_eq!(json_payload(line), Some(&b"{\"ts\":\"1\"}"[..]));
        assert_eq!(json_payload(b"{\"a\":1}"), Some(&b"{\"a\":1}"[..]));
        assert_eq!(json_payload(b"no json here\n"), None);
        assert_eq!(json_payload(b"   \n"), None);
    }
}
