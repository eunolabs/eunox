//! The pipeline from log lines to classified records, and the receivers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox_core::{Catalog, Class, Failure, IpNet, Reason, Unverifiable};
use eunox_directory::parse::DirectoryKey;
use eunox_directory::rdns::DnsError;
use eunox_directory::snapshot::merge_keys;
use eunox_directory::{DnsLookup, FcrDns, Snapshot};
use eunox_ingest::{ClassifiedRecord, Pipeline, SessionKey, read_lines, serve_tcp, serve_udp};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// JWK thumbprint of the RFC 9421 B.1.4 test key, the key behind Cloudflare's
/// Web Bot Auth test vector.
const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
const PUBLIC: [u8; 32] = [
    0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b, 0x23,
    0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43, 0xd1, 0xbb,
];
const CF_INPUT: &str = r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#;
const CF_SIG: &str = "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:";
/// Inside the vector's validity window.
const TS: &str = "2025-01-01T00:01:00+00:00";

const GPTBOT_UA: &str = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)";
const GOOGLEBOT_UA: &str =
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const BROWSER_UA: &str =
    "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15";

fn snapshot(with_ranges: bool) -> Arc<Snapshot> {
    let key = DirectoryKey {
        thumbprint: KEYID.into(),
        kid: None,
        public_key: PUBLIC,
        not_before: None,
        expires: None,
    };
    let keys = merge_keys(&[], &[key], "openai", 0, 86_400);
    let mut ranges: HashMap<String, Vec<IpNet>> = HashMap::new();
    if with_ranges {
        ranges.insert(
            "openai-gptbot".into(),
            vec!["192.0.2.0/24".parse().unwrap()],
        );
        ranges.insert(
            "google-common-crawlers".into(),
            vec!["198.51.100.0/24".parse().unwrap()],
        );
    }
    Arc::new(Snapshot::new(keys, ranges, vec![]))
}

/// DNS fixture: one real Googlebot outside the loaded ranges, and one IP
/// whose resolver times out.
struct Dns;

impl DnsLookup for Dns {
    async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        match ip.to_string().as_str() {
            "203.0.113.50" => Ok(vec!["crawl-203-0-113-50.googlebot.com.".into()]),
            "203.0.113.51" => Err(DnsError::Unavailable("timed out".into())),
            _ => Err(DnsError::NotFound),
        }
    }
    async fn addrs(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        match name {
            "crawl-203-0-113-50.googlebot.com." => Ok(vec!["203.0.113.50".parse().unwrap()]),
            _ => Err(DnsError::NotFound),
        }
    }
}

#[derive(Clone, Default)]
struct Collected(Arc<Mutex<Vec<ClassifiedRecord>>>);

impl Collected {
    /// Wait for `n` records; reverse-DNS results arrive from spawned tasks.
    async fn wait_for(&self, n: usize) -> Vec<ClassifiedRecord> {
        for _ in 0..400 {
            if self.0.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let got = self.0.lock().unwrap().clone();
        assert_eq!(got.len(), n, "records: {got:#?}");
        got
    }
}

fn pipeline(snap: Arc<Snapshot>, rdns: bool) -> (Pipeline<Dns>, Collected) {
    let out = Collected::default();
    let sink = out.clone();
    let p = Pipeline::new(
        Arc::new(Catalog::seed()),
        Arc::new(move || snap.clone()),
        rdns.then(|| Arc::new(FcrDns::new(Dns))),
        Arc::new(move |r: ClassifiedRecord| sink.0.lock().unwrap().push(r)),
    );
    (p, out)
}

fn line(ip: &str, ua: &str, sig: &str, sig_input: &str) -> String {
    json!({
        "ts": TS, "method": "GET", "scheme": "https", "host": "example.com",
        "authority": "example.com", "path": "/", "ip": ip, "status": "200",
        "ua": ua, "sig": sig, "sig_input": sig_input, "sig_agent": "",
    })
    .to_string()
}

fn one(records: &[ClassifiedRecord], ip: &str) -> ClassifiedRecord {
    records
        .iter()
        .find(|r| r.record.client_ip.to_string() == ip)
        .unwrap_or_else(|| panic!("no record for {ip}"))
        .clone()
}

#[tokio::test]
async fn every_class_end_to_end() {
    let (p, out) = pipeline(snapshot(true), false);
    let tap_input = r#"sig2=("@authority" "@path"); created=1735689600; expires=1735693200; keyId="k"; alg="ed25519"; nonce="n"; tag="agent-payer-auth""#;
    for l in [
        line("203.0.113.1", BROWSER_UA, CF_SIG, CF_INPUT),
        line("203.0.113.2", GPTBOT_UA, "", ""),
        line("192.0.2.3", GPTBOT_UA, "", ""),
        line("203.0.113.4", BROWSER_UA, "", ""),
        line("203.0.113.5", "python-requests/2.32", "", ""),
        line("203.0.113.6", BROWSER_UA, "sig2=:AAAA:", tap_input),
    ] {
        p.handle_line(l.as_bytes());
    }
    let got = out.wait_for(6).await;

    let signed = one(&got, "203.0.113.1");
    assert_eq!(signed.class, Class::Verified);
    assert_eq!(signed.operator.as_deref(), Some("openai"));
    assert_eq!(signed.signature_tags, ["web-bot-auth"]);
    assert_eq!(
        signed.session,
        SessionKey::Signed {
            operator: "openai".into(),
            keyid: KEYID.into()
        }
    );

    let forged = one(&got, "203.0.113.2");
    assert_eq!(forged.class, Class::Spoofed);
    assert_eq!(forged.agent.as_deref(), Some("openai-gptbot"));
    assert!(matches!(forged.session, SessionKey::Heuristic { .. }));

    assert_eq!(one(&got, "192.0.2.3").class, Class::IpVerified);
    assert_eq!(one(&got, "203.0.113.4").class, Class::Unclassified);
    assert_eq!(one(&got, "203.0.113.5").class, Class::UnknownBot);

    let tap = one(&got, "203.0.113.6");
    assert_eq!(tap.class, Class::UnknownBot);
    assert_eq!(tap.reason, Reason::UnknownSigner);
    assert_eq!(tap.signature_tags, ["agent-payer-auth"]);
    assert!(matches!(
        tap.signature_failure,
        Some(Failure::Unsupported(_))
    ));

    let c = p.counters();
    assert_eq!(c.lines.load(Ordering::Relaxed), 6);
    assert_eq!(c.records.load(Ordering::Relaxed), 6);
    assert_eq!(c.parse_errors.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn reverse_dns_verifies_googlebot_outside_its_ranges() {
    let (p, out) = pipeline(snapshot(true), true);
    p.handle_line(line("203.0.113.50", GOOGLEBOT_UA, "", "").as_bytes());
    let got = out.wait_for(1).await;
    assert_eq!(got[0].class, Class::IpVerified);
    assert_eq!(
        got[0].reason,
        Reason::ReverseDns("crawl-203-0-113-50.googlebot.com".into())
    );
    assert_eq!(p.counters().rdns_lookups.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn resolver_failure_is_unverifiable_not_spoofed() {
    let (p, out) = pipeline(snapshot(true), true);
    p.handle_line(line("203.0.113.51", GOOGLEBOT_UA, "", "").as_bytes());
    let got = out.wait_for(1).await;
    assert_eq!(got[0].class, Class::UnknownBot);
    assert_eq!(
        got[0].reason,
        Reason::Unverifiable(Unverifiable::MissingData)
    );
}

#[tokio::test]
async fn definite_reverse_dns_failure_is_spoofed() {
    let (p, out) = pipeline(snapshot(true), true);
    p.handle_line(line("203.0.113.52", GOOGLEBOT_UA, "", "").as_bytes());
    assert_eq!(out.wait_for(1).await[0].class, Class::Spoofed);
}

#[tokio::test]
async fn without_reverse_dns_googlebot_outside_ranges_is_unverifiable() {
    let (p, out) = pipeline(snapshot(true), false);
    p.handle_line(line("203.0.113.50", GOOGLEBOT_UA, "", "").as_bytes());
    let got = out.wait_for(1).await;
    assert_eq!(got[0].class, Class::UnknownBot);
    assert_eq!(p.counters().rdns_lookups.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn lookups_past_the_cap_go_out_unverified() {
    let (p, out) = pipeline(snapshot(true), true);
    let p = p.with_rdns_in_flight(0);
    p.handle_line(line("203.0.113.50", GOOGLEBOT_UA, "", "").as_bytes());
    let got = out.wait_for(1).await;
    assert_eq!(got[0].class, Class::UnknownBot);
    assert_eq!(p.counters().rdns_skipped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn no_lookup_for_agents_without_reverse_dns() {
    // GPTBot's ranges aren't loaded: missing data, but reverse DNS can't help.
    let (p, out) = pipeline(snapshot(false), true);
    p.handle_line(line("203.0.113.2", GPTBOT_UA, "", "").as_bytes());
    let got = out.wait_for(1).await;
    assert_eq!(
        got[0].reason,
        Reason::Unverifiable(Unverifiable::MissingData)
    );
    assert_eq!(p.counters().rdns_lookups.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn bad_lines_are_counted_and_described() {
    let (p, out) = pipeline(snapshot(true), false);
    p.handle_line(b"\n");
    p.handle_line(b"not json\n");
    p.handle_line(br#"{"ts":"2025-01-01T00:01:00Z"}"#);
    let mut syslog = b"<190>Nov  8 12:00:00 web-1 nginx: ".to_vec();
    syslog.extend_from_slice(line("203.0.113.4", BROWSER_UA, "", "").as_bytes());
    p.handle_line(&syslog);
    out.wait_for(1).await;

    let c = p.counters();
    assert_eq!(c.lines.load(Ordering::Relaxed), 3, "blank line ignored");
    assert_eq!(c.parse_errors.load(Ordering::Relaxed), 2);
    let last = c.last_parse_error.lock().unwrap().clone().unwrap();
    assert!(last.contains("missing \"ip\""), "{last}");
}

#[tokio::test]
async fn udp_syslog_receiver() {
    let (p, out) = pipeline(snapshot(true), false);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(serve_udp(socket, Arc::new(p)));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let msg = format!(
        "<190>Nov  8 12:00:00 web-1 nginx: {}",
        line("203.0.113.2", GPTBOT_UA, "", "")
    );
    client.send_to(msg.as_bytes(), addr).await.unwrap();
    assert_eq!(out.wait_for(1).await[0].class, Class::Spoofed);
}

#[tokio::test]
async fn tcp_line_receiver() {
    let (p, out) = pipeline(snapshot(true), false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_tcp(listener, Arc::new(p)));

    let mut conn = TcpStream::connect(addr).await.unwrap();
    let body = format!(
        "{}\n{}\n",
        line("203.0.113.2", GPTBOT_UA, "", ""),
        line("192.0.2.3", GPTBOT_UA, "", "")
    );
    conn.write_all(body.as_bytes()).await.unwrap();
    conn.shutdown().await.unwrap();
    let got = out.wait_for(2).await;
    assert_eq!(one(&got, "203.0.113.2").class, Class::Spoofed);
    assert_eq!(one(&got, "192.0.2.3").class, Class::IpVerified);
}

#[tokio::test]
async fn replay_skips_oversized_lines() {
    let (p, out) = pipeline(snapshot(true), false);
    let huge = format!("{{\"ua\":\"{}\"}}", "x".repeat(eunox_ingest::MAX_LINE * 2));
    let body = format!(
        "{}\n{huge}\n{}",
        line("203.0.113.2", GPTBOT_UA, "", ""),
        line("192.0.2.3", GPTBOT_UA, "", "")
    );
    let n = read_lines(body.as_bytes(), &p).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        out.wait_for(2).await.len(),
        2,
        "last line has no trailing newline"
    );
    let c = p.counters();
    assert_eq!(c.parse_errors.load(Ordering::Relaxed), 1);
    assert!(
        c.last_parse_error
            .lock()
            .unwrap()
            .as_deref()
            .unwrap()
            .contains("longer than")
    );
}
