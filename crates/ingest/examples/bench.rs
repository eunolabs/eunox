//! Ingest throughput: parse, verify and classify, one thread, no network.
//!
//!     cargo run --release -p eunox-ingest --example bench [LINES]
//!
//! The mix is mostly browser traffic, with forged and real crawlers, generic
//! bots, and 5% Web Bot Auth-signed requests (each one an Ed25519 check).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use eunox_core::{Catalog, IpNet};
use eunox_directory::Snapshot;
use eunox_directory::parse::DirectoryKey;
use eunox_directory::snapshot::merge_keys;
use eunox_ingest::{ClassifiedRecord, NoDns, Pipeline};
use serde_json::json;

const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
const PUBLIC: [u8; 32] = [
    0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b, 0x23,
    0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43, 0xd1, 0xbb,
];
const CF_INPUT: &str = r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#;
const CF_SIG: &str = "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:";

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map_or(200_000, |a| a.parse().expect("LINES must be a number"));

    let key = DirectoryKey {
        thumbprint: KEYID.into(),
        kid: None,
        public_key: PUBLIC,
        not_before: None,
        expires: None,
    };
    let ranges: HashMap<String, Vec<IpNet>> = HashMap::from([
        (
            "openai-gptbot".into(),
            vec!["192.0.2.0/24".parse().unwrap()],
        ),
        (
            "google-common-crawlers".into(),
            vec!["198.51.100.0/24".parse().unwrap()],
        ),
    ]);
    let snap = Arc::new(Snapshot::new(
        merge_keys(&[], &[key], "openai", 0, 86_400),
        ranges,
        vec![],
    ));

    let browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
    let gptbot = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot";
    let googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    let lines: Vec<String> = (0..n)
        .map(|i| {
            let (ip, ua, sig, input) = match i % 20 {
                0..=13 => (format!("203.0.{}.{}", i % 250, i % 200), browser, "", ""),
                14 | 15 => (format!("203.0.113.{}", i % 250), gptbot, "", ""),
                16 => (format!("192.0.2.{}", i % 250), gptbot, "", ""),
                17 => (format!("198.51.100.{}", i % 250), googlebot, "", ""),
                18 => (
                    format!("203.0.114.{}", i % 250),
                    "python-requests/2.32.3",
                    "",
                    "",
                ),
                _ => (format!("203.0.115.{}", i % 250), browser, CF_SIG, CF_INPUT),
            };
            json!({
                "ts": "2025-01-01T00:01:00+00:00", "method": "GET", "scheme": "https",
                "host": "example.com", "authority": "example.com",
                "path": format!("/products/{}?page={}", i % 500, i % 7),
                "ip": ip, "status": "200", "ua": ua,
                "sig": sig, "sig_input": input, "sig_agent": "",
            })
            .to_string()
        })
        .collect();

    let seen = Arc::new(AtomicU64::new(0));
    let counter = seen.clone();
    let pipeline: Pipeline<NoDns> = Pipeline::new(
        Arc::new(Catalog::seed()),
        Arc::new(move || snap.clone()),
        None,
        Arc::new(move |_: ClassifiedRecord| {
            counter.fetch_add(1, Ordering::Relaxed);
        }),
    );

    let start = Instant::now();
    for line in &lines {
        pipeline.handle_line(line.as_bytes());
    }
    let elapsed = start.elapsed();
    assert_eq!(seen.load(Ordering::Relaxed) as usize, n);
    println!(
        "{n} lines in {:.3}s: {:.0} lines/s on one thread",
        elapsed.as_secs_f64(),
        n as f64 / elapsed.as_secs_f64()
    );
}
