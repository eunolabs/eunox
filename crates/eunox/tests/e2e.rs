//! The whole service: a local key directory and range file, nginx-style
//! syslog over UDP, and the report over HTTP. Covers the v0 checks: a signed
//! request shows as verified and a forged GPTBot as spoofed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use eunox::{Config, replay, start};
use eunox_directory::unix_now;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

// RFC 9421 B.1.4 test key, the key behind Cloudflare's Web Bot Auth vector.
const TEST_KEYS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;
const GPTBOT_RANGES: &str = r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}"#;
const CF_INPUT: &str = r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#;
const CF_SIG: &str = "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:";
const GPTBOT_UA: &str = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)";
const BROWSER_UA: &str =
    "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15";

/// A tiny HTTP server serving fixed bodies by path.
async fn files(routes: HashMap<&'static str, &'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let (status, body) = routes.get(path).map_or((404, "nope"), |b| (200, *b));
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

fn config(files: SocketAddr) -> Config {
    let vars = HashMap::from([
        ("EUNOX_SYSLOG_UDP", "127.0.0.1:0".to_owned()),
        ("EUNOX_OTLP_GRPC", "127.0.0.1:0".to_owned()),
        ("EUNOX_KONG_HTTP", "127.0.0.1:0".to_owned()),
        ("EUNOX_HTTP", "127.0.0.1:0".to_owned()),
        ("EUNOX_RDNS", "off".to_owned()),
        ("EUNOX_SEED_SOURCES", "off".to_owned()),
        ("EUNOX_KEY_DIRECTORIES", format!("demo=http://{files}/keys")),
        (
            "EUNOX_RANGES",
            format!("openai-gptbot=http://{files}/gptbot.json"),
        ),
    ]);
    Config::from_vars(|k| vars.get(k).cloned()).unwrap()
}

fn line(ip: &str, path: &str, ua: &str, sig: &str, input: &str) -> String {
    json!({
        "ts": "2025-01-01T00:01:00+00:00", "method": "GET", "scheme": "https",
        "host": "example.com", "authority": "example.com", "path": path, "ip": ip,
        "ua": ua, "sig": sig, "sig_input": input, "sig_agent": "",
    })
    .to_string()
}

fn lines() -> Vec<String> {
    vec![
        line("203.0.113.1", "/", BROWSER_UA, CF_SIG, CF_INPUT),
        line("203.0.113.2", "/pricing?ref=x", GPTBOT_UA, "", ""),
        line(
            "203.0.113.3",
            "/<script>alert(1)</script>",
            GPTBOT_UA,
            "",
            "",
        ),
        line("192.0.2.4", "/pricing", GPTBOT_UA, "", ""),
        line("203.0.113.5", "/api", "curl/8.5.0", "", ""),
        line("198.18.0.6", "/", BROWSER_UA, "", ""),
    ]
}

async fn get(client: &reqwest::Client, url: String) -> (u16, String) {
    let r = client.get(&url).send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_verified_and_forged_spoofed_over_syslog_and_http() {
    let files = files(HashMap::from([
        ("/keys", TEST_KEYS),
        ("/gptbot.json", GPTBOT_RANGES),
    ]))
    .await;
    let running = start(&config(files)).await.unwrap();
    running.app.directory.refresh(unix_now()).await;

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for l in lines() {
        let msg = format!("<190>Jan  1 00:01:00 web-1 nginx: {l}");
        client_sock
            .send_to(msg.as_bytes(), running.syslog_udp.unwrap())
            .await
            .unwrap();
    }
    running.app.settle(Duration::from_secs(5)).await;
    for _ in 0..100 {
        if running
            .app
            .pipeline
            .counters()
            .records
            .load(std::sync::atomic::Ordering::Relaxed)
            == 6
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{}", running.http);

    let (status, text) = get(&http, format!("{base}/report.txt")).await;
    assert_eq!(status, 200);
    assert!(
        text.contains("24h window ending 2025-01-01T00:01:00Z, 6 requests"),
        "{text}"
    );
    let row = |needle: &str| {
        text.lines().any(|l| {
            l.split_whitespace()
                .collect::<Vec<_>>()
                .starts_with(&needle.split_whitespace().collect::<Vec<_>>())
        })
    };
    assert!(row("demo verified 1"), "{text}");
    assert!(row("GPTBot spoofed 2"), "{text}");
    assert!(row("GPTBot ip-verified 1"), "{text}");
    assert!(row("curl/ unknown-bot 1"), "{text}");
    assert!(row("(other) unclassified 1"), "{text}");
    assert!(
        text.contains(
            "✗ GPTBot ×2 from 203.0.113.0/24: no valid signature, fails its published IP checks"
        ),
        "{text}"
    );
    assert!(!text.contains("warnings:"), "{text}");
    assert!(
        text.contains("came over UDP syslog"),
        "UDP counts carry the loss caveat: {text}"
    );

    let (status, metrics) = get(&http, format!("{base}/metrics")).await;
    assert_eq!(status, 200);
    for want in [
        r#"eunox_requests_total{class="verified",agent="other"} 1"#,
        r#"eunox_requests_total{class="spoofed",agent="openai-gptbot"} 2"#,
        r#"eunox_requests_total{class="ip-verified",agent="openai-gptbot"} 1"#,
        r#"eunox_window_requests{class="spoofed"} 2"#,
        "eunox_ingest_lines_total 6",
        "eunox_ingest_parse_errors_total 0",
        "eunox_ingest_udp_datagrams_total 6",
        r#"eunox_source_up{source="demo""#,
    ] {
        assert!(metrics.contains(want), "missing {want}\n{metrics}");
    }

    let (status, html) = get(&http, format!("{base}/")).await;
    assert_eq!(status, 200);
    assert!(html.contains("<h1>eunox report</h1>"));
    assert!(html.contains("came over UDP syslog"), "{html}");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "paths are escaped"
    );
    assert!(
        !html.contains("<script>alert"),
        "no raw script from a request path"
    );

    assert_eq!(
        get(&http, format!("{base}/healthz")).await,
        (200, "ok\n".to_owned())
    );
    assert_eq!(get(&http, format!("{base}/nope")).await.0, 404);
    let post = http.post(format!("{base}/")).send().await.unwrap();
    assert_eq!(post.status().as_u16(), 405);
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_a_saved_log() {
    let files = files(HashMap::from([
        ("/keys", TEST_KEYS),
        ("/gptbot.json", GPTBOT_RANGES),
    ]))
    .await;
    let mut log = lines().join("\n");
    log.push_str("\nnot a log line\n");
    let text = replay(&config(files), log.as_bytes()).await.unwrap();
    assert!(text.contains("6 requests"), "{text}");
    assert!(text.contains("demo"), "{text}");
    assert!(
        !text.contains("UDP"),
        "no loss caveat when nothing came over UDP: {text}"
    );
    assert!(
        text.contains("1 lines couldn't be parsed; last: no JSON object in line"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_sources_show_as_warnings_not_spoofs() {
    // Key directory and ranges both 404: nothing loads.
    let files = files(HashMap::new()).await;
    let running = start(&config(files)).await.unwrap();
    running.app.directory.refresh(unix_now()).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(
        line("203.0.113.2", "/", GPTBOT_UA, "", "").as_bytes(),
        running.syslog_udp.unwrap(),
    )
    .await
    .unwrap();
    running.app.settle(Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let (_, text) = get(&http, format!("http://{}/report.txt", running.http)).await;
    assert!(
        !text.contains("spoofed"),
        "missing ranges must not produce spoofed:\n{text}"
    );
    assert!(text.contains("unknown-bot"), "{text}");
    assert!(text.contains("source demo not loaded: HTTP 404"), "{text}");
    assert!(text.contains("source openai-gptbot not loaded"), "{text}");
}
