//! The demo traffic generator behind `eunox-demo`, for the compose demo.
//!
//! It plays every kind of client eunox classifies:
//! - an agent that signs fresh Web Bot Auth requests and serves its own key
//!   directory (`verified`, once eunox lists that directory as a source);
//! - forged GPTBot, ClaudeBot and Googlebot user agents (`spoofed`: the demo
//!   network isn't in any operator's published ranges);
//! - a Visa Trusted Agent Protocol-style `agent-payer-auth` signature and
//!   `python-requests` (`unknown-bot`);
//! - browsers (`unclassified`).
//!
//! It signs with the RFC 9421 Appendix B.1.4 test key, whose private half is
//! published in the RFC. Never use it for anything but a demo.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// RFC 9421 B.1.4 `test-key-ed25519`, private half (published in the RFC).
const TEST_PRIVATE: [u8; 32] = [
    0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c, 0x0e, 0x84,
    0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f, 0x6a, 0x7d, 0x29, 0xc5,
];
/// Its JWK thumbprint, the Web Bot Auth `keyid`.
pub const TEST_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
/// The key directory the demo agent serves.
pub const KEY_DIRECTORY: &str =
    r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;
/// Where it serves it.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// How long each signature is valid.
const LIFETIME_SECS: i64 = 60;

/// `Signature-Input` and `Signature` values for a request to `authority`
/// (lowercase, default port omitted, as RFC 9421 §2.2.3 normalizes it)
/// naming `signature_agent` (a structured-field string, quotes included),
/// signed at `created`.
pub fn sign(authority: &str, signature_agent: &str, created: i64, nonce: &str) -> (String, String) {
    let params = format!(
        r#"("@authority" "signature-agent");created={created};expires={};keyid="{TEST_KEYID}";alg="ed25519";nonce="{nonce}";tag="web-bot-auth""#,
        created + LIFETIME_SECS
    );
    let base = format!(
        "\"@authority\": {authority}\n\"signature-agent\": {signature_agent}\n\"@signature-params\": {params}"
    );
    let signature = SigningKey::from_bytes(&TEST_PRIVATE).sign(base.as_bytes());
    (
        format!("sig1={params}"),
        format!("sig1=:{}:", BASE64.encode(signature.to_bytes())),
    )
}

/// Generator settings, from `DEMO_*` environment variables.
#[derive(Clone, Debug)]
pub struct DemoConfig {
    /// `DEMO_TARGETS`: gateway base URLs, comma-separated.
    pub targets: Vec<String>,
    /// `DEMO_LISTEN`: where to serve the key directory (default 0.0.0.0:8000).
    pub listen: String,
    /// `DEMO_DIRECTORY_URL`: the key directory URL signed requests name in
    /// `Signature-Agent`, as eunox reaches it.
    pub directory_url: String,
    /// `DEMO_INTERVAL_MS`: time between requests per target (default 400).
    pub interval: Duration,
}

impl DemoConfig {
    /// Read the environment.
    pub fn from_env() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let targets: Vec<String> = var("DEMO_TARGETS")
            .ok_or(
                "DEMO_TARGETS must list gateway URLs, e.g. http://nginx:8080,http://envoy:10000",
            )?
            .split(',')
            .map(|t| t.trim().trim_end_matches('/').to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some(bad) = targets
            .iter()
            .find(|t| !t.starts_with("http://") && !t.starts_with("https://"))
        {
            return Err(format!("DEMO_TARGETS: {bad:?} must be an http(s) URL"));
        }
        let interval = match var("DEMO_INTERVAL_MS") {
            None => 400,
            Some(v) => v
                .parse()
                .map_err(|_| format!("DEMO_INTERVAL_MS: {v:?} must be milliseconds"))?,
        };
        Ok(Self {
            targets,
            listen: var("DEMO_LISTEN").unwrap_or_else(|| "0.0.0.0:8000".into()),
            directory_url: var("DEMO_DIRECTORY_URL")
                .unwrap_or_else(|| format!("http://traffic:8000{DIRECTORY_PATH}")),
            interval: Duration::from_millis(interval),
        })
    }
}

/// One kind of request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Signed,
    ForgedGptBot,
    ForgedClaudeBot,
    ForgedGooglebot,
    PayerAuth,
    PythonRequests,
    Browser,
}

/// Round-robin mix: browsers dominate, as on a real site.
const MIX: [Kind; 12] = [
    Kind::Browser,
    Kind::Signed,
    Kind::Browser,
    Kind::ForgedGptBot,
    Kind::Browser,
    Kind::PythonRequests,
    Kind::Browser,
    Kind::ForgedClaudeBot,
    Kind::Signed,
    Kind::ForgedGooglebot,
    Kind::Browser,
    Kind::PayerAuth,
];

const PATHS: [&str; 6] = [
    "/",
    "/pricing",
    "/docs/getting-started",
    "/products/42",
    "/api/search?q=agents",
    "/blog",
];
const BROWSER: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

/// Serve the key directory and send traffic forever.
pub async fn run(config: DemoConfig) -> Result<(), String> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|e| format!("DEMO_LISTEN {}: {e}", config.listen))?;
    eprintln!(
        "eunox-demo: key directory on http://{}{DIRECTORY_PATH}",
        config.listen
    );
    tokio::spawn(serve_directory(listener));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let sent = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    for target in config.targets.clone() {
        let (client, config, sent, failed) =
            (client.clone(), config.clone(), sent.clone(), failed.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(config.interval);
            let mut i: usize = 0;
            loop {
                tick.tick().await;
                let kind = MIX[i % MIX.len()];
                let path = PATHS[i % PATHS.len()];
                i = i.wrapping_add(1);
                match send(&client, &target, path, kind, &config.directory_url, i).await {
                    Ok(()) => sent.fetch_add(1, Ordering::Relaxed),
                    Err(_) => failed.fetch_add(1, Ordering::Relaxed),
                };
            }
        });
    }
    let mut report = tokio::time::interval(Duration::from_secs(10));
    report.tick().await;
    loop {
        report.tick().await;
        eprintln!(
            "eunox-demo: {} requests sent, {} failed (a gateway not up yet fails until it is)",
            sent.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed)
        );
    }
}

async fn send(
    client: &reqwest::Client,
    target: &str,
    path: &str,
    kind: Kind,
    directory_url: &str,
    n: usize,
) -> Result<(), reqwest::Error> {
    let url = format!("{target}{path}");
    let authority = target
        .split_once("://")
        .map_or(target, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let req = match kind {
        Kind::Browser => client.get(&url).header(header::USER_AGENT, BROWSER),
        Kind::ForgedGptBot => client.get(&url).header(
            header::USER_AGENT,
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
        ),
        Kind::ForgedClaudeBot => client.get(&url).header(
            header::USER_AGENT,
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        ),
        Kind::ForgedGooglebot => client.get(&url).header(
            header::USER_AGENT,
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ),
        Kind::PythonRequests => client.get(&url).header(header::USER_AGENT, "python-requests/2.32.3"),
        Kind::PayerAuth => client
            .get(&url)
            .header(header::USER_AGENT, BROWSER)
            .header(
                "signature-input",
                r#"sig2=("@authority" "@path"); created=1735689600; expires=1735693200; keyId="demo"; alg="ed25519"; nonce="n"; tag="agent-payer-auth""#,
            )
            .header("signature", "sig2=:AAAA:"),
        Kind::Signed => {
            let agent = format!("\"{directory_url}\"");
            let created = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
            let (input, signature) = sign(&authority, &agent, created, &format!("demo-{created}-{n}"));
            client
                .get(&url)
                .header(header::USER_AGENT, "eunox-demo-agent/1.0 (+signed with Web Bot Auth)")
                .header("signature-agent", agent)
                .header("signature-input", input)
                .header("signature", signature)
        }
    };
    req.send().await.map(|_| ())
}

async fn serve_directory(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                let mut resp =
                    Response::new(Full::new(Bytes::from_static(KEY_DIRECTORY.as_bytes())));
                if req.uri().path() == DIRECTORY_PATH {
                    resp.headers_mut().insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static(
                            "application/http-message-signatures-directory+json",
                        ),
                    );
                } else {
                    *resp.body_mut() = Full::new(Bytes::from_static(b"not found\n"));
                    *resp.status_mut() = StatusCode::NOT_FOUND;
                }
                Ok::<_, Infallible>(resp)
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eunox_core::{Key, Outcome, Request, VerifyOptions, verify};
    use eunox_directory::parse::parse_key_directory;
    use std::collections::HashMap;

    #[test]
    fn demo_signatures_verify_with_eunox() {
        let dir = parse_key_directory(KEY_DIRECTORY.as_bytes()).unwrap();
        assert_eq!(
            dir[0].thumbprint, TEST_KEYID,
            "served directory matches the signing key"
        );
        let keys = HashMap::from([(
            TEST_KEYID.to_owned(),
            Key {
                operator: "demo".into(),
                public_key: dir[0].public_key,
            },
        )]);
        let agent = format!("\"http://traffic:8000{DIRECTORY_PATH}\"");
        let (input, signature) = sign("nginx:8080", &agent, 1_000, "n1");
        let req = Request {
            method: "GET",
            scheme: "http",
            authority: "nginx:8080",
            target: "/pricing",
            signature: Some(&signature),
            signature_input: Some(&input),
            signature_agent: Some(&agent),
            ..Default::default()
        };
        let opts = VerifyOptions::default();
        let Outcome::Verified(v) = verify(&req, &keys, 1_010, &opts) else {
            panic!("{:?}", verify(&req, &keys, 1_010, &opts))
        };
        assert_eq!(v.operator, "demo");
        assert_eq!(
            v.signature_agent.as_deref(),
            Some(&agent[1..agent.len() - 1])
        );
        // Signed for one authority, it doesn't verify on another.
        let other = Request {
            authority: "envoy:10000",
            ..req
        };
        assert!(matches!(
            verify(&other, &keys, 1_010, &opts),
            Outcome::Failed(_)
        ));
        // And it expires.
        assert!(matches!(
            verify(&req, &keys, 1_000 + LIFETIME_SECS + 60, &opts),
            Outcome::Failed(_)
        ));
    }
}
