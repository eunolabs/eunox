//! `eunox sign` end to end: `init` writes an operator, `serve` publishes its
//! signed directory, and eunox's own verifier, given that directory as a
//! source, reports a request signed by `eunox sign` as verified.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use eunox::sign::{self, State};
use eunox::{Config, replay};
use eunox_core::{DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, DIRECTORY_TAG, content_digest};
use eunox_directory::parse::parse_key_directory;
use hyper::{Method, StatusCode};
use serde_json::json;
use tokio::net::TcpListener;

fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("eunox-sign-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_request_verifies_from_the_operators_own_directory() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = tempdir("e2e");
    let out = sign::init(&dir, &format!("https://{addr}"), None).unwrap();
    assert!(
        out.contains("self-check    a signed request verifies"),
        "{out}"
    );
    let state = Arc::new(State::load_with(&dir, None).unwrap());
    tokio::spawn(sign::serve(listener, state.clone(), 600));

    // The served directory: right media type, signed for our authority,
    // digest matching the body, and parseable by the v0 directory fetcher.
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}{DIRECTORY_PATH}");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers().clone();
    let body = resp.text().await.unwrap();
    assert_eq!(h["content-type"], DIRECTORY_MEDIA_TYPE);
    assert_eq!(h["cache-control"], "max-age=600");
    assert_eq!(
        h["content-digest"].to_str().unwrap(),
        content_digest(body.as_bytes())
    );
    let input = h["signature-input"].to_str().unwrap();
    assert!(input.starts_with(r#"binding=("@authority";req "content-digest")"#));
    assert!(input.contains(&format!(r#"tag="{DIRECTORY_TAG}""#)));
    let keyid = state.signing_key().unwrap().keyid().to_owned();
    let parsed = parse_key_directory(body.as_bytes()).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].thumbprint, keyid);

    // A log line carrying a request `eunox sign` signed, replayed through
    // eunox with that directory as its only key source.
    let ts = 1_767_225_660; // 2026-01-01T00:01:00Z
    let headers = state
        .sign_request("https://shop.example/pricing", ts, 60, "bm9uY2U=")
        .unwrap();
    let line = json!({
        "ts": "2026-01-01T00:01:00+00:00", "method": "GET", "scheme": "https",
        "host": "shop.example", "authority": "shop.example", "path": "/pricing",
        "ip": "203.0.113.9", "ua": "acme-procurement/1.0",
        "sig": headers.signature, "sig_input": headers.signature_input,
        "sig_agent": headers.signature_agent,
    })
    .to_string();
    let vars = HashMap::from([
        ("EUNOX_RDNS", "off".to_owned()),
        ("EUNOX_SEED_SOURCES", "off".to_owned()),
        ("EUNOX_KEY_DIRECTORIES", format!("acme={url}")),
    ]);
    let config = Config::from_vars(|k| vars.get(k).cloned()).unwrap();
    let report = replay(&config, format!("{line}\n").as_bytes())
        .await
        .unwrap();
    assert!(
        report
            .lines()
            .any(|l| l.split_whitespace().take(3).eq(["acme", "verified", "1"])),
        "{report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_server_answers_only_for_its_authority() {
    let dir = tempdir("respond");
    sign::init(&dir, "https://agent.example", None).unwrap();
    let state = State::load_with(&dir, None).unwrap();
    let get = |method: &Method, path: &str, host: Option<&str>| {
        sign::respond(&state, method, path, host, 3600, 1_000)
    };

    let ok = get(&Method::GET, DIRECTORY_PATH, Some("Agent.Example:443"));
    assert_eq!(ok.status(), StatusCode::OK);
    let input = ok.headers()["signature-input"].to_str().unwrap();
    assert!(input.contains("created=1000;expires=8200;"), "{input}");

    let head = get(&Method::HEAD, DIRECTORY_PATH, Some("agent.example"));
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.headers().contains_key("signature"));

    for (method, path, host, want) in [
        (Method::GET, DIRECTORY_PATH, Some("evil.example"), 421),
        (Method::GET, DIRECTORY_PATH, None, 421),
        (Method::GET, DIRECTORY_PATH, Some("agent.example:8443"), 421),
        (Method::POST, DIRECTORY_PATH, Some("agent.example"), 405),
        (Method::GET, "/", Some("agent.example"), 404),
    ] {
        let r = get(&method, path, host);
        assert_eq!(r.status().as_u16(), want, "{method} {path} {host:?}");
        assert!(!r.headers().contains_key("signature"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn init_never_overwrites_and_keys_round_trip() {
    let dir = tempdir("init");
    sign::init(&dir, "https://agent.example", None).unwrap();
    let err = sign::init(&dir, "https://agent.example", None).unwrap_err();
    assert!(err.contains("not overwriting"), "{err}");

    let state = State::load_with(&dir, None).unwrap();
    let key_file = std::fs::read_dir(dir.join("keys"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let pem = std::fs::read_to_string(&key_file).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let again = sign::parse_key(&pem).unwrap();
    assert_eq!(again.keyid(), state.signing_key().unwrap().keyid());
    assert_eq!(
        state.config.signature_agent,
        format!("https://agent.example{DIRECTORY_PATH}")
    );
    // A key supplied from outside replaces the directory's keys.
    let other = sign::parse_key(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    assert_eq!(other.keyid(), "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
    let replaced = State::load_with(&dir, Some(other)).unwrap();
    assert_eq!(
        replaced.signing_key().unwrap().keyid(),
        "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_writes_static_files_and_refuses_short_lifetimes() {
    let dir = tempdir("export");
    sign::init(&dir, "https://agent.example", None).unwrap();
    let state = State::load_with(&dir, None).unwrap();
    let out = dir.join("site");
    sign::export(&state, &out, 1_000, 7, 3600).unwrap();
    let body =
        std::fs::read_to_string(out.join(".well-known/http-message-signatures-directory")).unwrap();
    let headers = std::fs::read_to_string(out.join("_headers")).unwrap();
    assert!(headers.starts_with(&format!("{DIRECTORY_PATH}\n")));
    assert!(headers.contains(&format!(
        "  Content-Digest: {}\n",
        content_digest(body.as_bytes())
    )));
    assert!(headers.contains(&format!("created=1000;expires={};", 1_000 + 7 * 86_400)));
    let err = sign::export(&state, &out, 1_000, 1, 86_400).unwrap_err();
    assert!(err.contains("must outlast"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
