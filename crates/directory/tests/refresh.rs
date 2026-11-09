//! `Directory::refresh` against a local HTTP server, and the seed data's
//! consistency with `eunox-core`'s catalog.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use eunox_core::{
    Catalog, Class, IpRanges, KeyStore, Observation, Outcome, Rdns, Request, VerifyOptions,
    classify, verify,
};
use eunox_directory::{Directory, KeySource, Options, RangeSource, Sources};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// path -> (status, body). Mutable so a test can make a source fail.
type Routes = Arc<Mutex<HashMap<String, (u16, String)>>>;

async fn serve(routes: Routes) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (status, body) = routes
                    .lock()
                    .unwrap()
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, "not found".into()));
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

fn directory(addr: SocketAddr) -> Directory {
    let base = format!("http://{addr}");
    let sources = Sources {
        ranges: vec![RangeSource {
            id: "openai-gptbot".into(),
            url: format!("{base}/gptbot.json"),
        }],
        keys: vec![KeySource {
            operator: "openai".into(),
            url: format!("{base}/keys"),
        }],
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    Directory::with_client(sources, Options::default(), client)
}

const GPTBOT_RANGES: &str =
    r#"{"creationTime":"2026-11-06","prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}"#;
// RFC 9421 B.1.4 test key, the key behind Cloudflare's Web Bot Auth vector.
const TEST_KEYS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;
const TEST_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

fn routes() -> Routes {
    Arc::new(Mutex::new(HashMap::from([
        ("/gptbot.json".to_owned(), (200, GPTBOT_RANGES.to_owned())),
        ("/keys".to_owned(), (200, TEST_KEYS.to_owned())),
    ])))
}

#[tokio::test]
async fn refresh_loads_ranges_and_keys() {
    let r = routes();
    let dir = directory(serve(r.clone()).await);
    assert!(
        dir.snapshot().lookup(TEST_KEYID, 0).is_none(),
        "empty before refresh"
    );

    let snap = dir.refresh(1_000).await;
    assert_eq!(
        snap.contains("openai-gptbot", "192.0.2.7".parse().unwrap()),
        Some(true)
    );
    assert_eq!(snap.lookup(TEST_KEYID, 1_000).unwrap().operator, "openai");
    assert!(
        snap.lookup("test-key-ed25519", 1_000).is_some(),
        "kid alias"
    );
    assert!(
        snap.status()
            .iter()
            .all(|s| s.last_success == Some(1_000) && s.last_error.is_none())
    );
}

#[tokio::test]
async fn failed_fetch_keeps_previous_data() {
    let r = routes();
    let dir = directory(serve(r.clone()).await);
    dir.refresh(1_000).await;

    r.lock()
        .unwrap()
        .insert("/gptbot.json".into(), (500, "oops".into()));
    r.lock()
        .unwrap()
        .insert("/keys".into(), (200, "<html>".into()));
    let snap = dir.refresh(2_000).await;

    assert_eq!(
        snap.contains("openai-gptbot", "192.0.2.7".parse().unwrap()),
        Some(true)
    );
    assert!(snap.lookup(TEST_KEYID, 2_000).is_some());
    for s in snap.status() {
        assert_eq!(s.last_attempt, Some(2_000));
        assert_eq!(s.last_success, Some(1_000), "{}", s.url);
        assert!(s.last_error.is_some(), "{}", s.url);
    }
}

#[tokio::test]
async fn rotated_out_key_verifies_requests_logged_before_rotation() {
    let r = routes();
    let dir = directory(serve(r.clone()).await);
    dir.refresh(1_735_689_000).await;
    r.lock()
        .unwrap()
        .insert("/keys".into(), (200, r#"{"keys":[]}"#.into()));
    let snap = dir.refresh(1_735_689_700).await;

    // Cloudflare's vector, logged at 1735689660: before the rotation was seen.
    let req = Request {
        method: "GET",
        scheme: "https",
        authority: "example.com",
        target: "/",
        signature: Some(
            "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:",
        ),
        signature_input: Some(
            r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#,
        ),
        ..Default::default()
    };
    let opts = VerifyOptions::default();
    assert!(matches!(
        verify(&req, &*snap, 1_735_689_660, &opts),
        Outcome::Verified(_)
    ));
    // Logged after the rotation was seen: no longer accepted.
    assert!(matches!(
        verify(&req, &*snap, 1_735_689_800, &opts),
        Outcome::Failed(_)
    ));
}

#[tokio::test]
async fn end_to_end_signed_and_forged_requests() {
    let dir = directory(serve(routes()).await);
    let snap = dir.refresh(1_735_689_000).await;
    let catalog = Catalog::seed();

    let signed = Request {
        method: "GET",
        scheme: "https",
        authority: "example.com",
        target: "/",
        signature: Some(
            "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:",
        ),
        signature_input: Some(
            r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#,
        ),
        ..Default::default()
    };
    let at = 1_735_689_660;
    let o = Observation {
        user_agent: "Mozilla/5.0 Chrome/131.0",
        client_ip: "203.0.113.9".parse().unwrap(),
        signature_agent: None,
        signature: verify(&signed, &*snap, at, &VerifyOptions::default()),
        rdns: Rdns::NotChecked,
    };
    assert_eq!(classify(&o, &catalog, &*snap).class, Class::Verified);

    let forged = Observation {
        user_agent: "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
        signature: Outcome::Unsigned,
        ..o.clone()
    };
    assert_eq!(classify(&forged, &catalog, &*snap).class, Class::Spoofed);

    let real = Observation {
        client_ip: "192.0.2.50".parse().unwrap(),
        ..forged.clone()
    };
    assert_eq!(classify(&real, &catalog, &*snap).class, Class::IpVerified);
}

#[test]
fn every_catalog_range_set_has_a_source() {
    let sources = Sources::seed();
    for agent in Catalog::seed().agents() {
        if let Some(set) = &agent.ip_ranges {
            assert!(
                sources.ranges.iter().any(|r| &r.id == set),
                "{} names range set {set}, which has no source",
                agent.id
            );
        }
    }
}

#[test]
fn every_key_source_operator_is_in_the_catalog() {
    let catalog = Catalog::seed();
    for k in Sources::seed().keys {
        assert!(
            catalog.agents().iter().any(|a| a.operator == k.operator),
            "key directory {} has operator {}, unknown to the catalog",
            k.url,
            k.operator
        );
    }
}
