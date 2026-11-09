//! Retrying sources that failed to load, without refetching the rest.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox_directory::fetch::next_retry;
use eunox_directory::{Directory, KeySource, Options, RangeSource, Sources, unix_now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const RANGES: &str = r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}"#;
const KEYS: &str =
    r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;

/// path -> body; a missing path is a 503. Counts hits per path.
#[derive(Clone, Default)]
struct Server {
    bodies: Arc<Mutex<HashMap<String, &'static str>>>,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl Server {
    async fn start(&self) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    continue;
                };
                let me = me.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    *me.hits.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let body = me.bodies.lock().unwrap().get(&path).copied();
                    let resp = match body {
                        Some(b) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        ),
                        None => "HTTP/1.1 503 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned(),
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn serve(&self, path: &str, body: &'static str) {
        self.bodies.lock().unwrap().insert(path.into(), body);
    }

    fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

fn directory(addr: SocketAddr, retry: Duration) -> Directory {
    let sources = Sources {
        ranges: vec![RangeSource {
            id: "ok".into(),
            url: format!("http://{addr}/ranges.json"),
        }],
        keys: vec![KeySource {
            operator: "late".into(),
            url: format!("http://{addr}/keys"),
        }],
    };
    let options = Options {
        retry_interval: retry,
        ..Options::default()
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    Directory::with_client(sources, options, client)
}

#[test]
fn backoff_doubles_up_to_the_refresh_interval() {
    let hour = Duration::from_secs(3600);
    let mut backoff = Duration::from_secs(30);
    let mut waits = Vec::new();
    for _ in 0..9 {
        let (wait, next) = next_retry(backoff, hour);
        waits.push(wait.as_secs());
        backoff = next;
    }
    assert_eq!(waits, [30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
}

#[tokio::test]
async fn refresh_failed_only_refetches_failing_sources() {
    let server = Server::default();
    server.serve("/ranges.json", RANGES);
    let dir = directory(server.start().await, Duration::from_secs(30));
    assert!(dir.any_failing(), "nothing fetched yet");

    dir.refresh(unix_now()).await;
    assert!(dir.any_failing(), "keys still 503");
    assert_eq!((server.hits("/ranges.json"), server.hits("/keys")), (1, 1));

    dir.refresh_failed(unix_now()).await;
    assert_eq!(
        (server.hits("/ranges.json"), server.hits("/keys")),
        (1, 2),
        "only the failing one"
    );

    server.serve("/keys", KEYS);
    let snap = dir.refresh_failed(unix_now()).await;
    assert!(!dir.any_failing());
    assert_eq!(server.hits("/ranges.json"), 1);
    assert!(snap.status().iter().all(|s| s.last_error.is_none()));
    assert_eq!(snap.key_records().count(), 1);
    assert_eq!(
        snap.range_sets().count(),
        1,
        "the earlier source's data is kept"
    );
}

#[tokio::test]
async fn run_picks_up_a_source_that_comes_up_later() {
    let server = Server::default();
    server.serve("/ranges.json", RANGES);
    let dir = Arc::new(directory(server.start().await, Duration::from_millis(50)));
    tokio::spawn(dir.clone().run());

    // The key directory starts out down, as when eunox starts before the
    // service that hosts it.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(dir.any_failing());
    server.serve("/keys", KEYS);

    for _ in 0..100 {
        if !dir.any_failing() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!dir.any_failing(), "retried until the key directory loaded");
    assert_eq!(dir.snapshot().key_records().count(), 1);
    assert_eq!(
        server.hits("/ranges.json"),
        1,
        "the healthy source isn't refetched"
    );
    assert!(server.hits("/keys") >= 2);
}
