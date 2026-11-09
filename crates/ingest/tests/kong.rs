//! The Kong http-log endpoint over a real socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox_core::{Catalog, Class, IpNet};
use eunox_directory::Snapshot;
use eunox_ingest::{ClassifiedRecord, NoDns, Pipeline, serve_kong};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn entry(ip: &str, ua: &str) -> String {
    format!(
        r#"{{"request":{{"method":"GET","uri":"/","url":"http://example.com/","headers":{{"host":"example.com","user-agent":"{ua}"}}}},"response":{{"status":200}},"client_ip":"{ip}","started_at":1735689660000}}"#
    )
}

async fn send(addr: SocketAddr, method: &str, body: &str) -> u16 {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} /kong HTTP/1.1\r\nHost: eunox\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    conn.read_to_string(&mut resp).await.unwrap();
    resp.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn kong_http_log_posts() {
    let ranges = HashMap::from([(
        "openai-gptbot".to_owned(),
        vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
    )]);
    let snap = Arc::new(Snapshot::new(vec![], ranges, vec![]));
    let got: Arc<Mutex<Vec<ClassifiedRecord>>> = Arc::default();
    let sink = got.clone();
    let pipeline: Arc<Pipeline<NoDns>> = Arc::new(Pipeline::new(
        Arc::new(Catalog::seed()),
        Arc::new(move || snap.clone()),
        None,
        Arc::new(move |r: ClassifiedRecord| sink.lock().unwrap().push(r)),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_kong(listener, pipeline.clone()));

    let gptbot = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)";
    // One entry, as with max_batch_size 1.
    assert_eq!(send(addr, "POST", &entry("203.0.113.7", gptbot)).await, 200);
    // A batch, with one entry that can't be used.
    let batch = format!(
        "[{},{},{{\"request\":{{}}}}]",
        entry("192.0.2.7", gptbot),
        entry("203.0.113.8", "curl/8.5.0")
    );
    assert_eq!(send(addr, "POST", &batch).await, 200);
    assert_eq!(send(addr, "POST", "not json").await, 400);
    assert_eq!(send(addr, "GET", "").await, 405);

    for _ in 0..100 {
        if got.lock().unwrap().len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let got = got.lock().unwrap().clone();
    let class = |ip: &str| {
        got.iter()
            .find(|r| r.record.client_ip.to_string() == ip)
            .map(|r| r.class)
    };
    assert_eq!(class("203.0.113.7"), Some(Class::Spoofed));
    assert_eq!(class("192.0.2.7"), Some(Class::IpVerified));
    assert_eq!(class("203.0.113.8"), Some(Class::UnknownBot));
    let c = pipeline.counters();
    assert_eq!(c.records.load(Ordering::Relaxed), 3);
    assert_eq!(
        c.parse_errors.load(Ordering::Relaxed),
        2,
        "the bad entry and the non-JSON body"
    );
}
