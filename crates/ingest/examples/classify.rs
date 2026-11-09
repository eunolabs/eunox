//! Classify nginx JSON log lines and print one line per request, then a
//! summary. Uses the live seed key directories and IP ranges.
//!
//! Replay a log file written with the eunox `log_format`:
//!
//!     cargo run --release -p eunox-ingest --example classify < access.log
//!
//! Or listen for nginx's syslog on UDP (Ctrl-C prints the summary):
//!
//!     cargo run --release -p eunox-ingest --example classify -- --udp 0.0.0.0:5140

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eunox_core::{Catalog, Reason};
use eunox_directory::{Directory, FcrDns, Options, Sources, unix_now};
use eunox_ingest::{ClassifiedRecord, Pipeline, read_lines, serve_udp};
use tokio::io::BufReader;
use tokio::net::UdpSocket;

type Summary = Arc<Mutex<BTreeMap<(String, String), u64>>>;

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let udp = match args.as_slice() {
        [] => None,
        [flag, addr] if flag == "--udp" => Some(addr.clone()),
        _ => return Err("usage: classify [--udp ADDR] (reads stdin without --udp)".into()),
    };

    let directory = Arc::new(Directory::new(Sources::seed(), Options::default())?);
    let snap = directory.refresh(unix_now()).await;
    for s in snap.status().iter().filter(|s| s.last_error.is_some()) {
        eprintln!(
            "warning: {} not loaded: {}",
            s.id,
            s.last_error.as_deref().unwrap_or("")
        );
    }
    let rdns = match FcrDns::system() {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            eprintln!("warning: reverse DNS disabled: {e}");
            None
        }
    };

    let summary = Summary::default();
    let counts = summary.clone();
    let dir = directory.clone();
    let pipeline = Arc::new(Pipeline::new(
        Arc::new(Catalog::seed()),
        Arc::new(move || dir.snapshot()),
        rdns,
        Arc::new(move |r: ClassifiedRecord| {
            let who = r.agent.clone().or(r.operator.clone()).unwrap_or("-".into());
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                r.record.timestamp_ms,
                r.class.as_str(),
                who,
                reason(&r.reason),
                r.record.client_ip,
                r.record.target
            );
            *counts
                .lock()
                .unwrap()
                .entry((r.class.as_str().to_owned(), who))
                .or_default() += 1;
        }),
    ));

    match udp {
        None => {
            read_lines(BufReader::new(tokio::io::stdin()), &pipeline)
                .await
                .map_err(|e| e.to_string())?;
            // Let reverse-DNS lookups still in flight finish.
            let c = pipeline.counters().clone();
            for _ in 0..200 {
                let done =
                    c.records.load(Ordering::Relaxed) + c.parse_errors.load(Ordering::Relaxed);
                if done >= c.lines.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        Some(addr) => {
            let socket = UdpSocket::bind(&addr)
                .await
                .map_err(|e| format!("{addr}: {e}"))?;
            eprintln!("listening for syslog on udp://{addr}");
            tokio::spawn(directory.clone().run());
            tokio::select! {
                r = serve_udp(socket, pipeline.clone()) => r.map_err(|e| e.to_string())?,
                _ = tokio::signal::ctrl_c() => {}
            }
        }
    }

    let c = pipeline.counters();
    eprintln!(
        "\n{} lines, {} records, {} parse errors, {} reverse-DNS lookups",
        c.lines.load(Ordering::Relaxed),
        c.records.load(Ordering::Relaxed),
        c.parse_errors.load(Ordering::Relaxed),
        c.rdns_lookups.load(Ordering::Relaxed)
    );
    if let Some(e) = c.last_parse_error.lock().unwrap().as_deref() {
        eprintln!("last parse error: {e}");
    }
    let mut rows: Vec<_> = summary.lock().unwrap().clone().into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    eprintln!("{:<14} {:<28} {:>9}", "class", "agent", "requests");
    for ((class, who), n) in rows {
        eprintln!("{class:<14} {who:<28} {n:>9}");
    }
    Ok(())
}

fn reason(r: &Reason) -> String {
    match r {
        Reason::Signature => "signature".into(),
        Reason::PublishedRange => "published-range".into(),
        Reason::ReverseDns(host) => format!("rdns:{host}"),
        Reason::FailedIpChecks => "failed-ip-checks".into(),
        Reason::Unverifiable(u) => format!("unverifiable:{u:?}"),
        Reason::UnknownSigner => "unknown-signer".into(),
        Reason::BotUserAgent(m) => format!("bot-ua:{m}"),
        Reason::NoBotSignals => "-".into(),
    }
}
