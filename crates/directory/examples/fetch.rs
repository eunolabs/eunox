//! Fetch every seed source once and print what came back.
//!
//!     cargo run -p eunox-directory --example fetch
//!
//! Pass IP addresses to see which range sets hold them and to run
//! forward-confirmed reverse DNS on them:
//!
//!     cargo run -p eunox-directory --example fetch -- 66.249.66.1

use std::net::IpAddr;

use eunox_core::IpRanges;
use eunox_directory::{Directory, FcrDns, Options, Sources, unix_now};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let dir = Directory::new(Sources::seed(), Options::default())?;
    let snap = dir.refresh(unix_now()).await;

    println!("{:<30} {:>6}  status", "source", "items");
    for s in snap.status() {
        let state = match &s.last_error {
            None => "ok".to_owned(),
            Some(e) => format!("FAILED: {e}"),
        };
        println!("{:<30} {:>6}  {state}  {}", s.id, s.items, s.url);
    }
    for k in snap.key_records() {
        println!(
            "key {} operator={} kid={} nbf={:?} exp={:?}",
            k.thumbprint,
            k.key.operator,
            k.kid.as_deref().unwrap_or("-"),
            k.not_before,
            k.expires
        );
    }

    let ips: Vec<IpAddr> = std::env::args()
        .skip(1)
        .map(|a| a.parse().map_err(|e| format!("{a}: {e}")))
        .collect::<Result<_, _>>()?;
    if !ips.is_empty() {
        let rdns = FcrDns::system()?;
        for ip in ips {
            let mut sets: Vec<&str> = snap
                .range_sets()
                .map(|(id, _)| id)
                .filter(|id| snap.contains(id, ip) == Some(true))
                .collect();
            sets.sort_unstable();
            println!("{ip}: in ranges {sets:?}, rdns {:?}", rdns.check(ip).await);
        }
    }
    Ok(())
}
