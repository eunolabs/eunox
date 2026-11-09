//! Log receivers. All of them feed lines to a [`Pipeline`].
//!
//! - UDP syslog: what nginx's `access_log syslog:` sends, one message per
//!   datagram.
//! - TCP: newline-delimited lines, for log shippers (Vector, Fluent Bit,
//!   rsyslog) forwarding JSON lines.
//! - Any reader: replaying an access-log file or stdin.

use std::io;
use std::sync::Arc;

use eunox_directory::DnsLookup;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};

use crate::pipeline::Pipeline;

/// Longest line accepted. Longer lines are dropped and counted as parse
/// errors. A line with every field filled is typically under 2 KB.
pub const MAX_LINE: usize = 64 * 1024;

/// Receive syslog datagrams forever.
pub async fn serve_udp<L: DnsLookup + 'static>(
    socket: UdpSocket,
    pipeline: Arc<Pipeline<L>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, _) = socket.recv_from(&mut buf).await?;
        pipeline
            .counters()
            .udp_datagrams
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pipeline.handle_line(&buf[..n]);
    }
}

/// Accept TCP connections forever, reading newline-delimited lines from each.
pub async fn serve_tcp<L: DnsLookup + 'static>(
    listener: TcpListener,
    pipeline: Arc<Pipeline<L>>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            let _ = read_lines(BufReader::new(stream), &pipeline).await;
        });
    }
}

/// Read newline-delimited lines until EOF. Returns how many lines were read.
pub async fn read_lines<R, L>(mut reader: R, pipeline: &Pipeline<L>) -> io::Result<u64>
where
    R: AsyncBufRead + Unpin,
    L: DnsLookup + 'static,
{
    let mut line = Vec::with_capacity(1024);
    let mut count = 0;
    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .await?;
        if n == 0 {
            return Ok(count);
        }
        count += 1;
        if line.len() > MAX_LINE {
            // Skip the rest of the oversized line.
            if line.last() != Some(&b'\n') {
                let mut sink = Vec::new();
                loop {
                    sink.clear();
                    let m = (&mut reader)
                        .take(MAX_LINE as u64)
                        .read_until(b'\n', &mut sink)
                        .await?;
                    if m == 0 || sink.last() == Some(&b'\n') {
                        break;
                    }
                }
            }
            pipeline.reject_line(format!("line longer than {MAX_LINE} bytes"));
            continue;
        }
        pipeline.handle_line(&line);
    }
}
