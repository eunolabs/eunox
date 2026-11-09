//! eunox: tells a site which AI agents hit it and which are who they claim to
//! be, from its gateway's access logs. Observe-only: nothing sits in the
//! request path.
//!
//! The `eunox` binary wires `eunox-directory` (keys, IP ranges, reverse DNS),
//! `eunox-ingest` (log receivers and classification) and `eunox-stats`
//! (counters) to a small HTTP server for the report and `/metrics`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod app;
pub mod config;
pub mod demo;
pub mod otlp_export;
pub mod render;
pub mod server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use eunox_directory::unix_now;
use eunox_ingest::{read_lines, serve_kong, serve_otlp, serve_tcp, serve_udp};
use tokio::io::AsyncBufRead;
use tokio::net::{TcpListener, UdpSocket};

pub use app::App;
pub use config::Config;

/// A started server and the addresses it bound.
pub struct Running {
    /// The shared state.
    pub app: Arc<App>,
    /// Report and metrics address.
    pub http: SocketAddr,
    /// UDP syslog address, if enabled.
    pub syslog_udp: Option<SocketAddr>,
    /// TCP lines address, if enabled.
    pub lines_tcp: Option<SocketAddr>,
    /// OTLP logs gRPC address, if enabled.
    pub otlp_grpc: Option<SocketAddr>,
    /// Kong `http-log` address, if enabled.
    pub kong_http: Option<SocketAddr>,
}

/// Bind every listener and start serving in the background. Key directories
/// and ranges load in the background too; until they do, requests that
/// depend on them come out unverifiable, never spoofed.
pub async fn start(config: &Config) -> Result<Running, String> {
    let app = Arc::new(App::new(config)?);
    tokio::spawn(app.directory.clone().run());

    let http = TcpListener::bind(config.http)
        .await
        .map_err(|e| format!("EUNOX_HTTP {}: {e}", config.http))?;
    let http_addr = http.local_addr().map_err(|e| e.to_string())?;
    tokio::spawn(server::serve(http, app.clone()));

    let syslog_udp = match config.syslog_udp {
        None => None,
        Some(addr) => {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|e| format!("EUNOX_SYSLOG_UDP {addr}: {e}"))?;
            let bound = socket.local_addr().map_err(|e| e.to_string())?;
            tokio::spawn(serve_udp(socket, app.pipeline.clone()));
            Some(bound)
        }
    };
    let lines_tcp = match config.lines_tcp {
        None => None,
        Some(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("EUNOX_LINES_TCP {addr}: {e}"))?;
            let bound = listener.local_addr().map_err(|e| e.to_string())?;
            tokio::spawn(serve_tcp(listener, app.pipeline.clone()));
            Some(bound)
        }
    };
    let otlp_grpc = match config.otlp_grpc {
        None => None,
        Some(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("EUNOX_OTLP_GRPC {addr}: {e}"))?;
            let bound = listener.local_addr().map_err(|e| e.to_string())?;
            tokio::spawn(serve_otlp(listener, app.pipeline.clone()));
            Some(bound)
        }
    };
    let kong_http = match config.kong_http {
        None => None,
        Some(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("EUNOX_KONG_HTTP {addr}: {e}"))?;
            let bound = listener.local_addr().map_err(|e| e.to_string())?;
            tokio::spawn(serve_kong(listener, app.pipeline.clone()));
            Some(bound)
        }
    };
    if let Some(endpoint) = &config.otlp_metrics_endpoint {
        tokio::spawn(otlp_export::run(
            app.clone(),
            endpoint.clone(),
            config.otlp_metrics_interval,
        ));
    }
    Ok(Running {
        app,
        http: http_addr,
        syslog_udp,
        lines_tcp,
        otlp_grpc,
        kong_http,
    })
}

/// Classify a saved log and return the text report. Fetches key directories
/// and ranges once first, so the result doesn't depend on fetch timing.
pub async fn replay<R: AsyncBufRead + Unpin>(config: &Config, reader: R) -> Result<String, String> {
    let app = App::new(config)?;
    app.directory.refresh(unix_now()).await;
    read_lines(reader, &app.pipeline)
        .await
        .map_err(|e| format!("reading the log: {e}"))?;
    app.settle(Duration::from_secs(15)).await;
    Ok(app.render(render::text))
}
