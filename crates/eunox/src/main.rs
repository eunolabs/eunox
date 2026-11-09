use std::process::ExitCode;

use eunox::{Config, config::DEFAULT_HTTP};
use tokio::io::BufReader;

const USAGE: &str = "\
usage:
  eunox [serve]              receive access logs and serve the report
  eunox replay [FILE]        classify a saved log (stdin if FILE is - or missing) and print the report
  eunox report [--url URL]   print a running eunox's report (default http://127.0.0.1:8040)
  eunox sign COMMAND ...     act as a Web Bot Auth operator: init, request, serve, export
                             (`eunox sign help` for details)

configuration (environment):
  EUNOX_SYSLOG_UDP       UDP syslog address, or off            (default 0.0.0.0:5140)
  EUNOX_LINES_TCP        TCP address for JSON lines            (default off)
  EUNOX_OTLP_GRPC        OTLP logs over gRPC (Envoy), or off   (default 0.0.0.0:4317)
  EUNOX_KONG_HTTP        Kong http-log endpoint, or off        (default 0.0.0.0:8041)
  EUNOX_HTTP             report, /report.txt, /metrics         (default 0.0.0.0:8040)
  EUNOX_RDNS             forward-confirmed reverse DNS, on|off (default on)
  EUNOX_REFRESH_SECS     key directory and range refresh       (default 3600)
  EUNOX_SEED_SOURCES     built-in operator sources, on|off     (default on)
  EUNOX_OTLP_METRICS_ENDPOINT       push metrics over OTLP gRPC, http://host:4317 (default off)
  EUNOX_OTLP_METRICS_INTERVAL_SECS  OTLP metrics export interval  (default 60)
  EUNOX_KEY_DIRECTORIES  extra key directories, operator=url,...
  EUNOX_RANGES           extra range files, set-id=url,...
";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["serve"] => serve().await,
        ["replay"] | ["replay", "-"] => replay(None).await,
        ["replay", path] => replay(Some(path)).await,
        ["report"] => report(&format!("http://127.0.0.1:{}", port(DEFAULT_HTTP))).await,
        ["report", "--url", url] => report(url).await,
        ["sign", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|s| (*s).to_owned()).collect();
            eunox::sign::main(&rest).await
        }
        ["help" | "-h" | "--help"] => {
            print!("{USAGE}");
            Ok(())
        }
        ["--version" | "-V"] => {
            println!("eunox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(format!("unrecognized arguments\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eunox: {e}");
            ExitCode::FAILURE
        }
    }
}

fn port(addr: &str) -> &str {
    addr.rsplit(':').next().unwrap_or("8040")
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env()?;
    let running = eunox::start(&config).await?;
    eprintln!("eunox: report on http://{}/", running.http);
    if let Some(a) = running.syslog_udp {
        eprintln!("eunox: syslog on udp://{a}");
    }
    if let Some(a) = running.lines_tcp {
        eprintln!("eunox: JSON lines on tcp://{a}");
    }
    if let Some(a) = running.otlp_grpc {
        eprintln!("eunox: OTLP logs (gRPC) on {a}");
    }
    if let Some(a) = running.kong_http {
        eprintln!("eunox: Kong http-log on http://{a}/");
    }
    if let Some(e) = &config.otlp_metrics_endpoint {
        eprintln!(
            "eunox: exporting OTLP metrics to {e} every {}s",
            config.otlp_metrics_interval.as_secs()
        );
    }
    shutdown_signal().await;
    eprintln!("eunox: shutting down");
    Ok(())
}

async fn replay(path: Option<&str>) -> Result<(), String> {
    let mut config = Config::from_env()?;
    config.syslog_udp = None;
    config.lines_tcp = None;
    config.otlp_grpc = None;
    config.kong_http = None;
    let report = match path {
        None => eunox::replay(&config, BufReader::new(tokio::io::stdin())).await?,
        Some(p) => {
            let file = tokio::fs::File::open(p)
                .await
                .map_err(|e| format!("{p}: {e}"))?;
            eunox::replay(&config, BufReader::new(file)).await?
        }
    };
    print!("{report}");
    Ok(())
}

async fn report(url: &str) -> Result<(), String> {
    let url = format!("{}/report.txt", url.trim_end_matches('/'));
    let body = reqwest::get(&url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("{url}: {e}"))?
        .text()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    print!("{body}");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
