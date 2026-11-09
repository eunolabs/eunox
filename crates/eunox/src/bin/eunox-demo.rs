//! Demo traffic generator for the compose demo. See `eunox::demo`.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let result = match eunox::demo::DemoConfig::from_env() {
        Ok(config) => eunox::demo::run(config).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eunox-demo: {e}");
            ExitCode::FAILURE
        }
    }
}
