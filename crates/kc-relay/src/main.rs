//! `kc-relay` binary. Configuration comes from the environment
//! (`KC_RELAY_BIND`, `KC_RELAY_DB`, `KC_RELAY_TRUSTED_PROXIES`, `RUST_LOG`).

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use kc_relay::{AppState, Config};

const USAGE: &str = "usage: kc-relay [--healthcheck | --version | --help]

Environment:
  KC_RELAY_BIND             listen address (default 0.0.0.0:8080)
  KC_RELAY_DB               SQLite file for inboxes (default /data/relay.db; :memory: for none)
  KC_RELAY_TRUSTED_PROXIES  comma-separated CIDRs allowed to set x-kc-client-ip
                            (default: loopback and Docker's private ranges)
  RUST_LOG                  log filter (default info)";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("--healthcheck") => return healthcheck(),
        Some("--version" | "-V") => {
            println!("kc-relay {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(_) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("kc-relay: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build();
    let result = match runtime {
        Ok(rt) => {
            let result = rt.block_on(run(cfg));
            // A database call still running on a blocking thread must not hold
            // the process past the container's stop grace period.
            rt.shutdown_timeout(Duration::from_secs(5));
            result
        }
        Err(e) => Err(e.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "kc-relay stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(
        bind = %cfg.bind,
        trusted_proxies = cfg.trusted_proxies.len(),
        version = env!("CARGO_PKG_VERSION"),
        "kc-relay listening"
    );
    let state = AppState::new(cfg)?;
    kc_relay::serve(state, listener, shutdown_signal()).await?;
    tracing::info!("kc-relay stopped cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received, draining");
}

/// `GET /healthz` against our own listener, for the container HEALTHCHECK
/// (the runtime image has no curl).
fn healthcheck() -> ExitCode {
    let bind = match Config::from_env() {
        Ok(cfg) => cfg.bind,
        Err(e) => {
            eprintln!("kc-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let target = kc_relay::ip::local_target(bind);
    let probe = || -> std::io::Result<bool> {
        let timeout = Duration::from_secs(3);
        let mut stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut head = Vec::with_capacity(256);
        stream.take(256).read_to_end(&mut head)?;
        Ok(head.starts_with(b"HTTP/1.1 200 ") && head.ends_with(b"ok"))
    };
    match probe() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("kc-relay: healthz did not answer 200 ok");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("kc-relay: healthz unreachable on {target}: {e}");
            ExitCode::FAILURE
        }
    }
}
