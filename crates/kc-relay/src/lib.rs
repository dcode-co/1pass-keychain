//! `kc-relay`: the relay between `kc` devices. It holds one-shot channels in
//! memory and remembered-device inboxes in SQLite, and never sees plaintext.
//! The HTTP contract is `kc-wire`; the rules are `docs/PROTOCOL.md` §5.

pub mod body;
pub mod channels;
pub mod config;
pub mod error;
pub mod http;
pub mod inbox;
pub mod ip;
pub mod limiter;
pub mod logging;
pub mod serve;
pub mod util;

use std::future::Future;

pub use config::{Config, DbLocation};
pub use http::{AppState, router};

/// Serve on `listener` until `shutdown` resolves, then drain: long-polls end
/// at once, in-flight requests finish (within `drain_timeout`), background
/// tasks stop.
pub async fn serve(
    state: AppState,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let background = state.spawn_background();
    let app = router(state.clone());
    let draining = state.clone();
    let result = serve::run(listener, app, &state.cfg.http, async move {
        shutdown.await;
        draining.begin_shutdown();
    })
    .await;
    state.begin_shutdown();
    // Background tasks stop between batches; don't wait on them forever.
    let mut background = background;
    let joined = async {
        for task in &mut background {
            let _ = task.await;
        }
    };
    if tokio::time::timeout(std::time::Duration::from_secs(5), joined)
        .await
        .is_err()
    {
        for task in &background {
            task.abort();
        }
    }
    result.map_err(Into::into)
}

#[cfg(feature = "test-util")]
mod testing {
    use std::net::SocketAddr;

    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use crate::{AppState, Config};

    /// A relay on a loopback port for end-to-end tests. Dropping it stops the
    /// server; `shutdown` also waits for it.
    pub struct TestRelay {
        pub addr: SocketAddr,
        pub state: AppState,
        stop: Option<oneshot::Sender<()>>,
        task: Option<JoinHandle<anyhow::Result<()>>>,
    }

    impl TestRelay {
        /// `http://127.0.0.1:<port>`, without a trailing slash.
        pub fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        pub async fn shutdown(mut self) -> anyhow::Result<()> {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            match self.task.take() {
                Some(task) => task.await?,
                None => Ok(()),
            }
        }
    }

    impl Drop for TestRelay {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    /// Bind `cfg.bind` (use port 0; `Config::for_tests()` does) and serve in
    /// the background on the current runtime.
    pub async fn spawn_test_relay(cfg: Config) -> anyhow::Result<TestRelay> {
        let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
        let addr = listener.local_addr()?;
        let state = AppState::new(cfg)?;
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(crate::serve(state.clone(), listener, async move {
            let _ = stopped.await;
        }));
        Ok(TestRelay {
            addr,
            state,
            stop: Some(stop),
            task: Some(task),
        })
    }
}

#[cfg(feature = "test-util")]
pub use testing::{TestRelay, spawn_test_relay};
