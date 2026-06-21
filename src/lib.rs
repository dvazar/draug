//! draug — a small, cgroup-aware process supervisor.
//!
//! Wraps a single long-running target process and restarts it *gracefully*
//! (SIGTERM -> grace period -> SIGKILL) on any of:
//!   * a periodic timer (flush slow memory leaks),
//!   * a cgroup memory threshold (`memory.current / memory.max`),
//!   * PSI memory pressure (`memory.pressure`), or
//!   * a stale heartbeat file.
//!
//! Designed to run as a lightweight child of tini:
//!   tini (PID 1) -> draug -> <command> [args...]
//!
//! The supervisor decides *when* to restart and escalates to SIGKILL if the
//! target hangs; the graceful drain itself lives in the target's own signal
//! handler.

pub mod alert;
pub mod cgroup;
pub mod child;
pub mod config;
pub mod decision;
pub mod diagnostics;
pub mod fsm;
pub mod heartbeat;
pub mod log;
pub mod procfs;
pub mod psi;
pub mod supervisor;

pub use config::Config;

/// Build alert sinks from `config` and run the supervisor; return the exit code.
pub fn run(config: Config) -> i32 {
    // Block the supervised signals (SIGTERM, SIGINT, SIGCHLD) on the MAIN thread
    // BEFORE constructing any sink. A sink such as `WebhookSink` spawns a worker
    // thread, which inherits the creating thread's signal mask at spawn time:
    // blocking here first guarantees the worker is born with those signals
    // already masked, closing the startup race where the kernel could route a
    // process-directed signal to a worker that has not yet blocked it itself.
    // No-op on non-Linux (the supervisor event loop is Linux-only).
    supervisor::block_supervised_signals();

    let mut sinks: Vec<std::sync::Arc<dyn alert::AlertSink>> = Vec::new();
    if let Some(url) = config.webhook_url.clone() {
        sinks.push(std::sync::Arc::new(alert::WebhookSink::new(
            url,
            config.service.clone(),
            config.env.clone(),
        )));
    }
    let sink: Box<dyn alert::AlertSink> = if sinks.is_empty() {
        Box::new(alert::NullSink)
    } else {
        Box::new(alert::CompositeSink::new(sinks))
    };
    supervisor::run(config, sink.as_ref())
}
