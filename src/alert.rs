//! Alerting — fires only on anomalies (SIGKILL escalation, crash-loop, and
//! memory/PSI restarts); routine periodic restarts are logged, not alerted.
//!
//! Behind an `AlertSink` trait so tests inject a double. The production sink is
//! the webhook — POST a JSON payload to `DRAUG_WEBHOOK_URL`. The trait makes
//! additional sinks (e.g. a paging integration) a drop-in addition later.
//!
//! Network I/O uses a short timeout and is best-effort: a failed or slow alert
//! must never block the drain/respawn path.

use crate::decision::RestartReason;
use crate::diagnostics::Snapshot;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Bound on the webhook worker's pending-alert queue. Alerts are rare (only
/// anomalies fire one), so 128 pending is generous
/// for any realistic burst. A bounded queue means a slow or black-holed
/// endpoint (each POST blocks the full 5s timeout) can no longer make the
/// queue grow without limit: once it fills, `send` sheds *Warning* alerts
/// instead of leaking memory. Critical alerts are never silently shed — under
/// saturation a Critical evicts the oldest non-Critical to make room (see
/// `WebhookSink::send`). The bound is the right trade-off — never block the
/// event loop, never grow unbounded, never lose a Critical.
const ALERT_QUEUE_CAPACITY: usize = 128;

/// Alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Anomaly classification. Returns `None` when the event is log-only.
/// `escalated` = had to SIGKILL a hung target; `crash_loop` = giving up.
pub fn classify(reason: RestartReason, escalated: bool, crash_loop: bool) -> Option<Severity> {
    if escalated || crash_loop {
        return Some(Severity::Critical);
    }
    match reason {
        RestartReason::Memory | RestartReason::Psi => Some(Severity::Warning),
        RestartReason::Periodic
        | RestartReason::HeartbeatStale
        | RestartReason::Crash
        | RestartReason::Shutdown => None,
    }
}

/// A destination for anomaly alerts.
pub trait AlertSink: Send + Sync {
    fn send(&self, snapshot: &Snapshot, severity: Severity);
}

/// Discards everything (used when no sinks are configured).
pub struct NullSink;
impl AlertSink for NullSink {
    fn send(&self, _snapshot: &Snapshot, _severity: Severity) {}
}

/// Fan-out to several sinks.
pub struct CompositeSink {
    sinks: Vec<Arc<dyn AlertSink>>,
}
impl CompositeSink {
    pub fn new(sinks: Vec<Arc<dyn AlertSink>>) -> CompositeSink {
        CompositeSink { sinks }
    }
}
impl AlertSink for CompositeSink {
    fn send(&self, snapshot: &Snapshot, severity: Severity) {
        for s in &self.sinks {
            s.send(snapshot, severity);
        }
    }
}

/// Block every signal on the current thread. Used by the webhook worker so it
/// never intercepts a signal the supervisor expects to read via signalfd (see
/// `WebhookSink::new`). Errors are swallowed: failing to block here would at
/// worst reintroduce the original race, never crash.
fn block_all_signals() {
    nix::sys::signal::SigSet::all().thread_block().ok();
}

/// The pending-alert queue shared between `send` (producer, the event-loop
/// thread) and the worker (consumer). Guarded by a single `Mutex`; a `Condvar`
/// wakes the worker when work arrives or shutdown is requested.
struct AlertQueue {
    /// FIFO of pending (snapshot, severity) pairs awaiting a POST.
    items: VecDeque<(Snapshot, Severity)>,
    /// Set by `Drop` to tell the worker to drain and exit.
    shutdown: bool,
    /// Count of alerts shed under saturation (Warnings evicted/dropped, plus
    /// the pathological all-Criticals case). Lives inside the lock — no separate
    /// atomic — so it is consistent with the queue state under one hold. (#14:
    /// the old redundant `Arc<AtomicU64>` is gone.)
    dropped: u64,
}

/// POSTs a JSON payload to a webhook URL; best-effort with a short timeout.
///
/// The actual network I/O runs on a dedicated worker thread so `send` never
/// blocks the supervisor's event-loop thread (a slow/black-holed endpoint must
/// not stall the drain/respawn path). `send`
/// merely enqueues the (snapshot, severity) pair into a BOUNDED queue
/// (`Mutex<VecDeque>` + `Condvar`) and returns; the worker owns the single
/// pre-built `ureq::Agent` (with its 5s global timeout) and POSTs each pending
/// alert in order. The queue is bounded (`ALERT_QUEUE_CAPACITY`), so a
/// slow/black-holed endpoint cannot make it grow without bound.
///
/// Admission is SEVERITY-AWARE so a Warning flood can never starve a Critical:
///   * A `Warning` that arrives at a full queue is shed (best-effort): the
///     `dropped` counter is bumped and a concise, rate-limited line is logged.
///   * A `Critical` that arrives at a full queue EVICTS the oldest non-Critical
///     (Warning) to make room, so it is always admitted. Only in the
///     pathological case where the queue is *entirely* full of not-yet-delivered
///     Criticals is a Critical dropped — and even then it is counted and logged,
///     never silent.
///
/// This is what guarantees the crash-loop Critical (sent right before the
/// process exits 1) is never silently lost.
///
/// Worker death is observable (#8): a Drop guard inside the worker flips
/// `alive` to `false` even on a panic-unwind. `send` checks `alive` and, the
/// first time it sees the worker gone, logs exactly once (`death_logged`) then
/// returns — subsequent sends after worker death do not spam the log.
///
/// `Drop` flushes: it sets `shutdown`, wakes the worker, and joins it. The
/// worker drains every queued alert (attempting the POST) before exiting, so a
/// just-enqueued final Critical is actually attempted before the process exits.
/// `lib::run` owns the boxed sink and drops it on the return path, before `main`
/// calls `std::process::exit`. Drop is unbounded (drain-all-then-join): bounding
/// the total flush time risks skipping the final Critical against a black-holed
/// endpoint, so we deliberately do not bound it.
pub struct WebhookSink {
    /// Shared queue + wakeup. `Arc` because the worker holds a clone.
    queue: Arc<(Mutex<AlertQueue>, Condvar)>,
    /// `false` once the worker thread has exited for any reason (normal,
    /// error, or panic-unwind) — flipped by a Drop guard inside the worker.
    alive: Arc<AtomicBool>,
    /// Latches so `send` logs worker death at most once (no spam).
    death_logged: AtomicBool,
    /// `Option` so `Drop` can `.take()` and `join()` it.
    worker: Option<JoinHandle<()>>,
}

impl WebhookSink {
    pub fn new(url: String, service: Option<String>, env: Option<String>) -> WebhookSink {
        // Build the Agent ONCE here and move it into the worker, rather than
        // rebuilding a fresh Agent on every send.
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        let agent: ureq::Agent = config.into();
        let queue = Arc::new((
            Mutex::new(AlertQueue {
                items: VecDeque::new(),
                shutdown: false,
                dropped: 0,
            }),
            Condvar::new(),
        ));
        let alive = Arc::new(AtomicBool::new(true));
        let worker_queue = Arc::clone(&queue);
        let worker_alive = Arc::clone(&alive);
        let worker = std::thread::spawn(move || {
            // Flip `alive` to false whenever this thread leaves `run` — even via
            // a panic-unwind — so `send` can observe worker death (#8). Held for
            // the whole thread body; its `Drop` runs last on the way out.
            struct AliveGuard(Arc<AtomicBool>);
            impl Drop for AliveGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::SeqCst);
                }
            }
            let _alive_guard = AliveGuard(worker_alive);

            // Block ALL signals on this worker thread as defense-in-depth. The
            // supervisor relies on signalfd, which only delivers reliably when
            // the watched signals (SIGCHLD, SIGTERM, SIGINT) are blocked in
            // EVERY thread of the process — otherwise the kernel may route one
            // to this thread (which has no handler) and the supervisor's
            // signalfd never sees it, stalling reaps/respawns and shutdown. The
            // main thread now blocks the supervised set BEFORE spawning this
            // worker, so the worker already inherits a blocked mask; blocking
            // the full set here is belt-and-suspenders (and this worker has no
            // business handling any signal). (No-op / harmless on non-Linux
            // test hosts.)
            block_all_signals();
            worker_loop(&worker_queue, &agent, &url, &service, &env);
        });
        WebhookSink {
            queue,
            alive,
            death_logged: AtomicBool::new(false),
            worker: Some(worker),
        }
    }

    /// Number of alerts shed under saturation (full queue).
    #[cfg(test)]
    fn dropped_count(&self) -> u64 {
        self.queue.0.lock().unwrap().dropped
    }

    /// Test hook: simulate the worker thread having died (the in-worker Drop
    /// guard flips `alive` the same way on a real exit/panic). Lets a test
    /// exercise the `send`-side worker-death detection (#8) deterministically,
    /// without racing a real thread teardown.
    #[cfg(test)]
    fn force_worker_dead_for_test(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// Test hook: whether `send` has already logged the worker-death diagnostic.
    #[cfg(test)]
    fn death_logged_for_test(&self) -> bool {
        self.death_logged.load(Ordering::SeqCst)
    }
}

/// Worker loop: wait for work, pop one alert, POST it (NEVER while holding the
/// lock), repeat. On shutdown, drain everything still queued, then return.
fn worker_loop(
    queue: &Arc<(Mutex<AlertQueue>, Condvar)>,
    agent: &ureq::Agent,
    url: &str,
    service: &Option<String>,
    env: &Option<String>,
) {
    let (lock, cvar) = &**queue;
    loop {
        // Acquire the lock, take exactly one item, then RELEASE the lock before
        // the POST. The Condvar pairing: wait while empty and not shutting down;
        // `send` and `Drop` both `notify_one` after mutating, so no lost wakeup.
        let next = {
            let mut q = lock.lock().unwrap();
            while q.items.is_empty() && !q.shutdown {
                q = cvar.wait(q).unwrap();
            }
            match q.items.pop_front() {
                Some(item) => item,
                // Empty AND shutdown => fully drained, time to exit.
                None => return,
            }
        };
        let (snapshot, severity) = next;
        let payload = snapshot_json(&snapshot, severity, service, env);
        let body = payload.to_string();
        let result = agent
            .post(url)
            .header("Content-Type", "application/json")
            .send(body.as_str());
        if let Err(e) = result {
            eprintln!("draug: webhook alert failed: {e}");
        }
    }
}

impl Drop for WebhookSink {
    fn drop(&mut self) {
        // Signal shutdown and wake the worker BEFORE join so it can observe the
        // flag and exit once the queue is drained — joining first would deadlock
        // if the worker were parked in `cvar.wait`. The worker drains every
        // remaining alert (attempting each POST) before returning, so a
        // just-enqueued final Critical is flushed. Drop is intentionally
        // unbounded (see the type doc): bounding the flush could skip the final
        // Critical against a black-holed endpoint.
        {
            let (lock, cvar) = &*self.queue;
            let mut q = lock.lock().unwrap();
            q.shutdown = true;
            cvar.notify_one();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn snapshot_json(
    snapshot: &Snapshot,
    severity: Severity,
    service: &Option<String>,
    env: &Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "service": service,
        "env": env,
        "severity": severity.as_str(),
        "reason": format!("{:?}", snapshot.reason),
        "restart_count": snapshot.restart_count,
        "mem_current": snapshot.mem_current,
        "mem_max": snapshot.mem_max,
        "mem_ratio": snapshot.mem_ratio,
        "cpu_quota_ratio": snapshot.cpu_quota_ratio,
        "threads": snapshot.threads,
        "open_fds": snapshot.open_fds,
        "heartbeat_age_secs": snapshot.heartbeat_age_secs,
    })
}

impl AlertSink for WebhookSink {
    fn send(&self, snapshot: &Snapshot, severity: Severity) {
        // Non-blocking: enqueue and return at once. Never touch the network on
        // the caller's (event-loop) thread, and never wait on a full queue — the
        // only blocking here is a brief mutex hold (no I/O under the lock).

        // #8: if the worker has died (normal exit, error, or panic-unwind), the
        // queue would silently black-hole every future alert. Surface it ONCE.
        if !self.alive.load(Ordering::SeqCst) {
            if !self.death_logged.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "draug: webhook alert worker is not running; \
                     alerts will not be delivered"
                );
            }
            return;
        }

        let (lock, cvar) = &*self.queue;
        let mut q = lock.lock().unwrap();

        if q.items.len() < ALERT_QUEUE_CAPACITY {
            // Room available — fast path.
            q.items.push_back((snapshot.clone(), severity));
            cvar.notify_one();
            return;
        }

        // Queue is full. Admission is severity-aware so a Warning flood can
        // never starve a Critical (#11).
        match severity {
            Severity::Warning => {
                // Warnings are best-effort: shed this one. Bump the counter and
                // log concisely — first drop, then power-of-two thresholds
                // (1, 2, 4, 8, ...) — so a restart storm cannot flood the log.
                q.dropped += 1;
                let n = q.dropped;
                drop(q);
                if n == 1 || n.is_power_of_two() {
                    eprintln!(
                        "draug: webhook alert queue full, dropping Warning alert \
                         (total dropped: {n})"
                    );
                }
            }
            Severity::Critical => {
                // A Critical must never be silently dropped (#1). Evict the
                // OLDEST non-Critical (Warning) to make room, then admit it.
                let evict = q
                    .items
                    .iter()
                    .position(|(_, sev)| *sev != Severity::Critical);
                match evict {
                    Some(idx) => {
                        q.items.remove(idx);
                        q.items.push_back((snapshot.clone(), severity));
                        q.dropped += 1; // the evicted Warning counts as shed
                        let n = q.dropped;
                        cvar.notify_one();
                        drop(q);
                        if n == 1 || n.is_power_of_two() {
                            eprintln!(
                                "draug: webhook alert queue full, evicted a Warning \
                                 to admit a Critical (total dropped: {n})"
                            );
                        }
                    }
                    None => {
                        // Pathological: the queue is ENTIRELY full of
                        // not-yet-delivered Criticals. We cannot evict a peer
                        // Critical, so this one is dropped — but it is counted
                        // and logged, NEVER silent.
                        q.dropped += 1;
                        let n = q.dropped;
                        drop(q);
                        eprintln!(
                            "draug: webhook alert queue full of undelivered \
                             Critical alerts; dropping a Critical \
                             (total dropped: {n})"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::RestartReason;
    use crate::diagnostics::Snapshot;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn snap(reason: RestartReason) -> Snapshot {
        Snapshot {
            reason,
            restart_count: 1,
            mem_current: Some(900),
            mem_max: Some(1000),
            mem_ratio: Some(0.9),
            cpu_quota_ratio: None,
            threads: None,
            open_fds: None,
            heartbeat_age_secs: None,
        }
    }

    #[test]
    fn classification_matrix() {
        assert_eq!(classify(RestartReason::Periodic, false, false), None);
        assert_eq!(classify(RestartReason::HeartbeatStale, false, false), None);
        assert_eq!(classify(RestartReason::Crash, false, false), None);
        assert_eq!(
            classify(RestartReason::Memory, false, false),
            Some(Severity::Warning)
        );
        assert_eq!(
            classify(RestartReason::Psi, false, false),
            Some(Severity::Warning)
        );
        // escalation to SIGKILL (hang) and crash-loop are always critical
        assert_eq!(
            classify(RestartReason::Periodic, true, false),
            Some(Severity::Critical)
        );
        assert_eq!(
            classify(RestartReason::Crash, false, true),
            Some(Severity::Critical)
        );
    }

    #[derive(Default)]
    struct RecordingSink {
        sent: Mutex<Vec<(RestartReason, Severity)>>,
    }
    impl AlertSink for RecordingSink {
        fn send(&self, snap: &Snapshot, severity: Severity) {
            self.sent.lock().unwrap().push((snap.reason, severity));
        }
    }

    #[test]
    fn composite_forwards_to_all() {
        let a = Arc::new(RecordingSink::default());
        let b = Arc::new(RecordingSink::default());
        let composite = CompositeSink::new(vec![a.clone(), b.clone()]);
        composite.send(&snap(RestartReason::Memory), Severity::Warning);
        assert_eq!(a.sent.lock().unwrap().len(), 1);
        assert_eq!(b.sent.lock().unwrap().len(), 1);
    }

    /// Read one full HTTP request (headers + JSON body) from `stream` and return
    /// the raw request text — or `None` once the peer closes the connection with
    /// no further request. Stops a read once the header/body separator AND the
    /// JSON body terminator have arrived, so it never returns a partial request
    /// split across TCP segments.
    ///
    /// Single source of the request-framing logic for both unit mocks: the
    /// "reply" vs "no-reply" difference is the caller's, not this helper's.
    /// `read_one_request` calls this then `write_200_close`; the gated mock calls
    /// this, withholds the reply, then sends `write_200_close` after `release`.
    fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                // Clean EOF with no bytes yet => the peer is done; no request.
                Ok(0) => {
                    return if data.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&data).to_string())
                    };
                }
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    let s = String::from_utf8_lossy(&data);
                    if let Some(idx) = s.find("\r\n\r\n")
                        && s[idx + 4..].contains('}')
                    {
                        break;
                    }
                }
                // Read timeout / error. With no bytes buffered this means the
                // connection is idle or closed: signal "no more requests" so the
                // per-connection loop ends instead of spinning on empty reads.
                Err(_) => {
                    if data.is_empty() {
                        return None;
                    }
                    break; // partial request — let the caller's asserts report
                }
            }
        }
        Some(String::from_utf8_lossy(&data).to_string())
    }

    /// Reply `200 OK` with an empty body and `Connection: close` so the client
    /// (ureq) does NOT pool/reuse the socket; every POST then arrives on a
    /// connection the mock fully owns end-to-end. `Content-Length: 0` lets the
    /// client see a complete response.
    fn write_200_close(stream: &mut std::net::TcpStream) {
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    /// Read one full HTTP request, reply `200 OK` with `Connection: close`, and
    /// return the raw request text (or `None` once the peer closes with no
    /// request). Thin wrapper over `read_http_request` + `write_200_close`.
    fn read_one_request(stream: &mut std::net::TcpStream) -> Option<String> {
        let req = read_http_request(stream)?;
        write_200_close(stream);
        Some(req)
    }

    /// Accept exactly `total` connections, recording each request body, and
    /// return them in arrival order. Every reply carries `Connection: close`, so
    /// the client (ureq) opens exactly one fresh connection per POST — one
    /// accept per request, with no connection reuse to deadlock the loop.
    fn mock_server(total: usize) -> (String, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || collect_bodies(listener, total, None, None));
        (url, handle)
    }

    /// Like `mock_server`, but GATES the very first request: it reads the first
    /// request, signals `ready` (the worker has now popped exactly one alert and
    /// is parked awaiting the reply; the queue is empty again), and withholds
    /// that reply until `release` fires. After release it serves the remaining
    /// `total - 1` requests as usual. Lets a test hold the worker mid-POST
    /// deterministically (no sleeps / timing guesses).
    fn gated_mock_server(
        total: usize,
    ) -> (
        String,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        JoinHandle<Vec<String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            collect_bodies(listener, total, Some(ready_tx), Some(release_rx))
        });
        (url, ready_rx, release_tx, handle)
    }

    /// Shared accept loop for the mock servers. Accepts EXACTLY `total`
    /// connections (one request each, guaranteed by the `Connection: close`
    /// reply), recording each body. Each connection is served in its own thread
    /// so a withheld reply on one cannot stall reads on the others. When `ready`
    /// is `Some`, the FIRST connection is GATED: its body is recorded and `ready`
    /// is signalled, but the 200 reply is withheld until `release` fires.
    fn collect_bodies(
        listener: TcpListener,
        total: usize,
        ready: Option<std::sync::mpsc::Sender<()>>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Vec<String> {
        let bodies = Arc::new(Mutex::new(vec![String::new(); total]));
        let mut handlers = Vec::with_capacity(total);
        let mut gate = Some((ready, release));
        for i in 0..total {
            let (mut stream, _) = match listener.accept() {
                Ok(c) => c,
                Err(_) => break,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let bodies = Arc::clone(&bodies);
            // Only connection 0 is gated; later connections get `None`.
            let conn_gate = if i == 0 { gate.take() } else { None };
            handlers.push(std::thread::spawn(move || {
                if let Some((ready, release)) = conn_gate {
                    // Gated first connection: read, signal, wait, then reply.
                    let body = read_request_no_reply(&mut stream);
                    bodies.lock().unwrap()[i] = body;
                    if let Some(tx) = ready {
                        tx.send(()).unwrap();
                    }
                    if let Some(rx) = release {
                        rx.recv().unwrap();
                    }
                    write_200_close(&mut stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                } else if let Some(body) = read_one_request(&mut stream) {
                    bodies.lock().unwrap()[i] = body;
                }
            }));
        }
        // Wait for every handler to finish writing its reply before returning.
        for h in handlers {
            let _ = h.join();
        }
        Arc::try_unwrap(bodies).unwrap().into_inner().unwrap()
    }

    /// Read one full HTTP request from `stream` but DO NOT reply (the caller
    /// replies later via `write_200_close` to unblock the client). Returns the
    /// raw request text. Reuses the shared `read_http_request` framing; a closed
    /// peer with no request yields an empty string (the gated path never sees it).
    fn read_request_no_reply(stream: &mut std::net::TcpStream) -> String {
        read_http_request(stream).unwrap_or_default()
    }

    #[test]
    fn webhook_posts_json_body() {
        let (url, handle) = mock_server(1);
        let sink = WebhookSink::new(url, Some("svc".into()), Some("test".into()));
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        // Drop the sink to flush (close channel + join worker): this makes the
        // assertion deterministic without any sleep — by the time `drop`
        // returns, the worker has finished POSTing.
        drop(sink);
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 1);
        let req = &bodies[0];
        assert!(req.contains("POST /hook"));
        assert!(req.contains("\"reason\":\"Memory\""));
        assert!(req.contains("\"severity\":\"warning\""));
        assert!(req.contains("\"service\":\"svc\""));
    }

    #[test]
    fn webhook_send_is_non_blocking() {
        // Hold the worker mid-POST (gated mock), then fire a batch of sends.
        // Every send must return without waiting on the stuck network I/O, so
        // the whole batch completes near-instantly. `send` may only take a brief
        // mutex hold — never block on the POST.
        let (url, ready_rx, _release_tx, _handle) = gated_mock_server(1);
        let sink = WebhookSink::new(url, None, None);
        // Kick off the first POST and wait until the worker is provably parked
        // on it (queue empty again), so the timing below measures pure enqueue.
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        ready_rx.recv().unwrap();
        let start = std::time::Instant::now();
        for _ in 0..ALERT_QUEUE_CAPACITY {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "sends must be non-blocking even while the worker is stuck \
             (took {elapsed:?})"
        );
        // Forget the sink so its Drop does not join the still-POSTing worker.
        std::mem::forget(sink);
    }

    #[test]
    fn webhook_bounded_queue_drops_warning_when_saturated() {
        // Hold the worker mid-POST so the queue cannot drain. Fill it to
        // capacity, then keep sending Warnings: each excess Warning must be
        // shed (dropped counter rises) and every send must stay non-blocking.
        let (url, ready_rx, _release_tx, _handle) = gated_mock_server(1);
        let sink = WebhookSink::new(url, None, None);
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        ready_rx.recv().unwrap(); // worker now parked on the POST; queue empty
        // Fill exactly to capacity — none of these may be dropped yet.
        for _ in 0..ALERT_QUEUE_CAPACITY {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        assert_eq!(
            sink.dropped_count(),
            0,
            "filling exactly to capacity must not drop anything"
        );
        // Now the queue is full: further Warnings are shed.
        let extra = 50;
        let start = std::time::Instant::now();
        for _ in 0..extra {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "sends must stay non-blocking even when saturated (took {elapsed:?})"
        );
        assert_eq!(
            sink.dropped_count(),
            extra,
            "every Warning past capacity must be counted as dropped"
        );
        std::mem::forget(sink);
    }

    #[test]
    fn webhook_critical_survives_saturation() {
        // The headline guarantee (#1, #11): a Warning flood must NOT crowd out a
        // Critical. Saturate the queue with Warnings while the worker is gated,
        // then send a Critical — it must be ADMITTED (evicting an oldest
        // Warning, counted as dropped) and ultimately DELIVERED once the worker
        // is released. On the OLD code the Critical was silently dropped.
        // total bodies the mock will serve: the gated first POST + a full
        // queue's worth of buffered alerts. After eviction the buffered set is
        // (CAPACITY - 1) Warnings + 1 Critical, plus the first in-flight one.
        let total = ALERT_QUEUE_CAPACITY + 1;
        let (url, ready_rx, release_tx, handle) = gated_mock_server(total);
        let sink = WebhookSink::new(url, None, None);
        // First send is popped by the worker and gated mid-POST.
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        ready_rx.recv().unwrap(); // queue now empty, worker parked on the POST
        // Saturate with Warnings.
        for _ in 0..ALERT_QUEUE_CAPACITY {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        assert_eq!(sink.dropped_count(), 0, "capacity-fill drops nothing");
        // The Critical arrives at a FULL queue: it must evict an oldest Warning
        // (counted) rather than be dropped itself.
        sink.send(&snap(RestartReason::Crash), Severity::Critical);
        assert_eq!(
            sink.dropped_count(),
            1,
            "admitting the Critical must evict exactly one Warning"
        );
        // Release the worker; it drains everything (incl. the Critical).
        release_tx.send(()).unwrap();
        drop(sink); // flush + join
        let bodies = handle.join().unwrap();
        assert_eq!(
            bodies.len(),
            total,
            "the worker must deliver every retained alert"
        );
        let criticals = bodies
            .iter()
            .filter(|b| b.contains("\"severity\":\"critical\""))
            .count();
        assert_eq!(
            criticals, 1,
            "the Critical must be delivered, not silently dropped"
        );
    }

    #[test]
    fn webhook_critical_evicts_oldest_warning() {
        // Saturate, then send a Critical: it must evict the OLDEST queued
        // Warning, so total delivered Warnings = CAPACITY - 1 (the gated first
        // POST is a Warning that is delivered separately).
        let total = ALERT_QUEUE_CAPACITY + 1; // first POST + (CAP-1 W + 1 C)
        let (url, ready_rx, release_tx, handle) = gated_mock_server(total);
        let sink = WebhookSink::new(url, None, None);
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        ready_rx.recv().unwrap();
        for _ in 0..ALERT_QUEUE_CAPACITY {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        sink.send(&snap(RestartReason::Crash), Severity::Critical);
        release_tx.send(()).unwrap();
        drop(sink);
        let bodies = handle.join().unwrap();
        let warnings = bodies
            .iter()
            .filter(|b| b.contains("\"severity\":\"warning\""))
            .count();
        let criticals = bodies
            .iter()
            .filter(|b| b.contains("\"severity\":\"critical\""))
            .count();
        // 1 gated Warning + (CAPACITY - 1) buffered Warnings delivered.
        assert_eq!(warnings, ALERT_QUEUE_CAPACITY);
        assert_eq!(criticals, 1);
    }

    #[test]
    fn webhook_delivers_multiple_sends() {
        let (url, handle) = mock_server(3);
        let sink = WebhookSink::new(url, None, None);
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        sink.send(&snap(RestartReason::Psi), Severity::Warning);
        sink.send(&snap(RestartReason::Crash), Severity::Critical);
        // Drop flushes the whole queue: the worker drains all three in order.
        drop(sink);
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 3);
        assert!(bodies[0].contains("\"reason\":\"Memory\""));
        assert!(bodies[1].contains("\"reason\":\"Psi\""));
        assert!(bodies[2].contains("\"reason\":\"Crash\""));
        assert!(bodies[2].contains("\"severity\":\"critical\""));
    }

    #[test]
    fn webhook_unreachable_does_not_panic() {
        // Port 1 is reserved/closed; send must swallow the error. Dropping the
        // sink flushes (joins the worker) without panicking on the failed POST.
        let sink = WebhookSink::new("http://127.0.0.1:1/hook".into(), None, None);
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        drop(sink);
    }

    #[test]
    fn webhook_drop_flushes_final_critical() {
        // Drop must flush queued alerts before joining the worker, so a final
        // just-enqueued Critical is actually attempted (the crash-loop alert
        // scenario). Enqueue several alerts ending in a Critical, then drop the
        // sink WITHOUT giving the worker time to drain first; the mock must still
        // receive every one, the Critical last.
        let (url, handle) = mock_server(3);
        let sink = WebhookSink::new(url, None, None);
        sink.send(&snap(RestartReason::Memory), Severity::Warning);
        sink.send(&snap(RestartReason::Psi), Severity::Warning);
        sink.send(&snap(RestartReason::Crash), Severity::Critical);
        drop(sink); // flush-before-join
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 3, "Drop must flush all queued alerts");
        assert!(
            bodies
                .iter()
                .any(|b| b.contains("\"severity\":\"critical\"")),
            "the final Critical must be flushed on Drop"
        );
    }

    #[test]
    fn webhook_worker_death_is_logged_once() {
        // #8: once the worker is gone, every later `send` would silently
        // black-hole alerts. The first `send` after death must surface it
        // exactly once; later sends must NOT relog (no spam).
        let sink = WebhookSink::new("http://127.0.0.1:1/hook".into(), None, None);
        assert!(!sink.death_logged_for_test());
        // Simulate the worker having died (its Drop guard flips this on a real
        // exit/panic-unwind).
        sink.force_worker_dead_for_test();
        sink.send(&snap(RestartReason::Crash), Severity::Critical);
        assert!(
            sink.death_logged_for_test(),
            "first send after worker death must log the diagnostic once"
        );
        // Many more sends must not change the latch (log-once, no spam) and must
        // not panic.
        for _ in 0..10 {
            sink.send(&snap(RestartReason::Memory), Severity::Warning);
        }
        assert!(
            sink.death_logged_for_test(),
            "the death diagnostic latch stays set (logged exactly once)"
        );
        std::mem::forget(sink); // worker is "dead" for the test; skip join
    }

    #[test]
    fn null_sink_is_noop() {
        NullSink.send(&snap(RestartReason::Periodic), Severity::Warning);
    }
}
