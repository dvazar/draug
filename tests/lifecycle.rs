//! Integration tests for the supervisor lifecycle.
//!
//! These drive the `fake_target` helper bin (located via
//! `env!("CARGO_BIN_EXE_fake_target")`) through a temp cgroup root and a temp
//! heartbeat file. The matrix is destructive-first: hang -> SIGKILL, exec
//! failure, fast-exit crash-loop, stale heartbeat, memory threshold, then the
//! happy path and shutdown semantics.
//!
//! NOTE: EPOLLERR/EPOLLHUP on the PSI trigger fd (finding #2) is covered by the
//! `psi_err_or_hup_is_fatal_but_pri_is_not` unit test in src/supervisor.rs, not
//! an end-to-end case: forcing a real kernel PSI trigger fd into error/hangup
//! from the test harness is not practical. The wiring (deregister + fall back to
//! PSI-off) is exercised by code review.
//!
//! NOTE: The startup-race PSI recovery (#3 — trigger appears after startup and
//! draug upgrades to event mode) is covered by the
//! `psi_reopen_only_when_budget_and_not_event` unit test in src/supervisor.rs.
//! A faithful end-to-end case is not practical in this harness: it would require
//! a real kernel PSI trigger fd to materialize mid-run (after draug has already
//! started), which cannot be simulated with temp files. The decision predicate
//! (`should_attempt_psi_reopen`) and the wiring (`maybe_reopen_psi` called on
//! every tick while the budget remains) are verified by the unit test plus code
//! review.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// Single-sourced integration webhook mock (its reader + a `Connection: close`
// reply). Lives in tests/support so the lifecycle suite reuses it instead of
// keeping a third drifting copy of the HTTP reader. Integration tests cannot
// see src's `#[cfg(test)]` helpers (they compile against the crate as an
// external user), so this is the correct module-boundary idiom.
#[path = "support/webhook_mock.rs"]
mod webhook_mock;
use webhook_mock::WebhookMock;

const DRAUG: &str = env!("CARGO_BIN_EXE_draug");
const FAKE: &str = env!("CARGO_BIN_EXE_fake_target");

fn line_count(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// Poll `cond` until true or `timeout` elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

struct Draug(Child);
impl Draug {
    /// PID of the supervised `draug` process, used to deliver SIGTERM.
    fn pid(&self) -> i32 {
        self.0.id() as i32
    }
    /// Mutable access to the wrapped child so tests can wait on its exit.
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for Draug {
    fn drop(&mut self) {
        // On the happy path draug has already exited; killing a reaped pid is a
        // harmless no-op (ESRCH). On a panic before the explicit wait this is
        // what cleans up draug and, transitively, its target child.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// RAII guard for a temp directory: removes it on drop so cleanup happens even
/// when an assertion panics (a bare trailing `remove_dir_all` would be skipped).
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("draug-test-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_file(&p);
    p
}

// 1) DESTRUCTIVE: target ignores SIGTERM => SIGKILL escalation + critical alert.
#[test]
fn hang_escalates_to_sigkill_and_alerts() {
    let mock = WebhookMock::start();
    let mark = tmp("hang-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--restart-interval",
            "1s",
            "--grace-period",
            "1s",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
            "--startup-grace",
            "500ms",
        ])
        .arg("--")
        .args([FAKE, "--ignore-term", "--mark", mark.to_str().unwrap()]);
    let _g = Draug(draug.spawn().unwrap());
    // first launch + at least one forced respawn within the window
    assert!(
        wait_until(Duration::from_secs(15), || line_count(&mark) >= 2),
        "expected respawn after SIGKILL"
    );
    assert!(
        wait_until(Duration::from_secs(5), || mock
            .count_field_eq("severity", "critical".into())
            >= 1),
        "expected critical hang alert"
    );
}

// 2) DESTRUCTIVE: fast-exit => backoff then crash-loop exit (nonzero) + critical.
#[test]
fn fast_exit_triggers_crash_loop_exit() {
    let mock = WebhookMock::start();
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--max-failures",
            "2",
            "--backoff",
            "100ms",
            "--startup-grace",
            "2s",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([FAKE, "--exit-fast", "3"]);
    let mut child = draug.spawn().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "draug should exit nonzero on crash-loop");
    assert!(
        wait_until(Duration::from_secs(3), || mock
            .count_field_eq("severity", "critical".into())
            >= 1),
        "expected crash-loop alert"
    );
    // The crash-loop give-up performs NO restart, so its snapshot reports the
    // lifetime restarts COMPLETED before giving up (NOT a +1 in-progress count).
    // With --max-failures 2 the sequence is: initial spawn crashes (failures=1,
    // backoff), one respawn SUCCEEDS (restart_total=1), that child crashes
    // (failures=2 >= max) => crash-loop exit. So exactly ONE restart completed:
    // restart_count == 1, which is also the value quoted in the adjacent
    // "1 lifetime restart(s)" log line (snapshot and log can never disagree).
    // Parsed-JSON equality so this matches restart_count exactly 1 — never 10,
    // 11, 100 the way a `"restart_count":1` substring match would.
    assert!(
        wait_until(Duration::from_secs(3), || mock
            .count_field_eq("restart_count", 1.into())
            >= 1),
        "crash-loop alert must report the lifetime restarts completed (1 here)"
    );
    // Guard for #14: with parsed-JSON equality, a multi-digit restart_count
    // whose decimal text shares the `1` prefix (10, 11, 100, ...) must NOT be
    // counted as `restart_count == 1`. The old substring form
    // `count_containing("\"restart_count\":1")` false-matched all of these; this
    // assertion would fail under that brittle match, proving the fix is precise.
    assert_eq!(
        mock.count_where(|json| { json["restart_count"].as_u64().is_some_and(|n| n >= 10) }),
        0,
        "no alert should report a multi-digit restart_count in this scenario"
    );
}

// 3) Stale heartbeat => restart by staleness.
#[test]
fn stale_heartbeat_triggers_restart() {
    let hb = tmp("hb");
    let mark = tmp("hb-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .args([
            "--heartbeat-file",
            hb.to_str().unwrap(),
            "--heartbeat-max-age",
            "1s",
            "--startup-grace",
            "500ms",
            "--tick",
            "200ms",
            "--restart-interval",
            "0",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([
            FAKE,
            "--heartbeat",
            hb.to_str().unwrap(),
            "--stop-heartbeat-after",
            "1",
            "--mark",
            mark.to_str().unwrap(),
        ]);
    let _g = Draug(draug.spawn().unwrap());
    assert!(
        wait_until(Duration::from_secs(15), || line_count(&mark) >= 2),
        "expected restart after heartbeat went stale"
    );
}

// 4) Memory threshold (tempdir cgroup) => restart + warning alert whose
//    snapshot was taken while the target was still alive.
#[test]
fn memory_threshold_triggers_restart() {
    let mock = WebhookMock::start();
    // RAII guard: the temp cgroup dir is removed on drop, so it is cleaned up
    // even if an assertion below panics (no leaked /tmp/draug-cg-<pid>).
    let cg = TempDir(std::env::temp_dir().join(format!("draug-cg-{}", std::process::id())));
    let dir = &cg.0;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("cgroup.controllers"), "memory\n").unwrap();
    std::fs::write(dir.join("memory.max"), "1000\n").unwrap();
    std::fs::write(dir.join("memory.current"), "100\n").unwrap();
    let mark = tmp("mem-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--cgroup-root",
            dir.to_str().unwrap(),
            "--mem-threshold",
            "0.85",
            "--tick",
            "200ms",
            "--startup-grace",
            "300ms",
            "--restart-interval",
            "0",
            "--psi-trigger",
            "",
            "--grace-period",
            "1s",
        ])
        .arg("--")
        .args([FAKE, "--mark", mark.to_str().unwrap()]);
    let _g = Draug(draug.spawn().unwrap());
    // Let it start, then push usage over threshold (900/1000 = 0.90 >= 0.85).
    std::thread::sleep(Duration::from_millis(600));
    std::fs::write(dir.join("memory.current"), "900\n").unwrap();
    // Rising edge: the over-threshold usage forces at least one restart.
    assert!(
        wait_until(Duration::from_secs(10), || line_count(&mark) >= 2),
        "expected restart over memory threshold"
    );
    // A Memory restart fires a Warning alert. Its snapshot must have been
    // captured while the target was alive: `threads` is read from
    // /proc/<pid>/status, so a post-mortem capture (against a reaped pid)
    // would render `"threads":null`. The fake cgroup files are static, so the
    // memory numbers do not discriminate alive-vs-dead — `threads` does.
    assert!(
        wait_until(Duration::from_secs(5), || mock
            .count_field_eq("severity", "warning".into())
            >= 1),
        "expected a warning memory alert"
    );
    assert_eq!(
        mock.count_field_eq("threads", serde_json::Value::Null),
        0,
        "snapshot must be taken while target is alive (non-null threads)"
    );
    // The first anomaly restart from a fresh process counts the in-progress
    // restart: restart_count == 1 (NOT 0). This is the lifetime restart total
    // including the restart this Memory Warning is about to perform. Parsed-JSON
    // equality so it matches exactly 1, never a multi-digit value with a 1 prefix.
    assert!(
        wait_until(Duration::from_secs(5), || mock
            .count_field_eq("restart_count", 1.into())
            >= 1),
        "first memory restart must report restart_count:1"
    );
    // Recovery: drop usage back under threshold (100/1000 = 0.10 < 0.85). Once
    // memory recovers, `decision::evaluate` returns None, so draug must STOP
    // restarting. This distinguishes "one restart then stops" from a restart
    // storm that would keep firing regardless of the recovered usage.
    std::fs::write(dir.join("memory.current"), "100\n").unwrap();
    // Let any restart already in flight at the moment of recovery drain. The
    // worst case is a tick that read the stale (over-threshold) value just
    // before the recovery write: its drain (up to grace-period 1s) plus the
    // fresh child's startup-grace (300ms) and a tick (200ms) must all elapse
    // before draug could re-sample the recovered value. Settle comfortably past
    // that sum (~1.5s) so the post-recovery baseline is stable on loaded CI.
    std::thread::sleep(Duration::from_millis(2000));
    let settled = line_count(&mark);
    // Several more ticks must NOT produce further restarts now that memory is
    // back under threshold — the count is frozen at the post-recovery baseline.
    assert!(
        !wait_until(Duration::from_secs(2), || line_count(&mark) > settled),
        "restarts must stop once memory recovers (storm guard); \
         count grew past {settled}"
    );
}

// 5) HAPPY: periodic restart, target honors SIGTERM, no critical alert.
#[test]
fn periodic_restart_happy_path() {
    let mock = WebhookMock::start();
    let mark = tmp("happy-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--restart-interval",
            "1s",
            "--grace-period",
            "3s",
            "--startup-grace",
            "200ms",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([FAKE, "--mark", mark.to_str().unwrap()]);
    let _g = Draug(draug.spawn().unwrap());
    assert!(
        wait_until(Duration::from_secs(12), || line_count(&mark) >= 3),
        "expected multiple periodic respawns"
    );
    assert_eq!(
        mock.count_field_eq("severity", "critical".into()),
        0,
        "periodic restarts must not alert critical"
    );
}

// 7) OBSERVABILITY: the structured `event=spawned` line carries the child's
// pid, and the `--log-level` threshold actually gates emission end-to-end --
// `info` shows `spawned`, `warn` suppresses it while still emitting `restart`.
// Without a pid an operator cannot attribute later restart/crash lines to a
// specific child (or tell apart N same-argv replicas); without working gating
// the `level=` field would be inert decoration.
#[test]
fn spawned_line_carries_pid_and_log_level_gates_it() {
    // Run draug at `level`, capturing its stderr to a FILE (not a pipe: the
    // target grandchild inherits draug's stderr, so a pipe would never reach
    // EOF after draug dies and the reader would deadlock -- a regular file does
    // not block). Drive at least one periodic restart, then SIGTERM draug for a
    // graceful exit that also stops the target, and return the captured stderr.
    fn run_capture(level: &str, mark: &Path, errfile: &Path) -> String {
        let f = std::fs::File::create(errfile).unwrap();
        let mut child = Command::new(DRAUG)
            .args([
                "--restart-interval",
                "1s",
                "--grace-period",
                "3s",
                "--startup-grace",
                "200ms",
                "--mem-threshold",
                "0",
                "--psi-trigger",
                "",
                "--log-level",
                level,
            ])
            .arg("--")
            .args([FAKE, "--mark", mark.to_str().unwrap()])
            .stderr(Stdio::from(f))
            .spawn()
            .unwrap();
        // >=2 marks => an initial spawn and a respawn, so both a `spawned` and a
        // `restart` line have been emitted before we stop draug.
        assert!(
            wait_until(Duration::from_secs(8), || line_count(mark) >= 2),
            "expected a respawn so spawned/restart lines exist"
        );
        unsafe { libc_kill(child.id() as i32, 15) }; // graceful: also stops target
        wait_with_timeout(&mut child, Duration::from_secs(6));
        std::fs::read_to_string(errfile).unwrap_or_default()
    }

    let info = run_capture("info", &tmp("obs-info-mark"), &tmp("obs-info-err"));
    assert!(
        info.contains("event=spawned"),
        "info must log spawned: {info}"
    );
    assert!(info.contains("pid="), "spawned must carry a pid: {info}");
    assert!(
        info.contains("level=info"),
        "lines carry a level field: {info}"
    );

    let warn = run_capture("warn", &tmp("obs-warn-mark"), &tmp("obs-warn-err"));
    assert!(
        !warn.contains("event=spawned"),
        "warn must suppress the info-level spawned line: {warn}"
    );
    assert!(
        warn.contains("event=restart"),
        "warn must still emit the restart line: {warn}"
    );
}

// 6) SHUTDOWN: SIGTERM to draug => drain target + exit 0, no respawn.
#[test]
fn shutdown_drains_and_exits() {
    let mark = tmp("shutdown-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .args([
            "--restart-interval",
            "0",
            "--grace-period",
            "3s",
            "--startup-grace",
            "200ms",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([FAKE, "--mark", mark.to_str().unwrap()]);
    let mut g = Draug(draug.spawn().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    // send SIGTERM to the draug process
    unsafe {
        libc_kill(g.pid(), 15);
    }
    let status =
        wait_with_timeout(g.child_mut(), Duration::from_secs(6)).expect("draug should exit");
    assert!(status.success(), "clean shutdown exits 0");
    assert_eq!(line_count(&mark), 1, "no respawn on shutdown");
}

// 7) RACE: double SIGTERM to draug with an ignoring target => immediate SIGKILL.
#[test]
fn double_sigterm_forces_immediate_kill() {
    let mut draug = Command::new(DRAUG);
    draug
        .args([
            "--restart-interval",
            "0",
            "--grace-period",
            "30s",
            "--startup-grace",
            "200ms",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([FAKE, "--ignore-term"]);
    let mut g = Draug(draug.spawn().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    unsafe {
        libc_kill(g.pid(), 15);
        std::thread::sleep(Duration::from_millis(200));
        libc_kill(g.pid(), 15);
    }
    // The double-term escalation must SIGKILL the hung target and let draug
    // exit cleanly WITHOUT waiting for the 30s grace period. We measure the
    // wall-clock time draug takes to exit: a working escalation returns in
    // well under the grace period, whereas a broken one would hang to ~30s and
    // be force-killed by `wait_with_timeout` at the 6s bound (yielding a
    // None exit code, i.e. NOT success).
    let started = Instant::now();
    let status = wait_with_timeout(g.child_mut(), Duration::from_secs(6))
        .expect("draug should exit promptly");
    let elapsed = started.elapsed();
    // A real, clean escalation: draug SIGKILLed the target and exited 0. No
    // escape hatch — a hung supervisor force-killed at the wait bound fails.
    assert!(
        status.success(),
        "double SIGTERM must escalate to a clean exit (status: {status:?})"
    );
    // Prove the escalation did NOT wait out the 30s grace: it must return well
    // below the grace period (and comfortably inside the 6s wait bound).
    assert!(
        elapsed < Duration::from_secs(5),
        "escalation must be prompt (well under grace=30s), took {elapsed:?}"
    );
}

// 7b) SHUTDOWN DURING ANOMALY DRAIN: a stale heartbeat starts an anomaly drain
//     (shutdown=false). An operator SIGTERM during that drain must escalate to a
//     clean shutdown — NOT a faster kill followed by a respawn. The target
//     ignores SIGTERM so it stays in the Draining phase under a long grace until
//     the operator signal forces the SIGKILL escalation.
#[test]
fn sigterm_during_anomaly_drain_shuts_down_no_respawn() {
    let mock = WebhookMock::start();
    let hb = tmp("anomaly-drain-hb");
    let mark = tmp("anomaly-drain-mark");
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--heartbeat-file",
            hb.to_str().unwrap(),
            "--heartbeat-max-age",
            "1s",
            "--startup-grace",
            "500ms",
            "--tick",
            "200ms",
            // Long grace so the anomaly drain cannot self-escalate before the
            // operator SIGTERM arrives: a respawn (the bug) would otherwise be
            // masked by the drain timer killing the target.
            "--grace-period",
            "30s",
            "--restart-interval",
            "0",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([
            FAKE,
            // Ignore SIGTERM so the target hangs in Draining until escalation.
            "--ignore-term",
            "--heartbeat",
            hb.to_str().unwrap(),
            // Heartbeat goes stale ~1s in => HeartbeatStale anomaly drain.
            "--stop-heartbeat-after",
            "1",
            "--mark",
            mark.to_str().unwrap(),
        ]);
    // Wrap draug in the RAII guard so an early assertion panic still kills draug
    // (and, transitively, its --ignore-term target, which only dies via SIGKILL
    // from its parent) instead of leaking both across the rest of the run.
    let mut g = Draug(draug.spawn().unwrap());
    // Wait until the anomaly drain is in flight: the target spawned once (one
    // mark line) and the heartbeat has gone stale long enough to trigger it.
    assert!(
        wait_until(Duration::from_secs(6), || line_count(&mark) >= 1),
        "target should have spawned"
    );
    std::thread::sleep(Duration::from_millis(2500)); // hb stale => drain in flight
    // Operator stop arrives mid anomaly-drain. With the fix this sets shutdown
    // and escalates to SIGKILL; on_drain_complete then exits 0 with no respawn.
    unsafe {
        libc_kill(g.pid(), 15);
    }
    let started = Instant::now();
    // A broken supervisor respawns and keeps running: wait_with_timeout then
    // force-kills it at the bound (None => NOT success). A correct one exits 0
    // promptly, well under the 30s grace.
    let status = wait_with_timeout(g.child_mut(), Duration::from_secs(8))
        .expect("draug should exit promptly");
    let elapsed = started.elapsed();
    assert!(
        status.success(),
        "SIGTERM during an anomaly drain must exit cleanly, not respawn (status: {status:?})"
    );
    assert!(
        elapsed < Duration::from_secs(7),
        "escalation+shutdown must be prompt (well under grace=30s), took {elapsed:?}"
    );
    // Exactly one spawn => no respawn happened.
    assert_eq!(
        line_count(&mark),
        1,
        "no respawn after operator shutdown during anomaly drain"
    );
    // The escalated kill on an anomaly drain (HeartbeatStale + escalated) emits a
    // Critical alert. Because this is a SHUTDOWN escalation, NO restart follows,
    // so the snapshot must report the lifetime restarts COMPLETED (0 here — the
    // target never respawned), NOT restart_total + 1. This directly guards
    // Change 1: pre-fix `escalate_to_kill` always added +1, so the payload
    // reported restart_count:1 for a restart that never happened.
    assert!(
        wait_until(Duration::from_secs(3), || mock
            .count_field_eq("severity", "critical".into())
            >= 1),
        "expected a critical escalation alert"
    );
    assert!(
        mock.count_field_eq("restart_count", 0.into()) >= 1,
        "shutdown escalation must report restart_count:0 (no respawn follows)"
    );
    assert_eq!(
        mock.count_field_eq("restart_count", 1.into()),
        0,
        "shutdown escalation must NOT over-count an in-progress restart"
    );
}

// 8) DETERMINISTIC: shutdown of a TERM-ignoring target escalates to SIGKILL
//    exactly once => exactly one critical alert, and draug still exits 0.
#[test]
fn shutdown_of_unkillable_target_escalates_once() {
    let mock = WebhookMock::start();
    let mut draug = Command::new(DRAUG);
    draug
        .env("DRAUG_WEBHOOK_URL", &mock.url)
        .args([
            "--restart-interval",
            "0",
            "--grace-period",
            "500ms",
            "--startup-grace",
            "200ms",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
        ])
        .arg("--")
        .args([FAKE, "--ignore-term"]);
    let mut g = Draug(draug.spawn().unwrap());
    std::thread::sleep(Duration::from_millis(600)); // past startup-grace; target running
    unsafe {
        libc_kill(g.pid(), 15); // single shutdown signal
    }
    let status = wait_with_timeout(g.child_mut(), Duration::from_secs(6))
        .expect("draug should exit after escalating");
    assert!(
        status.success(),
        "clean shutdown exits 0 even after escalation"
    );
    // exactly one escalation => exactly one critical alert (no double-send)
    assert!(
        wait_until(Duration::from_secs(2), || mock
            .count_field_eq("severity", "critical".into())
            >= 1),
        "expected a critical escalation alert"
    );
    assert_eq!(
        mock.count_field_eq("severity", "critical".into()),
        1,
        "one escalation must produce exactly one critical alert"
    );
    // The Critical hang alert re-captures its snapshot just before SIGKILL,
    // while the (hung) target is still alive, so `threads` must be non-null.
    assert_eq!(
        mock.count_field_eq("threads", serde_json::Value::Null),
        0,
        "pre-SIGKILL snapshot must be taken while target is alive (non-null threads)"
    );
}

// --- small helpers (kill + bounded wait) ---

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
unsafe fn libc_kill(pid: i32, sig: i32) {
    // SAFETY: `kill(2)` is async-signal-safe; the caller passes a valid pid.
    let _ = unsafe { kill(pid, sig) };
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(Some(s)) = child.try_wait() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.try_wait().ok().flatten()
}
