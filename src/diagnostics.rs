//! Diagnostics snapshot for alerts.
//!
//! Collects the evidence a developer needs when something goes wrong: the CPU
//! quota ratio (from cgroup), memory current/max/ratio, thread count, open
//! file descriptors, heartbeat age, and the restart counter. Captured while
//! the target is still alive — at the start of a drain and re-captured just
//! before a SIGKILL escalation — so the alert carries the state at the moment
//! of failure. The crash-loop
//! exit is the one unavoidable exception: the target is already gone, so
//! thread/fd counts are necessarily absent there.

use crate::decision::RestartReason;

/// Evidence captured at a failure/restart for an alert.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub reason: RestartReason,
    /// Total number of target restarts over the process lifetime, COUNTING the
    /// restart this event triggers (excludes the initial spawn). For a
    /// restart-performing alert (Memory/PSI Warning, escalated Critical) this is
    /// the in-progress restart: the first anomaly restart reports 1, the second
    /// 2, and so on. For the crash-loop give-up Critical — which performs NO
    /// restart — it is the number of restarts COMPLETED before giving up (e.g. 0
    /// when the target crash-looped from startup). Distinct from the transient
    /// consecutive-crash streak (`failures`) that drives backoff/max-failures.
    pub restart_count: u64,
    pub mem_current: Option<u64>,
    pub mem_max: Option<u64>,
    pub mem_ratio: Option<f64>,
    /// Configured cgroup CPU QUOTA ratio (`quota / period`, the ceiling), NOT
    /// live utilization; `None` when the cgroup is uncapped/unreadable.
    pub cpu_quota_ratio: Option<f64>,
    pub threads: Option<u64>,
    pub open_fds: Option<u64>,
    pub heartbeat_age_secs: Option<f64>,
}

/// Thread count from `/proc/<pid>/status` (Linux only; `None` elsewhere).
pub fn proc_threads(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Open file-descriptor count from `/proc/<pid>/fd` (Linux only).
/// May read one higher than the steady-state count because the `read_dir`
/// call itself holds a descriptor open during enumeration. This is a
/// diagnostics-only figure, so the small skew is acceptable.
pub fn proc_open_fds(pid: u32) -> Option<u64> {
    let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    Some(dir.filter_map(|e| e.ok()).count() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::RestartReason;

    #[test]
    fn proc_helpers_do_not_panic() {
        let pid = std::process::id();
        // On Linux these return Some; elsewhere None. Either way: no panic.
        let _ = proc_threads(pid);
        let _ = proc_open_fds(pid);
    }

    #[test]
    fn snapshot_carries_reason_and_count() {
        let snap = Snapshot {
            reason: RestartReason::Memory,
            restart_count: 4,
            mem_current: Some(900),
            mem_max: Some(1000),
            mem_ratio: Some(0.9),
            cpu_quota_ratio: None,
            threads: None,
            open_fds: None,
            heartbeat_age_secs: None,
        };
        assert_eq!(snap.reason, RestartReason::Memory);
        assert_eq!(snap.restart_count, 4);
        assert_eq!(snap.mem_ratio, Some(0.9));
        assert_eq!(snap.mem_max, Some(1000));
        assert_eq!(snap.cpu_quota_ratio, None);
    }
}
