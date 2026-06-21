//! Trigger evaluation — a PURE function with no I/O, so the whole policy is
//! table-testable.
//!
//! Given the latest resource samples, the supervisor state, and the config, it
//! returns a `Decision` (`None` or `Restart(reason)`). Precedence when several
//! fire at once: HeartbeatStale > Psi > Memory (threshold) >
//! Periodic. Startup grace suppresses the memory and heartbeat triggers in the
//! initial window.
//!
//! Crash handling and drain suppression are NOT part of this pure core: the
//! supervisor confirms a self-exited child via its reap-first check (it never
//! routes a crash through `evaluate`), and it only feeds `evaluate` while the
//! FSM state is `Running`, so a draining child never reaches this function.

use std::time::Duration;

/// Why the supervisor is restarting -- or, for `Shutdown`, gracefully stopping
/// -- the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartReason {
    Periodic,
    Memory,
    Psi,
    HeartbeatStale,
    Crash,
    /// Operator/orchestrator-initiated graceful stop (SIGTERM/SIGINT): the child
    /// is drained and the supervisor exits without respawning. Not an anomaly.
    Shutdown,
}

/// Outcome of evaluating the triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    None,
    Restart(RestartReason),
}

/// Heartbeat status as seen by the decision core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatInput {
    /// Heartbeat checking is off (no `--heartbeat-file`).
    Disabled,
    /// Enabled, but the file is genuinely absent (true `NotFound`): the target
    /// has not created its heartbeat yet. Treated as stale past startup grace.
    Missing,
    /// Enabled, but the file's metadata could not be read (permission/ownership
    /// mismatch or other IO error). We cannot tell the age, so this is treated
    /// as "no signal" — exactly like a fresh heartbeat — and never triggers a
    /// restart. This prevents a silent permanent restart loop of a healthy
    /// target caused by a misconfiguration draug cannot see through.
    Unreadable,
    /// Enabled and present, with this age.
    Age(Duration),
}

/// The config slice the decision core needs.
#[derive(Debug, Clone, Copy)]
pub struct DecisionLimits {
    pub restart_interval: Option<Duration>,
    pub mem_threshold: Option<f64>,
    pub heartbeat_max_age: Duration,
    pub startup_grace: Duration,
}

/// Inputs sampled by the supervisor for one evaluation.
#[derive(Debug, Clone, Copy)]
pub struct Inputs {
    /// Monotonic time since the current child was spawned.
    pub elapsed: Duration,
    /// Memory usage ratio (current/limit), or `None` when the cgroup is
    /// unlimited. A `NaN` ratio (degenerate cgroup division) is treated as
    /// "below threshold": `NaN >= threshold` is `false`, so it never triggers
    /// a Memory restart — a missed trigger is safer than a false restart.
    pub mem_ratio: Option<f64>,
    pub psi_triggered: bool,
    pub heartbeat: HeartbeatInput,
}

/// Pure trigger evaluation. Precedence:
/// HeartbeatStale > Psi > Memory(threshold) > Periodic. Startup grace suppresses
/// the memory and heartbeat triggers. Crash and drain suppression are handled
/// by the supervisor, not this pure core (see the module doc).
///
/// Heartbeat handling past grace: `Missing` (true not-found) and an `Age`
/// exceeding `heartbeat_max_age` are stale and restart. `Disabled` and
/// `Unreadable` produce no signal: `Unreadable` means draug could not read the
/// heartbeat (permission/IO error) and must not restart a target it cannot
/// actually assess.
pub fn evaluate(i: &Inputs, l: &DecisionLimits) -> Decision {
    let past_grace = i.elapsed >= l.startup_grace;
    if past_grace {
        match i.heartbeat {
            HeartbeatInput::Missing => return Decision::Restart(RestartReason::HeartbeatStale),
            HeartbeatInput::Age(age) if age > l.heartbeat_max_age => {
                return Decision::Restart(RestartReason::HeartbeatStale);
            }
            // Disabled, Unreadable, or a fresh `Age`: no heartbeat-driven
            // restart. Unreadable explicitly behaves like "no signal".
            _ => {}
        }
        if i.psi_triggered {
            return Decision::Restart(RestartReason::Psi);
        }
        if let (Some(ratio), Some(threshold)) = (i.mem_ratio, l.mem_threshold)
            && ratio >= threshold
        {
            return Decision::Restart(RestartReason::Memory);
        }
    }
    if let Some(interval) = l.restart_interval
        && i.elapsed >= interval
    {
        return Decision::Restart(RestartReason::Periodic);
    }
    Decision::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limits() -> DecisionLimits {
        DecisionLimits {
            restart_interval: Some(Duration::from_secs(1800)),
            mem_threshold: Some(0.85),
            heartbeat_max_age: Duration::from_secs(60),
            startup_grace: Duration::from_secs(15),
        }
    }

    fn base() -> Inputs {
        Inputs {
            elapsed: Duration::from_secs(100),
            mem_ratio: Some(0.10),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        }
    }

    #[test]
    fn heartbeat_stale_beats_memory_and_periodic() {
        let i = Inputs {
            elapsed: Duration::from_secs(2000),
            mem_ratio: Some(0.99),
            heartbeat: HeartbeatInput::Age(Duration::from_secs(120)),
            ..base()
        };
        assert_eq!(
            evaluate(&i, &limits()),
            Decision::Restart(RestartReason::HeartbeatStale)
        );
    }

    #[test]
    fn psi_beats_threshold() {
        let i = Inputs {
            psi_triggered: true,
            mem_ratio: Some(0.99),
            ..base()
        };
        assert_eq!(
            evaluate(&i, &limits()),
            Decision::Restart(RestartReason::Psi)
        );
    }

    #[test]
    fn psi_within_grace_is_suppressed() {
        // PSI sits in the memory tier, which startup grace suppresses. A PSI
        // trigger fired during the initial window must NOT restart the target.
        let i = Inputs {
            elapsed: Duration::from_secs(5), // within startup grace (15s)
            psi_triggered: true,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn memory_threshold_boundaries() {
        let l = limits();
        assert_eq!(
            evaluate(
                &Inputs {
                    mem_ratio: Some(0.849),
                    ..base()
                },
                &l
            ),
            Decision::None
        );
        assert_eq!(
            evaluate(
                &Inputs {
                    mem_ratio: Some(0.850),
                    ..base()
                },
                &l
            ),
            Decision::Restart(RestartReason::Memory)
        );
        assert_eq!(
            evaluate(
                &Inputs {
                    mem_ratio: Some(0.851),
                    ..base()
                },
                &l
            ),
            Decision::Restart(RestartReason::Memory)
        );
    }

    #[test]
    fn no_memory_when_unlimited() {
        let i = Inputs {
            mem_ratio: None,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn periodic_fires_at_deadline() {
        let i = Inputs {
            elapsed: Duration::from_secs(1800),
            ..base()
        };
        assert_eq!(
            evaluate(&i, &limits()),
            Decision::Restart(RestartReason::Periodic)
        );
    }

    #[test]
    fn startup_grace_suppresses_memory_and_heartbeat() {
        let i = Inputs {
            elapsed: Duration::from_secs(5),
            mem_ratio: Some(0.99),
            heartbeat: HeartbeatInput::Missing,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn heartbeat_missing_within_grace_is_not_stale() {
        let i = Inputs {
            elapsed: Duration::from_secs(5),
            heartbeat: HeartbeatInput::Missing,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn memory_beats_periodic() {
        // Both periodic deadline AND memory threshold are satisfied at once,
        // past startup grace; Memory must win (higher precedence than Periodic).
        let i = Inputs {
            elapsed: Duration::from_secs(2000), // >= restart_interval (1800)
            mem_ratio: Some(0.90),              // >= mem_threshold (0.85)
            ..base()
        };
        assert_eq!(
            evaluate(&i, &limits()),
            Decision::Restart(RestartReason::Memory)
        );
    }

    #[test]
    fn unreadable_heartbeat_never_stale_past_grace() {
        // The heartbeat file exists but draug cannot read its metadata. Well
        // past startup grace, memory under threshold, and before the periodic
        // deadline => no restart. An unreadable heartbeat is "no signal" and
        // must NOT be conflated with a missing/stale one (Finding 6).
        let i = Inputs {
            elapsed: Duration::from_secs(100), // past grace (15s), below interval (1800s)
            heartbeat: HeartbeatInput::Unreadable,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn disabled_heartbeat_never_stale_past_grace() {
        // Heartbeat disabled, well past startup grace, memory under threshold,
        // and not yet at the periodic deadline => no restart. Proves a Disabled
        // heartbeat can never produce HeartbeatStale.
        let i = Inputs {
            elapsed: Duration::from_secs(100), // past grace (15s), below interval (1800s)
            heartbeat: HeartbeatInput::Disabled,
            ..base()
        };
        assert_eq!(evaluate(&i, &limits()), Decision::None);
    }

    #[test]
    fn disabled_triggers_yield_none() {
        let l = DecisionLimits {
            restart_interval: None,
            mem_threshold: None,
            heartbeat_max_age: Duration::from_secs(60),
            startup_grace: Duration::from_secs(15),
        };
        let i = Inputs {
            elapsed: Duration::from_secs(99999),
            mem_ratio: Some(0.99),
            ..base()
        };
        assert_eq!(evaluate(&i, &l), Decision::None);
    }
}
