//! The supervisor state machine — a PURE core with no I/O.
//!
//! `step(state, ctx, event, samples) -> (state, actions)` owns every lifecycle
//! transition and all restart accounting, so the entire policy (precedence,
//! grace, drain -> escalate -> kill, crash-loop give-up) is table-tested on the
//! host. The I/O shell (`supervisor::linux`) turns epoll/syscalls into `Event`s
//! and executes the returned `Action`s via existing leaf functions.

use crate::decision::{self, Decision, HeartbeatInput, Inputs, RestartReason};
use std::time::Duration;

/// Wait window after SIGKILL before we give up on a child that will not die.
/// SIGKILL almost always reaps within milliseconds; 2s is generous headroom.
pub const KILL_CONFIRM: Duration = Duration::from_secs(2);

/// Which graceful signal to send (mirrors `config::GracefulSignal` without a
/// dependency cycle through the I/O config).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GracefulKind {
    Term,
    Int,
}

/// State of the supervised child. The timer ROLE is part of the state, so there
/// is no overloaded shared timer disambiguated by reading a phase elsewhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Target alive, normal monitoring.
    Running,
    /// Graceful signal sent; awaiting exit before the grace deadline.
    Draining {
        reason: RestartReason,
        shutdown: bool,
    },
    /// SIGKILL sent; awaiting confirmed death before the kill-confirm deadline.
    /// Being in this state makes escalation idempotent (#5/#9); the bounded
    /// deadline guarantees forward progress and removes the Draining hang (#4).
    Killing {
        reason: RestartReason,
        shutdown: bool,
    },
    /// Crash-loop backoff; awaiting the respawn deadline.
    Backoff,
    /// Spawn commanded; awaiting the `SpawnResult`. `shutdown_pending` records an
    /// operator stop that arrived during the respawn window: when the spawn
    /// confirms, drain the new child for shutdown instead of returning to
    /// `Running` (and exit cleanly if the spawn failed), so a SIGTERM is never
    /// lost here (#2).
    Respawning { shutdown_pending: bool },
}

/// Something that happened in the outside world, produced by the shell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// The shell reaped and CONFIRMED the child exited (status discarded).
    ChildExited,
    /// Periodic tick.
    Tick,
    /// The action (deferred) timer fired; the state interprets its meaning.
    TimerExpired,
    /// Operator SIGTERM/SIGINT (shutdown, no respawn).
    OperatorStop,
    /// PSI memory-pressure edge (event mode).
    PsiEdge,
    /// Result of a commanded `Action::Spawn`.
    SpawnResult(SpawnOutcome),
}

/// Outcome of a commanded `Action::Spawn`, fed back as `Event::SpawnResult`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpawnOutcome {
    Ok,
    Err,
}

/// Resource samples captured by the shell for this step (built from `sample`).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Samples {
    pub elapsed: Duration,
    pub mem_ratio: Option<f64>,
    pub psi_triggered: bool,
    pub heartbeat: HeartbeatInput,
}

impl Samples {
    /// Placeholder samples for `step` calls in states that do not consult them
    /// (every state except `Running`). Cheap and `const`; it must never reach
    /// `decision::evaluate`, which only runs from the `Running` arm.
    pub(crate) const fn placeholder() -> Samples {
        Samples {
            elapsed: Duration::ZERO,
            mem_ratio: None,
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        }
    }

    fn to_inputs(self, psi_override: bool) -> Inputs {
        Inputs {
            elapsed: self.elapsed,
            mem_ratio: self.mem_ratio,
            psi_triggered: self.psi_triggered || psi_override,
            heartbeat: self.heartbeat,
        }
    }
}

/// A side effect the shell must perform. The FSM decides WHAT/WHEN/ORDER; the
/// shell calls the existing leaf functions to carry it out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Spawn,
    SignalGraceful,
    SignalKill,
    ArmActionTimer(Duration),
    DisarmActionTimer,
    /// Snapshot /proc + cgroup while the child is alive and stash it.
    CaptureSnapshot {
        reason: RestartReason,
        restart_count: u64,
    },
    /// Send the stashed pre-mortem alert (on_drain_complete effect): classify
    /// (reason, escalated) -> send stash if Some, else log_restart.
    SendDrainAlert {
        reason: RestartReason,
        escalated: bool,
    },
    LogCrash {
        healthy: bool,
        lived: Duration,
    },
    /// Crash-loop give-up: send Critical + log (crash_loop_exit effect).
    CrashLoopGiveUp {
        failures: u32,
        restart_count: u64,
    },
    /// The target survived SIGKILL within the kill-confirm window. Send the
    /// stashed pre-SIGKILL snapshot (captured while the hung child was still
    /// alive) as a Critical alert and log the un-killable diagnostic
    /// (unkillable_exit effect), then `Exit` non-zero. Modeled as an
    /// FSM-ordered action — like `CrashLoopGiveUp` — so the diagnostic provably
    /// precedes the exit instead of living only in a comment.
    Unkillable {
        reason: RestartReason,
    },
    Exit(i32),
}

/// Mutable accounting + immutable config the core needs. No I/O handles.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub limits: decision::DecisionLimits,
    pub failures: u32,
    pub restart_total: u64,
    pub grace_period: Duration,
    pub backoff: Duration,
    pub startup_grace: Duration,
    pub max_failures: u32,
    pub graceful: GracefulKind,
}

/// `restart_total + 1` when a restart will follow, else the raw lifetime total.
fn restart_count(restart_total: u64, will_restart: bool) -> u64 {
    if will_restart {
        restart_total.saturating_add(1)
    } else {
        restart_total
    }
}

/// Backoff delay: `base × streak`, saturating; a 0 streak gets a 1ms respawn.
fn backoff_delay(backoff: Duration, failures: u32) -> Duration {
    if failures == 0 {
        Duration::from_millis(1)
    } else {
        backoff.saturating_mul(failures)
    }
}

/// Begin a drain: capture pre-mortem snapshot, signal graceful, arm grace timer.
fn begin_drain(reason: RestartReason, shutdown: bool, ctx: &Ctx) -> (State, Vec<Action>) {
    let count = restart_count(ctx.restart_total, !shutdown);
    (
        State::Draining { reason, shutdown },
        vec![
            Action::CaptureSnapshot {
                reason,
                restart_count: count,
            },
            Action::SignalGraceful,
            Action::ArmActionTimer(ctx.grace_period),
        ],
    )
}

/// Escalate a stuck drain to SIGKILL: snapshot, kill, arm the kill-confirm timer.
fn escalate(reason: RestartReason, shutdown: bool, ctx: &Ctx) -> (State, Vec<Action>) {
    let count = restart_count(ctx.restart_total, !shutdown);
    (
        State::Killing { reason, shutdown },
        vec![
            Action::CaptureSnapshot {
                reason,
                restart_count: count,
            },
            Action::SignalKill,
            Action::ArmActionTimer(KILL_CONFIRM),
        ],
    )
}

/// Crash accounting + transition into backoff (shared by SIGCHLD/tick paths).
fn handle_crash(ctx: &mut Ctx, lived: Duration) -> (State, Vec<Action>) {
    let healthy = lived >= ctx.startup_grace;
    if healthy {
        ctx.failures = 0;
    } else {
        ctx.failures = ctx.failures.saturating_add(1);
    }
    let mut acts = vec![Action::LogCrash { healthy, lived }];
    if ctx.failures >= ctx.max_failures {
        acts.push(Action::CrashLoopGiveUp {
            failures: ctx.failures,
            restart_count: ctx.restart_total,
        });
        acts.push(Action::Exit(1));
        return (State::Backoff, acts);
    }
    acts.push(Action::ArmActionTimer(backoff_delay(
        ctx.backoff,
        ctx.failures,
    )));
    (State::Backoff, acts)
}

pub fn step(state: State, ctx: &mut Ctx, event: Event, samples: &Samples) -> (State, Vec<Action>) {
    match state {
        State::Running => match event {
            Event::ChildExited => handle_crash(ctx, samples.elapsed),
            Event::OperatorStop => begin_drain(RestartReason::Periodic, true, ctx),
            Event::Tick | Event::PsiEdge => {
                if matches!(event, Event::Tick) && samples.elapsed >= ctx.startup_grace {
                    ctx.failures = 0;
                }
                let psi_override = matches!(event, Event::PsiEdge);
                let inputs = samples.to_inputs(psi_override);
                match decision::evaluate(&inputs, &ctx.limits) {
                    Decision::Restart(reason) => begin_drain(reason, false, ctx),
                    Decision::None => (State::Running, Vec::new()),
                }
            }
            Event::TimerExpired | Event::SpawnResult(_) => (State::Running, Vec::new()),
        },
        State::Draining { reason, shutdown } => match event {
            Event::ChildExited => {
                let mut acts = vec![Action::SendDrainAlert {
                    reason,
                    escalated: false,
                }];
                if shutdown {
                    acts.push(Action::Exit(0));
                    // The Exit(0) terminates the supervisor, so the returned
                    // state is never observed again; we keep Draining rather
                    // than invent a terminal variant.
                    (State::Draining { reason, shutdown }, acts)
                } else {
                    ctx.failures = 0;
                    acts.push(Action::DisarmActionTimer);
                    acts.push(Action::Spawn);
                    (
                        State::Respawning {
                            shutdown_pending: false,
                        },
                        acts,
                    )
                }
            }
            Event::TimerExpired => escalate(reason, shutdown, ctx),
            Event::OperatorStop => escalate(reason, true, ctx),
            _ => (State::Draining { reason, shutdown }, Vec::new()),
        },
        State::Killing { reason, shutdown } => match event {
            Event::ChildExited => {
                let mut acts = vec![Action::SendDrainAlert {
                    reason,
                    escalated: true,
                }];
                if shutdown {
                    acts.push(Action::Exit(0));
                    (State::Killing { reason, shutdown }, acts)
                } else {
                    ctx.failures = 0;
                    acts.push(Action::DisarmActionTimer);
                    acts.push(Action::Spawn);
                    (
                        State::Respawning {
                            shutdown_pending: false,
                        },
                        acts,
                    )
                }
            }
            Event::OperatorStop => {
                // Record the operator's shutdown intent WITHOUT a second SIGKILL
                // or re-snapshot — escalation stays idempotent (#5/#9). Flipping
                // `shutdown` to true makes the pending ChildExited exit cleanly
                // (Exit(0)) instead of respawning the target (#1). When `shutdown`
                // was already true this is a pure no-op.
                (
                    State::Killing {
                        reason,
                        shutdown: true,
                    },
                    Vec::new(),
                )
            }
            Event::TimerExpired => (
                State::Killing { reason, shutdown },
                // Surviving SIGKILL is the un-killable case: surface the
                // pre-SIGKILL snapshot as a Critical alert + log BEFORE the
                // non-zero exit, so the headline safety feature is never silent.
                vec![Action::Unkillable { reason }, Action::Exit(1)],
            ),
            _ => (State::Killing { reason, shutdown }, Vec::new()),
        },
        State::Backoff => match event {
            Event::TimerExpired => (
                State::Respawning {
                    shutdown_pending: false,
                },
                vec![Action::Spawn],
            ),
            Event::OperatorStop => (State::Backoff, vec![Action::Exit(0)]),
            _ => (State::Backoff, Vec::new()),
        },
        State::Respawning { shutdown_pending } => match event {
            Event::SpawnResult(SpawnOutcome::Ok) => {
                // Single source of truth for the lifetime restart count (#9).
                ctx.restart_total = ctx.restart_total.saturating_add(1);
                if shutdown_pending {
                    // An operator stop arrived mid-respawn: the new child is up,
                    // so honor the stop by draining it for shutdown rather than
                    // dropping the SIGTERM and returning to Running (#2). Reuses
                    // the same shutdown-drain path as Running + OperatorStop.
                    begin_drain(RestartReason::Periodic, true, ctx)
                } else {
                    (State::Running, Vec::new())
                }
            }
            Event::SpawnResult(SpawnOutcome::Err) => {
                if shutdown_pending {
                    // The respawn failed and the operator asked to stop: there is
                    // no child to drain, so exit cleanly instead of backing off
                    // (#2). Not a crash-loop give-up — this is a requested stop.
                    (State::Backoff, vec![Action::Exit(0)])
                } else {
                    ctx.failures = ctx.failures.saturating_add(1);
                    if ctx.failures >= ctx.max_failures {
                        (
                            State::Backoff,
                            vec![
                                Action::CrashLoopGiveUp {
                                    failures: ctx.failures,
                                    restart_count: ctx.restart_total,
                                },
                                Action::Exit(1),
                            ],
                        )
                    } else {
                        (
                            State::Backoff,
                            vec![Action::ArmActionTimer(backoff_delay(
                                ctx.backoff,
                                ctx.failures,
                            ))],
                        )
                    }
                }
            }
            Event::OperatorStop => {
                // Defer: the SpawnResult is already queued, so record the stop and
                // let the SpawnResult arm act on it (drain the new child, or exit
                // if the spawn failed). This closes the lost-SIGTERM window (#2).
                (
                    State::Respawning {
                        shutdown_pending: true,
                    },
                    Vec::new(),
                )
            }
            _ => (State::Respawning { shutdown_pending }, Vec::new()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_construct() {
        let ctx = Ctx {
            limits: limits_for_test(),
            failures: 0,
            restart_total: 0,
            grace_period: std::time::Duration::from_secs(90),
            backoff: std::time::Duration::from_secs(5),
            startup_grace: std::time::Duration::from_secs(15),
            max_failures: 3,
            graceful: GracefulKind::Term,
        };
        let _ = (State::Running, Event::Tick, ctx);
    }

    fn limits_for_test() -> decision::DecisionLimits {
        decision::DecisionLimits {
            restart_interval: Some(std::time::Duration::from_secs(1800)),
            mem_threshold: Some(0.85),
            heartbeat_max_age: std::time::Duration::from_secs(60),
            startup_grace: std::time::Duration::from_secs(15),
        }
    }

    fn ctx() -> Ctx {
        Ctx {
            limits: limits_for_test(),
            failures: 0,
            restart_total: 0,
            grace_period: Duration::from_secs(90),
            backoff: Duration::from_secs(5),
            startup_grace: Duration::from_secs(15),
            max_failures: 3,
            graceful: GracefulKind::Term,
        }
    }

    fn samples(elapsed_s: u64) -> Samples {
        Samples {
            elapsed: Duration::from_secs(elapsed_s),
            mem_ratio: Some(0.1),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        }
    }

    #[test]
    fn running_memory_trigger_begins_drain() {
        let mut c = ctx();
        let s = Samples {
            mem_ratio: Some(0.99),
            ..samples(100)
        };
        let (st, acts) = step(State::Running, &mut c, Event::Tick, &s);
        assert_eq!(
            st,
            State::Draining {
                reason: RestartReason::Memory,
                shutdown: false
            }
        );
        assert!(acts.contains(&Action::SignalGraceful));
        assert!(acts.contains(&Action::ArmActionTimer(c.grace_period)));
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                reason: RestartReason::Memory,
                restart_count: 1
            }
        )));
    }

    #[test]
    fn running_psi_edge_begins_drain() {
        let mut c = ctx();
        c.failures = 2;
        let (st, _) = step(State::Running, &mut c, Event::PsiEdge, &samples(100));
        assert_eq!(
            st,
            State::Draining {
                reason: RestartReason::Psi,
                shutdown: false
            }
        );
        // PsiEdge must NOT reset the failure streak (only Tick proves health).
        assert_eq!(c.failures, 2);
    }

    #[test]
    fn running_tick_no_trigger_stays_running_and_resets_failures() {
        let mut c = ctx();
        c.failures = 2;
        let (st, acts) = step(State::Running, &mut c, Event::Tick, &samples(100));
        assert_eq!(st, State::Running);
        assert!(acts.is_empty());
        assert_eq!(c.failures, 0); // elapsed (100) >= startup_grace (15)
    }

    #[test]
    fn running_tick_within_grace_does_not_reset_failures() {
        let mut c = ctx();
        c.failures = 2;
        let (_, _) = step(State::Running, &mut c, Event::Tick, &samples(5));
        assert_eq!(c.failures, 2);
    }

    #[test]
    fn running_crash_within_grace_increments_and_backs_off() {
        let mut c = ctx();
        let (st, acts) = step(State::Running, &mut c, Event::ChildExited, &samples(5));
        assert_eq!(c.failures, 1);
        assert_eq!(st, State::Backoff);
        assert!(
            acts.iter()
                .any(|a| matches!(a, Action::LogCrash { healthy: false, .. }))
        );
        assert!(acts.iter().any(|a| matches!(a, Action::ArmActionTimer(_))));
    }

    #[test]
    fn running_crash_after_grace_resets_streak() {
        let mut c = ctx();
        c.failures = 2;
        let (st, _) = step(State::Running, &mut c, Event::ChildExited, &samples(100));
        assert_eq!(c.failures, 0);
        assert_eq!(st, State::Backoff);
    }

    #[test]
    fn running_crash_trips_give_up_at_max_failures() {
        let mut c = ctx();
        c.failures = 2; // next crash within grace -> 3 == max
        let (st, acts) = step(State::Running, &mut c, Event::ChildExited, &samples(5));
        assert_eq!(c.failures, 3);
        assert!(acts.contains(&Action::Exit(1)));
        assert!(
            acts.iter()
                .any(|a| matches!(a, Action::CrashLoopGiveUp { failures: 3, .. }))
        );
        assert_eq!(st, State::Backoff); // state irrelevant once Exit is emitted
    }

    #[test]
    fn running_operator_stop_begins_shutdown_drain() {
        let mut c = ctx();
        let (st, acts) = step(State::Running, &mut c, Event::OperatorStop, &samples(100));
        assert_eq!(
            st,
            State::Draining {
                reason: RestartReason::Periodic,
                shutdown: true
            }
        );
        assert!(acts.contains(&Action::SignalGraceful));
        // A shutdown drain will NOT respawn, so the snapshot reports the raw
        // lifetime total (no +1). This pins the single-source accounting (#9).
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                restart_count: 0,
                ..
            }
        )));
    }

    #[test]
    fn running_timer_expired_is_noop() {
        let mut c = ctx();
        let (st, acts) = step(State::Running, &mut c, Event::TimerExpired, &samples(100));
        assert_eq!(st, State::Running);
        assert!(acts.is_empty());
    }

    #[test]
    fn running_spawn_result_is_noop() {
        let mut c = ctx();
        let (st, acts) = step(
            State::Running,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Ok),
            &samples(100),
        );
        assert_eq!(st, State::Running);
        assert!(acts.is_empty());
    }

    #[test]
    fn draining_clean_exit_respawns() {
        let mut c = ctx();
        c.failures = 2;
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::ChildExited, &samples(100));
        assert_eq!(
            st,
            State::Respawning {
                shutdown_pending: false
            }
        );
        // A clean drain proves health: the failure streak resets.
        assert_eq!(c.failures, 0);
        assert!(acts.contains(&Action::DisarmActionTimer));
        assert!(acts.contains(&Action::Spawn));
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::SendDrainAlert {
                reason: RestartReason::Memory,
                escalated: false
            }
        )));
    }

    #[test]
    fn draining_clean_exit_shutdown_exits_zero() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Periodic,
            shutdown: true,
        };
        let (_, acts) = step(st0, &mut c, Event::ChildExited, &samples(100));
        assert!(acts.contains(&Action::Exit(0)));
        assert!(!acts.contains(&Action::Spawn));
        // The alert still fires on shutdown; the grace timer is not disarmed
        // (the process is exiting, so the timer is irrelevant).
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::SendDrainAlert {
                escalated: false,
                ..
            }
        )));
        assert!(!acts.contains(&Action::DisarmActionTimer));
    }

    #[test]
    fn draining_grace_deadline_escalates_to_killing() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::TimerExpired, &samples(100));
        assert_eq!(
            st,
            State::Killing {
                reason: RestartReason::Memory,
                shutdown: false
            }
        );
        assert!(acts.contains(&Action::SignalKill));
        assert!(acts.contains(&Action::ArmActionTimer(KILL_CONFIRM)));
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                restart_count: 1,
                ..
            }
        ))); // restart_total+1
    }

    #[test]
    fn draining_operator_stop_escalates_as_shutdown() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::OperatorStop, &samples(100));
        assert_eq!(
            st,
            State::Killing {
                reason: RestartReason::Memory,
                shutdown: true
            }
        );
        assert!(acts.contains(&Action::SignalKill));
        // shutdown escalation must NOT count a restart: restart_count == restart_total (0)
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                restart_count: 0,
                ..
            }
        )));
    }

    #[test]
    fn draining_tick_is_noop() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::Tick, &samples(100));
        assert_eq!(st, st0);
        assert!(acts.is_empty());
    }

    #[test]
    fn draining_psi_edge_is_noop() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::PsiEdge, &samples(100));
        assert_eq!(st, st0);
        assert!(acts.is_empty());
    }

    #[test]
    fn killing_confirmed_death_respawns() {
        let mut c = ctx();
        c.failures = 2;
        let st0 = State::Killing {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::ChildExited, &samples(100));
        assert_eq!(
            st,
            State::Respawning {
                shutdown_pending: false
            }
        );
        // A confirmed death that respawns proves health: streak resets, and the
        // kill-confirm timer is disarmed before the new child arms its own.
        assert_eq!(c.failures, 0);
        assert!(acts.contains(&Action::DisarmActionTimer));
        assert!(acts.contains(&Action::Spawn));
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::SendDrainAlert {
                reason: RestartReason::Memory,
                escalated: true
            }
        )));
    }

    #[test]
    fn killing_confirmed_death_shutdown_exits_zero() {
        let mut c = ctx();
        let st0 = State::Killing {
            reason: RestartReason::Psi,
            shutdown: true,
        };
        let (_, acts) = step(st0, &mut c, Event::ChildExited, &samples(100));
        assert!(acts.contains(&Action::Exit(0)));
        assert!(!acts.contains(&Action::Spawn));
    }

    #[test]
    fn killing_deadline_survived_sigkill_alerts_then_exits_nonzero() {
        let mut c = ctx();
        let st0 = State::Killing {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (_, acts) = step(st0, &mut c, Event::TimerExpired, &samples(100));
        // Surviving SIGKILL surfaces the pre-SIGKILL snapshot as a Critical
        // un-killable alert FIRST, then exits non-zero. Pinning the exact vec
        // also pins the order: the alert must precede the Exit or the shell
        // would return the code before sending it (cf. crash_loop_giveup). No
        // second signal, no re-snapshot — the stash captured at escalation is
        // what the shell consumes.
        assert_eq!(
            acts,
            vec![
                Action::Unkillable {
                    reason: RestartReason::Memory
                },
                Action::Exit(1),
            ]
        );
    }

    #[test]
    fn killing_operator_stop_records_shutdown_without_rekill() {
        // #1/#3: an operator stop during the kill-confirm window must NOT issue a
        // second SIGKILL or re-snapshot (escalation stays idempotent, #5/#9), but
        // it MUST record the shutdown intent so the pending ChildExited exits
        // cleanly instead of respawning the target.
        let mut c = ctx();
        let st0 = State::Killing {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::OperatorStop, &samples(100));
        assert_eq!(
            st,
            State::Killing {
                reason: RestartReason::Memory,
                shutdown: true,
            }
        );
        assert!(acts.is_empty()); // no second kill, no re-snapshot (#5/#9)
        // A second operator stop is now a pure no-op (already shutting down).
        let (st2, acts2) = step(st, &mut c, Event::OperatorStop, &samples(100));
        assert_eq!(st2, st);
        assert!(acts2.is_empty());
        // The confirmed death now exits cleanly rather than respawning (#1).
        let (_, acts3) = step(st, &mut c, Event::ChildExited, &samples(100));
        assert!(acts3.contains(&Action::Exit(0)));
        assert!(!acts3.contains(&Action::Spawn));
    }

    #[test]
    fn killing_tick_is_noop() {
        let mut c = ctx();
        let st0 = State::Killing {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (st, acts) = step(st0, &mut c, Event::Tick, &samples(100));
        assert_eq!(st, st0);
        assert!(acts.is_empty());
    }

    #[test]
    fn backoff_deadline_spawns() {
        let mut c = ctx();
        let (st, acts) = step(State::Backoff, &mut c, Event::TimerExpired, &samples(0));
        assert_eq!(
            st,
            State::Respawning {
                shutdown_pending: false
            }
        );
        assert!(acts.contains(&Action::Spawn));
    }

    #[test]
    fn backoff_operator_stop_exits_zero() {
        let mut c = ctx();
        let (_, acts) = step(State::Backoff, &mut c, Event::OperatorStop, &samples(0));
        assert!(acts.contains(&Action::Exit(0)));
    }

    #[test]
    fn respawn_success_returns_to_running_and_counts() {
        let mut c = ctx();
        c.restart_total = 4;
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st, acts) = step(
            st0,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Ok),
            &samples(0),
        );
        assert_eq!(st, State::Running);
        assert_eq!(c.restart_total, 5);
        assert!(acts.is_empty());
    }

    #[test]
    fn respawn_failure_backs_off_and_keeps_streak() {
        let mut c = ctx();
        c.failures = 1;
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st, acts) = step(
            st0,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Err),
            &samples(0),
        );
        assert_eq!(c.failures, 2);
        assert_eq!(st, State::Backoff);
        assert!(acts.iter().any(|a| matches!(a, Action::ArmActionTimer(_))));
    }

    #[test]
    fn respawn_failure_trips_give_up() {
        let mut c = ctx();
        c.failures = 2; // -> 3 == max
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (_, acts) = step(
            st0,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Err),
            &samples(0),
        );
        assert_eq!(c.failures, 3);
        assert!(acts.contains(&Action::Exit(1)));
        // Pin the give-up payload: streak == max, raw lifetime total (no +1).
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::CrashLoopGiveUp {
                failures: 3,
                restart_count: 0
            }
        )));
    }

    #[test]
    fn backoff_child_exited_is_noop() {
        let mut c = ctx();
        let (st, acts) = step(State::Backoff, &mut c, Event::ChildExited, &samples(0));
        assert_eq!(st, State::Backoff);
        assert!(acts.is_empty());
    }

    #[test]
    fn respawn_success_does_not_touch_failures() {
        let mut c = ctx();
        c.failures = 0;
        c.restart_total = 1;
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st, _) = step(
            st0,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Ok),
            &samples(0),
        );
        assert_eq!(st, State::Running);
        assert_eq!(c.failures, 0);
        assert_eq!(c.restart_total, 2);
    }

    #[test]
    fn respawn_tick_is_noop() {
        let mut c = ctx();
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st, acts) = step(st0, &mut c, Event::Tick, &samples(0));
        assert_eq!(st, st0);
        assert!(acts.is_empty());
    }

    // #1: a crash coincident with a PSI edge must be accounted as a crash, never a
    // graceful Psi restart. The shell's reap-first rule delivers ChildExited before
    // PsiEdge; this asserts the core does the right thing with that ordering.
    #[test]
    fn regression_crash_before_psi_is_a_crash_not_a_drain() {
        let mut c = ctx();
        let (st1, a1) = step(State::Running, &mut c, Event::ChildExited, &samples(5));
        assert_eq!(c.failures, 1); // crash counted
        assert_eq!(st1, State::Backoff);
        assert!(a1.iter().any(|a| matches!(a, Action::LogCrash { .. })));
        // A PsiEdge arriving in the same batch now lands in Backoff -> no drain.
        let (st2, a2) = step(st1, &mut c, Event::PsiEdge, &samples(5));
        assert_eq!(st2, State::Backoff);
        assert!(!a2.contains(&Action::SignalGraceful));
    }

    // #4: the old code could hang in Draining forever on an inconclusive reap. The
    // FSM guarantees forward progress: Killing always resolves via ChildExited or a
    // bounded TimerExpired -> Exit. No event leaves the machine without a next step.
    #[test]
    fn regression_no_hang_killing_always_progresses() {
        let mut c = ctx();
        let st = State::Killing {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (_, acts) = step(st, &mut c, Event::TimerExpired, &samples(100));
        assert!(acts.contains(&Action::Exit(1))); // never an infinite wait
    }

    // #5/#9: a second OperatorStop while Killing must NOT re-snapshot or re-kill,
    // and the restart count is computed once.
    #[test]
    fn regression_escalation_is_idempotent() {
        let mut c = ctx();
        let (st1, _) = step(
            State::Draining {
                reason: RestartReason::Memory,
                shutdown: false,
            },
            &mut c,
            Event::OperatorStop,
            &samples(100),
        );
        assert_eq!(
            st1,
            State::Killing {
                reason: RestartReason::Memory,
                shutdown: true,
            }
        );
        let (st2, a2) = step(st1, &mut c, Event::OperatorStop, &samples(100));
        assert_eq!(st2, st1);
        assert!(a2.is_empty());
    }

    // #9: anomaly drain reports restart_total+1; shutdown drain reports restart_total.
    #[test]
    fn regression_restart_count_single_source() {
        let mut c = ctx();
        c.restart_total = 7;
        let (_, a_anom) = step(State::Running, &mut c, Event::PsiEdge, &samples(100));
        assert!(a_anom.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                restart_count: 8,
                ..
            }
        )));
        let mut c2 = ctx();
        c2.restart_total = 7;
        let (_, a_shut) = step(State::Running, &mut c2, Event::OperatorStop, &samples(100));
        assert!(a_shut.iter().any(|a| matches!(
            a,
            Action::CaptureSnapshot {
                restart_count: 7,
                ..
            }
        )));
    }

    // Precedence characterization: a Running Tick routes the winning reason from
    // decision::evaluate into the drain. HeartbeatStale > Psi > Memory > Periodic;
    // Crash is the separate ChildExited path. These pin the routing so a future
    // refactor cannot silently reorder precedence.
    fn drain_reason_for(s: &Samples) -> Option<RestartReason> {
        let mut c = ctx();
        match step(State::Running, &mut c, Event::Tick, s) {
            (State::Draining { reason, .. }, _) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn precedence_heartbeat_beats_all() {
        let s = Samples {
            elapsed: Duration::from_secs(2000),
            mem_ratio: Some(0.99),
            psi_triggered: true,
            heartbeat: HeartbeatInput::Age(Duration::from_secs(120)),
        };
        assert_eq!(drain_reason_for(&s), Some(RestartReason::HeartbeatStale));
    }

    #[test]
    fn precedence_psi_beats_memory_and_periodic() {
        let s = Samples {
            elapsed: Duration::from_secs(2000),
            mem_ratio: Some(0.99),
            psi_triggered: true,
            heartbeat: HeartbeatInput::Disabled,
        };
        assert_eq!(drain_reason_for(&s), Some(RestartReason::Psi));
    }

    #[test]
    fn precedence_memory_beats_periodic() {
        let s = Samples {
            elapsed: Duration::from_secs(2000),
            mem_ratio: Some(0.90),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        };
        assert_eq!(drain_reason_for(&s), Some(RestartReason::Memory));
    }

    #[test]
    fn precedence_periodic_alone() {
        let s = Samples {
            elapsed: Duration::from_secs(1800),
            mem_ratio: Some(0.10),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        };
        assert_eq!(drain_reason_for(&s), Some(RestartReason::Periodic));
    }

    #[test]
    fn precedence_no_trigger_is_none() {
        let s = Samples {
            elapsed: Duration::from_secs(100), // past grace, below periodic interval
            mem_ratio: Some(0.10),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Disabled,
        };
        assert_eq!(drain_reason_for(&s), None);
    }

    #[test]
    fn precedence_crash_is_separate_path() {
        // A crash arrives as ChildExited, never routed through evaluate; it must
        // back off, not drain — even when resource triggers would also fire.
        let mut c = ctx();
        let s = Samples {
            elapsed: Duration::from_secs(2000),
            mem_ratio: Some(0.99),
            psi_triggered: true,
            heartbeat: HeartbeatInput::Age(Duration::from_secs(120)),
        };
        let (st, acts) = step(State::Running, &mut c, Event::ChildExited, &s);
        assert_eq!(st, State::Backoff);
        assert!(acts.iter().any(|a| matches!(a, Action::LogCrash { .. })));
        assert!(!acts.contains(&Action::SignalGraceful));
    }

    #[test]
    fn precedence_heartbeat_missing_is_stale() {
        // The `Missing` heartbeat branch is distinct from `Age(..)`; both must
        // route to HeartbeatStale past grace. Pins the Missing path.
        let s = Samples {
            elapsed: Duration::from_secs(100),
            mem_ratio: Some(0.10),
            psi_triggered: false,
            heartbeat: HeartbeatInput::Missing,
        };
        assert_eq!(drain_reason_for(&s), Some(RestartReason::HeartbeatStale));
    }

    #[test]
    fn precedence_periodic_fires_within_startup_grace() {
        // Periodic is intentionally NOT gated by startup grace (unlike memory,
        // psi, and heartbeat). A periodic deadline reached during the initial
        // window still drains — even though the other triggers are suppressed.
        // This pins that deliberate asymmetry.
        let mut c = ctx();
        c.limits.restart_interval = Some(Duration::from_secs(5));
        let s = Samples {
            elapsed: Duration::from_secs(5),    // within startup_grace (15s)
            mem_ratio: Some(0.99),              // would-be Memory, grace-suppressed
            psi_triggered: true,                // would-be Psi, grace-suppressed
            heartbeat: HeartbeatInput::Missing, // would-be HeartbeatStale, suppressed
        };
        let (st, _) = step(State::Running, &mut c, Event::Tick, &s);
        assert_eq!(
            st,
            State::Draining {
                reason: RestartReason::Periodic,
                shutdown: false
            }
        );
    }

    // #2: a SIGTERM that arrives while awaiting the SpawnResult must not be lost.
    // It is recorded as shutdown_pending; once the spawn confirms, the freshly
    // respawned child is drained for shutdown instead of returning to Running.
    #[test]
    fn respawning_operator_stop_defers_then_drains_new_child_on_success() {
        let mut c = ctx();
        c.restart_total = 3;
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st1, acts1) = step(st0, &mut c, Event::OperatorStop, &samples(0));
        assert_eq!(
            st1,
            State::Respawning {
                shutdown_pending: true
            }
        );
        assert!(acts1.is_empty()); // deferred; nothing to do until the SpawnResult
        let (st2, acts2) = step(
            st1,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Ok),
            &samples(0),
        );
        // The respawn still counts (single source, #9) and then drains for stop.
        assert_eq!(c.restart_total, 4);
        assert_eq!(
            st2,
            State::Draining {
                reason: RestartReason::Periodic,
                shutdown: true
            }
        );
        assert!(acts2.contains(&Action::SignalGraceful));
        assert!(acts2.contains(&Action::ArmActionTimer(c.grace_period)));
    }

    // #2: an operator stop arriving in Respawning is recorded even when it shows
    // up before the SpawnResult in the queue; a later non-stop event must NOT
    // clear the flag (the `_` arm preserves it).
    #[test]
    fn respawning_operator_stop_flag_survives_unrelated_events() {
        let mut c = ctx();
        let st0 = State::Respawning {
            shutdown_pending: false,
        };
        let (st1, _) = step(st0, &mut c, Event::OperatorStop, &samples(0));
        let (st2, acts2) = step(st1, &mut c, Event::Tick, &samples(0));
        assert_eq!(
            st2,
            State::Respawning {
                shutdown_pending: true
            }
        );
        assert!(acts2.is_empty());
    }

    // #2: if the deferred-stop respawn FAILS, there is no child to drain — exit
    // cleanly rather than backing off, and do not count it as a crash-loop.
    #[test]
    fn respawning_operator_stop_exits_cleanly_when_spawn_fails() {
        let mut c = ctx();
        let st0 = State::Respawning {
            shutdown_pending: true,
        };
        let (_, acts) = step(
            st0,
            &mut c,
            Event::SpawnResult(SpawnOutcome::Err),
            &samples(0),
        );
        assert!(acts.contains(&Action::Exit(0)));
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, Action::CrashLoopGiveUp { .. }))
        );
        assert_eq!(c.failures, 0); // a requested stop is not a failed start
    }

    // #10: action ORDER is load-bearing — the snapshot must be captured while the
    // child is still alive, BEFORE any signal; the deadline timer is armed last.
    // Membership tests (.contains/.any) cannot catch a reorder, so pin positions.
    #[test]
    fn begin_drain_orders_snapshot_before_signal_before_timer() {
        let mut c = ctx();
        let s = Samples {
            mem_ratio: Some(0.99),
            ..samples(100)
        };
        let (_, acts) = step(State::Running, &mut c, Event::Tick, &s);
        let snap = acts
            .iter()
            .position(|a| matches!(a, Action::CaptureSnapshot { .. }))
            .expect("snapshot present");
        let sig = acts
            .iter()
            .position(|a| matches!(a, Action::SignalGraceful))
            .expect("graceful signal present");
        let timer = acts
            .iter()
            .position(|a| matches!(a, Action::ArmActionTimer(_)))
            .expect("timer present");
        assert!(snap < sig, "snapshot must precede the graceful signal");
        assert!(sig < timer, "signal must precede arming the grace timer");
    }

    // #10: escalation must snapshot the still-alive hung child BEFORE the SIGKILL.
    #[test]
    fn escalate_orders_snapshot_before_kill() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (_, acts) = step(st0, &mut c, Event::TimerExpired, &samples(100));
        let snap = acts
            .iter()
            .position(|a| matches!(a, Action::CaptureSnapshot { .. }))
            .expect("snapshot present");
        let kill = acts
            .iter()
            .position(|a| matches!(a, Action::SignalKill))
            .expect("kill present");
        assert!(snap < kill, "snapshot must precede the SIGKILL");
    }

    // #10: a clean drain must send the alert, then disarm the grace timer, then
    // respawn — disarming before the new child arms its own deadline.
    #[test]
    fn draining_clean_exit_orders_alert_disarm_spawn() {
        let mut c = ctx();
        let st0 = State::Draining {
            reason: RestartReason::Memory,
            shutdown: false,
        };
        let (_, acts) = step(st0, &mut c, Event::ChildExited, &samples(100));
        let alert = acts
            .iter()
            .position(|a| matches!(a, Action::SendDrainAlert { .. }))
            .expect("alert present");
        let disarm = acts
            .iter()
            .position(|a| matches!(a, Action::DisarmActionTimer))
            .expect("disarm present");
        let spawn = acts
            .iter()
            .position(|a| matches!(a, Action::Spawn))
            .expect("spawn present");
        assert!(alert < disarm, "alert must precede disarming the timer");
        assert!(disarm < spawn, "disarm must precede the respawn");
    }

    // #10: the crash-loop give-up alert must fire BEFORE the Exit, or the shell
    // returns the exit code and the final Critical is never sent.
    #[test]
    fn crash_loop_giveup_orders_before_exit() {
        let mut c = ctx();
        c.failures = 2; // next crash within grace -> 3 == max
        let (_, acts) = step(State::Running, &mut c, Event::ChildExited, &samples(5));
        let giveup = acts
            .iter()
            .position(|a| matches!(a, Action::CrashLoopGiveUp { .. }))
            .expect("giveup present");
        let exit = acts
            .iter()
            .position(|a| matches!(a, Action::Exit(_)))
            .expect("exit present");
        assert!(giveup < exit, "give-up alert must fire before the exit");
    }
}
