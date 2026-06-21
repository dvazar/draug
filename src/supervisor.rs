//! The supervisor's I/O shell: owns the single synchronous `epoll` loop and the
//! child/fd handles, and drives the pure state machine in `crate::fsm`. This is
//! the only module that knows about epoll.
//!
//! Watches four fds:
//!   * signalfd — SIGTERM/SIGINT (shutdown, no respawn) and SIGCHLD (reap),
//!   * tick timerfd — sample `memory.current`, heartbeat age, periodic deadline,
//!   * action timerfd — the deferred deadline (grace / kill-confirm / respawn),
//!   * psi fd — EPOLLPRI when memory pressure crosses the threshold.
//!
//! Each wakeup it reaps first (so a crash is never mislabeled), turns epoll
//! readiness into `fsm::Event`s, runs `fsm::step` to get the next state plus the
//! `fsm::Action`s to perform, and executes those actions via the leaf functions
//! here (spawn, signal, snapshot, alert, log). The lifecycle policy — graceful
//! drain -> grace deadline -> SIGKILL -> respawn, crash-loop backoff, and alert
//! classification — lives in `fsm` and `decision`.

use crate::alert::AlertSink;
use crate::config::Config;

#[cfg(not(target_os = "linux"))]
pub fn run(_config: Config, _sink: &dyn AlertSink) -> i32 {
    eprintln!("draug: the supervisor event loop requires Linux");
    1
}

/// Block the signals the supervisor reads via signalfd (SIGTERM, SIGINT,
/// SIGCHLD) on the CURRENT thread. Must be called on the main thread at the very
/// start of `lib::run`, BEFORE any sink worker thread is spawned: a spawned
/// thread inherits the creating thread's signal mask, so blocking here closes
/// the startup race where the kernel could route a process-directed signal to an
/// alert worker that has not yet blocked it itself (see `linux::run`).
/// No-op on non-Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) fn block_supervised_signals() {}

#[cfg(target_os = "linux")]
pub(crate) use linux::block_supervised_signals;

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::child::{self, Child};
    use crate::decision::{HeartbeatInput, Inputs, RestartReason};
    use crate::diagnostics::Snapshot;
    use crate::fsm;
    use crate::heartbeat::{HeartbeatAge, heartbeat_age};
    use crate::log::{LogLevel, Logger};
    use crate::psi::{self, PsiHandle};
    use crate::{alert, cgroup};
    use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
    use nix::sys::signal::{SigSet, Signal};
    use nix::sys::signalfd::{SfdFlags, SignalFd};
    use nix::sys::time::TimeSpec;
    use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
    use std::collections::VecDeque;
    use std::os::fd::AsFd;
    use std::path::Path;
    use std::process::ExitStatus;
    use std::time::{Duration, Instant, SystemTime};

    // epoll tokens
    const TOK_SIGNAL: u64 = 1;
    const TOK_TICK: u64 = 2;
    const TOK_ACTION: u64 = 3;
    const TOK_PSI: u64 = 4;

    /// Bounded retries to upgrade PSI to event mode after a startup race (#3).
    /// At ~1–2s per tick this covers tens of seconds of slow orchestrator setup,
    /// then gives up so a genuinely PSI-less host adds no per-tick reopen cost.
    const PSI_REOPEN_ATTEMPTS: u32 = 30;

    /// The canonical set of signals the supervisor reads via signalfd:
    /// SIGTERM/SIGINT (shutdown, no respawn) and SIGCHLD (reap). This is the
    /// single source of truth for the mask, used BOTH to pre-block on the main
    /// thread (`block_supervised_signals`, called before any worker is spawned)
    /// and to construct the `SignalFd` in `run`, so the two can never drift.
    fn supervised_sigset() -> SigSet {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGCHLD);
        mask
    }

    /// Block the supervised signal set on the current thread. See the
    /// module-level `block_supervised_signals` doc for why this must run on the
    /// main thread before any sink worker is spawned.
    pub(crate) fn block_supervised_signals() {
        supervised_sigset().thread_block().expect("block signals");
    }

    fn timespec(d: Duration) -> TimeSpec {
        // never arm a zero/expired timer; clamp to 1ms
        let d = if d.is_zero() {
            Duration::from_millis(1)
        } else {
            d
        };
        // Cap the high end so `as_secs()` can never overflow a `time_t` (i64 on
        // Linux). nix's `TimeSpec::from_duration` does an unchecked
        // `tv_sec = duration.as_secs() as time_t`; a duration whose `as_secs()`
        // exceeds `i64::MAX` (reachable when a saturating `backoff * failures`
        // approaches `Duration::MAX`) would wrap to a NEGATIVE `tv_sec`, which
        // `timerfd_settime` rejects with EINVAL → `arm_oneshot` panics and
        // aborts the supervisor. `i64::MAX` seconds is a valid, positive,
        // effectively-infinite `tv_sec` (tv_nsec stays 0). This is the single
        // conversion point for every timer arming, so it protects the tick
        // timer too — no caller can ever produce a negative tv_sec.
        const MAX_TIMER_SECS: u64 = i64::MAX as u64;
        let d = if d.as_secs() > MAX_TIMER_SECS {
            Duration::new(MAX_TIMER_SECS, 0)
        } else {
            d
        };
        TimeSpec::from_duration(d)
    }

    fn arm_oneshot(timer: &TimerFd, d: Duration) {
        timer
            .set(Expiration::OneShot(timespec(d)), TimerSetTimeFlags::empty())
            .expect("arm oneshot timer");
    }

    fn disarm(timer: &TimerFd) {
        timer
            .set(
                Expiration::OneShot(TimeSpec::new(0, 0)),
                TimerSetTimeFlags::empty(),
            )
            .ok();
    }

    /// Read the cgroup memory limit at startup with a small bounded retry.
    ///
    /// `retry_on_none` decides how `Ok(None)` is treated, which differs by
    /// whether the operator configured `--mem-threshold`:
    ///
    /// * `false` (no threshold): the limit is display-only. A genuine read
    ///   failure (`Err`) is retried, but a `None` (legitimately unlimited, or
    ///   the cgroup v2 `memory.max` default of `"max"`) is accepted at once and
    ///   never retried — we must not add startup latency for a value nobody
    ///   acts on.
    /// * `true` (threshold configured): the operator expects a real limit. At
    ///   container startup cgroup v2 `memory.max` defaults to the literal `"max"`
    ///   (=> `Ok(None)`) until the orchestrator writes the real limit, so a read
    ///   in that window looks unlimited even though it is not. We therefore treat
    ///   `Ok(None)` like a transient miss and retry it with the SAME attempts and
    ///   backoff as the `Err` path, so a short startup race does not permanently
    ///   disable the memory trigger.
    ///
    /// `Ok(Some(_))` (a finite limit) is always returned immediately. A short
    /// fixed sleep separates attempts; no sleep follows the last one. The final
    /// outcome of the last attempt (which may be `Ok(None)` when `retry_on_none`
    /// is set and the limit never appeared) is returned to the caller, which logs
    /// the appropriate warning.
    fn read_mem_max_with_retry(
        cg: &cgroup::CgroupPaths,
        attempts: u32,
        retry_on_none: bool,
    ) -> std::io::Result<Option<u64>> {
        let attempts = attempts.max(1);
        let mut last: std::io::Result<Option<u64>> = Err(std::io::Error::other("no attempts made"));
        for attempt in 0..attempts {
            last = cgroup::read_memory_max(cg);
            match &last {
                // A finite limit: accept now.
                Ok(Some(_)) => return last,
                // Legitimately unlimited (or the startup "max" default): accept
                // at once unless a threshold is configured, in which case retry.
                Ok(None) if !retry_on_none => return last,
                // Retryable: a genuine read failure, or a `None` we are told to
                // retry. Pause before the next attempt (but not after the last).
                Ok(None) | Err(_) => {
                    if attempt + 1 < attempts {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }
        last
    }

    pub fn run(config: Config, sink: &dyn AlertSink) -> i32 {
        // 0) Logger: gates every line by `--log-level` and optionally stamps it.
        let logger = Logger::new(config.log_level, config.log_timestamps);

        // 1) Block the signals we will read via signalfd. `lib::run` already
        // blocked this exact set on the main thread before spawning any alert
        // worker (so workers inherit the blocked mask — see
        // `block_supervised_signals`); re-blocking here is idempotent and keeps
        // the signalfd's source mask co-located with its construction. Both
        // sites derive the set from `supervised_sigset`, so they cannot drift.
        let mask = supervised_sigset();
        mask.thread_block().expect("block signals");
        let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK).expect("signalfd");

        // 2) Periodic tick timer.
        let tick = TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::TFD_NONBLOCK).expect("tick");
        tick.set(
            Expiration::Interval(timespec(config.tick)),
            TimerSetTimeFlags::empty(),
        )
        .expect("arm tick");

        // 3) Shared deferred-action timer. Its meaning is determined solely by
        // the FSM `State` when the TimerExpired event fires: the grace deadline
        // while Draining, the kill-confirm deadline while Killing, and the
        // respawn deadline while Backoff. It is never armed while Running, so a
        // stale latched expiry after a drain->respawn is a harmless no-op.
        let action =
            TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::TFD_NONBLOCK).expect("action");

        // 4a) cgroup paths resolved authoritatively from /proc; PSI and the
        // memory limit read below both depend on the resolved directories.
        let cg =
            cgroup::CgroupPaths::resolve(&config.cgroup_root, &crate::procfs::ProcSource::system());
        logger.log(
            LogLevel::Info,
            &format!(
                "event=cgroup-resolved version={:?} memory_dir={} cpu_dir={}",
                cg.version,
                logfmt_value(&cg.memory_dir.display().to_string()),
                logfmt_value(&cg.cpu_dir.display().to_string()),
            ),
        );

        // 4) PSI (optional).
        let mut psi_handle = match &config.psi_trigger {
            Some(t) => psi::open(&cg.memory_dir, t),
            None => PsiHandle::Unavailable,
        };
        // Budget for upgrading PSI to event mode after a startup race (#3): when
        // a trigger is configured but startup got `Unavailable` (the orchestrator
        // had not created `memory.pressure` yet), try once per tick for up to
        // PSI_REOPEN_ATTEMPTS ticks. A `Poll` handle is NOT a startup race — the
        // file exists but the trigger write is not permitted, so reopening would
        // just fail the same way every tick; it gets no budget (see
        // `initial_psi_reopen_budget`). Once the budget is consumed (or on
        // success), reopen cost is one cheap branch per tick. A runtime
        // EPOLLERR/HUP (#2) occurs only while in event mode, where the budget is
        // already 0, so it is never retried as a startup race.
        let mut psi_reopen_left: u32 =
            initial_psi_reopen_budget(config.psi_trigger.is_some(), &psi_handle);

        // 5) the memory limit read at startup. We treat a
        // KNOWN limit as fixed for this process's lifetime — true for typical
        // container runtimes; an in-place resize of an already-known limit is
        // NOT observed until restart. Caching it avoids re-reading and
        // re-parsing `memory.max` (v2) / `memory.limit_in_bytes` (v1) on every
        // tick. The one case we DO recover is an INITIALLY-missing limit (the
        // startup read saw the cgroup v2 `"max"` default because the
        // orchestrator had not yet written the real limit): the tick path
        // re-reads while the cache is still `None` and a threshold is set, and
        // caches the first real value it sees (see `refresh_mem_limit`). Once a
        // real limit is cached we stop re-reading.
        // When a threshold is configured the operator expects a real limit, so
        // retry both a genuine read failure (cgroupfs may not be fully mounted
        // yet during container init) AND an `Ok(None)` (cgroup v2 `memory.max`
        // defaults to the literal "max" until the orchestrator writes the real
        // limit) a few times, so a single transient miss at startup does not
        // permanently disable the memory trigger. When no threshold is set the
        // trigger is off and the limit is display-only, so there is no point
        // blocking startup — do a single read and accept whatever it reports.
        let has_threshold = config.mem_threshold.is_some();
        let read_attempts = if has_threshold { 3 } else { 1 };
        // `mut` because the tick path recovers an initially-missing limit (see
        // `refresh_mem_limit`): if the orchestrator writes the real `memory.max`
        // after this startup window, the first tick that sees it caches it here.
        let mut cached_mem_max: Option<u64> =
            match read_mem_max_with_retry(&cg, read_attempts, has_threshold) {
                // A finite limit, or (no threshold) a legitimately unlimited
                // cgroup. Cache as-is; nothing to warn about.
                Ok(limit @ Some(_)) => limit,
                Ok(None) if !has_threshold => None,
                // Threshold configured but the limit still reads as unlimited
                // after every retry: the cgroup reports no limit YET. Never
                // silent — the operator asked for a threshold but it cannot fire
                // until a real limit appears, so the gap is visible in logs. The
                // tick path keeps retrying (see `refresh_mem_limit`), so a limit
                // written shortly after startup is recovered and the trigger
                // becomes live without a restart.
                Ok(None) => {
                    logger.log(
                        LogLevel::Warn,
                        "event=mem-limit-unavailable detail=\"cgroup reports no \
                         memory limit at startup; --mem-threshold cannot fire \
                         until a limit appears (retried each tick)\"",
                    );
                    None
                }
                // A read failure (as opposed to a legitimately unlimited cgroup)
                // means the memory-threshold trigger cannot fire until the limit
                // becomes readable. Surface it when the operator actually
                // configured a threshold, so the gap is visible in logs; the
                // tick path keeps retrying (`refresh_mem_limit`) so a limit that
                // becomes readable later is recovered without a restart.
                Err(e) => {
                    if has_threshold {
                        logger.log(
                            LogLevel::Warn,
                            &format!(
                                "event=mem-limit-unreadable error={e:?} \
                                 path={} detail=\"--mem-threshold cannot fire \
                                 until the limit becomes readable (retried each \
                                 tick)\"",
                                logfmt_value(&cg.memory_dir.display().to_string())
                            ),
                        );
                    }
                    None
                }
            };

        // 6) epoll registration.
        let epoll = Epoll::new(EpollCreateFlags::empty()).expect("epoll");
        epoll
            .add(
                sfd.as_fd(),
                EpollEvent::new(EpollFlags::EPOLLIN, TOK_SIGNAL),
            )
            .unwrap();
        epoll
            .add(tick.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, TOK_TICK))
            .unwrap();
        epoll
            .add(
                action.as_fd(),
                EpollEvent::new(EpollFlags::EPOLLIN, TOK_ACTION),
            )
            .unwrap();
        if let PsiHandle::Event(fd) = &psi_handle {
            epoll
                .add(fd.as_fd(), EpollEvent::new(EpollFlags::EPOLLPRI, TOK_PSI))
                .unwrap();
        }

        // 7) State. `failures` and `restart_total` now live INSIDE the FSM
        // `Ctx` (the single source of truth); `phase`/`shutdown`/`drain_reason`/
        // `escalated` are encoded in `fsm::State` and no longer have shell
        // locals. The initial spawn (and its `return 1` on failure) is
        // unchanged.
        let mut child = match spawn(&config) {
            Ok(c) => c,
            Err(e) => {
                logger.log(
                    LogLevel::Error,
                    &format!("event=spawn-failed phase=initial error={e:?}"),
                );
                return 1;
            }
        };
        log_spawned(&logger, &config, child.pid().as_raw());
        let mut spawn_instant = Instant::now();
        // Edge-triggered latch for the "heartbeat unreadable" WARNING. Set when
        // the heartbeat first becomes unreadable so we log once per unreadable
        // episode (not per child/restart) rather than every tick; cleared once
        // it is readable or missing again, so a later recurrence is re-logged
        // (see `sample`).
        let mut heartbeat_unreadable_warned = false;

        let mut ctx = fsm::Ctx {
            limits: config.decision_limits(),
            failures: 0,
            restart_total: 0,
            grace_period: config.grace_period,
            backoff: config.backoff,
            startup_grace: config.startup_grace,
            max_failures: config.max_failures,
            graceful: match config.graceful_signal {
                crate::config::GracefulSignal::Term => fsm::GracefulKind::Term,
                crate::config::GracefulSignal::Int => fsm::GracefulKind::Int,
            },
        };
        let mut state = fsm::State::Running;
        // Single pre-mortem snapshot for the active drain. The FSM commands a
        // `CaptureSnapshot` while the child is alive (and re-captures before any
        // SIGKILL escalation); `SendDrainAlert` consumes it exactly once via
        // `.take()`.
        let mut stash: Option<Snapshot> = None;

        let mut pending: VecDeque<fsm::Event> = VecDeque::new();
        let mut events = [EpollEvent::empty(); 8];
        loop {
            let n = match epoll.wait(&mut events, EpollTimeout::NONE) {
                Ok(n) => n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    logger.log(LogLevel::Error, &format!("event=epoll-error error={e:?}"));
                    return 1;
                }
            };

            // REAP-FIRST (#1): before processing ANY epoll event, confirm child
            // liveness ONCE. A child that exited is delivered as ChildExited
            // BEFORE any PSI/tick/action event in this batch, so a crash
            // coincident with a PSI edge is accounted as a crash, never
            // mislabeled as a graceful PSI restart. This unifies the old SIGCHLD
            // fast-path and the tick backstop into one rule.
            if state_implies_live_child(state) && reap(&logger, &mut child) == ReapOutcome::Exited {
                pending.push_back(fsm::Event::ChildExited);
            }

            for ev in &events[..n] {
                match ev.data() {
                    TOK_SIGNAL => {
                        while let Ok(Some(siginfo)) = sfd.read_signal() {
                            match Signal::try_from(siginfo.ssi_signo as i32) {
                                // SIGCHLD liveness is handled by reap-first above;
                                // just drain it from the signalfd here so EPOLLIN
                                // clears.
                                Ok(Signal::SIGCHLD) => {}
                                Ok(Signal::SIGTERM) | Ok(Signal::SIGINT) => {
                                    pending.push_back(fsm::Event::OperatorStop);
                                }
                                _ => {}
                            }
                        }
                    }
                    TOK_TICK => {
                        tick.wait().ok();
                        // Recover an initially-missing memory limit (unchanged
                        // policy).
                        refresh_mem_limit(
                            &mut cached_mem_max,
                            || cgroup::read_memory_max(&cg),
                            has_threshold,
                        );
                        maybe_reopen_psi(
                            &logger,
                            &mut psi_handle,
                            &mut psi_reopen_left,
                            &epoll,
                            &config,
                            &cg.memory_dir,
                        );
                        pending.push_back(fsm::Event::Tick);
                    }
                    TOK_ACTION => {
                        action.wait().ok();
                        pending.push_back(fsm::Event::TimerExpired);
                    }
                    TOK_PSI => {
                        if psi_ready_is_fatal(ev.events()) {
                            // The trigger fd is in a sticky error/hangup state.
                            // Deregister it (so epoll stops waking us on it) and
                            // fall back to PSI-off, rather than spinning. Log once.
                            if let PsiHandle::Event(fd) = &psi_handle {
                                let _ = epoll.delete(fd.as_fd());
                            }
                            logger.log(
                                LogLevel::Warn,
                                "event=psi-disabled reason=fd-error-or-hangup",
                            );
                            psi_handle = PsiHandle::Unavailable;
                            // A runtime HUP is not a startup race; never retry it
                            // as one (the budget is already 0 here in practice).
                            psi_reopen_left = 0;
                        } else {
                            pending.push_back(fsm::Event::PsiEdge);
                        }
                    }
                    _ => {}
                }
            }

            while let Some(event) = pending.pop_front() {
                // Samples are consulted ONLY by the Running arm of `fsm::step`
                // (resource/heartbeat triggers and crash liveness); every other
                // state ignores them. Skip the cgroup/heartbeat reads otherwise so
                // a burst of queued events (e.g. ticks during a backoff storm)
                // does no per-event I/O (#9).
                let samples = if matches!(state, fsm::State::Running) {
                    build_samples(
                        &logger,
                        &cg,
                        cached_mem_max,
                        &config,
                        &psi_handle,
                        spawn_instant,
                        &mut heartbeat_unreadable_warned,
                    )
                } else {
                    fsm::Samples::placeholder()
                };
                let (next, acts) = fsm::step(state, &mut ctx, event, &samples);
                state = next;
                for a in acts {
                    match a {
                        fsm::Action::Spawn => match spawn(&config) {
                            Ok(c) => {
                                child = c;
                                spawn_instant = Instant::now();
                                log_spawned(&logger, &config, child.pid().as_raw());
                                pending.push_back(fsm::Event::SpawnResult(fsm::SpawnOutcome::Ok));
                            }
                            Err(e) => {
                                logger.log(
                                    LogLevel::Error,
                                    &format!("event=spawn-failed phase=respawn error={e:?}"),
                                );
                                pending.push_back(fsm::Event::SpawnResult(fsm::SpawnOutcome::Err));
                            }
                        },
                        fsm::Action::SignalGraceful => {
                            let sig = match ctx.graceful {
                                fsm::GracefulKind::Term => Signal::SIGTERM,
                                fsm::GracefulKind::Int => Signal::SIGINT,
                            };
                            let _ = child::signal_group(&child, sig);
                        }
                        fsm::Action::SignalKill => {
                            let _ = child::signal_group(&child, Signal::SIGKILL);
                        }
                        fsm::Action::ArmActionTimer(d) => arm_oneshot(&action, d),
                        fsm::Action::DisarmActionTimer => disarm(&action),
                        fsm::Action::CaptureSnapshot {
                            reason,
                            restart_count,
                        } => {
                            stash = Some(snapshot(
                                &cg,
                                cached_mem_max,
                                &config,
                                reason,
                                restart_count,
                                &child,
                            ));
                        }
                        fsm::Action::SendDrainAlert { reason, escalated } => {
                            // Inlined on_drain_complete: classify -> send the
                            // stashed pre-mortem snapshot (captured while alive)
                            // if alert-worthy, else just log. The child is already
                            // reaped; never recompute.
                            if let Some(sev) = alert::classify(reason, escalated, false) {
                                // Every drain that classifies to an alert was
                                // preceded by a CaptureSnapshot (begin_drain /
                                // escalate), so the stash is always Some here.
                                // Keep the canary the old on_drain_complete had.
                                debug_assert!(
                                    stash.is_some(),
                                    "SendDrainAlert fired without a prior CaptureSnapshot"
                                );
                                if let Some(snap) = stash.take() {
                                    sink.send(&snap, sev);
                                } else {
                                    // Unreachable: begin_drain/escalate always
                                    // CaptureSnapshot first (asserted above in
                                    // debug). In release the debug_assert is
                                    // compiled out, so surface the broken
                                    // invariant instead of silently dropping an
                                    // anomaly alert.
                                    logger.log(
                                        LogLevel::Error,
                                        &format!(
                                            "event=internal detail=\"drain alert had no \
                                             captured snapshot; alert dropped\" \
                                             reason={reason:?} escalated={escalated}"
                                        ),
                                    );
                                }
                            } else {
                                log_restart(
                                    &logger,
                                    &config,
                                    child.pid().as_raw(),
                                    reason,
                                    escalated,
                                    ctx.restart_total,
                                );
                            }
                        }
                        fsm::Action::LogCrash { healthy, lived } => {
                            log_crash(&logger, &config, child.pid().as_raw(), healthy, lived);
                        }
                        fsm::Action::CrashLoopGiveUp {
                            failures,
                            restart_count,
                        } => {
                            crash_loop_exit(
                                sink,
                                &cg,
                                cached_mem_max,
                                &config,
                                restart_count,
                                &child,
                            );
                            // Log the give-up with the SAME counters the snapshot
                            // carried, so stderr and the webhook cannot disagree.
                            let label =
                                target_label(&config.target, config.heartbeat_file.as_deref());
                            logger.log(
                                LogLevel::Error,
                                &crash_loop_message(
                                    &label,
                                    child.pid().as_raw(),
                                    failures,
                                    restart_count,
                                ),
                            );
                        }
                        fsm::Action::Unkillable { reason } => {
                            // The target survived SIGKILL within the kill-confirm
                            // window. The escalate() that entered Killing stashed a
                            // pre-SIGKILL snapshot while the hung child was still
                            // alive; surface it as Critical (an un-killable target
                            // is always Critical) and log, BEFORE the loop returns
                            // the non-zero Exit below. Without this the headline
                            // safety feature would exit with no alert, no log, and
                            // the captured snapshot silently discarded.
                            if let Some(sev) = alert::classify(reason, true, false) {
                                debug_assert!(
                                    stash.is_some(),
                                    "Unkillable fired without a prior CaptureSnapshot"
                                );
                                if let Some(snap) = stash.take() {
                                    sink.send(&snap, sev);
                                }
                            }
                            logger.log(
                                LogLevel::Error,
                                &format!(
                                    "event=unkillable detail=\"target survived SIGKILL \
                                     within {:?}; exiting non-zero so tini tears down \
                                     the container\"",
                                    fsm::KILL_CONFIRM
                                ),
                            );
                        }
                        fsm::Action::Exit(code) => return code,
                    }
                }
            }
        }
    }

    /// States in which a live child exists and must be reaped before processing
    /// trigger events (reap-first, #1). Backoff/Respawning have no live child.
    fn state_implies_live_child(state: fsm::State) -> bool {
        matches!(
            state,
            fsm::State::Running | fsm::State::Draining { .. } | fsm::State::Killing { .. }
        )
    }

    /// Whether a PSI epoll readiness is FATAL for the trigger fd. EPOLLERR/EPOLLHUP
    /// on a PSI trigger fd are sticky: the kernel keeps reporting them on every
    /// epoll wakeup, so treating them as a pressure edge would busy-spin / storm
    /// restarts. They mean the trigger is gone, so we disable PSI instead. A plain
    /// EPOLLPRI (possibly alongside other bits) is a normal pressure edge.
    fn psi_ready_is_fatal(flags: EpollFlags) -> bool {
        flags.intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP)
    }

    /// Initial budget for upgrading PSI to event mode after a startup race (#3).
    /// Only an `Unavailable` handle is a recoverable startup race: the
    /// `memory.pressure` file is not there yet, so reopening it on a later tick
    /// can succeed once the orchestrator creates it. A `Poll` handle means the
    /// file exists but the trigger WRITE is not permitted, so `psi::open` would
    /// fail the same way every tick — retrying is futile, so it gets no budget
    /// (closes #2, which otherwise burned ~30 reopen attempts on a Poll-only
    /// host). `Event` is already upgraded; no trigger configured => no budget.
    fn initial_psi_reopen_budget(trigger_configured: bool, handle: &PsiHandle) -> u32 {
        if trigger_configured && matches!(handle, PsiHandle::Unavailable) {
            PSI_REOPEN_ATTEMPTS
        } else {
            0
        }
    }

    /// Whether to attempt upgrading PSI to event mode this tick. Retry only when a
    /// trigger is configured, we are NOT already in event mode, and the bounded
    /// startup-race budget remains. The budget separates a slow-to-appear trigger
    /// (recoverable, #3) from a runtime EPOLLERR/HUP (#2, budget already 0 → no churn).
    fn should_attempt_psi_reopen(
        handle: &PsiHandle,
        trigger_configured: bool,
        budget: u32,
    ) -> bool {
        budget > 0 && trigger_configured && !matches!(handle, PsiHandle::Event(_))
    }

    /// Try once to upgrade PSI to event mode and register the new fd in epoll.
    /// Consumes one budget unit per real attempt; on success registers the fd,
    /// swaps the handle, logs once, and zeroes the budget (no further attempts).
    fn maybe_reopen_psi(
        logger: &Logger,
        psi_handle: &mut PsiHandle,
        psi_reopen_left: &mut u32,
        epoll: &Epoll,
        config: &Config,
        psi_dir: &Path,
    ) {
        let Some(trigger) = &config.psi_trigger else {
            return;
        };
        if !should_attempt_psi_reopen(psi_handle, true, *psi_reopen_left) {
            return;
        }
        *psi_reopen_left -= 1;
        let reopened = psi::open(psi_dir, trigger);
        if let PsiHandle::Event(fd) = &reopened {
            match epoll.add(fd.as_fd(), EpollEvent::new(EpollFlags::EPOLLPRI, TOK_PSI)) {
                Ok(()) => {
                    logger.log(LogLevel::Info, "event=psi-active detail=\"event mode\"");
                    *psi_handle = reopened;
                    *psi_reopen_left = 0;
                }
                Err(e) => {
                    // `reopened` drops here (closing the fd); we retry next tick
                    // until the budget runs out. Log the failure so a PSI trigger
                    // that opens but never registers is diagnosable instead of
                    // silently staying disabled for the process lifetime (#5).
                    logger.log(
                        LogLevel::Warn,
                        &format!(
                            "event=psi-reopen-failed error={e:?} \
                             detail=\"reopened but epoll registration failed; will retry\""
                        ),
                    );
                }
            }
        }
        // Poll/Unavailable result: leave the existing handle untouched and retry
        // next tick until the budget is exhausted.
    }

    /// Build the FSM's `Samples` for one step from the existing `sample` leaf.
    fn build_samples(
        logger: &Logger,
        cg: &cgroup::CgroupPaths,
        cached_mem_max: Option<u64>,
        config: &Config,
        psi_handle: &PsiHandle,
        spawn_instant: Instant,
        heartbeat_unreadable_warned: &mut bool,
    ) -> fsm::Samples {
        let i = sample(
            logger,
            cg,
            cached_mem_max,
            config,
            psi_handle,
            spawn_instant,
            heartbeat_unreadable_warned,
        );
        fsm::Samples {
            elapsed: i.elapsed,
            mem_ratio: i.mem_ratio,
            psi_triggered: i.psi_triggered,
            heartbeat: i.heartbeat,
        }
    }

    fn spawn(config: &Config) -> std::io::Result<Child> {
        let mut env = Vec::new();
        if let Some(hb) = &config.heartbeat_file {
            env.push(("DRAUG_HEARTBEAT_FILE".to_string(), hb.display().to_string()));
        }
        child::spawn(&config.target, &env)
    }

    /// Bounded cap on EINTR retries inside `reap_with_retry`. The normal
    /// "still running" outcome is `Ok(None)` (not `Err`), so this loop never
    /// busy-spins in steady state; the cap only bounds a pathological signal
    /// storm where `waitpid` keeps being interrupted before it can report.
    const REAP_EINTR_RETRIES: u32 = 8;

    /// The three possible results of a non-blocking reap, from the supervisor's
    /// point of view. We deliberately drop the exit-code `i32`: every decision
    /// the loop makes (crash-vs-hang-vs-keep-running) needs only WHICH of these
    /// three states holds, never the code itself.
    ///
    /// * `Exited` — the child was reaped (`waitpid` returned a status, clean exit
    ///   OR signal death). A confirmed termination.
    /// * `Running` — `waitpid(WNOHANG)` reported the child is still alive. A
    ///   confirmed liveness.
    /// * `Inconclusive` — neither could be established: a persistent EINTR past
    ///   the retry cap, or a non-EINTR `waitpid` error. This is NOT a confirmed
    ///   exit and NOT a confirmed-running result, so it must never be collapsed
    ///   into either: reading it as `Exited` would fabricate a phantom crash,
    ///   while reading it as `Running` would silently drop a real crash (#4).
    ///   The reap-first caller acts ONLY on a confirmed `Exited` (it pushes a
    ///   `ChildExited` event), so an `Inconclusive` produces no event and is
    ///   simply retried on the next epoll wakeup's reap.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum ReapOutcome {
        Exited,
        Running,
        Inconclusive,
    }

    /// Apply the EINTR-retry reap policy to a single non-blocking wait closure,
    /// decoupled from the real `child::try_reap` so it can be unit-tested.
    ///
    /// `try_wait` wraps `waitpid(pid, WNOHANG)` in std's `cvt` (NOT `cvt_r`), so
    /// EINTR is surfaced as `Err(ErrorKind::Interrupted)` rather than retried.
    /// Mapping that to `Running` ("still alive") is wrong: a child that exited at
    /// the grace deadline would be misread as hung, and a SIGKILL'd child's exit
    /// would be missed, stalling shutdown. We therefore retry on `Interrupted`.
    /// Because the wait is non-blocking (WNOHANG), each retry returns
    /// immediately; the loop cannot spin in the normal case (the steady-state
    /// "still running" result is `Ok(None)`, never `Err`).
    ///
    /// Mapping to the three `ReapOutcome` states (the exit code is intentionally
    /// discarded — the supervisor never reads it):
    /// * `Ok(Some(_))` → `Exited` (clean exit or signal death; code irrelevant).
    /// * `Ok(None)` → `Running` (genuinely still alive under WNOHANG).
    /// * `Err(Interrupted)` past `cap` → `Inconclusive` (do NOT fabricate an
    ///   exit nor a confirmed-running result from a persistent interruption);
    ///   log it.
    /// * `Err(other)` → `Inconclusive` and log; a non-EINTR error on an owned,
    ///   un-reaped child is essentially impossible (ECHILD is cached by std,
    ///   EINVAL is a programming error). It must not be read as `Exited` (a
    ///   phantom crash while `Running`) nor as `Running` (a dropped real crash);
    ///   `Inconclusive` lets the caller act defensively without committing to
    ///   either.
    fn reap_with_retry(
        logger: &Logger,
        mut try_wait: impl FnMut() -> std::io::Result<Option<ExitStatus>>,
        cap: u32,
    ) -> ReapOutcome {
        // `cap` retries means `cap + 1` total attempts (initial + retries).
        for _ in 0..=cap {
            match try_wait() {
                // A status (clean exit OR signal death) confirms termination.
                // The exit code is irrelevant to every supervisor decision, so
                // we discard it and report only `Exited`.
                Ok(Some(_)) => return ReapOutcome::Exited,
                Ok(None) => return ReapOutcome::Running,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // EINTR: the wait was interrupted before it could report.
                    // Retry — WNOHANG makes this non-blocking, so we do not spin.
                    continue;
                }
                Err(e) => {
                    // Any other error proves NEITHER an exit nor liveness, so it
                    // is `Inconclusive`. Reporting it as `Exited` would trigger a
                    // phantom crash; reporting it as `Running` would silently drop
                    // a real crash (#4). The reap-first caller acts only on a
                    // confirmed `Exited`, so an `Inconclusive` is simply retried
                    // on the next wakeup's reap. Log once.
                    logger.log(LogLevel::Warn, &format!("event=reap-error error={e:?}"));
                    return ReapOutcome::Inconclusive;
                }
            }
        }
        // Interrupted past the cap: do NOT fabricate an exit and do NOT fake a
        // confirmed-running result — report `Inconclusive`. A pathological signal
        // storm is the only way to get here; make the give-up visible.
        logger.log(
            LogLevel::Warn,
            "event=reap-inconclusive detail=\"interrupted past retry cap\"",
        );
        ReapOutcome::Inconclusive
    }

    fn reap(logger: &Logger, child: &mut Child) -> ReapOutcome {
        reap_with_retry(logger, || child::try_reap(child), REAP_EINTR_RETRIES)
    }

    /// The crash-loop give-up log body. Quotes BOTH counters so the stderr log
    /// can never contradict the webhook: `failures` is the consecutive-crash
    /// streak that tripped `max_failures`, while `restart_total` is the lifetime
    /// number of restarts COMPLETED before giving up (the SAME value carried by
    /// the crash-loop alert's snapshot).
    fn crash_loop_message(label: &str, pid: i32, failures: u32, restart_total: u64) -> String {
        format!(
            "event=crash-loop {label} pid={pid} failures={failures} \
             restarts={restart_total} action=giving-up"
        )
    }

    fn crash_loop_exit(
        sink: &dyn AlertSink,
        cg: &cgroup::CgroupPaths,
        cached_mem_max: Option<u64>,
        config: &Config,
        restart_total: u64,
        child: &Child,
    ) {
        // Crash-loop is unavoidably post-mortem: the target exited on its own,
        // so there is no live child to inspect. `snapshot` here reads
        // /proc/<dead-pid>, hence `threads`/`open_fds` are necessarily `None`.
        // We do not fake them; cgroup memory/cpu and the restart count remain
        // meaningful. This event performs NO restart (`will_restart = false`), so
        // it carries `restart_total` unchanged (NOT +1): the lifetime restarts
        // completed before giving up (e.g. 0 if it crash-looped from startup).
        let snap = snapshot(
            cg,
            cached_mem_max,
            config,
            RestartReason::Crash,
            restart_total,
            child,
        );
        if let Some(sev) = alert::classify(RestartReason::Crash, false, true) {
            sink.send(&snap, sev);
        }
        // The adjacent stderr give-up line is emitted by the caller with these
        // same `failures`/`restart_total` counters, so the two cannot disagree.
    }

    /// Recover an initially-missing cgroup memory limit on the live decision
    /// path, then cache it. Pure and unit-testable (the real cgroup read is
    /// injected as a closure), mirroring `read_mem_max_with_retry` /
    /// `reap_with_retry`.
    ///
    /// The startup read can legitimately miss the limit: with cgroup v2 a
    /// just-created container reads `memory.max == "max"` (=> `Ok(None)`) until a
    /// slow orchestrator writes the real limit, possibly AFTER the bounded
    /// startup retry window. Without recovery the Memory trigger would stay dead
    /// for the whole process lifetime. This helper re-reads on the tick path so
    /// the first real value is picked up and cached.
    ///
    /// It only reads when BOTH conditions hold, keeping the per-tick cost minimal:
    /// * `has_threshold` — no threshold means the trigger is off and the limit is
    ///   display-only, so re-reading is pointless;
    /// * `cached.is_none()` — once a real limit is cached the limit is treated as
    ///   fixed for the process lifetime (an in-place RESIZE is intentionally NOT
    ///   observed until restart), so we never re-read and never add a syscall.
    ///
    /// On a successful `Ok(Some(limit))` the recovered value is stored in
    /// `cached`. An `Ok(None)` (still unlimited) or `Err` leaves `cached` as
    /// `None` so the next tick tries again. The unavoidable cost is one small
    /// file read per tick while a threshold is set but the cgroup is genuinely
    /// still unlimited.
    fn refresh_mem_limit(
        cached: &mut Option<u64>,
        read: impl FnOnce() -> std::io::Result<Option<u64>>,
        has_threshold: bool,
    ) {
        if !has_threshold || cached.is_some() {
            return;
        }
        if let Ok(Some(limit)) = read() {
            *cached = Some(limit);
        }
    }

    /// Build a `MemorySample` from a fresh `memory.current` read plus the
    /// startup-cached limit. The single source of truth for both the per-tick
    /// `sample` hot path and the rare `snapshot` alert path (see Finding C).
    ///
    /// `recover` controls the limit when `cached_mem_max` is `None`:
    /// * `false` (hot path): use the cached value as-is — never add per-tick I/O.
    /// * `true` (alert path): a `None` cache may be stale (the startup limit read
    ///   missed because cgroup v2 `memory.max` was still "max"); attempt one
    ///   fresh `read_memory_max` so an alert can report the now-readable limit.
    ///   This neither mutates the cache nor reads the limit when it is already
    ///   cached.
    ///
    /// Returns `None` when `memory.current` itself is unreadable.
    fn mem_sample(
        cg: &cgroup::CgroupPaths,
        cached_mem_max: Option<u64>,
        recover: bool,
    ) -> Option<cgroup::MemorySample> {
        let current = cgroup::read_memory_current(cg).ok()?;
        let max = match cached_mem_max {
            some @ Some(_) => some,
            None if recover => cgroup::read_memory_max(cg).unwrap_or(None),
            None => None,
        };
        Some(cgroup::MemorySample { current, max })
    }

    fn sample(
        logger: &Logger,
        cg: &cgroup::CgroupPaths,
        cached_mem_max: Option<u64>,
        config: &Config,
        psi_handle: &PsiHandle,
        spawn_instant: Instant,
        heartbeat_unreadable_warned: &mut bool,
    ) -> Inputs {
        // Per-tick read is just `memory.current`; the limit is the cached value
        // (captured at startup, or recovered on a later tick by the `run` loop's
        // tick path -> `refresh_mem_limit` if it was initially missing, then
        // cached — see the assumption documented in `run`). `sample` itself never
        // re-reads the limit, so `recover` is false here.
        let mem_ratio = mem_sample(cg, cached_mem_max, false).and_then(|m| m.ratio());
        let heartbeat = match &config.heartbeat_file {
            None => HeartbeatInput::Disabled,
            Some(p) => match heartbeat_age(p, SystemTime::now()) {
                HeartbeatAge::Missing => {
                    *heartbeat_unreadable_warned = false;
                    HeartbeatInput::Missing
                }
                HeartbeatAge::Age(a) => {
                    *heartbeat_unreadable_warned = false;
                    HeartbeatInput::Age(a)
                }
                HeartbeatAge::Unreadable => {
                    // Edge-triggered: warn only on the transition INTO the
                    // unreadable state so a persistent misconfig (permission/
                    // ownership/IO error) is visible without flooding the log
                    // every tick. The latch is reset whenever the file becomes
                    // readable/missing again so a recurrence is re-logged.
                    if !*heartbeat_unreadable_warned {
                        logger.log(
                            LogLevel::Warn,
                            &format!(
                                "event=heartbeat-unreadable heartbeat={} \
                                 detail=\"exists but unreadable; treating as no \
                                 signal (NOT restarting); check permissions/ownership\"",
                                logfmt_value(&p.display().to_string())
                            ),
                        );
                        *heartbeat_unreadable_warned = true;
                    }
                    HeartbeatInput::Unreadable
                }
            },
        };
        // Event mode drives restarts via the epoll TOK_PSI path, so the tick
        // sample never re-checks it (returns `false`). Poll mode has no fd to
        // arm, so each tick reads the averages directly; Unavailable has no PSI
        // at all.
        let psi_triggered = match psi_handle {
            PsiHandle::Poll(path) => match &config.psi_trigger {
                Some(trigger) => psi::poll_triggered(path, trigger),
                None => false,
            },
            PsiHandle::Event(_) | PsiHandle::Unavailable => false,
        };
        Inputs {
            elapsed: spawn_instant.elapsed(),
            mem_ratio,
            psi_triggered,
            heartbeat,
        }
    }

    fn snapshot(
        cg: &cgroup::CgroupPaths,
        cached_mem_max: Option<u64>,
        config: &Config,
        reason: RestartReason,
        restart_count: u64,
        child: &Child,
    ) -> Snapshot {
        // Reuse the startup-cached limit, but recover when it is `None`: snapshot
        // is the rare alert path (anomalies only), so one fresh `read_memory_max`
        // here is cheap, and it lets an alert report a limit that became readable
        // after startup (e.g. cgroup v2 `memory.max` was still "max" when the
        // startup read ran). The cache itself is not mutated; the per-tick
        // `sample` hot path keeps using the cached value.
        let mem = mem_sample(cg, cached_mem_max, true);
        let hb = config.heartbeat_file.as_ref().and_then(|p| {
            match heartbeat_age(p, SystemTime::now()) {
                HeartbeatAge::Age(a) => Some(a.as_secs_f64()),
                // Neither a missing nor an unreadable heartbeat has a knowable
                // age; report `None` for both rather than fabricating one.
                HeartbeatAge::Missing | HeartbeatAge::Unreadable => None,
            }
        });
        let pid = child.pid().as_raw() as u32;
        Snapshot {
            reason,
            restart_count,
            mem_current: mem.map(|m| m.current),
            mem_max: mem.and_then(|m| m.max),
            mem_ratio: mem.and_then(|m| m.ratio()),
            cpu_quota_ratio: cgroup::read_cpu(cg),
            threads: crate::diagnostics::proc_threads(pid),
            open_fds: crate::diagnostics::proc_open_fds(pid),
            heartbeat_age_secs: hb,
        }
    }

    /// Concise identity of the supervised target for log correlation: the
    /// command line (argv joined by spaces) and the heartbeat file draug
    /// watches. Without it, a host running several draug-supervised targets side
    /// by side (two different programs, or N replicas of one) emits
    /// indistinguishable restart lines, so an operator cannot tell WHICH target
    /// is flapping. Takes the two fields rather than `&Config` so it stays a
    /// pure, table-testable formatter. `heartbeat=none` when no heartbeat file
    /// is configured.
    fn target_label(target: &[String], heartbeat_file: Option<&std::path::Path>) -> String {
        let cmd = target.join(" ");
        match heartbeat_file {
            Some(p) => format!(
                "target={cmd:?} heartbeat={}",
                logfmt_value(&p.display().to_string())
            ),
            None => format!("target={cmd:?} heartbeat=none"),
        }
    }

    /// Render a logfmt value, quoting it (Rust-debug-escaped) only when it
    /// contains whitespace or a logfmt delimiter, so a heartbeat path with a
    /// space cannot break the `key=value` framing a collector relies on. Values
    /// with no special chars stay bare for readability (the common case). The
    /// target argv is always rendered with `{:?}` because a command line almost
    /// always has spaces; this helper covers the path field.
    fn logfmt_value(s: &str) -> String {
        if s.is_empty() || s.contains([' ', '\t', '\n', '"', '=']) {
            format!("{s:?}")
        } else {
            s.to_string()
        }
    }

    fn spawned_message(label: &str, pid: i32) -> String {
        format!("event=spawned {label} pid={pid}")
    }

    /// `restarts` is the lifetime number of restarts COMPLETED before this one
    /// (a monotonic counter), matching the field's meaning in the crash-loop
    /// line; `pid` is the outgoing child being restarted.
    fn restart_message(
        label: &str,
        pid: i32,
        reason: RestartReason,
        escalated: bool,
        restarts: u64,
    ) -> String {
        format!(
            "event=restart {label} pid={pid} reason={reason:?} \
             escalated={escalated} restarts={restarts}"
        )
    }

    fn crash_message(label: &str, pid: i32, healthy: bool, lived: Duration) -> String {
        format!("event=crash {label} pid={pid} healthy={healthy} lived={lived:?}")
    }

    fn log_spawned(logger: &Logger, config: &Config, pid: i32) {
        let label = target_label(&config.target, config.heartbeat_file.as_deref());
        logger.log(LogLevel::Info, &spawned_message(&label, pid));
    }
    fn log_restart(
        logger: &Logger,
        config: &Config,
        pid: i32,
        reason: RestartReason,
        escalated: bool,
        restarts: u64,
    ) {
        let label = target_label(&config.target, config.heartbeat_file.as_deref());
        logger.log(
            LogLevel::Warn,
            &restart_message(&label, pid, reason, escalated, restarts),
        );
    }
    fn log_crash(logger: &Logger, config: &Config, pid: i32, healthy: bool, lived: Duration) {
        let label = target_label(&config.target, config.heartbeat_file.as_deref());
        logger.log(LogLevel::Warn, &crash_message(&label, pid, healthy, lived));
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::alert::Severity;
        use std::fs;
        use std::sync::Mutex;
        use tempfile::tempdir;

        /// A `Logger` for tests: emits everything (debug threshold), no
        /// timestamps. The helper tests assert on returned strings, not stderr,
        /// so the sink itself is irrelevant -- this just satisfies the `&Logger`
        /// argument the reap path now takes.
        fn test_logger() -> Logger {
            Logger::new(LogLevel::Debug, false)
        }

        /// Build a fake cgroup v2 dir with the given `memory.max` contents and an
        /// optional `memory.current`.
        fn fake_cgroup_v2(max: &str, current: Option<&str>) -> tempfile::TempDir {
            let d = tempdir().unwrap();
            fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
            fs::write(d.path().join("memory.max"), format!("{max}\n")).unwrap();
            if let Some(c) = current {
                fs::write(d.path().join("memory.current"), format!("{c}\n")).unwrap();
            }
            d
        }

        /// A minimal `Config` for the supervisor helper tests: triggers off,
        /// `cgroup_root` pointed at `cg_dir`. Only the fields the exercised
        /// helpers touch (graceful_signal, grace_period, heartbeat_file,
        /// cgroup_root) are meaningful.
        fn test_config(cg_dir: &std::path::Path) -> Config {
            use clap::Parser as _;
            let cli = crate::config::Cli::try_parse_from([
                "draug",
                "--restart-interval",
                "0",
                "--mem-threshold",
                "0",
                "--psi-trigger",
                "",
                "--cgroup-root",
                cg_dir.to_str().unwrap(),
                "--",
                "true",
            ])
            .unwrap();
            Config::build(cli, crate::config::EnvVars::default()).unwrap()
        }

        /// Spawn a short-lived real child so the snapshot helpers have a live pid
        /// to read /proc from. The caller SIGKILLs and reaps it.
        fn spawn_sleeper() -> Child {
            child::spawn(&["sleep".into(), "30".into()], &[]).expect("spawn sleeper")
        }

        fn kill_and_reap(child: &Child) {
            let _ = child::signal_group(child, Signal::SIGKILL);
            let _ = child::wait_blocking(child);
        }

        /// Recording `AlertSink` that captures every `Snapshot` it is sent so a
        /// test can assert on the exact `restart_count` carried in the payload.
        #[derive(Default)]
        struct RecordingSink {
            sent: Mutex<Vec<(Snapshot, Severity)>>,
        }
        impl AlertSink for RecordingSink {
            fn send(&self, snapshot: &Snapshot, severity: Severity) {
                self.sent.lock().unwrap().push((snapshot.clone(), severity));
            }
        }

        // Finding A: when a threshold is configured (`retry_on_none = true`) and
        // `memory.max` reads as the literal "max" for the whole startup window,
        // the retry loop must NOT short-circuit on the first `Ok(None)`. It runs
        // every attempt and returns `Ok(None)` so the caller can warn loudly —
        // the trigger is never silently disabled. (Pre-fix this returned on the
        // first `Ok(_)`, so it never retried.)
        #[test]
        fn retry_on_persistent_none_when_threshold_configured() {
            let d = fake_cgroup_v2("max", Some("100"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            // 1 attempt to keep the test fast: the point is that `Ok(None)` is
            // returned (not an early-accepted unlimited), so the caller warns.
            let got = read_mem_max_with_retry(&cg, 1, true);
            assert!(matches!(got, Ok(None)));
        }

        // Finding A: a finite limit is returned immediately even when retry-on-
        // none is enabled.
        #[test]
        fn finite_limit_returned_with_retry_on_none() {
            let d = fake_cgroup_v2("4096", Some("100"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            assert_eq!(read_mem_max_with_retry(&cg, 3, true).unwrap(), Some(4096));
        }

        // Finding A: with no threshold (`retry_on_none = false`) a legitimately
        // unlimited cgroup is accepted at once — single attempt, no retry, no
        // added startup latency, and no change in handling of a real "max".
        #[test]
        fn none_accepted_at_once_without_threshold() {
            let d = fake_cgroup_v2("max", Some("100"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            assert_eq!(read_mem_max_with_retry(&cg, 1, false).unwrap(), None);
        }

        // Finding A: a genuine read failure still surfaces as `Err` after the
        // retries are exhausted (no `memory.max` file present).
        #[test]
        fn read_failure_surfaces_as_err() {
            let d = tempdir().unwrap();
            fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
            // no memory.max file => read error
            let cg = cgroup::CgroupPaths::flat(d.path());
            assert!(read_mem_max_with_retry(&cg, 1, true).is_err());
        }

        /// Build a clean-exit `ExitStatus` carrying the given code.
        fn exited(code: i32) -> ExitStatus {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw((code & 0xff) << 8)
        }

        fn eintr() -> std::io::Error {
            std::io::Error::from(std::io::ErrorKind::Interrupted)
        }

        // Findings #3/#4: an EINTR (`Interrupted`) from `try_wait` must be
        // retried, not mis-mapped to "still running". Here the child has really
        // exited (code 0) but the first non-blocking wait was interrupted; the
        // retry observes the exit and reports `Exited`. Pre-fix (`Err -> None`
        // without retry) this returned `Running`, causing a false hang
        // escalation (#3) / shutdown stall (#4).
        #[test]
        fn reap_retries_eintr_then_observes_exit() {
            let mut calls = 0;
            let got = reap_with_retry(
                &test_logger(),
                || {
                    calls += 1;
                    if calls == 1 {
                        Err(eintr())
                    } else {
                        Ok(Some(exited(0)))
                    }
                },
                REAP_EINTR_RETRIES,
            );
            assert_eq!(got, ReapOutcome::Exited);
            assert_eq!(calls, 2, "must retry exactly once after EINTR");
        }

        // #12: a clean exit reports `Exited` regardless of the exit code — the
        // supervisor only needs the exited-vs-running-vs-inconclusive decision,
        // never the i32. Code 0 and code 137 (SIGKILL via 128+9) both map to the
        // SAME `Exited`, proving the code is not consulted.
        #[test]
        fn reap_maps_clean_exit_to_exited_code_independent() {
            assert_eq!(
                reap_with_retry(&test_logger(), || Ok(Some(exited(0))), REAP_EINTR_RETRIES),
                ReapOutcome::Exited
            );
            assert_eq!(
                reap_with_retry(&test_logger(), || Ok(Some(exited(137))), REAP_EINTR_RETRIES),
                ReapOutcome::Exited,
                "the exit code is irrelevant: any Ok(Some) is Exited"
            );
        }

        // #12: a signal death (no exit code; `code()` is None) is still just an
        // exit as far as the supervisor is concerned — `Exited`, NOT a separate
        // sentinel. Replaces the obsolete `reap_signalled_exit_reports_minus_one`
        // test that pinned the now-removed `-1` value.
        #[test]
        fn reap_maps_signalled_exit_to_exited() {
            use std::os::unix::process::ExitStatusExt;
            let signalled = ExitStatus::from_raw(Signal::SIGKILL as i32);
            let got = reap_with_retry(&test_logger(), || Ok(Some(signalled)), REAP_EINTR_RETRIES);
            assert_eq!(got, ReapOutcome::Exited);
        }

        // Steady state: a genuinely still-running child reports `Ok(None)` on the
        // first attempt (never `Err`), so there is exactly one call, no spin, and
        // the outcome is `Running`.
        #[test]
        fn reap_returns_running_immediately_when_still_running() {
            let mut calls = 0;
            let got = reap_with_retry(
                &test_logger(),
                || {
                    calls += 1;
                    Ok(None)
                },
                REAP_EINTR_RETRIES,
            );
            assert_eq!(got, ReapOutcome::Running);
            assert_eq!(calls, 1, "Ok(None) must not retry");
        }

        // #5: a persistent EINTR past the retry cap is NOT fabricated into a
        // confirmed exit NOR a confirmed-running result: it is `Inconclusive`, a
        // third state the caller must handle defensively (it can neither finish a
        // drain cleanly nor declare a confirmed hang on it). The call count is
        // bounded by `cap + 1` (initial attempt + `cap` retries).
        #[test]
        fn reap_gives_up_to_inconclusive_when_eintr_persists() {
            let mut calls = 0;
            let cap = 3;
            let got = reap_with_retry(
                &test_logger(),
                || {
                    calls += 1;
                    Err(eintr())
                },
                cap,
            );
            assert_eq!(
                got,
                ReapOutcome::Inconclusive,
                "persistent EINTR is inconclusive, not a confirmed exit or run"
            );
            assert_eq!(calls, cap + 1, "must stop after cap + 1 attempts");
        }

        // #4/#5: a non-EINTR error is also `Inconclusive` (never a confirmed
        // exit nor confirmed-running), and is NOT retried (only `Interrupted` is
        // retryable). The Running-path backstop and the grace-deadline defensive
        // escalation are what cover this state — it must never be silently
        // dropped as "still running".
        #[test]
        fn reap_non_eintr_error_is_inconclusive_without_retry() {
            let mut calls = 0;
            let got = reap_with_retry(
                &test_logger(),
                || {
                    calls += 1;
                    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
                },
                REAP_EINTR_RETRIES,
            );
            assert_eq!(got, ReapOutcome::Inconclusive);
            assert_eq!(calls, 1, "a non-EINTR error must not retry");
        }

        // Finding B: when the startup limit read missed (cached `None`) but the
        // limit is now readable, the alert/snapshot path (`recover = true`)
        // re-reads `memory.max` so the sample reports the recovered limit/ratio.
        #[test]
        fn mem_sample_recovers_limit_when_cache_none() {
            let d = fake_cgroup_v2("1000", Some("850"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            let s = mem_sample(&cg, None, true).expect("current readable");
            assert_eq!(s.current, 850);
            assert_eq!(s.max, Some(1000));
            assert_eq!(s.ratio(), Some(0.85));
        }

        // Finding B/C: the hot path (`recover = false`) must NOT re-read the
        // limit — a `None` cache stays `None` even though `memory.max` is now a
        // finite value, so no per-tick I/O is added.
        #[test]
        fn mem_sample_keeps_cache_none_on_hot_path() {
            let d = fake_cgroup_v2("1000", Some("850"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            let s = mem_sample(&cg, None, false).expect("current readable");
            assert_eq!(s.current, 850);
            assert_eq!(s.max, None);
            assert_eq!(s.ratio(), None);
        }

        // Finding C: a cached finite limit is used verbatim and the limit file is
        // never consulted (the cached value wins even if `memory.max` differs).
        #[test]
        fn mem_sample_uses_cached_limit_verbatim() {
            let d = fake_cgroup_v2("max", Some("256"));
            let cg = cgroup::CgroupPaths::flat(d.path());
            // cache says 512; the file says "max" (None) — cache must win, and
            // recovery must not even run because the cache is already Some.
            let s = mem_sample(&cg, Some(512), true).expect("current readable");
            assert_eq!(s.current, 256);
            assert_eq!(s.max, Some(512));
            assert_eq!(s.ratio(), Some(0.5));
        }

        // `mem_sample` returns `None` when `memory.current` itself is unreadable.
        #[test]
        fn mem_sample_none_when_current_unreadable() {
            let d = fake_cgroup_v2("1000", None);
            let cg = cgroup::CgroupPaths::flat(d.path());
            assert!(mem_sample(&cg, Some(1000), false).is_none());
        }

        // Startup-race recovery (a): the cache is `None`, a threshold is
        // configured, and the limit is now readable — `refresh_mem_limit` must
        // store the recovered limit so the SAME tick samples against it and the
        // cache stops re-reading on later ticks.
        #[test]
        fn refresh_recovers_limit_when_cache_none_and_threshold_set() {
            let mut cached: Option<u64> = None;
            refresh_mem_limit(&mut cached, || Ok(Some(4096)), true);
            assert_eq!(cached, Some(4096));
        }

        // Recovery (b): the cache is `None` and the limit still reads as
        // unlimited (`Ok(None)`) — the cache stays `None` so the next tick tries
        // again. An `Err` behaves identically (left `None`, retried next tick).
        #[test]
        fn refresh_keeps_none_when_read_still_unlimited() {
            let mut cached: Option<u64> = None;
            refresh_mem_limit(&mut cached, || Ok(None), true);
            assert_eq!(cached, None);

            let mut cached: Option<u64> = None;
            refresh_mem_limit(
                &mut cached,
                || Err(std::io::Error::other("read failed")),
                true,
            );
            assert_eq!(cached, None);
        }

        // Recovery (c): once a real limit is cached, the limit is fixed for the
        // process lifetime — `refresh_mem_limit` must NOT call the read closure
        // and must leave the cached value untouched (no per-tick syscall forever,
        // and an in-place resize is intentionally not observed). A `Cell` flag
        // asserts the closure was never invoked.
        #[test]
        fn refresh_does_not_read_once_limit_cached() {
            use std::cell::Cell;
            let called = Cell::new(false);
            let mut cached: Option<u64> = Some(512);
            refresh_mem_limit(
                &mut cached,
                || {
                    called.set(true);
                    Ok(Some(9999))
                },
                true,
            );
            assert!(!called.get(), "closure must not run when a limit is cached");
            assert_eq!(cached, Some(512), "the cached limit must be untouched");
        }

        // Recovery (d): with no threshold configured the trigger is off and the
        // limit is display-only, so there is no point re-reading — the closure
        // must NOT be called and the cache stays `None`.
        #[test]
        fn refresh_does_not_read_without_threshold() {
            use std::cell::Cell;
            let called = Cell::new(false);
            let mut cached: Option<u64> = None;
            refresh_mem_limit(
                &mut cached,
                || {
                    called.set(true);
                    Ok(Some(4096))
                },
                false,
            );
            assert!(!called.get(), "closure must not run without a threshold");
            assert_eq!(cached, None, "the cache stays None with no threshold");
        }

        // Finding #5: the crash-loop give-up event performs NO restart, so its
        // reported restart_count is the lifetime restarts COMPLETED (unchanged
        // `restart_total`). The adjacent stderr log MUST quote that SAME number
        // alongside the consecutive-failure streak so the webhook and stderr can
        // never contradict each other. A target that crash-looped from startup
        // reports 0 lifetime restarts.
        #[test]
        fn crash_loop_message_quotes_failures_and_lifetime_restarts() {
            let label = "target=\"svc\" heartbeat=none";
            // Crash-looped from startup: 0 lifetime restarts.
            let msg = crash_loop_message(label, 1234, 3, 0);
            assert!(msg.contains("event=crash-loop"), "msg = {msg}");
            assert!(msg.contains("failures=3"), "msg = {msg}");
            assert!(msg.contains("restarts=0"), "msg = {msg}");
            assert!(msg.contains("pid=1234"), "msg = {msg}");
            assert!(msg.contains(label), "msg = {msg}");
            // The two distinct counters must both be present and distinct.
            let msg = crash_loop_message(label, 1234, 5, 2);
            assert!(msg.contains("failures=5"), "msg = {msg}");
            assert!(msg.contains("restarts=2"), "msg = {msg}");
        }

        // `spawned` is the new lifecycle line that answers "what did draug just
        // start, and as which PID" -- the field an operator needs to attribute a
        // later restart/crash line to a specific child (and to tell apart N
        // same-argv replicas, where the pid is the only unique key).
        #[test]
        fn spawned_message_carries_label_and_pid() {
            let label = "target=\"sleep 30\" heartbeat=/run/draug/hb";
            let m = spawned_message(label, 4321);
            assert!(m.contains("event=spawned"), "msg = {m}");
            assert!(m.contains(label), "msg = {m}");
            assert!(m.contains("pid=4321"), "msg = {m}");
        }

        // The lifecycle log lines must carry the target's identity (argv +
        // heartbeat path) so an operator triaging a host with several
        // draug-supervised targets can tell WHICH one is flapping. Before this,
        // every restart line read `draug: restart reason=... escalated=...` with
        // no way to attribute it.
        #[test]
        fn target_label_includes_argv_and_heartbeat_path() {
            use std::path::Path;
            let argv = ["sleep".to_string(), "30".to_string()];
            let with_hb = target_label(&argv, Some(Path::new("/run/draug/a.hb")));
            assert!(with_hb.contains("sleep 30"), "label = {with_hb}");
            assert!(
                with_hb.contains("heartbeat=/run/draug/a.hb"),
                "label = {with_hb}"
            );
            // Two targets differing only by heartbeat path stay distinguishable.
            let other = target_label(&argv, Some(Path::new("/run/draug/b.hb")));
            assert_ne!(with_hb, other);
            // No heartbeat configured => explicit `none`, never an empty value.
            let no_hb = target_label(&argv, None);
            assert!(no_hb.contains("heartbeat=none"), "label = {no_hb}");
        }

        // A heartbeat path containing whitespace must NOT break the logfmt
        // framing: it has to be quoted so a collector still parses `heartbeat`
        // as one value. A path with no special chars stays bare for readability.
        #[test]
        fn logfmt_value_quotes_only_when_needed() {
            // Bare for the common case.
            assert_eq!(logfmt_value("/run/draug/hb"), "/run/draug/hb");
            // Quoted (and escaped) when whitespace or a delimiter is present.
            assert_eq!(logfmt_value("/run/my dir/hb"), "\"/run/my dir/hb\"");
            assert_eq!(logfmt_value("a=b"), "\"a=b\"");
            assert!(logfmt_value("a\"b").starts_with('"'));
            assert!(logfmt_value("a\nb").starts_with('"'));
            assert_eq!(logfmt_value(""), "\"\"");
        }

        #[test]
        fn target_label_quotes_a_spaced_heartbeat_path() {
            use std::path::Path;
            let argv = ["sleep".to_string(), "30".to_string()];
            let label = target_label(&argv, Some(Path::new("/run/my dir/hb")));
            // The spaced path is quoted, so `heartbeat=` stays a single value and
            // the line does not split into a stray bare token.
            assert!(
                label.contains("heartbeat=\"/run/my dir/hb\""),
                "label = {label}"
            );
        }

        #[test]
        fn restart_and_crash_messages_carry_label_pid_and_fields() {
            let label = "target=\"sleep 30\" heartbeat=/run/draug/hb";
            let r = restart_message(label, 1234, RestartReason::HeartbeatStale, false, 3);
            assert!(r.contains("event=restart"), "msg = {r}");
            assert!(r.contains(label), "msg = {r}");
            assert!(r.contains("pid=1234"), "msg = {r}");
            assert!(r.contains("reason=HeartbeatStale"), "msg = {r}");
            assert!(r.contains("escalated=false"), "msg = {r}");
            assert!(r.contains("restarts=3"), "msg = {r}");

            let c = crash_message(label, 1234, true, Duration::from_secs(7));
            assert!(c.contains("event=crash"), "msg = {c}");
            assert!(c.contains(label), "msg = {c}");
            assert!(c.contains("pid=1234"), "msg = {c}");
            assert!(c.contains("healthy=true"), "msg = {c}");
        }

        // Finding #5 (actual invariant): the `Snapshot` the crash-loop give-up
        // path SENDS carries `restart_count == restart_total` (the lifetime
        // restarts COMPLETED, NOT the +1 used for restart-performing alerts), and
        // that value equals the number quoted in the adjacent stderr log — so the
        // webhook payload and the log can never contradict each other.
        //
        // Unlike the previous version, this drives the real `crash_loop_exit`
        // with a recording sink and asserts on the ACTUAL captured snapshot, so
        // it FAILS if someone regresses `crash_loop_exit` to pass
        // `restart_total + 1` (the restart-performing count) into the snapshot.
        #[test]
        fn crash_loop_snapshot_count_matches_log_lifetime_restarts() {
            let cgdir = fake_cgroup_v2("1000", Some("100"));
            let cg = cgroup::CgroupPaths::flat(cgdir.path());
            let config = test_config(cgdir.path());
            let child = spawn_sleeper();
            let sink = RecordingSink::default();

            // A target that has been restarted twice before crash-looping.
            let restart_total = 2u64;
            crash_loop_exit(&sink, &cg, None, &config, restart_total, &child);
            kill_and_reap(&child);

            let sent = sink.sent.lock().unwrap();
            assert_eq!(sent.len(), 1, "crash-loop must send exactly one alert");
            let (snap, sev) = &sent[0];
            assert_eq!(*sev, Severity::Critical);
            // The actual webhook restart_count equals the lifetime restarts, NOT
            // the +1 used by restart-performing alerts.
            assert_eq!(
                snap.restart_count, restart_total,
                "crash-loop snapshot must carry the raw lifetime restart_total"
            );
            assert_ne!(
                snap.restart_count,
                restart_total.saturating_add(1),
                "crash-loop snapshot must NOT use the +1 pending count"
            );
            // The adjacent stderr log quotes the SAME number.
            let label = target_label(&config.target, config.heartbeat_file.as_deref());
            assert!(
                crash_loop_message(&label, child.pid().as_raw(), 3, restart_total)
                    .contains("restarts=2"),
                "log must quote the same lifetime restart count as the snapshot"
            );
        }

        // Bug: nix's `TimeSpec::from_duration` does `tv_sec = as_secs() as
        // time_t` with no high-end check, so a Duration whose `as_secs()`
        // exceeds `i64::MAX` casts to a NEGATIVE `tv_sec`, which
        // `timerfd_settime` rejects with EINVAL → `arm_oneshot` panics. The
        // clamp in `timespec` must cap such pathological durations to a valid,
        // effectively-infinite positive `tv_sec`. This is the regression guard:
        // without the clamp `Duration::MAX` yields `tv_sec() == -1`.
        #[test]
        fn timespec_clamps_saturated_duration_to_non_negative() {
            let ts = timespec(Duration::MAX);
            assert!(
                ts.tv_sec() >= 0,
                "tv_sec must stay non-negative; got {}",
                ts.tv_sec()
            );
        }

        // Normal whole-second durations must convert exactly as before: only
        // pathologically huge durations are touched by the clamp.
        #[test]
        fn timespec_preserves_whole_seconds() {
            let ts = timespec(Duration::from_secs(5));
            assert_eq!(ts.tv_sec(), 5);
            assert_eq!(ts.tv_nsec(), 0);
        }

        // Sub-second durations must survive unchanged: zero seconds, non-zero
        // nanoseconds.
        #[test]
        fn timespec_preserves_sub_second() {
            let ts = timespec(Duration::from_millis(250));
            assert_eq!(ts.tv_sec(), 0);
            assert!(
                ts.tv_nsec() != 0,
                "sub-second duration must keep non-zero nanoseconds"
            );
        }

        // The existing zero-clamp behavior is unchanged: ZERO floors to 1ms so
        // we never arm an already-expired oneshot timer.
        #[test]
        fn timespec_floors_zero_to_one_millisecond() {
            let ts = timespec(Duration::ZERO);
            assert_eq!(ts.tv_sec(), 0);
            assert_eq!(ts.tv_nsec(), 1_000_000);
        }

        // Ties the clamp to the real overflow source: a large `--backoff`
        // multiplied by a large failure streak saturates toward `Duration::MAX`,
        // and the resulting timespec must still be a valid non-negative `tv_sec`
        // the kernel accepts.
        #[test]
        fn timespec_of_saturated_backoff_is_non_negative() {
            let d = fake_cgroup_v2("max", Some("100"));
            let mut config = test_config(d.path());
            config.backoff = Duration::from_secs(u64::MAX / 2);
            let delay = config.backoff.saturating_mul(u32::MAX);
            let ts = timespec(delay);
            assert!(
                ts.tv_sec() >= 0,
                "a saturated backoff must not produce a negative tv_sec; got {}",
                ts.tv_sec()
            );
        }

        // Finding #2: EPOLLERR/EPOLLHUP on the PSI trigger fd are sticky — the
        // kernel keeps reporting them on every epoll wakeup. Treating them as a
        // pressure edge would busy-spin and storm restarts, so they are classified
        // as fatal (disable PSI) rather than as a PsiEdge. A plain EPOLLPRI
        // (possibly alongside other bits) is a normal pressure edge, not fatal.
        #[test]
        fn psi_err_or_hup_is_fatal_but_pri_is_not() {
            use nix::sys::epoll::EpollFlags;
            assert!(psi_ready_is_fatal(EpollFlags::EPOLLERR));
            assert!(psi_ready_is_fatal(EpollFlags::EPOLLHUP));
            // A fatal bit coincident with EPOLLPRI is still fatal.
            assert!(psi_ready_is_fatal(
                EpollFlags::EPOLLERR | EpollFlags::EPOLLPRI
            ));
            // A normal pressure edge is NOT fatal.
            assert!(!psi_ready_is_fatal(EpollFlags::EPOLLPRI));
        }

        #[test]
        fn psi_reopen_only_when_budget_and_not_event() {
            use std::path::PathBuf;
            // Not in event mode, budget remaining, trigger configured -> attempt.
            assert!(should_attempt_psi_reopen(&PsiHandle::Unavailable, true, 5));
            assert!(should_attempt_psi_reopen(
                &PsiHandle::Poll(PathBuf::from("/x")),
                true,
                1
            ));
            // No budget -> never.
            assert!(!should_attempt_psi_reopen(&PsiHandle::Unavailable, true, 0));
            // No trigger configured -> never (even with budget + non-Event).
            assert!(!should_attempt_psi_reopen(
                &PsiHandle::Unavailable,
                false,
                5
            ));
            // Already event mode -> never, even with budget remaining. This is
            // the #2/#3 separation: a HUP'd fd is set to Unavailable with budget
            // 0, and a healthy Event needs no retry. We borrow an arbitrary fd
            // (/dev/null) only to exercise the `!matches!(handle, Event(_))` gate.
            let dev_null = std::fs::File::open("/dev/null").unwrap();
            let event = PsiHandle::Event(std::os::fd::OwnedFd::from(dev_null));
            assert!(!should_attempt_psi_reopen(&event, true, 5));
        }

        // #2: only an `Unavailable` startup handle is a recoverable startup race
        // and earns the reopen budget. A `Poll` handle (file readable but the
        // trigger write is rejected) would fail `psi::open` identically every
        // tick, so it must get ZERO budget rather than burning ~30 futile
        // open/write/close cycles. `Event` is already upgraded, and no trigger
        // configured means no budget regardless of handle.
        #[test]
        fn psi_reopen_budget_armed_only_for_unavailable() {
            use std::path::PathBuf;
            // Unavailable + trigger configured -> full startup-race budget.
            assert_eq!(
                initial_psi_reopen_budget(true, &PsiHandle::Unavailable),
                PSI_REOPEN_ATTEMPTS
            );
            // Poll -> retrying is futile, so NO budget (this is the #2 fix).
            assert_eq!(
                initial_psi_reopen_budget(true, &PsiHandle::Poll(PathBuf::from("/x"))),
                0
            );
            // Event -> already upgraded, no budget.
            let dev_null = std::fs::File::open("/dev/null").unwrap();
            let event = PsiHandle::Event(std::os::fd::OwnedFd::from(dev_null));
            assert_eq!(initial_psi_reopen_budget(true, &event), 0);
            // No trigger configured -> no budget even for Unavailable.
            assert_eq!(initial_psi_reopen_budget(false, &PsiHandle::Unavailable), 0);
        }
    }
}
