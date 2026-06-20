# draug

[![CI](https://github.com/dvazar/draug/actions/workflows/ci.yml/badge.svg)](https://github.com/dvazar/draug/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/dvazar/draug/graph/badge.svg)](https://codecov.io/gh/dvazar/draug)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> A small, cgroup-aware process supervisor in Rust — built **for containers** —
> that restarts the target gracefully, before the OOM killer does.

```
draug [options] -- <command> [args...]
```

## The problem it solves

Long-running processes — a script, a server, a worker, a daemon, anything that
stays up for hours — tend to leak memory over time. The standard mitigation is
**recycling**: restart on a timer and restart *before* the process hits its
memory limit. On a bare host or VM, mature tools already do this well — but
**inside a container they fall apart**, for two reasons:

1. **Generic tools measure the wrong number.** [psutil](https://github.com/giampaolo/psutil),
   [monit](https://mmonit.com/monit/), and [circus](https://github.com/circus-tent/circus)
   read host-level statistics (`/proc/meminfo` and friends), not the cgroup the
   container actually lives in. Under a container memory limit their numbers are
   simply wrong — the only correct source of truth is the cgroup itself.
2. **The OOM killer is brutal.** When a cgroup hits its limit the kernel sends
   `SIGKILL` — no chance to finish in-flight work, flush state, or drain
   connections, leaving jobs half-done and data inconsistent.
   [systemd-oomd](https://www.freedesktop.org/software/systemd/man/latest/systemd-oomd.service.html)
   / [oomd](https://github.com/facebookincubator/oomd) can act earlier, but they
   also `SIGKILL` — and they aren't available on AWS ECS/Fargate at all. That
   is exactly where this problem bites hardest: a managed container platform with a
   hard memory limit but no built-in graceful pre-OOM mechanism. draug is built for
   precisely that gap.

## Why draug exists

draug was built to do the one thing those tools can't: read the cgroup
**directly** and act **before** the kernel would OOM-kill the target, restarting
it the gentle way — `SIGTERM` → grace period → `SIGKILL` — so the application
gets a real chance to shut down cleanly. The graceful part (finishing jobs,
closing resources) lives in the *target's* own signal handler; draug decides
*when* to restart, sends the signal, and escalates to `SIGKILL` only if the
target hangs.

It is deliberately tiny: a single static binary, no interpreter, no GC, one
supervised target per container. It does one job — supervise your process — and
leaves the PID 1 duties (reaping orphans, forwarding signals) to a minimal init
like [`tini`](https://github.com/krallin/tini) or `docker run --init`, which most
container setups already run anyway. draug works the same whether or not one is
present; an init just keeps a misbehaving target from leaking zombie processes.

**The name:** `draug` is `guard` reversed (a nod to `tini` = `init` reversed),
and Old Norse *draugr* — the undead that returns from the grave. Fitting for a
supervisor whose whole job is resurrecting its target.

## What it does

draug restarts the target gracefully on any of:

- a **periodic timer** (`--restart-interval`) — flush slow leaks proactively;
- a **cgroup memory threshold** (`--mem-threshold`, `memory.current / memory.max`);
- **PSI memory pressure** (`memory.pressure`, event-driven, with a polling fallback);
- a **stale heartbeat** (`--heartbeat-file`) — catches alive-but-stuck targets;

and it backs off and gives up after repeated crash-loops. CPU is monitored for
diagnostics/alerts only, never as a restart trigger.

## Install

Linux only (x86_64 / aarch64). Prebuilt static (musl) and glibc binaries are
attached to every GitHub Release.

One-line install (picks the right binary for your platform):

    curl --proto '=https' --tlsv1.2 -LsSf \
      https://github.com/dvazar/draug/releases/latest/download/draug-installer.sh | sh

In a container, copy a static binary straight into your image:

    COPY --from=builder /draug /usr/local/bin/draug

Or download a binary manually from the [Releases page](https://github.com/dvazar/draug/releases).

## How it works

A single synchronous `epoll` loop drives everything, over four fds:

| fd               | source                                              | role                                                             |
|------------------|-----------------------------------------------------|------------------------------------------------------------------|
| `signalfd`       | `SIGTERM`/`SIGINT`/`SIGCHLD` (blocked, read via fd) | `TERM` from PID 1 / the orchestrator → graceful shutdown + exit; `SIGCHLD` → reap |
| tick `timerfd`   | a 1–2 s tick                                        | read `memory.current/max`, heartbeat age, periodic deadline      |
| action `timerfd` | a deferred one-shot                                 | the active deadline: grace period, `SIGKILL`-confirm, or respawn |
| `psi_fd`         | `memory.pressure` trigger                           | `EPOLLPRI` = pressure crossed the threshold                      |

All trigger logic lives in a **pure decision core** (`decision::evaluate`) that
takes samples + state and returns a decision — no I/O, so it is exhaustively
table-tested. Precedence is `Crash > HeartbeatStale > Psi > Memory > Periodic`,
and heartbeat/psi/memory are gated by a configurable startup grace. Both PSI
modes (event and poll) flow through this same core, so grace and precedence have
a single source of truth.

The control logic is a second **pure state machine** (`fsm::step`): given the
current state, an event, and the latest samples, it returns the next state and a
list of side-effect *actions*. A thin I/O shell owns the epoll loop, the child,
and the fds; each wakeup it **reaps first** (so a crash is never mislabeled as a
graceful restart), turns fd readiness into events, runs `fsm::step`, and executes
the returned actions (spawn, signal, snapshot, alert, log). The states —
`Running → Draining → Killing → Backoff → Respawning` — distinguish a *restart*
(reap, then respawn) from a *shutdown* (drain, then exit), so an operator's
`SIGTERM` stops the container cleanly while an internal trigger restarts the
target. A hung target is escalated to `SIGKILL`; if it survives even that within
a bounded confirm window, draug exits non-zero rather than hanging forever. This
split — a pure core plus an I/O shell — makes the whole lifecycle policy
host-testable without spawning real processes.

## Build

```sh
cargo build --release          # binary at target/release/draug
```

Requires Rust (edition 2024). Linux for the real thing (cgroups, PSI, epoll);
the pure/parser layers build and test on macOS too.

## Usage

Put your command after `--`:

```sh
draug \
    --restart-interval 30m \
    --mem-threshold 0.85 \
    --grace-period 90s \
    --heartbeat-file /run/draug/hb \
    -- <command> [args...]
```

Run it under a minimal init so PID 1 reaps orphans and forwards signals —
`tini -g -- draug …`, or simply start the container with `docker run --init`
(which gives you tini). Most orchestrators already run an init as PID 1, so often
there is nothing extra to add.

Disable any trigger individually: `--restart-interval 0`, `--mem-threshold 0`,
`--psi-trigger ""` (PSI is disabled by an *empty string*, not `0`). So one
binary covers everything from "timer only" to "timer + memory + PSI + heartbeat".

## Configuration

CLI flags (the target command follows `--`):

| Flag                        | Default          | Purpose                                                                    |
|-----------------------------|------------------|----------------------------------------------------------------------------|
| `--restart-interval <dur>`  | `30m`            | Periodic graceful restart. `0` = off                                       |
| `--mem-threshold <ratio>`   | `0.85`           | Restart when `memory.current/memory.max >= ratio`. `0` = off               |
| `--psi-trigger <stall/win>` | `150000/1000000` | PSI `some` threshold in µs. Empty = off; requires `stall <= window`        |
| `--graceful-signal <T\|I>`  | `TERM`           | Graceful stop signal (`TERM` or `INT`)                                     |
| `--grace-period <dur>`      | `90s`            | How long to wait before `SIGKILL` (must be `> 0`)                          |
| `--tick <dur>`              | `2s`             | Memory/heartbeat poll period (must be `> 0`)                               |
| `--heartbeat-file <path>`   | — (off)          | Heartbeat file; target updates its **mtime**, draug reads `now - mtime`    |
| `--heartbeat-max-age <dur>` | `60s`            | Staleness threshold (must be `> 0` when a heartbeat file is set)           |
| `--startup-grace <dur>`     | `15s`            | Suppress heartbeat/triggers for the first N s (must be `> 0`)              |
| `--max-failures <n>`        | `3`              | Consecutive failed starts → alert + exit (must be `>= 1`)                  |
| `--backoff <dur>`           | `5s`             | Backoff base (grows linearly with the failure streak)                      |
| `--cgroup-root <path>`      | `/sys/fs/cgroup` | Override the cgroup root (testing)                                         |
| `--log-level <level>`       | `info`           | Min level to emit: `error`/`warn`/`info`/`debug`. Env `DRAUG_LOG_LEVEL`    |
| `--log-timestamps`          | off              | Prefix each line with an RFC3339 UTC timestamp. Env `DRAUG_LOG_TIMESTAMPS` |

Durations accept `ms`/`s`/`m`/`h` (a bare number means seconds). Zero values for
the protection knobs (`--startup-grace`, `--heartbeat-max-age` with a heartbeat
file, `--max-failures`, `--tick`, `--grace-period`, `--backoff`) are rejected,
because they would silently defeat the very protection they configure.

### Environment

| Variable               | Purpose                                                                           |
|------------------------|-----------------------------------------------------------------------------------|
| `DRAUG_WEBHOOK_URL`    | POST anomaly alerts as JSON                                                       |
| `DRAUG_SERVICE`        | Service name tag in the alert payload                                             |
| `DRAUG_ENV`            | Environment tag (`dev`/`staging`/`prod`)                                          |
| `DRAUG_HEARTBEAT_FILE` | Passed to the target so it knows where to write heartbeats                        |
| `DRAUG_LOG_LEVEL`      | Min log level (`error`/`warn`/`info`/`debug`); `--log-level` overrides it         |
| `DRAUG_LOG_TIMESTAMPS` | Truthy (`1`/`true`/`yes`/`on`) enables RFC3339 timestamps (or `--log-timestamps`) |

## Alerting

Alerts fire on **anomalies only** — `SIGKILL` escalation (a hung target),
crash-loop give-up, and memory/PSI restarts (a growing leak). Periodic restarts
and single recovered crashes are logged, not alerted. Each payload carries the
restart reason, a lifetime restart count, and a diagnostic snapshot
(memory/CPU/threads/fds/heartbeat age) captured while the target is still alive.

Delivery runs on a background worker with a **severity-aware bounded queue** that
never blocks the event loop. Under saturation, `Critical` alerts (escalation,
crash-loop) are **never silently dropped** — a new `Critical` evicts the oldest
`Warning` to make room; only `Warning`s are shed (counted, with rate-limited
logging). If the worker ever dies, that is surfaced once rather than silently
black-holing alerts.

## Logging

draug logs one structured event per line to **stderr** in logfmt (`key=value`),
so collectors (CloudWatch Logs Insights, Loki) parse it without a custom pattern
while it stays readable in `docker logs`:

```
draug: level=info event=spawned target="<command> [args...]" pid=1234 heartbeat=/run/draug/hb
draug: level=warn event=restart target="..." pid=1234 reason=HeartbeatStale escalated=false restarts=3
draug: level=error event=crash-loop target="..." pid=1234 failures=3 restarts=2 action=giving-up
```

Every lifecycle line carries the target's identity — its command line and the
heartbeat path it watches — plus the child **pid**. So when several
draug-supervised targets run side by side (or N replicas of one), you can tell
*which* one (re)started or crashed instead of reading an indistinguishable line.

`--log-level` sets the minimum severity emitted (`error < warn < info < debug`):
`info` (the default) shows lifecycle events; `warn` keeps only restarts, crashes,
and errors; `debug` adds internal diagnostics. Timestamps are **off by default**
— CloudWatch and journald already stamp each line — and turned on with
`--log-timestamps` for a bare `docker logs` with no collector in front.

Key events: `spawned` (info, every spawn/respawn, with the new pid), `restart`
(warn, with `reason`/`escalated`/`restarts`), `crash` (warn), `crash-loop`
(error). The `restarts=` field is the running count of restarts **completed so
far** (the same monotonic value on the `restart` and `crash-loop` lines). The
crash-loop give-up line and its webhook payload (see [Alerting](#alerting)) quote
that same number; an anomaly alert (memory/PSI) instead counts the in-progress
restart, so its `restart_count` reads one higher than the stderr `restarts=`.

## Guarantees & design notes

- **cgroup-accurate.** Reads `memory.current` / `memory.max` from the cgroup,
  auto-detecting v1/v2 — not host `/proc` stats.
- **Graceful first, forceful only if needed.** `SIGTERM` → grace → `SIGKILL`,
  signalling the whole target process group; a clean exit at the grace boundary
  is recognized and not mislabeled as a hang.
- **EINTR-safe reaping.** A transient interrupted `waitpid` is retried, so a
  clean exit is reliably observed and shutdown never stalls.
- **Crash-loop backoff.** Linear backoff; after `--max-failures` consecutive
  failed starts draug exits non-zero so PID 1 tears down the container and the
  orchestrator (e.g. ECS) restarts the task — the last-resort safety net.
- **Graceful degradation.** Missing cgroup files, an unreadable memory limit, or
  no PSI write access disable the relevant trigger (logged once) rather than
  crashing — the timer and heartbeat keep working. A PSI trigger that only
  becomes available after a slow startup is picked up automatically (bounded
  retry); a PSI fd that errors or hangs up at runtime disables PSI (until the
  next restart) instead of busy-looping.

## Development

- Pure / parser / POSIX tests (macOS or Linux): `cargo test`
- Full suite incl. the Linux-only supervisor + lifecycle matrix: `./scripts/test-linux.sh`
- Lint/format: `cargo fmt` and `cargo clippy --all-targets --features _test_support -- -D warnings`
