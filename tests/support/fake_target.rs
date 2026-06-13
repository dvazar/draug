//! Test-only helper binary: a configurable fake target the integration tests
//! supervise. Modes are selected via argv:
//!   --ignore-term               ignore SIGTERM (forces the SIGKILL escalation path)
//!   --exit-fast <code>          exit immediately with the given exit code
//!   --heartbeat <path>          touch a heartbeat file every 200 ms
//!   --stop-heartbeat-after <s>  stop touching after N seconds (drives stale-hb)
//!   --mark <path>               append this process's PID to a file on startup

use std::time::{Duration, Instant};

/// Runtime behavior selected from argv.
struct Opts {
    ignore_term: bool,
    exit_fast: Option<i32>,
    heartbeat: Option<String>,
    stop_heartbeat_after: Option<u64>,
    mark: Option<String>,
}

fn parse_opts() -> Opts {
    let mut o = Opts {
        ignore_term: false,
        exit_fast: None,
        heartbeat: None,
        stop_heartbeat_after: None,
        mark: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ignore-term" => o.ignore_term = true,
            "--exit-fast" => {
                o.exit_fast = Some(args.next().and_then(|c| c.parse().ok()).unwrap_or(1))
            }
            "--heartbeat" => o.heartbeat = args.next(),
            "--stop-heartbeat-after" => {
                o.stop_heartbeat_after = args.next().and_then(|c| c.parse().ok())
            }
            "--mark" => o.mark = args.next(),
            _ => {}
        }
    }
    o
}

/// Overwrite the file at `path` with a timestamp string, which also bumps its
/// mtime — sufficient for a heartbeat check.
fn touch(path: &str) {
    let _ = std::fs::write(path, format!("{:?}", Instant::now()));
}

fn main() {
    let o = parse_opts();

    // Append our PID to the mark file before anything else so that even an
    // --exit-fast run records the spawn.
    if let Some(path) = &o.mark {
        use std::fs::OpenOptions;
        use std::io::Write;
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", std::process::id());
        }
    }

    if let Some(code) = o.exit_fast {
        std::process::exit(code);
    }

    if o.ignore_term {
        // SAFETY: `signal(2)` is only well-defined in a single-threaded
        // process; at this point fake_target has spawned no threads, so
        // installing SIG_IGN here is sound. SIG_IGN itself is async-signal-safe.
        // Ignoring SIGTERM/SIGINT is the intended effect (forces the supervisor
        // to escalate to SIGKILL); SIGKILL cannot be caught and is left alone.
        unsafe {
            use nix::sys::signal::{SigHandler, Signal, signal};
            let _ = signal(Signal::SIGTERM, SigHandler::SigIgn);
            let _ = signal(Signal::SIGINT, SigHandler::SigIgn);
        }
    }

    let started = Instant::now();
    loop {
        if let Some(path) = &o.heartbeat {
            let stop = o
                .stop_heartbeat_after
                .is_some_and(|s| started.elapsed() >= Duration::from_secs(s));
            if !stop {
                touch(path);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
