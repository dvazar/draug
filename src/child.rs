//! Target process lifecycle: spawn, signal, and reap.
//!
//! The target is started in its own process group (`setpgid`) so the
//! supervisor can signal the whole tree via `kill(-pgid, sig)`. Provides the
//! graceful signal (SIGTERM/SIGINT), the SIGKILL escalation, and `waitpid`
//! reaping of *only* the direct child — grandchildren are reparented to and
//! reaped by tini (PID 1). Races (`ESRCH` when the child is already dead) are
//! treated as a successful reap.

use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, setpgid};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child as StdChild, Command, ExitStatus};

/// A supervised target process running in its own process group.
pub struct Child {
    inner: StdChild,
    pid: Pid,
}

impl Child {
    pub fn pid(&self) -> Pid {
        self.pid
    }
    /// The process group id (equals the child pid; `setpgid(0,0)` was called).
    pub fn pgid(&self) -> Pid {
        self.pid
    }
}

/// Spawn `cmd` (argv) in a fresh process group, injecting `extra_env`.
pub fn spawn(cmd: &[String], extra_env: &[(String, String)]) -> io::Result<Child> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty target command",
        ));
    }
    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (k, v) in extra_env {
        command.env(k, v);
    }
    // SAFETY: the closure runs in the forked child, after fork() and before
    // exec(). Only async-signal-safe operations are permitted in that window.
    // `setpgid` and `sigprocmask` are async-signal-safe (POSIX.1-2017 §2.4.3).
    // `SigSet` is a stack-only `sigset_t`, and `io::Error::from_raw_os_error`
    // stores only an i32 — no heap allocation occurs before exec(). The closure
    // captures nothing from the heap.
    unsafe {
        command.pre_exec(|| {
            setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            // Reset the signal mask inherited from the supervisor, which blocks
            // SIGTERM/SIGINT/SIGCHLD to drive its signalfd. Without this the
            // target would start with the graceful-stop signal blocked and could
            // only be stopped via SIGKILL — defeating graceful shutdown.
            nix::sys::signal::sigprocmask(
                nix::sys::signal::SigmaskHow::SIG_SETMASK,
                Some(&nix::sys::signal::SigSet::empty()),
                None,
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            Ok(())
        });
    }
    let inner = command.spawn()?;
    let pid = Pid::from_raw(inner.id() as i32);
    Ok(Child { inner, pid })
}

/// Send `sig` to the whole target process group. `ESRCH` (already dead) is OK.
pub fn signal_group(child: &Child, sig: Signal) -> nix::Result<()> {
    match killpg(child.pgid(), sig) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Non-blocking reap. `Ok(Some(status))` if exited, `Ok(None)` if still running.
pub fn try_reap(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    child.inner.try_wait()
}

/// Blocking reap (used in tests and final shutdown). Uses `nix::waitpid`
/// because `std::process::Child::wait` requires `&mut Child`, which is
/// inconvenient for callers (tests) that hold a shared `&Child`. The
/// supervisor's hot path uses `try_reap` instead.
pub fn wait_blocking(child: &Child) -> io::Result<ExitStatus> {
    use nix::sys::wait::{WaitStatus, waitpid};
    loop {
        match waitpid(child.pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                return Ok(exit_status_from_code(code));
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                return Ok(exit_status_signaled(sig));
            }
            Ok(_) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                // Already reaped (e.g. by std Child) — synthesize success.
                return Ok(exit_status_from_code(0));
            }
            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
}

fn exit_status_from_code(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw((code & 0xff) << 8)
}

fn exit_status_signaled(sig: Signal) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    // A wait status terminated by signal N has N in the low 7 bits and is not
    // WIFEXITED, so `code()` is None and `signal()` reports the real signal.
    ExitStatus::from_raw(sig as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_sets_pgid_to_pid() {
        let child = spawn(&["sleep".into(), "30".into()], &[]).unwrap();
        // The child runs setpgid(0,0) in pre_exec; poll until the kernel
        // reports its process group equals its pid (own group leader).
        let mut observed = None;
        for _ in 0..100 {
            if let Ok(pg) = nix::unistd::getpgid(Some(child.pid()))
                && pg == child.pid()
            {
                observed = Some(pg);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            observed,
            Some(child.pid()),
            "child should lead its own process group"
        );
        signal_group(&child, nix::sys::signal::Signal::SIGKILL).unwrap();
        let _ = wait_blocking(&child);
    }

    #[test]
    fn signal_group_reaps_after_term() {
        let child = spawn(&["sleep".into(), "30".into()], &[]).unwrap();
        signal_group(&child, nix::sys::signal::Signal::SIGTERM).unwrap();
        let status = wait_blocking(&child).unwrap();
        // terminated by signal, not a clean exit
        assert!(status.code().is_none());
    }

    #[test]
    fn signal_already_dead_is_ok() {
        let child = spawn(&["true".into()], &[]).unwrap();
        // Reap first so the process (and its group) are definitively gone.
        let _ = wait_blocking(&child);
        // Signalling a vanished group must map ESRCH to Ok, not error.
        signal_group(&child, nix::sys::signal::Signal::SIGTERM).unwrap();
    }

    #[test]
    fn spawn_missing_binary_errors() {
        assert!(spawn(&["/no/such/binary/xyz".into()], &[]).is_err());
    }

    #[test]
    fn extra_env_is_passed() {
        // `sh -c 'test "$FOO" = bar'` exits 0 only when FOO=bar was injected.
        let child = spawn(
            &["sh".into(), "-c".into(), "test \"$FOO\" = bar".into()],
            &[("FOO".into(), "bar".into())],
        )
        .unwrap();
        let status = wait_blocking(&child).unwrap();
        assert_eq!(status.code(), Some(0));
    }
}
