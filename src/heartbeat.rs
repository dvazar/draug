//! Heartbeat watcher — detects a target that is alive but stuck.
//!
//! Contract is intentionally minimal: the target periodically updates the
//! file's mtime (a plain touch/rewrite); the supervisor computes
//! `age = now - mtime` and treats `age > max_age` (after startup grace) as
//! stale. File *contents* are ignored, which is sturdier than parsing a
//! timestamp. The same path is shared with the target via
//! `DRAUG_HEARTBEAT_FILE`.
//!
//! # Clock dependence (wall-clock, not monotonic)
//!
//! Age is computed as `now - mtime` using the wall clock (`SystemTime`),
//! because a file's mtime is itself a wall-clock value and there is no
//! monotonic alternative for a timestamp written by an external process.
//! This means heartbeat staleness is sensitive to clock adjustments:
//!   * A **forward** clock/NTP step inflates the computed age, so a perfectly
//!     fresh heartbeat can momentarily look stale and trigger a spurious
//!     `HeartbeatStale` restart on the next tick.
//!   * A **backward** clock step makes the mtime appear to be in the future;
//!     `duration_since` then errors and we clamp the age to zero. This is the
//!     safe direction (no false restart) but it masks genuine staleness until
//!     the clock catches up.
//!
//! This coupling is inherent to mtime-based liveness and is not worked around
//! with heuristics; large clock jumps are assumed to be rare on a healthy host.
//!
//! # Missing vs. Unreadable
//!
//! We distinguish a genuinely absent file from one we merely cannot inspect.
//! A `NotFound` error means the target has not created its heartbeat yet, which
//! is legitimately treated as stale once past the startup grace. Any *other*
//! `metadata`/`modified` error (permission/ownership mismatch, `ENOTDIR`, or a
//! transient IO failure) means "we cannot tell" — reporting that as `Missing`
//! would force an endless restart loop of a healthy target, so it maps to
//! `Unreadable` and the decision core treats it as "no signal".

use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Result of inspecting the heartbeat file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAge {
    /// File does not exist (a true `NotFound`): the target has not started its
    /// heartbeat yet.
    Missing,
    /// The file exists (or its absence could not be confirmed) but its metadata
    /// could not be read — e.g. a permission/ownership mismatch, `ENOTDIR`, or a
    /// transient IO error. We cannot tell the age, so this must NOT force a
    /// restart.
    Unreadable,
    /// Time since the file's mtime; a future mtime (clock skew) clamps to zero.
    Age(Duration),
}

/// Compute the heartbeat age from the file's mtime relative to `now`.
///
/// A `NotFound` error yields [`HeartbeatAge::Missing`]; any other
/// `metadata`/`modified` error yields [`HeartbeatAge::Unreadable`]. See the
/// module docs for the wall-clock dependence of the returned age.
pub fn heartbeat_age(path: &Path, now: SystemTime) -> HeartbeatAge {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => match now.duration_since(mtime) {
            Ok(age) => HeartbeatAge::Age(age),
            Err(_) => HeartbeatAge::Age(Duration::ZERO),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => HeartbeatAge::Missing,
        Err(_) => HeartbeatAge::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    #[test]
    fn missing_file_is_missing() {
        let d = tempdir().unwrap();
        let p = d.path().join("hb");
        assert!(matches!(
            heartbeat_age(&p, SystemTime::now()),
            HeartbeatAge::Missing
        ));
    }

    #[test]
    fn present_but_unreadable_is_not_missing() {
        // Produce a non-`NotFound` metadata error deterministically and
        // independently of the running uid: create a regular file `f`, then
        // query a path whose parent component IS that file. The OS must
        // resolve through `f` as a directory, fails with `ENOTDIR`, and that
        // error kind is NOT `NotFound`. (Avoids `chmod 0000`, which root —
        // the Docker test uid — bypasses, making such a test env-dependent.)
        let d = tempdir().unwrap();
        let f = d.path().join("f");
        fs::write(&f, b"").unwrap();
        let p = f.join("hb");
        let got = heartbeat_age(&p, SystemTime::now());
        assert_eq!(
            got,
            HeartbeatAge::Unreadable,
            "a non-NotFound metadata error must be Unreadable, not Missing"
        );
    }

    #[test]
    fn fresh_file_has_small_age() {
        let d = tempdir().unwrap();
        let p = d.path().join("hb");
        fs::write(&p, b"").unwrap();
        match heartbeat_age(&p, SystemTime::now()) {
            HeartbeatAge::Age(a) => assert!(a < Duration::from_secs(5)),
            other => panic!("should exist: {other:?}"),
        }
    }

    #[test]
    fn future_mtime_clamps_to_zero() {
        let d = tempdir().unwrap();
        let p = d.path().join("hb");
        fs::write(&p, b"").unwrap();
        let past = SystemTime::now() - Duration::from_secs(3600);
        // `now` in the past relative to mtime => negative age => Fresh (zero).
        assert!(matches!(heartbeat_age(&p, past), HeartbeatAge::Age(a) if a.is_zero()));
    }

    #[test]
    fn known_offset_yields_exact_age() {
        let d = tempdir().unwrap();
        let p = d.path().join("hb");
        fs::write(&p, b"").unwrap();
        let mtime = fs::metadata(&p).unwrap().modified().unwrap();
        let now = mtime + Duration::from_secs(100);
        match heartbeat_age(&p, now) {
            HeartbeatAge::Age(a) => assert_eq!(a, Duration::from_secs(100)),
            other => panic!("file should exist: {other:?}"),
        }
    }
}
