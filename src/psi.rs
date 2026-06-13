//! PSI (Pressure Stall Information) watcher for memory pressure.
//!
//! Opens `memory.pressure` (cgroup v2) or `/proc/pressure/memory` (system-wide
//! fallback), writes a trigger (`some <stall_us> <window_us>`), and exposes a
//! raw fd that becomes EPOLLPRI-ready when pressure crosses the threshold —
//! event-driven, no polling race.
//!
//! Capability detection picks one of: Event (trigger armed), Poll (parse the
//! `some`/`full` averages on each tick), or Unavailable (rely on the
//! `memory.current` threshold only).

use crate::config::PsiTrigger;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Parsed PSI averages from `memory.pressure`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsiAverages {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
}

/// How we watch PSI, in capability order.
pub enum PsiHandle {
    /// Trigger armed; the fd becomes EPOLLPRI-ready on threshold crossing.
    Event(OwnedFd),
    /// Readable but no trigger; poll the averages each tick.
    Poll(PathBuf),
    /// No PSI support; rely on the memory threshold only.
    Unavailable,
}

fn parse_avg(token: &str, key: &str) -> Option<f64> {
    // `f64::from_str` accepts inf/-inf/nan (case-insensitive). Reject non-finite
    // values so a bogus reading cannot force the poll trigger every tick,
    // mirroring `config::parse_ratio`'s finiteness guard.
    let v: f64 = token.strip_prefix(key)?.parse().ok()?;
    v.is_finite().then_some(v)
}

/// Parse a `memory.pressure` block (`some`/`full` lines). Returns `None` for an
/// empty or malformed file.
pub fn parse_pressure(text: &str) -> Option<PsiAverages> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(kind) = it.next() else { continue };
        let (Some(t10), Some(t60), Some(t300)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Some(a10), Some(a60), Some(a300)) = (
            parse_avg(t10, "avg10="),
            parse_avg(t60, "avg60="),
            parse_avg(t300, "avg300="),
        ) else {
            continue;
        };
        match kind {
            "some" => some = Some((a10, a60, a300)),
            "full" => full = Some((a10, a60, a300)),
            _ => {}
        }
    }
    let some = some?;
    let full = full.unwrap_or((0.0, 0.0, 0.0));
    Some(PsiAverages {
        some_avg10: some.0,
        some_avg60: some.1,
        some_avg300: some.2,
        full_avg10: full.0,
        full_avg60: full.1,
        full_avg300: full.2,
    })
}

/// Poll-mode pressure check: read `path`, parse it, and report whether the
/// `some avg10` figure has reached the trigger's effective threshold.
///
/// This is an *approximation* of the kernel's event trigger. An armed trigger
/// (Event mode) fires when `stall_us` microseconds of stall accumulate within a
/// sliding `window_us` window — a precise, edge-driven measurement the kernel
/// delivers via EPOLLPRI. Poll mode has no such trigger, so we compare the
/// coarse `some avg10` percentage (the share of the last 10s spent stalled)
/// against the equivalent ratio `100 * stall_us / window_us` (e.g.
/// 150000/1000000 -> 15.0%). avg10 smooths over a fixed 10s window rather than
/// the configured one, so the two are not identical, but avg10 is the best
/// signal available without a trigger.
///
/// Any read or parse failure yields `false` (fail safe): a missed PSI restart
/// is preferable to a false one, matching the project's existing philosophy
/// (see the `mem_ratio` NaN handling in `decision.rs`).
pub fn poll_triggered(path: &Path, trigger: &PsiTrigger) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Some(avgs) = parse_pressure(&text) else {
        return false;
    };
    let threshold_pct = 100.0 * (trigger.stall_us as f64) / (trigger.window_us as f64);
    avgs.some_avg10 >= threshold_pct
}

/// Open `memory.pressure` under `root` and arm a trigger; fall back to polling
/// or unavailable per the capability ladder.
pub fn open(root: &Path, trigger: &PsiTrigger) -> PsiHandle {
    let path = root.join("memory.pressure");
    if !path.exists() {
        return PsiHandle::Unavailable;
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
    {
        Ok(mut file) => {
            let cmd = format!("some {} {}", trigger.stall_us, trigger.window_us);
            match file.write_all(cmd.as_bytes()) {
                Ok(()) => PsiHandle::Event(OwnedFd::from(file)),
                Err(_) => PsiHandle::Poll(path),
            }
        }
        Err(_) => {
            if std::fs::File::open(&path).is_ok() {
                PsiHandle::Poll(path)
            } else {
                PsiHandle::Unavailable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PsiTrigger;
    use tempfile::tempdir;

    #[test]
    fn parse_full_pressure_block() {
        let text = "some avg10=0.50 avg60=0.10 avg300=0.00 total=12345\n\
                    full avg10=0.20 avg60=0.05 avg300=0.00 total=678\n";
        let p = parse_pressure(text).unwrap();
        assert_eq!(p.some_avg10, 0.50);
        assert_eq!(p.some_avg60, 0.10);
        assert_eq!(p.full_avg10, 0.20);
    }

    #[test]
    fn parse_rejects_empty_or_garbage() {
        assert!(parse_pressure("").is_none());
        assert!(parse_pressure("garbage line\n").is_none());
    }

    #[test]
    fn trailing_blank_line_still_parses() {
        let text = "some avg10=0.50 avg60=0.10 avg300=0.00 total=12345\n\n";
        let p = parse_pressure(text).unwrap();
        assert_eq!(p.some_avg10, 0.50);
    }

    #[test]
    fn parse_avg_rejects_non_finite() {
        // Rust's `f64::from_str` accepts inf/-inf/nan (case-insensitive); a
        // non-finite PSI average must be treated as unparseable, mirroring
        // `config::parse_ratio`.
        assert_eq!(parse_avg("avg10=inf", "avg10="), None);
        assert_eq!(parse_avg("avg10=-inf", "avg10="), None);
        assert_eq!(parse_avg("avg10=infinity", "avg10="), None);
        assert_eq!(parse_avg("avg10=nan", "avg10="), None);
        assert_eq!(parse_avg("avg10=NaN", "avg10="), None);
    }

    #[test]
    fn parse_avg_accepts_finite() {
        assert_eq!(parse_avg("avg10=12.34", "avg10="), Some(12.34));
        assert_eq!(parse_avg("avg10=0.00", "avg10="), Some(0.0));
        assert_eq!(parse_avg("avg10=100.00", "avg10="), Some(100.0));
    }

    #[test]
    fn parse_pressure_non_finite_some_avg10_does_not_parse() {
        // A non-finite `some avg10` makes the `some` line unparseable, so the
        // whole block is rejected (None) rather than yielding INFINITY.
        let text = "some avg10=inf avg60=0.00 avg300=0.00 total=0\n\
                    full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert!(parse_pressure(text).is_none());
    }

    #[test]
    fn poll_non_finite_some_avg10_is_false() {
        // The realistic exploit: a non-kernel file yielding `avg10=inf` must not
        // force the trigger on every poll. Fail safe to `false`.
        let (_d, path) = write_pressure("inf");
        assert!(!poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn parse_some_only_defaults_full_to_zero() {
        let text = "some avg10=1.50 avg60=0.30 avg300=0.10 total=999\n";
        let p = parse_pressure(text).unwrap();
        assert_eq!(p.some_avg10, 1.50);
        assert_eq!(p.full_avg10, 0.0);
        assert_eq!(p.full_avg60, 0.0);
        assert_eq!(p.full_avg300, 0.0);
    }

    #[test]
    fn open_missing_file_is_unavailable() {
        let d = tempdir().unwrap();
        let trig = PsiTrigger {
            stall_us: 150000,
            window_us: 1000000,
        };
        assert!(matches!(open(d.path(), &trig), PsiHandle::Unavailable));
    }

    /// 150000/1000000 => a 15.0% effective threshold.
    fn trig_15pct() -> PsiTrigger {
        PsiTrigger {
            stall_us: 150000,
            window_us: 1000000,
        }
    }

    fn write_pressure(some_avg10: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempdir().unwrap();
        let path = d.path().join("memory.pressure");
        let text = format!(
            "some avg10={some_avg10} avg60=0.00 avg300=0.00 total=0\n\
             full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        );
        std::fs::write(&path, text).unwrap();
        (d, path)
    }

    #[test]
    fn poll_above_threshold_is_true() {
        let (_d, path) = write_pressure("42.00");
        assert!(poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_below_threshold_is_false() {
        let (_d, path) = write_pressure("5.00");
        assert!(!poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_exactly_at_threshold_is_true() {
        // `>=` boundary: avg10 == threshold (15.0%) must trigger.
        let (_d, path) = write_pressure("15.0");
        assert!(poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_just_above_threshold_is_true() {
        let (_d, path) = write_pressure("15.1");
        assert!(poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_just_below_threshold_is_false() {
        let (_d, path) = write_pressure("14.9");
        assert!(!poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_malformed_file_is_false() {
        let d = tempdir().unwrap();
        let path = d.path().join("memory.pressure");
        std::fs::write(&path, "garbage line\n").unwrap();
        assert!(!poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_empty_file_is_false() {
        let d = tempdir().unwrap();
        let path = d.path().join("memory.pressure");
        std::fs::write(&path, "").unwrap();
        assert!(!poll_triggered(&path, &trig_15pct()));
    }

    #[test]
    fn poll_nonexistent_path_is_false() {
        let d = tempdir().unwrap();
        let path = d.path().join("does-not-exist");
        assert!(!poll_triggered(&path, &trig_15pct()));
    }
}
