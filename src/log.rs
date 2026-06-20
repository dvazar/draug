//! Structured stderr logging for draug's lifecycle and operational events.
//!
//! One event per line, logfmt (`key=value`) so log collectors (CloudWatch
//! Logs Insights, Loki) parse it without a custom pattern while a human can
//! still read it in `docker logs`:
//!
//! ```text
//! draug: level=info event=spawned target="<command> [args...]" pid=1234 heartbeat=/run/draug/hb
//! draug: level=warn event=restart target="..." pid=1234 reason=HeartbeatStale escalated=false restarts=3
//! ```
//!
//! A single [`Logger`] (built from `Config`) gates every line by a configurable
//! minimum level (`--log-level`, default `info`) and optionally prefixes an
//! RFC3339 UTC timestamp (`--log-timestamps`, off by default because collectors
//! such as CloudWatch and journald already stamp each line and a second
//! timestamp is just noise).

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Severity of a log line. Declared most-severe -> most-verbose, so the derived
/// `Ord` makes `error < warn < info < debug`: a line is emitted when its level
/// is at or below the configured threshold (see [`enabled`]). Thus
/// `--log-level info` shows error/warn/info but hides debug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    /// The lowercase token used in the `level=` field and accepted on the CLI.
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

impl FromStr for LogLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            other => Err(format!(
                "invalid log level: {other} (want error|warn|info|debug)"
            )),
        }
    }
}

/// Whether a line at `line` severity is emitted under `threshold`. Pure so the
/// whole gating policy is table-testable.
pub fn enabled(line: LogLevel, threshold: LogLevel) -> bool {
    line <= threshold
}

/// Emits gated, formatted event lines to stderr. Cheap to copy (a level + a
/// bool) so it can be passed by value to log call sites and across threads.
#[derive(Debug, Clone, Copy)]
pub struct Logger {
    min: LogLevel,
    timestamps: bool,
}

impl Logger {
    pub fn new(min: LogLevel, timestamps: bool) -> Logger {
        Logger { min, timestamps }
    }

    /// Emit one event line if `level` passes the threshold. `body` is the
    /// logfmt payload that follows the `level=` field, e.g.
    /// `event=spawned target="x" pid=1`.
    pub fn log(&self, level: LogLevel, body: &str) {
        if !enabled(level, self.min) {
            return;
        }
        let line = format!("draug: level={} {body}", level.label());
        if self.timestamps {
            eprintln!("{} {line}", now_rfc3339());
        } else {
            eprintln!("{line}");
        }
    }
}

/// Current wall-clock time as RFC3339 UTC. A pre-1970 clock (`Err`) is clamped
/// to the epoch rather than panicking -- a timestamp is a log nicety, never
/// worth aborting a restart over.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

/// Format Unix epoch seconds as RFC3339 UTC (`YYYY-MM-DDThh:mm:ssZ`). Pure and
/// table-testable; converts the day count with Howard Hinnant's civil-from-days
/// algorithm so draug carries no date/time dependency.
pub fn format_rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let sod = unix_secs % 86_400;
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let (y, mon, d) = civil_from_days(days);
    format!("{y:04}-{mon:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's `days -> (year, month, day)` for the proleptic Gregorian
/// calendar; `z` is days since 1970-01-01. Correct across leap years and
/// century boundaries.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_parses_case_insensitively_with_aliases() {
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("WARN".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("warning".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("  Info ".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
    }

    #[test]
    fn log_level_rejects_unknown() {
        assert!("trace".parse::<LogLevel>().is_err());
        assert!("".parse::<LogLevel>().is_err());
        assert!("3".parse::<LogLevel>().is_err());
    }

    #[test]
    fn label_roundtrips_through_parse() {
        for lvl in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
        ] {
            assert_eq!(lvl.label().parse::<LogLevel>().unwrap(), lvl);
        }
    }

    // The whole point of levels: the `--log-level` threshold must gate emission.
    // Exhaustive 4x4 matrix so no off-by-one in the ordering slips through.
    #[test]
    fn enabled_matrix_is_at_or_below_threshold() {
        use LogLevel::*;
        let order = [Error, Warn, Info, Debug];
        for (ti, &threshold) in order.iter().enumerate() {
            for (li, &line) in order.iter().enumerate() {
                // A line shows iff it is at least as severe as the threshold,
                // i.e. its index <= the threshold's index.
                assert_eq!(
                    enabled(line, threshold),
                    li <= ti,
                    "line={line:?} threshold={threshold:?}"
                );
            }
        }
        // Spot-check the documented behavior at the default threshold.
        assert!(enabled(Error, Info));
        assert!(enabled(Warn, Info));
        assert!(enabled(Info, Info));
        assert!(!enabled(Debug, Info));
        // At warn, routine info (e.g. `spawned`) is suppressed.
        assert!(!enabled(Info, Warn));
    }

    #[test]
    fn rfc3339_epoch_and_day_boundaries() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(format_rfc3339_utc(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn rfc3339_handles_leap_years_and_centuries() {
        // 2020-01-01, 2020-02-29 (leap day), 2020-03-01, 2021-01-01.
        assert_eq!(format_rfc3339_utc(1_577_836_800), "2020-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_582_934_400), "2020-02-29T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_583_020_800), "2020-03-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_609_459_200), "2021-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_formats_intraday_time() {
        // 2026-06-20T17:45:47Z (the dev01 incident window from the logs).
        assert_eq!(format_rfc3339_utc(1_781_977_547), "2026-06-20T17:45:47Z");
    }
}
