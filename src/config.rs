//! Configuration: CLI flags (operational params) + environment (secrets,
//! endpoints, alert context). The target command follows `--`.
//!
//! Flags: --restart-interval, --mem-threshold, --psi-trigger,
//! --graceful-signal, --grace-period, --tick, --heartbeat-file,
//! --heartbeat-max-age, --startup-grace, --max-failures, --backoff,
//! --cgroup-root.
//!
//! Env: DRAUG_WEBHOOK_URL, SENTRY_DSN, DRAUG_SERVICE,
//! DRAUG_ENV, DRAUG_HEARTBEAT_FILE.
//!
//! Triggers are disabled individually: `--restart-interval 0` and
//! `--mem-threshold 0` turn those off, while `--psi-trigger ""` (empty string,
//! not `0`) disables PSI. One binary thus covers both "timer only" and
//! "timer + memory + PSI + heartbeat".

use std::path::PathBuf;
use std::time::Duration;

/// A PSI trigger threshold: `stall_us` microseconds of stall within a
/// `window_us` microsecond window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsiTrigger {
    pub stall_us: u64,
    pub window_us: u64,
}

/// Parse a human duration: bare number = seconds; suffixes `ms`, `s`, `m`, `h`.
/// `"0"` yields `Duration::ZERO` (callers treat zero as "disabled").
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (digits, mult_ms): (&str, u64) = if let Some(d) = s.strip_suffix("ms") {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('s') {
        (d, 1000)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60_000)
    } else if let Some(d) = s.strip_suffix('h') {
        (d, 3_600_000)
    } else {
        (s, 1000)
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    Ok(Duration::from_millis(value.saturating_mul(mult_ms)))
}

/// Parse a memory ratio in `[0.0, 1.0]`. `0` means "disabled" (handled by the
/// caller).
pub fn parse_ratio(s: &str) -> Result<f64, String> {
    let v: f64 = s
        .trim()
        .parse()
        .map_err(|_| format!("invalid ratio: {s}"))?;
    if !v.is_finite() {
        return Err(format!("invalid ratio (not a finite number): {s}"));
    }
    if !(0.0..=1.0).contains(&v) {
        return Err(format!("ratio out of range [0,1]: {s}"));
    }
    Ok(v)
}

/// Parse a `stall_us/window_us` PSI trigger. Empty string => `None` (disabled).
pub fn parse_psi_trigger(s: &str) -> Result<Option<PsiTrigger>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (stall, window) = s
        .split_once('/')
        .ok_or_else(|| format!("invalid psi trigger (want stall/window): {s}"))?;
    let stall_us: u64 = stall
        .trim()
        .parse()
        .map_err(|_| "invalid psi stall".to_string())?;
    if window.contains('/') {
        return Err(format!("invalid psi trigger (too many '/'): {s}"));
    }
    let window_us: u64 = window
        .trim()
        .parse()
        .map_err(|_| "invalid psi window".to_string())?;
    if window_us == 0 {
        return Err("psi window must be > 0".into());
    }
    if stall_us == 0 {
        return Err("psi stall must be > 0".into());
    }
    if stall_us > window_us {
        return Err(format!(
            "psi stall ({stall_us}us) must not exceed window ({window_us}us)"
        ));
    }
    Ok(Some(PsiTrigger {
        stall_us,
        window_us,
    }))
}

/// Which signal to send for a graceful stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GracefulSignal {
    Term,
    Int,
}

impl std::str::FromStr for GracefulSignal {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "TERM" | "SIGTERM" => Ok(GracefulSignal::Term),
            "INT" | "SIGINT" => Ok(GracefulSignal::Int),
            other => Err(format!("invalid graceful signal: {other}")),
        }
    }
}

/// Raw CLI flags as parsed by clap; converted to `Config` by `Config::build`.
#[derive(Debug, clap::Parser)]
#[command(name = "draug", about = "Graceful, cgroup-aware process supervisor")]
pub struct Cli {
    #[arg(long, default_value = "30m")]
    pub restart_interval: String,
    #[arg(long, default_value = "0.85")]
    pub mem_threshold: String,
    #[arg(long, default_value = "150000/1000000")]
    pub psi_trigger: String,
    #[arg(long, default_value = "TERM")]
    pub graceful_signal: String,
    #[arg(long, default_value = "90s")]
    pub grace_period: String,
    #[arg(long, default_value = "2s")]
    pub tick: String,
    #[arg(long)]
    pub heartbeat_file: Option<PathBuf>,
    #[arg(long, default_value = "60s")]
    pub heartbeat_max_age: String,
    #[arg(long, default_value = "15s")]
    pub startup_grace: String,
    #[arg(long, default_value_t = 3)]
    pub max_failures: u32,
    #[arg(long, default_value = "5s")]
    pub backoff: String,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup_root: PathBuf,
    /// Target command and its args, following `--`.
    #[arg(last = true)]
    pub target: Vec<String>,
}

/// Environment-sourced configuration (secrets, endpoints, alert context).
#[derive(Debug, Default, Clone)]
pub struct EnvVars {
    pub webhook_url: Option<String>,
    pub sentry_dsn: Option<String>,
    pub service: Option<String>,
    pub env: Option<String>,
    pub heartbeat_file: Option<String>,
}

impl EnvVars {
    /// Read the relevant variables from the process environment.
    pub fn from_process() -> EnvVars {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        EnvVars {
            webhook_url: get("DRAUG_WEBHOOK_URL"),
            sentry_dsn: get("SENTRY_DSN"),
            service: get("DRAUG_SERVICE"),
            env: get("DRAUG_ENV"),
            heartbeat_file: get("DRAUG_HEARTBEAT_FILE"),
        }
    }
}

/// Fully resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub restart_interval: Option<Duration>,
    pub mem_threshold: Option<f64>,
    pub psi_trigger: Option<PsiTrigger>,
    pub graceful_signal: GracefulSignal,
    pub grace_period: Duration,
    pub tick: Duration,
    pub heartbeat_file: Option<PathBuf>,
    pub heartbeat_max_age: Duration,
    pub startup_grace: Duration,
    pub max_failures: u32,
    pub backoff: Duration,
    pub cgroup_root: PathBuf,
    pub target: Vec<String>,
    pub webhook_url: Option<String>,
    pub sentry_dsn: Option<String>,
    pub service: Option<String>,
    pub env: Option<String>,
}

impl Config {
    /// Parse argv + environment into a `Config`, exiting the process on error.
    pub fn from_args() -> Config {
        let cli = <Cli as clap::Parser>::parse();
        match Config::build(cli, EnvVars::from_process()) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("draug: configuration error: {e}");
                std::process::exit(2);
            }
        }
    }

    /// Project the config onto the slice the decision core needs.
    pub fn decision_limits(&self) -> crate::decision::DecisionLimits {
        crate::decision::DecisionLimits {
            restart_interval: self.restart_interval,
            mem_threshold: self.mem_threshold,
            heartbeat_max_age: self.heartbeat_max_age,
            startup_grace: self.startup_grace,
        }
    }

    /// Convert parsed flags + env into a validated `Config`.
    pub fn build(cli: Cli, env: EnvVars) -> Result<Config, String> {
        if cli.target.is_empty() {
            return Err("no target command given (expected `-- <cmd> [args]`)".into());
        }
        let restart_interval = nonzero(parse_duration(&cli.restart_interval)?);
        let mem_ratio = parse_ratio(&cli.mem_threshold)?;
        let mem_threshold = (mem_ratio > 0.0).then_some(mem_ratio);
        let psi_trigger = parse_psi_trigger(&cli.psi_trigger)?;
        let heartbeat_file = cli
            .heartbeat_file
            .or_else(|| env.heartbeat_file.clone().map(PathBuf::from));
        let grace_period = parse_duration(&cli.grace_period)?;
        let tick = parse_duration(&cli.tick)?;
        let backoff = parse_duration(&cli.backoff)?;
        let startup_grace = parse_duration(&cli.startup_grace)?;
        let heartbeat_max_age = parse_duration(&cli.heartbeat_max_age)?;
        if tick.is_zero() {
            return Err("--tick must be greater than zero".into());
        }
        if grace_period.is_zero() {
            return Err("--grace-period must be greater than zero".into());
        }
        if backoff.is_zero() {
            return Err("--backoff must be greater than zero".into());
        }
        if cli.max_failures == 0 {
            return Err("--max-failures must be greater than zero".into());
        }
        if startup_grace.is_zero() {
            return Err(
                "--startup-grace must be greater than zero (zero disables crash-loop detection)"
                    .into(),
            );
        }
        // `heartbeat_max_age` only matters when a heartbeat file is configured;
        // a zero value there marks every real heartbeat (age > 0) stale.
        if heartbeat_file.is_some() && heartbeat_max_age.is_zero() {
            return Err(
                "--heartbeat-max-age must be greater than zero when --heartbeat-file is set".into(),
            );
        }
        Ok(Config {
            restart_interval,
            mem_threshold,
            psi_trigger,
            graceful_signal: cli.graceful_signal.parse()?,
            grace_period,
            tick,
            heartbeat_file,
            heartbeat_max_age,
            startup_grace,
            max_failures: cli.max_failures,
            backoff,
            cgroup_root: cli.cgroup_root,
            target: cli.target,
            webhook_url: env.webhook_url,
            sentry_dsn: env.sentry_dsn,
            service: env.service,
            env: env.env,
        })
    }
}

/// `None` if the duration is zero (a disabled trigger), else `Some`.
fn nonzero(d: Duration) -> Option<Duration> {
    (!d.is_zero()).then_some(d)
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn duration_units() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("5").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn duration_zero_is_zero() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
    }

    #[test]
    fn duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("-5s").is_err());
    }

    #[test]
    fn ratio_parsing() {
        assert_eq!(parse_ratio("0.85").unwrap(), 0.85);
        assert_eq!(parse_ratio("0").unwrap(), 0.0);
        assert_eq!(parse_ratio("1").unwrap(), 1.0);
    }

    #[test]
    fn ratio_rejects_out_of_range() {
        assert!(parse_ratio("-0.1").is_err());
        assert!(parse_ratio("1.5").is_err());
        assert!(parse_ratio("x").is_err());
        assert!(parse_ratio("NaN").is_err());
        assert!(parse_ratio("inf").is_err());
    }

    #[test]
    fn psi_trigger_parsing() {
        let t = parse_psi_trigger("150000/1000000").unwrap().unwrap();
        assert_eq!(t.stall_us, 150000);
        assert_eq!(t.window_us, 1000000);
        assert!(parse_psi_trigger("").unwrap().is_none());
        assert!(parse_psi_trigger("123").is_err());
        assert!(parse_psi_trigger("a/b").is_err());
        assert!(parse_psi_trigger("100/0").is_err());
        assert!(parse_psi_trigger("0/1000000").is_err());
        assert!(parse_psi_trigger("100/200/300").is_err());
        // Boundary: stall == window yields threshold_pct == 100.0 (max valid).
        assert!(parse_psi_trigger("1000000/1000000").unwrap().is_some());
        // stall > window is a silent dead zone (threshold_pct > 100); reject.
        assert!(parse_psi_trigger("2000000/1000000").is_err());
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use clap::Parser as _;
    use std::path::PathBuf;
    use std::time::Duration;

    fn empty_env() -> EnvVars {
        EnvVars::default()
    }

    #[test]
    fn defaults_and_target() {
        let cli = Cli::try_parse_from(["draug", "--", "echo", "hi"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.restart_interval, Some(Duration::from_secs(1800)));
        assert_eq!(cfg.mem_threshold, Some(0.85));
        assert_eq!(cfg.grace_period, Duration::from_secs(90));
        assert_eq!(cfg.tick, Duration::from_secs(2));
        assert_eq!(cfg.target, vec!["echo".to_string(), "hi".to_string()]);
        assert_eq!(cfg.cgroup_root, PathBuf::from("/sys/fs/cgroup"));
    }

    #[test]
    fn zero_disables_triggers() {
        let cli = Cli::try_parse_from([
            "draug",
            "--restart-interval",
            "0",
            "--mem-threshold",
            "0",
            "--psi-trigger",
            "",
            "--",
            "sleep",
            "1",
        ])
        .unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.restart_interval, None);
        assert_eq!(cfg.mem_threshold, None);
        assert_eq!(cfg.psi_trigger, None);
    }

    #[test]
    fn missing_target_is_error() {
        let cli = Cli::try_parse_from(["draug"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn heartbeat_flag_overrides_env() {
        let cli =
            Cli::try_parse_from(["draug", "--heartbeat-file", "/flag/hb", "--", "x"]).unwrap();
        let env = EnvVars {
            heartbeat_file: Some("/env/hb".into()),
            ..Default::default()
        };
        let cfg = Config::build(cli, env).unwrap();
        assert_eq!(cfg.heartbeat_file, Some(PathBuf::from("/flag/hb")));
    }

    #[test]
    fn heartbeat_from_env_when_flag_absent() {
        let cli = Cli::try_parse_from(["draug", "--", "x"]).unwrap();
        let env = EnvVars {
            heartbeat_file: Some("/env/hb".into()),
            ..Default::default()
        };
        let cfg = Config::build(cli, env).unwrap();
        assert_eq!(cfg.heartbeat_file, Some(PathBuf::from("/env/hb")));
    }

    #[test]
    fn graceful_signal_parsing() {
        // Explicit INT
        let cli = Cli::try_parse_from(["draug", "--graceful-signal", "INT", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.graceful_signal, GracefulSignal::Int);

        // Default (no --graceful-signal) resolves to TERM
        let cli = Cli::try_parse_from(["draug", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.graceful_signal, GracefulSignal::Term);

        // "SIGTERM" resolves to TERM
        let cli =
            Cli::try_parse_from(["draug", "--graceful-signal", "SIGTERM", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.graceful_signal, GracefulSignal::Term);

        // Lowercase "int" is accepted (case-insensitive)
        let cli = Cli::try_parse_from(["draug", "--graceful-signal", "int", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.graceful_signal, GracefulSignal::Int);
    }

    #[test]
    fn graceful_signal_invalid_is_error() {
        let cli =
            Cli::try_parse_from(["draug", "--graceful-signal", "SIGKILL", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn zero_tick_is_error() {
        let cli = Cli::try_parse_from(["draug", "--tick", "0", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn zero_grace_period_is_error() {
        let cli = Cli::try_parse_from(["draug", "--grace-period", "0", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn zero_backoff_is_error() {
        let cli = Cli::try_parse_from(["draug", "--backoff", "0", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn zero_max_failures_is_error() {
        let cli = Cli::try_parse_from(["draug", "--max-failures", "0", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn zero_startup_grace_is_error() {
        // `--startup-grace 0` makes `healthy = lived >= 0` always true, so the
        // crash streak never accumulates and `--max-failures` never trips.
        let cli = Cli::try_parse_from(["draug", "--startup-grace", "0", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn positive_startup_grace_ok() {
        let cli = Cli::try_parse_from(["draug", "--startup-grace", "1s", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.startup_grace, Duration::from_secs(1));
    }

    #[test]
    fn zero_heartbeat_max_age_with_heartbeat_is_error() {
        // With a heartbeat file configured, `--heartbeat-max-age 0` marks every
        // real heartbeat (age > 0) as stale, restarting a healthy target.
        let cli = Cli::try_parse_from([
            "draug",
            "--heartbeat-file",
            "/tmp/hb",
            "--heartbeat-max-age",
            "0",
            "--",
            "x",
        ])
        .unwrap();
        assert!(Config::build(cli, empty_env()).is_err());
    }

    #[test]
    fn positive_heartbeat_max_age_with_heartbeat_ok() {
        let cli = Cli::try_parse_from([
            "draug",
            "--heartbeat-file",
            "/tmp/hb",
            "--heartbeat-max-age",
            "1s",
            "--",
            "x",
        ])
        .unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.heartbeat_max_age, Duration::from_secs(1));
    }

    #[test]
    fn zero_heartbeat_max_age_without_heartbeat_ok() {
        // Heartbeat monitoring is OFF (no file), so `heartbeat_max_age` is inert
        // and a zero value must not raise a spurious error.
        let cli = Cli::try_parse_from(["draug", "--heartbeat-max-age", "0", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.heartbeat_max_age, Duration::ZERO);
        assert_eq!(cfg.heartbeat_file, None);
    }

    #[test]
    fn default_max_failures_is_three() {
        let cli = Cli::try_parse_from(["draug", "--", "x"]).unwrap();
        let cfg = Config::build(cli, empty_env()).unwrap();
        assert_eq!(cfg.max_failures, 3);
    }

    #[test]
    fn positive_operational_intervals_ok() {
        // sanity: the defaults (tick 2s, grace 90s, backoff 5s) still build
        let cli = Cli::try_parse_from(["draug", "--", "x"]).unwrap();
        assert!(Config::build(cli, empty_env()).is_ok());
    }
}
