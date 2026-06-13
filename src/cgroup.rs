//! cgroup reader: auto-detects cgroup v2 vs v1 and reads memory and CPU usage
//! relative to the container's limits — the source of truth the kernel OOM
//! killer actually uses.
//!
//! v2: `memory.current`, `memory.max`, `memory.events`, `cpu.max`.
//! v1: `memory.usage_in_bytes`, `memory.limit_in_bytes`, `cpu.cfs_quota_us` /
//!     `cpu.cfs_period_us`.
//!
//! Usage is read from `memory.current` (NOT process RSS) so the percentage
//! matches what triggers the OOM killer, including page cache.
//! The cgroup root is injectable (`--cgroup-root`) so tests can point at a
//! tempdir of fixture files.

use std::io;
use std::path::{Path, PathBuf};

/// cgroup hierarchy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
}

/// Resolved cgroup root + detected version.
#[derive(Debug, Clone)]
pub struct CgroupPaths {
    pub version: CgroupVersion,
    pub root: PathBuf,
}

impl CgroupPaths {
    /// Detect the version at `root` and capture both.
    pub fn resolve(root: &Path) -> CgroupPaths {
        CgroupPaths {
            version: detect(root),
            root: root.to_path_buf(),
        }
    }
}

/// v2 if `cgroup.controllers` exists under `root`, else v1.
pub fn detect(root: &Path) -> CgroupVersion {
    if root.join("cgroup.controllers").exists() {
        CgroupVersion::V2
    } else {
        CgroupVersion::V1
    }
}

/// A memory usage sample relative to the limit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemorySample {
    pub current: u64,
    pub max: Option<u64>,
}

impl MemorySample {
    /// `current / max`, or `None` when there is no limit.
    ///
    /// A zero limit (`memory.max == 0`, a real writable cgroup-v2 state) is the
    /// maximally-constrained case: any usage is over the limit and the kernel
    /// OOM killer is imminent. Returning `0.0` there would silently kill the
    /// Memory trigger exactly when it must fire, so report `+inf` instead — it
    /// is `>= any finite threshold` yet is not NaN, keeping the `ratio >=
    /// threshold` comparison in `decision::evaluate` well-defined. With zero
    /// usage nothing is over the limit, so the ratio is `0.0`.
    pub fn ratio(&self) -> Option<f64> {
        self.max.map(|m| {
            if m == 0 {
                if self.current > 0 { f64::INFINITY } else { 0.0 }
            } else {
                self.current as f64 / m as f64
            }
        })
    }
}

/// cgroup v1 `memory.limit_in_bytes` uses a page-aligned i64::MAX sentinel for
/// "unlimited"; anything at/above it means no limit.
const V1_UNLIMITED_SENTINEL: u64 = 0x7FFF_FFFF_FFFF_F000;

/// Parse cgroup v2 `memory.max`: `"max"` => unlimited, else a byte count.
pub fn parse_mem_max_v2(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "max" { None } else { s.parse().ok() }
}

/// Map a cgroup v1 `memory.limit_in_bytes` value to an optional limit.
pub fn v1_limit_to_max(raw: u64) -> Option<u64> {
    if raw >= V1_UNLIMITED_SENTINEL {
        None
    } else {
        Some(raw)
    }
}

fn read_u64(path: &Path) -> io::Result<u64> {
    let text = std::fs::read_to_string(path)?;
    text.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("non-integer in {path:?}"),
        )
    })
}

/// Read just the current memory usage: `memory.current` (v2) /
/// `memory.usage_in_bytes` (v1). This is the only value that changes per tick.
pub fn read_memory_current(p: &CgroupPaths) -> io::Result<u64> {
    let file = match p.version {
        CgroupVersion::V2 => "memory.current",
        CgroupVersion::V1 => "memory.usage_in_bytes",
    };
    read_u64(&p.root.join(file))
}

/// Read the memory limit once: `memory.max` (v2) / `memory.limit_in_bytes`
/// (v1), mapped to `None` when unlimited. The limit is fixed for the
/// container's lifetime, so callers cache this at startup rather than re-read
/// it every tick.
pub fn read_memory_max(p: &CgroupPaths) -> io::Result<Option<u64>> {
    match p.version {
        CgroupVersion::V2 => {
            let max_raw = std::fs::read_to_string(p.root.join("memory.max"))?;
            Ok(parse_mem_max_v2(&max_raw))
        }
        CgroupVersion::V1 => {
            let limit = read_u64(&p.root.join("memory.limit_in_bytes"))?;
            Ok(v1_limit_to_max(limit))
        }
    }
}

/// Parse cgroup v2 `cpu.max` (`"<quota|max> <period>"`) into a quota ratio.
///
/// Returns `None` when the cgroup is uncapped (`"max"`) or the values are not a
/// valid positive quota/period pair. A conformant kernel never writes negative
/// or zero values here, but we guard against them anyway so the v2 path matches
/// `v1_cpu_quota_ratio`'s contract instead of emitting a sign-flipped ratio.
pub fn parse_cpu_max_v2(s: &str) -> Option<f64> {
    let mut it = s.split_whitespace();
    let quota = it.next()?;
    let period: f64 = it.next()?.parse().ok()?;
    if quota == "max" {
        return None;
    }
    let quota: f64 = quota.parse().ok()?;
    if quota < 0.0 || period <= 0.0 {
        return None;
    }
    Some(quota / period)
}

/// cgroup v1 quota ratio: `cfs_quota_us` of `-1` means uncapped.
pub fn v1_cpu_quota_ratio(quota_us: i64, period_us: i64) -> Option<f64> {
    if quota_us < 0 || period_us <= 0 {
        None
    } else {
        Some(quota_us as f64 / period_us as f64)
    }
}

/// Read the cgroup CPU QUOTA ratio (`quota / period`, the configured CPU
/// ceiling), reading `cpu.max` (v2) or `cpu.cfs_quota_us` / `cpu.cfs_period_us`
/// (v1). Returns `None` when the cgroup is uncapped or the values are
/// missing/unreadable — this is a static configured ceiling, NOT live CPU
/// utilization. An unreadable file degrades to `None` so it never crashes the
/// snapshot.
pub fn read_cpu(p: &CgroupPaths) -> Option<f64> {
    match p.version {
        CgroupVersion::V2 => std::fs::read_to_string(p.root.join("cpu.max"))
            .ok()
            .and_then(|s| parse_cpu_max_v2(&s)),
        CgroupVersion::V1 => {
            let quota: i64 = std::fs::read_to_string(p.root.join("cpu.cfs_quota_us"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(-1);
            let period: i64 = std::fs::read_to_string(p.root.join("cpu.cfs_period_us"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            v1_cpu_quota_ratio(quota, period)
        }
    }
}

#[cfg(test)]
mod cpu_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_cpu_max_variants() {
        assert_eq!(parse_cpu_max_v2("max 100000"), None);
        assert_eq!(parse_cpu_max_v2("50000 100000"), Some(0.5));
        assert_eq!(parse_cpu_max_v2("200000 100000"), Some(2.0));
        assert_eq!(parse_cpu_max_v2("50000 0"), None);
        // #15: negative quota/period must yield None (mirrors v1's guard),
        // never a sign-flipped ratio.
        assert_eq!(parse_cpu_max_v2("-50000 100000"), None);
        assert_eq!(parse_cpu_max_v2("50000 -100000"), None);
    }

    #[test]
    fn v1_quota_ratio() {
        assert_eq!(v1_cpu_quota_ratio(-1, 100000), None);
        assert_eq!(v1_cpu_quota_ratio(50000, 100000), Some(0.5));
        assert_eq!(v1_cpu_quota_ratio(100000, 0), None);
    }

    #[test]
    fn read_cpu_v2_from_fixture() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "cpu\n").unwrap();
        fs::write(d.path().join("cpu.max"), "50000 100000\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_cpu(&paths), Some(0.5));
    }

    #[test]
    fn read_cpu_v2_uncapped() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "cpu\n").unwrap();
        fs::write(d.path().join("cpu.max"), "max 100000\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_cpu(&paths), None);
    }

    #[test]
    fn read_cpu_v2_missing_file_is_none() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "cpu\n").unwrap();
        // no cpu.max => unreadable => None, not a crash
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_cpu(&paths), None);
    }

    #[test]
    fn read_cpu_v1_from_fixture() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("cpu.cfs_quota_us"), "50000\n").unwrap();
        fs::write(d.path().join("cpu.cfs_period_us"), "100000\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_cpu(&paths), Some(0.5));
    }

    #[test]
    fn read_cpu_v1_uncapped() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1; quota -1 means uncapped
        fs::write(d.path().join("cpu.cfs_quota_us"), "-1\n").unwrap();
        fs::write(d.path().join("cpu.cfs_period_us"), "100000\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_cpu(&paths), None);
    }
}

#[cfg(test)]
mod mem_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_max_handles_max_and_number() {
        assert_eq!(parse_mem_max_v2("max"), None);
        assert_eq!(parse_mem_max_v2("max\n"), None);
        assert_eq!(parse_mem_max_v2("1048576"), Some(1048576));
    }

    #[test]
    fn v1_sentinel_is_unlimited() {
        assert_eq!(v1_limit_to_max(9223372036854771712), None);
        assert_eq!(v1_limit_to_max(536870912), Some(536870912));
    }

    #[test]
    fn ratio_none_when_unlimited() {
        let s = MemorySample {
            current: 100,
            max: None,
        };
        assert_eq!(s.ratio(), None);
        let s = MemorySample {
            current: 850,
            max: Some(1000),
        };
        assert_eq!(s.ratio(), Some(0.85));
    }

    #[test]
    fn ratio_zero_limit_with_usage_is_over_limit() {
        // memory.max == 0 with current > 0 means the cgroup is maximally
        // constrained: every byte is over the limit and the kernel OOM killer
        // is imminent. The ratio must signal "over limit" so the Memory trigger
        // (ratio >= threshold) fires. We use +inf, which is >= any finite
        // threshold yet is not NaN, so the comparison is well-defined.
        let s = MemorySample {
            current: 1,
            max: Some(0),
        };
        let r = s.ratio().expect("ratio must be Some for a limited cgroup");
        assert!(r.is_infinite(), "expected +inf, got {r}");
        assert!(r >= 1.0, "expected over-limit (>= 1.0), got {r}");
    }

    #[test]
    fn ratio_zero_limit_zero_usage_is_zero() {
        // memory.max == 0 AND current == 0: nothing used, nothing allowed — not
        // over the limit, so the ratio is 0.0 (the Memory trigger stays quiet).
        let s = MemorySample {
            current: 0,
            max: Some(0),
        };
        assert_eq!(s.ratio(), Some(0.0));
    }

    #[test]
    fn detect_v2_when_controllers_present() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory cpu\n").unwrap();
        assert_eq!(detect(d.path()), CgroupVersion::V2);
    }

    #[test]
    fn detect_v1_when_no_controllers() {
        let d = tempdir().unwrap();
        assert_eq!(detect(d.path()), CgroupVersion::V1);
    }

    #[test]
    fn read_memory_current_v2_from_fixture() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        fs::write(d.path().join("memory.current"), "900\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_memory_current(&paths).unwrap(), 900);
    }

    #[test]
    fn read_memory_current_v1_from_fixture() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("memory.usage_in_bytes"), "256\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_memory_current(&paths).unwrap(), 256);
    }

    #[test]
    fn read_memory_current_missing_errors() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert!(read_memory_current(&paths).is_err());
    }

    #[test]
    fn read_memory_max_v2_number_and_unlimited() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        fs::write(d.path().join("memory.max"), "1000\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_memory_max(&paths).unwrap(), Some(1000));
        fs::write(d.path().join("memory.max"), "max\n").unwrap();
        assert_eq!(read_memory_max(&paths).unwrap(), None);
    }

    #[test]
    fn read_memory_max_v1_number_and_sentinel() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("memory.limit_in_bytes"), "512\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());
        assert_eq!(read_memory_max(&paths).unwrap(), Some(512));
        fs::write(
            d.path().join("memory.limit_in_bytes"),
            "9223372036854771712\n",
        )
        .unwrap();
        assert_eq!(read_memory_max(&paths).unwrap(), None);
    }

    // The cached-limit hot path must yield the expected sample/ratio: read the
    // limit ONCE, then per "tick" read only `current` and assemble a
    // `MemorySample { current, max: cached }`.
    #[test]
    fn cached_max_plus_current_yields_expected_sample_v2() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        fs::write(d.path().join("memory.max"), "1000\n").unwrap();
        fs::write(d.path().join("memory.current"), "850\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());

        let cached_max = read_memory_max(&paths).unwrap();
        let per_tick = MemorySample {
            current: read_memory_current(&paths).unwrap(),
            max: cached_max,
        };
        assert_eq!(
            per_tick,
            MemorySample {
                current: 850,
                max: Some(1000),
            }
        );
        assert_eq!(per_tick.ratio(), Some(0.85));
    }

    #[test]
    fn cached_max_plus_current_yields_expected_sample_v1() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("memory.limit_in_bytes"), "512\n").unwrap();
        fs::write(d.path().join("memory.usage_in_bytes"), "256\n").unwrap();
        let paths = CgroupPaths::resolve(d.path());

        let cached_max = read_memory_max(&paths).unwrap();
        let per_tick = MemorySample {
            current: read_memory_current(&paths).unwrap(),
            max: cached_max,
        };
        assert_eq!(
            per_tick,
            MemorySample {
                current: 256,
                max: Some(512),
            }
        );
        assert_eq!(per_tick.ratio(), Some(0.5));
    }
}
