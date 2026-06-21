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
//!
//! Controller directories are resolved authoritatively from
//! `/proc/self/mountinfo` + `/proc/self/cgroup` (see `CgroupPaths::resolve`), so
//! reads land in the right place on v1 split hierarchies (e.g. AWS Fargate,
//! where `memory.*` lives under `<root>/memory/`) as well as v2 unified hosts.
//! `--cgroup-root` overrides the mount base; the `/proc` source is injectable
//! (`ProcSource`) so resolution is host-testable from fixture files.

use std::io;
use std::path::{Path, PathBuf};

/// cgroup hierarchy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
}

/// Resolved per-controller cgroup directories + detected version.
#[derive(Debug, Clone)]
pub struct CgroupPaths {
    pub version: CgroupVersion,
    /// Directory holding `memory.*` (and, on v2, `memory.pressure`).
    pub memory_dir: PathBuf,
    /// Directory holding `cpu.*` / `cpu.cfs_*`.
    pub cpu_dir: PathBuf,
}

impl CgroupPaths {
    /// Construct paths for a flat/legacy single-directory layout where every
    /// controller lives directly under `root` (the pre-authoritative-resolution
    /// behavior). Version is detected from `root`. Used by tests and as the
    /// legacy branch of the fallback chain.
    pub fn flat(root: &Path) -> CgroupPaths {
        CgroupPaths {
            version: detect(root),
            memory_dir: root.to_path_buf(),
            cpu_dir: root.to_path_buf(),
        }
    }

    /// Authoritative resolution: parse mountinfo + self_cgroup, detect version,
    /// locate each controller's directory under `cgroup_root`.
    pub fn resolve(cgroup_root: &Path, proc: &crate::procfs::ProcSource) -> CgroupPaths {
        let mounts = crate::procfs::parse_mountinfo(&proc.read_mountinfo());
        let self_cg = crate::procfs::parse_self_cgroup(&proc.read_self_cgroup());

        // V2 iff a cgroup2 hierarchy is mounted exactly at cgroup_root. On
        // hybrid hosts cgroup2 is mounted elsewhere (e.g. /sys/fs/cgroup/unified)
        // so this condition is false and we correctly fall through to V1. Note
        // the kernel — not this code — guarantees a controller is never on both
        // v1 and v2 at once, so picking V2 here can't strand a v1 controller.
        if let Some(m) = mounts
            .iter()
            .find(|m| m.fstype == CgroupVersion::V2 && m.mount_point == cgroup_root)
        {
            let rel = match &self_cg {
                crate::procfs::SelfCgroup::V2 { path } => adjust(path, &m.mount_root),
                _ => PathBuf::from("/"),
            };
            let dir = join_rel(cgroup_root, &rel);
            return CgroupPaths {
                version: CgroupVersion::V2,
                memory_dir: dir.clone(),
                cpu_dir: dir,
            };
        }

        // V1: locate each controller's mount, re-root its subdir under
        // cgroup_root, and join the process's relative cgroup path.
        let mem = v1_controller_dir(&mounts, &self_cg, "memory", cgroup_root);
        let cpu = v1_controller_dir(&mounts, &self_cg, "cpu", cgroup_root);
        if let Some(memory_dir) = mem {
            return CgroupPaths {
                version: CgroupVersion::V1,
                // When only memory is locatable, guess the conventional
                // Fargate/ECS cpu basename rather than failing the whole resolve.
                cpu_dir: cpu.unwrap_or_else(|| cgroup_root.join("cpu,cpuacct")),
                memory_dir,
            };
        }

        // No usable mount info (e.g. /proc unreadable): use the heuristic chain.
        resolve_fallback(cgroup_root)
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

/// Strip `mount_root` from an absolute cgroup path (the libcontainer nuance:
/// when only a subtree of the hierarchy is mounted, the cgroup path is relative
/// to that subtree). `mount_root == "/"` is the common case and is a no-op.
fn adjust(cgroup_path: &Path, mount_root: &Path) -> PathBuf {
    if mount_root == Path::new("/") {
        return cgroup_path.to_path_buf();
    }
    match cgroup_path.strip_prefix(mount_root) {
        Ok(rest) => Path::new("/").join(rest),
        Err(_) => cgroup_path.to_path_buf(),
    }
}

/// Join an absolute-looking relative cgroup path onto a base dir. `"/"` yields
/// the base unchanged (no trailing-slash artifact).
fn join_rel(base: &Path, rel: &Path) -> PathBuf {
    let stripped = rel.strip_prefix("/").unwrap_or(rel);
    if stripped.as_os_str().is_empty() {
        base.to_path_buf()
    } else {
        base.join(stripped)
    }
}

/// Locate a v1 controller's directory: find the mount whose super-options name
/// the controller, take its mount-point basename as the subdir under
/// `cgroup_root` (so `--cgroup-root` overrides the base), then join the
/// process's relative cgroup path for that controller.
fn v1_controller_dir(
    mounts: &[crate::procfs::CgroupMount],
    self_cg: &crate::procfs::SelfCgroup,
    controller: &str,
    cgroup_root: &Path,
) -> Option<PathBuf> {
    let m = mounts
        .iter()
        .find(|m| m.fstype == CgroupVersion::V1 && m.controllers.iter().any(|c| c == controller))?;
    // Use the mount-point basename as the controller subdir under cgroup_root.
    // A "/" mount point (pathological — real cgroup mounts live at
    // /sys/fs/cgroup/<name>) has no basename; `?` then propagates None so
    // resolve degrades to the fallback chain, which is the correct outcome.
    let subdir = m.mount_point.file_name()?;
    let rel = match self_cg {
        crate::procfs::SelfCgroup::V1 { by_controller } => by_controller
            .get(controller)
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/")),
        _ => PathBuf::from("/"),
    };
    let rel = adjust(&rel, &m.mount_root);
    Some(join_rel(&cgroup_root.join(subdir), &rel))
}

/// Heuristic fallback when `/proc` is unreadable/empty: prefer the conventional
/// container layout, then the legacy flat layout (draug's pre-fix behavior).
fn resolve_fallback(cgroup_root: &Path) -> CgroupPaths {
    // Conventional v2: unified hierarchy with a controllers file at the root.
    // This is a best-effort heuristic for when /proc is unreadable, not an
    // authoritative detect — the live resolver above is the source of truth.
    if cgroup_root.join("cgroup.controllers").exists() {
        return CgroupPaths {
            version: CgroupVersion::V2,
            memory_dir: cgroup_root.to_path_buf(),
            cpu_dir: cgroup_root.to_path_buf(),
        };
    }
    // Conventional v1: controllers in per-controller subdirs (e.g. Fargate's
    // <root>/memory/, <root>/cpu,cpuacct/).
    let mem_sub = cgroup_root.join("memory");
    if mem_sub.join("memory.limit_in_bytes").exists() {
        return CgroupPaths {
            version: CgroupVersion::V1,
            memory_dir: mem_sub,
            cpu_dir: cgroup_root.join("cpu,cpuacct"),
        };
    }
    // Legacy flat: draug's original single-directory behavior (the root IS the
    // controller dir). Version auto-detected from the root.
    CgroupPaths::flat(cgroup_root)
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
    read_u64(&p.memory_dir.join(file))
}

/// Read the memory limit once: `memory.max` (v2) / `memory.limit_in_bytes`
/// (v1), mapped to `None` when unlimited. The limit is fixed for the
/// container's lifetime, so callers cache this at startup rather than re-read
/// it every tick.
pub fn read_memory_max(p: &CgroupPaths) -> io::Result<Option<u64>> {
    match p.version {
        CgroupVersion::V2 => {
            let max_raw = std::fs::read_to_string(p.memory_dir.join("memory.max"))?;
            Ok(parse_mem_max_v2(&max_raw))
        }
        CgroupVersion::V1 => {
            let limit = read_u64(&p.memory_dir.join("memory.limit_in_bytes"))?;
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
        CgroupVersion::V2 => std::fs::read_to_string(p.cpu_dir.join("cpu.max"))
            .ok()
            .and_then(|s| parse_cpu_max_v2(&s)),
        CgroupVersion::V1 => {
            let quota: i64 = std::fs::read_to_string(p.cpu_dir.join("cpu.cfs_quota_us"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(-1);
            let period: i64 = std::fs::read_to_string(p.cpu_dir.join("cpu.cfs_period_us"))
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
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_cpu(&paths), Some(0.5));
    }

    #[test]
    fn read_cpu_v2_uncapped() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "cpu\n").unwrap();
        fs::write(d.path().join("cpu.max"), "max 100000\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_cpu(&paths), None);
    }

    #[test]
    fn read_cpu_v2_missing_file_is_none() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "cpu\n").unwrap();
        // no cpu.max => unreadable => None, not a crash
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_cpu(&paths), None);
    }

    #[test]
    fn read_cpu_v1_from_fixture() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("cpu.cfs_quota_us"), "50000\n").unwrap();
        fs::write(d.path().join("cpu.cfs_period_us"), "100000\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_cpu(&paths), Some(0.5));
    }

    #[test]
    fn read_cpu_v1_uncapped() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1; quota -1 means uncapped
        fs::write(d.path().join("cpu.cfs_quota_us"), "-1\n").unwrap();
        fs::write(d.path().join("cpu.cfs_period_us"), "100000\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
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
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_memory_current(&paths).unwrap(), 900);
    }

    #[test]
    fn read_memory_current_v1_from_fixture() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("memory.usage_in_bytes"), "256\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_memory_current(&paths).unwrap(), 256);
    }

    #[test]
    fn read_memory_current_missing_errors() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
        assert!(read_memory_current(&paths).is_err());
    }

    #[test]
    fn read_memory_max_v2_number_and_unlimited() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), "memory\n").unwrap();
        fs::write(d.path().join("memory.max"), "1000\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
        assert_eq!(read_memory_max(&paths).unwrap(), Some(1000));
        fs::write(d.path().join("memory.max"), "max\n").unwrap();
        assert_eq!(read_memory_max(&paths).unwrap(), None);
    }

    #[test]
    fn read_memory_max_v1_number_and_sentinel() {
        let d = tempdir().unwrap();
        // no cgroup.controllers => v1
        fs::write(d.path().join("memory.limit_in_bytes"), "512\n").unwrap();
        let paths = CgroupPaths::flat(d.path());
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
        let paths = CgroupPaths::flat(d.path());

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
        let paths = CgroupPaths::flat(d.path());

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

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::procfs::ProcSource;
    use std::fs;
    use tempfile::tempdir;

    /// Build a ProcSource from fixture mountinfo/self_cgroup strings.
    fn proc_fixture(dir: &Path, mountinfo: &str, self_cgroup: &str) -> ProcSource {
        let mi = dir.join("mountinfo");
        let sc = dir.join("cgroup");
        fs::write(&mi, mountinfo).unwrap();
        fs::write(&sc, self_cgroup).unwrap();
        ProcSource {
            mountinfo: mi,
            self_cgroup: sc,
        }
    }

    #[test]
    fn v2_unified_namespaced() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        let mi = format!("31 23 0:27 / {} rw - cgroup2 cgroup2 rw\n", root.display());
        let proc = proc_fixture(d.path(), &mi, "0::/\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V2);
        assert_eq!(p.memory_dir, root);
        assert_eq!(p.cpu_dir, root);
    }

    #[test]
    fn v2_unified_non_namespaced_joins_leaf() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        let mi = format!("31 23 0:27 / {} rw - cgroup2 cgroup2 rw\n", root.display());
        let proc = proc_fixture(d.path(), &mi, "0::/system.slice/app\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.memory_dir, root.join("system.slice/app"));
    }

    #[test]
    fn v1_split_namespaced_memory_subdir() {
        // The Fargate regression: memory controller in <root>/memory/.
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let mem = root.join("memory");
        fs::create_dir_all(&mem).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n",
            mem.display()
        );
        let proc = proc_fixture(d.path(), &mi, "9:memory:/\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V1);
        assert_eq!(p.memory_dir, mem);
        // No cpu mount in this fixture => cpu_dir uses the conventional basename.
        assert_eq!(p.cpu_dir, root.join("cpu,cpuacct"));
    }

    #[test]
    fn v1_cpu_cpuacct_combined() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let cpu = root.join("cpu,cpuacct");
        let mem = root.join("memory");
        fs::create_dir_all(&cpu).unwrap();
        fs::create_dir_all(&mem).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n\
             41 31 0:36 / {} rw - cgroup cgroup rw,cpu,cpuacct\n",
            mem.display(),
            cpu.display()
        );
        let proc = proc_fixture(d.path(), &mi, "9:memory:/\n4:cpu,cpuacct:/\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.cpu_dir, cpu);
    }

    #[test]
    fn v1_non_namespaced_joins_relative() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let mem = root.join("memory");
        fs::create_dir_all(&mem).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n",
            mem.display()
        );
        let proc = proc_fixture(d.path(), &mi, "9:memory:/docker/abc\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.memory_dir, mem.join("docker/abc"));
    }

    #[test]
    fn v2_self_cgroup_without_v2_mount_resolves_v1_at_root() {
        // self_cgroup advertises unified v2, but no cgroup2 mount exists; a v1
        // memory mount does. Resolve must fall through to V1 and, since the v1
        // controller path is unknown for a V2 self_cgroup, default to "/".
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let mem = root.join("memory");
        fs::create_dir_all(&mem).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n",
            mem.display()
        );
        let proc = proc_fixture(d.path(), &mi, "0::/system.slice/app\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V1);
        assert_eq!(p.memory_dir, mem);
    }

    #[test]
    fn v1_controller_absent_from_self_cgroup_defaults_to_root() {
        // memory mount exists, but self_cgroup lists only cpu => the memory
        // controller's relative path defaults to "/" (process at hierarchy root).
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let mem = root.join("memory");
        fs::create_dir_all(&mem).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n",
            mem.display()
        );
        let proc = proc_fixture(d.path(), &mi, "4:cpu,cpuacct:/some/path\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V1);
        assert_eq!(p.memory_dir, mem);
    }

    #[test]
    fn fallback_conventional_v1_when_proc_empty() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        let mem = root.join("memory");
        fs::create_dir_all(&mem).unwrap();
        fs::write(mem.join("memory.limit_in_bytes"), "512\n").unwrap();
        // empty /proc => no mounts, no self_cgroup
        let proc = proc_fixture(d.path(), "", "");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V1);
        assert_eq!(p.memory_dir, mem);
    }

    #[test]
    fn fallback_conventional_v2_when_proc_empty() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.controllers"), "memory cpu\n").unwrap();
        let proc = proc_fixture(d.path(), "", "");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V2);
        assert_eq!(p.memory_dir, root);
        assert_eq!(p.cpu_dir, root);
    }

    #[test]
    fn fallback_legacy_flat_when_nothing_present() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        // no cgroup.controllers, no memory/ subdir => legacy flat, v1
        let proc = proc_fixture(d.path(), "", "");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.version, CgroupVersion::V1);
        assert_eq!(p.memory_dir, root);
    }

    #[test]
    fn mount_base_override_reroots_v1() {
        // mountinfo describes the real host paths; cgroup_root override points
        // elsewhere. The controller subdir name is taken from the mount basename.
        let d = tempdir().unwrap();
        let real_mem = PathBuf::from("/sys/fs/cgroup/memory");
        let override_root = d.path().join("custom");
        fs::create_dir_all(override_root.join("memory")).unwrap();
        let mi = format!(
            "40 31 0:35 / {} rw - cgroup cgroup rw,memory\n",
            real_mem.display()
        );
        let proc = proc_fixture(d.path(), &mi, "9:memory:/\n");
        let p = CgroupPaths::resolve(&override_root, &proc);
        assert_eq!(p.memory_dir, override_root.join("memory"));
    }

    #[test]
    fn v2_mount_root_subtree_adjusts() {
        let d = tempdir().unwrap();
        let root = d.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        // mount_root=/leaf, self path=/leaf/app => adjusted rel=/app
        let mi = format!(
            "31 23 0:27 /leaf {} rw - cgroup2 cgroup2 rw\n",
            root.display()
        );
        let proc = proc_fixture(d.path(), &mi, "0::/leaf/app\n");
        let p = CgroupPaths::resolve(&root, &proc);
        assert_eq!(p.memory_dir, root.join("app"));
    }
}

#[cfg(test)]
mod path_helper_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn adjust_identity_when_root_is_slash() {
        assert_eq!(
            adjust(Path::new("/a/b"), Path::new("/")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn adjust_strips_mount_root_subtree() {
        // mount_root=/leaf, cgroup path=/leaf/x => relative /x
        assert_eq!(
            adjust(Path::new("/leaf/x"), Path::new("/leaf")),
            PathBuf::from("/x")
        );
    }

    #[test]
    fn adjust_equal_path_becomes_root() {
        assert_eq!(
            adjust(Path::new("/leaf"), Path::new("/leaf")),
            PathBuf::from("/")
        );
    }

    #[test]
    fn join_rel_empty_returns_base() {
        assert_eq!(
            join_rel(Path::new("/base"), Path::new("/")),
            PathBuf::from("/base")
        );
    }

    #[test]
    fn join_rel_appends_relative() {
        assert_eq!(
            join_rel(Path::new("/base"), Path::new("/x/y")),
            PathBuf::from("/base/x/y")
        );
    }

    #[test]
    fn adjust_returns_path_unchanged_when_mount_root_not_a_prefix() {
        // mount_root is not a prefix of the path => pass through unchanged.
        assert_eq!(
            adjust(Path::new("/a/b"), Path::new("/c")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn join_rel_empty_path_returns_base() {
        // a literally empty rel (not "/") also yields base unchanged.
        assert_eq!(
            join_rel(Path::new("/base"), Path::new("")),
            PathBuf::from("/base")
        );
    }

    #[test]
    fn join_rel_relative_without_leading_slash_appends() {
        assert_eq!(
            join_rel(Path::new("/base"), Path::new("x/y")),
            PathBuf::from("/base/x/y")
        );
    }
}
