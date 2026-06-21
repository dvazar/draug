//! Parsers for `/proc/self/mountinfo` and `/proc/self/cgroup`. Pure functions
//! over file *content* (no I/O) so the whole cgroup-location policy is
//! host-testable from fixture strings.

use crate::cgroup::CgroupVersion;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupMount {
    pub fstype: CgroupVersion, // V1 = "cgroup", V2 = "cgroup2"
    pub mount_point: PathBuf,
    pub mount_root: PathBuf,
    // v1: super-options tokens (incl. controllers). On v2 this is just the
    // generic mount super-options (e.g. ["rw"]) and carries no controller list.
    pub controllers: Vec<String>,
}

/// Decode mountinfo octal escapes (`\040` space, `\011` tab, `\012` nl,
/// `\134` backslash). Non-escape bytes pass through unchanged.
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            // `from_utf8` can fail when this 3-byte window splits a multibyte
            // char; `unwrap_or("")` then makes the radix parse fail, so the
            // backslash is emitted literally rather than panicking.
            if let Ok(code) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap_or(""), 8)
            {
                out.push(code);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo` content, keeping cgroup/cgroup2 mounts only.
/// Lines without the ` - ` separator or with a non-cgroup fstype are skipped.
///
/// Format (per `proc(5)`): `id pid maj:min root mount_point options
/// [optional_fields...] - fstype source super_options`. Splitting on the first
/// ` - ` cleanly separates the variable-count optional fields from the
/// `fstype source super_options` tail.
pub fn parse_mountinfo(content: &str) -> Vec<CgroupMount> {
    let mut out = Vec::new();
    for line in content.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let lf: Vec<&str> = left.split_whitespace().collect();
        let rf: Vec<&str> = right.split_whitespace().collect();
        if lf.len() < 5 || rf.len() < 3 {
            continue;
        }
        let fstype = match rf[0] {
            "cgroup" => CgroupVersion::V1,
            "cgroup2" => CgroupVersion::V2,
            _ => continue,
        };
        out.push(CgroupMount {
            fstype,
            mount_root: PathBuf::from(unescape_octal(lf[3])),
            mount_point: PathBuf::from(unescape_octal(lf[4])),
            controllers: rf[2].split(',').map(|s| s.to_string()).collect(),
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfCgroup {
    V2 {
        path: PathBuf,
    },
    V1 {
        by_controller: BTreeMap<String, PathBuf>,
    },
}

/// Parse `/proc/self/cgroup`. A `0::<path>` line is the unified (v2) hierarchy.
/// Otherwise each `id:controllers:path` line maps every controller token to its
/// path. If any v2 line is present it wins (the process is on unified v2).
pub fn parse_self_cgroup(content: &str) -> SelfCgroup {
    let mut by_controller: BTreeMap<String, PathBuf> = BTreeMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let (controllers, path) = (parts[1], parts[2]);
        if controllers.is_empty() {
            // "0::<path>" — unified v2 hierarchy.
            return SelfCgroup::V2 {
                path: PathBuf::from(path),
            };
        }
        for ctrl in controllers.split(',') {
            by_controller.insert(ctrl.to_string(), PathBuf::from(path));
        }
    }
    SelfCgroup::V1 { by_controller }
}

/// Where the live `/proc` files are read from. Overridable in tests with
/// fixture files; in production points at the real per-process files.
#[derive(Debug, Clone)]
pub struct ProcSource {
    pub mountinfo: PathBuf,
    pub self_cgroup: PathBuf,
}

impl ProcSource {
    pub fn system() -> Self {
        Self {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            self_cgroup: PathBuf::from("/proc/self/cgroup"),
        }
    }

    /// Read a file's content, or `""` when missing/unreadable. A missing
    /// `/proc` source degrades the resolver to its fallback chain rather than
    /// crashing the supervisor.
    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    pub fn read_mountinfo(&self) -> String {
        Self::read(&self.mountinfo)
    }
    pub fn read_self_cgroup(&self) -> String {
        Self::read(&self.self_cgroup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn mountinfo_v2_unified() {
        let s = "31 23 0:27 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n";
        let m = parse_mountinfo(s);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].fstype, CgroupVersion::V2);
        assert_eq!(m[0].mount_point, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(m[0].mount_root, PathBuf::from("/"));
    }

    #[test]
    fn mountinfo_v1_split_memory_and_cpu() {
        let s = "\
40 31 0:35 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory
41 31 0:36 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
";
        let m = parse_mountinfo(s);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].fstype, CgroupVersion::V1);
        assert_eq!(m[0].mount_point, PathBuf::from("/sys/fs/cgroup/memory"));
        assert!(m[0].controllers.iter().any(|c| c == "memory"));
        assert!(m[1].controllers.iter().any(|c| c == "cpu"));
        assert!(m[1].controllers.iter().any(|c| c == "cpuacct"));
    }

    #[test]
    fn mountinfo_handles_optional_fields_before_separator() {
        // optional fields ("master:1 shared:2") sit between options and "-".
        let s =
            "40 31 0:35 / /sys/fs/cgroup/memory rw master:1 shared:2 - cgroup cgroup rw,memory\n";
        let m = parse_mountinfo(s);
        assert_eq!(m[0].mount_point, PathBuf::from("/sys/fs/cgroup/memory"));
        assert!(m[0].controllers.iter().any(|c| c == "memory"));
    }

    #[test]
    fn mountinfo_octal_escapes_in_path() {
        // a space in the mount point is encoded as \040.
        let s = "40 31 0:35 / /sys/fs/cgroup/a\\040b rw - cgroup cgroup rw,memory\n";
        let m = parse_mountinfo(s);
        assert_eq!(m[0].mount_point, PathBuf::from("/sys/fs/cgroup/a b"));
    }

    #[test]
    fn mountinfo_skips_non_cgroup_and_malformed_lines() {
        let s = "\
26 18 0:5 / /dev rw - devtmpfs devtmpfs rw
garbage line with no dash
40 31 0:35 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
";
        let m = parse_mountinfo(s);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].mount_point, PathBuf::from("/sys/fs/cgroup/memory"));
    }

    #[test]
    fn mountinfo_mount_root_subtree() {
        let s = "40 31 0:35 /leaf /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        let m = parse_mountinfo(s);
        assert_eq!(m[0].mount_root, PathBuf::from("/leaf"));
    }

    #[test]
    fn mountinfo_empty_and_blank_input_yields_empty() {
        assert!(parse_mountinfo("").is_empty());
        assert!(parse_mountinfo("\n\n").is_empty());
    }

    #[test]
    fn self_cgroup_v2_root() {
        let s = "0::/\n";
        match parse_self_cgroup(s) {
            SelfCgroup::V2 { path } => assert_eq!(path, PathBuf::from("/")),
            other => panic!("expected V2, got {other:?}"),
        }
    }

    #[test]
    fn self_cgroup_v2_leaf() {
        let s = "0::/system.slice/app.service\n";
        match parse_self_cgroup(s) {
            SelfCgroup::V2 { path } => {
                assert_eq!(path, PathBuf::from("/system.slice/app.service"))
            }
            other => panic!("expected V2, got {other:?}"),
        }
    }

    #[test]
    fn self_cgroup_v1_multi_controller() {
        let s = "\
9:memory:/docker/abc
4:cpu,cpuacct:/docker/abc
";
        match parse_self_cgroup(s) {
            SelfCgroup::V1 { by_controller } => {
                assert_eq!(
                    by_controller.get("memory").unwrap(),
                    &PathBuf::from("/docker/abc")
                );
                assert_eq!(
                    by_controller.get("cpu").unwrap(),
                    &PathBuf::from("/docker/abc")
                );
                assert_eq!(
                    by_controller.get("cpuacct").unwrap(),
                    &PathBuf::from("/docker/abc")
                );
            }
            other => panic!("expected V1, got {other:?}"),
        }
    }

    #[test]
    fn self_cgroup_v1_namespaced_root() {
        let s = "9:memory:/\n";
        match parse_self_cgroup(s) {
            SelfCgroup::V1 { by_controller } => {
                assert_eq!(by_controller.get("memory").unwrap(), &PathBuf::from("/"))
            }
            other => panic!("expected V1, got {other:?}"),
        }
    }

    #[test]
    fn self_cgroup_ignores_malformed_lines() {
        let s = "\
garbage
9:memory:/ok
";
        match parse_self_cgroup(s) {
            SelfCgroup::V1 { by_controller } => {
                assert_eq!(by_controller.len(), 1);
                assert_eq!(by_controller.get("memory").unwrap(), &PathBuf::from("/ok"));
            }
            other => panic!("expected V1, got {other:?}"),
        }
    }

    #[test]
    fn proc_source_reads_files_or_empty_on_missing() {
        let d = tempdir().unwrap();
        let mi = d.path().join("mountinfo");
        fs::write(&mi, "X\n").unwrap();
        let missing = d.path().join("nope");

        // Present file reads back its content; missing self_cgroup => "".
        let ps = ProcSource {
            mountinfo: mi.clone(),
            self_cgroup: missing.clone(),
        };
        assert_eq!(ps.read_mountinfo(), "X\n");
        assert_eq!(ps.read_self_cgroup(), ""); // missing => empty, never panics

        // Symmetric case: a missing mountinfo also degrades to "" (no panic).
        let ps_missing_mi = ProcSource {
            mountinfo: missing,
            self_cgroup: mi,
        };
        assert_eq!(ps_missing_mi.read_mountinfo(), "");
        assert_eq!(ps_missing_mi.read_self_cgroup(), "X\n");
    }
}
