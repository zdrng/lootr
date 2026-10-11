//! `suid`: setuid/setgid binaries and Linux file capabilities at the
//! source's `paths`.
//!
//! A setuid/setgid program runs with its owner's or group's identity, and a
//! file capability grants a specific kernel privilege (`cap_net_raw`,
//! `cap_sys_admin`, ...). Either is a privilege boundary: one that an
//! unprivileged user can **write** (or that lives where untrusted code can
//! replace it) is an escalation path.
//!
//! lootr does not inventory the whole system (that is Lynis/OpenSCAP
//! territory, a non-goal); the default config points this probe at the
//! directories untrusted code can plausibly reach, and the rules fire on the
//! risky cases (writable, not root-owned, or carrying capabilities). A fact
//! is emitted only for objects that are setuid, setgid or have capabilities.
//!
//! File capabilities are read from the `security.capability` extended
//! attribute with `lgetxattr` (Linux only; forbids following a symlink). On
//! systems without that xattr (macOS) the `capabilities` list is always
//! empty and only the setuid/setgid bits are reported.

use crate::domain::model::{
    AttrValue, Attrs, DisplayPath, Fact, FileKind, Ident, Location, Skipped,
};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::writable::writable_by;
use crate::service::probe::{Probe, ProbeContext};

pub const NAME: &str = "suid";
pub const FACT: &str = "suid_binary";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("setuid", AttrKind::Bool, "the setuid bit is set"),
    AttrSpec::new("setgid", AttrKind::Bool, "the setgid bit is set"),
    AttrSpec::new(
        "owner_is_root",
        AttrKind::Bool,
        "owned by root (setuid root runs as root)",
    ),
    AttrSpec::new(
        "owner_is_self",
        AttrKind::Bool,
        "owned by the scanning user",
    ),
    AttrSpec::new(
        "writable",
        AttrKind::Bool,
        "the scanning user may write it (so replace it)",
    ),
    AttrSpec::new("world_writable", AttrKind::Bool, "any user may write it"),
    AttrSpec::new("mode", AttrKind::Int, "permission bits incl. setuid/setgid"),
    AttrSpec::new(
        "capabilities",
        AttrKind::List,
        "Linux file capabilities in the permitted set (e.g. cap_net_raw), empty if none/unsupported",
    ),
];

const FACT_TYPES: &[FactType] = &[FactType {
    name: FACT,
    doc: "a setuid/setgid binary or a binary with file capabilities at a probe path",
    schema: ATTRS,
}];

pub struct SuidProbe;

impl Probe for SuidProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, _skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let Ok(type_) = Ident::from_non_secret(FACT) else {
            return Vec::new();
        };
        let system = ctx.system;
        let uid = system.uid();
        let root = system.euid() == 0;
        let mut gids = system.groups();
        gids.push(system.gid());
        let mut facts = Vec::new();
        for path in ctx.paths {
            let Ok(meta) = ctx.files.metadata(path) else {
                continue;
            };
            if meta.kind != FileKind::File {
                continue;
            }
            let setuid = meta.mode & 0o4000 != 0;
            let setgid = meta.mode & 0o2000 != 0;
            let caps = read_capabilities(path);
            if !setuid && !setgid && caps.is_empty() {
                continue;
            }
            let mut attrs = Attrs::new();
            attrs.insert("setuid", AttrValue::Bool(setuid));
            attrs.insert("setgid", AttrValue::Bool(setgid));
            attrs.insert("owner_is_root", AttrValue::Bool(meta.uid == 0));
            attrs.insert("owner_is_self", AttrValue::Bool(meta.uid == uid));
            attrs.insert(
                "writable",
                AttrValue::Bool(writable_by(&meta, uid, root, &gids)),
            );
            attrs.insert("world_writable", AttrValue::Bool(meta.mode & 0o002 != 0));
            attrs.insert("mode", AttrValue::Int(i64::from(meta.mode & 0o7777)));
            let cap_list = caps
                .iter()
                .filter_map(|c| Ident::from_non_secret(c).ok())
                .map(AttrValue::Name)
                .collect();
            attrs.insert("capabilities", AttrValue::List(cap_list));
            facts.push(Fact {
                type_: type_.clone(),
                location: Location::File {
                    path: DisplayPath::new(path),
                    key_path: None,
                },
                source: ctx.source.clone(),
                attrs,
            });
        }
        facts
    }
}

/// Linux capability names, indexed by bit (`CAP_CHOWN` = 0 ...). Unused on
/// platforms without file capabilities (macOS).
#[allow(dead_code)]
const CAP_NAMES: &[&str] = &[
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// Names of the capabilities in a `security.capability` xattr's permitted
/// set. Empty where xattrs or capabilities are not available (non-Linux).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_capabilities(path: &std::path::Path) -> Vec<&'static str> {
    let mut buf = [0u8; 64];
    let n = match rustix::fs::lgetxattr(path, "security.capability", &mut buf) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    parse_capabilities(&buf[..n])
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_capabilities(_path: &std::path::Path) -> Vec<&'static str> {
    Vec::new()
}

/// Parses the permitted mask of a `vfs_cap_data` structure (little endian):
/// `magic_etc`, then `permitted_lo`, `inheritable_lo`, (rev2/3)
/// `permitted_hi`, `inheritable_hi`. Unused on non-Linux (no file caps).
#[allow(dead_code)]
fn parse_capabilities(data: &[u8]) -> Vec<&'static str> {
    let word = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(magic) = word(0) else {
        return Vec::new();
    };
    let (lo, hi) = match magic & 0xFF00_0000 {
        0x0100_0000 => (word(4), Some(0)),
        0x0200_0000 | 0x0300_0000 => (word(4), word(12)),
        _ => return Vec::new(),
    };
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Vec::new();
    };
    let mask = (u64::from(hi) << 32) | u64::from(lo);
    CAP_NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Registry;
    use crate::repository::fake::{FakeFiles, FakeSystem};
    use std::path::PathBuf;

    fn run(system: &FakeSystem, files: &FakeFiles, paths: &[&str]) -> Vec<Fact> {
        let source = Ident::from_non_secret("suid").unwrap();
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        let registry = Registry::builtin(0);
        let ctx = ProbeContext {
            source: &source,
            paths: &paths,
            system,
            files,
            registry: &registry,
        };
        SuidProbe.run(&ctx, &mut Vec::new())
    }

    #[test]
    fn reports_setuid_and_skips_ordinary_files() {
        let files = FakeFiles::new()
            .special_owned("/usr/local/bin/escalate", FileKind::File, 0, 0, 0o6755)
            .file_with_mode("/usr/local/bin/ordinary", "bin", 0o755);
        let facts = run(
            &FakeSystem::default(),
            &files,
            &["/usr/local/bin/escalate", "/usr/local/bin/ordinary"],
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].attrs["setuid"], AttrValue::Bool(true));
        assert_eq!(facts[0].attrs["setgid"], AttrValue::Bool(true));
        assert_eq!(facts[0].attrs["owner_is_root"], AttrValue::Bool(true));
    }

    #[test]
    fn parses_a_rev2_capability_block() {
        // magic 0x02000000, permitted_lo with cap_net_raw (bit 13).
        let mut data = vec![0u8; 20];
        data[3] = 0x02;
        data[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
        assert_eq!(parse_capabilities(&data), ["cap_net_raw"]);
        assert!(parse_capabilities(&[]).is_empty());
    }
}
