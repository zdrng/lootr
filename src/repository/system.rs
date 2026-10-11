//! The real process identity, groups, home and current directory, clock.
//!
//! Group names come from `/etc/group` (read with the secure open, never
//! through NSS: that would load shared libraries and may talk to the
//! network). On systems with directory services (LDAP, macOS Open
//! Directory) groups missing from `/etc/group` stay unnamed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::model::FsError;
use crate::domain::secret::SecretBuf;
use crate::os::open::{read_proc, read_regular};
use crate::repository::{ProcInfo, SystemRepository};

const GROUP_FILE: &str = "/etc/group";
const MAX_GROUP_FILE: u64 = 4 << 20;
/// `/proc/<pid>/comm` is a short process name.
const MAX_COMM: u64 = 256;

pub struct RealSystem;

impl SystemRepository for RealSystem {
    fn uid(&self) -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn group_name(&self, gid: u32) -> Option<String> {
        let (_, buf) = read_regular(Path::new(GROUP_FILE), MAX_GROUP_FILE).ok()?;
        group_name(&String::from_utf8_lossy(buf.expose()), gid)
    }

    fn gid(&self) -> u32 {
        rustix::process::getgid().as_raw()
    }

    fn groups(&self) -> Vec<u32> {
        rustix::process::getgroups()
            .map(|g| g.into_iter().map(|g| g.as_raw()).collect())
            .unwrap_or_default()
    }

    /// `$HOME`, else the password database entry.
    fn home_dir(&self) -> Option<PathBuf> {
        std::env::home_dir()
    }

    fn current_dir(&self) -> Result<PathBuf, FsError> {
        std::env::current_dir().map_err(|e| FsError::Io {
            message: format!("current directory: {e}"),
        })
    }

    fn now(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }

    fn pid(&self) -> u32 {
        rustix::process::getpid().as_raw_nonzero().get() as u32
    }

    fn processes(&self) -> Vec<ProcInfo> {
        // `/proc/<pid>` directories (Linux). On systems without /proc this
        // listing fails and no foreign process is seen.
        let Ok(entries) = crate::os::open::read_dir(Path::new("/proc")) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, _) in entries {
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let comm = read_proc(Path::new(&format!("/proc/{pid}/comm")), MAX_COMM)
                .ok()
                .map(|b| String::from_utf8_lossy(b.expose()).trim().to_string())
                .filter(|s| !s.is_empty());
            out.push(ProcInfo { pid, comm });
        }
        out
    }

    fn read_proc_environ(&self, pid: u32, max: u64) -> Result<SecretBuf, FsError> {
        read_proc(Path::new(&format!("/proc/{pid}/environ")), max)
    }
}

/// The name of `gid` in `/etc/group` content (`name:password:gid:members`).
pub fn group_name(text: &str, gid: u32) -> Option<String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let id = fields.nth(1)?.trim().parse::<u32>().ok()?;
            (id == gid && !name.is_empty()).then(|| name.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_group_file() {
        let text = "# comment\nroot:x:0:\nsudo:x:27:alice\nbroken\n:x:5:\ndocker:x:999:alice,bob\n";
        assert_eq!(group_name(text, 0).as_deref(), Some("root"));
        assert_eq!(group_name(text, 999).as_deref(), Some("docker"));
        assert_eq!(group_name(text, 5), None);
        assert_eq!(group_name(text, 1234), None);
    }
}
