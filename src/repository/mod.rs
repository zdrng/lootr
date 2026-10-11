//! Repository layer: every byte lootr sees comes from here.
//!
//! The traits below are the only way the service layer reaches the system.
//! Real implementations ([`fs`], [`env`], [`system`], [`config`]) use `os/`
//! and `std`; [`fake`] has in-memory implementations so every service test
//! runs without touching the machine.
//!
//! Secret values (file contents, env values) are only handed out as
//! [`SecretBuf`]s.

pub mod config;
pub mod env;
pub mod fake;
pub mod fs;
pub mod system;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::domain::model::{FileMeta, FsError};
use crate::domain::secret::SecretBuf;

/// A directory entry with its `lstat` metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: OsString,
    pub meta: FileMeta,
}

/// A process visible in `/proc` (Linux): its pid and `comm` (the process
/// name, non-secret). The command line and environment are read separately
/// and only if permitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    /// The process name (`/proc/<pid>/comm`), if readable.
    pub comm: Option<String>,
}

/// File system access. Never follows symlinks, except where a method says
/// so: [`FileRepository::metadata_followed`] (`stat`, nothing is opened),
/// [`FileRepository::read_link`] (the link's target, for the literal prefix
/// of a source) and the `*_within` methods (links whose target stays below a
/// directory, e.g. Kubernetes projected volumes).
///
/// The `*_beneath` methods resolve the relative part `rel` component by
/// component below a trusted `root` (a source's literal prefix), so a symlink
/// planted in a parent directory cannot be followed. The real implementation
/// uses `openat`; the default here (used by the in-memory fake) joins the
/// paths and calls the plain methods, which keep the same results for a tree
/// without malicious parent symlinks.
pub trait FileRepository {
    /// `lstat`.
    fn metadata(&self, path: &Path) -> Result<FileMeta, FsError>;
    /// Entries of a directory (not following a symlink at `path`).
    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, FsError>;
    /// Contents of a regular file of at most `max_size` bytes, opened
    /// securely; the metadata comes from the open descriptor.
    fn read_file(&self, path: &Path, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError>;

    /// [`FileRepository::metadata`] of `root`/`rel`, parent-symlink safe.
    fn metadata_beneath(&self, root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
        self.metadata(&join(root, rel))
    }
    /// [`FileRepository::read_dir`] of `root`/`rel`, parent-symlink safe.
    fn read_dir_beneath(&self, root: &Path, rel: &Path) -> Result<Vec<DirEntry>, FsError> {
        self.read_dir(&join(root, rel))
    }
    /// [`FileRepository::read_file`] of `root`/`rel`, parent-symlink safe.
    fn read_file_beneath(
        &self,
        root: &Path,
        rel: &Path,
        max_size: u64,
    ) -> Result<(FileMeta, SecretBuf), FsError> {
        self.read_file(&join(root, rel), max_size)
    }

    /// `stat`: metadata of what `path` points to, following symlinks.
    /// Nothing is opened.
    fn metadata_followed(&self, path: &Path) -> Result<FileMeta, FsError>;
    /// The target of the symlink at `path`, unresolved (`readlink`).
    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError>;
    /// [`FileRepository::read_file`] of `root`/`rel`, following symlinks
    /// only while they stay below `root`: relative targets that do not climb
    /// above it, at most a few links. Anything else is
    /// [`FsError::Symlink`]. The metadata is the final file's.
    fn read_file_within(
        &self,
        root: &Path,
        rel: &Path,
        max_size: u64,
    ) -> Result<(FileMeta, SecretBuf), FsError>;
    /// [`FileRepository::metadata`] of `root`/`rel`, following symlinks like
    /// [`FileRepository::read_file_within`].
    fn metadata_within(&self, root: &Path, rel: &Path) -> Result<FileMeta, FsError>;
}

/// `root`/`rel`, or `root` when `rel` is empty.
pub fn join(root: &Path, rel: &Path) -> PathBuf {
    if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    }
}

/// The process environment.
pub trait EnvRepository {
    /// All variable names.
    fn names(&self) -> Vec<OsString>;
    /// The value of one variable, as a secret.
    fn value(&self, name: &OsStr) -> Option<SecretBuf>;
    /// A variable that configures lootr itself (`NO_COLOR`, `TERM`) and is
    /// never a secret. Not for scanning.
    fn setting(&self, name: &str) -> Option<String>;
}

/// Facts about the running process and the machine.
pub trait SystemRepository {
    /// Real user id.
    fn uid(&self) -> u32;
    /// Effective user id (differs from `uid` in setuid programs).
    fn euid(&self) -> u32;
    fn gid(&self) -> u32;
    /// Supplementary group ids.
    fn groups(&self) -> Vec<u32>;
    /// Name of a group from the group database (`/etc/group`).
    fn group_name(&self, gid: u32) -> Option<String>;
    fn home_dir(&self) -> Option<PathBuf>;
    fn current_dir(&self) -> Result<PathBuf, FsError>;
    /// Seconds since the Unix epoch.
    fn now(&self) -> i64;

    /// The process's own pid (so probes can skip it among the processes).
    fn pid(&self) -> u32 {
        0
    }
    /// Processes visible in `/proc` (Linux). Empty on systems without
    /// `/proc` (macOS): the `proc_environ` probe then finds nothing.
    fn processes(&self) -> Vec<ProcInfo> {
        Vec::new()
    }
    /// Reads another process's environment (`/proc/<pid>/environ`): its
    /// contents are secret (that process's environment values). `max` caps
    /// the bytes read. `Err` when the file is not readable (another user,
    /// `hidepid`, a non-dumpable process) or does not exist. These `/proc`
    /// files report size 0, so they cannot be read through the ordinary
    /// size-bounded file path.
    fn read_proc_environ(&self, _pid: u32, _max: u64) -> Result<SecretBuf, FsError> {
        Err(FsError::NotFound)
    }
}

/// Reads config files (local files only; includes are resolved by the
/// config service).
pub trait ConfigRepository {
    /// The file's bytes, in a wiped buffer (a config path given by mistake
    /// may hold secrets).
    fn read(&self, path: &Path) -> Result<SecretBuf, FsError>;
}
