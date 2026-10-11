//! In-memory repositories for tests: a fake file tree, environment, process
//! and config files. Paths are absolute; parent directories are created
//! implicitly.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::domain::model::{FileKind, FileMeta, FsError};
use crate::domain::secret::SecretBuf;
use crate::repository::{
    ConfigRepository, DirEntry, EnvRepository, FileRepository, ProcInfo, SystemRepository, join,
};

/// Default owner of fake files and the fake process.
pub const FAKE_UID: u32 = 1000;
pub const FAKE_GID: u32 = 1000;
/// 2026-10-08T14:03:00Z
pub const FAKE_NOW: i64 = 1_791_468_180;

#[derive(Clone)]
struct FakeNode {
    meta: FileMeta,
    data: Vec<u8>,
    /// Reading fails with this error (e.g. permission denied).
    error: Option<FsError>,
    /// The target of a symlink made with [`FakeFiles::symlink`].
    target: Option<PathBuf>,
}

/// A fake file tree. Every node gets its own inode number; [`FakeFiles::alias`]
/// makes one node visible at a second path (a hard link, or a path through a
/// symlinked parent such as `/var/run` → `/run`).
#[derive(Default)]
pub struct FakeFiles {
    nodes: BTreeMap<PathBuf, FakeNode>,
    next_ino: u64,
}

impl FakeFiles {
    pub fn new() -> FakeFiles {
        FakeFiles::default()
    }

    fn meta(kind: FileKind, mode: u32, size: u64, dev: u64) -> FileMeta {
        FileMeta {
            kind,
            mode,
            uid: FAKE_UID,
            gid: FAKE_GID,
            size,
            mtime: FAKE_NOW - 10 * 86_400,
            dev,
            ino: 0,
        }
    }

    fn ino(&mut self) -> u64 {
        self.next_ino += 1;
        self.next_ino
    }

    fn insert(&mut self, path: &Path, mut node: FakeNode) {
        let mut parent = path.parent();
        while let Some(p) = parent {
            if !self.nodes.contains_key(p) {
                let mut meta = FakeFiles::meta(FileKind::Dir, 0o755, 0, node.meta.dev);
                meta.ino = self.ino();
                self.nodes.insert(
                    p.to_path_buf(),
                    FakeNode {
                        meta,
                        data: Vec::new(),
                        error: None,
                        target: None,
                    },
                );
            }
            parent = p.parent();
        }
        node.meta.ino = self.ino();
        self.nodes.insert(path.to_path_buf(), node);
    }

    /// A symlink at `path` pointing to `target` (relative to the link's
    /// directory or absolute), owned by the fake user. `metadata` reports
    /// the link; `metadata_followed`, `read_link` and the `*_within` methods
    /// resolve it.
    pub fn symlink(self, path: impl AsRef<Path>, target: impl AsRef<Path>) -> FakeFiles {
        self.symlink_owned(path, target, FAKE_UID)
    }

    /// [`FakeFiles::symlink`] owned by `uid`.
    pub fn symlink_owned(
        mut self,
        path: impl AsRef<Path>,
        target: impl AsRef<Path>,
        uid: u32,
    ) -> FakeFiles {
        let meta = FileMeta {
            uid,
            ..FakeFiles::meta(FileKind::Symlink, 0o777, 0, 1)
        };
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: None,
                target: Some(target.as_ref().to_path_buf()),
            },
        );
        self
    }

    /// Makes every node at or below `existing` visible below `path` too,
    /// with the same metadata and inode (what a symlinked parent directory
    /// or a hard link looks like through `lstat`).
    pub fn alias(mut self, path: impl AsRef<Path>, existing: impl AsRef<Path>) -> FakeFiles {
        let (path, existing) = (path.as_ref(), existing.as_ref());
        let copies: Vec<(PathBuf, FakeNode)> = self
            .nodes
            .iter()
            .filter_map(|(p, n)| {
                let rest = p.strip_prefix(existing).ok()?;
                Some((join(path, rest), n.clone()))
            })
            .collect();
        for (p, node) in copies {
            let ino = node.meta.ino;
            self.insert(&p, node);
            if let Some(n) = self.nodes.get_mut(&p) {
                n.meta.ino = ino;
            }
        }
        self
    }

    /// Resolves symlinks in `path` (every component, the last one too) like
    /// the kernel does for `stat`. Relative targets are joined to the link's
    /// directory.
    fn resolve(&self, path: &Path) -> Result<PathBuf, FsError> {
        let mut out = PathBuf::from("/");
        let mut pending: Vec<std::ffi::OsString> = path
            .components()
            .rev()
            .filter_map(|c| match c {
                std::path::Component::Normal(n) => Some(n.to_os_string()),
                std::path::Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect();
        let mut links = 0;
        while let Some(name) = pending.pop() {
            if name == ".." {
                out.pop();
                continue;
            }
            let next = out.join(&name);
            let node = self.nodes.get(&next).ok_or(FsError::NotFound)?;
            match &node.target {
                Some(target) => {
                    links += 1;
                    if links > 40 {
                        return Err(FsError::Symlink);
                    }
                    if target.is_absolute() {
                        out = PathBuf::from("/");
                    }
                    pending.extend(target.components().rev().filter_map(|c| match c {
                        std::path::Component::Normal(n) => Some(n.to_os_string()),
                        std::path::Component::ParentDir => Some("..".into()),
                        _ => None,
                    }));
                }
                None => out = next,
            }
        }
        Ok(out)
    }

    /// `root`/`rel` with symlinks resolved only while they stay below `root`
    /// (the real `os::open::resolve_within`, on paths).
    fn resolve_within(&self, root: &Path, rel: &Path) -> Result<PathBuf, FsError> {
        let mut below: Vec<std::ffi::OsString> = Vec::new();
        let mut pending: Vec<std::ffi::OsString> = Vec::new();
        for c in rel.components().rev() {
            match c {
                std::path::Component::Normal(n) => pending.push(n.to_os_string()),
                std::path::Component::CurDir => {}
                _ => return Err(FsError::Symlink),
            }
        }
        let mut links = 0;
        while let Some(name) = pending.pop() {
            if name == ".." {
                below.pop().ok_or(FsError::Symlink)?;
                continue;
            }
            let path = below
                .iter()
                .fold(root.to_path_buf(), |p, c| p.join(c))
                .join(&name);
            let node = self.nodes.get(&path).ok_or(FsError::NotFound)?;
            if let Some(target) = &node.target {
                links += 1;
                if links > crate::os::open::MAX_LINKS_WITHIN || target.is_absolute() {
                    return Err(FsError::Symlink);
                }
                for c in target.components().rev() {
                    match c {
                        std::path::Component::Normal(n) => pending.push(n.to_os_string()),
                        std::path::Component::ParentDir => pending.push("..".into()),
                        std::path::Component::CurDir => {}
                        _ => return Err(FsError::Symlink),
                    }
                }
                continue;
            }
            if !pending.is_empty() && node.meta.kind != FileKind::Dir {
                return Err(FsError::NotFound);
            }
            below.push(name);
        }
        Ok(below.iter().fold(root.to_path_buf(), |p, c| p.join(c)))
    }

    /// A regular file with mode 0600.
    pub fn file(self, path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> FakeFiles {
        self.file_with_mode(path, data, 0o600)
    }

    pub fn file_with_mode(
        mut self,
        path: impl AsRef<Path>,
        data: impl AsRef<[u8]>,
        mode: u32,
    ) -> FakeFiles {
        let data = data.as_ref().to_vec();
        let meta = FakeFiles::meta(FileKind::File, mode, data.len() as u64, 1);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data,
                error: None,
                target: None,
            },
        );
        self
    }

    /// A file that exists but cannot be read.
    pub fn unreadable(mut self, path: impl AsRef<Path>) -> FakeFiles {
        let meta = FakeFiles::meta(FileKind::File, 0o000, 10, 1);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: Some(FsError::PermissionDenied),
                target: None,
            },
        );
        self
    }

    /// A directory that cannot be listed.
    pub fn locked_dir(mut self, path: impl AsRef<Path>) -> FakeFiles {
        let meta = FakeFiles::meta(FileKind::Dir, 0o000, 0, 1);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: Some(FsError::PermissionDenied),
                target: None,
            },
        );
        self
    }

    pub fn dir(mut self, path: impl AsRef<Path>) -> FakeFiles {
        let meta = FakeFiles::meta(FileKind::Dir, 0o755, 0, 1);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: None,
                target: None,
            },
        );
        self
    }

    /// A directory on another device (for `one-file-system`).
    pub fn mount(mut self, path: impl AsRef<Path>) -> FakeFiles {
        let meta = FakeFiles::meta(FileKind::Dir, 0o755, 0, 2);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: None,
                target: None,
            },
        );
        self
    }

    /// A non-regular entry with an owner, group and mode (e.g. a socket
    /// `root:docker 0660`).
    pub fn special_owned(
        mut self,
        path: impl AsRef<Path>,
        kind: FileKind,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> FakeFiles {
        let meta = FileMeta {
            uid,
            gid,
            ..FakeFiles::meta(kind, mode, 0, 1)
        };
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: None,
                target: None,
            },
        );
        self
    }

    /// A non-regular entry (symlink, FIFO, socket, device).
    pub fn special(mut self, path: impl AsRef<Path>, kind: FileKind) -> FakeFiles {
        let meta = FakeFiles::meta(kind, 0o777, 0, 1);
        self.insert(
            path.as_ref(),
            FakeNode {
                meta,
                data: Vec::new(),
                error: None,
                target: None,
            },
        );
        self
    }
}

impl FileRepository for FakeFiles {
    fn metadata(&self, path: &Path) -> Result<FileMeta, FsError> {
        self.nodes
            .get(path)
            .map(|n| n.meta)
            .ok_or(FsError::NotFound)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, FsError> {
        let node = self.nodes.get(path).ok_or(FsError::NotFound)?;
        match node.meta.kind {
            FileKind::Dir => {}
            FileKind::Symlink => return Err(FsError::Symlink),
            _ => return Err(FsError::NotFound),
        }
        if let Some(e) = &node.error {
            return Err(e.clone());
        }
        Ok(self
            .nodes
            .iter()
            .filter(|(p, _)| p.parent() == Some(path))
            .filter_map(|(p, n)| {
                Some(DirEntry {
                    name: p.file_name()?.to_os_string(),
                    meta: n.meta,
                })
            })
            .collect())
    }

    fn read_file(&self, path: &Path, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError> {
        let node = self.nodes.get(path).ok_or(FsError::NotFound)?;
        if let Some(e) = &node.error {
            return Err(e.clone());
        }
        match node.meta.kind {
            FileKind::File => {}
            FileKind::Symlink => return Err(FsError::Symlink),
            kind => return Err(FsError::NotRegular { kind }),
        }
        if node.meta.size > max_size {
            return Err(FsError::TooLarge {
                size: node.meta.size,
            });
        }
        Ok((node.meta, SecretBuf::copy_from(&node.data)))
    }

    fn metadata_followed(&self, path: &Path) -> Result<FileMeta, FsError> {
        self.metadata(&self.resolve(path)?)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError> {
        let node = self.nodes.get(path).ok_or(FsError::NotFound)?;
        node.target.clone().ok_or(FsError::Io {
            message: "Invalid argument".into(),
        })
    }

    fn read_file_within(
        &self,
        root: &Path,
        rel: &Path,
        max_size: u64,
    ) -> Result<(FileMeta, SecretBuf), FsError> {
        let path = self.resolve_within(root, rel)?;
        if path == root {
            return Err(FsError::NotRegular {
                kind: FileKind::Dir,
            });
        }
        self.read_file(&path, max_size)
    }

    fn metadata_within(&self, root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
        self.metadata(&self.resolve_within(root, rel)?)
    }
}

/// A fake environment.
#[derive(Default)]
pub struct FakeEnv {
    vars: BTreeMap<OsString, Vec<u8>>,
}

impl FakeEnv {
    pub fn new() -> FakeEnv {
        FakeEnv::default()
    }

    pub fn var(mut self, name: impl AsRef<OsStr>, value: impl AsRef<[u8]>) -> FakeEnv {
        self.vars
            .insert(name.as_ref().to_os_string(), value.as_ref().to_vec());
        self
    }
}

impl EnvRepository for FakeEnv {
    fn names(&self) -> Vec<OsString> {
        self.vars.keys().cloned().collect()
    }

    fn value(&self, name: &OsStr) -> Option<SecretBuf> {
        self.vars.get(name).map(|v| SecretBuf::copy_from(v))
    }

    fn setting(&self, name: &str) -> Option<String> {
        self.vars
            .get(OsStr::new(name))
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }
}

/// A fake process: uid 1000 (group `user`) in `/home/user`, working in
/// `/work`.
pub struct FakeSystem {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    /// The group database.
    pub group_names: BTreeMap<u32, String>,
    pub home: Option<PathBuf>,
    pub cwd: PathBuf,
    pub now: i64,
    pub pid: u32,
    /// Fake `/proc`: pid → (comm, environ). A `None` environ means it exists
    /// but is not readable (another user, non-dumpable).
    pub processes: BTreeMap<u32, (Option<String>, Option<Vec<u8>>)>,
}

impl Default for FakeSystem {
    fn default() -> Self {
        FakeSystem {
            uid: FAKE_UID,
            euid: FAKE_UID,
            gid: FAKE_GID,
            groups: vec![FAKE_GID],
            group_names: BTreeMap::from([(0, "root".to_string()), (FAKE_GID, "user".to_string())]),
            home: Some(PathBuf::from("/home/user")),
            cwd: PathBuf::from("/work"),
            now: FAKE_NOW,
            pid: 100,
            processes: BTreeMap::new(),
        }
    }
}

impl FakeSystem {
    /// Adds a fake process with a readable environment.
    pub fn process(mut self, pid: u32, comm: &str, environ: impl AsRef<[u8]>) -> FakeSystem {
        self.processes.insert(
            pid,
            (Some(comm.to_string()), Some(environ.as_ref().to_vec())),
        );
        self
    }

    /// Adds a fake process whose environment cannot be read.
    pub fn process_unreadable(mut self, pid: u32, comm: &str) -> FakeSystem {
        self.processes.insert(pid, (Some(comm.to_string()), None));
        self
    }
}

impl SystemRepository for FakeSystem {
    fn uid(&self) -> u32 {
        self.uid
    }
    fn euid(&self) -> u32 {
        self.euid
    }
    fn gid(&self) -> u32 {
        self.gid
    }
    fn groups(&self) -> Vec<u32> {
        self.groups.clone()
    }
    fn group_name(&self, gid: u32) -> Option<String> {
        self.group_names.get(&gid).cloned()
    }
    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }
    fn current_dir(&self) -> Result<PathBuf, FsError> {
        Ok(self.cwd.clone())
    }
    fn now(&self) -> i64 {
        self.now
    }
    fn pid(&self) -> u32 {
        self.pid
    }
    fn processes(&self) -> Vec<ProcInfo> {
        self.processes
            .iter()
            .map(|(&pid, (comm, _))| ProcInfo {
                pid,
                comm: comm.clone(),
            })
            .collect()
    }
    fn read_proc_environ(&self, pid: u32, max: u64) -> Result<SecretBuf, FsError> {
        match self.processes.get(&pid) {
            Some((_, Some(bytes))) => {
                let n = bytes.len().min(usize::try_from(max).unwrap_or(usize::MAX));
                Ok(SecretBuf::copy_from(&bytes[..n]))
            }
            Some((_, None)) => Err(FsError::PermissionDenied),
            None => Err(FsError::NotFound),
        }
    }
}

/// Fake config files.
#[derive(Default)]
pub struct FakeConfig {
    files: BTreeMap<PathBuf, String>,
}

impl FakeConfig {
    pub fn new() -> FakeConfig {
        FakeConfig::default()
    }

    pub fn file(mut self, path: impl AsRef<Path>, text: &str) -> FakeConfig {
        self.files
            .insert(path.as_ref().to_path_buf(), text.to_string());
        self
    }
}

impl ConfigRepository for FakeConfig {
    fn read(&self, path: &Path) -> Result<SecretBuf, FsError> {
        self.files
            .get(path)
            .map(|t| SecretBuf::copy_from(t.as_bytes()))
            .ok_or(FsError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_tree() {
        let fs = FakeFiles::new()
            .file("/h/.ssh/id", "KEY")
            .special("/h/.ssh/link", FileKind::Symlink)
            .unreadable("/h/.ssh/locked");
        let mut names: Vec<_> = fs
            .read_dir(Path::new("/h/.ssh"))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, ["id", "link", "locked"]);
        assert_eq!(fs.metadata(Path::new("/h")).unwrap().kind, FileKind::Dir);
        let (_, buf) = fs.read_file(Path::new("/h/.ssh/id"), 10).unwrap();
        assert_eq!(buf.expose(), b"KEY");
        assert_eq!(
            fs.read_file(Path::new("/h/.ssh/link"), 10).err(),
            Some(FsError::Symlink)
        );
        assert_eq!(
            fs.read_file(Path::new("/h/.ssh/locked"), 10).err(),
            Some(FsError::PermissionDenied)
        );
        assert_eq!(
            fs.read_file(Path::new("/h/.ssh/id"), 2).err(),
            Some(FsError::TooLarge { size: 3 })
        );
    }
}
