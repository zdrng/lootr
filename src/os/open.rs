//! Secure file access.
//!
//! - Files are opened with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY`
//!   after an `lstat` check, and judged by `fstat` on the descriptor, not the
//!   path (no TOCTOU between check and read). Only regular files are read;
//!   symlinks, FIFOs, sockets and devices are reported by metadata only.
//! - The size is checked on the descriptor before reading; the buffer is
//!   allocated once with that size (capped by `max-file-size`) and never
//!   grows.
//! - Directories are listed through a descriptor opened with `O_NOFOLLOW`,
//!   and entries are `lstat`ed relative to it (`fstatat` with
//!   `AT_SYMLINK_NOFOLLOW`).
//!
//! `O_NOFOLLOW` only covers the last path component. The `*_beneath`
//! functions close the parent-directory gap: they open a trusted `root` (a
//! source's literal prefix, operator-controlled) by path and then resolve
//! each component of the relative part with `openat` and `O_NOFOLLOW`, so a
//! symlink planted in any directory below `root` between discovery and open
//! is refused rather than followed. rustix's `openat` is a safe wrapper, so
//! this keeps `#![forbid(unsafe_code)]`.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path};

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::domain::model::{FileKind, FileMeta, FsError};
use crate::domain::secret::SecretBuf;

const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY);

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// `lstat`: metadata of `path` itself, never following a symlink.
pub fn lstat(path: &Path) -> Result<FileMeta, FsError> {
    rustix::fs::lstat(path)
        .map(|st| meta(&st))
        .map_err(fs_error)
}

/// Reads a regular file into a [`SecretBuf`] of at most `max_size` bytes.
pub fn read_regular(path: &Path, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError> {
    // Never open anything that is not a regular file: opening a device can
    // have side effects.
    let pre = lstat(path)?;
    check_regular(&pre)?;
    let fd = rustix::fs::open(path, READ_FLAGS, Mode::empty()).map_err(fs_error)?;
    read_open(&fd, max_size)
}

/// Reads an open descriptor: `fstat` (it must be a regular file of at most
/// `max_size` bytes), then the contents into a buffer of exactly that size.
fn read_open(fd: &OwnedFd, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError> {
    let file_meta = meta(&rustix::fs::fstat(fd).map_err(fs_error)?);
    check_regular(&file_meta)?;
    if file_meta.size > max_size {
        return Err(FsError::TooLarge {
            size: file_meta.size,
        });
    }
    let capacity = usize::try_from(file_meta.size).map_err(|_| FsError::TooLarge {
        size: file_meta.size,
    })?;
    let mut buf = SecretBuf::with_capacity(capacity);
    // A file that grew after fstat is cut at its size then.
    buf.fill_with(|out| {
        loop {
            match rustix::io::read(fd, &mut *out) {
                Err(Errno::INTR) => continue,
                other => return other,
            }
        }
    })
    .map_err(fs_error)?;
    Ok((file_meta, buf))
}

/// Reads a config file: like [`read_regular`], but a symlink at `path` is
/// followed (configs are trusted, see `repository::config`). `stat` first,
/// so a FIFO or device is never opened; the open has `O_NONBLOCK` and the
/// descriptor is checked again (a swap after `stat` cannot make the read
/// block or read a device).
pub fn read_followed(path: &Path, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError> {
    let pre = rustix::fs::stat(path)
        .map(|st| meta(&st))
        .map_err(fs_error)?;
    check_regular(&pre)?;
    let flags = OFlags::RDONLY
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOCTTY);
    let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(fs_error)?;
    read_open(&fd, max_size)
}

/// Entries of a directory with their `lstat` metadata, without following a
/// symlink at `path` or in the entries. Entries that vanish while listing are
/// left out.
pub fn read_dir(path: &Path) -> Result<Vec<(OsString, FileMeta)>, FsError> {
    list_fd(&open_dir(path)?)
}

/// Lists an already-open directory descriptor (entries `fstatat`ed relative
/// to it, so no path is re-resolved).
fn list_fd(fd: &OwnedFd) -> Result<Vec<(OsString, FileMeta)>, FsError> {
    let dir = Dir::read_from(fd).map_err(fs_error)?;
    let mut out = Vec::new();
    for entry in dir {
        let entry = entry.map_err(fs_error)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if let Ok(st) = rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            out.push((OsString::from_vec(name.to_bytes().to_vec()), meta(&st)));
        }
    }
    Ok(out)
}

/// Opens a directory with `O_NOFOLLOW | O_DIRECTORY`; a symlink gives ELOOP
/// (Linux) or ENOTDIR (macOS), reported as [`FsError::Symlink`].
fn open_dir(path: &Path) -> Result<OwnedFd, FsError> {
    match rustix::fs::open(path, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::NOTDIR | Errno::LOOP) => Err(match lstat(path)?.kind {
            FileKind::Symlink => FsError::Symlink,
            kind => FsError::NotRegular { kind },
        }),
        Err(e) => Err(fs_error(e)),
    }
}

/// Normal components of `rel`, or `None` if it has a `..`, root or prefix
/// component (the caller then falls back to a plain path-based open).
fn normal_components(rel: &Path) -> Option<Vec<&OsStr>> {
    let mut out = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

/// Opens `root` by path (trusted prefix), then each name in `comps` with
/// `openat` and `O_NOFOLLOW | O_DIRECTORY`.
fn descend(root: &Path, comps: &[&OsStr]) -> Result<OwnedFd, FsError> {
    let mut fd = open_dir(root)?;
    for name in comps {
        fd = match rustix::fs::openat(&fd, *name, DIR_FLAGS, Mode::empty()) {
            Ok(child) => child,
            Err(e) => return Err(error_at(&fd, name, e)),
        };
    }
    Ok(fd)
}

/// Maps an `openat` error for `name` under `dirfd`, telling a symlink from a
/// non-directory (via `fstatat`, which does not follow symlinks).
fn error_at(dirfd: &OwnedFd, name: &OsStr, e: Errno) -> FsError {
    match e {
        Errno::NOTDIR | Errno::LOOP => {
            match rustix::fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => match meta(&st).kind {
                    FileKind::Symlink => FsError::Symlink,
                    kind => FsError::NotRegular { kind },
                },
                Err(e) => fs_error(e),
            }
        }
        _ => fs_error(e),
    }
}

/// [`lstat`] of `root/rel`, resolving `rel` component by component below the
/// trusted `root` (parent-symlink safe).
pub fn metadata_beneath(root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
    let Some(comps) = normal_components(rel) else {
        return lstat(&root.join(rel));
    };
    let Some((last, parents)) = comps.split_last() else {
        return lstat(root);
    };
    let dirfd = descend(root, parents)?;
    rustix::fs::statat(&dirfd, *last, AtFlags::SYMLINK_NOFOLLOW)
        .map(|st| meta(&st))
        .map_err(fs_error)
}

/// [`read_dir`] of `root/rel`, resolving `rel` below the trusted `root`.
pub fn read_dir_beneath(root: &Path, rel: &Path) -> Result<Vec<(OsString, FileMeta)>, FsError> {
    let Some(comps) = normal_components(rel) else {
        return read_dir(&root.join(rel));
    };
    if comps.is_empty() {
        return read_dir(root);
    }
    list_fd(&descend(root, &comps)?)
}

/// [`read_regular`] of `root/rel`, resolving `rel` below the trusted `root`.
pub fn read_regular_beneath(
    root: &Path,
    rel: &Path,
    max_size: u64,
) -> Result<(FileMeta, SecretBuf), FsError> {
    let Some(comps) = normal_components(rel) else {
        return read_regular(&root.join(rel), max_size);
    };
    let Some((last, parents)) = comps.split_last() else {
        return read_regular(root, max_size);
    };
    let dirfd = descend(root, parents)?;
    let pre = rustix::fs::statat(&dirfd, *last, AtFlags::SYMLINK_NOFOLLOW)
        .map(|st| meta(&st))
        .map_err(fs_error)?;
    check_regular(&pre)?;
    let fd = match rustix::fs::openat(&dirfd, *last, READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => return Err(error_at(&dirfd, last, e)),
    };
    read_open(&fd, max_size)
}

/// Reads a `/proc` pseudo-file (`environ`, `comm`, `cmdline`) into a
/// [`SecretBuf`]. These files report size 0 in `fstat`, so [`read_regular`]
/// (which allocates the stat size and trusts it) cannot read them; here the
/// buffer is `max` bytes and filled until end of file. Opened with
/// `O_NOFOLLOW | O_CLOEXEC`; `environ` contents are secret.
pub fn read_proc(path: &Path, max: u64) -> Result<SecretBuf, FsError> {
    let flags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOCTTY);
    let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(fs_error)?;
    let capacity = usize::try_from(max).unwrap_or(usize::MAX);
    let mut buf = SecretBuf::with_capacity(capacity);
    buf.fill_with(|out| {
        loop {
            match rustix::io::read(&fd, &mut *out) {
                Err(Errno::INTR) => continue,
                other => return other,
            }
        }
    })
    .map_err(fs_error)?;
    Ok(buf)
}

/// `stat`: metadata of what `path` points to, following symlinks. Nothing
/// is opened.
pub fn stat_followed(path: &Path) -> Result<FileMeta, FsError> {
    rustix::fs::stat(path).map(|st| meta(&st)).map_err(fs_error)
}

/// The target of the symlink at `path` (`readlink`), unresolved.
pub fn read_link(path: &Path) -> Result<std::path::PathBuf, FsError> {
    let target = rustix::fs::readlink(path, Vec::new()).map_err(fs_error)?;
    Ok(std::path::PathBuf::from(OsString::from_vec(
        target.into_bytes(),
    )))
}

/// Most symlinks [`resolve_within`] follows for one path.
pub const MAX_LINKS_WITHIN: usize = 8;

/// Resolves `rel` below `root` like [`descend`], but follows a symlink when
/// its target is relative and stays below `root` (`token -> ..data/token`,
/// `..data -> ..2024_01_01_00_00_00.1`, the layout of Kubernetes projected
/// volumes). Absolute targets, targets that climb above `root` and more
/// than [`MAX_LINKS_WITHIN`] links are refused ([`FsError::Symlink`]).
/// Every step is an `openat`/`fstatat`/`readlinkat` relative to a held
/// descriptor, so nothing outside `root` is ever opened. Returns the
/// directory holding the final entry, its name and its `lstat` metadata
/// (never a symlink).
fn resolve_within(root: &Path, rel: &Path) -> Result<(OwnedFd, OsString, FileMeta), FsError> {
    use std::collections::VecDeque;
    let Some(comps) = normal_components(rel) else {
        return Err(FsError::Symlink);
    };
    let mut pending: VecDeque<OsString> = comps.into_iter().map(OsStr::to_os_string).collect();
    let mut dirs: Vec<OwnedFd> = vec![open_dir(root)?];
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            if dirs.len() == 1 {
                return Err(FsError::Symlink); // above `root`
            }
            dirs.pop();
            continue;
        }
        if name == "." || name.is_empty() {
            continue;
        }
        let dirfd = dirs.last().ok_or(FsError::NotFound)?;
        let st = meta(
            &rustix::fs::statat(dirfd, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(fs_error)?,
        );
        match st.kind {
            FileKind::Symlink => {
                links += 1;
                if links > MAX_LINKS_WITHIN {
                    return Err(FsError::Symlink);
                }
                let target = rustix::fs::readlinkat(dirfd, name.as_os_str(), Vec::new())
                    .map_err(fs_error)?;
                let target = std::path::PathBuf::from(OsString::from_vec(target.into_bytes()));
                if target.is_absolute() {
                    return Err(FsError::Symlink);
                }
                for c in target.components().rev() {
                    match c {
                        Component::Normal(n) => pending.push_front(n.to_os_string()),
                        Component::ParentDir => pending.push_front(OsString::from("..")),
                        Component::CurDir => {}
                        _ => return Err(FsError::Symlink),
                    }
                }
            }
            FileKind::Dir if !pending.is_empty() => {
                let child = rustix::fs::openat(dirfd, name.as_os_str(), DIR_FLAGS, Mode::empty())
                    .map_err(|e| error_at(dirfd, &name, e))?;
                dirs.push(child);
            }
            _ if pending.is_empty() => {
                let dirfd = dirs.pop().ok_or(FsError::NotFound)?;
                return Ok((dirfd, name, st));
            }
            _ => return Err(FsError::NotFound),
        }
    }
    // `rel` named `root` itself or ended in `..`.
    Err(FsError::NotRegular {
        kind: FileKind::Dir,
    })
}

/// [`lstat`] of `root/rel`, following symlinks that stay below `root`
/// (see [`resolve_within`]).
pub fn metadata_within(root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
    resolve_within(root, rel).map(|(_, _, m)| m)
}

/// [`read_regular`] of `root/rel`, following symlinks that stay below
/// `root` (see [`resolve_within`]).
pub fn read_regular_within(
    root: &Path,
    rel: &Path,
    max_size: u64,
) -> Result<(FileMeta, SecretBuf), FsError> {
    let (dirfd, name, pre) = resolve_within(root, rel)?;
    check_regular(&pre)?;
    let fd = match rustix::fs::openat(&dirfd, name.as_os_str(), READ_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => return Err(error_at(&dirfd, &name, e)),
    };
    read_open(&fd, max_size)
}

/// Creates (or replaces the contents of) the report file, never through a
/// symlink. An existing path must be a regular file owned by the effective
/// user: anything else (a FIFO, a device, another user's file) is refused
/// before it is opened or truncated (`lstat` first, `fstat` on the
/// descriptor again). The mode is set to 0600 on the descriptor, so a file
/// that existed with a wider mode does not keep it; only then is it
/// truncated.
pub fn create_report(path: &Path) -> Result<File, FsError> {
    match lstat(path) {
        Ok(pre) => check_report_target(&pre)?,
        Err(FsError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let flags = OFlags::WRONLY
        | OFlags::CREATE
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | OFlags::NOCTTY;
    let fd = rustix::fs::open(path, flags, Mode::from_raw_mode(0o600)).map_err(fs_error)?;
    check_report_target(&meta(&rustix::fs::fstat(&fd).map_err(fs_error)?))?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(fs_error)?;
    rustix::fs::ftruncate(&fd, 0).map_err(fs_error)?;
    Ok(File::from(fd))
}

/// The report may only replace a regular file of the effective user.
fn check_report_target(m: &FileMeta) -> Result<(), FsError> {
    check_regular(m)?;
    if m.uid != rustix::process::geteuid().as_raw() {
        return Err(FsError::PermissionDenied);
    }
    Ok(())
}

fn check_regular(meta: &FileMeta) -> Result<(), FsError> {
    match meta.kind {
        FileKind::File => Ok(()),
        FileKind::Symlink => Err(FsError::Symlink),
        kind => Err(FsError::NotRegular { kind }),
    }
}

/// Converts `stat` fields; their integer types differ between platforms.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn meta(st: &Stat) -> FileMeta {
    let kind = match FileType::from_raw_mode(st.st_mode as _) {
        FileType::RegularFile => FileKind::File,
        FileType::Directory => FileKind::Dir,
        FileType::Symlink => FileKind::Symlink,
        FileType::Fifo => FileKind::Fifo,
        FileType::Socket => FileKind::Socket,
        FileType::CharacterDevice => FileKind::CharDevice,
        FileType::BlockDevice => FileKind::BlockDevice,
        FileType::Unknown => FileKind::Unknown,
    };
    FileMeta {
        kind,
        mode: (st.st_mode as u32) & 0o7777,
        uid: st.st_uid as u32,
        gid: st.st_gid as u32,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mtime: st.st_mtime as i64,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    }
}

fn fs_error(e: Errno) -> FsError {
    match e {
        Errno::NOENT | Errno::NOTDIR => FsError::NotFound,
        Errno::ACCESS | Errno::PERM => FsError::PermissionDenied,
        // O_NOFOLLOW on a symlink.
        Errno::LOOP => FsError::Symlink,
        e => FsError::Io {
            message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[allow(clippy::disallowed_methods)]
    fn write(path: &Path, data: &[u8]) {
        std::fs::write(path, data).unwrap();
    }

    #[test]
    fn beneath_reads_through_real_directories_but_refuses_a_parent_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        write(&root.join("a/b/secret"), b"value");
        // The ordinary case resolves exactly like a path open.
        let (_, buf) = read_regular_beneath(root, Path::new("a/b/secret"), 100).unwrap();
        assert_eq!(buf.expose(), b"value");
        assert_eq!(
            metadata_beneath(root, Path::new("a/b/secret"))
                .unwrap()
                .kind,
            FileKind::File
        );
        assert!(read_dir_beneath(root, Path::new("a")).is_ok());

        // Swap the parent directory `a` for a symlink to an attacker tree:
        // every `*_beneath` call must refuse to follow it.
        let evil = dir.path().join("evil");
        std::fs::create_dir_all(evil.join("b")).unwrap();
        write(&evil.join("b/secret"), b"attacker");
        std::fs::remove_dir_all(root.join("a")).unwrap();
        symlink(&evil, root.join("a")).unwrap();
        assert_eq!(
            read_regular_beneath(root, Path::new("a/b/secret"), 100).err(),
            Some(FsError::Symlink)
        );
        assert_eq!(
            read_dir_beneath(root, Path::new("a/b")).err(),
            Some(FsError::Symlink)
        );
        assert_eq!(
            metadata_beneath(root, Path::new("a/b/secret")).err(),
            Some(FsError::Symlink)
        );
    }

    /// The Kubernetes projected-volume layout: `token -> ..data/token`,
    /// `..data -> ..<timestamp>`. Links that stay below the root are
    /// followed; absolute links, links above the root and loops are not.
    #[test]
    fn within_follows_links_that_stay_below_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sa");
        std::fs::create_dir_all(root.join("..2024_01_01.1")).unwrap();
        write(&root.join("..2024_01_01.1/token"), b"tok");
        symlink("..2024_01_01.1", root.join("..data")).unwrap();
        symlink("..data/token", root.join("token")).unwrap();
        let (m, buf) = read_regular_within(&root, Path::new("token"), 100).unwrap();
        assert_eq!(buf.expose(), b"tok");
        assert_eq!(m.kind, FileKind::File);
        assert_eq!(
            metadata_within(&root, Path::new("token")).unwrap().ino,
            lstat(&root.join("..2024_01_01.1/token")).unwrap().ino
        );

        write(&dir.path().join("outside"), b"secret");
        symlink(dir.path().join("outside"), root.join("abs")).unwrap();
        symlink("../outside", root.join("up")).unwrap();
        symlink("..data/../../outside", root.join("up2")).unwrap();
        symlink("loop", root.join("loop")).unwrap();
        symlink("..2024_01_01.1", root.join("dir")).unwrap();
        for name in ["abs", "up", "up2", "loop"] {
            assert_eq!(
                read_regular_within(&root, Path::new(name), 100).err(),
                Some(FsError::Symlink),
                "{name}"
            );
        }
        assert_eq!(
            read_regular_within(&root, Path::new("dir"), 100).err(),
            Some(FsError::NotRegular {
                kind: FileKind::Dir
            })
        );
        assert_eq!(
            read_regular_within(&root, Path::new("missing"), 100).err(),
            Some(FsError::NotFound)
        );
        assert_eq!(
            read_link(&root.join("token")).unwrap(),
            Path::new("..data/token")
        );
        assert_eq!(
            stat_followed(&root.join("token")).unwrap().kind,
            FileKind::File
        );
    }

    #[test]
    fn reads_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write(&p, b"hello");
        let (meta, buf) = read_regular(&p, 100).unwrap();
        assert_eq!(buf.expose(), b"hello");
        assert_eq!(meta.kind, FileKind::File);
        assert_eq!(meta.size, 5);
        assert_eq!(buf.capacity(), 5);
    }

    #[test]
    fn refuses_symlinks_dirs_and_big_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        write(&target, b"0123456789");
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert_eq!(read_regular(&link, 100).err(), Some(FsError::Symlink));
        assert_eq!(
            read_regular(dir.path(), 100).err(),
            Some(FsError::NotRegular {
                kind: FileKind::Dir
            })
        );
        assert_eq!(
            read_regular(&target, 9).err(),
            Some(FsError::TooLarge { size: 10 })
        );
        assert_eq!(
            read_regular(&dir.path().join("missing"), 9).err(),
            Some(FsError::NotFound)
        );
    }

    #[test]
    fn unreadable_files_are_permission_denied() {
        if rustix::process::geteuid().is_root() {
            return; // root reads everything
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        write(&p, b"x");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(read_regular(&p, 10).err(), Some(FsError::PermissionDenied));
    }

    #[test]
    fn lists_directories_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("a"), b"x");
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        symlink(dir.path().join("a"), dir.path().join("l")).unwrap();
        let mut entries = read_dir(dir.path()).unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let kinds: Vec<(String, FileKind)> = entries
            .iter()
            .map(|(n, m)| (n.to_string_lossy().into_owned(), m.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("a".to_string(), FileKind::File),
                ("l".to_string(), FileKind::Symlink),
                ("sub".to_string(), FileKind::Dir),
            ]
        );
        let link = dir.path().join("l2");
        symlink(dir.path().join("sub"), &link).unwrap();
        assert_eq!(read_dir(&link).err(), Some(FsError::Symlink));
    }

    #[test]
    fn report_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("report.json");
        drop(create_report(&p).unwrap());
        assert_eq!(lstat(&p).unwrap().mode, 0o600);
        let link = dir.path().join("link.json");
        symlink(&p, &link).unwrap();
        assert_eq!(create_report(&link).err(), Some(FsError::Symlink));

        // An existing report with a wider mode is tightened and emptied.
        let old = dir.path().join("old.json");
        write(&old, b"previous report contents");
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(create_report(&old).unwrap());
        let m = lstat(&old).unwrap();
        assert_eq!((m.mode, m.size), (0o600, 0));

        // A directory is refused before anything is truncated.
        assert_eq!(
            create_report(dir.path()).err(),
            Some(FsError::NotRegular {
                kind: FileKind::Dir
            })
        );
    }
}
