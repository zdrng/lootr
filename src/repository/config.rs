//! Reads config files from the local disk. Configs are trusted (they are
//! code, see README), so a symlink at the path is followed; only regular
//! files up to [`MAX_CONFIG_SIZE`] are read, never a FIFO or device (a
//! `--config` pointing at one must not block or have side effects).
//!
//! The text is returned in a [`SecretBuf`]: a mistaken `--config .env` or
//! `include = ["~/.git-credentials"]` must not leave the file's secrets in
//! an unwiped buffer (the TOML parser's own strings remain, see
//! docs/threat-model.md).

use std::path::Path;

use crate::domain::model::FsError;
use crate::domain::secret::SecretBuf;
use crate::os::open;
use crate::repository::ConfigRepository;

pub const MAX_CONFIG_SIZE: u64 = 1 << 20;

pub struct RealConfig;

impl ConfigRepository for RealConfig {
    fn read(&self, path: &Path) -> Result<SecretBuf, FsError> {
        open::read_followed(path, MAX_CONFIG_SIZE).map(|(_, buf)| buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::FileKind;

    #[test]
    fn reads_regular_files_and_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lootr.toml");
        #[allow(clippy::disallowed_methods)]
        std::fs::write(&p, "version = 1\n").unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(RealConfig.read(&p).unwrap().expose(), b"version = 1\n");
        assert_eq!(RealConfig.read(&link).unwrap().expose(), b"version = 1\n");
        assert_eq!(
            RealConfig.read(dir.path()).err(),
            Some(FsError::NotRegular {
                kind: FileKind::Dir
            })
        );
    }

    /// A FIFO is refused without opening it (opening a FIFO for reading
    /// blocks until a writer appears).
    #[test]
    #[allow(clippy::disallowed_types, clippy::disallowed_methods)] // test setup only
    fn fifos_are_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&p).status();
        if !made.is_ok_and(|s| s.success()) {
            return; // no mkfifo on this system
        }
        assert_eq!(
            RealConfig.read(&p).err(),
            Some(FsError::NotRegular {
                kind: FileKind::Fifo
            })
        );
    }
}
