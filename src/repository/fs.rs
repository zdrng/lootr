//! Real file access through `os::open` (secure open, `lstat`, listing).

use std::path::{Path, PathBuf};

use crate::domain::model::{FileMeta, FsError};
use crate::domain::secret::SecretBuf;
use crate::os::open;
use crate::repository::{DirEntry, FileRepository};

pub struct RealFiles;

impl FileRepository for RealFiles {
    fn metadata(&self, path: &Path) -> Result<FileMeta, FsError> {
        open::lstat(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, FsError> {
        let entries = open::read_dir(path)?;
        Ok(entries
            .into_iter()
            .map(|(name, meta)| DirEntry { name, meta })
            .collect())
    }

    fn read_file(&self, path: &Path, max_size: u64) -> Result<(FileMeta, SecretBuf), FsError> {
        open::read_regular(path, max_size)
    }

    fn metadata_beneath(&self, root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
        open::metadata_beneath(root, rel)
    }

    fn read_dir_beneath(&self, root: &Path, rel: &Path) -> Result<Vec<DirEntry>, FsError> {
        let entries = open::read_dir_beneath(root, rel)?;
        Ok(entries
            .into_iter()
            .map(|(name, meta)| DirEntry { name, meta })
            .collect())
    }

    fn read_file_beneath(
        &self,
        root: &Path,
        rel: &Path,
        max_size: u64,
    ) -> Result<(FileMeta, SecretBuf), FsError> {
        open::read_regular_beneath(root, rel, max_size)
    }

    fn metadata_followed(&self, path: &Path) -> Result<FileMeta, FsError> {
        open::stat_followed(path)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError> {
        open::read_link(path)
    }

    fn read_file_within(
        &self,
        root: &Path,
        rel: &Path,
        max_size: u64,
    ) -> Result<(FileMeta, SecretBuf), FsError> {
        open::read_regular_within(root, rel, max_size)
    }

    fn metadata_within(&self, root: &Path, rel: &Path) -> Result<FileMeta, FsError> {
        open::metadata_within(root, rel)
    }
}
