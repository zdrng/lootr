//! Git context of a file without running git: is it inside a work tree, and
//! do the repository's ignore files ignore it?
//!
//! - The work tree root is the nearest parent directory containing `.git`
//!   (a directory, or a file for worktrees and submodules).
//! - Ignore rules come from `<root>/.git/info/exclude` and every
//!   `.gitignore` from the root down to the file's directory, with
//!   gitignore precedence (deeper files win, the last match wins, files
//!   below an ignored directory are ignored).
//! - Not considered: the global excludes file (`core.excludesFile`, it is
//!   per machine; a file is only safe if the repository ignores it for
//!   everyone) and the index (a tracked file stays tracked even if a
//!   pattern matches it later).
//!
//! Everything is read through the [`FileRepository`] and cached per
//! directory for one scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::domain::gitignore::{IgnoreRule, decide, parse};
use crate::repository::FileRepository;

/// Largest ignore file that is read.
const MAX_IGNORE_FILE: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GitInfo {
    pub in_repo: bool,
    pub ignored: bool,
}

pub struct GitInspector<'a> {
    files: &'a dyn FileRepository,
    /// Directory → work tree root (or none).
    roots: HashMap<PathBuf, Option<PathBuf>>,
    /// Ignore file → its rules.
    rules: HashMap<PathBuf, Vec<IgnoreRule>>,
}

impl<'a> GitInspector<'a> {
    pub fn new(files: &'a dyn FileRepository) -> GitInspector<'a> {
        GitInspector {
            files,
            roots: HashMap::new(),
            rules: HashMap::new(),
        }
    }

    /// The git context of the file at `path` (absolute).
    pub fn inspect(&mut self, path: &Path) -> GitInfo {
        let Some(dir) = path.parent() else {
            return GitInfo::default();
        };
        let Some(root) = self.root(dir) else {
            return GitInfo::default();
        };
        let Ok(relative) = path.strip_prefix(&root) else {
            return GitInfo::default();
        };
        // Inside `.git` itself nothing is "ignored".
        if relative.starts_with(".git") {
            return GitInfo {
                in_repo: true,
                ignored: false,
            };
        }
        let mut sources = vec![root.join(".git/info/exclude")];
        let mut current = root.clone();
        let components: Vec<_> = relative.components().collect();
        let mut ignored = false;
        for (i, c) in components.iter().enumerate() {
            sources.push(current.join(".gitignore"));
            current.push(c);
            let is_dir = i + 1 < components.len();
            for s in &sources {
                self.load(s);
            }
            let rules = sources.iter().filter_map(|s| self.rules.get(s)).flatten();
            if decide(rules, &current.to_string_lossy(), is_dir) == Some(true) {
                // An ignored directory hides everything below it.
                ignored = true;
                break;
            }
        }
        GitInfo {
            in_repo: true,
            ignored,
        }
    }

    fn root(&mut self, dir: &Path) -> Option<PathBuf> {
        if let Some(cached) = self.roots.get(dir) {
            return cached.clone();
        }
        let found = if self.files.metadata(&dir.join(".git")).is_ok() {
            Some(dir.to_path_buf())
        } else {
            dir.parent().and_then(|p| self.root(p))
        };
        self.roots.insert(dir.to_path_buf(), found.clone());
        found
    }

    fn load(&mut self, file: &Path) {
        if self.rules.contains_key(file) {
            return;
        }
        let rules = match self.files.read_file(file, MAX_IGNORE_FILE) {
            Ok((_, buf)) => {
                // `.git/info/exclude` patterns are relative to the root.
                let dir = if file.ends_with(".git/info/exclude") {
                    file.parent().and_then(Path::parent).and_then(Path::parent)
                } else {
                    file.parent()
                };
                let dir = dir.map(|d| d.to_string_lossy().into_owned());
                parse(
                    dir.as_deref().unwrap_or("/"),
                    &String::from_utf8_lossy(buf.expose()),
                )
            }
            Err(_) => Vec::new(),
        };
        self.rules.insert(file.to_path_buf(), rules);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::fake::FakeFiles;

    fn check(files: &FakeFiles, path: &str) -> (bool, bool) {
        let info = GitInspector::new(files).inspect(Path::new(path));
        (info.in_repo, info.ignored)
    }

    #[test]
    fn outside_a_repository() {
        let files = FakeFiles::new().file("/w/.env", "A=1");
        assert_eq!(check(&files, "/w/.env"), (false, false));
    }

    #[test]
    fn ignore_files_and_precedence() {
        let files = FakeFiles::new()
            .dir("/w/repo/.git/objects")
            .file("/w/repo/.git/info/exclude", "*.local\n")
            .file("/w/repo/.gitignore", ".env*\n!.env.example\nbuild/\n")
            .file("/w/repo/app/.gitignore", "!.env.keep\n")
            .file("/w/repo/.env", "")
            .file("/w/repo/.env.example", "")
            .file("/w/repo/app/.env.keep", "")
            .file("/w/repo/app/x.local", "")
            .file("/w/repo/app/config.env", "")
            .file("/w/repo/build/.env.keep", "");
        assert_eq!(check(&files, "/w/repo/.env"), (true, true));
        assert_eq!(check(&files, "/w/repo/.env.example"), (true, false));
        assert_eq!(check(&files, "/w/repo/app/.env.keep"), (true, false));
        assert_eq!(check(&files, "/w/repo/app/x.local"), (true, true));
        assert_eq!(check(&files, "/w/repo/app/config.env"), (true, false));
        // A file below an ignored directory cannot be re-included.
        assert_eq!(check(&files, "/w/repo/build/.env.keep"), (true, true));
        assert_eq!(check(&files, "/w/repo/.git/config"), (true, false));
    }

    #[test]
    fn nearest_git_wins_and_git_files_count() {
        let files = FakeFiles::new()
            .dir("/r/.git")
            .file("/r/.gitignore", "sub/\n")
            .file("/r/sub/.git", "gitdir: ../.git/modules/sub\n")
            .file("/r/sub/.env", "");
        // The submodule is its own work tree; the outer ignore file does not
        // apply inside it.
        assert_eq!(check(&files, "/r/sub/.env"), (true, false));
    }
}
