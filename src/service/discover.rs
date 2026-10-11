//! Discover: expands every source into candidates, without reading any
//! secret.
//!
//! - `env` sources: variable names matching the source's globs.
//! - `file` sources: paths matching the source's globs after `~` and
//!   relative paths are expanded. The walk starts at the longest literal
//!   prefix of the pattern, never follows symlinks, stays on one file system
//!   (`one-file-system`), descends at most as deep as the pattern needs
//!   (`max-depth` for `**`) and prunes everything matching `exclude` (global
//!   and per source). Matching non-regular entries (symlinks, FIFOs, ...)
//!   are candidates too: collect reports them by metadata. Directories are
//!   never candidates of a file source (there is nothing to read).
//! - `probe` sources: one candidate per probe, with every path the source's
//!   `paths` globs matched — **directories included** (the `writable` probe
//!   judges PATH directories and shared caches) — plus every absolute entry
//!   of the `path-vars` environment variables (`PATH`), taken as a literal
//!   path from the [`EnvRepository`] (locations come from config: the
//!   default `path-dirs` source names `PATH`).
//!
//! Nothing a source selects is dropped silently. Reported as skipped (with
//! the directory's path, never anything read from a file):
//!
//! - unreadable directories (`permission_denied`, ...); missing paths are
//!   not reported (a source lists many optional locations);
//! - a directory a `**` pattern would descend into but `max-depth` stops
//!   (`depth_limit`), and one on another file system with
//!   `one-file-system = true` (`other_fs`);
//! - a glob's literal prefix that is a symlink which may not be followed
//!   (`symlink_root`, see below).
//!
//! # Symlinked literal prefix
//!
//! The literal prefix of a glob (`~/.ssh` in `~/.ssh/**`) comes from the
//! config, which is trusted; symlinks in its parent components are already
//! resolved by the kernel. A symlink as its **last** component (dotfile
//! managers: `~/.ssh -> ~/dotfiles/ssh`) is followed once, with checks: the
//! link must be owned by the scanning user or root, its target (relative
//! targets resolved against the link's directory) must be a real directory,
//! not another symlink, and not excluded. The walk then runs below the
//! target with the usual `openat` protection; reported paths keep the
//! configured prefix (`~/.ssh/id_ed25519`). If a check fails, the prefix is
//! reported as skipped (`symlink_root`). Everything below the prefix is
//! never followed.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::domain::config::{FileAction, ScanSettings, Source, SourceKind};
use crate::domain::glob::{Glob, expand_path, is_literal, unescape};
use crate::domain::model::{DisplayPath, FileKind, FileMeta, FsError, Ident, Location, Skipped};
use crate::repository::{EnvRepository, FileRepository, join};

/// What to collect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Env {
        name: Ident,
        os_name: OsString,
    },
    File {
        /// The path as reported (below the configured prefix).
        path: PathBuf,
        /// The source glob's trusted literal prefix (resolved if it was a
        /// followed symlink); `collect` resolves `rel` below it with `openat`
        /// (parent-symlink safe).
        root: PathBuf,
        /// `path` relative to `root` (empty for a literal path).
        rel: PathBuf,
        action: FileAction,
    },
    /// A probe with the paths its source's `paths` globs matched.
    Probe {
        name: Ident,
        paths: Vec<PathBuf>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub source: Ident,
    pub target: Target,
}

#[derive(Default)]
pub struct Discovery {
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<Skipped>,
}

/// Where relative paths and `~` point, and who scans (symlinked literal
/// prefixes must be owned by this user or root).
pub struct Paths<'a> {
    pub home: Option<&'a Path>,
    pub cwd: &'a Path,
    pub uid: u32,
}

/// Where a found path is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Found {
    root: PathBuf,
    rel: PathBuf,
}

pub fn discover(
    sources: &[Source],
    settings: &ScanSettings,
    paths: &Paths<'_>,
    files: &dyn FileRepository,
    env: &dyn EnvRepository,
) -> Discovery {
    let mut out = Discovery::default();
    let global_excludes = compile_globs(&settings.exclude, paths, &mut out, None);
    let ctx = WalkCtx {
        paths,
        settings,
        files,
    };
    let ctx = &ctx;
    for source in sources {
        match &source.kind {
            SourceKind::Env { names } => discover_env(source, names, env, &mut out),
            SourceKind::File {
                paths: patterns,
                exclude,
                action,
            } => {
                let found = find_paths(
                    source,
                    &Patterns {
                        globs: patterns,
                        exclude,
                        literals: &[],
                        include_dirs: false,
                    },
                    &global_excludes,
                    ctx,
                    &mut out,
                );
                out.candidates
                    .extend(found.into_iter().map(|(path, f)| Candidate {
                        source: source.id.clone(),
                        target: Target::File {
                            path,
                            root: f.root,
                            rel: f.rel,
                            action: action.clone(),
                        },
                    }));
            }
            SourceKind::Probe {
                probes,
                paths: patterns,
                exclude,
                path_vars,
            } => {
                let literals = path_var_entries(path_vars, env);
                let found: Vec<PathBuf> = find_paths(
                    source,
                    &Patterns {
                        globs: patterns,
                        exclude,
                        literals: &literals,
                        include_dirs: true,
                    },
                    &global_excludes,
                    ctx,
                    &mut out,
                )
                .into_keys()
                .collect();
                out.candidates.extend(probes.iter().map(|p| Candidate {
                    source: source.id.clone(),
                    target: Target::Probe {
                        name: p.clone(),
                        paths: found.clone(),
                    },
                }));
            }
        }
    }
    // Several globs of one source can prune the same directory.
    let mut seen = std::collections::BTreeSet::new();
    out.skipped
        .retain(|s| seen.insert((s.source.clone(), s.location.clone(), s.reason)));
    out
}

struct WalkCtx<'a> {
    paths: &'a Paths<'a>,
    settings: &'a ScanSettings,
    files: &'a dyn FileRepository,
}

/// What a file or probe source selects.
struct Patterns<'a> {
    globs: &'a [String],
    exclude: &'a [String],
    /// Absolute paths taken literally (not globs), e.g. `PATH` entries.
    literals: &'a [PathBuf],
    /// Matching directories are candidates too (probe sources).
    include_dirs: bool,
}

/// Every path matching one of the globs (or one of the literal paths) and
/// none of the excludes, mapped to where it is read from: the trusted
/// literal prefix (`root`) of the glob that matched it and the rest.
fn find_paths(
    source: &Source,
    patterns: &Patterns<'_>,
    global_excludes: &[Glob],
    ctx: &WalkCtx<'_>,
    out: &mut Discovery,
) -> BTreeMap<PathBuf, Found> {
    let mut excludes = global_excludes.to_vec();
    excludes.extend(compile_globs(
        patterns.exclude,
        ctx.paths,
        out,
        Some(&source.id),
    ));
    let mut found = BTreeMap::new();
    let globs = compile_globs(patterns.globs, ctx.paths, out, Some(&source.id));
    let mut walk = Walk {
        files: ctx.files,
        glob: None,
        excludes: &excludes,
        settings: ctx.settings,
        source: &source.id,
        include_dirs: patterns.include_dirs,
        uid: ctx.paths.uid,
    };
    for glob in &globs {
        walk.glob = Some(glob);
        walk.run(&mut found, &mut out.skipped);
    }
    for path in patterns.literals {
        walk.literal(path, &mut found, &mut out.skipped);
    }
    found
}

/// The absolute entries of `:`-separated directory lists in the named
/// environment variables (`PATH`), in order, without duplicates. Empty and
/// relative entries (which would resolve against whatever the current
/// directory is) and non-UTF-8 entries are left out. The value is read as
/// a secret like every env value; only the directory paths leave it.
fn path_var_entries(names: &[String], env: &dyn EnvRepository) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for name in names {
        let Some(value) = env.value(std::ffi::OsStr::new(name)) else {
            continue;
        };
        for part in value.expose().split(|b| *b == b':') {
            let Ok(text) = std::str::from_utf8(part) else {
                continue;
            };
            let path = PathBuf::from(text);
            if path.is_absolute() && !entries.contains(&path) {
                entries.push(path);
            }
        }
    }
    entries
}

fn discover_env(source: &Source, names: &[String], env: &dyn EnvRepository, out: &mut Discovery) {
    let globs: Vec<Glob> = names.iter().filter_map(|n| Glob::new(n).ok()).collect();
    for os_name in env.names() {
        // Names that are not UTF-8 or not valid identifiers cannot be
        // reported, so they are not scanned.
        let Some(name) = os_name.to_str() else {
            continue;
        };
        if !globs.iter().any(|g| g.matches(name)) {
            continue;
        }
        if let Ok(name) = Ident::from_non_secret(name) {
            out.candidates.push(Candidate {
                source: source.id.clone(),
                target: Target::Env { name, os_name },
            });
        }
    }
}

/// Expands and compiles path globs. Patterns were validated at config load;
/// expansion can still fail (no home directory), which is reported.
fn compile_globs(
    patterns: &[String],
    paths: &Paths<'_>,
    out: &mut Discovery,
    source: Option<&Ident>,
) -> Vec<Glob> {
    let mut globs = Vec::new();
    for p in patterns {
        match expand_path(p, paths.home, paths.cwd)
            .and_then(|e| Glob::new(&e).map_err(|e| e.to_string()))
        {
            Ok(g) => globs.push(g),
            Err(e) => {
                if let Some(source) = source {
                    out.skipped.push(Skipped {
                        source: source.clone(),
                        location: file_location(Path::new(p)),
                        reason: "invalid_path",
                        detail: e,
                    });
                }
            }
        }
    }
    globs
}

struct Walk<'a> {
    files: &'a dyn FileRepository,
    /// The glob being walked ([`Walk::run`]).
    glob: Option<&'a Glob>,
    excludes: &'a [Glob],
    settings: &'a ScanSettings,
    source: &'a Ident,
    /// Directories are candidates too (probe sources).
    include_dirs: bool,
    /// The scanning user (a followed prefix symlink must be theirs or root's).
    uid: u32,
}

/// The directory a walk runs below: `real` is opened, `shown` is what
/// reported paths start with (they differ for a followed prefix symlink).
struct Root<'a> {
    real: &'a Path,
    shown: &'a Path,
}

impl Walk<'_> {
    /// A literal path (not a glob): a candidate if it exists, is not
    /// excluded and is not a directory (unless `include_dirs`).
    fn literal(
        &self,
        path: &Path,
        found: &mut BTreeMap<PathBuf, Found>,
        skipped: &mut Vec<Skipped>,
    ) {
        if self.excluded(path) {
            return;
        }
        match self.files.metadata(path) {
            Ok(meta) => {
                if self.include_dirs || meta.kind != FileKind::Dir {
                    found.insert(path.to_path_buf(), literal_found(path));
                }
            }
            Err(FsError::NotFound) => {}
            Err(e) => skipped.push(self.skip(path, &e)),
        }
    }

    fn run(&self, found: &mut BTreeMap<PathBuf, Found>, skipped: &mut Vec<Skipped>) {
        let Some(glob) = self.glob else {
            return;
        };
        let pattern = glob.pattern();
        let comps: Vec<&str> = pattern
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();
        let literal = comps.iter().take_while(|c| is_literal(c)).count();
        let mut base = PathBuf::from("/");
        for c in &comps[..literal] {
            base.push(unescape(c));
        }
        if self.excluded(&base) {
            return;
        }
        let meta = match self.files.metadata(&base) {
            Ok(m) => m,
            Err(FsError::NotFound) => return,
            Err(e) => {
                skipped.push(self.skip(&base, &e));
                return;
            }
        };
        if literal == comps.len() {
            // A literal path: a candidate whatever it is, except a directory
            // for a file source. Its own last component already has
            // `O_NOFOLLOW` protection when read (root = the path, nothing
            // below it to descend).
            if self.include_dirs || meta.kind != FileKind::Dir {
                found.insert(base.clone(), literal_found(&base));
            }
            return;
        }
        let (real, meta) = if meta.kind == FileKind::Symlink {
            match self.follow_prefix(&base, &meta) {
                Ok(Some(r)) => r,
                Ok(None) => return, // the target is excluded
                Err(detail) => {
                    skipped.push(Skipped {
                        source: self.source.clone(),
                        location: file_location(&base),
                        reason: "symlink_root",
                        detail,
                    });
                    return;
                }
            }
        } else {
            (base.clone(), meta)
        };
        if meta.kind != FileKind::Dir {
            return;
        }
        let rest = &comps[literal..];
        let recursive = rest.contains(&"**");
        let max_depth = if recursive {
            self.settings.max_depth
        } else {
            u32::try_from(rest.len()).unwrap_or(u32::MAX)
        };
        // `real` is the trusted literal prefix; everything below it is
        // resolved with `openat` against a held directory fd.
        let root = Root {
            real: &real,
            shown: &base,
        };
        let limits = Limits {
            max_depth,
            recursive,
            dev: meta.dev,
        };
        self.walk(&root, Path::new(""), 1, &limits, found, skipped);
    }

    /// Follows a symlink that is the last component of a glob's literal
    /// prefix, once (see the module docs). `Ok(None)` if the target is
    /// excluded, `Err(detail)` if a check fails.
    #[allow(clippy::type_complexity)]
    fn follow_prefix(
        &self,
        base: &Path,
        link: &FileMeta,
    ) -> Result<Option<(PathBuf, FileMeta)>, String> {
        if link.uid != self.uid && link.uid != 0 {
            return Err(format!(
                "literal prefix is a symlink owned by uid {} (only the scanning user's or \
                 root's are followed)",
                link.uid
            ));
        }
        let target = self
            .files
            .read_link(base)
            .map_err(|e| format!("literal prefix is a symlink that cannot be read: {e}"))?;
        let target = normalize(&match base.parent() {
            Some(dir) if target.is_relative() => dir.join(target),
            _ => target,
        });
        if self.excluded(&target) {
            return Ok(None);
        }
        match self.files.metadata(&target) {
            Ok(m) if m.kind == FileKind::Dir => Ok(Some((target, m))),
            Ok(m) => Err(format!(
                "literal prefix is a symlink to a {} (only a link to a directory is followed, once)",
                m.kind
            )),
            Err(e) => Err(format!("literal prefix is a symlink whose target is {e}")),
        }
    }

    fn walk(
        &self,
        root: &Root<'_>,
        rel: &Path,
        depth: u32,
        limits: &Limits,
        found: &mut BTreeMap<PathBuf, Found>,
        skipped: &mut Vec<Skipped>,
    ) {
        let dir = join(root.shown, rel);
        let mut entries = match self.files.read_dir_beneath(root.real, rel) {
            Ok(e) => e,
            Err(FsError::NotFound) => return,
            Err(e) => {
                skipped.push(self.skip(&dir, &e));
                return;
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in entries {
            let child = rel.join(&entry.name);
            let path = dir.join(&entry.name);
            if self.excluded(&path) {
                continue;
            }
            let is_dir = entry.meta.kind == FileKind::Dir;
            if (self.include_dirs || !is_dir)
                && self
                    .glob
                    .is_some_and(|g| g.matches(&path.to_string_lossy()))
            {
                found.insert(
                    path.clone(),
                    Found {
                        root: root.real.to_path_buf(),
                        rel: child.clone(),
                    },
                );
            }
            if !is_dir {
                continue;
            }
            if depth >= limits.max_depth {
                // A `**` pattern would go on: the limit hides what is below.
                if limits.recursive {
                    skipped.push(Skipped {
                        source: self.source.clone(),
                        location: file_location(&path),
                        reason: "depth_limit",
                        detail: format!(
                            "not descended: deeper than scan.max-depth ({})",
                            limits.max_depth
                        ),
                    });
                }
            } else if self.settings.one_file_system && entry.meta.dev != limits.dev {
                skipped.push(Skipped {
                    source: self.source.clone(),
                    location: file_location(&path),
                    reason: "other_fs",
                    detail: "not descended: another file system (scan.one-file-system)".into(),
                });
            } else {
                self.walk(root, &child, depth + 1, limits, found, skipped);
            }
        }
    }

    /// Excluded paths and directories (`~/Library/**` prunes `~/Library`).
    fn excluded(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();
        let dir = format!("{s}/");
        self.excludes
            .iter()
            .any(|g| g.matches(&s) || g.matches(&dir))
    }

    fn skip(&self, path: &Path, e: &FsError) -> Skipped {
        Skipped {
            source: self.source.clone(),
            location: file_location(path),
            reason: e.code(),
            detail: e.to_string(),
        }
    }
}

/// How deep a walk goes and where it stops.
struct Limits {
    max_depth: u32,
    /// The pattern has `**` (so `max_depth` is `scan.max-depth`, a limit
    /// worth reporting, not the pattern's own depth).
    recursive: bool,
    /// Device of the walk's root (`one-file-system`).
    dev: u64,
}

/// A literal path is read by itself: its parent is resolved by the kernel,
/// the file is opened with `O_NOFOLLOW`.
fn literal_found(path: &Path) -> Found {
    Found {
        root: path.to_path_buf(),
        rel: PathBuf::new(),
    }
}

/// Lexical normalization (`a/./b/../c` → `a/c`) of a symlink target.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

pub fn file_location(path: &Path) -> Location {
    Location::File {
        path: DisplayPath::new(path),
        key_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::fake::{FakeEnv, FakeFiles};

    fn id(s: &str) -> Ident {
        Ident::from_non_secret(s).unwrap()
    }

    fn file_source(paths: &[&str], exclude: &[&str]) -> Source {
        Source {
            id: id("files"),
            kind: SourceKind::File {
                paths: paths.iter().map(|s| s.to_string()).collect(),
                exclude: exclude.iter().map(|s| s.to_string()).collect(),
                action: FileAction::Extract("lines".into()),
            },
        }
    }

    fn tree() -> FakeFiles {
        FakeFiles::new()
            .file("/home/user/.ssh/id_rsa", "k")
            .file("/home/user/.ssh/config", "c")
            .file("/home/user/.ssh/sub/deep_key", "k")
            .special("/home/user/.ssh/linked", FileKind::Symlink)
            .file("/work/.env", "A=1")
            .file("/work/app/.env", "A=1")
            .file("/work/app/node_modules/x/.env", "A=1")
            .file("/work/a/b/c/d/.env", "A=1")
            .special("/work/linkdir", FileKind::Symlink)
            .mount("/work/mnt")
            .file("/work/mnt/.env", "A=1")
            .file("/home/user/Library/k/.env", "A=1")
            .unreadable("/home/user/locked")
    }

    fn found(
        sources: &[Source],
        settings: &ScanSettings,
        fs: &FakeFiles,
    ) -> (Vec<String>, Vec<Skipped>) {
        let paths = Paths {
            home: Some(Path::new("/home/user")),
            cwd: Path::new("/work"),
            uid: crate::repository::fake::FAKE_UID,
        };
        let d = discover(sources, settings, &paths, fs, &FakeEnv::new());
        let names = d
            .candidates
            .iter()
            .map(|c| match &c.target {
                Target::File { path, .. } => path.display().to_string(),
                other => format!("{other:?}"),
            })
            .collect();
        (names, d.skipped)
    }

    #[test]
    fn single_level_globs_do_not_descend() {
        let (paths, _) = found(
            &[file_source(&["~/.ssh/*"], &[])],
            &ScanSettings::default(),
            &tree(),
        );
        assert_eq!(
            paths,
            [
                "/home/user/.ssh/config",
                "/home/user/.ssh/id_rsa",
                "/home/user/.ssh/linked"
            ]
        );
    }

    #[test]
    fn recursive_globs_with_excludes_and_one_file_system() {
        let settings = ScanSettings::default();
        let src = file_source(&["./**/.env"], &["**/node_modules/**"]);
        let (paths, _) = found(&[src], &settings, &tree());
        assert_eq!(
            paths,
            ["/work/.env", "/work/a/b/c/d/.env", "/work/app/.env"]
        );

        let settings = ScanSettings {
            one_file_system: false,
            max_depth: 2,
            exclude: vec!["/work/app/**".into()],
            ..ScanSettings::default()
        };
        let (paths, _) = found(&[file_source(&["./**/.env"], &[])], &settings, &tree());
        assert_eq!(paths, ["/work/.env", "/work/mnt/.env"]);
    }

    #[test]
    fn global_excludes_prune_home_dirs() {
        let settings = ScanSettings {
            exclude: vec!["~/Library/**".into()],
            ..ScanSettings::default()
        };
        let (paths, _) = found(&[file_source(&["~/**/.env"], &[])], &settings, &tree());
        assert!(paths.is_empty(), "{paths:?}");
        let (paths, _) = found(
            &[file_source(&["~/**/.env"], &[])],
            &ScanSettings::default(),
            &tree(),
        );
        assert_eq!(paths, ["/home/user/Library/k/.env"]);
    }

    #[test]
    fn literal_paths_and_missing_paths() {
        let src = file_source(&["~/.ssh/id_rsa", "~/nope/*", "/work/linkdir"], &[]);
        let (paths, skipped) = found(&[src], &ScanSettings::default(), &tree());
        assert_eq!(paths, ["/home/user/.ssh/id_rsa", "/work/linkdir"]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn symlinked_dirs_are_not_followed() {
        let fs = tree().file("/work/linkdir/.env", "x");
        // The fake keeps `linkdir` a symlink; a walk must not list it.
        let (paths, _) = found(
            &[file_source(&["/work/*/.env"], &[])],
            &ScanSettings::default(),
            &fs,
        );
        assert_eq!(paths, ["/work/app/.env"]);
    }

    fn probe_paths(src: Source, env: &FakeEnv, fs: &FakeFiles) -> Vec<String> {
        let paths = Paths {
            home: Some(Path::new("/home/user")),
            cwd: Path::new("/work"),
            uid: crate::repository::fake::FAKE_UID,
        };
        let d = discover(&[src], &ScanSettings::default(), &paths, fs, env);
        assert_eq!(d.candidates.len(), 1);
        match &d.candidates[0].target {
            Target::Probe { paths, .. } => paths.iter().map(|p| p.display().to_string()).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn probe_sources_get_directories_and_path_var_entries() {
        let fs = FakeFiles::new()
            .dir("/usr/local/bin")
            .dir("/opt/shared/bin")
            .dir("/usr/bin")
            .dir("/home/user/.cache/pip")
            .dir("/home/user/.config/git/hooks/sub")
            .file("/home/user/.config/git/hooks/pre-commit", "x")
            .file("/home/user/.bashrc", "x")
            .dir("/excluded/bin");
        let env = FakeEnv::new().var(
            "PATH",
            "/opt/shared/bin:/usr/bin::relative/bin:/usr/local/bin:/missing:/excluded/bin:/usr/bin",
        );
        let src = Source {
            id: id("probe"),
            kind: SourceKind::Probe {
                probes: vec![id("writable")],
                paths: vec![
                    "/usr/local/bin".into(),
                    "~/.cache/pip".into(),
                    "~/.bashrc".into(),
                    "~/.config/git/hooks/*".into(),
                ],
                exclude: vec!["/excluded/**".into()],
                path_vars: vec!["PATH".into(), "UNSET_PATH".into()],
            },
        };
        assert_eq!(
            probe_paths(src, &env, &fs),
            [
                "/home/user/.bashrc",
                "/home/user/.cache/pip",
                "/home/user/.config/git/hooks/pre-commit",
                "/home/user/.config/git/hooks/sub",
                "/opt/shared/bin",
                "/usr/bin",
                "/usr/local/bin",
            ]
        );
    }

    #[test]
    fn file_sources_never_get_directories() {
        let fs = FakeFiles::new()
            .dir("/home/user/.cache/pip")
            .dir("/home/user/conf/sub")
            .file("/home/user/conf/a", "x");
        let (paths, _) = found(
            &[file_source(&["~/.cache/pip", "~/conf/*"], &[])],
            &ScanSettings::default(),
            &fs,
        );
        assert_eq!(paths, ["/home/user/conf/a"]);
    }

    #[test]
    fn env_names_by_glob() {
        let env = FakeEnv::new()
            .var("GH_TOKEN", "x")
            .var("PATH", "/bin")
            .var("CI_JOB_TOKEN", "y")
            .var("BAD NAME", "z");
        let src = Source {
            id: id("env"),
            kind: SourceKind::Env {
                names: vec!["*TOKEN".into(), "BAD*".into()],
            },
        };
        let paths = Paths {
            home: None,
            cwd: Path::new("/"),
            uid: crate::repository::fake::FAKE_UID,
        };
        let d = discover(
            &[src],
            &ScanSettings::default(),
            &paths,
            &FakeFiles::new(),
            &env,
        );
        let names: Vec<String> = d
            .candidates
            .iter()
            .map(|c| match &c.target {
                Target::Env { name, .. } => name.to_string(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(names, ["CI_JOB_TOKEN", "GH_TOKEN"]);
    }

    #[test]
    fn unreadable_dirs_are_skipped_and_reported() {
        let fs = FakeFiles::new()
            .file("/work/a/.env", "x")
            .locked_dir("/work/locked");
        let (paths, skipped) = found(
            &[file_source(&["./**/.env"], &[])],
            &ScanSettings::default(),
            &fs,
        );
        assert_eq!(paths, ["/work/a/.env"]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].reason, "permission_denied");
        assert_eq!(skipped[0].location.to_string(), "/work/locked");
    }

    fn reasons(skipped: &[Skipped]) -> Vec<(String, &'static str)> {
        skipped
            .iter()
            .map(|s| (s.location.to_string(), s.reason))
            .collect()
    }

    /// `max-depth` and `one-file-system` prune visibly: the directory that
    /// was not descended is reported once, even with several globs.
    #[test]
    fn depth_and_file_system_limits_are_reported() {
        let settings = ScanSettings {
            max_depth: 2,
            ..ScanSettings::default()
        };
        let src = file_source(&["./**/.env", "./**/.env.*"], &["**/node_modules/**"]);
        let (paths, skipped) = found(&[src], &settings, &tree());
        assert_eq!(paths, ["/work/.env", "/work/app/.env"]);
        assert_eq!(
            reasons(&skipped),
            [
                ("/work/a/b".to_string(), "depth_limit"),
                ("/work/mnt".to_string(), "other_fs"),
            ]
        );
        // A pattern's own depth is no limit: `/work/*/.env` reports no
        // `depth_limit`, but the other file system it would look into.
        let (_, skipped) = found(&[file_source(&["/work/*/.env"], &[])], &settings, &tree());
        assert_eq!(reasons(&skipped), [("/work/mnt".to_string(), "other_fs")]);
    }

    /// A glob whose literal prefix is a symlink (`~/.ssh -> dotfiles/ssh`)
    /// is walked below the target once, paths keep the configured prefix
    /// and are read below the resolved root.
    #[test]
    fn a_symlinked_literal_prefix_is_followed_once() {
        let fs = FakeFiles::new()
            .file("/home/user/dotfiles/ssh/id_ed25519", "k")
            .file("/home/user/dotfiles/ssh/sub/key", "k")
            .symlink("/home/user/.ssh", "dotfiles/ssh");
        let paths = Paths {
            home: Some(Path::new("/home/user")),
            cwd: Path::new("/work"),
            uid: crate::repository::fake::FAKE_UID,
        };
        let src = file_source(&["~/.ssh/**"], &[]);
        let d = discover(
            &[src],
            &ScanSettings::default(),
            &paths,
            &fs,
            &FakeEnv::new(),
        );
        assert!(d.skipped.is_empty(), "{:?}", d.skipped);
        let targets: Vec<(String, String, String)> = d
            .candidates
            .iter()
            .map(|c| match &c.target {
                Target::File {
                    path, root, rel, ..
                } => (
                    path.display().to_string(),
                    root.display().to_string(),
                    rel.display().to_string(),
                ),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            targets,
            [
                (
                    "/home/user/.ssh/id_ed25519".into(),
                    "/home/user/dotfiles/ssh".into(),
                    "id_ed25519".into()
                ),
                (
                    "/home/user/.ssh/sub/key".into(),
                    "/home/user/dotfiles/ssh".into(),
                    "sub/key".into()
                ),
            ]
        );
        // Excluding the target excludes the walk.
        let settings = ScanSettings {
            exclude: vec!["~/dotfiles/**".into()],
            ..ScanSettings::default()
        };
        let (found_paths, skipped) = found(&[file_source(&["~/.ssh/**"], &[])], &settings, &fs);
        assert!(found_paths.is_empty() && skipped.is_empty());
    }

    /// A prefix symlink that fails a check is reported, never silently
    /// empty: another user's link, a link to a file, a link to a link.
    #[test]
    fn an_unsafe_symlinked_prefix_is_reported() {
        let fs = FakeFiles::new()
            .file("/tmp/evil/id", "k")
            .symlink_owned("/home/user/.ssh", "/tmp/evil", 1002)
            .file("/home/user/file", "x")
            .symlink("/home/user/.kube", "file")
            .dir("/home/user/real")
            .symlink("/home/user/hop", "real")
            .symlink("/home/user/.aws", "hop")
            .symlink("/home/user/.docker", "missing");
        let src = file_source(&["~/.ssh/**", "~/.kube/*", "~/.aws/*", "~/.docker/*"], &[]);
        let (paths, skipped) = found(&[src], &ScanSettings::default(), &fs);
        assert!(paths.is_empty(), "{paths:?}");
        let r = reasons(&skipped);
        assert_eq!(
            r,
            [
                ("/home/user/.ssh".to_string(), "symlink_root"),
                ("/home/user/.kube".to_string(), "symlink_root"),
                ("/home/user/.aws".to_string(), "symlink_root"),
                ("/home/user/.docker".to_string(), "symlink_root"),
            ]
        );
        assert!(
            skipped[0].detail.contains("uid 1002"),
            "{}",
            skipped[0].detail
        );
        // Root's links are followed (`/var/run -> /run` style).
        let fs =
            FakeFiles::new()
                .file("/run/app/x.sock", "")
                .symlink_owned("/srv/link", "/run/app", 0);
        let (paths, skipped) = found(
            &[file_source(&["/srv/link/*"], &[])],
            &ScanSettings::default(),
            &fs,
        );
        assert_eq!(paths, ["/srv/link/x.sock"]);
        assert!(skipped.is_empty());
    }
}
