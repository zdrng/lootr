//! `writable`: file-system objects at the source's `paths` that can be
//! written, by their mode, owner and group — never by trying to write.
//!
//! Three attack surfaces, all configured as `paths` (no location is
//! hardcoded, per the project principle):
//!
//! - **PATH directories** and **shared caches** (`~/.cargo/registry`,
//!   `~/.npm`, runner tool caches): a directory others can write lets them
//!   plant a binary or poison a cached artifact a later build runs.
//! - **shell rc files** (`~/.bashrc`, `~/.zshrc`, `~/.profile`, ...) and
//!   **git hooks** (`.git/hooks/*`): a file (or its directory) others can
//!   write lets them inject code that runs as the file's owner.
//!
//! Directories become `writable_path_dir` facts, other objects
//! `writable_file` facts (with the writability of the containing directory,
//! because a writable directory lets a file be replaced even when the file
//! itself is not writable).
//!
//! Only objects someone other than their owner may write produce a fact:
//! a directory with the group or world write bit, a file with it on the file
//! or on its directory. An ordinary private rc file or a root-owned `0755`
//! PATH directory produces nothing. The paths come from discovery: the
//! source's `paths` (directories included) and the entries of its
//! `path-vars` (`PATH`).
//!
//! A symlink's own mode bits mean nothing (`0777` on Linux). What it points
//! to is judged instead, by `stat` (nothing is opened or written): a PATH
//! entry `~/bin -> /tmp/bin` with a world-writable target is as dangerous
//! as a world-writable PATH directory, an rc file linked to a world-writable
//! file as a world-writable rc file. Such facts have `symlink = true`; the
//! location stays the configured path. For files the link's own directory
//! is judged too (whoever may write it may replace the link). A dangling
//! link counts only by its directory.

use crate::domain::model::{
    AttrValue, Attrs, DisplayPath, Fact, FileKind, FileMeta, Ident, Location, Skipped,
};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::{Probe, ProbeContext};

pub const NAME: &str = "writable";
pub const DIR_TYPE: &str = "writable_path_dir";
pub const FILE_TYPE: &str = "writable_file";

pub const DIR_ATTRS: &[AttrSpec] = &[
    AttrSpec::new("dir", AttrKind::Path, "the directory"),
    AttrSpec::new(
        "writable",
        AttrKind::Bool,
        "the scanning user may write in it (mode, owner and groups; root always may)",
    ),
    AttrSpec::new("world_writable", AttrKind::Bool, "any user may write in it"),
    AttrSpec::new(
        "group_writable",
        AttrKind::Bool,
        "its group may write in it",
    ),
    AttrSpec::new(
        "owner_is_self",
        AttrKind::Bool,
        "owned by the scanning user",
    ),
    AttrSpec::new("mode", AttrKind::Int, "permission bits, e.g. 0o755 = 493"),
    AttrSpec::new(
        "symlink",
        AttrKind::Bool,
        "the path is a symlink; the other attributes describe the directory it points to",
    ),
];

pub const FILE_ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "writable",
        AttrKind::Bool,
        "the scanning user may write the file",
    ),
    AttrSpec::new(
        "world_writable",
        AttrKind::Bool,
        "any user may write the file",
    ),
    AttrSpec::new(
        "group_writable",
        AttrKind::Bool,
        "its group may write the file",
    ),
    AttrSpec::new(
        "parent_writable",
        AttrKind::Bool,
        "the scanning user may write its directory (so replace the file)",
    ),
    AttrSpec::new(
        "parent_world_writable",
        AttrKind::Bool,
        "any user may write its directory",
    ),
    AttrSpec::new(
        "parent_group_writable",
        AttrKind::Bool,
        "its directory's group may write it",
    ),
    AttrSpec::new(
        "owner_is_self",
        AttrKind::Bool,
        "the file is owned by the scanning user",
    ),
    AttrSpec::new("mode", AttrKind::Int, "permission bits, e.g. 0o644 = 420"),
    AttrSpec::new(
        "symlink",
        AttrKind::Bool,
        "the path is a symlink; `writable`, the write bits, owner and mode describe the file \
         it points to (none for a dangling link), the parent attributes the link's directory",
    ),
];

const FACT_TYPES: &[FactType] = &[
    FactType {
        name: DIR_TYPE,
        doc: "a directory at a probe path and who may write in it (PATH dirs, shared caches)",
        schema: DIR_ATTRS,
    },
    FactType {
        name: FILE_TYPE,
        doc: "a file at a probe path and who may write it or its directory (shell rc, git hooks)",
        schema: FILE_ATTRS,
    },
];

/// Who may write an object, from its metadata (never by writing). Mirrors
/// the `unix_socket` probe's write check.
pub fn writable_by(meta: &FileMeta, uid: u32, root: bool, gids: &[u32]) -> bool {
    if root {
        return true;
    }
    let bits = if meta.uid == uid {
        meta.mode & 0o200
    } else if gids.contains(&meta.gid) {
        meta.mode & 0o020
    } else {
        meta.mode & 0o002
    };
    bits != 0
}

/// Someone other than the owner may write: the group or world write bit.
fn others_may_write(mode: u32) -> bool {
    mode & 0o022 != 0
}

pub struct WritableProbe;

impl Probe for WritableProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, _skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let (Ok(dir_type), Ok(file_type)) = (
            Ident::from_non_secret(DIR_TYPE),
            Ident::from_non_secret(FILE_TYPE),
        ) else {
            return Vec::new();
        };
        let system = ctx.system;
        let uid = system.uid();
        let root = system.euid() == 0;
        let mut gids = system.groups();
        gids.push(system.gid());
        let mut facts = Vec::new();
        for path in ctx.paths {
            let Ok(own) = ctx.files.metadata(path) else {
                continue;
            };
            let link = own.kind == FileKind::Symlink;
            // A symlink is judged by what it points to (`stat`, nothing
            // opened); a dangling one keeps its own metadata.
            let meta = if link {
                ctx.files.metadata_followed(path).unwrap_or(own)
            } else {
                own
            };
            let loc = Location::File {
                path: DisplayPath::new(path),
                key_path: None,
            };
            if meta.kind == FileKind::Dir {
                if !others_may_write(meta.mode) {
                    continue;
                }
                let mut attrs = Attrs::new();
                attrs.insert("dir", AttrValue::Path(DisplayPath::new(path)));
                attrs.insert(
                    "writable",
                    AttrValue::Bool(writable_by(&meta, uid, root, &gids)),
                );
                attrs.insert("world_writable", AttrValue::Bool(meta.mode & 0o002 != 0));
                attrs.insert("group_writable", AttrValue::Bool(meta.mode & 0o020 != 0));
                attrs.insert("owner_is_self", AttrValue::Bool(meta.uid == uid));
                attrs.insert("mode", AttrValue::Int(i64::from(meta.mode & 0o7777)));
                attrs.insert("symlink", AttrValue::Bool(link));
                facts.push(Fact {
                    type_: dir_type.clone(),
                    location: loc,
                    source: ctx.source.clone(),
                    attrs,
                });
            } else {
                let parent = path.parent().and_then(|p| ctx.files.metadata(p).ok());
                // A dangling symlink's own mode is meaningless: only its
                // directory counts.
                let dangling = meta.kind == FileKind::Symlink;
                let own_mode = if dangling { 0 } else { meta.mode };
                let parent_mode = parent.as_ref().map_or(0, |p| p.mode);
                if !others_may_write(own_mode) && !others_may_write(parent_mode) {
                    continue;
                }
                let mut attrs = Attrs::new();
                attrs.insert(
                    "writable",
                    AttrValue::Bool(!dangling && writable_by(&meta, uid, root, &gids)),
                );
                attrs.insert("world_writable", AttrValue::Bool(own_mode & 0o002 != 0));
                attrs.insert("group_writable", AttrValue::Bool(own_mode & 0o020 != 0));
                let (pw, pww, pgw) = match &parent {
                    Some(p) => (
                        writable_by(p, uid, root, &gids),
                        p.mode & 0o002 != 0,
                        p.mode & 0o020 != 0,
                    ),
                    None => (false, false, false),
                };
                attrs.insert("parent_writable", AttrValue::Bool(pw));
                attrs.insert("parent_world_writable", AttrValue::Bool(pww));
                attrs.insert("parent_group_writable", AttrValue::Bool(pgw));
                attrs.insert("owner_is_self", AttrValue::Bool(meta.uid == uid));
                attrs.insert("mode", AttrValue::Int(i64::from(meta.mode & 0o7777)));
                attrs.insert("symlink", AttrValue::Bool(link));
                facts.push(Fact {
                    type_: file_type.clone(),
                    location: loc,
                    source: ctx.source.clone(),
                    attrs,
                });
            }
        }
        facts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Registry;
    use crate::repository::fake::{FakeFiles, FakeSystem};
    use std::path::PathBuf;

    fn run(system: &FakeSystem, files: &FakeFiles, paths: &[&str]) -> Vec<Fact> {
        let source = Ident::from_non_secret("w").unwrap();
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        let registry = Registry::builtin(0);
        let ctx = ProbeContext {
            source: &source,
            paths: &paths,
            system,
            files,
            registry: &registry,
        };
        WritableProbe.run(&ctx, &mut Vec::new())
    }

    #[test]
    fn reports_a_world_writable_path_dir_and_a_writable_rc_file() {
        let files = FakeFiles::new()
            .special_owned("/opt/bin", FileKind::Dir, 0, 0, 0o777)
            .file_with_mode("/home/user/.bashrc", "echo hi", 0o666);
        let facts = run(
            &FakeSystem::default(),
            &files,
            &["/opt/bin", "/home/user/.bashrc"],
        );
        let dir = facts.iter().find(|f| f.type_.as_str() == DIR_TYPE).unwrap();
        assert_eq!(dir.attrs["world_writable"], AttrValue::Bool(true));
        assert_eq!(dir.attrs["writable"], AttrValue::Bool(true));
        let rc = facts
            .iter()
            .find(|f| f.type_.as_str() == FILE_TYPE)
            .unwrap();
        assert_eq!(rc.attrs["world_writable"], AttrValue::Bool(true));
        assert_eq!(rc.location.to_string(), "/home/user/.bashrc");
    }

    #[test]
    fn private_dirs_and_files_produce_nothing() {
        let files = FakeFiles::new()
            .special_owned("/home/user/.local/bin", FileKind::Dir, 1000, 1000, 0o755)
            .special_owned("/usr/local/bin", FileKind::Dir, 0, 0, 0o755)
            .file_with_mode("/home/user/.profile", "x", 0o644);
        let facts = run(
            &FakeSystem::default(),
            &files,
            &[
                "/home/user/.local/bin",
                "/usr/local/bin",
                "/home/user/.profile",
            ],
        );
        assert!(facts.is_empty(), "{facts:?}");
    }

    #[test]
    fn a_group_writable_dir_of_another_user() {
        let files = FakeFiles::new().special_owned(
            "/home/user/.cache/pip",
            FileKind::Dir,
            1002,
            1000,
            0o775,
        );
        let facts = run(&FakeSystem::default(), &files, &["/home/user/.cache/pip"]);
        assert_eq!(facts.len(), 1);
        let a = &facts[0].attrs;
        assert_eq!(facts[0].type_.as_str(), DIR_TYPE);
        assert_eq!(a["group_writable"], AttrValue::Bool(true));
        assert_eq!(a["world_writable"], AttrValue::Bool(false));
        assert_eq!(a["writable"], AttrValue::Bool(true));
        assert_eq!(a["owner_is_self"], AttrValue::Bool(false));
        assert_eq!(a["mode"], AttrValue::Int(0o775));
    }

    #[test]
    fn a_symlink_counts_only_by_its_directory() {
        // Symlinks report mode 0777 on Linux: that alone is no finding.
        let files = FakeFiles::new()
            .special("/home/user/.bashrc", FileKind::Symlink)
            .special_owned("/srv/shared", FileKind::Dir, 0, 0, 0o777)
            .special("/srv/shared/hook", FileKind::Symlink);
        let facts = run(
            &FakeSystem::default(),
            &files,
            &["/home/user/.bashrc", "/srv/shared/hook"],
        );
        assert_eq!(facts.len(), 1, "{facts:?}");
        assert_eq!(facts[0].location.to_string(), "/srv/shared/hook");
        assert_eq!(facts[0].attrs["world_writable"], AttrValue::Bool(false));
        assert_eq!(facts[0].attrs["writable"], AttrValue::Bool(false));
        assert_eq!(
            facts[0].attrs["parent_world_writable"],
            AttrValue::Bool(true)
        );
    }

    /// A PATH entry or rc file that is a symlink is judged by its target:
    /// `~/bin -> /tmp/shared-bin` (world-writable) is a writable PATH dir.
    #[test]
    fn symlinks_are_judged_by_their_target() {
        let files = FakeFiles::new()
            .special_owned("/tmp/shared-bin", FileKind::Dir, 1002, 1002, 0o777)
            .symlink("/home/user/bin", "/tmp/shared-bin")
            .file_with_mode("/tmp/rc", "echo", 0o666)
            .symlink("/home/user/.bashrc", "../../tmp/rc")
            .special_owned("/usr/bin", FileKind::Dir, 0, 0, 0o755)
            .symlink_owned("/bin", "usr/bin", 0);
        let facts = run(
            &FakeSystem::default(),
            &files,
            &["/home/user/bin", "/home/user/.bashrc", "/bin"],
        );
        assert_eq!(facts.len(), 2, "{facts:?}");
        let dir = facts.iter().find(|f| f.type_.as_str() == DIR_TYPE).unwrap();
        assert_eq!(dir.location.to_string(), "/home/user/bin");
        assert_eq!(dir.attrs["world_writable"], AttrValue::Bool(true));
        assert_eq!(dir.attrs["symlink"], AttrValue::Bool(true));
        assert_eq!(dir.attrs["mode"], AttrValue::Int(0o777));
        let rc = facts
            .iter()
            .find(|f| f.type_.as_str() == FILE_TYPE)
            .unwrap();
        assert_eq!(rc.location.to_string(), "/home/user/.bashrc");
        assert_eq!(rc.attrs["world_writable"], AttrValue::Bool(true));
        assert_eq!(rc.attrs["writable"], AttrValue::Bool(true));
        assert_eq!(rc.attrs["symlink"], AttrValue::Bool(true));
    }
}
