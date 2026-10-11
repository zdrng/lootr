//! `unix_socket`: container runtime sockets (Docker, containerd, Podman, ...)
//! at the paths of the probe source. One fact per path that is a socket.
//!
//! Access is judged from metadata only, lootr never connects: connecting
//! needs write permission on the socket for the process's user or one of its
//! groups (root always may). Search permission on the parent directories is
//! implied: the socket could be `lstat`ed. A socket owned by root that the
//! process can use usually means root on the machine (`docker run -v /:/host`).
//!
//! `kind` comes from the file name: `docker`, `containerd`, `podman`,
//! `buildkit`, else `other`.

use std::path::Path;

use crate::domain::model::{
    AttrValue, Attrs, DisplayPath, Fact, FileKind, Ident, Location, Skipped,
};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::{Probe, ProbeContext};

pub const NAME: &str = "unix_socket";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "docker | containerd | podman | buildkit | other (from the file name)",
    ),
    AttrSpec::new(
        "accessible",
        AttrKind::Bool,
        "the process may connect (write permission for its user or groups, or root)",
    ),
    AttrSpec::new(
        "rootful",
        AttrKind::Bool,
        "owned by root: the daemon behind it most likely runs as root",
    ),
    AttrSpec::new(
        "owner_is_self",
        AttrKind::Bool,
        "owned by the scanning user (e.g. rootless Podman/Docker)",
    ),
    AttrSpec::new("mode", AttrKind::Int, "permission bits, e.g. 0o660 = 432"),
    AttrSpec::new(
        "group",
        AttrKind::Name,
        "group of the socket (numeric id if unnamed)",
    ),
];

const FACT_TYPES: &[FactType] = &[FactType {
    name: NAME,
    doc: "a container runtime socket at a path of the probe source",
    schema: ATTRS,
}];

const KINDS: &[&str] = &["containerd", "buildkit", "podman", "docker"];

pub struct UnixSocketProbe;

impl Probe for UnixSocketProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, _skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let Ok(type_) = Ident::from_non_secret(NAME) else {
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
            if meta.kind != FileKind::Socket {
                continue;
            }
            // Write permission for the class the process falls in.
            let write = if meta.uid == uid {
                meta.mode & 0o200
            } else if gids.contains(&meta.gid) {
                meta.mode & 0o020
            } else {
                meta.mode & 0o002
            };
            let group = system
                .group_name(meta.gid)
                .and_then(|g| Ident::from_non_secret(&g).ok())
                .or_else(|| Ident::from_non_secret(&meta.gid.to_string()).ok());
            let mut attrs = Attrs::new();
            attrs.insert("kind", AttrValue::Sym(kind(path)));
            attrs.insert("accessible", AttrValue::Bool(root || write != 0));
            attrs.insert("rootful", AttrValue::Bool(meta.uid == 0));
            attrs.insert("owner_is_self", AttrValue::Bool(meta.uid == uid));
            attrs.insert("mode", AttrValue::Int(i64::from(meta.mode & 0o7777)));
            if let Some(g) = group {
                attrs.insert("group", AttrValue::Name(g));
            }
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

fn kind(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    KINDS
        .iter()
        .find(|k| name.contains(*k))
        .copied()
        .unwrap_or("other")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::fake::{FakeFiles, FakeSystem};
    use std::path::PathBuf;

    fn run(system: &FakeSystem, files: &FakeFiles, paths: &[&str]) -> Vec<Fact> {
        let source = Ident::from_non_secret("sockets").unwrap();
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        let registry = crate::domain::types::Registry::builtin(0);
        let ctx = ProbeContext {
            source: &source,
            paths: &paths,
            system,
            files,
            registry: &registry,
        };
        UnixSocketProbe.run(&ctx, &mut Vec::new())
    }

    fn files() -> FakeFiles {
        FakeFiles::new()
            .special_owned("/run/docker.sock", FileKind::Socket, 0, 999, 0o660)
            .special_owned(
                "/run/containerd/containerd.sock",
                FileKind::Socket,
                0,
                0,
                0o660,
            )
            .special_owned(
                "/run/user/1000/podman/podman.sock",
                FileKind::Socket,
                1000,
                1000,
                0o600,
            )
            .special("/var/run/docker.sock", FileKind::Symlink)
            .file("/tmp/not-a.sock", "")
    }

    fn summary(facts: &[Fact]) -> Vec<String> {
        facts
            .iter()
            .map(|f| {
                let a = &f.attrs;
                format!(
                    "{} {} accessible={} rootful={} self={} group={}",
                    f.location,
                    a["kind"],
                    a["accessible"],
                    a["rootful"],
                    a["owner_is_self"],
                    a["group"]
                )
            })
            .collect()
    }

    const ALL: &[&str] = &[
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/user/1000/podman/podman.sock",
        "/var/run/docker.sock",
        "/tmp/not-a.sock",
        "/missing.sock",
    ];

    #[test]
    fn ordinary_user() {
        let facts = run(&FakeSystem::default(), &files(), ALL);
        assert_eq!(
            summary(&facts),
            [
                "/run/docker.sock docker accessible=false rootful=true self=false group=999",
                "/run/containerd/containerd.sock containerd accessible=false rootful=true self=false group=root",
                "/run/user/1000/podman/podman.sock podman accessible=true rootful=false self=true group=user",
            ]
        );
        assert_eq!(facts[0].attrs["mode"], AttrValue::Int(0o660));
    }

    #[test]
    fn docker_group_member_and_root() {
        let mut system = FakeSystem {
            groups: vec![1000, 999],
            ..FakeSystem::default()
        };
        system.group_names.insert(999, "docker".into());
        let facts = run(&system, &files(), &ALL[..2]);
        assert_eq!(
            summary(&facts),
            [
                "/run/docker.sock docker accessible=true rootful=true self=false group=docker",
                "/run/containerd/containerd.sock containerd accessible=false rootful=true self=false group=root",
            ]
        );
        let root = FakeSystem {
            uid: 0,
            euid: 0,
            gid: 0,
            groups: vec![0],
            ..FakeSystem::default()
        };
        let facts = run(&root, &files(), &ALL[1..2]);
        assert_eq!(facts[0].attrs["accessible"], AttrValue::Bool(true));
        assert_eq!(facts[0].attrs["owner_is_self"], AttrValue::Bool(true));
    }
}
