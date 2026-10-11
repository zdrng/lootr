//! `kube_service_account`: the in-cluster Kubernetes service account token
//! mounted into a pod (`/var/run/secrets/kubernetes.io/serviceaccount/token`
//! and its siblings `namespace`, `ca.crt`).
//!
//! The token is a bearer credential for the cluster API with the service
//! account's rights, so lootr reads it the way it reads any token file and
//! classifies its value (a JWT) through the value types — a long-lived or
//! non-expiring bound token is then reported by the ordinary `jwt` rules.
//! The namespace (not secret) and whether a CA is present become facts; the
//! token's content never does.
//!
//! The source's `paths` point at the token file (a matching directory is
//! ignored: only regular files are read); the namespace and CA are read next
//! to it.
//!
//! In a real pod these are symlinks into a projected volume
//! (`token -> ..data/token`, `..data -> ..2024_01_01_00_00_00.123`). They
//! are followed only while they stay inside the token's directory
//! ([`crate::repository::FileRepository::read_file_within`]); a link that
//! points elsewhere, or any other read failure, is reported as skipped.
//! The same file reached through two configured paths (`/var/run` is a
//! symlink to `/run` on most distributions) is reported once, by device and
//! inode.

use std::collections::BTreeSet;
use std::path::Path;

use crate::domain::model::{
    AttrValue, Attrs, DisplayPath, Fact, FileKind, FsError, Ident, Location, PublicText, Skipped,
};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::{Probe, ProbeContext, classify_value};

pub const NAME: &str = "kube_service_account";

const MAX_TOKEN: u64 = 64 << 10;
const MAX_NAMESPACE: u64 = 4 << 10;

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::optional(
        "namespace",
        AttrKind::Text,
        "the pod's namespace (from the sibling `namespace` file)",
    ),
    AttrSpec::new(
        "has_ca",
        AttrKind::Bool,
        "a sibling `ca.crt` is present (the cluster CA)",
    ),
];

const FACT_TYPES: &[FactType] = &[FactType {
    name: NAME,
    doc: "an in-cluster Kubernetes service account token mount",
    schema: ATTRS,
}];

pub struct KubeServiceAccountProbe;

impl Probe for KubeServiceAccountProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let Ok(type_) = Ident::from_non_secret(NAME) else {
            return Vec::new();
        };
        let mut facts = Vec::new();
        let mut seen = BTreeSet::new();
        for token_path in ctx.paths {
            let location = Location::File {
                path: DisplayPath::new(token_path),
                key_path: None,
            };
            let (Some(dir), Some(name)) = (token_path.parent(), token_path.file_name()) else {
                continue;
            };
            let (meta, token) = match ctx.files.read_file_within(dir, Path::new(name), MAX_TOKEN) {
                Ok(r) => r,
                Err(FsError::NotRegular {
                    kind: FileKind::Dir,
                }) => continue,
                Err(e) => {
                    skipped.push(Skipped {
                        source: ctx.source.clone(),
                        location,
                        reason: e.code(),
                        detail: e.to_string(),
                    });
                    continue;
                }
            };
            // One token mount reached through two paths is one fact.
            if !seen.insert((meta.dev, meta.ino)) {
                continue;
            }
            // The token's value, classified like any secret (→ jwt).
            classify_value(
                ctx.registry,
                ctx.source,
                &location,
                None,
                token.as_slice(),
                &mut facts,
            );
            let namespace = ctx
                .files
                .read_file_within(dir, Path::new("namespace"), MAX_NAMESPACE)
                .ok()
                .map(|(_, b)| {
                    PublicText::from_non_secret(String::from_utf8_lossy(b.expose()).trim())
                });
            let has_ca = ctx
                .files
                .metadata_within(dir, Path::new("ca.crt"))
                .is_ok_and(|m| m.kind == FileKind::File);
            let mut attrs = Attrs::new();
            if let Some(ns) = namespace {
                attrs.insert("namespace", AttrValue::Text(ns));
            }
            attrs.insert("has_ca", AttrValue::Bool(has_ca));
            facts.push(Fact {
                type_: type_.clone(),
                location,
                source: ctx.source.clone(),
                attrs,
            });
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

    #[test]
    fn reads_the_token_namespace_and_ca() {
        let dir = "/var/run/secrets/kubernetes.io/serviceaccount";
        // A JWT-looking token (header.payload.signature); not a real one.
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJrOHMiLCJleHAiOjQxMDI0NDQ4MDB9.sig";
        let files = FakeFiles::new()
            .file(format!("{dir}/token"), token)
            .file(format!("{dir}/namespace"), "ci\n")
            .file(format!("{dir}/ca.crt"), "-----BEGIN CERTIFICATE-----");
        let source = Ident::from_non_secret("kube").unwrap();
        let paths = vec![PathBuf::from(format!("{dir}/token"))];
        let registry = Registry::builtin(0);
        let system = FakeSystem::default();
        let ctx = ProbeContext {
            source: &source,
            paths: &paths,
            system: &system,
            files: &files,
            registry: &registry,
        };
        let facts = KubeServiceAccountProbe.run(&ctx, &mut Vec::new());
        let sa = facts
            .iter()
            .find(|f| f.type_.as_str() == NAME)
            .expect("service account fact");
        assert_eq!(sa.attrs["has_ca"], AttrValue::Bool(true));
        assert_eq!(sa.attrs["namespace"].to_string(), "ci");
        assert!(
            facts.iter().any(|f| f.type_.as_str() == "jwt"),
            "token classified as jwt"
        );
    }

    fn run(files: &FakeFiles, paths: &[&str]) -> (Vec<Fact>, Vec<Skipped>) {
        let source = Ident::from_non_secret("kube").unwrap();
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        let registry = Registry::builtin(0);
        let system = FakeSystem::default();
        let ctx = ProbeContext {
            source: &source,
            paths: &paths,
            system: &system,
            files,
            registry: &registry,
        };
        let mut skipped = Vec::new();
        let facts = KubeServiceAccountProbe.run(&ctx, &mut skipped);
        (facts, skipped)
    }

    /// The real projected-volume layout (`token -> ..data/token`, `..data ->
    /// ..<timestamp>`), reachable as `/run/...` and through the `/var/run`
    /// symlink: read through the links, reported once.
    #[test]
    fn projected_volume_symlinks_are_followed_and_reported_once() {
        let dir = "/run/secrets/kubernetes.io/serviceaccount";
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJrOHMiLCJleHAiOjQxMDI0NDQ4MDB9.sig";
        let files = FakeFiles::new()
            .file(format!("{dir}/..2024_01_01_00_00_00.1/token"), token)
            .file(format!("{dir}/..2024_01_01_00_00_00.1/namespace"), "ci")
            .file(
                format!("{dir}/..2024_01_01_00_00_00.1/ca.crt"),
                "-----BEGIN",
            )
            .symlink(format!("{dir}/..data"), "..2024_01_01_00_00_00.1")
            .symlink(format!("{dir}/token"), "..data/token")
            .symlink(format!("{dir}/namespace"), "..data/namespace")
            .symlink(format!("{dir}/ca.crt"), "..data/ca.crt")
            .alias("/var/run/secrets", "/run/secrets");
        let (facts, skipped) = run(
            &files,
            &[
                &format!("{dir}/token"),
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            ],
        );
        assert!(skipped.is_empty(), "{skipped:?}");
        let sa: Vec<&Fact> = facts.iter().filter(|f| f.type_.as_str() == NAME).collect();
        assert_eq!(sa.len(), 1, "{facts:?}");
        assert_eq!(sa[0].location.to_string(), format!("{dir}/token"));
        assert_eq!(sa[0].attrs["namespace"].to_string(), "ci");
        assert_eq!(sa[0].attrs["has_ca"], AttrValue::Bool(true));
        assert_eq!(
            facts.iter().filter(|f| f.type_.as_str() == "jwt").count(),
            1
        );
    }

    /// A token link that leaves the directory is not followed, and the
    /// failure is reported instead of dropped.
    #[test]
    fn links_out_of_the_directory_are_skipped_and_reported() {
        let dir = "/var/run/secrets/kubernetes.io/serviceaccount";
        let files = FakeFiles::new()
            .file("/home/user/.ssh/id_ed25519", "not a token")
            .symlink(format!("{dir}/token"), "/home/user/.ssh/id_ed25519")
            .symlink(
                format!("{dir}/token2"),
                "../../../../../../home/user/.ssh/id_ed25519",
            )
            .unreadable(format!("{dir}/token3"));
        let (facts, skipped) = run(
            &files,
            &[
                &format!("{dir}/token"),
                &format!("{dir}/token2"),
                &format!("{dir}/token3"),
            ],
        );
        assert!(facts.is_empty(), "{facts:?}");
        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason).collect();
        assert_eq!(reasons, ["symlink", "symlink", "permission_denied"]);
    }
}
