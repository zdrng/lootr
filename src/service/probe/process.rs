//! `process`: who lootr runs as. One fact per run:
//!
//! - `uid`, `is_root` (real or effective uid 0);
//! - `groups`: names of the primary and supplementary groups. Membership in
//!   `docker`, `lxd` or `disk` is root-equivalent; `sudo`, `wheel` and
//!   `admin` usually allow `sudo` (lootr cannot check the sudoers file
//!   without privileges);
//! - `in_container`: a container marker exists (`/.dockerenv`,
//!   `/run/.containerenv`, a Kubernetes service account directory). A
//!   heuristic: not every runtime leaves a marker.

use std::path::Path;

use crate::domain::model::{AttrValue, Attrs, Fact, Ident, Location, Skipped};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::{Probe, ProbeContext, group_names};

pub const NAME: &str = "process";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("uid", AttrKind::Int, "real user id"),
    AttrSpec::new(
        "is_root",
        AttrKind::Bool,
        "running as root (real or effective uid 0)",
    ),
    AttrSpec::new(
        "groups",
        AttrKind::List,
        "names of the process's groups (numeric id if unnamed), e.g. docker, sudo, wheel",
    ),
    AttrSpec::new(
        "in_container",
        AttrKind::Bool,
        "a container marker exists (/.dockerenv, /run/.containerenv, Kubernetes service account)",
    ),
];

const FACT_TYPES: &[FactType] = &[FactType {
    name: NAME,
    doc: "the process lootr runs as (one fact per run)",
    schema: ATTRS,
}];

/// Files or directories whose existence means "in a container".
const CONTAINER_MARKERS: &[&str] = &[
    "/.dockerenv",
    "/run/.containerenv",
    "/var/run/secrets/kubernetes.io/serviceaccount",
];

pub struct ProcessProbe;

impl Probe for ProcessProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, _skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let (Ok(type_), Ok(name)) = (Ident::from_non_secret(NAME), Ident::from_non_secret(NAME))
        else {
            return Vec::new();
        };
        let system = ctx.system;
        let uid = system.uid();
        let mut attrs = Attrs::new();
        attrs.insert("uid", AttrValue::Int(i64::from(uid)));
        attrs.insert("is_root", AttrValue::Bool(uid == 0 || system.euid() == 0));
        let groups = group_names(system)
            .into_iter()
            .map(AttrValue::Name)
            .collect();
        attrs.insert("groups", AttrValue::List(groups));
        let in_container = CONTAINER_MARKERS
            .iter()
            .any(|m| ctx.files.metadata(Path::new(m)).is_ok());
        attrs.insert("in_container", AttrValue::Bool(in_container));
        vec![Fact {
            type_,
            location: Location::Probe { name },
            source: ctx.source.clone(),
            attrs,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::fake::{FakeFiles, FakeSystem};

    fn run(system: &FakeSystem, files: &FakeFiles) -> Attrs {
        let source = Ident::from_non_secret("system").unwrap();
        let registry = crate::domain::types::Registry::builtin(0);
        let ctx = ProbeContext {
            source: &source,
            paths: &[],
            system,
            files,
            registry: &registry,
        };
        let mut facts = ProcessProbe.run(&ctx, &mut Vec::new());
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].location.to_string(), "probe:process");
        facts.pop().unwrap().attrs
    }

    #[test]
    fn ordinary_user() {
        let a = run(&FakeSystem::default(), &FakeFiles::new());
        assert_eq!(a["uid"], AttrValue::Int(1000));
        assert_eq!(a["is_root"], AttrValue::Bool(false));
        assert_eq!(a["groups"].to_string(), "user");
        assert_eq!(a["in_container"], AttrValue::Bool(false));
    }

    #[test]
    fn root_in_a_container_with_groups() {
        let mut system = FakeSystem {
            euid: 0,
            groups: vec![1000, 999, 4242, 1000],
            ..FakeSystem::default()
        };
        system.group_names.insert(999, "docker".into());
        let files = FakeFiles::new().file("/run/.containerenv", "");
        let a = run(&system, &files);
        assert_eq!(a["is_root"], AttrValue::Bool(true));
        assert_eq!(a["groups"].to_string(), "user, docker, 4242");
        assert_eq!(a["in_container"], AttrValue::Bool(true));
    }
}
