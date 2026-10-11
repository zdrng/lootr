//! Probes: built-in system checks selected by name in `kind = "probe"`
//! sources. A probe reads only through the repositories and produces facts
//! directly; its fact types are registered in the type registry so rules can
//! be validated.
//!
//! A probe source may list `paths` (globs, `~` expanded, walked like file
//! sources but without reading anything) and `path-vars` (environment
//! variables holding `:`-separated directory lists, e.g. `PATH`, whose
//! absolute entries are taken as literal paths). Every matching path,
//! directories included, is handed to the probe: probes that look at file
//! system objects (`unix_socket`, `writable`, `suid`, ...) pick the kinds
//! they judge, others ignore the paths.
//!
//! - [`process`] - who lootr runs as: root, groups, container
//! - [`unix_socket`] - container runtime sockets and whether they are usable
//! - [`proc_environ`] - environments of other processes readable via `/proc`
//! - [`writable`] - writable PATH dirs / shared caches / shell rc / git hooks
//! - [`suid`] - setuid/setgid binaries and file capabilities
//! - [`kube_service_account`] - the in-cluster Kubernetes service account token
//!
//! Adding a probe: implement [`Probe`] in a file next to this one and list
//! it in [`builtin`]. A probe that reads a secret value (a foreign environ,
//! a token file) classifies it through the value types with
//! [`classify_value`].

pub mod kube_service_account;
pub mod proc_environ;
pub mod process;
pub mod suid;
pub mod unix_socket;
pub mod writable;

use std::path::PathBuf;

use crate::domain::model::{Attrs, Fact, Ident, Location, Skipped};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{FactType, Registry, entry_attrs};

use crate::repository::{FileRepository, SystemRepository};

/// What a probe can see.
pub struct ProbeContext<'a> {
    /// The config source that selected the probe.
    pub source: &'a Ident,
    /// Paths matched by the source's `paths` globs plus the absolute entries
    /// of its `path-vars` (any file type, directories included).
    pub paths: &'a [PathBuf],
    pub system: &'a dyn SystemRepository,
    pub files: &'a dyn FileRepository,
    /// The type registry, so a probe can classify a secret value it reads
    /// (a token in a foreign process's environ, a service account token)
    /// through the value types, exactly like `collect` does.
    pub registry: &'a Registry,
}

pub trait Probe {
    /// Name used in `probes = [...]`.
    fn name(&self) -> &'static str;
    /// The fact types this probe produces.
    fn fact_types(&self) -> &'static [FactType];
    /// The probe's facts. Anything it was pointed at but could not judge
    /// (an unreadable token file, a truncated environment) goes to
    /// `skipped`, with a reason: a probe never drops a selected path
    /// silently.
    fn run(&self, ctx: &ProbeContext<'_>, skipped: &mut Vec<Skipped>) -> Vec<Fact>;
}

/// Every probe compiled into the binary.
pub fn builtin() -> Vec<Box<dyn Probe>> {
    vec![
        Box::new(process::ProcessProbe),
        Box::new(unix_socket::UnixSocketProbe),
        Box::new(proc_environ::ProcEnvironProbe),
        Box::new(writable::WritableProbe),
        Box::new(suid::SuidProbe),
        Box::new(kube_service_account::KubeServiceAccountProbe),
    ]
}

/// Classifies a secret `value` through every value type and appends a fact
/// per match at `location`. With `entry = Some((type, name))` it also
/// prepends the generic entry fact (`env_var`, ...), as `collect` does for
/// environment variables. Used by probes that read secret values themselves
/// (`proc_environ`, `kube_service_account`). No file attributes are added:
/// the value does not come from a regular file the walk opened.
pub fn classify_value(
    registry: &Registry,
    source: &Ident,
    location: &Location,
    entry: Option<(&str, &Ident)>,
    value: SecretSlice<'_>,
    facts: &mut Vec<Fact>,
) {
    let fact = |type_: Ident, attrs: Attrs| Fact {
        type_,
        location: location.clone(),
        source: source.clone(),
        attrs,
    };
    let mut matched = Vec::new();
    let mut typed = Vec::new();
    for vt in registry.value_types() {
        let Some(attrs) = vt.classify(value) else {
            continue;
        };
        let Ok(type_) = Ident::from_non_secret(vt.name()) else {
            continue;
        };
        matched.push(vt.name());
        typed.push(fact(type_, attrs));
    }
    if let Some((entry_type, name)) = entry
        && let Ok(type_) = Ident::from_non_secret(entry_type)
    {
        facts.push(fact(type_, entry_attrs(name, value, &matched)));
    }
    facts.extend(typed);
}

/// The names of the groups the process is in (primary first, then the
/// supplementary groups), numeric ids for groups without a name.
pub fn group_names(system: &dyn SystemRepository) -> Vec<Ident> {
    let mut gids = vec![system.gid()];
    for g in system.groups() {
        if !gids.contains(&g) {
            gids.push(g);
        }
    }
    gids.into_iter()
        .filter_map(|gid| {
            let name = system.group_name(gid).unwrap_or_else(|| gid.to_string());
            Ident::from_non_secret(&name)
                .or_else(|_| Ident::from_non_secret(&gid.to_string()))
                .ok()
        })
        .collect()
}
