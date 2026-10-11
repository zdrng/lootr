//! `github_workflow`: a GitHub Actions workflow
//! (`.github/workflows/*.yml`). One fact per job (key path `jobs.<id>`)
//! with the triggers of the workflow and the job's **effective**
//! `GITHUB_TOKEN` permissions. Nothing else is interpreted (no general
//! workflow linting).
//!
//! Effective permissions: the job's `permissions` replace the workflow's
//! entirely; without either, the repository / organization default applies,
//! which lootr cannot see (`permissions_source = "repository"`, empty
//! `permissions`). `read-all` / `write-all` grant read / write on every
//! scope (`id-token` has no read level, `models` no write level); an
//! explicit map (also `{}`) sets every scope it does not list to `none`.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::format::yaml::{Value, Yaml};
use crate::domain::model::{AttrValue, Attrs, Ident, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "github_workflow";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("job", AttrKind::Text, "the job id"),
    AttrSpec::new(
        "triggers",
        AttrKind::List,
        "events that start the workflow (names: push, pull_request, pull_request_target, \
         workflow_run, issue_comment, ...)",
    ),
    AttrSpec::new(
        "permissions",
        AttrKind::Map,
        "effective GITHUB_TOKEN permission per scope: read | write | none (every scope; \
         empty when permissions_source is repository)",
    ),
    AttrSpec::new(
        "write_scopes",
        AttrKind::List,
        "scopes with write access (names; empty when permissions_source is repository)",
    ),
    AttrSpec::new(
        "default_permissions",
        AttrKind::Sym,
        "what unlisted scopes get: read-all | write-all | none (explicit map) | \
         repository (no permissions key: the repository/organization default)",
    ),
    AttrSpec::new(
        "permissions_source",
        AttrKind::Sym,
        "where the effective permissions are set: job | workflow | repository",
    ),
];

/// GITHUB_TOKEN permission scopes (`metadata` is always read and cannot be
/// set).
const SCOPES: &[&str] = &[
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
];

enum Perms {
    Unset,
    ReadAll,
    WriteAll,
    Map(BTreeMap<String, &'static str>),
}

fn level(v: Value<'_, '_>) -> Option<&'static str> {
    match v.text()? {
        "read" => Some("read"),
        "write" => Some("write"),
        "none" => Some("none"),
        _ => None,
    }
}

fn perms(v: Option<Value<'_, '_>>) -> Perms {
    let Some(v) = v else {
        return Perms::Unset;
    };
    if v.is_map() {
        let map = v
            .entries()
            .filter_map(|(k, l)| Some((k.text()?.to_string(), level(l)?)))
            .collect();
        return Perms::Map(map);
    }
    match v.text() {
        Some("read-all") => Perms::ReadAll,
        Some("write-all") => Perms::WriteAll,
        _ => Perms::Unset,
    }
}

fn ident(s: &str) -> Option<Ident> {
    Ident::from_non_secret(s).ok()
}

/// `permissions`, `write_scopes` and `default_permissions`.
fn effective(p: &Perms) -> (BTreeMap<Ident, AttrValue>, Vec<AttrValue>, &'static str) {
    let all = |f: fn(&str) -> &'static str| -> BTreeMap<String, &'static str> {
        SCOPES.iter().map(|s| (s.to_string(), f(s))).collect()
    };
    let (levels, default) = match p {
        Perms::Unset => (BTreeMap::new(), "repository"),
        Perms::ReadAll => (
            all(|s| if s == "id-token" { "none" } else { "read" }),
            "read-all",
        ),
        Perms::WriteAll => (
            all(|s| if s == "models" { "read" } else { "write" }),
            "write-all",
        ),
        Perms::Map(m) => {
            let mut levels = all(|_| "none");
            levels.extend(m.iter().map(|(k, v)| (k.clone(), *v)));
            (levels, "none")
        }
    };
    let mut map = BTreeMap::new();
    let mut writes = Vec::new();
    for (scope, l) in levels {
        if let Some(id) = ident(&scope) {
            if l == "write" {
                writes.push(AttrValue::Name(id.clone()));
            }
            map.insert(id, AttrValue::Sym(l));
        }
    }
    (map, writes, default)
}

/// Event names from `on:` (a name, a list of names or a map).
fn triggers(on: Option<Value<'_, '_>>) -> Vec<AttrValue> {
    let Some(on) = on else {
        return Vec::new();
    };
    let names: BTreeSet<&str> = if on.is_map() {
        on.entries().filter_map(|(k, _)| k.text()).collect()
    } else if on.is_seq() {
        on.items().filter_map(|v| v.text()).collect()
    } else {
        on.text().into_iter().collect()
    };
    names
        .into_iter()
        .filter_map(ident)
        .map(AttrValue::Name)
        .collect()
}

pub struct GithubWorkflow;

impl DocumentType for GithubWorkflow {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a GitHub Actions workflow: one fact per job with triggers and effective token permissions"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        crate::domain::format::is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let yaml = Yaml::parse(doc)?;
        let Some(root) = yaml.root().filter(|r| r.is_map()) else {
            return Ok(());
        };
        let Some(jobs) = root.get("jobs").filter(|j| j.is_map()) else {
            return Ok(());
        };
        let triggers = triggers(root.get("on"));
        let workflow = perms(root.get("permissions"));
        for (id, job) in jobs.entries() {
            let Some(id) = id.text() else {
                continue;
            };
            let job_perms = perms(job.get("permissions"));
            let (p, source) = match (&job_perms, &workflow) {
                (Perms::Unset, Perms::Unset) => (&workflow, "repository"),
                (Perms::Unset, _) => (&workflow, "workflow"),
                _ => (&job_perms, "job"),
            };
            let (map, writes, default) = effective(p);
            let mut attrs = Attrs::new();
            attrs.insert("job", AttrValue::Text(PublicText::from_non_secret(id)));
            attrs.insert("triggers", AttrValue::List(triggers.clone()));
            attrs.insert("permissions", AttrValue::Map(map));
            attrs.insert("write_scopes", AttrValue::List(writes));
            attrs.insert("default_permissions", AttrValue::Sym(default));
            attrs.insert("permissions_source", AttrValue::Sym(source));
            out.fact_at(PublicText::from_non_secret(&format!("jobs.{id}")), attrs);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jobs(text: &str) -> Vec<(String, Attrs)> {
        let mut out = Emitter::default();
        GithubWorkflow
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        assert!(out.values.is_empty());
        out.facts
            .into_iter()
            .map(|(k, a)| (k.unwrap().to_string(), a))
            .collect()
    }

    #[test]
    fn effective_permissions_per_job() {
        let text = "on:\n  pull_request_target:\n    types: [opened]\n  push:\n    branches: [main]\n\
                    permissions: read-all\n\
                    jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: make}]\n\
                    \x20 publish:\n    permissions:\n      contents: read\n      packages: write\n      id-token: write\n\
                    \x20 none:\n    permissions: {}\n";
        let j = jobs(text);
        assert_eq!(j.len(), 3);
        let (path, test) = &j[0];
        assert_eq!(path, "jobs.test");
        assert_eq!(test["job"].to_string(), "test");
        assert_eq!(test["triggers"].to_string(), "pull_request_target, push");
        assert_eq!(test["permissions_source"], AttrValue::Sym("workflow"));
        assert_eq!(test["default_permissions"], AttrValue::Sym("read-all"));
        let AttrValue::Map(m) = &test["permissions"] else {
            panic!()
        };
        assert_eq!(m.len(), SCOPES.len());
        assert_eq!(m[&ident("contents").unwrap()], AttrValue::Sym("read"));
        assert_eq!(m[&ident("id-token").unwrap()], AttrValue::Sym("none"));
        assert_eq!(test["write_scopes"], AttrValue::List(vec![]));

        let publish = &j[1].1;
        assert_eq!(publish["permissions_source"], AttrValue::Sym("job"));
        assert_eq!(publish["default_permissions"], AttrValue::Sym("none"));
        assert_eq!(publish["write_scopes"].to_string(), "id-token, packages");
        let AttrValue::Map(m) = &publish["permissions"] else {
            panic!()
        };
        assert_eq!(m[&ident("issues").unwrap()], AttrValue::Sym("none"));

        let none = &j[2].1;
        assert_eq!(none["permissions_source"], AttrValue::Sym("job"));
        assert_eq!(none["write_scopes"].to_string(), "");
    }

    #[test]
    fn defaults_and_shorthands() {
        let j = jobs("on: push\njobs:\n  a:\n    steps: []\n  b:\n    permissions: write-all\n");
        assert_eq!(j[0].1["triggers"].to_string(), "push");
        assert_eq!(j[0].1["permissions_source"], AttrValue::Sym("repository"));
        assert_eq!(j[0].1["default_permissions"], AttrValue::Sym("repository"));
        assert_eq!(j[0].1["permissions"], AttrValue::Map(BTreeMap::new()));
        assert_eq!(j[1].1["default_permissions"], AttrValue::Sym("write-all"));
        let AttrValue::Map(m) = &j[1].1["permissions"] else {
            panic!()
        };
        assert_eq!(m[&ident("packages").unwrap()], AttrValue::Sym("write"));
        assert_eq!(m[&ident("models").unwrap()], AttrValue::Sym("read"));
        let j = jobs("on: [push, pull_request]\njobs:\n  a: {}\n");
        assert_eq!(j[0].1["triggers"].to_string(), "pull_request, push");
        assert!(jobs("name: no jobs\n").is_empty());
        assert!(jobs("- list\n").is_empty());
    }

    #[test]
    fn anchors_are_supported_within_limits() {
        let text =
            "on: push\npermissions: &p\n  contents: write\njobs:\n  a:\n    permissions: *p\n";
        let j = jobs(text);
        assert_eq!(j[0].1["write_scopes"].to_string(), "contents");
    }
}
