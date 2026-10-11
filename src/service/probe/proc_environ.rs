//! `proc_environ`: what the environment of *other* processes exposes
//! (Linux `/proc/<pid>/environ`).
//!
//! On Linux a process can read the environment of another process that runs
//! as the same user and is dumpable. That environment often holds the
//! secrets of a different job on the same runner (another pipeline's
//! `GITHUB_TOKEN`, a database password), so being able to read it is lateral
//! visibility worth reporting.
//!
//! lootr reads a foreign environment exactly the way it treats a file's
//! bytes: in memory only, to interpret it. Its **values** are classified by
//! the value types, so a GitHub token in another process's environment is
//! found — but, like any secret, the content never becomes a fact. The facts
//! are a summary (how many foreign processes, how many readable) and, for the
//! recognized values, their *type* at the owning process, never their value
//! or variable content.
//!
//! One summary fact of type `proc_environ` per run; plus one fact per
//! recognized value (`github_token`, `jwt`, ...) located at
//! `probe:proc_environ:<name>` (the owning process's name, or its pid if it
//! has none — reports never depend on the volatile pid).

use crate::domain::model::{AttrValue, Attrs, Fact, Ident, Location, Skipped};
use crate::domain::types::{AttrKind, AttrSpec, FactType};
use crate::service::probe::{Probe, ProbeContext, classify_value};

pub const NAME: &str = "proc_environ";

/// Bytes read from one `environ` (more than most real environment blocks).
/// A block that fills it may have been cut: that process is reported as
/// skipped with reason `truncated` (its first entries are still classified).
pub const MAX_ENVIRON: u64 = 256 << 10;
/// Most readable pids / names listed in the summary fact.
const MAX_LISTED: usize = 256;

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "foreign_processes",
        AttrKind::Int,
        "processes other than lootr itself visible in /proc",
    ),
    AttrSpec::new(
        "readable_environ",
        AttrKind::Int,
        "foreign processes whose environment lootr could read",
    ),
    AttrSpec::new(
        "names",
        AttrKind::List,
        "process names (comm) of the readable foreign processes, sorted",
    ),
];

const FACT_TYPES: &[FactType] = &[FactType {
    name: NAME,
    doc: "foreign process environments readable through /proc (one fact per run)",
    schema: ATTRS,
}];

pub struct ProcEnvironProbe;

impl Probe for ProcEnvironProbe {
    fn name(&self) -> &'static str {
        NAME
    }

    fn fact_types(&self) -> &'static [FactType] {
        FACT_TYPES
    }

    fn run(&self, ctx: &ProbeContext<'_>, skipped: &mut Vec<Skipped>) -> Vec<Fact> {
        let Ok(summary_name) = Ident::from_non_secret(NAME) else {
            return Vec::new();
        };
        let own = ctx.system.pid();
        let mut facts = Vec::new();
        let mut foreign = 0i64;
        let mut readable = 0i64;
        let mut readable_names = Vec::new();
        for proc in ctx.system.processes() {
            if proc.pid == own {
                continue;
            }
            foreign += 1;
            let Ok(environ) = ctx.system.read_proc_environ(proc.pid, MAX_ENVIRON) else {
                continue;
            };
            if environ.is_empty() {
                continue; // kernel threads and the like have no environ
            }
            readable += 1;
            // A stable label for the process (its name, else its pid): used in
            // the location so reports do not depend on the volatile pid.
            let label = proc
                .comm
                .as_deref()
                .and_then(|c| Ident::from_non_secret(c).ok())
                .unwrap_or_else(|| {
                    Ident::from_non_secret(&proc.pid.to_string())
                        .unwrap_or_else(|_| summary_name.clone())
                });
            if readable_names.len() < MAX_LISTED {
                readable_names.push(AttrValue::Name(label.clone()));
            }
            classify_environ(ctx, &label, environ.as_slice(), &mut facts);
            if environ.len() as u64 >= MAX_ENVIRON
                && let Ok(name) = Ident::from_non_secret(&format!("{NAME}:{label}"))
            {
                skipped.push(Skipped {
                    source: ctx.source.clone(),
                    location: Location::Probe { name },
                    reason: "truncated",
                    detail: format!(
                        "environment larger than {} KiB: only the first part was classified",
                        MAX_ENVIRON >> 10
                    ),
                });
            }
        }
        readable_names.sort_by_key(|a| a.to_string());
        let mut attrs = Attrs::new();
        attrs.insert("foreign_processes", AttrValue::Int(foreign));
        attrs.insert("readable_environ", AttrValue::Int(readable));
        attrs.insert("names", AttrValue::List(readable_names));
        let summary = Fact {
            type_: summary_name.clone(),
            location: Location::Probe { name: summary_name },
            source: ctx.source.clone(),
            attrs,
        };
        // Summary first, then the per-value facts.
        let mut out = vec![summary];
        out.append(&mut facts);
        out
    }
}

/// Splits a NUL-separated environment block into `KEY=VALUE` entries and
/// classifies each value through the value types, at
/// `probe:proc_environ:<label>` (the process name, or its pid).
fn classify_environ(
    ctx: &ProbeContext<'_>,
    label: &Ident,
    environ: crate::domain::secret::SecretSlice<'_>,
    facts: &mut Vec<Fact>,
) {
    let Ok(name) = Ident::from_non_secret(&format!("{NAME}:{label}")) else {
        return;
    };
    let location = Location::Probe { name };
    let bytes = environ.expose();
    let mut start = 0;
    for end in 0..=bytes.len() {
        if end == bytes.len() || bytes[end] == 0 {
            if end > start
                && let Some(eq) = bytes[start..end].iter().position(|&b| b == b'=')
                && let Some(value) = environ.slice(start + eq + 1..end)
            {
                classify_value(ctx.registry, ctx.source, &location, None, value, facts);
            }
            start = end + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Registry;
    use crate::repository::fake::{FakeFiles, FakeSystem};

    fn run(system: &FakeSystem) -> Vec<Fact> {
        run_skipped(system).0
    }

    fn run_skipped(system: &FakeSystem) -> (Vec<Fact>, Vec<Skipped>) {
        let source = Ident::from_non_secret("proc").unwrap();
        let files = FakeFiles::new();
        let registry = Registry::builtin(0);
        let ctx = ProbeContext {
            source: &source,
            paths: &[],
            system,
            files: &files,
            registry: &registry,
        };
        let mut skipped = Vec::new();
        let facts = ProcEnvironProbe.run(&ctx, &mut skipped);
        (facts, skipped)
    }

    /// An environment that fills the read limit is reported as truncated,
    /// never silently cut.
    #[test]
    fn a_huge_environment_is_reported_as_truncated() {
        let big = format!("A={}\0", "x".repeat(MAX_ENVIRON as usize));
        let system = FakeSystem::default()
            .process(200, "big", big)
            .process(201, "small", "B=1\0");
        let (facts, skipped) = run_skipped(&system);
        assert_eq!(facts[0].attrs["readable_environ"], AttrValue::Int(2));
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].reason, "truncated");
        assert_eq!(skipped[0].location.to_string(), "probe:proc_environ:big");
    }

    #[test]
    fn classifies_a_token_in_a_foreign_environment() {
        let token = crate::testing::github_token("ghp_", "LOOTRCANARYclassicTok012345678");
        let environ = format!("PATH=/bin\0GITHUB_TOKEN={token}\0HOME=/home/x\0");
        let system = FakeSystem::default()
            .process(100, "lootr", "SELF=1\0") // own pid, skipped
            .process(200, "sleep", environ)
            .process_unreadable(300, "secret-job");
        let facts = run(&system);
        let summary = &facts[0];
        assert_eq!(summary.type_.as_str(), "proc_environ");
        assert_eq!(summary.attrs["foreign_processes"], AttrValue::Int(2));
        assert_eq!(summary.attrs["readable_environ"], AttrValue::Int(1));
        let gh = facts
            .iter()
            .find(|f| f.type_.as_str() == "github_token")
            .expect("github token found in the foreign environment");
        assert_eq!(gh.location.to_string(), "probe:proc_environ:sleep");
        assert_eq!(summary.attrs["names"].to_string(), "sleep");
    }

    #[test]
    fn no_processes_means_only_the_summary() {
        let facts = run(&FakeSystem::default());
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].attrs["readable_environ"], AttrValue::Int(0));
    }
}
