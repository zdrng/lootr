//! Report: the presentation of a [`ScanResult`].
//!
//! [`Report`] is the format-independent model every renderer works from:
//! [`json`] (the default), [`sarif`] (SARIF 2.1.0 for GitHub code scanning)
//! and [`markdown`] (PR comments, job summaries). It also decides the exit
//! code. Paths are mapped once, when the report is built ([`paths`]: `~`
//! normalization, `--redact-paths`), so every format shows the same paths.
//! With `--summary-only` every renderer leaves out findings, facts and
//! locations and keeps the counts.
//!
//! Renderers return strings; writing them to stdout or `--output` is the
//! CLI's job.

pub mod json;
pub mod markdown;
pub mod paths;
pub mod sarif;

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::domain::model::{
    AttrValue, DisplayPath, ExpiredWaiver, Fact, Finding, Ident, Location, RuleError, Severity,
    Skipped,
};
use crate::domain::time::rfc3339;
use crate::domain::types::Registry;
use crate::report::paths::PathMapper;
use crate::service::scan::ScanResult;

/// Version of the JSON report layout. Bump on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Output formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Sarif,
    Markdown,
}

/// Run information that does not come from the scan itself.
pub struct RunMeta {
    pub duration_ms: u64,
    pub fail_on: Severity,
    pub config_layers: Vec<String>,
    /// Include all facts (`--emit-facts`, JSON only).
    pub emit_facts: bool,
    /// Counts only (`--summary-only`).
    pub summary_only: bool,
    /// `--redact-paths`.
    pub redact_paths: bool,
    /// The enabled rules (SARIF rule metadata).
    pub rules: Vec<RuleMeta>,
    /// Skip reasons that fail the run (`[scan] fail-on-skipped`; `"*"` =
    /// any).
    pub fail_on_skipped: Vec<String>,
}

/// An enabled rule as configured (templates unrendered). Not part of the
/// JSON report; SARIF lists it as rule metadata.
#[derive(Clone, Debug)]
pub struct RuleMeta {
    pub id: Ident,
    pub type_: String,
    pub when: String,
    pub severity: Severity,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub tags: BTreeMap<Ident, Ident>,
    pub locked: bool,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RunInfo {
    pub started_at: String,
    pub duration_ms: u64,
    pub uid: u32,
    pub home: Option<String>,
    pub cwd: String,
    pub config_layers: Vec<String>,
    pub fail_on: Severity,
}

/// A custom regex type from the config. Listed so readers can spot a
/// config that probes for specific secret values.
#[derive(Debug, Serialize)]
pub struct CustomTypeInfo {
    pub name: String,
    pub pattern: String,
}

/// Unwaived findings per severity.
#[derive(Debug, Default, Serialize)]
pub struct BySeverity {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub candidates: usize,
    pub facts: usize,
    pub findings: usize,
    pub waived: usize,
    /// Unwaived findings at or above `fail_on`.
    pub failing: usize,
    pub by_severity: BySeverity,
    pub rule_errors: usize,
    pub expired_waivers: usize,
    pub skipped: usize,
    /// Skipped entries whose reason is in `[scan] fail-on-skipped`.
    pub failing_skipped: usize,
    /// Unwaived findings per rule id.
    pub by_rule: BTreeMap<String, usize>,
}

/// The report. Field order is the JSON order.
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub run: RunInfo,
    pub custom_types: Vec<CustomTypeInfo>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub rule_errors: Vec<RuleError>,
    pub expired_waivers: Vec<ExpiredWaiver>,
    pub skipped: Vec<Skipped>,
    /// Only with `--emit-facts`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<Vec<Fact>>,
    /// `--summary-only`: renderers leave out everything but the counts.
    #[serde(skip)]
    pub summary_only: bool,
    #[serde(skip)]
    pub rules: Vec<RuleMeta>,
    /// The working directory as it appears in mapped paths (`None` with
    /// `--redact-paths`, where project paths are `./relative`).
    #[serde(skip)]
    pub cwd_prefix: Option<String>,
}

impl Report {
    pub fn new(result: ScanResult, registry: &Registry, meta: RunMeta) -> Report {
        let mut summary = Summary {
            candidates: result.candidates,
            facts: result.facts.len(),
            findings: result.findings.len(),
            rule_errors: result.rule_errors.len(),
            expired_waivers: result.expired_waivers.len(),
            skipped: result.skipped.len(),
            failing_skipped: result
                .skipped
                .iter()
                .filter(|s| {
                    meta.fail_on_skipped
                        .iter()
                        .any(|r| r == "*" || r == s.reason)
                })
                .count(),
            ..Summary::default()
        };
        for f in &result.findings {
            if f.waived.is_some() {
                summary.waived += 1;
                continue;
            }
            if f.severity >= meta.fail_on {
                summary.failing += 1;
            }
            *summary.by_rule.entry(f.rule.to_string()).or_default() += 1;
            let s = &mut summary.by_severity;
            *match f.severity {
                Severity::Critical => &mut s.critical,
                Severity::High => &mut s.high,
                Severity::Medium => &mut s.medium,
                Severity::Low => &mut s.low,
                Severity::Info => &mut s.info,
            } += 1;
        }

        let mut paths = PathMapper::new(result.home.as_deref(), &result.cwd, meta.redact_paths);
        let findings = result
            .findings
            .into_iter()
            .map(|f| map_finding(f, &mut paths))
            .collect();
        let rule_errors = result
            .rule_errors
            .into_iter()
            .map(|e| {
                let message = match e.location.path() {
                    Some(p) => paths.text(&e.message, p.as_str()),
                    None => e.message,
                };
                RuleError {
                    location: map_location(e.location, &mut paths),
                    message,
                    ..e
                }
            })
            .collect();
        let expired_waivers = result
            .expired_waivers
            .into_iter()
            .map(|w| ExpiredWaiver {
                layer: paths.map(&w.layer),
                ..w
            })
            .collect();
        let skipped = result
            .skipped
            .into_iter()
            .map(|s| Skipped {
                location: map_location(s.location, &mut paths),
                ..s
            })
            .collect();
        let facts = meta.emit_facts.then(|| {
            result
                .facts
                .into_iter()
                .map(|f| map_fact(f, &mut paths))
                .collect()
        });
        let config_layers = meta.config_layers.iter().map(|l| paths.map(l)).collect();
        let home = result.home.map(|h| paths.run_dir(&h.display().to_string()));
        let cwd = paths.run_dir(&result.cwd.display().to_string());

        Report {
            schema_version: SCHEMA_VERSION,
            tool: Tool {
                name: "lootr",
                version: env!("CARGO_PKG_VERSION"),
            },
            run: RunInfo {
                started_at: rfc3339(result.started_at),
                duration_ms: meta.duration_ms,
                uid: result.uid,
                home,
                cwd,
                config_layers,
                fail_on: meta.fail_on,
            },
            custom_types: registry
                .custom_types()
                .iter()
                .map(|t| CustomTypeInfo {
                    name: crate::domain::types::ValueType::name(t).to_string(),
                    pattern: t.pattern().to_string(),
                })
                .collect(),
            summary,
            findings,
            rule_errors,
            expired_waivers,
            skipped,
            facts,
            summary_only: meta.summary_only,
            rules: meta.rules,
            cwd_prefix: paths.cwd_prefix(),
        }
    }

    /// Whether the run fails (exit code 1 or 2).
    pub fn passed(&self) -> bool {
        self.exit_code() == 0
    }

    /// 2 if a rule failed to evaluate, 1 if an unwaived finding is at or
    /// above `fail_on` or a skipped entry has a `fail-on-skipped` reason,
    /// else 0.
    pub fn exit_code(&self) -> u8 {
        if self.summary.rule_errors > 0 {
            2
        } else if self.summary.failing > 0 || self.summary.failing_skipped > 0 {
            1
        } else {
            0
        }
    }

    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Json => json::render(self),
            Format::Sarif => sarif::render(self),
            Format::Markdown => markdown::render(self),
        }
    }
}

fn map_location(location: Location, paths: &mut PathMapper) -> Location {
    match location {
        Location::File { path, key_path } => Location::File {
            path: DisplayPath::new(Path::new(&paths.map(path.as_str()))),
            key_path,
        },
        other => other,
    }
}

fn map_attr(value: AttrValue, paths: &mut PathMapper) -> AttrValue {
    match value {
        AttrValue::Path(p) => AttrValue::Path(DisplayPath::new(Path::new(&paths.map(p.as_str())))),
        AttrValue::List(items) => {
            AttrValue::List(items.into_iter().map(|v| map_attr(v, paths)).collect())
        }
        AttrValue::Map(map) => AttrValue::Map(
            map.into_iter()
                .map(|(k, v)| (k, map_attr(v, paths)))
                .collect(),
        ),
        other => other,
    }
}

fn map_fact(fact: Fact, paths: &mut PathMapper) -> Fact {
    Fact {
        location: map_location(fact.location, paths),
        attrs: fact
            .attrs
            .into_iter()
            .map(|(k, v)| (k, map_attr(v, paths)))
            .collect(),
        ..fact
    }
}

/// Maps the location and every path inside the rendered texts.
fn map_finding(f: Finding, paths: &mut PathMapper) -> Finding {
    let (message, remediation) = match f.fact.location.path() {
        Some(p) => {
            let p = p.as_str().to_string();
            (paths.text(&f.message, &p), paths.text(&f.remediation, &p))
        }
        None => (f.message, f.remediation),
    };
    Finding {
        message,
        remediation,
        fact: map_fact(f.fact, paths),
        ..f
    }
}

/// Builds the report model from scan results for renderer tests.
#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::domain::model::{AppliedWaiver, Attrs, PublicText};
    use std::path::PathBuf;

    pub fn id(s: &str) -> Ident {
        Ident::from_non_secret(s).unwrap()
    }

    pub fn file(path: &str, key: Option<&str>) -> Location {
        Location::File {
            path: DisplayPath::new(Path::new(path)),
            key_path: key.map(PublicText::from_non_secret),
        }
    }

    pub fn finding(rule: &str, severity: Severity, location: Location, message: &str) -> Finding {
        let mut tags = BTreeMap::new();
        tags.insert(id("category"), id("key-protection"));
        Finding {
            rule: id(rule),
            severity,
            message: message.into(),
            remediation: format!("fix {rule}"),
            tags,
            waived: None,
            fact: Fact {
                type_: id("ssh_private_key"),
                location,
                source: id("ssh"),
                attrs: Attrs::new(),
            },
        }
    }

    pub fn rule(id_: &str, severity: Severity) -> RuleMeta {
        let mut tags = BTreeMap::new();
        tags.insert(id("category"), id("key-protection"));
        RuleMeta {
            id: id(id_),
            type_: "ssh_private_key".into(),
            when: "!encrypted".into(),
            severity,
            message: Some("SSH private key {path} is not encrypted".into()),
            remediation: Some("ssh-keygen -p -f {path}".into()),
            tags,
            locked: id_ == "ssh-key-unencrypted",
        }
    }

    /// A report with findings in the project, the home, env and a probe,
    /// one waived finding, a rule error, an expired waiver and a skipped file.
    pub fn sample(redact: bool, summary_only: bool) -> Report {
        let mut waived = finding(
            "ssh-key-unencrypted",
            Severity::High,
            file("/home/u/.ssh/ci_deploy", None),
            "SSH private key /home/u/.ssh/ci_deploy is not encrypted",
        );
        waived.waived = Some(AppliedWaiver {
            reason: PublicText::from_non_secret("hardware-bound | *rotated* <weekly>"),
            expires: Some("2027-01-31".parse().unwrap()),
        });
        let mut env = finding(
            "github-token",
            Severity::Medium,
            Location::Env {
                name: id("GH_TOKEN"),
            },
            "GitHub app token (ghs_) visible in $GH_TOKEN",
        );
        env.fact.type_ = id("github_token");
        let mut probe = finding(
            "process-root",
            Severity::Low,
            Location::Probe {
                name: id("process"),
            },
            "lootr runs as root",
        );
        probe.tags.clear();
        let result = ScanResult {
            started_at: 1_791_468_180,
            uid: 1000,
            home: Some(PathBuf::from("/home/u")),
            cwd: PathBuf::from("/home/u/proj"),
            candidates: 9,
            facts: Vec::new(),
            findings: vec![
                finding(
                    "ssh-key-unencrypted",
                    Severity::High,
                    file("/home/u/.ssh/id_ed25519", None),
                    "SSH private key /home/u/.ssh/id_ed25519 is not encrypted",
                ),
                finding(
                    "dotenv-token-not-gitignored",
                    Severity::High,
                    file("/home/u/proj/deploy dir/.env", Some("GH_TOKEN")),
                    "GH_TOKEN in /home/u/proj/deploy dir/.env holds a github_token",
                ),
                waived,
                env,
                probe,
            ],
            rule_errors: vec![RuleError {
                rule: id("broken"),
                type_: id("env_var"),
                location: Location::Env { name: id("MULTI") },
                message: "no such overload".into(),
            }],
            expired_waivers: vec![ExpiredWaiver {
                rule: id("ssh-key-weak"),
                path: Some("~/.ssh/old".into()),
                name: None,
                reason: "legacy box".into(),
                expires: "2026-01-31".parse().unwrap(),
                layer: "/home/u/proj/lootr.toml".into(),
            }],
            skipped: vec![Skipped {
                source: id("ssh"),
                location: file("/home/u/.ssh/sock", None),
                reason: "not_regular",
                detail: "not a regular file (socket)".into(),
            }],
        };
        let meta = RunMeta {
            duration_ms: 3,
            fail_on: Severity::High,
            config_layers: vec!["<built-in>".into(), "/home/u/proj/lootr.toml".into()],
            emit_facts: false,
            summary_only,
            redact_paths: redact,
            fail_on_skipped: Vec::new(),
            rules: vec![
                rule("ssh-key-unencrypted", Severity::High),
                rule("dotenv-token-not-gitignored", Severity::High),
                rule("github-token", Severity::Medium),
                rule("process-root", Severity::Low),
                rule("unused-rule", Severity::Info),
            ],
        };
        Report::new(result, &Registry::default(), meta)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::sample;

    #[test]
    fn paths_are_mapped_everywhere() {
        let r = sample(false, false);
        let json = super::json::render(&r);
        assert!(!json.contains("\"/home/u/.ssh"), "{json}");
        assert!(
            json.contains("~/.ssh/id_ed25519 is not encrypted"),
            "{json}"
        );
        assert!(
            json.contains("\"path\": \"~/proj/deploy dir/.env\""),
            "{json}"
        );
        assert_eq!(r.run.home.as_deref(), Some("/home/u"));
        assert_eq!(r.run.config_layers[1], "~/proj/lootr.toml");
        assert_eq!(r.summary.by_rule["ssh-key-unencrypted"], 1);
        assert_eq!(r.summary.waived, 1);
        assert_eq!(r.summary.failing, 2);

        let r = sample(true, false);
        let json = super::json::render(&r);
        assert!(!json.contains("/home/u"), "{json}");
        assert!(!json.contains("id_ed25519"), "{json}");
        assert!(!json.contains("ci_deploy"), "{json}");
        assert!(json.contains("./deploy dir/.env"), "{json}");
        assert!(json.contains("~/<redacted:1> is not encrypted"), "{json}");
        assert_eq!(r.run.cwd, "<redacted>");
        assert_eq!(r.expired_waivers[0].layer, "./lootr.toml");
    }
}
