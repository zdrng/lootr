//! JSON report (`--format json`, the default).
//!
//! # Shape (`schema_version` 1)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "tool": {"name": "lootr", "version": "0.1.0"},
//!   "run": {"started_at": "2026-10-08T14:03:00Z", "duration_ms": 12, "uid": 1000,
//!           "home": "/home/u", "cwd": "/home/u/proj", "config_layers": ["<built-in>"],
//!           "fail_on": "high"},
//!   "custom_types": [{"name": "acme_api_key", "pattern": "^acme_..."}],
//!   "summary": {"candidates": 40, "facts": 41, "findings": 2, "waived": 1, "failing": 1,
//!               "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
//!               "rule_errors": 0, "expired_waivers": 0, "skipped": 1, "failing_skipped": 0,
//!               "by_rule": {"ssh-key-unencrypted": 1}},
//!   "findings": [{"rule": "...", "severity": "high", "message": "...", "remediation": "...",
//!                 "tags": {"category": "key-protection"},
//!                 "waived": null | {"reason": "...", "expires": "2027-01-31"},
//!                 "fact": {"type": "...", "location": {...}, "source": "...", "attrs": {...}}}],
//!   "rule_errors": [{"rule": "...", "type": "...", "location": {...}, "message": "..."}],
//!   "expired_waivers": [{"rule": "...", "path": "~/.ssh/old", "name": null, "reason": "...",
//!                        "expires": "2026-01-31", "layer": "..."}],
//!   "skipped": [{"source": "...", "location": {...}, "reason": "permission_denied", "detail": "..."}],
//!   "facts": [...]                       // only with --emit-facts
//! }
//! ```
//!
//! `by_severity` and `by_rule` count unwaived findings. `Location`, `Fact`
//! and attribute shapes are documented in `domain/model.rs`. Paths below the
//! home directory are written as `~/...` (`run.home` is the absolute home);
//! `--redact-paths` replaces paths outside the working directory (see
//! `report::paths`). Not stable for comparisons: `run.started_at`,
//! `run.duration_ms`, `tool.version`.
//!
//! # `--emit-facts`: facts for external tools
//!
//! `facts` lists every fact of the run in collection order (sources in
//! config order), before any rule ran, plus one `waiver` fact per configured
//! waiver: `{"type": "ssh_private_key", "location": {"kind": "file", "path":
//! "~/.ssh/id_ed25519"}, "source": "ssh", "attrs": {"encrypted": false,
//! "key_type": "ed25519", "mode": 384, ...}}`. Attributes are exactly those of
//! `lootr types --json` (optional ones only when present); values are plain
//! JSON (`true`, `42`, `"rsa"`, lists, objects). Facts never contain secret
//! material, so the array can be handed to jq, OPA or a data warehouse. Use
//! `--no-default` plus your own sources to collect facts without the
//! default rules.
//!
//! # `--summary-only`
//!
//! Only `schema_version`, `tool`, `run`, `custom_types` and `summary`
//! (`by_rule` tells which rules fired, without any location).

use serde::Serialize;

use crate::report::{CustomTypeInfo, Report, RunInfo, Summary, Tool};

#[derive(Serialize)]
struct SummaryOnly<'a> {
    schema_version: u32,
    tool: &'a Tool,
    run: &'a RunInfo,
    custom_types: &'a [CustomTypeInfo],
    summary: &'a Summary,
}

pub fn render(report: &Report) -> String {
    // Serializing plain data structures to a String cannot fail.
    let text = if report.summary_only {
        serde_json::to_string_pretty(&SummaryOnly {
            schema_version: report.schema_version,
            tool: &report.tool,
            run: &report.run,
            custom_types: &report.custom_types,
            summary: &report.summary,
        })
    } else {
        serde_json::to_string_pretty(report)
    };
    text.unwrap_or_default() + "\n"
}

#[cfg(test)]
mod tests {
    use crate::report::testing::sample;

    #[test]
    fn summary_only_has_counts_but_no_locations() {
        let text = super::render(&sample(false, true));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["schema_version", "tool", "run", "custom_types", "summary"]
        );
        assert_eq!(v["summary"]["by_rule"]["dotenv-token-not-gitignored"], 1);
        assert!(!text.contains(".ssh"), "{text}");
        assert!(!text.contains("GH_TOKEN"), "{text}");
    }
}
