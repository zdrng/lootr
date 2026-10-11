//! Markdown report (`--format markdown`): for pull request comments and
//! GitHub job summaries (`$GITHUB_STEP_SUMMARY`), GitLab merge request notes
//! and the like.
//!
//! Layout: the result and a summary table by severity (unwaived and waived
//! findings), then the unwaived findings grouped by severity (rule, location,
//! message, remediation, tags), waived findings, expired waivers, rule
//! errors and skipped files (collapsed). `--summary-only` stops after the
//! summary table.
//!
//! Every value that comes from the scan or the config (messages, locations,
//! rule ids, reasons) is written as a code span: a key name like
//! `@org/team` or `https://example.org` and text like `<img>` must not turn
//! into a mention, a link or HTML in a pull request comment.

use std::fmt::Write as _;

use crate::domain::model::{Finding, Severity};
use crate::report::Report;

/// Severities from the highest down.
const ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// `text` as an inline code span: no Markdown, HTML, link or mention inside
/// is interpreted. `in_table` escapes `|` (GFM tables split cells on it even
/// inside code spans).
pub fn code(text: &str, in_table: bool) -> String {
    let mut t = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            t.push(' ');
        } else {
            // Bidi overrides and zero-width characters become visible
            // escapes (`\u{202e}`).
            crate::domain::model::push_display_safe(&mut t, c);
        }
    }
    if in_table {
        t = t.replace('|', "\\|");
    }
    if t.trim().is_empty() {
        return "-".to_string();
    }
    let mut longest = 0;
    let mut run = 0;
    for c in t.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    let pad = if t.starts_with('`') || t.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{t}{pad}{fence}")
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    let s = &report.summary;
    let _ = writeln!(out, "## lootr report\n");
    let fail_on = report.run.fail_on;
    let result = if s.rule_errors > 0 {
        format!(
            "**Result: error**: {} failed to evaluate (exit code 2).",
            count(s.rule_errors, "rule", "rules")
        )
    } else if s.failing > 0 || s.failing_skipped > 0 {
        let mut why = Vec::new();
        if s.failing > 0 {
            why.push(format!(
                "{} at or above `{fail_on}`",
                count(s.failing, "unwaived finding", "unwaived findings")
            ));
        }
        if s.failing_skipped > 0 {
            why.push(format!(
                "{} with a `fail-on-skipped` reason",
                count(s.failing_skipped, "skipped entry", "skipped entries")
            ));
        }
        format!("**Result: failed**: {}.", why.join(", "))
    } else {
        format!("**Result: passed**: no unwaived finding at or above `{fail_on}`.")
    };
    let _ = writeln!(out, "{result}\n");

    let _ = writeln!(out, "| Severity | Findings | Waived |");
    let _ = writeln!(out, "|:---|---:|---:|");
    let by = &s.by_severity;
    for sev in ORDER {
        let unwaived = match sev {
            Severity::Critical => by.critical,
            Severity::High => by.high,
            Severity::Medium => by.medium,
            Severity::Low => by.low,
            Severity::Info => by.info,
        };
        let waived = report
            .findings
            .iter()
            .filter(|f| f.severity == sev && f.waived.is_some())
            .count();
        let _ = writeln!(out, "| {sev} | {unwaived} | {waived} |");
    }
    let _ = writeln!(
        out,
        "| **total** | **{}** | **{}** |\n",
        s.findings - s.waived,
        s.waived
    );
    let mut notes = vec![
        count(s.facts, "fact", "facts"),
        count(s.candidates, "candidate", "candidates"),
    ];
    if s.expired_waivers > 0 {
        notes.push(count(
            s.expired_waivers,
            "expired waiver",
            "expired waivers",
        ));
    }
    if s.skipped > 0 {
        notes.push(format!("{} skipped", s.skipped));
    }
    let layers: Vec<String> = report
        .run
        .config_layers
        .iter()
        .map(|l| code(l, false))
        .collect();
    let _ = writeln!(
        out,
        "lootr {} · {} · config: {}\n",
        report.tool.version,
        notes.join(" · "),
        layers.join(", ")
    );
    if report.summary_only {
        if !s.by_rule.is_empty() {
            let _ = writeln!(out, "| Rule | Findings |");
            let _ = writeln!(out, "|:---|---:|");
            for (rule, n) in &s.by_rule {
                let _ = writeln!(out, "| {} | {n} |", code(rule, true));
            }
            out.push('\n');
        }
        return out;
    }

    let unwaived: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.waived.is_none())
        .collect();
    if !unwaived.is_empty() {
        let _ = writeln!(out, "### Findings\n");
    }
    for sev in ORDER {
        let group: Vec<&&Finding> = unwaived.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(out, "#### {sev} ({})\n", group.len());
        for f in group {
            let _ = writeln!(
                out,
                "- **{}** at {}: {}",
                code(f.rule.as_str(), false),
                code(&f.fact.location.to_string(), false),
                code(&f.message, false)
            );
            if !f.remediation.is_empty() {
                let _ = writeln!(out, "  - Remediation: {}", code(&f.remediation, false));
            }
            if !f.tags.is_empty() {
                let tags: Vec<String> = f
                    .tags
                    .iter()
                    .map(|(k, v)| code(&format!("{k}={v}"), false))
                    .collect();
                let _ = writeln!(out, "  - Tags: {}", tags.join(" "));
            }
        }
        out.push('\n');
    }

    let waived: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.waived.is_some())
        .collect();
    if !waived.is_empty() {
        let _ = writeln!(out, "### Waived ({})\n", waived.len());
        let _ = writeln!(out, "| Severity | Rule | Location | Reason | Expires |");
        let _ = writeln!(out, "|:---|:---|:---|:---|:---|");
        for f in waived {
            let (reason, expires) = match &f.waived {
                Some(w) => (
                    w.reason.to_string(),
                    w.expires.map(|e| e.to_string()).unwrap_or("never".into()),
                ),
                None => (String::new(), String::new()),
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {expires} |",
                f.severity,
                code(f.rule.as_str(), true),
                code(&f.fact.location.to_string(), true),
                code(&reason, true)
            );
        }
        out.push('\n');
    }

    if !report.expired_waivers.is_empty() {
        let _ = writeln!(
            out,
            "### Expired waivers ({})\n",
            report.expired_waivers.len()
        );
        for w in &report.expired_waivers {
            let mut scope = Vec::new();
            if let Some(p) = &w.path {
                scope.push(format!("path {}", code(p, false)));
            }
            if let Some(n) = &w.name {
                scope.push(format!("name {}", code(n, false)));
            }
            let scope = if scope.is_empty() {
                String::new()
            } else {
                format!(" ({})", scope.join(", "))
            };
            let _ = writeln!(
                out,
                "- {}{scope} in {} expired on {}: {}",
                code(w.rule.as_str(), false),
                code(&w.layer, false),
                w.expires,
                code(&w.reason, false)
            );
        }
        out.push('\n');
    }

    if !report.rule_errors.is_empty() {
        let _ = writeln!(out, "### Rule errors ({})\n", report.rule_errors.len());
        for e in &report.rule_errors {
            let _ = writeln!(
                out,
                "- {} failed on {} at {}: {}",
                code(e.rule.as_str(), false),
                code(e.type_.as_str(), false),
                code(&e.location.to_string(), false),
                code(&e.message, false)
            );
        }
        out.push('\n');
    }

    if !report.skipped.is_empty() {
        let _ = writeln!(
            out,
            "<details><summary>Skipped ({})</summary>\n",
            report.skipped.len()
        );
        for s in &report.skipped {
            let _ = writeln!(
                out,
                "- {} (source {}): {}",
                code(&s.location.to_string(), false),
                code(s.source.as_str(), false),
                code(&s.detail, false)
            );
        }
        let _ = writeln!(out, "\n</details>\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::testing::sample;

    #[test]
    fn code_spans_neutralize_markdown() {
        assert_eq!(code("a`b", false), "``a`b``");
        assert_eq!(code("`x`", false), "`` `x` ``");
        assert_eq!(code("a|b", true), "`a\\|b`");
        assert_eq!(code("a\nb", false), "`a b`");
        assert_eq!(code("", false), "-");
        assert_eq!(code("a\u{202e}b\u{200b}", false), "`a\\u{202e}b\\u{200b}`");
        assert_eq!(
            code("@org/team https://x <img>", false),
            "`@org/team https://x <img>`"
        );
    }

    #[test]
    fn full_report() {
        let md = render(&sample(false, false));
        for want in [
            "## lootr report\n",
            "**Result: error**: 1 rule failed to evaluate (exit code 2).",
            "| high | 2 | 1 |",
            "| medium | 1 | 0 |",
            "| **total** | **4** | **1** |",
            "### Findings",
            "#### high (2)",
            "- **`ssh-key-unencrypted`** at `~/.ssh/id_ed25519`: `SSH private key ~/.ssh/id_ed25519 is not encrypted`",
            "  - Remediation: `fix ssh-key-unencrypted`",
            "  - Tags: `category=key-protection`",
            "#### low (1)",
            "### Waived (1)",
            "| high | `ssh-key-unencrypted` | `~/.ssh/ci_deploy` | `hardware-bound \\| *rotated* <weekly>` | 2027-01-31 |",
            "### Expired waivers (1)",
            "- `ssh-key-weak` (path `~/.ssh/old`) in `~/proj/lootr.toml` expired on 2026-01-31: `legacy box`",
            "### Rule errors (1)",
            "<details><summary>Skipped (1)</summary>",
            "config: `<built-in>`, `~/proj/lootr.toml`",
        ] {
            assert!(md.contains(want), "missing {want:?} in\n{md}");
        }
    }

    #[test]
    fn summary_only_and_redaction() {
        let md = render(&sample(true, true));
        assert!(md.contains("| high | 2 | 1 |"), "{md}");
        assert!(md.contains("| `ssh-key-unencrypted` | 1 |"), "{md}");
        assert!(!md.contains("### Findings"), "{md}");
        assert!(!md.contains(".ssh"), "{md}");
        assert!(!md.contains("/home/u"), "{md}");
        let md = render(&sample(true, false));
        assert!(md.contains("`~/<redacted:1>`"), "{md}");
        assert!(md.contains("`./deploy dir/.env#GH_TOKEN`"), "{md}");
        assert!(!md.contains("/home/u"), "{md}");
    }
}
