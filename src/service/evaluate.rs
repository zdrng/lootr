//! Evaluate: facts + rules → findings. A pure function: no I/O, no secrets
//! (it only sees facts).
//!
//! - Rules are selected by the fact's type and evaluated in config order.
//! - An evaluation error becomes a [`RuleError`] (the run exits with 2); it
//!   never counts as "no finding".
//! - Waivers match by rule id plus, if set, a path glob and/or a name (env
//!   var name or key path). A matching waiver marks the finding as waived;
//!   expired waivers are ignored and listed separately. Waivers for locked
//!   rules from other layers are rejected when the config is loaded.
//! - After all facts, every waiver becomes a `waiver` fact (with the number
//!   of findings it waived) and runs through the rules of that type, so the
//!   policy can report expired, unused or open-ended waivers as findings.
//! - `message` and `remediation` are rendered with the placeholders `{path}`,
//!   `{name}`, `{type}`, `{rule}`, `{source}`, `{location}` and the fact's
//!   attributes (`-` when an optional attribute is missing; `{mode}` in
//!   octal, `0644`).
//!
//! Findings are sorted by severity (highest first), then rule and location.

use std::collections::BTreeMap;

use crate::domain::config::Waiver;
use crate::domain::glob::Glob;
use crate::domain::model::{
    AppliedWaiver, AttrValue, ExpiredWaiver, Fact, Finding, PublicText, RuleError,
};
use crate::domain::template::render;
use crate::domain::time::Date;
use crate::domain::types::waiver;
use crate::service::config::CompiledRule;

/// Message used when a rule has none.
pub const DEFAULT_MESSAGE: &str = "{type} at {location} matches rule {rule}";

#[derive(Default)]
pub struct Evaluation {
    pub findings: Vec<Finding>,
    pub rule_errors: Vec<RuleError>,
    pub expired_waivers: Vec<ExpiredWaiver>,
    /// One `waiver` fact per configured waiver (evaluated after the other
    /// facts, so `matched` is known).
    pub waiver_facts: Vec<Fact>,
}

struct ActiveWaiver<'a> {
    /// Index into the configured waivers.
    index: usize,
    waiver: &'a Waiver,
    path: Option<Glob>,
}

pub fn evaluate(
    facts: &[Fact],
    rules: &[CompiledRule],
    waivers: &[Waiver],
    today: Date,
) -> Evaluation {
    let mut out = Evaluation::default();
    let mut active = Vec::new();
    for (index, w) in waivers.iter().enumerate() {
        match w.expires {
            Some(expires) if expires < today => out.expired_waivers.push(ExpiredWaiver {
                rule: w.rule.clone(),
                path: w.path_pattern.clone(),
                name: w.name.clone(),
                reason: w.reason.clone(),
                expires,
                layer: w.layer.clone(),
            }),
            _ => active.push(ActiveWaiver {
                index,
                waiver: w,
                // Validated at load time.
                path: w.path.as_deref().and_then(|p| Glob::new(p).ok()),
            }),
        }
    }

    let mut by_type: BTreeMap<&str, Vec<&CompiledRule>> = BTreeMap::new();
    for r in rules {
        by_type.entry(r.rule.type_.as_str()).or_default().push(r);
    }

    let mut matched = vec![0; waivers.len()];
    apply(facts, &by_type, &active, &mut matched, &mut out);
    // Waiver facts last: their `matched` counts come from the pass above.
    let waiver_facts = waiver::facts(waivers, &matched, today);
    apply(&waiver_facts, &by_type, &active, &mut matched, &mut out);
    out.waiver_facts = waiver_facts;

    out.findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.fact.location.cmp(&b.fact.location))
    });
    out
}

/// Runs the rules of each fact's type; counts waiver matches in `matched`.
fn apply(
    facts: &[Fact],
    by_type: &BTreeMap<&str, Vec<&CompiledRule>>,
    active: &[ActiveWaiver<'_>],
    matched: &mut [usize],
    out: &mut Evaluation,
) {
    for fact in facts {
        for rule in by_type.get(fact.type_.as_str()).into_iter().flatten() {
            match rule.condition.eval(fact) {
                Ok(false) => {}
                Ok(true) => {
                    let waiver = active
                        .iter()
                        .find(|w| waiver_matches(w, rule.rule.id.as_str(), fact));
                    if let Some(w) = waiver
                        && let Some(n) = matched.get_mut(w.index)
                    {
                        *n += 1;
                    }
                    out.findings.push(finding(rule, fact, waiver));
                }
                Err(message) => out.rule_errors.push(RuleError {
                    rule: rule.rule.id.clone(),
                    type_: fact.type_.clone(),
                    location: fact.location.clone(),
                    message,
                }),
            }
        }
    }
}

fn finding(rule: &CompiledRule, fact: &Fact, waiver: Option<&ActiveWaiver<'_>>) -> Finding {
    let r = &rule.rule;
    let placeholder = |name: &str| -> Option<String> {
        match name {
            "path" => fact.location.path().map(|p| p.to_string()),
            "name" => Some(fact.location.name()),
            "type" => Some(fact.type_.to_string()),
            "rule" => Some(r.id.to_string()),
            "source" => Some(fact.source.to_string()),
            "location" => Some(fact.location.to_string()),
            // Permission bits read best in octal (`0644`).
            "mode" => fact.attrs.get("mode").map(|v| match v {
                AttrValue::Int(m) => format!("{m:04o}"),
                other => other.to_string(),
            }),
            attr => fact.attrs.get(attr).map(|v| v.to_string()),
        }
    };
    let message = render(r.message.as_deref().unwrap_or(DEFAULT_MESSAGE), placeholder);
    let remediation = r
        .remediation
        .as_deref()
        .map(|t| render(t, placeholder))
        .unwrap_or_default();
    let waived = waiver.map(|w| AppliedWaiver {
        reason: PublicText::from_non_secret(&w.waiver.reason),
        expires: w.waiver.expires,
    });
    Finding {
        rule: r.id.clone(),
        severity: r.severity,
        message,
        remediation,
        tags: r.tags.clone(),
        waived,
        fact: fact.clone(),
    }
}

fn waiver_matches(w: &ActiveWaiver<'_>, rule: &str, fact: &Fact) -> bool {
    if w.waiver.rule.as_str() != rule {
        return false;
    }
    if let Some(glob) = &w.path {
        match fact.location.path() {
            Some(p) if glob.matches(p.as_str()) => {}
            _ => return false,
        }
    }
    if let Some(name) = &w.waiver.name
        && *name != fact.location.name()
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::Rule;
    use crate::domain::model::{AttrValue, Attrs, DisplayPath, Ident, Location, Severity};
    use crate::domain::types::test_types::registry;
    use crate::service::cel::{Cel, compile};
    use std::path::Path;

    fn id(s: &str) -> Ident {
        Ident::from_non_secret(s).unwrap()
    }

    fn rule(
        rule_id: &str,
        type_: &str,
        when: &str,
        severity: Severity,
        message: Option<&str>,
    ) -> CompiledRule {
        let info = registry().info(type_).unwrap();
        CompiledRule {
            rule: Rule {
                id: id(rule_id),
                type_: type_.into(),
                when: when.into(),
                severity,
                message: message.map(String::from),
                remediation: Some("fix {path} ({lines} lines)".into()),
                tags: BTreeMap::new(),
                locked: false,
                locked_by: None,
                layer: "test".into(),
            },
            condition: compile(&Cel::new(), when, &info).unwrap(),
        }
    }

    fn doc(path: &str, lines: i64) -> Fact {
        let mut attrs = Attrs::new();
        attrs.insert("lines", AttrValue::Int(lines));
        attrs.insert("marked", AttrValue::Bool(lines > 1));
        Fact {
            type_: id("test_doc"),
            location: Location::File {
                path: DisplayPath::new(Path::new(path)),
                key_path: None,
            },
            source: id("docs"),
            attrs,
        }
    }

    fn token(name: &str) -> Fact {
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym("long"));
        attrs.insert("length", AttrValue::Int(20));
        Fact {
            type_: id("test_token"),
            location: Location::Env { name: id(name) },
            source: id("env"),
            attrs,
        }
    }

    fn waiver(rule: &str, path: Option<&str>, name: Option<&str>, expires: Option<&str>) -> Waiver {
        Waiver {
            rule: id(rule),
            path: path.map(String::from),
            path_pattern: path.map(String::from),
            name: name.map(String::from),
            reason: "accepted".into(),
            expires: expires.map(|d| d.parse().unwrap()),
            layer: "/work/lootr.toml".into(),
            position: 1,
        }
    }

    fn today() -> Date {
        "2026-10-08".parse().unwrap()
    }

    #[test]
    fn rules_apply_by_type_and_render_messages() {
        let rules = [
            rule(
                "marked",
                "test_doc",
                "marked",
                Severity::High,
                Some("{path} has {lines} lines, {nope_ok}"),
            ),
            rule(
                "long",
                "test_token",
                r#"kind == "long""#,
                Severity::Low,
                None,
            ),
        ];
        let facts = [doc("/h/a", 3), doc("/h/b", 1), token("TOKEN")];
        let ev = evaluate(&facts, &rules, &[], today());
        assert!(ev.rule_errors.is_empty());
        let got: Vec<(String, Severity, String)> = ev
            .findings
            .iter()
            .map(|f| (f.rule.to_string(), f.severity, f.message.clone()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    "marked".into(),
                    Severity::High,
                    "/h/a has 3 lines, -".into()
                ),
                (
                    "long".into(),
                    Severity::Low,
                    "test_token at $TOKEN matches rule long".into()
                ),
            ]
        );
        assert_eq!(ev.findings[0].remediation, "fix /h/a (3 lines)");
        assert_eq!(ev.findings[1].remediation, "fix - (- lines)");
    }

    #[test]
    fn evaluation_errors_are_rule_errors() {
        let rules = [rule(
            "label",
            "test_doc",
            r#"label == "x""#,
            Severity::High,
            None,
        )];
        let ev = evaluate(&[doc("/h/a", 3)], &rules, &[], today());
        assert!(ev.findings.is_empty());
        assert_eq!(ev.rule_errors.len(), 1);
        assert_eq!(ev.rule_errors[0].rule.as_str(), "label");
        assert!(
            ev.rule_errors[0].message.contains("label"),
            "{}",
            ev.rule_errors[0].message
        );
    }

    #[test]
    fn waivers_match_by_path_and_name_and_expire() {
        let rules = [
            rule("marked", "test_doc", "marked", Severity::High, None),
            rule("long", "test_token", "true", Severity::Low, None),
        ];
        let facts = [doc("/h/a", 3), doc("/h/b", 3), token("A"), token("B")];
        let waivers = [
            waiver("marked", Some("/h/a"), None, Some("2026-10-08")),
            waiver("marked", Some("/h/*"), None, Some("2026-10-07")),
            waiver("long", None, Some("B"), None),
        ];
        let ev = evaluate(&facts, &rules, &waivers, today());
        let waived: Vec<(String, bool)> = ev
            .findings
            .iter()
            .map(|f| (f.fact.location.to_string(), f.waived.is_some()))
            .collect();
        assert_eq!(
            waived,
            [
                ("/h/a".into(), true),
                ("/h/b".into(), false),
                ("$A".into(), false),
                ("$B".into(), true),
            ]
        );
        assert_eq!(ev.expired_waivers.len(), 1);
        assert_eq!(ev.expired_waivers[0].expires.to_string(), "2026-10-07");
    }

    #[test]
    fn waivers_become_facts_for_waiver_rules() {
        let info = crate::domain::types::Registry::builtin(0)
            .info("waiver")
            .unwrap();
        let waiver_rule = |rule_id: &str, when: &str| CompiledRule {
            rule: Rule {
                id: id(rule_id),
                type_: "waiver".into(),
                when: when.into(),
                severity: Severity::Low,
                message: Some("waiver for {waived_rule} in {path} ({name}): {reason}".into()),
                remediation: None,
                tags: BTreeMap::new(),
                locked: false,
                locked_by: None,
                layer: "test".into(),
            },
            condition: compile(&Cel::new(), when, &info).unwrap(),
        };
        let rules = [
            rule("marked", "test_doc", "marked", Severity::High, None),
            waiver_rule("waiver-expired", "expired"),
            waiver_rule("waiver-unused", "!expired && matched == 0"),
            waiver_rule("waiver-open-ended", "!has(attrs.expires)"),
        ];
        let facts = [doc("/h/a", 3), doc("/h/b", 3)];
        let mut waivers = [
            waiver("marked", Some("/h/*"), None, Some("2026-10-31")),
            waiver("marked", Some("/h/a"), None, Some("2026-10-01")),
            waiver("marked", Some("/x/*"), None, None),
        ];
        for (i, w) in waivers.iter_mut().enumerate() {
            w.position = i + 1;
        }
        let ev = evaluate(&facts, &rules, &waivers, today());
        assert!(ev.rule_errors.is_empty(), "{:?}", ev.rule_errors);
        assert_eq!(ev.waiver_facts.len(), 3);
        assert_eq!(ev.waiver_facts[0].attrs["matched"], AttrValue::Int(2));
        let got: Vec<(String, String)> = ev
            .findings
            .iter()
            .filter(|f| f.fact.type_.as_str() == "waiver")
            .map(|f| (f.rule.to_string(), f.message.clone()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    "waiver-expired".into(),
                    "waiver for marked in /work/lootr.toml ([[waiver]] #2): accepted".into()
                ),
                (
                    "waiver-open-ended".into(),
                    "waiver for marked in /work/lootr.toml ([[waiver]] #3): accepted".into()
                ),
                (
                    "waiver-unused".into(),
                    "waiver for marked in /work/lootr.toml ([[waiver]] #3): accepted".into()
                ),
            ]
        );
    }
}
