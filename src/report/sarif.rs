//! SARIF 2.1.0 (`--format sarif`), for GitHub code scanning and other SARIF
//! consumers.
//!
//! - One run; `tool.driver.rules` lists every enabled rule: `shortDescription`
//!   is the message template with placeholders shown as `<path>`,
//!   `fullDescription` the fact type and CEL condition, `help` the
//!   remediation template. `properties.tags` holds `security` plus the rule's
//!   tags as `key/value`; `properties.security-severity` maps the severity
//!   for GitHub (critical 9.5, high 8.0, medium 5.5, low 3.0; info none).
//! - Levels: critical/high → `error`, medium → `warning`, low/info → `note`.
//! - Locations: files below the working directory (the repository root when
//!   lootr runs in a checkout) are relative URIs with `uriBaseId`
//!   `%SRCROOT%`; other files are absolute `file://` URIs (with
//!   `--redact-paths` they have no physical location, only the redacted
//!   name); a key inside a file, an env var and a probe are logical
//!   locations. GitHub code scanning only shows results with a file in the
//!   repository; the others stay in the SARIF file.
//! - Waived findings carry an `external` / `accepted` suppression with the
//!   waiver's reason. Rule errors and skipped files are tool execution
//!   notifications, expired waivers configuration notifications;
//!   `executionSuccessful` is false when a rule failed.
//! - `partialFingerprints.lootr/v1` is `<rule>|<location>` (as shown in the
//!   report), so alerts stay the same across runs.
//! - `--summary-only`: rules and notifications without locations, no
//!   `results` (do not upload it to code scanning: it would not close or
//!   open alerts), the summary in `runs[0].properties.summary`.
//!
//! Only facts reach this file: messages and locations contain no secret
//! material, like every other format.

use serde_json::{Map, Value, json};

use crate::domain::model::{Finding, Location, Severity};
use crate::domain::template::render as render_template;
use crate::report::paths::{REDACTED, below};
use crate::report::{Report, RuleMeta};
use crate::service::evaluate::DEFAULT_MESSAGE;

pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
/// `uriBaseId` of files below the working directory.
pub const SRCROOT: &str = "%SRCROOT%";

pub fn render(report: &Report) -> String {
    serde_json::to_string_pretty(&sarif(report)).unwrap_or_default() + "\n"
}

/// SARIF level of a severity.
pub fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub's `security-severity` (0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high,
/// 9.0+ critical).
fn security_severity(severity: Severity) -> Option<&'static str> {
    match severity {
        Severity::Critical => Some("9.5"),
        Severity::High => Some("8.0"),
        Severity::Medium => Some("5.5"),
        Severity::Low => Some("3.0"),
        Severity::Info => None,
    }
}

fn text(t: &str) -> Value {
    json!({ "text": t })
}

/// A message template with its placeholders as `<name>`.
fn template_text(template: &str) -> String {
    render_template(template, |name| Some(format!("<{name}>")))
}

fn rule_descriptor(rule: &RuleMeta) -> Value {
    let mut tags = vec![Value::from("security")];
    tags.extend(
        rule.tags
            .iter()
            .map(|(k, v)| Value::from(format!("{k}/{v}"))),
    );
    let mut props = Map::new();
    props.insert("tags".into(), Value::Array(tags));
    if let Some(s) = security_severity(rule.severity) {
        props.insert("security-severity".into(), s.into());
    }
    props.insert("lootr-type".into(), rule.type_.clone().into());
    props.insert("lootr-severity".into(), rule.severity.as_str().into());
    props.insert("lootr-locked".into(), rule.locked.into());

    let mut d = Map::new();
    d.insert("id".into(), rule.id.as_str().into());
    d.insert("name".into(), rule.id.as_str().into());
    d.insert(
        "shortDescription".into(),
        text(&template_text(
            rule.message.as_deref().unwrap_or(DEFAULT_MESSAGE),
        )),
    );
    d.insert(
        "fullDescription".into(),
        text(&format!(
            "Matches {} facts where: {}",
            rule.type_,
            rule.when.split_whitespace().collect::<Vec<_>>().join(" ")
        )),
    );
    if let Some(r) = &rule.remediation {
        d.insert("help".into(), text(&template_text(r)));
    }
    d.insert(
        "defaultConfiguration".into(),
        json!({ "level": level(rule.severity) }),
    );
    d.insert("properties".into(), Value::Object(props));
    Value::Object(d)
}

/// Percent-encodes a path for a URI (everything but unreserved characters
/// and `/`).
pub fn encode_uri_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The artifact location of a (mapped) report path, if it has one.
fn artifact(path: &str, report: &Report) -> Option<Value> {
    let relative = path
        .strip_prefix("./")
        .or_else(|| below(path, report.cwd_prefix.as_deref()?))
        .filter(|rel| !rel.is_empty());
    if let Some(rel) = relative {
        return Some(json!({ "uri": encode_uri_path(rel), "uriBaseId": SRCROOT }));
    }
    if path.contains("<redacted") {
        return None;
    }
    let absolute = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            let home = report.run.home.as_deref().filter(|h| *h != REDACTED)?;
            format!("{}{rest}", home.trim_end_matches('/'))
        }
        _ => path.to_string(),
    };
    absolute
        .starts_with('/')
        .then(|| json!({ "uri": format!("file://{}", encode_uri_path(&absolute)) }))
}

fn location(loc: &Location, report: &Report) -> Value {
    let mut out = Map::new();
    let logical = match loc {
        Location::File { path, key_path } => {
            let physical = artifact(path.as_str(), report);
            let has_physical = physical.is_some();
            if let Some(a) = physical {
                out.insert("physicalLocation".into(), json!({ "artifactLocation": a }));
            }
            match key_path {
                Some(key) => Some(json!({
                    "name": key.as_str(),
                    "fullyQualifiedName": loc.to_string(),
                    "kind": "variable",
                })),
                None if !has_physical => Some(json!({
                    "name": path.as_str(),
                    "kind": "resource",
                })),
                None => None,
            }
        }
        Location::Env { name } => Some(json!({
            "name": name.as_str(),
            "fullyQualifiedName": loc.to_string(),
            "kind": "variable",
        })),
        Location::Probe { name } => Some(json!({
            "name": name.as_str(),
            "fullyQualifiedName": loc.to_string(),
            "kind": "resource",
        })),
    };
    if let Some(l) = logical {
        out.insert("logicalLocations".into(), json!([l]));
    }
    Value::Object(out)
}

fn result(f: &Finding, rule_index: usize, report: &Report) -> Value {
    let mut props = Map::new();
    props.insert("severity".into(), f.severity.as_str().into());
    props.insert("type".into(), f.fact.type_.as_str().into());
    props.insert("source".into(), f.fact.source.as_str().into());
    if !f.remediation.is_empty() {
        props.insert("remediation".into(), f.remediation.clone().into());
    }
    if !f.tags.is_empty() {
        props.insert("tags".into(), json!(f.tags));
    }
    let mut r = Map::new();
    r.insert("ruleId".into(), f.rule.as_str().into());
    r.insert("ruleIndex".into(), rule_index.into());
    r.insert("level".into(), level(f.severity).into());
    r.insert("message".into(), text(&f.message));
    r.insert(
        "locations".into(),
        json!([location(&f.fact.location, report)]),
    );
    r.insert(
        "partialFingerprints".into(),
        json!({ "lootr/v1": format!("{}|{}", f.rule, f.fact.location) }),
    );
    if let Some(w) = &f.waived {
        let mut justification = w.reason.to_string();
        if let Some(e) = w.expires {
            justification.push_str(&format!(" (waived until {e})"));
        }
        r.insert(
            "suppressions".into(),
            json!([{ "kind": "external", "status": "accepted", "justification": justification }]),
        );
    }
    r.insert("properties".into(), Value::Object(props));
    Value::Object(r)
}

fn sarif(report: &Report) -> Value {
    // Rule metadata: the enabled rules, plus any rule a finding names that
    // has none (cannot happen with a loaded config).
    let mut rules: Vec<Value> = report.rules.iter().map(rule_descriptor).collect();
    let mut ids: Vec<String> = report.rules.iter().map(|r| r.id.to_string()).collect();
    for f in &report.findings {
        if !ids.iter().any(|id| id == f.rule.as_str()) {
            ids.push(f.rule.to_string());
            rules.push(json!({ "id": f.rule.as_str(), "defaultConfiguration": { "level": level(f.severity) } }));
        }
    }
    let index = |rule: &str| ids.iter().position(|id| id == rule);

    let mut exec = Vec::new();
    for e in &report.rule_errors {
        let mut n = Map::new();
        n.insert("level".into(), "error".into());
        if report.summary_only {
            n.insert(
                "message".into(),
                text(&format!("rule `{}` failed on a {} fact", e.rule, e.type_)),
            );
        } else {
            n.insert(
                "message".into(),
                text(&format!(
                    "rule `{}` failed on {} at {}: {}",
                    e.rule, e.type_, e.location, e.message
                )),
            );
            n.insert("locations".into(), json!([location(&e.location, report)]));
        }
        n.insert("associatedRule".into(), rule_ref(e.rule.as_str(), index));
        exec.push(Value::Object(n));
    }
    if !report.summary_only {
        for s in &report.skipped {
            exec.push(json!({
                "level": "note",
                "message": text(&format!("skipped {} (source {}): {}", s.location, s.source, s.detail)),
                "locations": [location(&s.location, report)],
            }));
        }
    }
    let config: Vec<Value> = report
        .expired_waivers
        .iter()
        .map(|w| {
            json!({
                "level": "warning",
                "message": text(&format!(
                    "waiver for `{}` in {} expired on {}; its findings are reported again",
                    w.rule, w.layer, w.expires
                )),
                "associatedRule": rule_ref(w.rule.as_str(), index),
            })
        })
        .collect();

    let mut invocation = Map::new();
    invocation.insert(
        "executionSuccessful".into(),
        report.rule_errors.is_empty().into(),
    );
    invocation.insert("startTimeUtc".into(), report.run.started_at.clone().into());
    invocation.insert("toolExecutionNotifications".into(), Value::Array(exec));
    invocation.insert(
        "toolConfigurationNotifications".into(),
        Value::Array(config),
    );

    let mut bases = Map::new();
    let cwd_known = report.run.cwd != REDACTED && report.run.cwd.starts_with('/');
    bases.insert(
        SRCROOT.into(),
        if cwd_known {
            let dir = report.run.cwd.trim_end_matches('/');
            json!({ "uri": format!("file://{}/", encode_uri_path(dir)) })
        } else {
            json!({ "description": text("the working directory lootr ran in") })
        },
    );

    let mut run = Map::new();
    run.insert(
        "tool".into(),
        json!({ "driver": {
            "name": report.tool.name,
            "version": report.tool.version,
            "semanticVersion": report.tool.version,
            "rules": rules,
        }}),
    );
    run.insert("invocations".into(), json!([invocation]));
    run.insert("originalUriBaseIds".into(), Value::Object(bases));
    if !report.summary_only {
        let results: Vec<Value> = report
            .findings
            .iter()
            .map(|f| result(f, index(f.rule.as_str()).unwrap_or(0), report))
            .collect();
        run.insert("results".into(), Value::Array(results));
    }
    run.insert(
        "properties".into(),
        json!({ "fail_on": report.run.fail_on, "summary": report.summary }),
    );

    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    })
}

fn rule_ref(rule: &str, index: impl Fn(&str) -> Option<usize>) -> Value {
    match index(rule) {
        Some(i) => json!({ "id": rule, "index": i }),
        None => json!({ "id": rule }),
    }
}

#[cfg(test)]
pub mod tests {
    //! A structural check against the SARIF 2.1.0 schema for every object
    //! lootr emits: required properties, no properties the schema does not
    //! define (the schema sets `additionalProperties: false`), enums, URI
    //! syntax and cross references (`ruleIndex`, `uriBaseId`). Shared with
    //! the CLI and canary tests through [`check_sarif`].

    use super::*;
    use crate::report::testing::sample;

    struct Shape {
        required: &'static [&'static str],
        allowed: &'static [&'static str],
    }

    fn shape(kind: &str) -> Shape {
        let (required, allowed): (&[&str], &[&str]) = match kind {
            "log" => (
                &["version", "runs"],
                &[
                    "$schema",
                    "version",
                    "runs",
                    "inlineExternalProperties",
                    "properties",
                ],
            ),
            "run" => (
                &["tool"],
                &[
                    "tool",
                    "invocations",
                    "conversion",
                    "language",
                    "versionControlProvenance",
                    "originalUriBaseIds",
                    "artifacts",
                    "logicalLocations",
                    "graphs",
                    "results",
                    "automationDetails",
                    "runAggregates",
                    "baselineGuid",
                    "redactionTokens",
                    "defaultEncoding",
                    "defaultSourceLanguage",
                    "newlineSequences",
                    "columnKind",
                    "externalPropertyFileReferences",
                    "threadFlowLocations",
                    "taxonomies",
                    "addresses",
                    "translations",
                    "policies",
                    "webRequests",
                    "webResponses",
                    "specialLocations",
                    "properties",
                ],
            ),
            "tool" => (&["driver"], &["driver", "extensions", "properties"]),
            "driver" => (
                &["name"],
                &[
                    "guid",
                    "name",
                    "organization",
                    "product",
                    "productSuite",
                    "shortDescription",
                    "fullDescription",
                    "fullName",
                    "version",
                    "semanticVersion",
                    "dottedQuadFileVersion",
                    "releaseDateUtc",
                    "downloadUri",
                    "informationUri",
                    "globalMessageStrings",
                    "notifications",
                    "rules",
                    "taxa",
                    "locations",
                    "language",
                    "contents",
                    "isComprehensive",
                    "localizedDataSemanticVersion",
                    "minimumRequiredLocalizedDataSemanticVersion",
                    "associatedComponent",
                    "translationMetadata",
                    "supportedTaxonomies",
                    "properties",
                ],
            ),
            "rule" => (
                &["id"],
                &[
                    "id",
                    "deprecatedIds",
                    "guid",
                    "deprecatedGuids",
                    "name",
                    "deprecatedNames",
                    "shortDescription",
                    "fullDescription",
                    "messageStrings",
                    "defaultConfiguration",
                    "helpUri",
                    "help",
                    "relationships",
                    "properties",
                ],
            ),
            "mfmessage" => (&["text"], &["text", "markdown", "properties"]),
            "configuration" => (
                &[],
                &["enabled", "level", "rank", "parameters", "properties"],
            ),
            "result" => (
                &["message"],
                &[
                    "ruleId",
                    "ruleIndex",
                    "rule",
                    "kind",
                    "level",
                    "message",
                    "analysisTarget",
                    "locations",
                    "guid",
                    "correlationGuid",
                    "occurrenceCount",
                    "partialFingerprints",
                    "fingerprints",
                    "stacks",
                    "codeFlows",
                    "graphs",
                    "graphTraversals",
                    "relatedLocations",
                    "suppressions",
                    "baselineState",
                    "rank",
                    "attachments",
                    "hostedViewerUri",
                    "workItemUris",
                    "provenance",
                    "fixes",
                    "taxa",
                    "webRequest",
                    "webResponse",
                    "properties",
                ],
            ),
            "message" => (&[], &["text", "markdown", "id", "arguments", "properties"]),
            "location" => (
                &[],
                &[
                    "id",
                    "physicalLocation",
                    "logicalLocations",
                    "message",
                    "annotations",
                    "relationships",
                    "properties",
                ],
            ),
            "physical" => (
                &[],
                &[
                    "address",
                    "artifactLocation",
                    "region",
                    "contextRegion",
                    "properties",
                ],
            ),
            "artifactLocation" => (
                &[],
                &["uri", "uriBaseId", "index", "description", "properties"],
            ),
            "logical" => (
                &[],
                &[
                    "name",
                    "index",
                    "fullyQualifiedName",
                    "decoratedName",
                    "parentIndex",
                    "kind",
                    "properties",
                ],
            ),
            "suppression" => (
                &["kind"],
                &[
                    "guid",
                    "kind",
                    "status",
                    "justification",
                    "location",
                    "properties",
                ],
            ),
            "invocation" => (
                &["executionSuccessful"],
                &[
                    "commandLine",
                    "arguments",
                    "responseFiles",
                    "startTimeUtc",
                    "endTimeUtc",
                    "exitCode",
                    "ruleConfigurationOverrides",
                    "notificationConfigurationOverrides",
                    "toolExecutionNotifications",
                    "toolConfigurationNotifications",
                    "exitCodeDescription",
                    "exitSignalName",
                    "exitSignalNumber",
                    "processStartFailureMessage",
                    "executionSuccessful",
                    "machine",
                    "account",
                    "processId",
                    "executableLocation",
                    "workingDirectory",
                    "environmentVariables",
                    "stdin",
                    "stdout",
                    "stderr",
                    "stdoutStderr",
                    "properties",
                ],
            ),
            "notification" => (
                &["message"],
                &[
                    "locations",
                    "message",
                    "level",
                    "threadId",
                    "timeUtc",
                    "exception",
                    "descriptor",
                    "associatedRule",
                    "properties",
                ],
            ),
            "descriptorRef" => (&[], &["id", "index", "guid", "toolComponent", "properties"]),
            other => panic!("no shape for {other}"),
        };
        Shape { required, allowed }
    }

    fn obj<'a>(
        v: &'a Value,
        kind: &str,
        at: &str,
        errs: &mut Vec<String>,
    ) -> Option<&'a Map<String, Value>> {
        let Some(m) = v.as_object() else {
            errs.push(format!("{at}: {kind} must be an object"));
            return None;
        };
        let s = shape(kind);
        for r in s.required {
            if !m.contains_key(*r) {
                errs.push(format!("{at}: {kind} lacks required `{r}`"));
            }
        }
        for k in m.keys() {
            if !s.allowed.contains(&k.as_str()) {
                errs.push(format!("{at}: {kind} has unknown property `{k}`"));
            }
        }
        if let Some(p) = m.get("properties")
            && !p.is_object()
        {
            errs.push(format!("{at}: properties must be an object"));
        }
        Some(m)
    }

    fn is_uri_reference(s: &str) -> bool {
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' {
                let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
                if !(hex(i + 1) && hex(i + 2)) {
                    return false;
                }
                i += 3;
                continue;
            }
            if !(b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=".contains(&b)) {
                return false;
            }
            i += 1;
        }
        !s.is_empty()
    }

    fn message(v: &Value, at: &str, errs: &mut Vec<String>) {
        if let Some(m) = obj(v, "message", at, errs)
            && !m.get("text").is_some_and(Value::is_string)
        {
            errs.push(format!("{at}: message needs `text`"));
        }
    }

    fn level(v: Option<&Value>, at: &str, errs: &mut Vec<String>) {
        if let Some(l) = v
            && !["none", "note", "warning", "error"].contains(&l.as_str().unwrap_or(""))
        {
            errs.push(format!("{at}: invalid level {l}"));
        }
    }

    fn location(v: &Value, bases: &Map<String, Value>, at: &str, errs: &mut Vec<String>) {
        let Some(m) = obj(v, "location", at, errs) else {
            return;
        };
        if let Some(p) = m.get("physicalLocation")
            && let Some(p) = obj(p, "physical", at, errs)
            && let Some(a) = p.get("artifactLocation")
            && let Some(a) = obj(a, "artifactLocation", at, errs)
        {
            let uri = a.get("uri").and_then(Value::as_str).unwrap_or("");
            if !is_uri_reference(uri) {
                errs.push(format!("{at}: invalid uri `{uri}`"));
            }
            match a.get("uriBaseId").and_then(Value::as_str) {
                Some(base) if !bases.contains_key(base) => {
                    errs.push(format!("{at}: undefined uriBaseId `{base}`"))
                }
                Some(_) if uri.starts_with('/') || uri.contains("://") => {
                    errs.push(format!("{at}: uri with uriBaseId must be relative"))
                }
                None if !uri.starts_with("file:///") => {
                    errs.push(format!("{at}: uri without uriBaseId must be absolute"))
                }
                _ => {}
            }
        }
        for l in m
            .get("logicalLocations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(l) = obj(l, "logical", at, errs) {
                let kinds = [
                    "function",
                    "member",
                    "module",
                    "namespace",
                    "parameter",
                    "resource",
                    "returnType",
                    "type",
                    "variable",
                    "object",
                    "array",
                    "property",
                    "value",
                    "element",
                    "text",
                    "attribute",
                    "comment",
                    "declaration",
                    "dtd",
                    "processingInstruction",
                ];
                if let Some(k) = l.get("kind")
                    && !kinds.contains(&k.as_str().unwrap_or(""))
                {
                    errs.push(format!("{at}: invalid logical location kind {k}"));
                }
            }
        }
    }

    fn notification(v: &Value, bases: &Map<String, Value>, at: &str, errs: &mut Vec<String>) {
        if let Some(n) = obj(v, "notification", at, errs) {
            if let Some(m) = n.get("message") {
                message(m, at, errs);
            }
            level(n.get("level"), at, errs);
            if let Some(r) = n.get("associatedRule") {
                obj(r, "descriptorRef", at, errs);
            }
            for l in n
                .get("locations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                location(l, bases, at, errs);
            }
        }
    }

    /// Problems of a SARIF log; empty if it fits the schema structure.
    pub fn check_sarif(v: &Value) -> Vec<String> {
        let mut errs = Vec::new();
        let Some(log) = obj(v, "log", "$", &mut errs) else {
            return errs;
        };
        if log.get("version") != Some(&Value::from("2.1.0")) {
            errs.push("$: version must be 2.1.0".into());
        }
        let runs = log
            .get("runs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if runs.is_empty() {
            errs.push("$: runs must not be empty".into());
        }
        for (ri, run) in runs.iter().enumerate() {
            let at = format!("runs[{ri}]");
            let Some(run) = obj(run, "run", &at, &mut errs) else {
                continue;
            };
            let empty = Map::new();
            let bases = run
                .get("originalUriBaseIds")
                .and_then(Value::as_object)
                .unwrap_or(&empty);
            for (k, b) in bases {
                if let Some(b) = obj(
                    b,
                    "artifactLocation",
                    &format!("{at}.originalUriBaseIds.{k}"),
                    &mut errs,
                ) && let Some(uri) = b.get("uri").and_then(Value::as_str)
                    && !(uri.starts_with("file:///") && uri.ends_with('/'))
                {
                    errs.push(format!(
                        "{at}: base `{k}` must be an absolute directory URI"
                    ));
                }
            }
            let mut rule_ids = Vec::new();
            if let Some(tool) = run.get("tool")
                && let Some(tool) = obj(tool, "tool", &at, &mut errs)
                && let Some(driver) = tool.get("driver")
                && let Some(driver) = obj(driver, "driver", &at, &mut errs)
            {
                for (i, r) in driver
                    .get("rules")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    let at = format!("{at}.rules[{i}]");
                    let Some(r) = obj(r, "rule", &at, &mut errs) else {
                        continue;
                    };
                    rule_ids.push(
                        r.get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    );
                    for k in ["shortDescription", "fullDescription", "help"] {
                        if let Some(m) = r.get(k) {
                            obj(m, "mfmessage", &at, &mut errs);
                        }
                    }
                    if let Some(c) = r.get("defaultConfiguration")
                        && let Some(c) = obj(c, "configuration", &at, &mut errs)
                    {
                        level(c.get("level"), &at, &mut errs);
                    }
                    if let Some(p) = r.get("properties") {
                        if let Some(s) = p.get("security-severity") {
                            let ok = s
                                .as_str()
                                .and_then(|s| s.parse::<f64>().ok())
                                .is_some_and(|x| (0.0..=10.0).contains(&x));
                            if !ok {
                                errs.push(format!("{at}: bad security-severity {s}"));
                            }
                        }
                        if !p.get("tags").is_none_or(|t| {
                            t.as_array().is_some_and(|a| a.iter().all(Value::is_string))
                        }) {
                            errs.push(format!("{at}: tags must be strings"));
                        }
                    }
                }
            }
            for (ii, inv) in run
                .get("invocations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let at = format!("{at}.invocations[{ii}]");
                if let Some(inv) = obj(inv, "invocation", &at, &mut errs) {
                    if !inv
                        .get("executionSuccessful")
                        .is_some_and(Value::is_boolean)
                    {
                        errs.push(format!("{at}: executionSuccessful must be a boolean"));
                    }
                    for key in [
                        "toolExecutionNotifications",
                        "toolConfigurationNotifications",
                    ] {
                        for n in inv.get(key).and_then(Value::as_array).into_iter().flatten() {
                            notification(n, bases, &at, &mut errs);
                        }
                    }
                }
            }
            for (i, r) in run
                .get("results")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let at = format!("{at}.results[{i}]");
                let Some(r) = obj(r, "result", &at, &mut errs) else {
                    continue;
                };
                if let Some(m) = r.get("message") {
                    message(m, &at, &mut errs);
                }
                level(r.get("level"), &at, &mut errs);
                let id = r.get("ruleId").and_then(Value::as_str);
                match r.get("ruleIndex").and_then(Value::as_u64) {
                    Some(ix) => {
                        let at_index = usize::try_from(ix).ok().and_then(|ix| rule_ids.get(ix));
                        if at_index.map(String::as_str) != id {
                            errs.push(format!("{at}: ruleIndex does not point at ruleId"));
                        }
                    }
                    None => errs.push(format!("{at}: ruleIndex missing")),
                }
                for l in r
                    .get("locations")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    location(l, bases, &at, &mut errs);
                }
                if let Some(fp) = r.get("partialFingerprints")
                    && !fp
                        .as_object()
                        .is_some_and(|m| m.values().all(Value::is_string))
                {
                    errs.push(format!("{at}: partialFingerprints must map to strings"));
                }
                for s in r
                    .get("suppressions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(s) = obj(s, "suppression", &at, &mut errs) {
                        if !["inSource", "external"].contains(&s["kind"].as_str().unwrap_or("")) {
                            errs.push(format!("{at}: invalid suppression kind"));
                        }
                        if let Some(st) = s.get("status")
                            && !["accepted", "underReview", "rejected"]
                                .contains(&st.as_str().unwrap_or(""))
                        {
                            errs.push(format!("{at}: invalid suppression status"));
                        }
                    }
                }
            }
        }
        errs
    }

    #[test]
    fn levels_follow_severity() {
        assert_eq!(super::level(Severity::Critical), "error");
        assert_eq!(super::level(Severity::High), "error");
        assert_eq!(super::level(Severity::Medium), "warning");
        assert_eq!(super::level(Severity::Low), "note");
        assert_eq!(super::level(Severity::Info), "note");
    }

    #[test]
    fn uri_encoding() {
        assert_eq!(encode_uri_path("deploy dir/.env"), "deploy%20dir/.env");
        assert_eq!(encode_uri_path("a#b?c%d:e"), "a%23b%3Fc%25d%3Ae");
        assert_eq!(encode_uri_path("ü"), "%C3%BC");
        assert!(is_uri_reference("file:///home/u/.ssh/id%20rsa"));
        assert!(!is_uri_reference("a b"));
        assert!(!is_uri_reference("%zz"));
    }

    #[test]
    fn the_validator_catches_schema_violations() {
        let bad = json!({"version": "2.0.0", "runs": [{"tool": {"driver": {}}, "results": [
            {"ruleId": "x", "ruleIndex": 3, "level": "fatal", "message": {"text": "m"}, "bogus": 1,
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a b", "uriBaseId": "NOPE"}}}]}
        ]}]});
        let errs = check_sarif(&bad);
        for want in [
            "version must be 2.1.0",
            "driver lacks required `name`",
            "unknown property `bogus`",
            "invalid level",
            "ruleIndex does not point",
            "invalid uri",
            "undefined uriBaseId",
        ] {
            assert!(errs.iter().any(|e| e.contains(want)), "{want}: {errs:#?}");
        }
    }

    #[test]
    fn the_sample_report_is_valid_sarif() {
        for (redact, summary_only) in [(false, false), (true, false), (false, true)] {
            let text = render(&sample(redact, summary_only));
            let v: Value = serde_json::from_str(&text).unwrap();
            let errs = check_sarif(&v);
            assert!(
                errs.is_empty(),
                "{redact} {summary_only}: {errs:#?}\n{text}"
            );
        }
    }

    #[test]
    fn results_rules_and_locations() {
        let v: Value = serde_json::from_str(&render(&sample(false, false))).unwrap();
        let run = &v["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5, "all enabled rules");
        assert_eq!(
            rules[0]["shortDescription"]["text"],
            "SSH private key <path> is not encrypted"
        );
        assert_eq!(rules[0]["properties"]["security-severity"], "8.0");
        assert_eq!(
            rules[0]["properties"]["tags"],
            json!(["security", "category/key-protection"])
        );
        assert!(rules[4]["properties"].get("security-severity").is_none());
        assert_eq!(
            run["originalUriBaseIds"]["%SRCROOT%"]["uri"],
            "file:///home/u/proj/"
        );
        let results = run["results"].as_array().unwrap();
        let by_rule = |id: &'static str| results.iter().filter(move |r| r["ruleId"] == id);
        let dotenv = by_rule("dotenv-token-not-gitignored").next().unwrap();
        assert_eq!(dotenv["level"], "error");
        assert_eq!(
            dotenv["locations"][0]["physicalLocation"]["artifactLocation"],
            json!({"uri": "deploy%20dir/.env", "uriBaseId": "%SRCROOT%"})
        );
        assert_eq!(
            dotenv["locations"][0]["logicalLocations"][0]["name"],
            "GH_TOKEN"
        );
        let ssh: Vec<&Value> = by_rule("ssh-key-unencrypted").collect();
        let uri = |r: &Value| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (waived, open) = if uri(ssh[0]).ends_with("ci_deploy") {
            (ssh[0], ssh[1])
        } else {
            (ssh[1], ssh[0])
        };
        assert_eq!(uri(waived), "file:///home/u/.ssh/ci_deploy");
        assert_eq!(waived["suppressions"][0]["status"], "accepted");
        assert_eq!(
            waived["suppressions"][0]["justification"],
            "hardware-bound | *rotated* <weekly> (waived until 2027-01-31)"
        );
        assert!(open.get("suppressions").is_none());
        assert_eq!(
            open["message"]["text"],
            "SSH private key ~/.ssh/id_ed25519 is not encrypted"
        );
        let env = by_rule("github-token").next().unwrap();
        assert_eq!(env["level"], "warning");
        assert!(env["locations"][0].get("physicalLocation").is_none());
        assert_eq!(
            env["locations"][0]["logicalLocations"][0]["kind"],
            "variable"
        );
        let inv = &run["invocations"][0];
        assert_eq!(inv["executionSuccessful"], false);
        assert_eq!(inv["toolConfigurationNotifications"][0]["level"], "warning");
    }

    #[test]
    fn redacted_paths_have_no_physical_location() {
        let text = render(&sample(true, false));
        assert!(!text.contains("/home/u"), "{text}");
        let v: Value = serde_json::from_str(&text).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        let ssh = results
            .iter()
            .find(|r| r["ruleId"] == "ssh-key-unencrypted")
            .unwrap();
        assert!(ssh["locations"][0].get("physicalLocation").is_none());
        assert_eq!(
            ssh["locations"][0]["logicalLocations"][0]["name"],
            "~/<redacted:1>"
        );
        let dotenv = results
            .iter()
            .find(|r| r["ruleId"] == "dotenv-token-not-gitignored")
            .unwrap();
        assert_eq!(
            dotenv["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "deploy%20dir/.env"
        );
    }

    #[test]
    fn summary_only_has_no_results() {
        let text = render(&sample(false, true));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert!(v["runs"][0].get("results").is_none());
        assert_eq!(v["runs"][0]["properties"]["summary"]["findings"], 5);
        assert!(!text.contains(".ssh"), "{text}");
    }
}
