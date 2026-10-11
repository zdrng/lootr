//! Config service: reads the layers, merges them and validates the result
//! against the type registry before anything is scanned.
//!
//! # Layers
//!
//! Applied in order: the built-in default (unless `--no-default`), then every
//! `--config` file. A file's `include = [...]` entries are local files
//! relative to it and are applied as layers before the file itself (no URLs,
//! cycles are errors).
//!
//! - `[scan]`: later layers override single settings; `exclude` lists are
//!   appended.
//! - `[[type]]`: by `name`; a later layer replaces the pattern.
//! - `[[source]]` and `[[rule]]`: by `id`; a later layer overrides the fields
//!   it sets (e.g. only `severity`) or disables the entry with
//!   `enabled = false`. Rule `tags` are merged key by key. An entry without
//!   `kind` (source) or `type` (rule) whose id no earlier layer defines is an
//!   error (a typo in an override must not pass silently).
//! - `locked = true` rules: later layers may only raise the severity or
//!   change message, remediation and tags. Disabling, changing `type` or
//!   `when` (whitespace aside), lowering the severity and unlocking are
//!   errors that name the file, the locking layer, the rule and every
//!   attempted change. Only the locking layer may waive a locked rule.
//! - `[[waiver]]`: appended.
//!
//! # Locked inputs
//!
//! A locked rule is only as strong as what it is evaluated on, so its
//! inputs are protected too. Locked against weakening by later layers are:
//!
//! - a `[[source]]`, `[[type]]` or `[scan]` with `locked = true` (set by the
//!   defining layer or by an override, e.g. `[[source]] id = "ssh"`
//!   `locked = true` in a company baseline);
//! - implicitly, everything a locked rule depends on, as it was when the
//!   rule was locked: `[scan]`, every custom type, and every source that can
//!   produce facts of the rule's type (a source with that document type or
//!   that extractor's entry type, env sources for `env_var`, probe sources
//!   for probe fact types; for a value type such as `github_token` or a
//!   custom type: every source).
//!
//! Weakening is: disabling or unlocking; changing a source's `kind`, `type`
//! or `extract`; replacing `paths`, `names`, `probes` or `path-vars` with a
//! list that drops an entry; a source `exclude` with a new entry; changing a
//! custom type's `pattern`; adding `[scan] exclude` entries, lowering
//! `max-file-size` or `max-depth`, or turning `one-file-system` on. Adding
//! sources, rules, types, paths or `fail-on-skipped` reasons is always
//! allowed. Each attempt is an error naming the layer, the locking layer and
//! why it is locked.
//!
//! # Validation
//!
//! Every problem is collected (not just the first) with the layer it comes
//! from: unknown keys, unknown types/extractors/probes, invalid globs and
//! regexes, CEL syntax, identifiers not in the type's schema, unknown
//! placeholders, lock violations. Any error means exit code 2.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::domain::config::{
    CONFIG_VERSION, ConfigFile, FileAction, Rule, RuleSpec, ScanSettings, ScanSpec, Source,
    SourceKind, SourceSpec, Waiver, WaiverSpec,
};
use crate::domain::glob::{Glob, expand_path};
use crate::domain::model::{Ident, SKIP_REASONS, Severity};
use crate::domain::template::placeholders;
use crate::domain::time::Date;
use crate::domain::types::custom::CustomType;
use crate::domain::types::{Registry, TypeInfo, TypeKind, attr_names};
use crate::repository::ConfigRepository;
use crate::service::cel::{self, Cel, Condition};

/// The built-in default layer.
pub const DEFAULT_CONFIG: &str = include_str!("default.toml");
/// Name of the built-in layer in messages and the report.
pub const DEFAULT_LAYER: &str = "<built-in>";
/// Placeholders every message template can use besides attributes.
pub const BUILTIN_PLACEHOLDERS: &[&str] = &["path", "name", "type", "rule", "source", "location"];

const MAX_INCLUDE_DEPTH: usize = 16;

/// What to load.
pub struct ConfigRequest<'a> {
    /// The built-in layer, `None` with `--no-default`.
    pub default: Option<&'a str>,
    /// `--config` files in order (relative to `cwd`).
    pub files: &'a [PathBuf],
    pub cwd: &'a Path,
    pub home: Option<&'a Path>,
    /// Names of the probes the binary has.
    pub probes: &'a [&'a str],
}

/// A rule ready for evaluation.
pub struct CompiledRule {
    pub rule: Rule,
    pub condition: Condition,
}

/// The validated, merged config.
pub struct LoadedConfig {
    pub scan: ScanSettings,
    pub sources: Vec<Source>,
    /// Built-in types plus the config's custom types.
    pub registry: Registry,
    pub rules: Vec<CompiledRule>,
    pub waivers: Vec<Waiver>,
    /// Layer names in the order applied.
    pub layers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// Layer (file) the problem is in.
    pub layer: String,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.layer, self.message)
    }
}

/// All problems found while loading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

struct Layer {
    name: String,
    file: ConfigFile,
}

/// Collects errors with their layer.
#[derive(Default)]
struct Errors(Vec<ConfigError>);

impl Errors {
    fn add(&mut self, layer: &str, message: impl Into<String>) {
        self.0.push(ConfigError {
            layer: layer.to_string(),
            message: message.into(),
        });
    }
}

/// Loads, merges and validates the config. `registry` holds the built-in
/// types; custom types are added to it.
pub fn load(
    repo: &dyn ConfigRepository,
    req: &ConfigRequest<'_>,
    registry: Registry,
    cel: &Cel,
) -> Result<LoadedConfig, ConfigErrors> {
    let mut errors = Errors::default();
    let mut layers = Vec::new();
    if let Some(text) = req.default {
        parse_layer(DEFAULT_LAYER, text, &mut layers, &mut errors);
    }
    for file in req.files {
        let path = normalize(&req.cwd.join(file));
        read_file_layer(repo, &path, &mut Vec::new(), &mut layers, &mut errors);
    }
    if !errors.0.is_empty() {
        return Err(ConfigErrors(errors.0));
    }
    let merged = merge(&layers, &mut errors);
    let config = validate(merged, req, registry, cel, &mut errors);
    if errors.0.is_empty() {
        Ok(LoadedConfig {
            layers: layers.into_iter().map(|l| l.name).collect(),
            ..config
        })
    } else {
        Err(ConfigErrors(errors.0))
    }
}

fn parse_layer(name: &str, text: &str, layers: &mut Vec<Layer>, errors: &mut Errors) -> bool {
    match toml::from_str::<ConfigFile>(text) {
        Ok(file) => {
            if file.version != Some(CONFIG_VERSION) {
                errors.add(name, format!("expected `version = {CONFIG_VERSION}`"));
                return false;
            }
            layers.push(Layer {
                name: name.to_string(),
                file,
            });
            true
        }
        Err(e) => {
            errors.add(name, toml_error(text, &e));
            false
        }
    }
}

/// A TOML error without any text from the file. `toml`'s `Display` prints
/// the offending line and its messages quote keys and values (`invalid
/// type: string "..."`), so a config path given by mistake (`--config .env`,
/// an include of `~/.git-credentials`) would put secrets into CI logs. Only
/// the position and a fixed description are shown; for serde errors the
/// expected part (it comes from lootr's schema) is kept.
fn toml_error(text: &str, e: &toml::de::Error) -> String {
    let message = e.message();
    let expected = |m: &str| {
        // The last `, expected ` starts the schema's part: whatever the file
        // put into the quoted part before it cannot reach past it.
        m.rfind(", expected ")
            .map(|i| format!(", expected {}", &m[i + ", expected ".len()..]))
            .filter(|tail| tail.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
            .unwrap_or_default()
    };
    let kind = if message.starts_with("unknown field `") {
        format!("unknown key{}", expected(message))
    } else if message.starts_with("unknown variant `") {
        format!("unknown value{}", expected(message))
    } else if message.starts_with("invalid type: ") {
        format!("wrong value type{}", expected(message))
    } else if message.starts_with("invalid value: ") || message.starts_with("invalid length ") {
        format!("invalid value{}", expected(message))
    } else if let Some(field) = message.strip_prefix("missing field `") {
        // The field name comes from the schema (`missing field `id``).
        match field.strip_suffix('`') {
            Some(f)
                if f.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'_') =>
            {
                format!("missing key `{f}`")
            }
            _ => "missing key".to_string(),
        }
    } else if message.starts_with("duplicate key") {
        "duplicate key".to_string()
    } else if message.starts_with("data did not match any variant") {
        "invalid value".to_string()
    } else {
        "invalid TOML syntax".to_string()
    };
    match e.span() {
        Some(span) => {
            let (line, column) = line_column(text, span.start);
            format!("line {line}, column {column}: {kind} (file content not shown)")
        }
        None => format!("{kind} (file content not shown)"),
    }
}

/// 1-based line and column (in characters) of byte `offset`.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = text.get(..offset).unwrap_or(text);
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let column = before[line_start..].chars().count() + 1;
    (line, column)
}

/// Reads `path` and its includes (depth first, includes before the file).
fn read_file_layer(
    repo: &dyn ConfigRepository,
    path: &Path,
    stack: &mut Vec<PathBuf>,
    layers: &mut Vec<Layer>,
    errors: &mut Errors,
) {
    let name = path.display().to_string();
    if stack.iter().any(|p| p == path) {
        let chain: Vec<String> = stack.iter().map(|p| p.display().to_string()).collect();
        errors.add(
            &name,
            format!("include cycle: {} -> {name}", chain.join(" -> ")),
        );
        return;
    }
    if stack.len() >= MAX_INCLUDE_DEPTH {
        errors.add(
            &name,
            format!("includes nested deeper than {MAX_INCLUDE_DEPTH}"),
        );
        return;
    }
    let buf = match repo.read(path) {
        Ok(t) => t,
        Err(e) => {
            errors.add(&name, format!("cannot read config: {e}"));
            return;
        }
    };
    let Ok(text) = std::str::from_utf8(buf.expose()) else {
        errors.add(&name, "config is not UTF-8 (file content not shown)");
        return;
    };
    let mut parsed = Vec::new();
    if !parse_layer(&name, text, &mut parsed, errors) {
        return;
    }
    let Some(layer) = parsed.pop() else { return };
    let dir = path.parent().unwrap_or(Path::new("/"));
    stack.push(path.to_path_buf());
    for include in &layer.file.include {
        if include.contains("://") {
            errors.add(
                &name,
                format!("include `{include}`: only local files can be included"),
            );
            continue;
        }
        let inc = normalize(&dir.join(include));
        read_file_layer(repo, &inc, stack, layers, errors);
    }
    stack.pop();
    layers.push(layer);
}

/// Lexical normalization (`a/./b/../c` → `a/c`), without touching the disk.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

// ---- merging ---------------------------------------------------------------

struct MergedRule {
    spec: RuleSpec,
    /// Last layer that touched the rule.
    layer: String,
    /// Index and name of the layer that locked it.
    locked_by: Option<(usize, String)>,
}

struct MergedSource {
    spec: SourceSpec,
    /// Last layer that touched the source.
    layer: String,
    /// Index of the layer that defined it.
    created: usize,
    /// Index and name of the layer that locked it explicitly.
    locked_by: Option<(usize, String)>,
}

struct MergedType {
    pattern: Option<String>,
    layer: String,
    created: usize,
    locked_by: Option<(usize, String)>,
}

/// What a lock protects.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Input {
    Source(String),
    Type(String),
    Scan,
}

/// A layer's change to a source, custom type or `[scan]` that would weaken
/// it, checked against locks once all layers are merged.
struct Weakening {
    index: usize,
    layer: String,
    input: Input,
    /// The source as it was before the change (decides which locked rules
    /// depend on it).
    before: Option<SourceSpec>,
    attempts: Vec<String>,
}

struct Merged {
    scan: Vec<(String, ScanSpec)>,
    scan_locked_by: Option<(usize, String)>,
    types: BTreeMap<String, MergedType>,
    sources: Vec<MergedSource>,
    rules: Vec<MergedRule>,
    waivers: Vec<(WaiverSpec, usize, String)>,
    weakenings: Vec<Weakening>,
}

fn set<T>(dst: &mut Option<T>, src: Option<T>) {
    if src.is_some() {
        *dst = src;
    }
}

/// `[scan]` as merged so far, for spotting weakening overrides.
struct ScanState {
    max_file_size: u64,
    max_depth: u32,
    one_file_system: bool,
    exclude: Vec<String>,
}

fn merge(layers: &[Layer], errors: &mut Errors) -> Merged {
    let mut m = Merged {
        scan: Vec::new(),
        scan_locked_by: None,
        types: BTreeMap::new(),
        sources: Vec::new(),
        rules: Vec::new(),
        waivers: Vec::new(),
        weakenings: Vec::new(),
    };
    let defaults = ScanSettings::default();
    let mut scan = ScanState {
        max_file_size: defaults.max_file_size,
        max_depth: defaults.max_depth,
        one_file_system: defaults.one_file_system,
        exclude: Vec::new(),
    };
    for (index, layer) in layers.iter().enumerate() {
        let name = &layer.name;
        let file = layer.file.clone();
        let attempts = scan_weakening(&mut scan, &file.scan);
        if !attempts.is_empty() {
            m.weakenings.push(Weakening {
                index,
                layer: name.clone(),
                input: Input::Scan,
                before: None,
                attempts,
            });
        }
        if file.scan.locked == Some(true) && m.scan_locked_by.is_none() {
            m.scan_locked_by = Some((index, name.clone()));
        }
        m.scan.push((name.clone(), file.scan));
        for t in file.types {
            match m.types.get_mut(&t.name) {
                Some(existing) => {
                    let mut attempts = Vec::new();
                    if t.locked == Some(false) {
                        attempts.push("unlock it (`locked = false`)".to_string());
                    }
                    if t.pattern.is_some() && t.pattern != existing.pattern {
                        attempts.push("change its pattern".to_string());
                    }
                    if !attempts.is_empty() {
                        m.weakenings.push(Weakening {
                            index,
                            layer: name.clone(),
                            input: Input::Type(t.name.clone()),
                            before: None,
                            attempts,
                        });
                    }
                    set(&mut existing.pattern, t.pattern);
                    if t.locked == Some(true) && existing.locked_by.is_none() {
                        existing.locked_by = Some((index, name.clone()));
                    }
                    existing.layer = name.clone();
                }
                None if t.pattern.is_none() => errors.add(
                    name,
                    format!(
                        "type `{}` overrides nothing: no earlier layer defines this type \
                         (check the name; a new type needs `pattern`)",
                        t.name
                    ),
                ),
                None => {
                    let locked_by = (t.locked == Some(true)).then(|| (index, name.clone()));
                    m.types.insert(
                        t.name,
                        MergedType {
                            pattern: t.pattern,
                            layer: name.clone(),
                            created: index,
                            locked_by,
                        },
                    );
                }
            }
        }
        for s in file.sources {
            match m.sources.iter_mut().find(|e| e.spec.id == s.id) {
                Some(existing) => {
                    let attempts = source_weakening(&existing.spec, &s);
                    if !attempts.is_empty() {
                        m.weakenings.push(Weakening {
                            index,
                            layer: name.clone(),
                            input: Input::Source(s.id.clone()),
                            before: Some(existing.spec.clone()),
                            attempts,
                        });
                    }
                    if s.locked == Some(true) && existing.locked_by.is_none() {
                        existing.locked_by = Some((index, name.clone()));
                    }
                    merge_source(&mut existing.spec, s);
                    existing.layer = name.clone();
                }
                None if s.kind.is_none() => errors.add(
                    name,
                    format!(
                        "source `{}` overrides nothing: no earlier layer defines this source \
                         (check the id; a new source needs `kind`)",
                        s.id
                    ),
                ),
                None => {
                    let locked_by = (s.locked == Some(true)).then(|| (index, name.clone()));
                    m.sources.push(MergedSource {
                        spec: s,
                        layer: name.clone(),
                        created: index,
                        locked_by,
                    });
                }
            }
        }
        for r in file.rules {
            match m.rules.iter_mut().find(|e| e.spec.id == r.id) {
                Some(existing) => override_rule(existing, r, index, name, errors),
                None if r.type_.is_none() => errors.add(
                    name,
                    format!(
                        "rule `{}` overrides nothing: no earlier layer defines this rule \
                         (check the id; a new rule needs `type`, `when` and `severity`)",
                        r.id
                    ),
                ),
                None => {
                    let locked_by = (r.locked == Some(true)).then(|| (index, name.clone()));
                    m.rules.push(MergedRule {
                        spec: r,
                        layer: name.clone(),
                        locked_by,
                    });
                }
            }
        }
        for w in file.waivers {
            m.waivers.push((w, index, name.clone()));
        }
    }
    m
}

fn merge_source(base: &mut SourceSpec, over: SourceSpec) {
    set(&mut base.kind, over.kind);
    set(&mut base.names, over.names);
    set(&mut base.paths, over.paths);
    set(&mut base.exclude, over.exclude);
    set(&mut base.type_, over.type_);
    set(&mut base.extract, over.extract);
    set(&mut base.probes, over.probes);
    set(&mut base.path_vars, over.path_vars);
    set(&mut base.enabled, over.enabled);
    set(&mut base.locked, over.locked);
}

/// `` `a`, `b` `` for messages.
fn quoted(items: &[&String]) -> String {
    let list: Vec<String> = items.iter().map(|i| format!("`{i}`")).collect();
    list.join(", ")
}

/// What `over` would weaken in `base`, as readable phrases (empty if it only
/// strengthens or changes nothing).
fn source_weakening(base: &SourceSpec, over: &SourceSpec) -> Vec<String> {
    let mut out = Vec::new();
    if over.enabled == Some(false) && base.enabled != Some(false) {
        out.push("disable it (`enabled = false`)".to_string());
    }
    if over.locked == Some(false) {
        out.push("unlock it (`locked = false`)".to_string());
    }
    for (field, old, new) in [
        ("kind", &base.kind, &over.kind),
        ("type", &base.type_, &over.type_),
        ("extract", &base.extract, &over.extract),
    ] {
        if new.is_some() && new != old {
            let old = old.as_deref().unwrap_or("-");
            let new = new.as_deref().unwrap_or("-");
            out.push(format!("change its {field} from `{old}` to `{new}`"));
        }
    }
    for (field, old, new) in [
        ("paths", &base.paths, &over.paths),
        ("names", &base.names, &over.names),
        ("probes", &base.probes, &over.probes),
        ("path-vars", &base.path_vars, &over.path_vars),
    ] {
        if let (Some(old), Some(new)) = (old, new) {
            let dropped: Vec<&String> = old.iter().filter(|o| !new.contains(o)).collect();
            if !dropped.is_empty() {
                out.push(format!("drop {field} {}", quoted(&dropped)));
            }
        }
    }
    if let Some(new) = &over.exclude {
        let old = base.exclude.clone().unwrap_or_default();
        let added: Vec<&String> = new.iter().filter(|n| !old.contains(n)).collect();
        if !added.is_empty() {
            out.push(format!("exclude {}", quoted(&added)));
        }
    }
    out
}

/// Applies `spec` to the running `[scan]` state and returns what it would
/// weaken.
fn scan_weakening(state: &mut ScanState, spec: &ScanSpec) -> Vec<String> {
    let mut out = Vec::new();
    if spec.locked == Some(false) {
        out.push("unlock `[scan]` (`locked = false`)".to_string());
    }
    if let Some(Ok(n)) = spec.max_file_size.as_ref().map(|s| s.bytes()) {
        if n < state.max_file_size {
            out.push(format!(
                "lower scan.max-file-size from {} to {n} bytes",
                state.max_file_size
            ));
        }
        state.max_file_size = n;
    }
    if let Some(d) = spec.max_depth {
        if d < state.max_depth {
            out.push(format!(
                "lower scan.max-depth from {} to {d}",
                state.max_depth
            ));
        }
        state.max_depth = d;
    }
    if let Some(b) = spec.one_file_system {
        if b && !state.one_file_system {
            out.push("turn scan.one-file-system on".to_string());
        }
        state.one_file_system = b;
    }
    let added: Vec<&String> = spec
        .exclude
        .iter()
        .filter(|e| !state.exclude.contains(e))
        .collect();
    if !added.is_empty() {
        out.push(format!("add scan.exclude {}", quoted(&added)));
    }
    state.exclude.extend(spec.exclude.iter().cloned());
    out
}

fn override_rule(
    existing: &mut MergedRule,
    over: RuleSpec,
    index: usize,
    layer: &str,
    errors: &mut Errors,
) {
    if let Some((lock_index, lock_layer)) = &existing.locked_by
        && *lock_index < index
    {
        let attempts = lock_violations(&existing.spec, &over);
        if !attempts.is_empty() {
            errors.add(
                layer,
                format!(
                    "rule `{}` is locked by {lock_layer}; this layer tries to {}. A locked rule \
                     only accepts a higher severity and a new message, remediation or tags",
                    over.id,
                    attempts.join(", ")
                ),
            );
            return;
        }
    }
    let base = &mut existing.spec;
    set(&mut base.type_, over.type_);
    set(&mut base.when, over.when);
    set(&mut base.severity, over.severity);
    set(&mut base.message, over.message);
    set(&mut base.remediation, over.remediation);
    // Tags are merged key by key: a team adds its control id without
    // dropping the baseline's.
    match (&mut base.tags, over.tags) {
        (Some(tags), Some(more)) => tags.extend(more),
        (tags, more) => set(tags, more),
    }
    set(&mut base.enabled, over.enabled);
    if over.locked == Some(true) && existing.locked_by.is_none() {
        existing.locked_by = Some((index, layer.to_string()));
    }
    set(&mut base.locked, over.locked);
    existing.layer = layer.to_string();
}

/// What `over` would weaken in a locked rule, as readable phrases.
fn lock_violations(base: &RuleSpec, over: &RuleSpec) -> Vec<String> {
    let mut out = Vec::new();
    if over.enabled == Some(false) {
        out.push("disable it (`enabled = false`)".to_string());
    }
    if over.locked == Some(false) {
        out.push("unlock it (`locked = false`)".to_string());
    }
    if let Some(t) = &over.type_
        && over.type_ != base.type_
    {
        let old = base.type_.as_deref().unwrap_or("-");
        out.push(format!("change its type from `{old}` to `{t}`"));
    }
    if let Some(w) = &over.when
        && over.when.as_deref().map(squash) != base.when.as_deref().map(squash)
    {
        let old = base.when.as_deref().map(squash).unwrap_or_default();
        out.push(format!(
            "change its condition from `{}` to `{}`",
            shorten(&old),
            shorten(&squash(w))
        ));
    }
    if let (Some(new), Some(old)) = (over.severity, base.severity)
        && new < old
    {
        out.push(format!("lower its severity from {old} to {new}"));
    }
    out
}

/// A CEL expression on one line (whitespace runs collapsed).
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// At most 60 characters, for messages.
fn shorten(text: &str) -> String {
    if text.chars().count() <= 60 {
        return text.to_string();
    }
    let mut out: String = text.chars().take(59).collect();
    out.push('…');
    out
}

// ---- validation ------------------------------------------------------------

fn validate(
    m: Merged,
    req: &ConfigRequest<'_>,
    mut registry: Registry,
    cel: &Cel,
    errors: &mut Errors,
) -> LoadedConfig {
    let scan = validate_scan(&m.scan, errors);

    for (name, t) in &m.types {
        let (Some(pattern), layer) = (&t.pattern, &t.layer) else {
            continue;
        };
        let ident = match Ident::from_non_secret(name) {
            Ok(i) => i,
            Err(e) => {
                errors.add(layer, format!("type: {e}"));
                continue;
            }
        };
        match CustomType::new(ident, pattern) {
            Ok(t) => {
                if let Err(e) = registry.add_custom(t) {
                    errors.add(layer, format!("type `{name}`: {e}"));
                }
            }
            Err(e) => errors.add(layer, format!("type `{name}`: invalid pattern: {e}")),
        }
    }

    check_locked_inputs(&m, &registry, errors);

    let sources = m
        .sources
        .iter()
        .filter(|s| s.spec.enabled != Some(false))
        .filter_map(|s| validate_source(&s.spec, &s.layer, &registry, req.probes, errors))
        .collect();

    let mut rules = Vec::new();
    for r in &m.rules {
        if r.spec.enabled == Some(false) {
            continue;
        }
        if let Some(rule) = validate_rule(r, &registry, cel, errors) {
            rules.push(rule);
        }
    }

    let mut waivers = Vec::new();
    for (i, (w, index, layer)) in m.waivers.iter().enumerate() {
        let position = 1 + m.waivers[..i].iter().filter(|(_, x, _)| x == index).count();
        if let Some(w) = validate_waiver(w, layer, &m.rules, req, errors) {
            waivers.push(Waiver { position, ..w });
        }
    }

    LoadedConfig {
        scan,
        sources,
        registry,
        rules,
        waivers,
        layers: Vec::new(),
    }
}

/// Reports every weakening of a locked source, custom type or `[scan]` (see
/// the module docs: explicit locks and the inputs of locked rules).
fn check_locked_inputs(m: &Merged, registry: &Registry, errors: &mut Errors) {
    let locked_rules: Vec<(usize, &str, &str, &str)> = m
        .rules
        .iter()
        .filter_map(|r| {
            let (index, layer) = r.locked_by.as_ref()?;
            Some((
                *index,
                layer.as_str(),
                r.spec.id.as_str(),
                r.spec.type_.as_deref().unwrap_or(""),
            ))
        })
        .collect();
    for w in &m.weakenings {
        let explicit = match &w.input {
            Input::Scan => m.scan_locked_by.as_ref(),
            Input::Type(name) => m.types.get(name).and_then(|t| t.locked_by.as_ref()),
            Input::Source(id) => m
                .sources
                .iter()
                .find(|s| &s.spec.id == id)
                .and_then(|s| s.locked_by.as_ref()),
        };
        let created = match &w.input {
            Input::Scan => 0,
            Input::Type(name) => m.types.get(name).map_or(0, |t| t.created),
            Input::Source(id) => m
                .sources
                .iter()
                .find(|s| &s.spec.id == id)
                .map_or(0, |s| s.created),
        };
        let reason = match explicit.filter(|(i, _)| *i < w.index) {
            Some((_, layer)) => Some(format!("locked by {layer}")),
            None => locked_rules
                .iter()
                .find(|(i, _, _, type_)| {
                    *i < w.index
                        && created <= *i
                        && match &w.input {
                            Input::Scan | Input::Type(_) => true,
                            Input::Source(_) => w
                                .before
                                .as_ref()
                                .is_some_and(|s| may_produce(s, type_, registry)),
                        }
                })
                .map(|(_, layer, rule, _)| {
                    format!("locked: rule `{rule}`, locked by {layer}, depends on it")
                }),
        };
        let Some(reason) = reason else { continue };
        let what = match &w.input {
            Input::Scan => "`[scan]`".to_string(),
            Input::Type(name) => format!("type `{name}`"),
            Input::Source(id) => format!("source `{id}`"),
        };
        errors.add(
            &w.layer,
            format!(
                "{what} is {reason}; this layer tries to {}. A locked input may only be \
                 extended (more paths, sources, rules), not weakened",
                w.attempts.join(", ")
            ),
        );
    }
}

/// Whether source `s` can produce facts of type `type_` (see the module
/// docs, "Locked inputs").
fn may_produce(s: &SourceSpec, type_: &str, registry: &Registry) -> bool {
    if registry.value_types().any(|v| v.name() == type_) {
        return true; // values come from every kind of source
    }
    let entry_type = |x: &Option<String>| {
        x.as_deref()
            .and_then(|x| registry.extractor(x))
            .is_some_and(|x| x.entry_type() == type_)
    };
    match s.kind.as_deref() {
        Some("env") => type_ == crate::domain::types::ENV_VAR,
        Some("file") => s.type_.as_deref() == Some(type_) || entry_type(&s.extract),
        Some("probe") => {
            registry.document(type_).is_none()
                && type_ != crate::domain::types::ENV_VAR
                && !registry.extractors().any(|x| x.entry_type() == type_)
        }
        _ => false,
    }
}

fn validate_scan(layers: &[(String, ScanSpec)], errors: &mut Errors) -> ScanSettings {
    let mut scan = ScanSettings::default();
    for (layer, spec) in layers {
        if let Some(size) = &spec.max_file_size {
            match size.bytes() {
                Ok(0) => errors.add(layer, "scan.max-file-size must be greater than 0"),
                Ok(n) => scan.max_file_size = n,
                Err(e) => errors.add(layer, format!("scan.max-file-size: {e}")),
            }
        }
        if let Some(depth) = spec.max_depth {
            if depth == 0 {
                errors.add(layer, "scan.max-depth must be at least 1");
            } else {
                scan.max_depth = depth;
            }
        }
        if let Some(b) = spec.one_file_system {
            scan.one_file_system = b;
        }
        for pattern in &spec.exclude {
            if let Err(e) = Glob::new(pattern) {
                errors.add(layer, format!("scan.exclude: {e}"));
            }
        }
        scan.exclude.extend(spec.exclude.iter().cloned());
        for reason in &spec.fail_on_skipped {
            if reason != "*" && !SKIP_REASONS.contains(&reason.as_str()) {
                errors.add(
                    layer,
                    format!(
                        "scan.fail-on-skipped: unknown reason `{reason}` (known: *, {})",
                        SKIP_REASONS.join(", ")
                    ),
                );
            } else if !scan.fail_on_skipped.contains(reason) {
                scan.fail_on_skipped.push(reason.clone());
            }
        }
    }
    scan
}

fn validate_source(
    s: &SourceSpec,
    layer: &str,
    registry: &Registry,
    probes: &[&str],
    errors: &mut Errors,
) -> Option<Source> {
    let id = match Ident::from_non_secret(&s.id) {
        Ok(id) => id,
        Err(e) => {
            errors.add(layer, format!("source: {e}"));
            return None;
        }
    };
    let mut problems: Vec<String> = Vec::new();
    let kind = source_kind(s, registry, probes, &mut problems);
    for p in &problems {
        errors.add(layer, format!("source `{id}`: {p}"));
    }
    match kind {
        Some(kind) if problems.is_empty() => Some(Source { id, kind }),
        _ => None,
    }
}

fn source_kind(
    s: &SourceSpec,
    registry: &Registry,
    probes: &[&str],
    problems: &mut Vec<String>,
) -> Option<SourceKind> {
    let not_allowed = |problems: &mut Vec<String>, field: &str, present: bool, kind: &str| {
        if present {
            problems.push(format!("`{field}` is not allowed for kind `{kind}`"));
        }
    };
    let kind = match s.kind.as_deref() {
        Some("env") => {
            not_allowed(problems, "paths", s.paths.is_some(), "env");
            not_allowed(problems, "exclude", s.exclude.is_some(), "env");
            not_allowed(problems, "type", s.type_.is_some(), "env");
            not_allowed(problems, "extract", s.extract.is_some(), "env");
            not_allowed(problems, "probes", s.probes.is_some(), "env");
            not_allowed(problems, "path-vars", s.path_vars.is_some(), "env");
            let names = s.names.clone().unwrap_or_default();
            if names.is_empty() {
                problems.push("`names` is required for kind `env`".into());
            }
            for g in &names {
                if let Err(e) = Glob::new(g) {
                    problems.push(e.to_string());
                }
            }
            SourceKind::Env { names }
        }
        Some("file") => {
            not_allowed(problems, "names", s.names.is_some(), "file");
            not_allowed(problems, "probes", s.probes.is_some(), "file");
            not_allowed(problems, "path-vars", s.path_vars.is_some(), "file");
            let paths = s.paths.clone().unwrap_or_default();
            if paths.is_empty() {
                problems.push("`paths` is required for kind `file`".into());
            }
            let exclude = s.exclude.clone().unwrap_or_default();
            for g in paths.iter().chain(&exclude) {
                if let Err(e) = Glob::new(g) {
                    problems.push(e.to_string());
                }
            }
            let action = match (&s.type_, &s.extract) {
                (Some(t), None) => {
                    if registry.document(t).is_none() {
                        problems.push(format!(
                            "unknown document type `{t}` (known: {})",
                            document_names(registry)
                        ));
                    }
                    FileAction::Document(t.clone())
                }
                (None, Some(x)) => {
                    if registry.extractor(x).is_none() {
                        problems.push(format!(
                            "unknown extractor `{x}` (known: {})",
                            extractor_names(registry)
                        ));
                    }
                    FileAction::Extract(x.clone())
                }
                _ => {
                    problems.push(
                        "set exactly one of `type` (a document type) or `extract` (an extractor)"
                            .into(),
                    );
                    FileAction::Extract(String::new())
                }
            };
            SourceKind::File {
                paths,
                exclude,
                action,
            }
        }
        Some("probe") => {
            not_allowed(problems, "names", s.names.is_some(), "probe");
            not_allowed(problems, "type", s.type_.is_some(), "probe");
            not_allowed(problems, "extract", s.extract.is_some(), "probe");
            let mut list = Vec::new();
            for p in s.probes.clone().unwrap_or_default() {
                if probes.contains(&p.as_str()) {
                    if let Ok(i) = Ident::from_non_secret(&p) {
                        list.push(i);
                    }
                } else {
                    let known = list_or_none(probes);
                    problems.push(format!("unknown probe `{p}` (known: {known})"));
                }
            }
            if list.is_empty() && s.probes.as_ref().is_none_or(|p| p.is_empty()) {
                problems.push("`probes` is required for kind `probe`".into());
            }
            let paths = s.paths.clone().unwrap_or_default();
            let exclude = s.exclude.clone().unwrap_or_default();
            for g in paths.iter().chain(&exclude) {
                if let Err(e) = Glob::new(g) {
                    problems.push(e.to_string());
                }
            }
            let path_vars = s.path_vars.clone().unwrap_or_default();
            for v in &path_vars {
                if v.is_empty() || v.contains(['=', '\0']) {
                    problems.push(format!(
                        "`path-vars`: `{v}` is not an environment variable name"
                    ));
                }
            }
            SourceKind::Probe {
                probes: list,
                paths,
                exclude,
                path_vars,
            }
        }
        Some(other) => {
            problems.push(format!("unknown kind `{other}` (env, file, probe)"));
            return None;
        }
        None => {
            problems.push("`kind` is required (env, file, probe)".into());
            return None;
        }
    };
    Some(kind)
}

fn document_names(registry: &Registry) -> String {
    let names: Vec<String> = registry
        .types()
        .into_iter()
        .filter(|t| t.kind == TypeKind::Document)
        .map(|t| t.name)
        .collect();
    list_or_none(&names)
}

fn extractor_names(registry: &Registry) -> String {
    let names: Vec<&str> = registry.extractors().map(|e| e.name()).collect();
    list_or_none(&names)
}

fn list_or_none<S: AsRef<str>>(names: &[S]) -> String {
    if names.is_empty() {
        return "none".into();
    }
    let names: Vec<&str> = names.iter().map(|n| n.as_ref()).collect();
    names.join(", ")
}

fn validate_rule(
    r: &MergedRule,
    registry: &Registry,
    cel: &Cel,
    errors: &mut Errors,
) -> Option<CompiledRule> {
    let layer = &r.layer;
    let spec = &r.spec;
    let id = match Ident::from_non_secret(&spec.id) {
        Ok(id) => id,
        Err(e) => {
            errors.add(layer, format!("rule: {e}"));
            return None;
        }
    };
    let n = errors.0.len();
    let mut err = |msg: String| errors.add(layer, format!("rule `{id}`: {msg}"));
    let info = match spec.type_.as_deref() {
        None => {
            err("`type` is required".into());
            None
        }
        Some(t) => {
            let info = registry.info(t);
            if info.is_none() {
                let known: Vec<String> = registry.types().into_iter().map(|t| t.name).collect();
                err(format!("unknown type `{t}` (known: {})", known.join(", ")));
            }
            info
        }
    };
    let condition = match (&spec.when, &info) {
        (None, _) => {
            err("`when` is required".into());
            None
        }
        (Some(when), Some(info)) => match cel::compile(cel, when, info) {
            Ok(c) => Some(c),
            Err(e) => {
                err(e.to_string());
                None
            }
        },
        (Some(_), None) => None,
    };
    let severity = spec.severity.unwrap_or(Severity::Info);
    if spec.severity.is_none() {
        err("`severity` is required".into());
    }
    if let Some(info) = &info {
        for template in [&spec.message, &spec.remediation].into_iter().flatten() {
            if let Err(e) = check_placeholders(template, info) {
                err(e);
            }
        }
    }
    let mut tags = BTreeMap::new();
    for (k, v) in spec.tags.clone().unwrap_or_default() {
        match (Ident::from_non_secret(&k), Ident::from_non_secret(&v)) {
            (Ok(k), Ok(v)) => {
                tags.insert(k, v);
            }
            (Err(e), _) | (_, Err(e)) => err(format!("tag: {e}")),
        }
    }
    if errors.0.len() != n {
        return None;
    }
    Some(CompiledRule {
        rule: Rule {
            id,
            type_: spec.type_.clone().unwrap_or_default(),
            when: spec.when.clone().unwrap_or_default(),
            severity,
            message: spec.message.clone(),
            remediation: spec.remediation.clone(),
            tags,
            locked: spec.locked == Some(true),
            locked_by: r.locked_by.as_ref().map(|(_, l)| l.clone()),
            layer: layer.clone(),
        },
        condition: condition?,
    })
}

fn check_placeholders(template: &str, info: &TypeInfo) -> Result<(), String> {
    for name in placeholders(template)? {
        if !BUILTIN_PLACEHOLDERS.contains(&name) && info.attr(name).is_none() {
            return Err(format!(
                "unknown placeholder `{{{name}}}` (known: {}, {})",
                BUILTIN_PLACEHOLDERS.join(", "),
                attr_names(info)
            ));
        }
    }
    Ok(())
}

fn validate_waiver(
    w: &WaiverSpec,
    layer: &str,
    rules: &[MergedRule],
    req: &ConfigRequest<'_>,
    errors: &mut Errors,
) -> Option<Waiver> {
    let n = errors.0.len();
    let mut err = |msg: String| errors.add(layer, format!("waiver for `{}`: {msg}", w.rule));
    let rule = Ident::from_non_secret(&w.rule)
        .map_err(|e| err(e.to_string()))
        .ok();
    match rules.iter().find(|r| r.spec.id == w.rule) {
        None => err("unknown rule".into()),
        Some(r) => {
            // Only the layer that locks a rule may waive it: neither later
            // layers nor earlier ones (a project file applied before the
            // baseline by mistake).
            if let Some((_, lock_layer)) = &r.locked_by
                && lock_layer != layer
            {
                err(format!(
                    "rule is locked by {lock_layer}; only that layer may waive it"
                ));
            }
        }
    }
    if w.reason.trim().is_empty() {
        err("`reason` must not be empty".into());
    }
    let path = match &w.path {
        Some(p) => match expand_path(p, req.home, req.cwd).and_then(|p| {
            Glob::new(&p).map_err(|e| e.to_string())?;
            Ok(p)
        }) {
            Ok(p) => Some(p),
            Err(e) => {
                err(format!("path {e}"));
                None
            }
        },
        None => None,
    };
    let expires = match &w.expires {
        None => None,
        Some(dt) => match (dt.date, dt.time) {
            (Some(d), None) => {
                let date = Date::new(i32::from(d.year), d.month, d.day);
                if date.is_none() {
                    err(format!("`expires = {dt}` is not a valid date"));
                }
                date
            }
            _ => {
                err(format!("`expires = {dt}` must be a date (YYYY-MM-DD)"));
                None
            }
        },
    };
    if errors.0.len() != n {
        return None;
    }
    Some(Waiver {
        rule: rule?,
        path,
        path_pattern: w.path.clone(),
        name: w.name.clone(),
        reason: w.reason.clone(),
        expires,
        layer: layer.to_string(),
        position: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::test_types::registry;
    use crate::repository::fake::FakeConfig;

    const BASE: &str = r#"
version = 1

[scan]
max-file-size = "2MiB"
exclude = ["~/Library/**"]

[[source]]
id = "env"
kind = "env"
names = ["*"]

[[source]]
id = "docs"
kind = "file"
paths = ["~/docs/*"]
type = "test_doc"

[[type]]
name = "acme_key"
pattern = '^acme_[a-z]{4}$'

[[rule]]
id = "doc-marked"
type = "test_doc"
when = "marked"
severity = "high"
message = "{path} is marked ({lines} lines)"
locked = true

[[rule]]
id = "long-token"
type = "test_token"
when = 'kind == "long"'
severity = "medium"
"#;

    fn load_files(files: &[(&str, &str)], args: &[&str]) -> Result<LoadedConfig, ConfigErrors> {
        let mut repo = FakeConfig::new();
        for (path, text) in files {
            repo = repo.file(path, text);
        }
        let args: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
        let req = ConfigRequest {
            default: None,
            files: &args,
            cwd: Path::new("/work"),
            home: Some(Path::new("/home/user")),
            probes: &["process"],
        };
        load(&repo, &req, registry(), &Cel::new())
    }

    fn messages(r: Result<LoadedConfig, ConfigErrors>) -> Vec<String> {
        match r {
            Ok(_) => panic!("expected errors"),
            Err(e) => e.0.into_iter().map(|e| e.to_string()).collect(),
        }
    }

    #[test]
    fn loads_a_valid_config() {
        let c = load_files(&[("/work/base.toml", BASE)], &["base.toml"]).unwrap();
        assert_eq!(c.scan.max_file_size, 2 << 20);
        assert_eq!(c.scan.exclude, ["~/Library/**"]);
        assert_eq!(c.sources.len(), 2);
        assert_eq!(c.rules.len(), 2);
        assert!(c.rules[0].rule.locked);
        assert_eq!(c.registry.custom_types().len(), 1);
        assert_eq!(c.layers, ["/work/base.toml"]);
    }

    #[test]
    fn the_builtin_default_is_valid() {
        let probes = crate::service::probe::builtin();
        let names: Vec<&str> = probes.iter().map(|p| p.name()).collect();
        let req = ConfigRequest {
            default: Some(DEFAULT_CONFIG),
            files: &[],
            cwd: Path::new("/work"),
            home: Some(Path::new("/home/user")),
            probes: &names,
        };
        let mut registry = Registry::builtin(0);
        for p in &probes {
            for t in p.fact_types() {
                registry.add_fact_type(*t).unwrap();
            }
        }
        let c = load(&FakeConfig::new(), &req, registry, &Cel::new()).unwrap();
        assert_eq!(c.layers, [DEFAULT_LAYER]);
        assert_eq!(c.sources.len(), 31);
        // Every built-in type has at least one rule, every document type
        // and extractor a source.
        for t in c.registry.types() {
            assert!(
                c.rules.iter().any(|r| r.rule.type_ == t.name),
                "no rule for {}",
                t.name
            );
        }
        for t in c
            .registry
            .types()
            .iter()
            .filter(|t| t.kind == TypeKind::Document)
        {
            let used = c.sources.iter().any(|s| {
                matches!(&s.kind, SourceKind::File { action: FileAction::Document(d), .. } if *d == t.name)
            });
            assert!(used, "no source for {}", t.name);
        }
        for x in c.registry.extractors() {
            let used = c.sources.iter().any(|s| {
                matches!(&s.kind, SourceKind::File { action: FileAction::Extract(e), .. } if e == x.name())
            });
            assert!(used, "no source for extractor {}", x.name());
        }
    }

    #[test]
    fn the_default_secret_name_heuristic() {
        use crate::domain::model::{AttrValue, Attrs, Fact, Location};
        let probes = crate::service::probe::builtin();
        let names: Vec<&str> = probes.iter().map(|p| p.name()).collect();
        let req = ConfigRequest {
            default: Some(DEFAULT_CONFIG),
            files: &[],
            cwd: Path::new("/work"),
            home: None,
            probes: &names,
        };
        let mut registry = Registry::builtin(0);
        for p in &probes {
            for t in p.fact_types() {
                registry.add_fact_type(*t).unwrap();
            }
        }
        let c = load(&FakeConfig::new(), &req, registry, &Cel::new()).unwrap();
        let rule = c
            .rules
            .iter()
            .find(|r| r.rule.id.as_str() == "env-secret-like")
            .unwrap();
        let fires = |name: &str| {
            let id = Ident::from_non_secret(name).unwrap();
            let mut attrs = Attrs::new();
            attrs.insert("name", AttrValue::Name(id.clone()));
            attrs.insert("length", AttrValue::Int(30));
            attrs.insert("entropy", AttrValue::Int(120));
            attrs.insert("classified_as", AttrValue::List(Vec::new()));
            let fact = Fact {
                type_: Ident::from_non_secret("env_var").unwrap(),
                location: Location::Env { name: id },
                source: Ident::from_non_secret("env").unwrap(),
                attrs,
            };
            rule.condition.eval(&fact).unwrap()
        };
        for name in [
            "NPM_TOKEN",
            "DB_PWD",
            "DB_PWD_OLD",
            "API_KEY",
            "x_auth",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_PRIVATE_KEY",
            "DB_PASSWORD",
        ] {
            assert!(fires(name), "{name}");
        }
        for name in [
            "PWD",
            "OLDPWD",
            "GIT_AUTHOR_EMAIL",
            "OAUTH_CLIENT_ID",
            "PRIVATE_URL",
            "HOME",
        ] {
            assert!(!fires(name), "{name}");
        }
    }

    #[test]
    fn later_layers_override_and_disable() {
        let team = r#"
version = 1
[scan]
max-depth = 4
exclude = ["/tmp/**"]
[[source]]
id = "env"
enabled = false
[[rule]]
id = "long-token"
severity = "critical"
[[rule]]
id = "doc-marked"
severity = "critical"
message = "custom {path}"
[[rule]]
id = "new-rule"
type = "env_var"
when = "length > 10"
severity = "low"
"#;
        // Without a locked rule nothing protects `[scan]` or the sources.
        let base = BASE.replace("locked = true\n", "");
        let c = load_files(
            &[("/work/base.toml", &base), ("/work/team.toml", team)],
            &["base.toml", "team.toml"],
        )
        .unwrap();
        assert_eq!(c.scan.max_depth, 4);
        assert_eq!(c.scan.max_file_size, 2 << 20);
        assert_eq!(c.scan.exclude, ["~/Library/**", "/tmp/**"]);
        assert_eq!(c.sources.len(), 1);
        let sev: Vec<(String, Severity)> = c
            .rules
            .iter()
            .map(|r| (r.rule.id.to_string(), r.rule.severity))
            .collect();
        assert_eq!(
            sev,
            [
                ("doc-marked".into(), Severity::Critical),
                ("long-token".into(), Severity::Critical),
                ("new-rule".into(), Severity::Low),
            ]
        );
        assert_eq!(c.rules[0].rule.message.as_deref(), Some("custom {path}"));
        assert_eq!(c.rules[0].rule.when, "marked");
    }

    #[test]
    fn locked_rules_cannot_be_weakened_or_waived() {
        let project = r#"
version = 1
[[rule]]
id = "doc-marked"
enabled = false
when = "false"
severity = "low"
[[waiver]]
rule = "doc-marked"
reason = "we do not care"
"#;
        let errs = messages(load_files(
            &[("/work/base.toml", BASE), ("/work/p.toml", project)],
            &["base.toml", "p.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/work/p.toml: rule `doc-marked` is locked by /work/base.toml; this layer tries \
                 to disable it (`enabled = false`), change its condition from `marked` to \
                 `false`, lower its severity from high to low. A locked rule only accepts a \
                 higher severity and a new message, remediation or tags",
                "/work/p.toml: waiver for `doc-marked`: rule is locked by /work/base.toml; only \
                 that layer may waive it",
            ]
        );
    }

    #[test]
    fn unlocking_and_retyping_a_locked_rule_are_errors() {
        let project = r#"
version = 1
[[rule]]
id = "doc-marked"
type = "test_token"
locked = false
when = """
  marked
"""
"#;
        let errs = messages(load_files(
            &[("/work/base.toml", BASE), ("/work/p.toml", project)],
            &["base.toml", "p.toml"],
        ));
        // The same condition with other whitespace is not a change.
        assert_eq!(
            errs,
            [
                "/work/p.toml: rule `doc-marked` is locked by /work/base.toml; this layer tries \
                 to unlock it (`locked = false`), change its type from `test_doc` to \
                 `test_token`. A locked rule only accepts a higher severity and a new message, \
                 remediation or tags"
            ]
        );
    }

    /// default → baseline (locks, raises) → team (strengthens, tags) →
    /// project (waives what is not locked).
    #[test]
    fn override_chain_across_four_layers() {
        let default = r#"
version = 1
[[source]]
id = "docs"
kind = "file"
paths = ["~/docs/*"]
type = "test_doc"
[[rule]]
id = "doc-marked"
type = "test_doc"
when = "marked"
severity = "medium"
tags = { category = "key-protection" }
[[rule]]
id = "long-token"
type = "test_token"
when = 'kind == "long"'
severity = "low"
"#;
        let baseline = r#"
version = 1
[[rule]]
id = "doc-marked"
severity = "high"
locked = true
tags = { control = "SEC-1" }
[[rule]]
id = "long-token"
severity = "medium"
"#;
        let team = r#"
version = 1
[[rule]]
id = "doc-marked"
severity = "critical"
message = "team: {path}"
tags = { team = "payments" }
[[rule]]
id = "long-token"
severity = "low"
when = 'kind == "long" && length > 8'
"#;
        let project = r#"
version = 1
[[rule]]
id = "doc-marked"
severity = "critical"
remediation = "ask #security"
[[rule]]
id = "long-token"
enabled = false
[[waiver]]
rule = "long-token"
name = "CI_TOKEN"
reason = "CI job token"
expires = 2027-01-31
"#;
        let mut repo = FakeConfig::new()
            .file("/c/baseline.toml", baseline)
            .file("/c/team.toml", team)
            .file("/c/project.toml", project);
        let files: Vec<PathBuf> = ["/c/baseline.toml", "/c/team.toml", "/c/project.toml"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let req = ConfigRequest {
            default: Some(default),
            files: &files,
            cwd: Path::new("/c"),
            home: Some(Path::new("/home/user")),
            probes: &[],
        };
        let c = load(&repo, &req, registry(), &Cel::new()).unwrap();
        assert_eq!(c.rules.len(), 1, "long-token is disabled");
        let r = &c.rules[0].rule;
        assert_eq!(r.severity, Severity::Critical);
        assert_eq!(r.when, "marked");
        assert_eq!(r.message.as_deref(), Some("team: {path}"));
        assert_eq!(r.remediation.as_deref(), Some("ask #security"));
        let tags: Vec<String> = r.tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        assert_eq!(
            tags,
            ["category=key-protection", "control=SEC-1", "team=payments"]
        );
        assert!(r.locked);
        assert_eq!(r.locked_by.as_deref(), Some("/c/baseline.toml"));
        assert_eq!(r.layer, "/c/project.toml");
        assert_eq!(c.waivers.len(), 1);
        assert_eq!(c.waivers[0].position, 1);
        assert_eq!(
            c.layers,
            [
                DEFAULT_LAYER,
                "/c/baseline.toml",
                "/c/team.toml",
                "/c/project.toml"
            ]
        );

        // The team may not lower below the baseline, the project may not
        // waive the locked rule; waivers of earlier layers are rejected too.
        repo = repo
            .file(
                "/c/team.toml",
                &team.replace("severity = \"critical\"", "severity = \"medium\""),
            )
            .file(
                "/c/project.toml",
                "version = 1\n[[waiver]]\nrule = \"doc-marked\"\npath = \"~/docs/a\"\nreason = \"x\"\n",
            );
        let errs = messages(load(&repo, &req, registry(), &Cel::new()));
        assert_eq!(
            errs,
            [
                "/c/team.toml: rule `doc-marked` is locked by /c/baseline.toml; this layer tries \
                 to lower its severity from high to medium. A locked rule only accepts a higher \
                 severity and a new message, remediation or tags",
                "/c/project.toml: waiver for `doc-marked`: rule is locked by /c/baseline.toml; \
                 only that layer may waive it",
            ]
        );
        let early =
            format!("{default}\n[[waiver]]\nrule = \"doc-marked\"\nreason = \"before the lock\"\n");
        let req = ConfigRequest {
            default: Some(&early),
            files: &files[..1],
            ..req
        };
        let errs = messages(load(&repo, &req, registry(), &Cel::new()));
        assert_eq!(
            errs,
            [
                "<built-in>: waiver for `doc-marked`: rule is locked by /c/baseline.toml; only \
              that layer may waive it"
            ]
        );
    }

    #[test]
    fn overrides_of_unknown_ids_are_errors() {
        let team = r#"
version = 1
[[source]]
id = "dcos"
enabled = false
[[rule]]
id = "doc-markd"
severity = "low"
[[rule]]
id = "long-tokn"
enabled = false
"#;
        let errs = messages(load_files(
            &[("/work/base.toml", BASE), ("/work/team.toml", team)],
            &["base.toml", "team.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/work/team.toml: source `dcos` overrides nothing: no earlier layer defines this \
                 source (check the id; a new source needs `kind`)",
                "/work/team.toml: rule `doc-markd` overrides nothing: no earlier layer defines \
                 this rule (check the id; a new rule needs `type`, `when` and `severity`)",
                "/work/team.toml: rule `long-tokn` overrides nothing: no earlier layer defines \
                 this rule (check the id; a new rule needs `type`, `when` and `severity`)",
            ]
        );
    }

    /// A company baseline over the real default layer: locks the
    /// per-type `credential-file-readable-*` rules.
    #[test]
    fn locking_default_rules() {
        let baseline = r#"
version = 1
[[rule]]
id = "credential-file-readable-npmrc"
locked = true
severity = "critical"
[[rule]]
id = "credential-file-readable-netrc"
locked = true
[[rule]]
id = "credential-file-readable-gh"
locked = true
tags = { control = "SEC-7" }
"#;
        let project_ok = r#"
version = 1
[[rule]]
id = "credential-file-readable-netrc"
severity = "critical"
message = "{path}: mode {mode}"
[[rule]]
id = "netrc-password"
enabled = false
[[waiver]]
rule = "credential-file-readable-pypirc"
path = "~/.pypirc"
reason = "read-only mirror token"
expires = 2027-01-31
"#;
        let project_bad = r#"
version = 1
[[rule]]
id = "credential-file-readable-npmrc"
severity = "high"
[[rule]]
id = "credential-file-readable-netrc"
enabled = false
[[waiver]]
rule = "credential-file-readable-gh"
path = "~/.config/gh/hosts.yml"
reason = "shared CI box"
"#;
        let run = |project: &str| {
            let repo = FakeConfig::new()
                .file("/c/baseline.toml", baseline)
                .file("/c/project.toml", project);
            let files = [
                PathBuf::from("baseline.toml"),
                PathBuf::from("project.toml"),
            ];
            let probes = crate::service::probe::builtin();
            let names: Vec<&str> = probes.iter().map(|p| p.name()).collect();
            let req = ConfigRequest {
                default: Some(DEFAULT_CONFIG),
                files: &files,
                cwd: Path::new("/c"),
                home: Some(Path::new("/home/user")),
                probes: &names,
            };
            let mut registry = Registry::builtin(0);
            for p in &probes {
                for t in p.fact_types() {
                    registry.add_fact_type(*t).unwrap();
                }
            }
            load(&repo, &req, registry, &Cel::new())
        };
        let c = run(project_ok).unwrap();
        let rule = |id: &str| c.rules.iter().find(|r| r.rule.id.as_str() == id);
        let npmrc = &rule("credential-file-readable-npmrc").unwrap().rule;
        assert_eq!(npmrc.severity, Severity::Critical);
        assert_eq!(npmrc.locked_by.as_deref(), Some("/c/baseline.toml"));
        let netrc = &rule("credential-file-readable-netrc").unwrap().rule;
        assert_eq!(netrc.severity, Severity::Critical);
        assert_eq!(netrc.message.as_deref(), Some("{path}: mode {mode}"));
        let gh = &rule("credential-file-readable-gh").unwrap().rule;
        assert_eq!(gh.tags.len(), 2);
        assert!(rule("netrc-password").is_none());
        assert!(!rule("credential-file-readable-pypirc").unwrap().rule.locked);
        assert_eq!(c.waivers.len(), 1);

        let errs = messages(run(project_bad));
        assert_eq!(
            errs,
            [
                "/c/project.toml: rule `credential-file-readable-npmrc` is locked by \
                 /c/baseline.toml; this layer tries to lower its severity from critical to high. \
                 A locked rule only accepts a higher severity and a new message, remediation or \
                 tags",
                "/c/project.toml: rule `credential-file-readable-netrc` is locked by \
                 /c/baseline.toml; this layer tries to disable it (`enabled = false`). A locked \
                 rule only accepts a higher severity and a new message, remediation or tags",
                "/c/project.toml: waiver for `credential-file-readable-gh`: rule is locked by \
                 /c/baseline.toml; only that layer may waive it",
            ]
        );
    }

    #[test]
    fn waivers_in_the_locking_layer_are_fine() {
        let text = format!(
            "{BASE}\n[[waiver]]\nrule = \"doc-marked\"\npath = \"~/docs/a\"\nreason = \"ok\"\nexpires = 2027-01-31\n"
        );
        let c = load_files(&[("/work/base.toml", &text)], &["base.toml"]).unwrap();
        assert_eq!(c.waivers.len(), 1);
        assert_eq!(c.waivers[0].path.as_deref(), Some("/home/user/docs/a"));
        assert_eq!(c.waivers[0].expires.unwrap().to_string(), "2027-01-31");
    }

    #[test]
    fn includes_are_relative_and_applied_first() {
        let main = r#"
version = 1
include = ["shared/base.toml"]
[[rule]]
id = "long-token"
severity = "high"
"#;
        let c = load_files(
            &[
                ("/etc/lootr/main.toml", main),
                ("/etc/lootr/shared/base.toml", BASE),
            ],
            &["/etc/lootr/main.toml"],
        )
        .unwrap();
        assert_eq!(
            c.layers,
            ["/etc/lootr/shared/base.toml", "/etc/lootr/main.toml"]
        );
        assert_eq!(c.rules[1].rule.severity, Severity::High);
    }

    #[test]
    fn include_errors() {
        let a = "version = 1\ninclude = [\"b.toml\"]\n";
        let b = "version = 1\ninclude = [\"a.toml\", \"https://example.com/x.toml\", \"missing.toml\"]\n";
        let errs = messages(load_files(
            &[("/c/a.toml", a), ("/c/b.toml", b)],
            &["/c/a.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/c/a.toml: include cycle: /c/a.toml -> /c/b.toml -> /c/a.toml",
                "/c/b.toml: include `https://example.com/x.toml`: only local files can be included",
                "/c/missing.toml: cannot read config: not found",
            ]
        );
    }

    #[test]
    fn reports_every_validation_error() {
        let bad = r#"
version = 1
[scan]
max-file-size = "lots"
[[source]]
id = "s1"
kind = "file"
paths = ["~/x"]
[[source]]
id = "s2"
kind = "env"
names = ["*"]
paths = ["/x"]
path-vars = ["PATH"]
[[source]]
id = "s3"
kind = "probe"
probes = ["nope"]
path-vars = ["A=B"]
[[source]]
id = "s4"
kind = "file"
paths = ["~/x"]
type = "nope_doc"
[[type]]
name = "bad_re"
pattern = "("
[[rule]]
id = "r1"
type = "test_doc"
when = "bits > 1"
severity = "high"
[[rule]]
id = "r2"
type = "nope"
when = "true"
[[rule]]
id = "r3"
type = "test_doc"
when = "marked"
severity = "low"
message = "{nope}"
[[waiver]]
rule = "r9"
reason = ""
"#;
        let errs = messages(load_files(&[("/w/bad.toml", bad)], &["/w/bad.toml"]));
        let expected = [
            "scan.max-file-size: `lots` is not a size",
            "type `bad_re`: invalid pattern",
            "source `s1`: set exactly one of `type`",
            "source `s2`: `paths` is not allowed for kind `env`",
            "source `s2`: `path-vars` is not allowed for kind `env`",
            "source `s3`: unknown probe `nope` (known: process)",
            "source `s3`: `path-vars`: `A=B` is not an environment variable name",
            "source `s4`: unknown document type `nope_doc` (known: test_doc)",
            "rule `r1`: unknown attribute `bits` for type `test_doc`",
            "rule `r2`: unknown type `nope`",
            "rule `r2`: `severity` is required",
            "rule `r3`: unknown placeholder `{nope}`",
            "waiver for `r9`: unknown rule",
            "waiver for `r9`: `reason` must not be empty",
        ];
        assert_eq!(errs.len(), expected.len(), "{errs:#?}");
        for (e, want) in errs.iter().zip(expected) {
            assert!(e.starts_with("/w/bad.toml: "), "{e}");
            assert!(e.contains(want), "{e} does not contain {want}");
        }
    }

    #[test]
    fn syntax_errors_and_versions() {
        let errs = messages(load_files(
            &[("/w/a.toml", "version = 2\n")],
            &["/w/a.toml"],
        ));
        assert_eq!(errs, ["/w/a.toml: expected `version = 1`"]);
        let errs = messages(load_files(
            &[("/w/a.toml", "version = 1\n[[rule]]\nid = 'x'\nwhen = 3\n")],
            &["/w/a.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/w/a.toml: line 4, column 8: wrong value type, expected a string \
              (file content not shown)"
            ]
        );
        let errs = messages(load_files(
            &[(
                "/w/a.toml",
                "version = 1\n[[rule]]\nid = 'x'\nseverity = 'severe'\n",
            )],
            &["/w/a.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/w/a.toml: line 4, column 12: unknown value, expected one of `info`, `low`, \
              `medium`, `high`, `critical` (file content not shown)"
            ]
        );
    }

    /// A config path given by mistake (`--config .env`, an include of
    /// `~/.git-credentials`) must not echo the file: no value, key or line
    /// of it appears in an error.
    #[test]
    fn errors_never_quote_the_file() {
        use crate::testing::CANARY;
        let files = [
            format!("GITHUB_TOKEN={CANARY}ghp\n"),
            format!("export API_KEY='{CANARY}'\n"),
            format!("https://alice:{CANARY}@github.com\n"),
            format!("version = 1\n{CANARY}_KEY = \"x\"\n"),
            format!("version = 1\nAPI_KEY = \"{CANARY}\"\n"),
            format!("version = \"{CANARY}\"\n"),
            format!("version = 1\n[[rule]]\nid = \"x\"\nseverity = \"{CANARY}\"\n"),
            format!("version = 1\n[scan]\nmax-file-size = [\"{CANARY}\"]\n"),
            format!("version = 1\n[scan]\nexclude = \"{CANARY}, expected x\"\n"),
            format!("version = 1\n[[waiver]]\nrule=\"x\"\nreason=\"y\"\nexpires = \"{CANARY}\"\n"),
            format!("version = 1\n[[source]]\nid = \"a\"\n{CANARY} = 1\n"),
            format!("version = 1\n\"{CANARY}`, expected \" = 1\n"),
            format!("{CANARY} = = 1"),
            format!("[{CANARY}\n"),
            format!("version = 1\nversion = \"{CANARY}\"\n"),
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n"),
        ];
        for text in &files {
            let errs = messages(load_files(&[("/w/a.toml", text.as_str())], &["/w/a.toml"]));
            assert_eq!(errs.len(), 1, "{text}: {errs:?}");
            assert!(!errs[0].contains(CANARY), "{text}: {errs:?}");
            assert!(!errs[0].contains("alice"), "{text}: {errs:?}");
            assert!(errs[0].contains("line "), "{text}: {errs:?}");
        }
        // Included files the same way, and invalid UTF-8.
        let errs = messages(load_files(
            &[
                ("/w/a.toml", "version = 1\ninclude = ['creds']\n"),
                ("/w/creds", &format!("https://u:{CANARY}@h\n")),
            ],
            &["/w/a.toml"],
        ));
        assert!(!errs.join("\n").contains(CANARY), "{errs:?}");
        assert_eq!(line_column("a\nbc\nd", 4), (2, 3));
        assert_eq!(line_column("ü\n", 2), (1, 2));
    }

    /// The review's bypasses: a later layer must not starve a locked rule
    /// of its inputs (disable or repoint its source, exclude everything,
    /// shrink the size limit, replace a custom type's pattern).
    #[test]
    fn inputs_of_locked_rules_cannot_be_weakened() {
        let project = r#"
version = 1
[scan]
max-file-size = "1KiB"
max-depth = 2
exclude = ["**"]
[[source]]
id = "docs"
paths = ["/nowhere/*"]
exclude = ["**"]
[[type]]
name = "acme_key"
pattern = '^never$'
"#;
        let errs = messages(load_files(
            &[("/work/base.toml", BASE), ("/work/p.toml", project)],
            &["base.toml", "p.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/work/p.toml: `[scan]` is locked: rule `doc-marked`, locked by \
                 /work/base.toml, depends on it; this layer tries to lower scan.max-file-size \
                 from 2097152 to 1024 bytes, lower scan.max-depth from 16 to 2, add \
                 scan.exclude `**`. A locked input may only be extended (more paths, sources, \
                 rules), not weakened",
                "/work/p.toml: type `acme_key` is locked: rule `doc-marked`, locked by \
                 /work/base.toml, depends on it; this layer tries to change its pattern. A \
                 locked input may only be extended (more paths, sources, rules), not weakened",
                "/work/p.toml: source `docs` is locked: rule `doc-marked`, locked by \
                 /work/base.toml, depends on it; this layer tries to drop paths `~/docs/*`, \
                 exclude `**`. A locked input may only be extended (more paths, sources, \
                 rules), not weakened",
            ]
        );
        for over in [
            "[[source]]\nid = \"docs\"\nenabled = false\n",
            "[[source]]\nid = \"docs\"\ntype = \"other_doc\"\n",
            "[[source]]\nid = \"docs\"\nlocked = false\n",
            "[scan]\none-file-system = false\n[[source]]\nid = \"docs\"\nkind = \"env\"\n",
        ] {
            let p = format!("version = 1\n{over}");
            let errs = messages(load_files(
                &[("/work/base.toml", BASE), ("/work/p.toml", &p)],
                &["base.toml", "p.toml"],
            ));
            assert!(
                errs.iter().any(|e| e.contains("source `docs` is locked")),
                "{over}: {errs:?}"
            );
        }
    }

    /// Only what a locked rule can see is protected, as it was when the
    /// rule was locked; extending is always fine.
    #[test]
    fn unrelated_and_later_inputs_stay_free() {
        let project = r#"
version = 1
[scan]
max-file-size = "4MiB"
exclude = ["~/Library/**"]
fail-on-skipped = ["truncated"]
[[source]]
id = "env"
enabled = false
[[source]]
id = "docs"
paths = ["~/docs/*", "~/more/*"]
[[source]]
id = "extra"
kind = "file"
paths = ["~/x/*"]
type = "test_doc"
"#;
        let later = "version = 1\n[[source]]\nid = \"extra\"\nenabled = false\n";
        let c = load_files(
            &[
                ("/work/base.toml", BASE),
                ("/work/p.toml", project),
                ("/work/q.toml", later),
            ],
            &["base.toml", "p.toml", "q.toml"],
        )
        .unwrap();
        // `env` cannot produce `test_doc` facts; `extra` did not exist when
        // `doc-marked` was locked.
        let ids: Vec<&str> = c.sources.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["docs"]);
        assert_eq!(c.scan.max_file_size, 4 << 20);
        assert_eq!(c.scan.fail_on_skipped, ["truncated"]);
        // Weakening before the lock is the locking layer's own business.
        let weaken = "version = 1\n[scan]\nexclude = [\"/tmp/**\"]\n";
        let lock = "version = 1\n[[rule]]\nid = \"long-token\"\nlocked = true\n";
        let c = load_files(
            &[
                ("/work/base.toml", &BASE.replace("locked = true\n", "")),
                ("/work/w.toml", weaken),
                ("/work/l.toml", lock),
            ],
            &["base.toml", "w.toml", "l.toml"],
        )
        .unwrap();
        assert_eq!(c.scan.exclude, ["~/Library/**", "/tmp/**"]);
    }

    /// A locked rule on a value type depends on every source (values come
    /// from env vars, extracted entries and documents alike).
    #[test]
    fn a_locked_value_type_rule_protects_every_source() {
        let lock = "version = 1\n[[rule]]\nid = \"long-token\"\nlocked = true\n";
        let project = "version = 1\n[[source]]\nid = \"env\"\nnames = [\"PATH\"]\n";
        let errs = messages(load_files(
            &[
                ("/work/base.toml", BASE),
                ("/work/l.toml", lock),
                ("/work/p.toml", project),
            ],
            &["base.toml", "l.toml", "p.toml"],
        ));
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].starts_with(
                "/work/p.toml: source `env` is locked: rule `long-token`, locked by \
                 /work/l.toml, depends on it; this layer tries to drop names `*`"
            ),
            "{errs:?}"
        );
    }

    /// `locked = true` on a source, a custom type and `[scan]`, also via an
    /// override of an earlier layer's entry.
    #[test]
    fn explicit_locks_on_sources_types_and_scan() {
        let base = BASE.replace("locked = true\n", "");
        let lock = r#"
version = 1
[scan]
locked = true
[[source]]
id = "env"
locked = true
[[type]]
name = "acme_key"
locked = true
"#;
        let project = r#"
version = 1
[scan]
one-file-system = false
max-depth = 3
[[source]]
id = "env"
enabled = false
[[source]]
id = "docs"
enabled = false
[[type]]
name = "acme_key"
pattern = '^x$'
locked = false
"#;
        let errs = messages(load_files(
            &[
                ("/work/base.toml", &base),
                ("/work/l.toml", lock),
                ("/work/p.toml", project),
            ],
            &["base.toml", "l.toml", "p.toml"],
        ));
        assert_eq!(
            errs,
            [
                "/work/p.toml: `[scan]` is locked by /work/l.toml; this layer tries to lower \
                 scan.max-depth from 16 to 3. A locked input may only be extended (more paths, \
                 sources, rules), not weakened",
                "/work/p.toml: type `acme_key` is locked by /work/l.toml; this layer tries to \
                 unlock it (`locked = false`), change its pattern. A locked input may only be \
                 extended (more paths, sources, rules), not weakened",
                "/work/p.toml: source `env` is locked by /work/l.toml; this layer tries to \
                 disable it (`enabled = false`). A locked input may only be extended (more \
                 paths, sources, rules), not weakened",
            ]
        );
        // A new type needs a pattern; an override may leave it out.
        let errs = messages(load_files(
            &[(
                "/work/a.toml",
                "version = 1\n[[type]]\nname = \"x_key\"\nlocked = true\n",
            )],
            &["a.toml"],
        ));
        assert!(
            errs[0].contains("type `x_key` overrides nothing"),
            "{errs:?}"
        );
    }

    #[test]
    fn fail_on_skipped_reasons_are_validated_and_appended() {
        let a = "version = 1\n[scan]\nfail-on-skipped = [\"truncated\", \"binary\"]\n";
        let b = "version = 1\n[scan]\nfail-on-skipped = [\"binary\", \"depth_limit\"]\n";
        let c = load_files(
            &[("/w/a.toml", a), ("/w/b.toml", b)],
            &["/w/a.toml", "/w/b.toml"],
        )
        .unwrap();
        assert_eq!(
            c.scan.fail_on_skipped,
            ["truncated", "binary", "depth_limit"]
        );
        let bad = "version = 1\n[scan]\nfail-on-skipped = [\"truncatd\"]\n";
        let errs = messages(load_files(&[("/w/a.toml", bad)], &["/w/a.toml"]));
        assert!(errs[0].contains("unknown reason `truncatd`"), "{errs:?}");
    }
}
