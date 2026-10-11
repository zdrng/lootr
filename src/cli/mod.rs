//! Presentation: command line parsing, wiring and exit codes.
//!
//! `lootr` scans and writes the report to stdout (or `--output`); progress,
//! warnings and errors go to stderr.
//!
//! Subcommands (they load the config like a scan, but scan nothing):
//!
//! - `lootr types [--json]`: every type with its attributes, for policy
//!   authors (custom types from the config included);
//! - `lootr explain <rule>`: a rule after layering (condition, severity,
//!   messages, the layer that defined and the one that locked it) and the
//!   attributes of its type;
//! - `lootr policy check [files]`: validates the config layers (built-in
//!   default unless `--no-default`, `--config` files, then `files`) and
//!   prints what they add up to. It reads only the config files: no
//!   environment, no home directory (waiver paths are expanded against a
//!   placeholder home), nothing is scanned. For policy repositories in CI.
//!
//! Exit codes: 0 = no unwaived finding at or above `--fail-on` (or the
//! subcommand succeeded), 1 = such findings, 2 = error (invalid config,
//! rule error, I/O error, unknown rule).

pub mod progress;
pub mod wiring;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

use crate::cli::progress::Progress;
use crate::cli::wiring::{Deps, Real};
use crate::domain::model::Severity;
use crate::domain::time::Date;
use crate::domain::types::{AttrKind, FILE_ATTRS, TypeInfo};
use crate::os::open::create_report;
use crate::report::paths::below;
use crate::report::{Format, Report, RuleMeta, RunMeta};
use crate::service::cel::Cel;
use crate::service::config::{ConfigRequest, DEFAULT_CONFIG, DEFAULT_LAYER, LoadedConfig, load};
use crate::service::scan::{ScanService, count};

/// Home directory `lootr policy check` expands `~` in waiver paths with: the
/// check must not depend on (or read) the machine it runs on.
pub const POLICY_CHECK_HOME: &str = "/nonexistent-home";

/// Show which secrets and credentials the current user can reach, and check
/// them against a policy. Read only, offline, no subprocesses.
///
/// Exit codes: 0 = no unwaived finding at or above --fail-on, 1 = such
/// findings, 2 = error (invalid config, rule error).
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Config layer applied after the built-in default (repeatable; later
    /// files override earlier ones).
    #[arg(long = "config", value_name = "PATH", global = true)]
    pub configs: Vec<PathBuf>,

    /// Do not load the built-in default config.
    #[arg(long, global = true)]
    pub no_default: bool,

    /// Exit with 1 if an unwaived finding has at least this severity
    /// (info, low, medium, high, critical).
    #[arg(long, value_name = "SEVERITY", default_value = "high")]
    pub fail_on: Severity,

    /// Report format: json, sarif (SARIF 2.1.0, GitHub code scanning) or
    /// markdown (PR comments, job summaries).
    #[arg(long, value_enum, default_value_t = FormatArg::Json)]
    pub format: FormatArg,

    /// Write the report to FILE (mode 0600) instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Include every collected fact in the report (JSON only), for external
    /// tools.
    #[arg(long, conflicts_with = "summary_only")]
    pub emit_facts: bool,

    /// Hide paths outside the working directory (`~/<redacted:1>`); paths
    /// in the project stay visible, relative.
    #[arg(long)]
    pub redact_paths: bool,

    /// Report only counts (by severity and rule), no findings or locations.
    #[arg(long)]
    pub summary_only: bool,

    /// Print only warnings and errors on stderr.
    #[arg(long, short, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Command {
    /// List every type (built-in, custom and probe fact types) with the
    /// attributes rules can use.
    Types {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show a rule as configured after all layers, with its type's
    /// attributes.
    Explain {
        /// Rule id, e.g. ssh-key-unencrypted.
        rule: String,
    },
    /// Work with policy (config) files without scanning.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum PolicyCommand {
    /// Validate config layers without scanning: the built-in default (unless
    /// --no-default), every --config, then FILES in order. Reads only these
    /// files. Exit code 0 if valid, 2 if not.
    Check {
        /// Config files, applied in order after --config.
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    Json,
    Sarif,
    Markdown,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Format {
        match f {
            FormatArg::Json => Format::Json,
            FormatArg::Sarif => Format::Sarif,
            FormatArg::Markdown => Format::Markdown,
        }
    }
}

/// Entry point after hardening: parses the arguments and runs against the
/// real system.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let real = Real::new();
    let deps = real.deps();
    let stderr = std::io::stderr();
    let color = stderr.is_terminal()
        && deps.env.setting("NO_COLOR").is_none_or(|v| v.is_empty())
        && deps.env.setting("TERM").is_none_or(|t| t != "dumb");
    let mut progress = Progress::new(Box::new(stderr), cli.quiet, color);
    let code = execute(&cli, &deps, &mut std::io::stdout(), &mut progress);
    ExitCode::from(code)
}

/// Runs the command with `deps`, writes its output to `stdout` (the scan
/// report unless `--output`) and returns the exit code.
pub fn execute(cli: &Cli, deps: &Deps<'_>, stdout: &mut dyn Write, progress: &mut Progress) -> u8 {
    let started = Instant::now();
    if let Some(Command::Policy {
        command: PolicyCommand::Check { files },
    }) = &cli.command
    {
        return policy_check(cli, deps, files, stdout, progress);
    }
    if cli.emit_facts && cli.format != FormatArg::Json {
        progress.error("--emit-facts needs --format json");
        return 2;
    }
    let home = deps.system.home_dir();
    let Some(config) = load_config(cli, deps, &cli.configs, home.as_deref(), progress) else {
        return 2;
    };
    let text = match &cli.command {
        None => return scan(cli, deps, &config, stdout, progress, started),
        Some(Command::Types { json }) => types_text(&config, *json),
        Some(Command::Explain { rule }) => match explain_text(&config, rule) {
            Some(t) => t,
            None => {
                let known: Vec<&str> = config.rules.iter().map(|r| r.rule.id.as_str()).collect();
                progress.error(format!(
                    "unknown rule `{rule}` (enabled rules: {})",
                    if known.is_empty() {
                        "none".to_string()
                    } else {
                        known.join(", ")
                    }
                ));
                return 2;
            }
        },
        Some(Command::Policy { .. }) => return 2,
    };
    write_out(stdout, &text, progress)
}

fn write_out(stdout: &mut dyn Write, text: &str, progress: &mut Progress) -> u8 {
    match stdout
        .write_all(text.as_bytes())
        .and_then(|_| stdout.flush())
    {
        Ok(()) => 0,
        Err(e) => {
            progress.error(format!("writing the output: {e}"));
            2
        }
    }
}

/// Builds the registry and loads the config layers (`files` after the
/// built-in default); errors are printed.
fn load_config(
    cli: &Cli,
    deps: &Deps<'_>,
    files: &[PathBuf],
    home: Option<&std::path::Path>,
    progress: &mut Progress,
) -> Option<LoadedConfig> {
    let cwd = match deps.system.current_dir() {
        Ok(c) => c,
        Err(e) => {
            progress.error(format!("cannot determine the current directory: {e}"));
            return None;
        }
    };
    let registry = match (deps.registry)(deps.probes, deps.system.now()) {
        Ok(r) => r,
        Err(e) => {
            progress.error(format!("internal type registry: {e}"));
            return None;
        }
    };
    let probe_names: Vec<&str> = deps.probes.iter().map(|p| p.name()).collect();
    let request = ConfigRequest {
        default: (!cli.no_default).then_some(DEFAULT_CONFIG),
        files,
        cwd: &cwd,
        home,
        probes: &probe_names,
    };
    match load(deps.config, &request, registry, &Cel::new()) {
        Ok(c) => Some(c),
        Err(errors) => {
            for e in &errors.0 {
                progress.error(e);
            }
            let what = if cli.command.is_none() {
                "nothing was scanned"
            } else {
                "nothing was done"
            };
            progress.error(format!(
                "invalid config ({}); {what}",
                count(errors.0.len(), "problem", "problems")
            ));
            None
        }
    }
}

/// A layer name for `policy check` output: relative to `cwd` when below it.
fn layer_name(layer: &str, cwd: &std::path::Path) -> String {
    match below(layer, &cwd.to_string_lossy()) {
        Some(rel) if !rel.is_empty() => rel.to_string(),
        _ => layer.to_string(),
    }
}

/// `lootr policy check`.
fn policy_check(
    cli: &Cli,
    deps: &Deps<'_>,
    files: &[PathBuf],
    stdout: &mut dyn Write,
    progress: &mut Progress,
) -> u8 {
    let mut all = cli.configs.clone();
    all.extend(files.iter().cloned());
    let home = std::path::Path::new(POLICY_CHECK_HOME);
    let Some(config) = load_config(cli, deps, &all, Some(home), progress) else {
        return 2;
    };
    let cwd = deps.system.current_dir().unwrap_or_default();
    let name = |l: &str| layer_name(l, &cwd);
    let today = Date::from_unix(deps.system.now());
    let locked: Vec<_> = config.rules.iter().filter(|r| r.rule.locked).collect();
    let mut out = format!(
        "policy ok: {}, {}, {} ({} locked), {}, {}\n",
        count(config.layers.len(), "layer", "layers"),
        count(config.sources.len(), "source", "sources"),
        count(config.rules.len(), "enabled rule", "enabled rules"),
        locked.len(),
        count(
            config.registry.custom_types().len(),
            "custom type",
            "custom types"
        ),
        count(config.waivers.len(), "waiver", "waivers"),
    );
    out.push_str("\nlayers (in order):\n");
    for (i, l) in config.layers.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", i + 1, name(l)));
    }
    if !locked.is_empty() {
        out.push_str("\nlocked rules:\n");
        for r in &locked {
            let by = r.rule.locked_by.as_deref().map(name).unwrap_or_default();
            out.push_str(&format!(
                "  {} ({}, locked by {by})\n",
                r.rule.id, r.rule.severity
            ));
        }
    }
    if !config.waivers.is_empty() {
        out.push_str("\nwaivers:\n");
    }
    for w in &config.waivers {
        let mut scope = Vec::new();
        if let Some(p) = &w.path_pattern {
            scope.push(format!("path {p}"));
        }
        if let Some(n) = &w.name {
            scope.push(format!("name {n}"));
        }
        if scope.is_empty() {
            scope.push("everywhere".into());
        }
        let until = match w.expires {
            Some(e) if e < today => {
                progress.warn(format!(
                    "waiver for `{}` ({} [[waiver]] #{}) expired on {e}: scans ignore it and \
                     report `waiver-expired`",
                    w.rule,
                    name(&w.layer),
                    w.position
                ));
                format!("expired on {e}")
            }
            Some(e) => format!("until {e} ({} days)", today.days_until(e)),
            None => "no expiry".to_string(),
        };
        out.push_str(&format!(
            "  {} {}, {until} ({} [[waiver]] #{}): {}\n",
            w.rule,
            scope.join(", "),
            name(&w.layer),
            w.position,
            w.reason
        ));
    }
    if config.layers.iter().all(|l| l == DEFAULT_LAYER) && files.is_empty() {
        progress.warn("no config files given: only the built-in default was checked");
    }
    write_out(stdout, &out, progress)
}

fn scan(
    cli: &Cli,
    deps: &Deps<'_>,
    config: &LoadedConfig,
    stdout: &mut dyn Write,
    progress: &mut Progress,
    started: Instant,
) -> u8 {
    progress.line(
        "Loaded",
        format!(
            "config: {}, {}, {}",
            count(config.layers.len(), "layer", "layers"),
            count(config.sources.len(), "source", "sources"),
            count(config.rules.len(), "rule", "rules")
        ),
    );

    let service = ScanService {
        files: deps.files,
        env: deps.env,
        system: deps.system,
        probes: deps.probes,
    };
    let result = match service.run(config, progress) {
        Ok(r) => r,
        Err(e) => {
            progress.error(format!("scan failed: {e}"));
            return 2;
        }
    };
    let meta = RunMeta {
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        fail_on: cli.fail_on,
        config_layers: config.layers.clone(),
        emit_facts: cli.emit_facts,
        summary_only: cli.summary_only,
        redact_paths: cli.redact_paths,
        fail_on_skipped: config.scan.fail_on_skipped.clone(),
        rules: config
            .rules
            .iter()
            .map(|r| RuleMeta {
                id: r.rule.id.clone(),
                type_: r.rule.type_.clone(),
                when: r.rule.when.clone(),
                severity: r.rule.severity,
                message: r.rule.message.clone(),
                remediation: r.rule.remediation.clone(),
                tags: r.rule.tags.clone(),
                locked: r.rule.locked,
            })
            .collect(),
    };
    let cwd = result.cwd.clone();
    let report = Report::new(result, &config.registry, meta);
    // stderr shows the same (mapped, possibly redacted) paths as the report:
    // CI logs are often public.
    for e in &report.rule_errors {
        progress.error(format!(
            "rule `{}` failed on {} at {}: {}",
            e.rule, e.type_, e.location, e.message
        ));
    }
    for w in &report.expired_waivers {
        progress.warn(format!(
            "waiver for `{}` ({}) expired on {}; the findings are reported again (renew or remove it)",
            w.rule, w.layer, w.expires
        ));
    }
    let text = report.render(cli.format.into());
    let written = match &cli.output {
        Some(path) => create_report(&cwd.join(path))
            .map_err(|e| format!("writing {}: {e}", path.display()))
            .and_then(|mut f| {
                f.write_all(text.as_bytes())
                    .map_err(|e| format!("writing {}: {e}", path.display()))
            }),
        None => stdout
            .write_all(text.as_bytes())
            .and_then(|_| stdout.flush())
            .map_err(|e| format!("writing the report: {e}")),
    };
    if let Err(e) = written {
        progress.error(e);
        return 2;
    }

    let s = &report.summary;
    let mut parts = vec![count(s.findings, "finding", "findings")];
    if s.waived > 0 {
        parts.push(format!("{} waived", s.waived));
    }
    parts.push(format!("{} at or above {}", s.failing, cli.fail_on));
    if s.rule_errors > 0 {
        parts.push(count(s.rule_errors, "rule error", "rule errors"));
    }
    if s.failing_skipped > 0 {
        parts.push(format!(
            "{} with a fail-on-skipped reason",
            count(s.failing_skipped, "skipped entry", "skipped entries")
        ));
    }
    progress.line(
        "Finished",
        format!(
            "{} in {:.1}s",
            parts.join(", "),
            started.elapsed().as_secs_f64()
        ),
    );
    report.exit_code()
}

fn kind_name(kind: AttrKind) -> &'static str {
    match kind {
        AttrKind::Bool => "bool",
        AttrKind::Int => "int",
        AttrKind::Sym => "sym",
        AttrKind::Name => "name",
        AttrKind::Text => "text",
        AttrKind::Path => "path",
        AttrKind::List => "list",
        AttrKind::Map => "map",
    }
}

/// The attribute table of a type, indented.
fn attr_table(info: &TypeInfo, out: &mut String) {
    let width = info.attrs.iter().map(|a| a.name.len()).max().unwrap_or(0);
    for a in &info.attrs {
        let optional = if a.optional { " (optional)" } else { "" };
        out.push_str(&format!(
            "    {:width$}  {:4}  {}{optional}\n",
            a.name,
            kind_name(a.kind),
            a.doc
        ));
    }
    if info.file_attrs {
        let names: Vec<&str> = FILE_ATTRS.iter().map(|a| a.name).collect();
        out.push_str(&format!(
            "    + file attributes when found in a file: {}\n",
            names.join(", ")
        ));
    }
}

/// `lootr types`.
pub fn types_text(config: &LoadedConfig, json: bool) -> String {
    let types = config.registry.types();
    if json {
        let doc = serde_json::json!({
            "types": types,
            "file_attrs": FILE_ATTRS,
            "builtin_variables": crate::domain::types::RESERVED_NAMES,
        });
        return serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n";
    }
    let mut out = String::from(
        "Every rule can use `type`, `source`, `location` (kind, path, key_path, name) and\n\
         `attrs` (test optional attributes with has(attrs.<name>)).\n",
    );
    for t in &types {
        let kind = serde_json::to_value(t.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        out.push_str(&format!("\n{} ({kind})\n    {}\n", t.name, t.doc));
        attr_table(t, &mut out);
    }
    out
}

/// `lootr explain <rule>`; `None` if no enabled rule has this id.
pub fn explain_text(config: &LoadedConfig, id: &str) -> Option<String> {
    let rule = &config.rules.iter().find(|r| r.rule.id.as_str() == id)?.rule;
    let mut out = String::new();
    let mut field = |name: &str, value: &str| {
        out.push_str(&format!("{name:12} {value}\n"));
    };
    field("rule", rule.id.as_str());
    field("type", &rule.type_);
    field("severity", rule.severity.as_str());
    field("when", &rule.when);
    field(
        "message",
        rule.message
            .as_deref()
            .unwrap_or(crate::service::evaluate::DEFAULT_MESSAGE),
    );
    field("remediation", rule.remediation.as_deref().unwrap_or("-"));
    let tags: Vec<String> = rule.tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let tags = if tags.is_empty() {
        "-".to_string()
    } else {
        tags.join(", ")
    };
    field("tags", &tags);
    let locked = match (&rule.locked_by, rule.locked) {
        (Some(by), true) => format!("yes (by {by})"),
        (None, true) => "yes".to_string(),
        _ => "no".to_string(),
    };
    field("locked", &locked);
    field("defined in", &rule.layer);
    if let Some(info) = config.registry.info(&rule.type_) {
        out.push_str(&format!("\nattributes of {}:\n", info.name));
        attr_table(&info, &mut out);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    //! End-to-end runs of the CLI on fake repositories, including the
    //! canary checks: no dummy secret may appear on stdout or stderr in any
    //! mode.

    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::domain::model::FileKind;
    use crate::domain::types::test_types;
    use crate::domain::types::{Registry, RegistryError};
    use crate::repository::fake::{FakeConfig, FakeEnv, FakeFiles, FakeSystem};
    use crate::service::probe::Probe;
    use crate::testing::{CANARY, find_leaks};

    /// A `Write` whose content the test can read afterwards.
    #[derive(Clone, Default)]
    struct Shared(Rc<RefCell<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.borrow()).into_owned()
        }
    }

    fn test_registry(_: &[Box<dyn Probe>], _: i64) -> Result<Registry, RegistryError> {
        Ok(test_types::registry())
    }

    // Dummy secrets, all carrying the canary.
    const TOKEN: &str = "tok_LOOTRCANARY_d41d8cd98f00b204";
    const ACME: &str = "acme_LOOTRCANARY_e9800998ecf8427e";
    const PLAIN: &str = "hunter2-LOOTRCANARY-plain-password";
    const DOC_VALUE: &str = "tok_LOOTRCANARY_doc_value_0123";
    const ENTRY_VALUE: &str = "tok_LOOTRCANARY_entry_value_456";

    const CONFIG: &str = r#"
version = 1

[[source]]
id = "env"
kind = "env"
names = ["*"]

[[source]]
id = "docs"
kind = "file"
paths = ["~/docs/*"]
type = "test_doc"

[[source]]
id = "dotfiles"
kind = "file"
paths = ["./**/.env"]
extract = "lines"

[[type]]
name = "acme_key"
pattern = '^acme_'

[[rule]]
id = "token-anywhere"
type = "test_token"
when = "true"
severity = "high"
message = "{type} {kind} ({length} bytes) at {location} name={name} path={path} source={source}"
remediation = "rotate {name}"

[[rule]]
id = "acme"
type = "acme_key"
when = "length > 10"
severity = "medium"
message = "{charset} {entropy} {length}"

[[rule]]
id = "env-entropy"
type = "env_var"
when = "entropy > 10"
severity = "low"
message = "{name} {length} {entropy} {classified_as}"

[[rule]]
id = "entries"
type = "line_entry"
when = "true"
severity = "info"
message = "{name} {mode} {world_readable} {size} {classified_as}"

[[rule]]
id = "doc-label"
type = "test_doc"
when = 'label == "x"'
severity = "high"

[[waiver]]
rule = "acme"
name = "ACME_KEY"
reason = "accepted"
expires = 2020-01-01
"#;

    struct World {
        files: FakeFiles,
        env: FakeEnv,
        system: FakeSystem,
        config: FakeConfig,
    }

    fn world(config: &str) -> World {
        World {
            files: FakeFiles::new()
                .file(
                    "/home/user/docs/a",
                    format!("TESTDOC\napi={DOC_VALUE}\nsecret={PLAIN}"),
                )
                .file_with_mode(
                    "/work/app/.env",
                    format!("TOKEN={ENTRY_VALUE}\nPASSWORD={PLAIN}\n"),
                    0o644,
                ),
            env: FakeEnv::new()
                .var("GH_TOKEN", TOKEN)
                .var("ACME_KEY", ACME)
                .var("DB_PASSWORD", PLAIN)
                .var("HOME", "/home/user"),
            system: FakeSystem::default(),
            config: FakeConfig::new().file("/work/lootr.toml", config),
        }
    }

    fn run(w: &World, args: &[&str]) -> (u8, String, String) {
        let probes: Vec<Box<dyn Probe>> = Vec::new();
        let deps = Deps {
            files: &w.files,
            env: &w.env,
            system: &w.system,
            config: &w.config,
            probes: &probes,
            registry: test_registry,
        };
        let mut argv = vec!["lootr", "--no-default", "--config", "lootr.toml"];
        argv.extend(args);
        let cli = Cli::try_parse_from(argv).unwrap();
        let mut stdout = Shared::default();
        let stderr = Shared::default();
        let mut progress = Progress::new(Box::new(stderr.clone()), cli.quiet, false);
        let code = execute(&cli, &deps, &mut stdout, &mut progress);
        (code, stdout.text(), stderr.text())
    }

    fn assert_no_leaks(output: &str) {
        let leaks = find_leaks(output, &[TOKEN, ACME, PLAIN, DOC_VALUE, ENTRY_VALUE]);
        assert!(leaks.is_empty(), "{leaks:#?}\n--- output ---\n{output}");
    }

    #[test]
    fn no_secret_reaches_any_output() {
        let w = world(CONFIG);
        for args in [
            &[][..],
            &["--emit-facts"],
            &["--quiet", "--emit-facts"],
            &["--fail-on", "info"],
        ] {
            let (code, stdout, stderr) = run(&w, args);
            // `doc-label` fails on a fact without `label`: a rule error.
            assert_eq!(code, 2, "{stderr}");
            assert_no_leaks(&stdout);
            assert_no_leaks(&stderr);
            let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["schema_version"], 1);
        }
    }

    #[test]
    fn the_report_has_findings_facts_and_errors() {
        let w = world(CONFIG);
        let (_, stdout, stderr) = run(&w, &["--emit-facts"]);
        let r: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules: Vec<&str> = r["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule"].as_str().unwrap())
            .collect();
        assert_eq!(
            rules,
            [
                "token-anywhere",
                "token-anywhere",
                "token-anywhere",
                "acme",
                "env-entropy",
                "env-entropy",
                "env-entropy",
                "env-entropy",
                "entries",
                "entries",
            ]
        );
        assert_eq!(
            r["findings"][0]["message"],
            "test_token long (30 bytes) at ~/docs/a#api name=api path=~/docs/a source=docs"
        );
        assert_eq!(r["findings"][0]["remediation"], "rotate api");
        assert_eq!(r["findings"][9]["message"], "TOKEN 0644 true 82 test_token");
        assert_eq!(r["custom_types"][0]["name"], "acme_key");
        assert_eq!(r["custom_types"][0]["pattern"], "^acme_");
        assert_eq!(r["rule_errors"][0]["rule"], "doc-label");
        assert_eq!(r["expired_waivers"][0]["rule"], "acme");
        assert_eq!(r["summary"]["failing"], 3);
        assert_eq!(r["run"]["started_at"], "2026-10-08T14:03:00Z");
        assert_eq!(r["run"]["config_layers"][0], "/work/lootr.toml");
        assert!(r["facts"].as_array().unwrap().len() > 9);
        assert!(stderr.contains("error: rule `doc-label` failed on test_doc at ~/docs/a"));
        assert!(stderr.contains("warning: waiver for `acme`"));
        assert!(!stderr.contains(CANARY));
    }

    #[test]
    fn exit_codes() {
        let base = CONFIG.replace(
            "when = 'label == \"x\"'",
            "when = 'has(attrs.label) && label == \"x\"'",
        );
        let w = world(&base);
        assert_eq!(run(&w, &[]).0, 1, "high findings fail by default");
        assert_eq!(run(&w, &["--fail-on", "critical"]).0, 0);
        let w = world("version = 1\n");
        let (code, stdout, _) = run(&w, &["--fail-on", "info"]);
        assert_eq!(code, 0);
        let r: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(r["summary"]["findings"], 0);
    }

    #[test]
    fn invalid_config_is_exit_2_without_scanning() {
        let w = world(
            "version = 1\n[[rule]]\nid = \"x\"\ntype = \"test_doc\"\nwhen = \"bits > 1\"\nseverity = \"high\"\n",
        );
        let (code, stdout, stderr) = run(&w, &[]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(
            stderr.contains(
                "error: /work/lootr.toml: rule `x`: unknown attribute `bits` for type `test_doc`"
            ),
            "{stderr}"
        );
        assert!(stderr.contains("nothing was scanned"));
    }

    // ---- the built-in types, probes and default policy on fakes ----------------

    const JWT_LONG: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiYXBpIiwic3ViIjoiTE9PVFJDQU5BUlktc3ViamVjdCIsInNjb3BlIjoicmVhZDpwYWNrYWdlcyB3cml0ZTpwYWNrYWdlcyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.LOOTRCANARY-Xq7Lm2Pz9Rk4Wt8Vn3Hb6Jc1Ds5Gf0";
    const SSH_KEY: &str =
        include_str!("../../test-envs/ssh/unencrypted/home/.ssh/dummy_id_ed25519");

    fn real_world() -> (World, Vec<String>) {
        let classic = crate::testing::github_token("ghp_", "LOOTRCANARYclassic0123456789ab");
        let app = crate::testing::github_token("ghs_", "LOOTRCANARYapp0123456789abcdef");
        let mut system = FakeSystem {
            groups: vec![1000, 999],
            ..FakeSystem::default()
        };
        system.group_names.insert(999, "docker".into());
        let w = World {
            files: FakeFiles::new()
                .file("/home/user/.ssh/dummy_id_ed25519", SSH_KEY)
                .file("/home/user/.ssh/config", "Host x\n")
                .dir("/work/.git")
                .file("/work/.gitignore", ".env.local\n")
                .file_with_mode(
                    "/work/.env",
                    format!(
                        "GH_TOKEN={classic}\nDB_PASSWORD=LOOTRCANARY-x9Qv3Lm8Zt2Rw7Kp\nPORT=8080\n"
                    ),
                    0o644,
                )
                .file("/work/.env.local", format!("ID_TOKEN={JWT_LONG}\n"))
                .special_owned("/var/run/docker.sock", FileKind::Socket, 0, 999, 0o660),
            env: FakeEnv::new()
                .var("GITHUB_TOKEN", &app)
                .var("API_SECRET", "LOOTRCANARY-q8Wn2Xc5Vb7Mz1Lk")
                .var("HOME", "/home/user"),
            system,
            config: FakeConfig::new(),
        };
        let secrets = vec![
            classic,
            app,
            JWT_LONG.to_string(),
            "LOOTRCANARY-x9Qv3Lm8Zt2Rw7Kp".to_string(),
            "LOOTRCANARY-q8Wn2Xc5Vb7Mz1Lk".to_string(),
        ];
        (w, secrets)
    }

    fn run_real(w: &World, args: &[&str]) -> (u8, String, String) {
        let probes = crate::service::probe::builtin();
        let deps = Deps {
            files: &w.files,
            env: &w.env,
            system: &w.system,
            config: &w.config,
            probes: &probes,
            registry: wiring::registry,
        };
        let mut argv = vec!["lootr"];
        argv.extend(args);
        let cli = Cli::try_parse_from(argv).unwrap();
        let mut stdout = Shared::default();
        let stderr = Shared::default();
        let mut progress = Progress::new(Box::new(stderr.clone()), cli.quiet, false);
        let code = execute(&cli, &deps, &mut stdout, &mut progress);
        (code, stdout.text(), stderr.text())
    }

    #[test]
    fn default_policy_end_to_end() {
        let (w, secrets) = real_world();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let (code, stdout, stderr) = run_real(&w, &["--emit-facts"]);
        for out in [&stdout, &stderr] {
            let leaks = find_leaks(out, &secrets);
            assert!(leaks.is_empty(), "{leaks:#?}\n{out}");
        }
        assert_eq!(code, 1, "{stderr}");
        let r: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(r["rule_errors"], serde_json::json!([]), "{stdout}");
        let mut found: Vec<String> = r["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let loc = &f["fact"]["location"];
                let at = loc["name"]
                    .as_str()
                    .or(loc["key_path"].as_str())
                    .or(loc["path"].as_str())
                    .unwrap_or("?");
                format!("{} {}", f["rule"].as_str().unwrap(), at)
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                "container-socket-root /var/run/docker.sock",
                "dotenv-secret-not-gitignored DB_PASSWORD",
                "dotenv-secret-world-readable DB_PASSWORD",
                "dotenv-secret-world-readable GH_TOKEN",
                "dotenv-token-not-gitignored GH_TOKEN",
                "env-secret-like API_SECRET",
                "github-classic-token GH_TOKEN",
                "github-token GITHUB_TOKEN",
                "jwt-long-lived ID_TOKEN",
                "process-root-equivalent-group process",
                "ssh-key-unencrypted ~/.ssh/dummy_id_ed25519",
            ],
            "{stdout}"
        );
        let jwt = r["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["type"] == "jwt")
            .unwrap();
        assert_eq!(jwt["attrs"]["issuer"], "https://issuer.example");
        assert_eq!(jwt["attrs"]["gitignored"], true);
        assert_eq!(jwt["attrs"]["in_git_repo"], true);
    }

    #[test]
    fn types_lists_builtin_custom_and_probe_types() {
        let (mut w, _) = real_world();
        w.config = FakeConfig::new().file(
            "/work/acme.toml",
            "version = 1\n[[type]]\nname = \"acme_key\"\npattern = '^acme_'\n",
        );
        let (code, stdout, stderr) = run_real(&w, &["types", "--config", "acme.toml"]);
        assert_eq!(code, 0, "{stderr}");
        for t in [
            "env_var (entry)",
            "dotenv_entry (entry)",
            "ssh_private_key (document)",
            "github_token (value)",
            "jwt (value)",
            "acme_key (custom)",
            "process (probe)",
            "unix_socket (probe)",
        ] {
            assert!(stdout.contains(t), "{t}\n{stdout}");
        }
        assert!(stdout.contains("    checksum_valid  bool  "), "{stdout}");
        assert!(stdout.contains("(optional)"));
        assert!(stdout.contains("+ file attributes when found in a file: mode,"));
        let (code, stdout, _) = run_real(&w, &["types", "--json"]);
        assert_eq!(code, 0);
        let j: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(j["types"][3]["name"], "ssh_private_key");
        assert_eq!(j["types"][3]["attrs"][0]["name"], "format");
    }

    #[test]
    fn explain_shows_a_rule_after_layering() {
        let (mut w, _) = real_world();
        w.config = FakeConfig::new().file(
            "/work/team.toml",
            "version = 1\n[[rule]]\nid = \"ssh-key-weak\"\nseverity = \"high\"\ntags = { cis = \"5.2.x\" }\n",
        );
        let (code, stdout, stderr) =
            run_real(&w, &["--config", "team.toml", "explain", "ssh-key-weak"]);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("rule         ssh-key-weak\n"), "{stdout}");
        assert!(stdout.contains("severity     high\n"));
        assert!(stdout.contains("tags         category=key-strength, cis=5.2.x\n"));
        assert!(stdout.contains("defined in   /work/team.toml\n"));
        assert!(stdout.contains("attributes of ssh_private_key:"));
        assert!(stdout.contains("    bits"));

        let (code, stdout, stderr) = run_real(&w, &["explain", "no-such-rule"]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unknown rule `no-such-rule`"), "{stderr}");
    }

    // ---- output formats and flags --------------------------------------------

    /// Every format with every flag combination: no leaks on stdout or
    /// stderr, valid SARIF, and the same exit code.
    #[test]
    fn every_format_and_flag_is_leak_free() {
        let (w, secrets) = real_world();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        for format in ["json", "sarif", "markdown"] {
            for flags in [
                &[][..],
                &["--redact-paths"],
                &["--summary-only"],
                &["--redact-paths", "--summary-only"],
                &["--quiet", "--fail-on", "info"],
            ] {
                let mut args = vec!["--format", format];
                args.extend(flags);
                let (code, stdout, stderr) = run_real(&w, &args);
                assert_eq!(code, 1, "{args:?}: {stderr}");
                for out in [&stdout, &stderr] {
                    let leaks = find_leaks(out, &secrets);
                    assert!(leaks.is_empty(), "{args:?}: {leaks:#?}\n{out}");
                }
                if flags.contains(&"--redact-paths") {
                    for out in [&stdout, &stderr] {
                        assert!(!out.contains("/home/user"), "{args:?}\n{out}");
                        assert!(!out.contains(".ssh"), "{args:?}\n{out}");
                    }
                }
                match format {
                    "json" => {
                        let r: serde_json::Value = serde_json::from_str(&stdout).unwrap();
                        assert_eq!(
                            r.get("findings").is_none(),
                            flags.contains(&"--summary-only"),
                            "{args:?}"
                        );
                    }
                    "sarif" => {
                        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
                        let errs = crate::report::sarif::tests::check_sarif(&v);
                        assert!(errs.is_empty(), "{args:?}: {errs:#?}\n{stdout}");
                    }
                    _ => assert!(stdout.starts_with("## lootr report\n"), "{stdout}"),
                }
            }
        }
    }

    #[test]
    fn sarif_and_markdown_of_the_default_policy() {
        let (w, _) = real_world();
        let (_, stdout, _) = run_real(&w, &["--format", "sarif"]);
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let run = &v["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules.len() > 60);
        assert!(rules.iter().all(|r| {
            r["properties"]["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t.as_str().unwrap().starts_with("category/"))
        }));
        let results = run["results"].as_array().unwrap();
        let dotenv = results
            .iter()
            .find(|r| r["ruleId"] == "dotenv-token-not-gitignored")
            .unwrap();
        assert_eq!(
            dotenv["locations"][0]["physicalLocation"]["artifactLocation"],
            serde_json::json!({"uri": ".env", "uriBaseId": "%SRCROOT%"})
        );
        let (_, md, _) = run_real(&w, &["--format", "markdown"]);
        assert!(
            md.contains("**Result: failed**: 5 unwaived findings at or above `high`."),
            "{md}"
        );
        assert!(md.contains("#### high (5)"), "{md}");
        assert!(md.contains("`/work/.env#GH_TOKEN`"), "{md}");
    }

    #[test]
    fn flag_combinations_that_make_no_sense_are_errors() {
        let (w, _) = real_world();
        let (code, stdout, stderr) = run_real(&w, &["--format", "sarif", "--emit-facts"]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("--emit-facts needs --format json"),
            "{stderr}"
        );
        assert!(Cli::try_parse_from(["lootr", "--emit-facts", "--summary-only"]).is_err());
    }

    #[test]
    fn expired_waivers_are_findings_of_the_default_policy() {
        let (mut w, _) = real_world();
        w.config = FakeConfig::new().file(
            "/work/lootr.toml",
            r#"version = 1
[[waiver]]
rule = "ssh-key-unencrypted"
path = "~/.ssh/dummy_*"
reason = "old laptop"
expires = 2026-09-30
[[waiver]]
rule = "github-token"
name = "GITHUB_TOKEN"
reason = "the job's own token"
expires = 2026-12-31
"#,
        );
        let (code, stdout, stderr) = run_real(&w, &["--config", "lootr.toml"]);
        assert_eq!(code, 1, "{stderr}");
        let r: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let findings = r["findings"].as_array().unwrap();
        let expired = findings
            .iter()
            .find(|f| f["rule"] == "waiver-expired")
            .unwrap();
        assert_eq!(
            expired["message"],
            "Waiver for ssh-key-unencrypted (/work/lootr.toml#[[waiver]] #1) expired on \
             2026-09-30; its findings are reported again"
        );
        assert_eq!(expired["tags"]["category"], "policy-hygiene");
        let ssh = findings
            .iter()
            .find(|f| f["rule"] == "ssh-key-unencrypted")
            .unwrap();
        assert!(ssh["waived"].is_null(), "expired waivers do not apply");
        let gh = findings
            .iter()
            .find(|f| f["rule"] == "github-token")
            .unwrap();
        assert_eq!(gh["waived"]["reason"], "the job's own token");
        assert_eq!(r["summary"]["waived"], 1);
        assert_eq!(r["expired_waivers"][0]["path"], "~/.ssh/dummy_*");
        assert!(
            stderr.contains("warning: waiver for `ssh-key-unencrypted`"),
            "{stderr}"
        );
    }

    // ---- policy check ------------------------------------------------------------

    /// Repositories that fail the test when touched: `policy check` reads
    /// config files only.
    struct Untouchable;

    impl crate::repository::FileRepository for Untouchable {
        fn metadata(
            &self,
            _: &std::path::Path,
        ) -> Result<crate::domain::model::FileMeta, crate::domain::model::FsError> {
            panic!("policy check read file metadata")
        }
        fn read_dir(
            &self,
            _: &std::path::Path,
        ) -> Result<Vec<crate::repository::DirEntry>, crate::domain::model::FsError> {
            panic!("policy check listed a directory")
        }
        fn read_file(
            &self,
            _: &std::path::Path,
            _: u64,
        ) -> Result<
            (
                crate::domain::model::FileMeta,
                crate::domain::secret::SecretBuf,
            ),
            crate::domain::model::FsError,
        > {
            panic!("policy check read a file")
        }
        fn metadata_followed(
            &self,
            _: &std::path::Path,
        ) -> Result<crate::domain::model::FileMeta, crate::domain::model::FsError> {
            panic!("policy check read file metadata")
        }
        fn read_link(
            &self,
            _: &std::path::Path,
        ) -> Result<std::path::PathBuf, crate::domain::model::FsError> {
            panic!("policy check read a symlink")
        }
        fn read_file_within(
            &self,
            _: &std::path::Path,
            _: &std::path::Path,
            _: u64,
        ) -> Result<
            (
                crate::domain::model::FileMeta,
                crate::domain::secret::SecretBuf,
            ),
            crate::domain::model::FsError,
        > {
            panic!("policy check read a file")
        }
        fn metadata_within(
            &self,
            _: &std::path::Path,
            _: &std::path::Path,
        ) -> Result<crate::domain::model::FileMeta, crate::domain::model::FsError> {
            panic!("policy check read file metadata")
        }
    }

    impl crate::repository::EnvRepository for Untouchable {
        fn names(&self) -> Vec<std::ffi::OsString> {
            panic!("policy check read the environment")
        }
        fn value(&self, _: &std::ffi::OsStr) -> Option<crate::domain::secret::SecretBuf> {
            panic!("policy check read the environment")
        }
        fn setting(&self, _: &str) -> Option<String> {
            panic!("policy check read the environment")
        }
    }

    /// The fake system without a home directory.
    struct NoHome(FakeSystem);

    impl crate::repository::SystemRepository for NoHome {
        fn uid(&self) -> u32 {
            self.0.uid()
        }
        fn euid(&self) -> u32 {
            self.0.euid()
        }
        fn gid(&self) -> u32 {
            self.0.gid()
        }
        fn groups(&self) -> Vec<u32> {
            panic!("policy check read the groups")
        }
        fn group_name(&self, _: u32) -> Option<String> {
            panic!("policy check read the group database")
        }
        fn home_dir(&self) -> Option<std::path::PathBuf> {
            panic!("policy check read the home directory")
        }
        fn current_dir(&self) -> Result<std::path::PathBuf, crate::domain::model::FsError> {
            self.0.current_dir()
        }
        fn now(&self) -> i64 {
            self.0.now()
        }
    }

    fn policy_check(config: FakeConfig, args: &[&str]) -> (u8, String, String) {
        let probes = crate::service::probe::builtin();
        let system = NoHome(FakeSystem::default());
        let deps = Deps {
            files: &Untouchable,
            env: &Untouchable,
            system: &system,
            config: &config,
            probes: &probes,
            registry: wiring::registry,
        };
        let mut argv = vec!["lootr"];
        argv.extend(args);
        let cli = Cli::try_parse_from(argv).unwrap();
        let mut stdout = Shared::default();
        let stderr = Shared::default();
        let mut progress = Progress::new(Box::new(stderr.clone()), cli.quiet, false);
        let code = execute(&cli, &deps, &mut stdout, &mut progress);
        (code, stdout.text(), stderr.text())
    }

    const BASELINE: &str = r#"version = 1
[[rule]]
id = "ssh-key-unencrypted"
locked = true
severity = "critical"
tags = { control = "SEC-1" }
[[waiver]]
rule = "ssh-key-unencrypted"
path = "~/.ssh/hsm_*"
reason = "keys on a hardware token"
"#;

    #[test]
    fn policy_check_validates_without_touching_the_system() {
        let project = r#"version = 1
[[waiver]]
rule = "netrc-password"
path = "./ci/.netrc"
reason = "mirror"
expires = 2026-11-07
[[waiver]]
rule = "github-token"
name = "GITHUB_TOKEN"
reason = "job token"
expires = 2026-01-01
"#;
        let config = FakeConfig::new()
            .file("/work/policy/baseline.toml", BASELINE)
            .file("/work/project.toml", project);
        let (code, stdout, stderr) = policy_check(
            config,
            &[
                "--config",
                "policy/baseline.toml",
                "policy",
                "check",
                "project.toml",
            ],
        );
        assert_eq!(code, 0, "{stderr}");
        assert!(
            stdout.starts_with(
                "policy ok: 3 layers, 31 sources, 71 enabled rules (1 locked), 0 custom types, 3 waivers\n"
            ),
            "{stdout}"
        );
        for want in [
            "  1. <built-in>\n  2. policy/baseline.toml\n  3. project.toml\n",
            "locked rules:\n  ssh-key-unencrypted (critical, locked by policy/baseline.toml)\n",
            "  ssh-key-unencrypted path ~/.ssh/hsm_*, no expiry (policy/baseline.toml [[waiver]] #1): keys on a hardware token\n",
            "  netrc-password path ./ci/.netrc, until 2026-11-07 (30 days) (project.toml [[waiver]] #1): mirror\n",
            "  github-token name GITHUB_TOKEN, expired on 2026-01-01 (project.toml [[waiver]] #2): job token\n",
        ] {
            assert!(stdout.contains(want), "missing {want:?} in\n{stdout}");
        }
        assert!(
            stderr.contains("warning: waiver for `github-token` (project.toml [[waiver]] #2) expired on 2026-01-01"),
            "{stderr}"
        );
    }

    #[test]
    fn policy_check_reports_every_problem() {
        let project = r#"version = 1
[[rule]]
id = "ssh-key-unencrypted"
severity = "low"
[[waiver]]
rule = "ssh-key-unencrypted"
reason = "no"
"#;
        let config = FakeConfig::new()
            .file("/work/baseline.toml", BASELINE)
            .file("/work/project.toml", project);
        let (code, stdout, stderr) = policy_check(
            config,
            &["policy", "check", "baseline.toml", "project.toml"],
        );
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(
            stderr.contains(
                "error: /work/project.toml: rule `ssh-key-unencrypted` is locked by \
                 /work/baseline.toml; this layer tries to lower its severity from critical to low"
            ),
            "{stderr}"
        );
        assert!(
            stderr.contains(
                "error: /work/project.toml: waiver for `ssh-key-unencrypted`: rule is locked by \
                 /work/baseline.toml; only that layer may waive it"
            ),
            "{stderr}"
        );
        assert!(stderr.contains("invalid config (2 problems); nothing was done"));
    }

    /// `examples/company` stays valid.
    #[test]
    fn the_company_example_passes_policy_check() {
        let config = FakeConfig::new()
            .file(
                "/work/baseline.toml",
                include_str!("../../examples/company/baseline.toml"),
            )
            .file(
                "/work/team-platform.toml",
                include_str!("../../examples/company/team-platform.toml"),
            )
            .file(
                "/work/project.toml",
                include_str!("../../examples/company/project.toml"),
            );
        let (code, stdout, stderr) = policy_check(
            config,
            &[
                "policy",
                "check",
                "baseline.toml",
                "team-platform.toml",
                "project.toml",
            ],
        );
        assert_eq!(code, 0, "{stderr}");
        assert!(
            stdout.starts_with(
                "policy ok: 4 layers, 31 sources, 73 enabled rules (14 locked), 1 custom type, 3 waivers\n"
            ),
            "{stdout}"
        );
        assert!(stderr.contains("waiver for `gh-token-in-file`"), "{stderr}");
    }
}
