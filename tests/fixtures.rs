//! Fixture harness: runs the `lootr` binary against every test environment
//! in `test-envs/` and compares the normalized JSON report with the
//! environment's `expected.json`.
//!
//! Never touches the developer's real home or environment: each environment
//! is copied into a temp dir, `HOME` points at its `home/`, the process
//! environment is empty except for the environment's variables.
//!
//! # Layout of `test-envs/<group>/<name>/`
//!
//! - `home/` (fake home, created empty if missing), optional `workdir/` (the
//!   working directory; default: the home);
//! - `env.toml` (marks the directory as an environment):
//!   - `[env]` variables;
//!   - `[modes]` file modes by relative path (default: files 0600,
//!     directories 0700, so results do not depend on the checkout's umask);
//!   - `git = ["workdir"]` directories that get an empty `.git/`;
//!   - `[rename]` files renamed after copying (e.g. a fixture `.gitignore`);
//!   - `sockets = [...]` Unix sockets the harness creates;
//!   - `args = [...]` extra command line arguments;
//!   - `ignore_attrs = [...]` attributes removed before comparing
//!     (machine-dependent values);
//!   - `secrets = [...]` extra strings for the leak check (encoded secrets
//!     that do not show the canary, e.g. base64 Docker auths);
//! - `lootr.toml` (optional): applied after `test-envs/common.toml`;
//! - `expected.json`: `{"exit_code": n, "report": {...}}`.
//!
//! Every run uses the built-in default config, `test-envs/common.toml`
//! (disables the host-dependent probes) and `--emit-facts`.
//!
//! Values in `[env]` and file contents may use placeholders, expanded when
//! the environment is set up, so no token with a valid checksum is ever
//! committed (secret scanners would flag it):
//!
//! - `{{github_token:<prefix>:<random>}}` → prefix + 30 random characters +
//!   CRC32 checksum ([`lootr::testing::github_token`]);
//! - `{{github_pat:<body>}}` → `github_pat_<body>`;
//! - `{{token:<prefix>:<rest>}}` → `<prefix><rest>` (split at the last
//!   `:`), so well-known key formats (`sk_live_...`, `AKIA...`, `xoxb-...`)
//!   never appear literally in the repository;
//! - `{{base64:<a>:<b>}}` → standard base64 of `<a><b>` (Docker and npm
//!   `auth` fields).
//!
//! Other `{{...}}` text (`${{ github.token }}` in workflows) stays as it is.
//!
//! # Normalization
//!
//! Removed before comparing: `run.started_at`, `run.duration_ms`, `run.uid`,
//! `tool.version`, every `age_days`, `expires_in_hours` and `expires_in_days` attribute (they
//! depend on the clock) and the entropy of `$HOME` (a random temp path). The
//! temp dir path is replaced by `<root>`.
//!
//! # Leak check
//!
//! stdout and stderr must not contain the canary nor any 8-character
//! substring of the dummy secrets: env values and `.env` values containing
//! the canary, the base64 lines of `dummy_*` key files, in every other file
//! the text from each canary to the next character that cannot be part of a
//! token, and the `secrets` of `env.toml`.
//!
//! # Updating
//!
//! `LOOTR_UPDATE_FIXTURES=1 cargo test --test fixtures` rewrites every
//! `expected.json`; review the diff before committing.

// Test code: the harness starts the binary under test, creates sockets and
// may panic on setup errors.
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use lootr::testing::{CANARY, find_leaks, github_token};
use serde::Deserialize;
use serde_json::Value;

const UPDATE_VAR: &str = "LOOTR_UPDATE_FIXTURES";

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvSpec {
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    modes: BTreeMap<String, String>,
    #[serde(default)]
    git: Vec<String>,
    #[serde(default)]
    rename: BTreeMap<String, String>,
    #[serde(default)]
    sockets: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    ignore_attrs: Vec<String>,
    #[serde(default)]
    secrets: Vec<String>,
}

fn test_envs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-envs")
}

/// Directories below `dir` that contain an `env.toml`.
fn find_envs(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("env.toml").is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for e in entries {
        find_envs(&e, out);
    }
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Expands one placeholder; `None` for text that is not one (`${{ ... }}`
/// in a workflow stays as it is).
fn placeholder(inner: &str) -> Option<String> {
    if let Some(token) = inner.strip_prefix("token:") {
        let (prefix, tail) = token.rsplit_once(':').expect("{{token:<prefix>:<rest>}}");
        return Some(format!("{prefix}{tail}"));
    }
    if let Some(parts) = inner.strip_prefix("base64:") {
        let (a, b) = parts.rsplit_once(':').expect("{{base64:<a>:<b>}}");
        return Some(base64(format!("{a}{b}").as_bytes()));
    }
    if let Some(rest) = inner.strip_prefix("github_token:") {
        let (prefix, random) = rest
            .split_once(':')
            .expect("{{github_token:<prefix>:<random>}}");
        assert_eq!(
            random.len(),
            30,
            "random part of {inner} must be 30 characters"
        );
        return Some(github_token(prefix, random));
    }
    inner
        .strip_prefix("github_pat:")
        .map(|body| format!("github_pat_{body}"))
}

/// Expands the placeholders in `text`.
fn expand(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("}}").map(|e| e + start) else {
            break;
        };
        match placeholder(&rest[start + 2..end]) {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[start..end + 2]),
        }
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Copies `from` to `to`, expanding placeholders in text files.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_tree(&src, &dst);
        } else {
            let data = fs::read(&src).unwrap();
            match String::from_utf8(data) {
                Ok(text) => fs::write(&dst, expand(&text)).unwrap(),
                Err(e) => fs::write(&dst, e.into_bytes()).unwrap(),
            }
        }
    }
}

/// Files 0600, directories 0700.
fn default_modes(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            default_modes(&p);
        } else {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

/// From every canary in `text`: the canary and what follows it up to the
/// first character that cannot be part of a token.
fn canary_tokens(text: &str) -> Vec<String> {
    text.match_indices(CANARY)
        .map(|(i, _)| {
            text[i..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || "_-.+/=".contains(*c))
                .collect()
        })
        .collect()
}

/// Secret strings that must not appear in any output.
fn secrets(root: &Path, spec_env: &BTreeMap<String, String>) -> Vec<String> {
    // Token prefixes are public (the `prefix` attribute); only the rest is
    // secret.
    let secret_part = |v: &str| v.strip_prefix("github_pat_").unwrap_or(v).to_string();
    let mut out: Vec<String> = spec_env
        .values()
        .filter(|v| v.contains(CANARY))
        .map(|v| secret_part(v))
        .collect();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            let meta = fs::symlink_metadata(&p).unwrap();
            if meta.is_dir() {
                stack.push(p);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            if name.starts_with("dummy_") && !name.ends_with(".pub") {
                out.extend(
                    text.lines()
                        .filter(|l| l.len() >= 8 && !l.starts_with("-----") && !l.contains(':'))
                        .map(str::to_string),
                );
            } else if name.starts_with(".env") {
                out.extend(
                    text.lines()
                        .filter_map(|l| l.split_once('=').map(|(_, v)| secret_part(v)))
                        .filter(|v| v.contains(CANARY)),
                );
            }
            out.extend(canary_tokens(&text));
        }
    }
    out
}

/// Removes `keys` from every object in `v`.
fn strip_keys(v: &mut Value, keys: &[&str]) {
    match v {
        Value::Object(map) => {
            for k in keys {
                map.remove(*k);
            }
            for child in map.values_mut() {
                strip_keys(child, keys);
            }
        }
        Value::Array(items) => {
            for child in items {
                strip_keys(child, keys);
            }
        }
        _ => {}
    }
}

/// The `env_var` fact of `HOME` (a random temp path) has no stable entropy.
fn strip_home_entropy(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let is_home = map
                .get("location")
                .is_some_and(|l| l["kind"] == "env" && l["name"] == "HOME");
            if is_home && let Some(Value::Object(attrs)) = map.get_mut("attrs") {
                attrs.remove("entropy");
            }
            for child in map.values_mut() {
                strip_home_entropy(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_home_entropy),
        _ => {}
    }
}

struct Outcome {
    actual: String,
    problems: Vec<String>,
}

fn run_env(env_dir: &Path) -> Outcome {
    let spec: EnvSpec = toml::from_str(&fs::read_to_string(env_dir.join("env.toml")).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", env_dir.display()));
    let tmp = tempfile::tempdir().unwrap();
    // Canonical, so the working directory the binary sees (getcwd) and HOME
    // agree (macOS: /var → /private/var).
    let root = fs::canonicalize(tmp.path()).unwrap();
    let home = root.join("home");
    for dir in ["home", "workdir"] {
        if env_dir.join(dir).is_dir() {
            copy_tree(&env_dir.join(dir), &root.join(dir));
        }
    }
    fs::create_dir_all(&home).unwrap();
    for (from, to) in &spec.rename {
        fs::rename(root.join(from), root.join(to)).unwrap();
    }
    for dir in &spec.git {
        fs::create_dir_all(root.join(dir).join(".git")).unwrap();
        fs::write(root.join(dir).join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }
    default_modes(&root);
    let mut listeners = Vec::new();
    for s in &spec.sockets {
        let path = root.join(s);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        listeners.push(UnixListener::bind(&path).unwrap());
    }
    for (path, mode) in &spec.modes {
        let mode = u32::from_str_radix(mode, 8).unwrap();
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    let env: BTreeMap<String, String> = spec
        .env
        .iter()
        .map(|(k, v)| (k.clone(), expand(v)))
        .collect();

    let cwd = if root.join("workdir").is_dir() {
        root.join("workdir")
    } else {
        home.clone()
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lootr"));
    cmd.arg("--config").arg(test_envs().join("common.toml"));
    if env_dir.join("lootr.toml").is_file() {
        cmd.arg("--config").arg(env_dir.join("lootr.toml"));
    }
    cmd.arg("--emit-facts")
        .args(&spec.args)
        .env_clear()
        .env("HOME", &home)
        .envs(&env)
        .current_dir(&cwd);
    let output = cmd.output().unwrap();
    drop(listeners);

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let mut problems = Vec::new();
    let mut secrets = secrets(&root, &env);
    secrets.extend(spec.secrets.iter().map(|s| expand(s)));
    let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
    for (what, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        for leak in find_leaks(text, &secret_refs) {
            problems.push(format!("{what}: {leak}"));
        }
    }

    let mut report: Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("no JSON report ({e}); stderr:\n{stderr}"));
            return Outcome {
                actual: String::new(),
                problems,
            };
        }
    };
    for (section, key) in [
        ("run", "started_at"),
        ("run", "duration_ms"),
        ("run", "uid"),
        ("tool", "version"),
    ] {
        if let Some(obj) = report[section].as_object_mut() {
            obj.remove(key);
        }
    }
    let mut keys = vec!["age_days", "expires_in_hours", "expires_in_days"];
    keys.extend(spec.ignore_attrs.iter().map(String::as_str));
    strip_keys(&mut report, &keys);
    strip_home_entropy(&mut report);
    let doc = serde_json::json!({
        "exit_code": output.status.code(),
        "report": report,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let actual = text.replace(&*root.to_string_lossy(), "<root>");
    Outcome { actual, problems }
}

#[test]
fn every_test_environment_matches_its_expected_report() {
    let mut envs = Vec::new();
    find_envs(&test_envs(), &mut envs);
    assert!(
        envs.len() >= 24,
        "found only {} test environments",
        envs.len()
    );
    let update = std::env::var_os(UPDATE_VAR).is_some_and(|v| v == "1");
    let mut failures = Vec::new();
    for env_dir in &envs {
        let name = env_dir
            .strip_prefix(test_envs())
            .unwrap()
            .display()
            .to_string();
        let outcome = run_env(env_dir);
        for p in &outcome.problems {
            failures.push(format!("{name}: {p}"));
        }
        let expected_path = env_dir.join("expected.json");
        if update {
            fs::write(&expected_path, &outcome.actual).unwrap();
            continue;
        }
        let expected = fs::read_to_string(&expected_path).unwrap_or_default();
        if expected != outcome.actual {
            let diff: Vec<String> = expected
                .lines()
                .zip(outcome.actual.lines())
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .take(5)
                .map(|(i, (a, b))| format!("  line {}:\n  - {a}\n  + {b}", i + 1))
                .collect();
            failures.push(format!(
                "{name}: report differs from expected.json ({} vs {} lines; \
                 {UPDATE_VAR}=1 rewrites it)\n{}",
                expected.lines().count(),
                outcome.actual.lines().count(),
                diff.join("\n")
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
