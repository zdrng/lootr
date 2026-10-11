//! Checks the GitHub Action and the CI files (no network, plain text):
//!
//! - every `uses:` is pinned by a full commit SHA (40 hex characters); the
//!   only exceptions are all-zero placeholders: lootr's own action in
//!   `examples/ci/` (marked TODO) and third-party actions whose SHA still has
//!   to be filled in before the first release (marked `TODO(pin)`, listed by
//!   `pin_placeholders_are_listed`);
//! - `action.yml` never puts `${{ ... }}` into a `run:` script (inputs reach
//!   scripts through `env:` only, so they cannot inject shell code).

// Test code: reads the repository's files directly and may panic.
#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn ci_files() -> Vec<PathBuf> {
    let mut files = vec![root().join("action.yml")];
    for dir in [".github/workflows", "examples/ci"] {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
            .collect();
        entries.sort();
        files.extend(entries);
    }
    files
}

#[test]
fn actions_are_pinned_by_commit_sha() {
    let placeholder = "OWNER/lootr@0000000000000000000000000000000000000000";
    let mut problems = Vec::new();
    let mut seen = 0;
    for file in ci_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let Some(rest) = line
                .trim_start()
                .trim_start_matches("- ")
                .strip_prefix("uses:")
            else {
                continue;
            };
            seen += 1;
            let target = rest.split_whitespace().next().unwrap_or("");
            let at = format!("{}:{}", file.display(), n + 1);
            if target.starts_with("./") {
                continue;
            }
            if target == placeholder {
                if !line.contains("TODO") {
                    problems.push(format!("{at}: placeholder without TODO"));
                }
                continue;
            }
            if target.ends_with(ZERO_SHA) {
                if !line.contains("TODO(pin)") {
                    problems.push(format!("{at}: zero SHA without `TODO(pin)`"));
                }
                continue;
            }
            let sha = target.rsplit_once('@').map(|(_, s)| s).unwrap_or("");
            let pinned = sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit());
            if !pinned {
                problems.push(format!("{at}: `{target}` is not pinned by commit SHA"));
            }
            if !line.contains(" # ") {
                problems.push(format!("{at}: add the version as a comment (`# vX.Y.Z`)"));
            }
        }
    }
    assert!(seen >= 5, "found only {seen} `uses:` lines");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

const ZERO_SHA: &str = "@0000000000000000000000000000000000000000";

/// Third-party actions still waiting for a verified commit SHA. They make
/// the workflows that use them fail on GitHub until they are filled in; this
/// list must shrink to empty before the first release tag.
#[test]
fn pin_placeholders_are_listed() {
    let expected = [
        "actions/attest-build-provenance",
        "actions/download-artifact",
        "actions/upload-artifact",
    ];
    let mut found = std::collections::BTreeSet::new();
    for file in ci_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        for line in text.lines().filter(|l| l.contains("TODO(pin)")) {
            if let Some(target) = line.split_whitespace().find(|w| w.ends_with(ZERO_SHA)) {
                found.insert(target.trim_end_matches(ZERO_SHA).to_string());
            }
        }
    }
    let found: Vec<_> = found.into_iter().collect();
    assert_eq!(
        found, expected,
        "update this list and the TODO(pin) note in PLAN.md (M7)"
    );
}

#[test]
fn action_scripts_take_inputs_from_env_only() {
    let text = std::fs::read_to_string(root().join("action.yml")).unwrap();
    let mut run_indent: Option<usize> = None;
    let mut problems = Vec::new();
    let mut scripts = 0;
    for (n, line) in text.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        if let Some(i) = run_indent {
            if line.trim().is_empty() || indent > i {
                if line.contains("${{") {
                    problems.push(format!("action.yml:{}: `${{{{` in a script", n + 1));
                }
                continue;
            }
            run_indent = None;
        }
        let key = line.trim_start().trim_start_matches("- ");
        if key.starts_with("run:") {
            if key.contains("${{") {
                problems.push(format!("action.yml:{}: `${{{{` in a script", n + 1));
            }
            run_indent = Some(indent);
            scripts += 1;
        }
    }
    assert_eq!(scripts, 4, "run: blocks in action.yml");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(text.contains("using: composite"));
}

/// The release contract ("Release artifacts" in PLAN.md): the targets the
/// release workflow builds are exactly the ones action.yml downloads, and the
/// workflow file is the signer action.yml verifies.
#[test]
fn release_workflow_matches_action() {
    let action = std::fs::read_to_string(root().join("action.yml")).unwrap();
    let release = std::fs::read_to_string(root().join(".github/workflows/release.yml")).unwrap();
    let mut from_action: Vec<&str> = action
        .lines()
        .filter_map(|l| l.split("target=").nth(1))
        .map(|t| t.split_whitespace().next().unwrap_or(""))
        .collect();
    let mut from_release: Vec<&str> = release
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- target: "))
        .collect();
    from_action.sort();
    from_action.dedup();
    from_release.sort();
    let expected = [
        "aarch64-unknown-linux-musl",
        "universal-apple-darwin",
        "x86_64-unknown-linux-musl",
    ];
    assert_eq!(from_action, expected);
    assert_eq!(from_release, expected);
    assert!(action.contains(r#"workflow="$LOOTR_REPOSITORY/.github/workflows/release.yml""#));
    for asset in [
        "lootr-$VERSION-x86_64-unknown-linux-musl.tar.gz.sigstore.json",
        "lootr-$VERSION.cdx.json.sigstore.json",
        "SHA256SUMS",
    ] {
        assert!(
            release.contains(asset),
            "release.yml does not produce {asset}"
        );
    }
}
