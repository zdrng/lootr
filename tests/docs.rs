//! Generated documentation stays in sync with the binary.
//!
//! `docs/types.json` is the exact output of `lootr types --json` with only
//! the built-in default config. The binary runs with an empty environment,
//! `HOME` and the working directory in temp dirs (never against the
//! developer's real home), so the output depends on nothing but the code.
//!
//! `LOOTR_UPDATE_DOCS=1 cargo test --test docs` rewrites the file; review
//! the diff before committing.

// Test code: the harness starts the binary under test (lootr itself never
// does) and may panic on setup errors.
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::unwrap_used
)]

use std::path::Path;
use std::process::Command;

const UPDATE_VAR: &str = "LOOTR_UPDATE_DOCS";

/// `lootr types --json` with the built-in default config only.
fn types_json() -> String {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lootr"))
        .args(["types", "--json"])
        .env_clear()
        .env("HOME", home.path())
        .current_dir(cwd.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "lootr types --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn types_json_is_up_to_date() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/types.json");
    let actual = types_json();
    assert_eq!(
        actual,
        types_json(),
        "lootr types --json is not deterministic"
    );
    if std::env::var_os(UPDATE_VAR).is_some_and(|v| v == "1") {
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        actual == expected,
        "{} is out of date with `lootr types --json`; regenerate it with \
         `{UPDATE_VAR}=1 cargo test --test docs` and review the diff",
        path.display()
    );
}
