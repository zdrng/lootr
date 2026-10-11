//! Canary test harness: helpers that prove no secret reaches any output.
//!
//! Every dummy secret in test environments and container scenarios contains
//! [`CANARY`] where the format allows it. [`find_leaks`] checks an output
//! (report in every format, `--emit-facts`, stderr) for the canary and for
//! any substring of [`MIN_LEAK_LEN`] or more characters of the dummy
//! secrets themselves. Used by unit tests (`service::scan` tests),
//! `tests/canary.rs`, `tests/fixtures.rs` and `containers/run.sh`
//! (which greps for the canary).

/// Marker in every dummy secret. Never appears in lootr's own strings.
pub const CANARY: &str = "LOOTRCANARY";

/// Shortest secret substring that counts as a leak.
pub const MIN_LEAK_LEN: usize = 8;

/// Describes every leak of `secrets` (or [`CANARY`]) in `output`.
pub fn find_leaks(output: &str, secrets: &[&str]) -> Vec<String> {
    let mut leaks = Vec::new();
    if output.contains(CANARY) {
        leaks.push(format!("canary `{CANARY}` found in output"));
    }
    for secret in secrets {
        let bytes = secret.as_bytes();
        if bytes.len() < MIN_LEAK_LEN {
            leaks.push(format!(
                "dummy secret shorter than {MIN_LEAK_LEN} bytes cannot be checked"
            ));
            continue;
        }
        let leaked = bytes
            .windows(MIN_LEAK_LEN)
            .filter_map(|w| std::str::from_utf8(w).ok())
            .find(|w| output.contains(w));
        if let Some(w) = leaked {
            leaks.push(format!("substring `{w}` of a dummy secret found in output"));
        }
    }
    leaks
}

/// A dummy GitHub token with a valid checksum: `prefix` (`ghp_`, `ghs_`,
/// ...) + `random` + the base62 CRC32 of `random` (see
/// `domain::types::github_token`). `random` should be 30 base62 characters
/// containing [`CANARY`]. Test environments use `{{github_token:<prefix>:<random>}}`
/// placeholders that the fixture harness expands with this function, so no
/// token with a valid checksum is committed (they would trip secret
/// scanners); container scenarios compute the same checksum in shell
/// (`containers/base/gen-github-token`).
pub fn github_token(prefix: &str, random: &str) -> String {
    use crate::domain::codec::{base62_6, crc32};
    let checksum = base62_6(crc32(random.as_bytes()));
    format!("{prefix}{random}{}", String::from_utf8_lossy(&checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_canary_and_substrings() {
        assert!(find_leaks("nothing here", &["abcdefghij"]).is_empty());
        assert_eq!(find_leaks("x LOOTRCANARY y", &[]).len(), 1);
        assert_eq!(find_leaks("...cdefghij...", &["abcdefghij"]).len(), 1);
        assert!(find_leaks("...cdefghi...", &["abcdefghij"]).is_empty());
        assert_eq!(find_leaks("", &["short"]).len(), 1);
    }
}
