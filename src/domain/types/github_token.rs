//! `github_token`: GitHub tokens recognized by their prefix.
//!
//! | prefix | kind |
//! |---|---|
//! | `ghp_` | `classic` (personal access token) |
//! | `github_pat_` | `fine_grained` (personal access token) |
//! | `gho_` | `oauth` (OAuth app user token) |
//! | `ghu_` | `app` (GitHub App user-to-server token) |
//! | `ghs_` | `app` (GitHub App installation token, e.g. Actions `GITHUB_TOKEN`) |
//! | `ghr_` | `refresh` (GitHub App refresh token) |
//!
//! `gh?_` tokens of the standard length (4 + 36 characters) end in a
//! checksum: the last 6 characters are the CRC32 of the 30 random characters
//! before them, base62 encoded (`0-9A-Za-z`) and zero padded. A valid
//! checksum tells a real token from an example or a typo; it says nothing
//! about whether the token is still active (lootr never asks GitHub).
//! Fine-grained tokens and non-standard lengths carry no `checksum_valid`.
//!
//! Nothing derived from the random part is emitted: only the kind, the
//! prefix and whether the checksum matches.

use crate::domain::codec::{base62_6, crc32};
use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, ValueType};

pub const NAME: &str = "github_token";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "classic | fine_grained | oauth | app | refresh",
    ),
    AttrSpec::new(
        "prefix",
        AttrKind::Sym,
        "ghp_ | github_pat_ | gho_ | ghu_ | ghs_ | ghr_",
    ),
    AttrSpec::optional(
        "checksum_valid",
        AttrKind::Bool,
        "the built-in CRC32 checksum matches (gh?_ tokens of standard length only)",
    ),
];

const PREFIXES: &[(&str, &str)] = &[
    ("ghp_", "classic"),
    ("gho_", "oauth"),
    ("ghu_", "app"),
    ("ghs_", "app"),
    ("ghr_", "refresh"),
    ("github_pat_", "fine_grained"),
];

/// Random part + checksum of a standard `gh?_` token.
const STANDARD_BODY: usize = 36;
const CHECKSUM: usize = 6;
const MAX_LEN: usize = 255;

pub struct GithubToken;

impl ValueType for GithubToken {
    fn name(&self) -> &str {
        NAME
    }

    fn doc(&self) -> &str {
        "a GitHub token (personal, fine-grained, OAuth, App, refresh), recognized by prefix and checksum"
    }

    fn schema(&self) -> &[AttrSpec] {
        ATTRS
    }

    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
        let bytes = value.expose();
        if bytes.len() > MAX_LEN {
            return None;
        }
        let (prefix, kind) = PREFIXES
            .iter()
            .find(|(p, _)| bytes.starts_with(p.as_bytes()))?;
        let body = &bytes[prefix.len()..];
        let mut attrs = Attrs::new();
        if *kind == "fine_grained" {
            // github_pat_<22>_<59>: base62 and one underscore.
            let ok =
                body.len() >= 70 && body.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                return None;
            }
        } else {
            if body.len() < STANDARD_BODY || !body.iter().all(u8::is_ascii_alphanumeric) {
                return None;
            }
            if body.len() == STANDARD_BODY {
                attrs.insert("checksum_valid", AttrValue::Bool(checksum_valid(body)));
            }
        }
        attrs.insert("kind", AttrValue::Sym(kind));
        attrs.insert("prefix", AttrValue::Sym(prefix));
        Some(attrs)
    }
}

/// `body` = 30 random characters + 6 checksum characters.
fn checksum_valid(body: &[u8]) -> bool {
    let (random, checksum) = body.split_at(body.len() - CHECKSUM);
    base62_6(crc32(random)) == checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::github_token as with_checksum;

    fn classify(s: &str) -> Option<Attrs> {
        GithubToken.classify(SecretSlice::new(s.as_bytes()))
    }

    const RANDOM: &str = "LOOTRCANARYdummy0123456789abcd";

    #[test]
    fn standard_tokens_and_checksums() {
        let token = with_checksum("ghp_", RANDOM);
        assert_eq!(token.len(), 40);
        let a = classify(&token).unwrap();
        assert_eq!(a["kind"], AttrValue::Sym("classic"));
        assert_eq!(a["prefix"], AttrValue::Sym("ghp_"));
        assert_eq!(a["checksum_valid"], AttrValue::Bool(true));
        assert!(!format!("{a:?}").contains("LOOTRCANARY"));

        let mut broken = token.clone();
        broken.replace_range(10..11, "x");
        assert_eq!(
            classify(&broken).unwrap()["checksum_valid"],
            AttrValue::Bool(false)
        );

        for (prefix, kind) in [
            ("gho_", "oauth"),
            ("ghu_", "app"),
            ("ghs_", "app"),
            ("ghr_", "refresh"),
        ] {
            let a = classify(&with_checksum(prefix, RANDOM)).unwrap();
            assert_eq!(a["kind"], AttrValue::Sym(kind));
            assert_eq!(a["checksum_valid"], AttrValue::Bool(true));
        }
    }

    #[test]
    fn longer_tokens_have_no_checksum_attribute() {
        let long = format!("ghs_{}", "a".repeat(80));
        let a = classify(&long).unwrap();
        assert!(!a.contains_key("checksum_valid"));
    }

    #[test]
    fn fine_grained_tokens() {
        let token = format!("github_pat_{}_{}", "A".repeat(22), "b".repeat(59));
        let a = classify(&token).unwrap();
        assert_eq!(a["kind"], AttrValue::Sym("fine_grained"));
        assert!(!a.contains_key("checksum_valid"));
        assert!(classify("github_pat_short").is_none());
    }

    #[test]
    fn rejects_other_values() {
        assert!(classify("ghp_short").is_none());
        assert!(classify(&format!("ghp_{}-", "a".repeat(36))).is_none());
        assert!(classify(&format!(" ghp_{}", "a".repeat(36))).is_none());
        assert!(classify("ghx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none());
        assert!(classify(&format!("ghp_{}", "a".repeat(300))).is_none());
        assert!(classify("").is_none());
    }
}
