//! AWS: the `aws_credentials` document type (`~/.aws/credentials` and
//! `~/.aws/config`, both INI) and the `aws_access_key_id` value type.
//!
//! Access key ids are `AKIA` (long-lived IAM user keys) or `ASIA`
//! (temporary STS session keys) followed by 16 characters of `[A-Z2-7]`.
//!
//! `aws_credentials` emits one fact per file with counts per profile kind
//! and the profile names; the key id, secret key and session token of each
//! profile are emitted as nested values (so `aws_access_key_id` facts appear
//! for them, at `<profile>.aws_access_key_id`). A `credential_process` is
//! only counted: lootr never runs it and does not report the command.
//! SSO profiles reference `sso_session` or `sso_start_url`.

use std::collections::BTreeSet;

use crate::domain::format::{ini, is_text};
use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{key_path, texts};
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError, ValueType};

pub const KEY_ID: &str = "aws_access_key_id";
pub const CREDENTIALS: &str = "aws_credentials";

pub const KEY_ID_ATTRS: &[AttrSpec] = &[AttrSpec::new(
    "kind",
    AttrKind::Sym,
    "long_lived (AKIA, IAM user key) | session (ASIA, temporary STS credentials)",
)];

/// `long_lived` / `session` for an access key id.
fn key_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() != 20 {
        return None;
    }
    let kind = match &bytes[..4] {
        b"AKIA" => "long_lived",
        b"ASIA" => "session",
        _ => return None,
    };
    bytes[4..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        .then_some(kind)
}

pub struct AwsAccessKeyId;

impl ValueType for AwsAccessKeyId {
    fn name(&self) -> &str {
        KEY_ID
    }

    fn doc(&self) -> &str {
        "an AWS access key id (AKIA long-lived, ASIA session)"
    }

    fn schema(&self) -> &[AttrSpec] {
        KEY_ID_ATTRS
    }

    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
        let kind = key_kind(value.expose())?;
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym(kind));
        Some(attrs)
    }
}

pub const CREDENTIALS_ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "profiles",
        AttrKind::List,
        "profile names (text; `[profile x]` in config is `x`)",
    ),
    AttrSpec::new(
        "long_lived_keys",
        AttrKind::Int,
        "profiles with a long-lived access key id (AKIA)",
    ),
    AttrSpec::new(
        "session_keys",
        AttrKind::Int,
        "profiles with temporary session credentials (ASIA)",
    ),
    AttrSpec::new(
        "secret_keys",
        AttrKind::Int,
        "profiles with an aws_secret_access_key",
    ),
    AttrSpec::new(
        "sso_profiles",
        AttrKind::Int,
        "profiles that use IAM Identity Center (sso_session / sso_start_url)",
    ),
    AttrSpec::new(
        "role_profiles",
        AttrKind::Int,
        "profiles that assume a role (role_arn)",
    ),
    AttrSpec::new(
        "credential_process",
        AttrKind::Int,
        "profiles with a credential_process (an external program; never run)",
    ),
];

/// Values passed on to the value types.
const SECRET_KEYS: &[&str] = &[
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "aws_security_token",
];

pub struct AwsCredentials;

#[derive(Default)]
struct Profile {
    key_kind: Option<&'static str>,
    secret: bool,
    sso: bool,
    role: bool,
    process: bool,
}

impl DocumentType for AwsCredentials {
    fn name(&self) -> &'static str {
        CREDENTIALS
    }

    fn doc(&self) -> &'static str {
        "AWS shared credentials or config file (profiles, key kinds, SSO, credential_process)"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        CREDENTIALS_ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let entries = ini::parse(doc);
        if entries.is_empty() {
            return Ok(());
        }
        // Profile name → what it has, in file order.
        let mut profiles: Vec<(String, Profile)> = Vec::new();
        for e in entries {
            let Some(name) = e.section.and_then(profile_name) else {
                continue;
            };
            let idx = match profiles.iter().position(|(n, _)| n == name) {
                Some(i) => i,
                None => {
                    profiles.push((name.to_string(), Profile::default()));
                    profiles.len() - 1
                }
            };
            let p = &mut profiles[idx].1;
            let key = e.key.as_ref();
            let set = !e.is_empty();
            match key {
                "aws_access_key_id" if set => p.key_kind = key_kind(e.value.expose()),
                "aws_secret_access_key" if set => p.secret = true,
                "sso_session" | "sso_start_url" if set => p.sso = true,
                "role_arn" if set => p.role = true,
                "credential_process" if set => p.process = true,
                _ => {}
            }
            if set && SECRET_KEYS.contains(&key) {
                out.value(key_path(&[name, key]), e.value);
            }
        }
        let count = |f: fn(&Profile) -> bool| {
            AttrValue::Int(profiles.iter().filter(|(_, p)| f(p)).count() as i64)
        };
        let mut attrs = Attrs::new();
        let names: BTreeSet<String> = profiles.iter().map(|(n, _)| n.clone()).collect();
        attrs.insert("profiles", texts(names.iter()));
        attrs.insert(
            "long_lived_keys",
            count(|p| p.key_kind == Some("long_lived")),
        );
        attrs.insert("session_keys", count(|p| p.key_kind == Some("session")));
        attrs.insert("secret_keys", count(|p| p.secret));
        attrs.insert("sso_profiles", count(|p| p.sso));
        attrs.insert("role_profiles", count(|p| p.role));
        attrs.insert("credential_process", count(|p| p.process));
        out.fact(attrs);
        Ok(())
    }
}

/// The profile a section defines: `default`, `x` for `[x]` (credentials)
/// and `[profile x]` (config). `sso-session`, `services` and other
/// sections with a space are not profiles.
fn profile_name(section: &str) -> Option<&str> {
    if let Some(name) = section.strip_prefix("profile ") {
        let name = name.trim();
        return (!name.is_empty()).then_some(name);
    }
    (!section.is_empty() && !section.contains(char::is_whitespace)).then_some(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::NestedValue;
    use crate::testing::CANARY;

    #[test]
    fn access_key_ids() {
        let k = |s: &str| {
            AwsAccessKeyId
                .classify(SecretSlice::new(s.as_bytes()))
                .map(|a| a["kind"].to_string())
        };
        assert_eq!(k("AKIALOOTRCANARY23456").as_deref(), Some("long_lived"));
        assert_eq!(k("ASIALOOTRCANARY23456").as_deref(), Some("session"));
        assert!(k("AKIALOOTRCANARY23451").is_none()); // 1 is not base32
        assert!(k("AKIAlootrcanary23456").is_none());
        assert!(k("AIDALOOTRCANARY23456").is_none());
        assert!(k("AKIALOOTRCANARY234567").is_none());
    }

    #[test]
    fn credentials_and_config() {
        let text = format!(
            "[default]\naws_access_key_id = AKIALOOTRCANARY23456\naws_secret_access_key = {CANARY}/secret\n\
             [temp]\naws_access_key_id=ASIALOOTRCANARY23456\naws_secret_access_key={CANARY}x\naws_session_token={CANARY}tok\n\
             [profile sso]\nsso_session = corp\nregion = eu-west-1\n\
             [sso-session corp]\nsso_start_url = https://corp.awsapps.example/start\n\
             [profile ops]\nrole_arn = arn:aws:iam::123456789012:role/ops\nsource_profile = default\n\
             [profile tool]\ncredential_process = /usr/bin/helper --{CANARY}\n"
        );
        let mut out = Emitter::default();
        AwsCredentials
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        assert_eq!(out.facts.len(), 1);
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["profiles"].to_string(), "default, ops, sso, temp, tool");
        assert_eq!(a["long_lived_keys"], AttrValue::Int(1));
        assert_eq!(a["session_keys"], AttrValue::Int(1));
        assert_eq!(a["secret_keys"], AttrValue::Int(2));
        assert_eq!(a["sso_profiles"], AttrValue::Int(1));
        assert_eq!(a["role_profiles"], AttrValue::Int(1));
        assert_eq!(a["credential_process"], AttrValue::Int(1));
        let paths: Vec<String> = out.values.iter().map(|(p, _)| p.to_string()).collect();
        assert_eq!(
            paths,
            [
                "default.aws_access_key_id",
                "default.aws_secret_access_key",
                "temp.aws_access_key_id",
                "temp.aws_secret_access_key",
                "temp.aws_session_token"
            ]
        );
        assert!(matches!(out.values[0].1, NestedValue::Borrowed(_)));
    }

    #[test]
    fn empty_files_have_no_fact() {
        let mut out = Emitter::default();
        AwsCredentials
            .parse(SecretSlice::new(b"# nothing\n"), &mut out)
            .unwrap();
        assert!(out.facts.is_empty());
    }
}
