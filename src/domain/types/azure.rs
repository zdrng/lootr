//! `azure_profile`: the Azure CLI's JSON files in `~/.azure`:
//!
//! - `azureProfile.json` (`kind = "profile"`): subscriptions, no secrets;
//! - `msal_token_cache.json` (`msal_token_cache`): MSAL's cache with
//!   `AccessToken`, `RefreshToken` and `IdToken` sections; every `secret` is
//!   emitted as a nested value (access and ID tokens are JWTs);
//! - `accessTokens.json` (`legacy_token_cache`, Azure CLI before 2.30): a
//!   list of entries with `accessToken` / `refreshToken`;
//! - `service_principal_entries.json` (`service_principals`): service
//!   principal secrets (`client_secret`, or `accessToken` in old versions).
//!
//! The CLI writes some of these files with a UTF-8 byte order mark. Account
//! names, tenants and cache keys are not reported; nested values are keyed
//! by section and position (`RefreshToken.0`).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::domain::format::json::{self, PlainText, SecretValue};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "azure_profile";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "profile | msal_token_cache | legacy_token_cache | service_principals",
    ),
    AttrSpec::new(
        "has_cached_tokens",
        AttrKind::Bool,
        "the file holds access or refresh tokens",
    ),
    AttrSpec::new("access_tokens", AttrKind::Int, "cached access tokens"),
    AttrSpec::new("refresh_tokens", AttrKind::Int, "cached refresh tokens"),
    AttrSpec::new(
        "service_principal_secrets",
        AttrKind::Int,
        "stored service principal secrets",
    ),
    AttrSpec::new(
        "subscriptions",
        AttrKind::Int,
        "subscriptions in azureProfile.json",
    ),
];

#[derive(Deserialize)]
struct Profile {
    subscriptions: Vec<IgnoredAny>,
}

#[derive(Deserialize)]
struct CacheEntry<'a> {
    #[serde(borrow, default)]
    secret: SecretValue<'a>,
}

#[derive(Deserialize)]
struct Msal<'a> {
    #[serde(rename = "AccessToken", borrow, default)]
    access: BTreeMap<String, CacheEntry<'a>>,
    #[serde(rename = "RefreshToken", borrow, default)]
    refresh: BTreeMap<String, CacheEntry<'a>>,
    #[serde(rename = "IdToken", borrow, default)]
    id: BTreeMap<String, CacheEntry<'a>>,
}

#[derive(Deserialize)]
struct LegacyEntry<'a> {
    #[serde(rename = "accessToken", borrow, default)]
    access_token: SecretValue<'a>,
    #[serde(rename = "refreshToken", borrow, default)]
    refresh_token: SecretValue<'a>,
    #[serde(borrow, default)]
    client_secret: SecretValue<'a>,
    #[serde(rename = "servicePrincipalId", default)]
    service_principal_id: PlainText,
    #[serde(default)]
    client_id: PlainText,
}

/// The top-level keys that identify the file.
#[derive(Deserialize)]
struct Keys {
    #[serde(default)]
    subscriptions: Option<IgnoredAny>,
    #[serde(rename = "AccessToken", default)]
    access: Option<IgnoredAny>,
    #[serde(rename = "RefreshToken", default)]
    refresh: Option<IgnoredAny>,
    #[serde(rename = "IdToken", default)]
    id: Option<IgnoredAny>,
}

#[derive(Default)]
struct Counts {
    access: i64,
    refresh: i64,
    sp: i64,
    subscriptions: i64,
}

pub struct AzureProfile;

impl DocumentType for AzureProfile {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "an Azure CLI file in ~/.azure (profile, MSAL token cache, legacy token cache, service principals)"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        matches!(json::first_byte(head), Some(b'{' | b'['))
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let mut c = Counts::default();
        let emit = |out: &mut Emitter<'a>, path: String, v: SecretValue<'a>| {
            if let Some(v) = v.nested() {
                out.nested(PublicText::from_non_secret(&path), v);
                true
            } else {
                false
            }
        };
        let kind = if json::first_byte(doc.expose()) == Some(b'[') {
            let entries: Vec<LegacyEntry<'a>> = json::parse(doc)?;
            let mut principals = false;
            for (i, e) in entries.into_iter().enumerate() {
                let is_sp =
                    e.service_principal_id.as_deref().is_some() || e.client_id.as_deref().is_some();
                if is_sp {
                    principals = true;
                    let secret = if e.client_secret.is_set() {
                        e.client_secret
                    } else {
                        e.access_token
                    };
                    if emit(out, format!("{i}.secret"), secret) {
                        c.sp += 1;
                    }
                    continue;
                }
                if emit(out, format!("{i}.accessToken"), e.access_token) {
                    c.access += 1;
                }
                if emit(out, format!("{i}.refreshToken"), e.refresh_token) {
                    c.refresh += 1;
                }
            }
            if principals {
                "service_principals"
            } else {
                "legacy_token_cache"
            }
        } else {
            let keys: Keys = json::parse(doc)?;
            if keys.subscriptions.is_some() {
                let p: Profile = json::parse(doc)?;
                c.subscriptions = p.subscriptions.len() as i64;
                "profile"
            } else if keys.access.is_some() || keys.refresh.is_some() || keys.id.is_some() {
                let m: Msal<'a> = json::parse(doc)?;
                for (section, entries, count) in [
                    ("AccessToken", m.access, Some(&mut c.access)),
                    ("RefreshToken", m.refresh, Some(&mut c.refresh)),
                    ("IdToken", m.id, None),
                ] {
                    let mut n = 0;
                    for (i, (_, e)) in entries.into_iter().enumerate() {
                        if emit(out, format!("{section}.{i}"), e.secret) {
                            n += 1;
                        }
                    }
                    if let Some(count) = count {
                        *count = n;
                    }
                }
                "msal_token_cache"
            } else {
                return Ok(());
            }
        };
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym(kind));
        attrs.insert(
            "has_cached_tokens",
            AttrValue::Bool(c.access + c.refresh > 0),
        );
        attrs.insert("access_tokens", AttrValue::Int(c.access));
        attrs.insert("refresh_tokens", AttrValue::Int(c.refresh));
        attrs.insert("service_principal_secrets", AttrValue::Int(c.sp));
        attrs.insert("subscriptions", AttrValue::Int(c.subscriptions));
        out.fact(attrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn parse(text: &str) -> (Attrs, Vec<String>) {
        let mut out = Emitter::default();
        AzureProfile
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let attrs = out.facts.pop().map(|f| f.1).unwrap_or_default();
        assert!(!format!("{attrs:?}").contains(CANARY));
        (
            attrs,
            out.values.iter().map(|(k, _)| k.to_string()).collect(),
        )
    }

    #[test]
    fn profile() {
        let (a, v) = parse(
            "\u{feff}{\"installationId\":\"x\",\"subscriptions\":[{\"id\":\"1\",\"user\":{\"name\":\"dev@example.com\"}},{}]}",
        );
        assert_eq!(a["kind"], AttrValue::Sym("profile"));
        assert_eq!(a["subscriptions"], AttrValue::Int(2));
        assert_eq!(a["has_cached_tokens"], AttrValue::Bool(false));
        assert!(v.is_empty());
    }

    #[test]
    fn msal_cache() {
        let text = format!(
            r#"{{"Account":{{"k":{{"username":"dev@example.com"}}}},
               "AccessToken":{{"k1":{{"credential_type":"AccessToken","secret":"{CANARY}a"}},"k2":{{"secret":"{CANARY}b"}}}},
               "RefreshToken":{{"k3":{{"secret":"{CANARY}r"}}}},
               "IdToken":{{"k4":{{"secret":"{CANARY}i"}}}},"AppMetadata":{{}}}}"#
        );
        let (a, v) = parse(&text);
        assert_eq!(a["kind"], AttrValue::Sym("msal_token_cache"));
        assert_eq!(a["access_tokens"], AttrValue::Int(2));
        assert_eq!(a["refresh_tokens"], AttrValue::Int(1));
        assert_eq!(a["has_cached_tokens"], AttrValue::Bool(true));
        assert_eq!(
            v,
            [
                "AccessToken.0",
                "AccessToken.1",
                "RefreshToken.0",
                "IdToken.0"
            ]
        );
    }

    #[test]
    fn legacy_caches_and_service_principals() {
        let text =
            format!(r#"[{{"accessToken":"{CANARY}a","refreshToken":"{CANARY}r","userId":"u"}}]"#);
        let (a, v) = parse(&text);
        assert_eq!(a["kind"], AttrValue::Sym("legacy_token_cache"));
        assert_eq!(v, ["0.accessToken", "0.refreshToken"]);
        let text = format!(
            r#"[{{"client_id":"c","tenant":"t","client_secret":"{CANARY}s"}},{{"servicePrincipalId":"p","accessToken":"{CANARY}o"}},{{"client_id":"c","certificate":"/x.pem"}}]"#
        );
        let (a, v) = parse(&text);
        assert_eq!(a["kind"], AttrValue::Sym("service_principals"));
        assert_eq!(a["service_principal_secrets"], AttrValue::Int(2));
        assert_eq!(v, ["0.secret", "1.secret"]);
        let (a, _) = parse(r#"{"other":1}"#);
        assert!(a.is_empty());
    }
}
