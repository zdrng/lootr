//! `docker_config`: the Docker / Podman client config
//! (`~/.docker/config.json`).
//!
//! Registry credentials are either stored inline (`auths.<registry>.auth`,
//! base64 of `user:password`, or an `identitytoken`) or delegated to a
//! credential helper (`credsStore` for all registries, `credHelpers` per
//! registry). Inline credentials are decoded and the **password** part is
//! emitted as a nested value at `auths.<registry>.auth` (a registry
//! password is often a token: `ghp_...` for ghcr.io, `dckr_pat_...` for
//! Docker Hub); the user name is not reported.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::domain::format::json::{self, PlainText, SecretValue};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds, key_path};
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "docker_config";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "inline_auths",
        AttrKind::Int,
        "registries with credentials stored in the file (auth, identitytoken, password)",
    ),
    creds::HOSTS,
    AttrSpec::optional(
        "creds_store",
        AttrKind::Text,
        "the credential helper for all registries (credsStore), e.g. desktop, osxkeychain, pass",
    ),
    AttrSpec::new(
        "cred_helpers",
        AttrKind::Int,
        "registries with their own credential helper (credHelpers)",
    ),
];

#[derive(Deserialize)]
struct Doc<'a> {
    #[serde(borrow, default)]
    auths: BTreeMap<String, Auth<'a>>,
    #[serde(rename = "credsStore", default)]
    creds_store: PlainText,
    #[serde(rename = "credHelpers", default)]
    cred_helpers: BTreeMap<String, PlainText>,
}

#[derive(Deserialize)]
struct Auth<'a> {
    #[serde(borrow, default)]
    auth: SecretValue<'a>,
    #[serde(borrow, default)]
    password: SecretValue<'a>,
    #[serde(borrow, default)]
    identitytoken: SecretValue<'a>,
    #[serde(borrow, default)]
    registrytoken: SecretValue<'a>,
}

pub struct DockerConfig;

impl DocumentType for DockerConfig {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "the Docker/Podman client config: inline registry credentials vs credential helpers"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        json::first_byte(head) == Some(b'{')
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let d: Doc<'a> = json::parse(doc)?;
        let mut stored = Creds::default();
        for (registry, auth) in d.auths {
            let host = registry_host(&registry);
            // A registry key with user info (`https://user:pw@host`) is shown
            // by its host only: user info never reaches a key path.
            let shown = if registry.contains('@') {
                host.unwrap_or("-")
            } else {
                registry.as_str()
            };
            let mut inline = false;
            if let Some(pair) = auth.auth.as_slice().and_then(creds::decode_base64) {
                inline |= !pair.is_empty();
                if let Some(pw) = creds::password_of(&pair) {
                    out.owned_value(key_path(&["auths", shown, "auth"]), pw);
                }
            }
            for (field, value) in [
                ("password", auth.password),
                ("identitytoken", auth.identitytoken),
                ("registrytoken", auth.registrytoken),
            ] {
                if let Some(v) = value.nested() {
                    inline = true;
                    out.nested(key_path(&["auths", shown, field]), v);
                }
            }
            if inline {
                stored.add(host);
            }
        }
        let mut attrs = Attrs::new();
        attrs.insert("inline_auths", AttrValue::Int(stored.inline_tokens));
        attrs.insert("hosts", stored.hosts());
        if let Some(s) = d.creds_store.as_deref().filter(|s| !s.is_empty()) {
            attrs.insert(
                "creds_store",
                AttrValue::Text(PublicText::from_non_secret(s)),
            );
        }
        attrs.insert("cred_helpers", AttrValue::Int(d.cred_helpers.len() as i64));
        out.fact(attrs);
        Ok(())
    }
}

/// `https://index.docker.io/v1/` → `index.docker.io`; plain names stay.
fn registry_host(registry: &str) -> Option<&str> {
    creds::url_host(registry.as_bytes()).or_else(|| {
        let name = registry.split('/').next().unwrap_or(registry);
        creds::host_name(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn b64(s: &str) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in s.as_bytes().chunks(3) {
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

    #[test]
    fn inline_auths_and_helpers() {
        let text = format!(
            r#"{{"auths":{{"ghcr.io":{{"auth":"{}"}},"https://index.docker.io/v1/":{{}},"registry.example:5000":{{"identitytoken":"{CANARY}id"}}}},
               "credsStore":"desktop","credHelpers":{{"gcr.io":"gcloud","123.dkr.ecr.example":"ecr-login"}}}}"#,
            b64(&format!("octo:{CANARY}pw"))
        );
        let mut out = Emitter::default();
        DockerConfig
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_auths"], AttrValue::Int(2));
        assert_eq!(a["hosts"].to_string(), "ghcr.io, registry.example:5000");
        assert_eq!(a["creds_store"].to_string(), "desktop");
        assert_eq!(a["cred_helpers"], AttrValue::Int(2));
        assert!(!a.contains_key("inline_tokens"));
        let values: Vec<(String, Vec<u8>)> = out
            .values
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_slice().expose().to_vec()))
            .collect();
        assert_eq!(values[0].0, "auths.ghcr.io.auth");
        assert_eq!(values[0].1, format!("{CANARY}pw").into_bytes());
        assert_eq!(values[1].0, "auths.registry.example:5000.identitytoken");
    }

    #[test]
    fn empty_and_broken() {
        let mut out = Emitter::default();
        DockerConfig
            .parse(SecretSlice::new(b"{}"), &mut out)
            .unwrap();
        assert_eq!(out.facts[0].1["inline_auths"], AttrValue::Int(0));
        assert!(!out.facts[0].1.contains_key("creds_store"));
        let mut out = Emitter::default();
        assert!(
            DockerConfig
                .parse(SecretSlice::new(b"{\"auths\":"), &mut out)
                .is_err()
        );
        assert_eq!(
            registry_host("https://index.docker.io/v1/"),
            Some("index.docker.io")
        );
        assert_eq!(registry_host("quay.io/org"), Some("quay.io"));
    }
}
