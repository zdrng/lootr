//! `npmrc`: npm configuration (`~/.npmrc`, a project's `.npmrc`).
//!
//! Credentials are `_authToken` (a token), `_auth` (base64 `user:password`)
//! and `_password` (base64 password), either global or scoped to a
//! registry (`//registry.npmjs.org/:_authToken=...`). Values of the form
//! `${NPM_TOKEN}` come from the environment and are only counted
//! (`env_refs`). Inline credentials are emitted as nested values at their
//! key (decoded for `_auth` / `_password`).

use crate::domain::format::{ini, is_text};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds};
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "npmrc";

pub const ATTRS: &[AttrSpec] = &[
    creds::INLINE_TOKENS,
    creds::HOSTS,
    AttrSpec::new(
        "env_refs",
        AttrKind::Int,
        "credentials taken from environment variables (`${VAR}`)",
    ),
];

const DEFAULT_REGISTRY: &str = "registry.npmjs.org";

pub struct Npmrc;

impl DocumentType for Npmrc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "an npm configuration file (.npmrc): stored registry tokens and passwords"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let entries = ini::parse_with(doc, ini::Delimiters::Equals);
        let default_host = entries
            .iter()
            .find(|e| e.key == "registry")
            .and_then(|e| creds::url_host(e.value.expose()))
            .unwrap_or(DEFAULT_REGISTRY)
            .to_string();
        let mut stored = Creds::default();
        let mut env_refs = 0;
        for e in &entries {
            let key = e.key.as_ref();
            let (host, field) = match key.strip_prefix("//") {
                Some(scoped) => {
                    let Some((target, field)) = scoped.rsplit_once(':') else {
                        continue;
                    };
                    (target.split('/').next(), field)
                }
                None => (Some(default_host.as_str()), key),
            };
            if !matches!(field, "_authToken" | "_auth" | "_password") || e.is_empty() {
                continue;
            }
            let v = e.value.expose();
            if v.starts_with(b"${") && v.ends_with(b"}") {
                env_refs += 1;
                continue;
            }
            stored.add(host);
            let path = PublicText::from_non_secret(key);
            match field {
                "_authToken" => out.value(path, e.value),
                "_auth" => {
                    if let Some(pw) = creds::decode_base64(e.value)
                        .as_ref()
                        .and_then(creds::password_of)
                    {
                        out.owned_value(path, pw);
                    }
                }
                _ => {
                    if let Some(pw) = creds::decode_base64(e.value) {
                        out.owned_value(path, pw);
                    }
                }
            }
        }
        let mut attrs = Attrs::new();
        stored.insert_attrs(&mut attrs);
        attrs.insert("env_refs", AttrValue::Int(env_refs));
        out.fact(attrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    #[test]
    fn tokens_passwords_and_env_refs() {
        let text = format!(
            "registry=https://npm.corp.example/\n_authToken={CANARY}global\n\
             //registry.npmjs.org/:_authToken=${{NPM_TOKEN}}\n\
             //npm.pkg.github.com/:_authToken={CANARY}gh\n\
             //localhost:4873/:_password=TE9PVFJDQU5BUllwdw==\n\
             //old.example/:_auth=dTpMT09UUkNBTkFSWXBhc3M=\nalways-auth=true\n"
        );
        let mut out = Emitter::default();
        Npmrc
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_tokens"], AttrValue::Int(4));
        assert_eq!(a["env_refs"], AttrValue::Int(1));
        assert_eq!(
            a["hosts"].to_string(),
            "localhost:4873, npm.corp.example, npm.pkg.github.com, old.example"
        );
        let values: Vec<(String, Vec<u8>)> = out
            .values
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_slice().expose().to_vec()))
            .collect();
        assert_eq!(values[0].0, "_authToken");
        assert_eq!(values[2].1, b"LOOTRCANARYpw");
        assert_eq!(values[3].1, b"LOOTRCANARYpass");
    }
}
