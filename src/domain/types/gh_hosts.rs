//! `gh_hosts`: the GitHub CLI's `~/.config/gh/hosts.yml`.
//!
//! When `gh` cannot use the system keyring it stores the OAuth token in
//! this file: `<host>.oauth_token`, and per account in
//! `<host>.users.<login>.oauth_token`. Each is emitted as a nested value
//! (classified as `github_token`). Parsed with the bounded YAML loader.

use crate::domain::format::yaml::Yaml;
use crate::domain::model::Attrs;
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds, key_path};
use crate::domain::types::{AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "gh_hosts";

pub const ATTRS: &[AttrSpec] = &[creds::INLINE_TOKENS, creds::HOSTS];

pub struct GhHosts;

impl DocumentType for GhHosts {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "the GitHub CLI's hosts.yml: OAuth tokens stored outside the keyring"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        crate::domain::format::is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let yaml = Yaml::parse(doc)?;
        let Some(root) = yaml.root().filter(|r| r.is_map()) else {
            return Ok(());
        };
        let mut stored = Creds::default();
        for (host, cfg) in root.entries() {
            let Some(host) = host.text() else {
                continue;
            };
            if let Some(token) = cfg.get("oauth_token").and_then(|t| t.secret()) {
                stored.add(Some(host));
                out.nested(key_path(&[host, "oauth_token"]), token);
            }
            for (user, ucfg) in cfg.get("users").into_iter().flat_map(|u| u.entries()) {
                let Some(user) = user.text() else {
                    continue;
                };
                if let Some(token) = ucfg.get("oauth_token").and_then(|t| t.secret()) {
                    stored.add(Some(host));
                    out.nested(key_path(&[host, "users", user, "oauth_token"]), token);
                }
            }
        }
        let mut attrs = Attrs::new();
        stored.insert_attrs(&mut attrs);
        out.fact(attrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::AttrValue;
    use crate::testing::CANARY;

    #[test]
    fn tokens_per_host_and_user() {
        let text = format!(
            "github.com:\n    users:\n        octo:\n            oauth_token: gho_{CANARY}\n    git_protocol: https\n    oauth_token: gho_{CANARY}\n    user: octo\n\
             ghe.corp.example:\n    user: me\n    git_protocol: ssh\n"
        );
        let mut out = Emitter::default();
        GhHosts
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_tokens"], AttrValue::Int(2));
        assert_eq!(a["hosts"].to_string(), "github.com");
        let keys: Vec<String> = out.values.iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(
            keys,
            [
                "github.com.oauth_token",
                "github.com.users.octo.oauth_token"
            ]
        );
    }
}
