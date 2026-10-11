//! `gcp_credentials`: Google Cloud credential files (application default
//! credentials, service account keys, workload identity federation
//! configs), JSON with a `type` field.
//!
//! The `private_key` of a service account key, the `refresh_token` and the
//! `client_secret` of user credentials are emitted as nested values; the
//! fact keeps the kind, the service account's e-mail address (an identity,
//! not a secret) and the project. JSON files without a known `type` produce
//! no fact (the file is not a Google credential).

use serde::Deserialize;

use crate::domain::format::json::{self, PlainText, SecretValue};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "gcp_credentials";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "service_account | authorized_user | external_account | \
         external_account_authorized_user | impersonated_service_account",
    ),
    AttrSpec::optional(
        "account",
        AttrKind::Text,
        "the service account's e-mail address (client_email)",
    ),
    AttrSpec::optional(
        "project",
        AttrKind::Text,
        "project_id (service accounts) or quota_project_id",
    ),
];

const KINDS: &[&str] = &[
    "service_account",
    "authorized_user",
    "external_account",
    "external_account_authorized_user",
    "impersonated_service_account",
];

#[derive(Deserialize)]
struct Doc<'a> {
    #[serde(rename = "type", default)]
    type_: PlainText,
    #[serde(default)]
    client_email: PlainText,
    #[serde(default)]
    project_id: PlainText,
    #[serde(default)]
    quota_project_id: PlainText,
    #[serde(borrow, default)]
    private_key: SecretValue<'a>,
    #[serde(borrow, default)]
    refresh_token: SecretValue<'a>,
    #[serde(borrow, default)]
    client_secret: SecretValue<'a>,
}

pub struct GcpCredentials;

impl DocumentType for GcpCredentials {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a Google Cloud credential file (service account key, user or federated credentials)"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        json::first_byte(head) == Some(b'{')
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let d: Doc<'a> = json::parse(doc)?;
        let Some(kind) = d
            .type_
            .as_deref()
            .and_then(|t| KINDS.iter().find(|k| **k == t))
        else {
            return Ok(());
        };
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym(kind));
        if *kind == "service_account"
            && let Some(email) = d.client_email.as_deref()
        {
            attrs.insert(
                "account",
                AttrValue::Text(PublicText::from_non_secret(email)),
            );
        }
        if let Some(p) = d.project_id.as_deref().or(d.quota_project_id.as_deref())
            && !p.is_empty()
        {
            attrs.insert("project", AttrValue::Text(PublicText::from_non_secret(p)));
        }
        out.fact(attrs);
        for (key, value) in [
            ("private_key", d.private_key),
            ("refresh_token", d.refresh_token),
            ("client_secret", d.client_secret),
        ] {
            if let Some(v) = value.nested() {
                out.nested(PublicText::from_non_secret(key), v);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn parse(text: &str) -> Emitter<'_> {
        let mut out = Emitter::default();
        GcpCredentials
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        out
    }

    #[test]
    fn service_account_and_user_credentials() {
        let sa = format!(
            r#"{{"type":"service_account","project_id":"demo-project","private_key_id":"{CANARY}","private_key":"-----BEGIN PRIVATE KEY-----\n{CANARY}\n-----END PRIVATE KEY-----\n","client_email":"ci@demo-project.iam.gserviceaccount.com"}}"#
        );
        let out = parse(&sa);
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["kind"], AttrValue::Sym("service_account"));
        assert_eq!(
            a["account"].to_string(),
            "ci@demo-project.iam.gserviceaccount.com"
        );
        assert_eq!(a["project"].to_string(), "demo-project");
        assert_eq!(out.values.len(), 1);
        assert_eq!(out.values[0].0.as_str(), "private_key");

        let user = format!(
            r#"{{"client_id":"x.apps.example","client_secret":"{CANARY}","refresh_token":"1//{CANARY}","type":"authorized_user","quota_project_id":"q"}}"#
        );
        let out = parse(&user);
        let a = &out.facts[0].1;
        assert_eq!(a["kind"], AttrValue::Sym("authorized_user"));
        assert!(!a.contains_key("account"));
        assert_eq!(a["project"].to_string(), "q");
        let keys: Vec<&str> = out.values.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["refresh_token", "client_secret"]);
    }

    #[test]
    fn other_json_is_not_a_credential() {
        assert!(parse(r#"{"type":"something_else"}"#).facts.is_empty());
        assert!(parse(r#"{"name":"x"}"#).facts.is_empty());
        let mut out = Emitter::default();
        assert!(
            GcpCredentials
                .parse(SecretSlice::new(b"[1,2"), &mut out)
                .is_err()
        );
        assert!(GcpCredentials.sniff(b"\xEF\xBB\xBF  {"));
        assert!(!GcpCredentials.sniff(b"[]"));
    }
}
