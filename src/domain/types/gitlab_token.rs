//! `gitlab_token`: GitLab tokens recognized by their documented prefix
//! (GitLab docs, "Token prefixes").
//!
//! | prefix | kind |
//! |---|---|
//! | `glpat-` | `access_token` (personal, project and group access tokens share the prefix) |
//! | `gloas-` | `oauth_app_secret` |
//! | `gldt-` | `deploy` |
//! | `glrt-` | `runner` (runner authentication token) |
//! | `GR1348941` | `runner_registration` (legacy runner registration token) |
//! | `glcbt-` | `ci_job` (CI/CD job token) |
//! | `glptt-` | `trigger` (pipeline trigger token) |
//! | `glft-` | `feed` |
//! | `glimt-` | `incoming_mail` |
//! | `glagent-` | `agent` (GitLab agent for Kubernetes) |
//! | `glsoat-` | `scim` |
//! | `glffct-` | `feature_flags_client` |
//!
//! The rest must be at least 20 characters of `[A-Za-z0-9_.-]` (GitLab's
//! newer routable tokens are longer and contain dots). GitLab documents no
//! checksum lootr could verify offline, so there is no `checksum_valid`.

use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, ValueType};

pub const NAME: &str = "gitlab_token";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "access_token | oauth_app_secret | deploy | runner | runner_registration | ci_job | \
         trigger | feed | incoming_mail | agent | scim | feature_flags_client",
    ),
    AttrSpec::new("prefix", AttrKind::Sym, "the token prefix, e.g. glpat-"),
];

const PREFIXES: &[(&str, &str)] = &[
    ("glpat-", "access_token"),
    ("gloas-", "oauth_app_secret"),
    ("gldt-", "deploy"),
    ("glrt-", "runner"),
    ("GR1348941", "runner_registration"),
    ("glcbt-", "ci_job"),
    ("glptt-", "trigger"),
    ("glft-", "feed"),
    ("glimt-", "incoming_mail"),
    ("glagent-", "agent"),
    ("glsoat-", "scim"),
    ("glffct-", "feature_flags_client"),
];

const MIN_BODY: usize = 20;
const MAX_LEN: usize = 255;

pub struct GitlabToken;

impl ValueType for GitlabToken {
    fn name(&self) -> &str {
        NAME
    }

    fn doc(&self) -> &str {
        "a GitLab token (access, deploy, runner, CI job, trigger, ...), recognized by its prefix"
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
        let ok = body.len() >= MIN_BODY
            && body
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !ok {
            return None;
        }
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym(kind));
        attrs.insert("prefix", AttrValue::Sym(prefix));
        Some(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn kind(s: &str) -> Option<String> {
        GitlabToken
            .classify(SecretSlice::new(s.as_bytes()))
            .map(|a| a["kind"].to_string())
    }

    #[test]
    fn prefixes() {
        assert_eq!(
            kind(&format!("glpat-{CANARY}012345678")).as_deref(),
            Some("access_token")
        );
        assert_eq!(
            kind(&format!("glcbt-64_{CANARY}abcdefghij")).as_deref(),
            Some("ci_job")
        );
        assert_eq!(
            kind(&format!("glrt-{CANARY}.01.abcdefgh")).as_deref(),
            Some("runner")
        );
        assert_eq!(
            kind(&format!("GR1348941{CANARY}abcdefghij")).as_deref(),
            Some("runner_registration")
        );
        assert_eq!(
            kind(&format!("gldt-{CANARY}abcdefghij")).as_deref(),
            Some("deploy")
        );
        assert!(kind("glpat-short").is_none());
        assert!(kind(&format!("glpat-{CANARY} 0123456789")).is_none());
        assert!(kind(&format!("xglpat-{CANARY}0123456789")).is_none());
        assert!(kind(&format!("glpat-{}", "a".repeat(300))).is_none());
    }
}
