//! `api_key`: well-known API key and token formats, recognized by prefix,
//! charset and length. One type with a `service` attribute, so a policy can
//! treat every known key alike (`type = "api_key"`) or single out a service
//! (`service == "stripe"`).
//!
//! Only formats with a documented, distinctive prefix are included; none of
//! them has a checksum lootr can verify, so there is no `checksum_valid`.
//! Several patterns follow gitleaks (MIT, see THIRD_PARTY.md).
//!
//! | service | prefix → kind |
//! |---|---|
//! | `slack` | `xoxb-` bot, `xoxp-` user, `xapp-` app, `xoxe.xoxb-`/`xoxe.xoxp-` rotating, `xoxe-` refresh, `https://hooks.slack.com/` webhook |
//! | `stripe` | `sk_live_`/`sk_test_` secret, `rk_live_`/`rk_test_` restricted (`live`), `whsec_` webhook_secret |
//! | `openai` | `sk-proj-` project, `sk-svcacct-` service_account, `sk-admin-` admin, other `sk-` user (all contain `T3BlbkFJ`) |
//! | `anthropic` | `sk-ant-api03-` api_key, `sk-ant-admin01-` admin_key, `sk-ant-oat01-` oauth_access, `sk-ant-ort01-` oauth_refresh |
//! | `npm` | `npm_` + 36 alphanumerics: access_token |
//! | `pypi` | `pypi-AgEIcHlwaS5vcmc` api_token (pypi.org), `pypi-AgENdGVzdC5weXBpLm9yZw` test_api_token |
//! | `docker_hub` | `dckr_pat_` personal_access_token |
//! | `google` | `AIza` + 35: api_key, `GOCSPX-` + 28: oauth_client_secret |
//! | `sendgrid` | `SG.` + 22 + `.` + 43: api_key |
//! | `huggingface` | `hf_` + 34 alphanumerics: access_token |
//! | `digitalocean` | `dop_v1_` personal_access_token, `doo_v1_` oauth_token, `dor_v1_` refresh_token (+ 64 hex) |
//! | `shopify` | `shpat_` access_token, `shpca_` custom_app_token, `shppa_` private_app_token, `shpss_` shared_secret (+ 32 hex) |
//! | `hashicorp_vault` | `hvs.` service_token, `hvb.` batch_token, `hvr.` recovery_token |
//! | `terraform_cloud` | 14 alphanumerics + `.atlasv1.` + 60-70: api_token |
//! | `rubygems` | `rubygems_` + 48 hex: api_key |
//!
//! GitHub, GitLab and AWS have types of their own (`github_token`,
//! `gitlab_token`, `aws_access_key_id`). Nothing derived from the random
//! part is emitted.

use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, ValueType};

pub const NAME: &str = "api_key";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "service",
        AttrKind::Sym,
        "slack | stripe | openai | anthropic | npm | pypi | docker_hub | google | sendgrid | \
         huggingface | digitalocean | shopify | hashicorp_vault | terraform_cloud | rubygems",
    ),
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "slack: bot | user | app | rotating | refresh | webhook; stripe: secret | restricted | \
         webhook_secret; openai: project | service_account | admin | user; anthropic: api_key | \
         admin_key | oauth_access | oauth_refresh; npm, huggingface: access_token; pypi: api_token | \
         test_api_token; docker_hub: personal_access_token; google: api_key | oauth_client_secret; \
         sendgrid, rubygems: api_key; digitalocean: personal_access_token | oauth_token | \
         refresh_token; shopify: access_token | custom_app_token | private_app_token | \
         shared_secret; hashicorp_vault: service_token | batch_token | recovery_token; \
         terraform_cloud: api_token",
    ),
    AttrSpec::optional(
        "live",
        AttrKind::Bool,
        "live mode (true) or test mode (false) key (Stripe only)",
    ),
];

const MAX_LEN: usize = 512;

/// The body after the prefix.
#[derive(Clone, Copy)]
enum Body {
    /// `[A-Za-z0-9_-]`, at least n bytes.
    Url(usize),
    /// `[A-Za-z0-9-]`, at least n bytes.
    Dash(usize),
    /// `[A-Za-z0-9]`, at least n bytes.
    Alnum(usize),
    /// `[A-Za-z0-9]`, exactly n bytes.
    AlnumExact(usize),
    /// `[A-Za-z0-9_-]`, exactly n bytes.
    UrlExact(usize),
    /// Lowercase or uppercase hex, exactly n bytes.
    Hex(usize),
    /// `[A-Za-z0-9+/=]`, at least n bytes.
    Base64(usize),
    /// `[A-Za-z0-9/_-]`, at least n bytes (URL path).
    Path(usize),
}

impl Body {
    fn matches(self, b: &[u8]) -> bool {
        let url = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-';
        match self {
            Body::Url(n) => b.len() >= n && b.iter().all(url),
            Body::UrlExact(n) => b.len() == n && b.iter().all(url),
            Body::Dash(n) => {
                b.len() >= n && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            }
            Body::Alnum(n) => b.len() >= n && b.iter().all(u8::is_ascii_alphanumeric),
            Body::AlnumExact(n) => b.len() == n && b.iter().all(u8::is_ascii_alphanumeric),
            Body::Hex(n) => b.len() == n && b.iter().all(u8::is_ascii_hexdigit),
            Body::Base64(n) => {
                b.len() >= n
                    && b.iter()
                        .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(c))
            }
            Body::Path(n) => b.len() >= n && b.iter().all(|c| url(c) || *c == b'/'),
        }
    }
}

struct Format {
    prefix: &'static str,
    body: Body,
    service: &'static str,
    kind: &'static str,
    live: Option<bool>,
}

const fn f(prefix: &'static str, body: Body, service: &'static str, kind: &'static str) -> Format {
    Format {
        prefix,
        body,
        service,
        kind,
        live: None,
    }
}

const fn stripe(prefix: &'static str, kind: &'static str, live: bool) -> Format {
    Format {
        prefix,
        body: Body::Alnum(16),
        service: "stripe",
        kind,
        live: Some(live),
    }
}

/// Longer prefixes before their own prefixes (`xoxe.xoxb-` before `xoxe-`).
const FORMATS: &[Format] = &[
    f("xoxe.xoxb-", Body::Dash(20), "slack", "rotating"),
    f("xoxe.xoxp-", Body::Dash(20), "slack", "rotating"),
    f("xoxe-", Body::Dash(20), "slack", "refresh"),
    f("xoxb-", Body::Dash(20), "slack", "bot"),
    f("xoxp-", Body::Dash(20), "slack", "user"),
    f("xapp-", Body::Dash(20), "slack", "app"),
    f(
        "https://hooks.slack.com/services/",
        Body::Path(20),
        "slack",
        "webhook",
    ),
    f(
        "https://hooks.slack.com/workflows/",
        Body::Path(20),
        "slack",
        "webhook",
    ),
    f(
        "https://hooks.slack.com/triggers/",
        Body::Path(20),
        "slack",
        "webhook",
    ),
    stripe("sk_live_", "secret", true),
    stripe("sk_test_", "secret", false),
    stripe("rk_live_", "restricted", true),
    stripe("rk_test_", "restricted", false),
    f("whsec_", Body::Base64(24), "stripe", "webhook_secret"),
    f("sk-ant-api03-", Body::Url(32), "anthropic", "api_key"),
    f("sk-ant-admin01-", Body::Url(32), "anthropic", "admin_key"),
    f("sk-ant-oat01-", Body::Url(32), "anthropic", "oauth_access"),
    f("sk-ant-ort01-", Body::Url(32), "anthropic", "oauth_refresh"),
    f("npm_", Body::AlnumExact(36), "npm", "access_token"),
    f("pypi-AgEIcHlwaS5vcmc", Body::Url(32), "pypi", "api_token"),
    f(
        "pypi-AgENdGVzdC5weXBpLm9yZw",
        Body::Url(32),
        "pypi",
        "test_api_token",
    ),
    f(
        "dckr_pat_",
        Body::Url(20),
        "docker_hub",
        "personal_access_token",
    ),
    f("AIza", Body::UrlExact(35), "google", "api_key"),
    f(
        "GOCSPX-",
        Body::UrlExact(28),
        "google",
        "oauth_client_secret",
    ),
    f("hf_", Body::AlnumExact(34), "huggingface", "access_token"),
    f(
        "dop_v1_",
        Body::Hex(64),
        "digitalocean",
        "personal_access_token",
    ),
    f("doo_v1_", Body::Hex(64), "digitalocean", "oauth_token"),
    f("dor_v1_", Body::Hex(64), "digitalocean", "refresh_token"),
    f("shpat_", Body::Hex(32), "shopify", "access_token"),
    f("shpca_", Body::Hex(32), "shopify", "custom_app_token"),
    f("shppa_", Body::Hex(32), "shopify", "private_app_token"),
    f("shpss_", Body::Hex(32), "shopify", "shared_secret"),
    f("hvs.", Body::Url(24), "hashicorp_vault", "service_token"),
    f("hvb.", Body::Url(24), "hashicorp_vault", "batch_token"),
    f("hvr.", Body::Url(24), "hashicorp_vault", "recovery_token"),
    f("rubygems_", Body::Hex(48), "rubygems", "api_key"),
];

const OPENAI_MARKER: &[u8] = b"T3BlbkFJ";

pub struct ApiKey;

impl ValueType for ApiKey {
    fn name(&self) -> &str {
        NAME
    }

    fn doc(&self) -> &str {
        "a well-known API key or token (Slack, Stripe, OpenAI, Anthropic, npm, PyPI, Docker Hub, \
         Google, SendGrid, Hugging Face, DigitalOcean, Shopify, Vault, Terraform Cloud, RubyGems), \
         recognized by prefix, charset and length"
    }

    fn schema(&self) -> &[AttrSpec] {
        ATTRS
    }

    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
        let bytes = value.expose();
        if bytes.len() > MAX_LEN {
            return None;
        }
        let (service, kind, live) = FORMATS
            .iter()
            .find(|f| {
                bytes
                    .strip_prefix(f.prefix.as_bytes())
                    .is_some_and(|body| f.body.matches(body))
            })
            .map(|f| (f.service, f.kind, f.live))
            .or_else(|| other_format(bytes).map(|(s, k)| (s, k, None)))?;
        let mut attrs = Attrs::new();
        attrs.insert("service", AttrValue::Sym(service));
        attrs.insert("kind", AttrValue::Sym(kind));
        if let Some(live) = live {
            attrs.insert("live", AttrValue::Bool(live));
        }
        Some(attrs)
    }
}

/// Formats that are not a prefix + body.
fn other_format(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    // OpenAI: `sk-` ... `T3BlbkFJ` (base64 of "OpenAI") ...
    if let Some(body) = bytes.strip_prefix(b"sk-")
        && !body.starts_with(b"ant-")
        && body.len() >= 40
        && Body::Url(0).matches(body)
        && body
            .windows(OPENAI_MARKER.len())
            .any(|w| w == OPENAI_MARKER)
    {
        let kind = if body.starts_with(b"proj-") {
            "project"
        } else if body.starts_with(b"svcacct-") {
            "service_account"
        } else if body.starts_with(b"admin-") {
            "admin"
        } else {
            "user"
        };
        return Some(("openai", kind));
    }
    // SendGrid: SG.<22>.<43>
    if let Some(body) = bytes.strip_prefix(b"SG.")
        && body.len() == 66
        && body[22] == b'.'
        && Body::UrlExact(22).matches(&body[..22])
        && Body::UrlExact(43).matches(&body[23..])
    {
        return Some(("sendgrid", "api_key"));
    }
    // Terraform Cloud / Enterprise: <14>.atlasv1.<60-70>
    if bytes.len() > 23
        && &bytes[14..23] == b".atlasv1."
        && Body::AlnumExact(14).matches(&bytes[..14])
        && (60..=70).contains(&(bytes.len() - 23))
        && bytes[23..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_-=".contains(c))
    {
        return Some(("terraform_cloud", "api_token"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn classify(s: &str) -> Option<(String, String, Option<bool>)> {
        ApiKey.classify(SecretSlice::new(s.as_bytes())).map(|a| {
            assert!(!format!("{a:?}").contains(CANARY));
            (
                a["service"].to_string(),
                a["kind"].to_string(),
                a.get("live").map(|v| *v == AttrValue::Bool(true)),
            )
        })
    }

    fn is(s: &str, service: &str, kind: &str) {
        let got = classify(s).unwrap_or_else(|| panic!("{s} not classified"));
        assert_eq!((got.0.as_str(), got.1.as_str()), (service, kind), "{s}");
    }

    #[test]
    fn known_formats() {
        // Assembled from parts, like the fixtures, so secret scanners do not
        // see whole dummy keys in the source.
        let c = CANARY;
        is(&format!("xoxb-1234567890-{c}abcdefgh"), "slack", "bot");
        is(
            &format!("xoxp-1234567890-1234567890-{c}abcd"),
            "slack",
            "user",
        );
        is(&format!("xoxe.xoxp-1-{c}abcdefghijkl"), "slack", "rotating");
        is(&format!("xoxe-1-{c}abcdefghijklmn"), "slack", "refresh");
        is(&format!("xapp-1-A0123-{c}abcdefgh"), "slack", "app");
        is(
            &format!("https://hooks.slack.com/services/T0/B0/{c}abcdef"),
            "slack",
            "webhook",
        );
        assert_eq!(
            classify(&format!("sk_live_{c}0123456789")).unwrap().2,
            Some(true)
        );
        assert_eq!(
            classify(&format!("rk_test_{c}0123456789")).unwrap().2,
            Some(false)
        );
        is(
            &format!("whsec_{c}0123456789abcdef+/="),
            "stripe",
            "webhook_secret",
        );
        let oa = format!("{c}0123456789T3BlbkFJ{c}0123456789");
        is(&format!("sk-proj-{oa}"), "openai", "project");
        is(&format!("sk-svcacct-{oa}"), "openai", "service_account");
        is(&format!("sk-admin-{oa}"), "openai", "admin");
        is(&format!("sk-{oa}"), "openai", "user");
        is(
            &format!("sk-ant-api03-{c}{}AA", "x".repeat(82)),
            "anthropic",
            "api_key",
        );
        is(
            &format!("sk-ant-oat01-{c}{}", "x".repeat(40)),
            "anthropic",
            "oauth_access",
        );
        is(&format!("npm_{c}{}", "a".repeat(25)), "npm", "access_token");
        is(
            &format!("pypi-AgEIcHlwaS5vcmc{c}{}", "x".repeat(40)),
            "pypi",
            "api_token",
        );
        is(
            &format!("pypi-AgENdGVzdC5weXBpLm9yZw{c}{}", "x".repeat(40)),
            "pypi",
            "test_api_token",
        );
        is(
            &format!("dckr_pat_{c}0123456789"),
            "docker_hub",
            "personal_access_token",
        );
        is(&format!("AIza{c}{}", "x".repeat(24)), "google", "api_key");
        is(
            &format!("GOCSPX-{c}{}", "x".repeat(17)),
            "google",
            "oauth_client_secret",
        );
        is(
            &format!("SG.{c}{}.{c}{}", "x".repeat(11), "y".repeat(32)),
            "sendgrid",
            "api_key",
        );
        is(
            &format!("hf_{c}{}", "x".repeat(23)),
            "huggingface",
            "access_token",
        );
        is(
            &format!("dop_v1_{}", "ab12".repeat(16)),
            "digitalocean",
            "personal_access_token",
        );
        is(
            &format!("shpat_{}", "ab12".repeat(8)),
            "shopify",
            "access_token",
        );
        is(
            &format!("hvs.{c}0123456789abcdef"),
            "hashicorp_vault",
            "service_token",
        );
        is(
            &format!("{c}abc.atlasv1.{c}{}", "x".repeat(50)),
            "terraform_cloud",
            "api_token",
        );
        is(
            &format!("rubygems_{}", "ab12".repeat(12)),
            "rubygems",
            "api_key",
        );
    }

    #[test]
    fn rejects_near_misses() {
        for s in [
            "",
            "xoxb-short",
            "sk_live_short",
            "sk-ant-api03-short",
            "sk-plainsecretwithoutmarker0123456789abcdefgh",
            "npm_tooshort",
            "AIzaTooShort",
            "pk_live_0123456789abcdefghijkl",
            "SG.x.y",
            "hf_has-dash-0123456789012345678901",
            "dop_v1_nothex",
            "LOOTRCANARYabc.atlasv1.short",
        ] {
            assert!(classify(s).is_none(), "{s}");
        }
        assert!(classify(&format!("xoxb-{}", "a".repeat(600))).is_none());
    }
}
