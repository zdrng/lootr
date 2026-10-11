//! `jwt`: JSON Web Tokens (JWS compact form, `header.payload.signature`).
//!
//! Only the header and the payload are decoded (base64url into a
//! [`SecretBuf`](crate::domain::secret::SecretBuf)), the signature never is.
//! Of the payload only the registered claims below are read; other claims
//! (subject, custom data) are skipped by the JSON parser and never become
//! facts. Issuer, audience and scopes are reported as non-secret text: they
//! name who issued the token and what it is for, not the credential.
//!
//! Time-dependent attributes are computed against the scan's start time,
//! given to [`Jwt::new`] (so tests can fix it).

use serde::Deserialize;

use crate::domain::codec::{Alphabet, Base64Reader};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::time::hours_between;
use crate::domain::types::{AttrKind, AttrSpec, ValueType};

pub const NAME: &str = "jwt";

/// Longest header or payload that is decoded.
const MAX_SEGMENT: usize = 16 * 1024;
/// Most audience entries / scopes reported.
const MAX_ITEMS: usize = 32;

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "alg",
        AttrKind::Sym,
        "signature algorithm: HS256, RS256, ES256, EdDSA, none, ... or other",
    ),
    AttrSpec::optional("issuer", AttrKind::Text, "the `iss` claim"),
    AttrSpec::optional("audience", AttrKind::List, "the `aud` claim (list of text)"),
    AttrSpec::optional(
        "scopes",
        AttrKind::List,
        "the `scope` (space separated) or `scp` claim (list of text)",
    ),
    AttrSpec::optional(
        "expires_in_hours",
        AttrKind::Int,
        "hours from the scan until `exp`; negative if expired; absent without `exp`",
    ),
    AttrSpec::optional(
        "lifetime_hours",
        AttrKind::Int,
        "hours from `iat` (or `nbf`) to `exp`; absent if either is missing",
    ),
    AttrSpec::new(
        "expired",
        AttrKind::Bool,
        "`exp` is at or before the scan time (false without `exp`)",
    ),
];

const ALGS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K",
    "PS256", "PS384", "PS512", "EdDSA", "none",
];

pub struct Jwt {
    now: i64,
}

impl Jwt {
    /// `now`: Unix time the scan started.
    pub fn new(now: i64) -> Jwt {
        Jwt { now }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn items(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// A claim of an unexpected JSON type is ignored, not an error.
#[derive(Deserialize)]
#[serde(untagged)]
enum Lenient<T> {
    Ok(T),
    Other(serde::de::IgnoredAny),
}

fn ok<T>(v: Option<Lenient<T>>) -> Option<T> {
    match v {
        Some(Lenient::Ok(t)) => Some(t),
        _ => None,
    }
}

/// The registered claims lootr reads. Everything else is skipped.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Claims {
    iss: Option<Lenient<String>>,
    aud: Option<Lenient<OneOrMany>>,
    exp: Option<Lenient<f64>>,
    iat: Option<Lenient<f64>>,
    nbf: Option<Lenient<f64>>,
    scope: Option<Lenient<String>>,
    scp: Option<Lenient<OneOrMany>>,
}

/// A JSON object (not an array, which serde would also map to a struct).
fn is_object(json: &[u8]) -> bool {
    json.trim_ascii_start().starts_with(b"{")
}

fn segment_ok(s: &[u8]) -> bool {
    s.iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Seconds since the epoch from a JSON NumericDate.
fn seconds(v: Option<f64>) -> Option<i64> {
    v.filter(|f| f.is_finite() && f.abs() < 1e15)
        .map(|f| f as i64)
}

fn texts(items: Vec<String>) -> AttrValue {
    AttrValue::List(
        items
            .iter()
            .filter(|s| !s.is_empty())
            .take(MAX_ITEMS)
            .map(|s| AttrValue::Text(PublicText::from_non_secret(s)))
            .collect(),
    )
}

impl ValueType for Jwt {
    fn name(&self) -> &str {
        NAME
    }

    fn doc(&self) -> &str {
        "a JSON Web Token; header and registered claims only, the signature is never decoded"
    }

    fn schema(&self) -> &[AttrSpec] {
        ATTRS
    }

    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
        let bytes = value.expose();
        let mut parts = bytes.split(|&b| b == b'.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some()
            || header.len() < 4
            || payload.is_empty()
            || header.len() > MAX_SEGMENT * 4 / 3
            || payload.len() > MAX_SEGMENT * 4 / 3
            || !segment_ok(header)
            || !segment_ok(payload)
            || !segment_ok(signature)
        {
            return None;
        }
        let header_len = header.len();
        let payload_start = header_len + 1;
        let payload_end = payload_start + payload.len();
        let decode = |range| {
            let seg = value.slice(range)?;
            Base64Reader::new(seg, Alphabet::UrlNoPad, MAX_SEGMENT)
                .decode_all()
                .ok()
        };
        let header_buf = decode(0..header_len)?;
        if !is_object(header_buf.expose()) {
            return None;
        }
        let header: Header = serde_json::from_slice(header_buf.expose()).ok()?;
        drop(header_buf);
        let alg = ALGS
            .iter()
            .find(|a| **a == header.alg)
            .copied()
            .unwrap_or("other");
        if signature.is_empty() && alg != "none" {
            return None;
        }
        let payload_buf = decode(payload_start..payload_end)?;
        if !is_object(payload_buf.expose()) {
            return None;
        }
        let claims: Claims = serde_json::from_slice(payload_buf.expose()).ok()?;
        drop(payload_buf);

        let mut attrs = Attrs::new();
        attrs.insert("alg", AttrValue::Sym(alg));
        if let Some(iss) = ok(claims.iss) {
            attrs.insert("issuer", AttrValue::Text(PublicText::from_non_secret(&iss)));
        }
        if let Some(aud) = ok(claims.aud) {
            attrs.insert("audience", texts(aud.items()));
        }
        let scopes = match (ok(claims.scope), ok(claims.scp)) {
            (Some(s), _) => Some(s.split_whitespace().map(str::to_string).collect()),
            (None, Some(scp)) => Some(scp.items()),
            (None, None) => None,
        };
        if let Some(s) = scopes {
            attrs.insert("scopes", texts(s));
        }
        let exp = seconds(ok(claims.exp));
        let start = seconds(ok(claims.iat)).or(seconds(ok(claims.nbf)));
        if let Some(exp) = exp {
            attrs.insert(
                "expires_in_hours",
                AttrValue::Int(hours_between(self.now, exp)),
            );
            if let Some(start) = start {
                attrs.insert("lifetime_hours", AttrValue::Int(hours_between(start, exp)));
            }
        }
        attrs.insert(
            "expired",
            AttrValue::Bool(exp.is_some_and(|e| e <= self.now)),
        );
        Some(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::fake::FAKE_NOW;
    use crate::testing::CANARY;

    fn b64url(s: &str) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in s.as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }

    fn token(header: &str, payload: &str, sig: &str) -> String {
        format!("{}.{}.{sig}", b64url(header), b64url(payload))
    }

    fn classify(t: &str) -> Option<Attrs> {
        Jwt::new(FAKE_NOW).classify(SecretSlice::new(t.as_bytes()))
    }

    #[test]
    fn reads_registered_claims_only() {
        let iat = FAKE_NOW - 3_600;
        let exp = FAKE_NOW + 47 * 3_600 + 10;
        let t = token(
            r#"{"alg":"RS256","typ":"JWT"}"#,
            &format!(
                r#"{{"iss":"https://token.actions.example","aud":["api","web"],"sub":"{CANARY}","scope":"read write","iat":{iat},"exp":{exp},"secret":"{CANARY}"}}"#
            ),
            &format!("sig{CANARY}"),
        );
        let a = classify(&t).unwrap();
        assert_eq!(a["alg"], AttrValue::Sym("RS256"));
        assert_eq!(a["issuer"].to_string(), "https://token.actions.example");
        assert_eq!(a["audience"].to_string(), "api, web");
        assert_eq!(a["scopes"].to_string(), "read, write");
        assert_eq!(a["expires_in_hours"], AttrValue::Int(47));
        assert_eq!(a["lifetime_hours"], AttrValue::Int(48));
        assert_eq!(a["expired"], AttrValue::Bool(false));
        assert!(!format!("{a:?}").contains(CANARY));
    }

    #[test]
    fn expiry_variants() {
        let t = token(
            r#"{"alg":"HS256"}"#,
            &format!(r#"{{"exp":{},"nbf":{}}}"#, FAKE_NOW - 1, FAKE_NOW - 7_200),
            "c2ln",
        );
        let a = classify(&t).unwrap();
        assert_eq!(a["expired"], AttrValue::Bool(true));
        assert_eq!(a["expires_in_hours"], AttrValue::Int(-1));
        assert_eq!(a["lifetime_hours"], AttrValue::Int(1));

        let t = token(
            r#"{"alg":"ES256"}"#,
            r#"{"scp":["a","b"],"aud":"x"}"#,
            "c2ln",
        );
        let a = classify(&t).unwrap();
        assert_eq!(a["expired"], AttrValue::Bool(false));
        assert!(!a.contains_key("expires_in_hours"));
        assert!(!a.contains_key("lifetime_hours"));
        assert_eq!(a["scopes"].to_string(), "a, b");
        assert_eq!(a["audience"].to_string(), "x");

        let t = token(r#"{"alg":"XYZ"}"#, r#"{"exp":1e300}"#, "c2ln");
        let a = classify(&t).unwrap();
        assert_eq!(a["alg"], AttrValue::Sym("other"));
        assert!(!a.contains_key("expires_in_hours"));

        // Claims of unexpected types are ignored.
        let t = token(
            r#"{"alg":"HS256"}"#,
            r#"{"exp":"soon","iss":7,"aud":[1]}"#,
            "c2ln",
        );
        let a = classify(&t).unwrap();
        assert!(!a.contains_key("expires_in_hours"));
        assert!(!a.contains_key("issuer"));
        assert!(!a.contains_key("audience"));
    }

    #[test]
    fn unsigned_tokens() {
        let t = token(r#"{"alg":"none"}"#, r#"{}"#, "");
        assert_eq!(classify(&t).unwrap()["alg"], AttrValue::Sym("none"));
        let t = token(r#"{"alg":"HS256"}"#, r#"{}"#, "");
        assert!(classify(&t).is_none());
    }

    #[test]
    fn rejects_other_values() {
        assert!(classify("").is_none());
        assert!(classify("a.b.c").is_none());
        assert!(classify("eyJhbGciOiJIUzI1NiJ9.e30.c2ln.extra").is_none());
        assert!(classify("eyJhbGciOiJIUzI1NiJ9.e30=.c2ln").is_none());
        // Header without `alg`, payload not an object, not JSON.
        assert!(classify(&token(r#"{"typ":"JWT"}"#, "{}", "c2ln")).is_none());
        assert!(classify(&token(r#"{"alg":"HS256"}"#, "[1]", "c2ln")).is_none());
        assert!(classify(&token("not json", "{}", "c2ln")).is_none());
        assert!(classify("ghp_abc.def.ghi jkl").is_none());
        assert!(classify("eyJhbGciOiJIUzI1NiJ9.e30.c2ln").is_some());
    }
}
