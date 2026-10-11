//! Helpers shared by the credential-file types (`npmrc`, `pypirc`, `netrc`,
//! `git_credentials`, `gh_hosts`, `docker_config`): the common attributes
//! `inline_tokens` and `hosts`, host names from URLs, key paths.

use std::collections::BTreeSet;

use crate::domain::codec::{Alphabet, Base64Reader};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::{SecretBuf, SecretSlice};
use crate::domain::types::{AttrKind, AttrSpec};

pub const INLINE_TOKENS: AttrSpec = AttrSpec::new(
    "inline_tokens",
    AttrKind::Int,
    "credentials (tokens, passwords) stored in the file itself",
);

pub const HOSTS: AttrSpec = AttrSpec::new(
    "hosts",
    AttrKind::List,
    "hosts the stored credentials are for (text, sorted)",
);

/// Longest host name kept (DNS names are at most 253 bytes).
const MAX_HOST: usize = 253;
/// Most hosts listed per file.
const MAX_HOSTS: usize = 64;

/// Counts inline credentials and collects their hosts.
#[derive(Default)]
pub struct Creds {
    pub inline_tokens: i64,
    hosts: BTreeSet<String>,
}

impl Creds {
    /// Records one stored credential for `host` (if it looks like a host).
    pub fn add(&mut self, host: Option<&str>) {
        self.inline_tokens += 1;
        if let Some(h) = host.and_then(host_name)
            && self.hosts.len() < MAX_HOSTS
        {
            self.hosts.insert(h.to_string());
        }
    }

    /// The `hosts` attribute.
    pub fn hosts(&self) -> AttrValue {
        texts(self.hosts.iter())
    }

    /// `inline_tokens` and `hosts`.
    pub fn insert_attrs(&self, attrs: &mut Attrs) {
        attrs.insert("inline_tokens", AttrValue::Int(self.inline_tokens));
        attrs.insert("hosts", self.hosts());
    }
}

/// A list of non-secret text values.
pub fn texts<'s>(items: impl Iterator<Item = &'s String>) -> AttrValue {
    AttrValue::List(
        items
            .map(|s| AttrValue::Text(PublicText::from_non_secret(s)))
            .collect(),
    )
}

/// `s` if it is a host name with an optional port: a registered name
/// (`[A-Za-z0-9._-]`) or an IPv6 literal in brackets, then optionally `:`
/// and 1 to 5 digits. Nothing else passes: no `@`, no second `:`, no
/// spaces. Anything else (user info, a whole line of a malformed file, which
/// might be a secret) is dropped.
pub fn host_name(s: &str) -> Option<&str> {
    if s.is_empty() || s.len() > MAX_HOST {
        return None;
    }
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']')?;
        let (host, port) = s.split_at(end + 1);
        let inner = &host[1..host.len() - 1];
        let ok = !inner.is_empty()
            && inner.contains(':')
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        (ok.then_some(host)?, port)
    } else {
        s.split_at(s.find(':').unwrap_or(s.len()))
    };
    let name_ok = host.starts_with('[')
        || (!host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)));
    let port_ok = match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(p) => (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()),
    };
    (name_ok && port_ok).then_some(s)
}

/// The parts of `scheme://[userinfo@]host[:port][/path]` lootr needs, as
/// found by [`split_url`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts<'a> {
    /// Byte range of the user info (`user:password`) in the input, without
    /// the `@`.
    pub userinfo: Option<std::ops::Range<usize>>,
    /// The host (with port), if it is unambiguous and passes [`host_name`].
    pub host: Option<&'a str>,
}

/// Splits a URL into user info and host, the one parser for every
/// credential type (so the password and the host can never overlap).
///
/// - The authority ends at the first `/`, `?` or `#`; inside it the user
///   info ends at the **last** `@` (RFC 3986: a host never contains `@`).
/// - Credential files are written by hand and are not strict URLs: a
///   password may contain an unencoded `/`, `?` or `#`
///   (`https://alice:s3cr#t@host`). When an `@` follows one of these
///   delimiters, the user info runs to the last `@` of the line, and no host
///   is reported: it cannot be told from a path, and guessing could put
///   password bytes into a report.
/// - Without any `@` there is no user info.
///
/// `None` if there is no `://`.
pub fn split_url(url: &[u8]) -> Option<UrlParts<'_>> {
    let url = url.strip_suffix(b"\r").unwrap_or(url);
    let start = url.windows(3).position(|w| w == b"://")? + 3;
    let rest = &url[start..];
    let is_delim = |b: &u8| matches!(*b, b'/' | b'?' | b'#');
    let auth_end = rest.iter().position(is_delim).unwrap_or(rest.len());
    let (at, ambiguous) = match rest[..auth_end].iter().rposition(|&b| b == b'@') {
        Some(at) => (Some(at), false),
        None => match rest.iter().rposition(|&b| b == b'@') {
            Some(at) => (Some(at), true),
            None => (None, false),
        },
    };
    let host_part = match at {
        Some(at) => &rest[at + 1..],
        None => rest,
    };
    let host_end = host_part
        .iter()
        .position(is_delim)
        .unwrap_or(host_part.len());
    let host = if ambiguous {
        None
    } else {
        std::str::from_utf8(&host_part[..host_end])
            .ok()
            .and_then(host_name)
    };
    Some(UrlParts {
        userinfo: at.map(|at| start..start + at),
        host,
    })
}

/// The host (with port) of a URL: `https://user:pw@host:443/path` →
/// `host:443`. Never returns the user info. `None` if it is not a URL with
/// an unambiguous, valid host (see [`split_url`]).
pub fn url_host(url: &[u8]) -> Option<&str> {
    split_url(url)?.host
}

/// `a.b.c` as a key path.
pub fn key_path(parts: &[&str]) -> PublicText {
    PublicText::from_non_secret(&parts.join("."))
}

/// Decodes standard base64 (Docker and npm `auth` fields) into a wiped
/// buffer. `None` if it is not valid base64.
pub fn decode_base64(value: SecretSlice<'_>) -> Option<SecretBuf> {
    Base64Reader::new(value, Alphabet::Standard, value.len())
        .decode_all()
        .ok()
}

/// The password of a decoded `user:password` pair, as a new wiped buffer.
/// `None` without a `:` or with an empty password.
pub fn password_of(pair: &SecretBuf) -> Option<SecretBuf> {
    let bytes = pair.expose();
    let colon = bytes.iter().position(|&b| b == b':')?;
    let password = &bytes[colon + 1..];
    (!password.is_empty()).then(|| SecretBuf::copy_from(password))
}

/// Percent-decodes `value` (git credential URLs) into a wiped buffer, or
/// `None` if there is nothing to decode.
pub fn percent_decode(value: SecretSlice<'_>) -> Option<SecretBuf> {
    let bytes = value.expose();
    if !bytes.contains(&b'%') {
        return None;
    }
    let mut out = SecretBuf::with_capacity(bytes.len());
    let mut i = 0;
    // Decoded straight into the fixed-capacity buffer (never longer than
    // the input).
    let hex = |b: u8| (b as char).to_digit(16);
    let _ = out.fill_with(|free| -> Result<usize, ()> {
        let mut n = 0;
        while n < free.len() && i < bytes.len() {
            let b = bytes[i];
            let pair = (b == b'%')
                .then(|| bytes.get(i + 1..i + 3))
                .flatten()
                .and_then(|h| Some(hex(h[0])? * 16 + hex(h[1])?));
            match pair {
                Some(v) => {
                    free[n] = v as u8;
                    i += 3;
                }
                None => {
                    free[n] = b;
                    i += 1;
                }
            }
            n += 1;
        }
        Ok(n)
    });
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_urls() {
        assert_eq!(
            url_host(b"https://user:pw@github.com/x"),
            Some("github.com")
        );
        assert_eq!(
            url_host(b"https://gitlab.example:8443"),
            Some("gitlab.example:8443")
        );
        assert_eq!(url_host(b"http://[::1]:80/"), Some("[::1]:80"));
        assert_eq!(url_host(b"https://a b@host/"), Some("host"));
        assert_eq!(url_host(b"no url"), None);
        assert_eq!(url_host(b"https://bad host/"), None);
        assert_eq!(host_name("ok.example"), Some("ok.example"));
        assert_eq!(host_name("not ok"), None);
    }

    /// The reviewer's case and its relatives: user info never becomes a
    /// host, whatever delimiter the password contains.
    #[test]
    fn user_info_never_becomes_the_host() {
        for url in [
            &b"https://alice:s3cr#t@github.com"[..],
            b"https://alice:s3cr?t@github.com",
            b"https://alice:s3cr/t@github.com",
            b"https://alice:1234#x@github.com",
            b"https://alice:s3cr",
            b"https://alice:s3cr#t",
            b"https://alice@",
        ] {
            let host = url_host(url);
            assert!(
                host.is_none_or(|h| !h.contains("alice") && !h.contains("s3cr")),
                "{host:?}"
            );
        }
        let parts = split_url(b"https://alice:s3cr#t@github.com").unwrap();
        assert_eq!(parts.userinfo, Some(8..20));
        assert_eq!(parts.host, None);
        let parts = split_url(b"https://alice:pw@github.com/a@b").unwrap();
        assert_eq!(parts.userinfo, Some(8..16));
        assert_eq!(parts.host, Some("github.com"));
        assert_eq!(url_host(b"https://alice:1234"), Some("alice:1234"));
    }

    #[test]
    fn strict_host_names() {
        for ok in [
            "a.example",
            "a-b_c.d",
            "h:1",
            "h:65535",
            "[::1]",
            "[fe80::1]:22",
            "[::ffff:1.2.3.4]",
        ] {
            assert_eq!(host_name(ok), Some(ok), "{ok}");
        }
        for bad in [
            "", "u:pw", "h:", "h:123456", "h:1:2", "a@b", "[::1", "[]", "[x::1]", "[::1]x",
            "[::1]:", ":80", "a b", "h/x", "h#x",
        ] {
            assert_eq!(host_name(bad), None, "{bad}");
        }
        assert_eq!(host_name(&"a".repeat(254)), None);
    }

    #[test]
    fn creds_attrs() {
        let mut c = Creds::default();
        c.add(Some("b.example"));
        c.add(Some("a.example"));
        c.add(Some("a.example"));
        c.add(Some("junk line"));
        let mut a = Attrs::new();
        c.insert_attrs(&mut a);
        assert_eq!(a["inline_tokens"], AttrValue::Int(4));
        assert_eq!(a["hosts"].to_string(), "a.example, b.example");
    }

    #[test]
    fn decoding() {
        let pair = decode_base64(SecretSlice::new(b"dXNlcjpwYXNz")).unwrap();
        assert_eq!(password_of(&pair).unwrap().expose(), b"pass");
        let pair = decode_base64(SecretSlice::new(b"dXNlcg==")).unwrap();
        assert!(password_of(&pair).is_none());
        assert!(decode_base64(SecretSlice::new(b"!!")).is_none());
        let d = percent_decode(SecretSlice::new(b"a%40b%2Fc%zz%4")).unwrap();
        assert_eq!(d.expose(), b"a@b/c%zz%4");
        assert!(percent_decode(SecretSlice::new(b"plain")).is_none());
    }
}
