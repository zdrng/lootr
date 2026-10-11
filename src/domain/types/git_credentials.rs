//! `git_credentials`: the file of git's `store` credential helper
//! (`~/.git-credentials`, `~/.config/git/credentials`): one URL per line,
//! `https://user:password@host/path`, stored in plain text.
//!
//! The password (percent-decoded) is emitted as a nested value at the
//! host; the user name is not reported. Lines that are not such a URL are
//! ignored and never reported (they might be secrets themselves).
//!
//! The file is written by hand too, so passwords may contain unencoded `#`,
//! `?` or `/`. User info and host come from one parser
//! ([`creds::split_url`]): the user info ends at the last `@`, and when that
//! `@` follows a `/`, `?` or `#` no host is reported (key path `-`), so no
//! part of a user name or password can end up in `hosts` or a key path.

use crate::domain::format::is_text;
use crate::domain::model::{Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds};
use crate::domain::types::{AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "git_credentials";

pub const ATTRS: &[AttrSpec] = &[creds::INLINE_TOKENS, creds::HOSTS];

pub struct GitCredentials;

impl DocumentType for GitCredentials {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "git's plain-text credential store (git-credentials): one URL with password per line"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let bytes = doc.expose();
        let mut stored = Creds::default();
        let mut offset = 0;
        for line in bytes.split(|&b| b == b'\n') {
            let start = offset;
            offset += line.len() + 1;
            let Some(url) = creds::split_url(line) else {
                continue;
            };
            let Some(range) = password_range(line, &url) else {
                continue;
            };
            let Some(pw) = doc.slice(start + range.start..start + range.end) else {
                continue;
            };
            let host = url.host;
            stored.add(host);
            let path = PublicText::from_non_secret(host.unwrap_or("-"));
            match creds::percent_decode(pw) {
                Some(decoded) => out.owned_value(path, decoded),
                None => out.value(path, pw),
            }
        }
        let mut attrs = Attrs::new();
        stored.insert_attrs(&mut attrs);
        out.fact(attrs);
        Ok(())
    }
}

/// The password inside `scheme://user:password@host...`: from the first
/// `:` of the user info to its end (both from [`creds::split_url`], so the
/// password and the reported host never overlap).
fn password_range(line: &[u8], url: &creds::UrlParts<'_>) -> Option<std::ops::Range<usize>> {
    let userinfo = url.userinfo.clone()?;
    let colon = line[userinfo.clone()].iter().position(|&b| b == b':')?;
    let range = userinfo.start + colon + 1..userinfo.end;
    (!range.is_empty()).then_some(range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::AttrValue;
    use crate::testing::CANARY;

    #[test]
    fn urls_with_passwords() {
        let text = format!(
            "https://octo:{CANARY}gh@github.com\nhttps://ci%40corp:{CANARY}%2Fx@gitlab.corp.example:8443/group\r\n\
             https://nopassword@host.example\n{CANARY}-not-a-url\n"
        );
        let mut out = Emitter::default();
        GitCredentials
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_tokens"], AttrValue::Int(2));
        assert_eq!(
            a["hosts"].to_string(),
            "github.com, gitlab.corp.example:8443"
        );
        let values: Vec<(String, Vec<u8>)> = out
            .values
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_slice().expose().to_vec()))
            .collect();
        assert_eq!(
            values[0],
            ("github.com".to_string(), format!("{CANARY}gh").into_bytes())
        );
        assert_eq!(values[1].1, format!("{CANARY}/x").into_bytes());
    }

    /// Passwords with unencoded delimiters and other hostile lines: the
    /// hosts, key paths and Debug output never contain user name or password
    /// bytes, and the password is still found.
    #[test]
    fn hostile_lines_never_leak_into_hosts_or_key_paths() {
        let pw = format!("{CANARY}pw");
        let cases: Vec<(String, Option<&str>)> = vec![
            (format!("https://alice:{pw}#frag@github.com"), None),
            (format!("https://alice:{pw}?q@github.com/x"), None),
            (format!("https://alice:{pw}/seg@github.com"), None),
            (format!("https://alice:{pw}#a/b?c@github.com:443/p"), None),
            (
                format!("https://alice:{pw}@@github.com"),
                Some("github.com"),
            ),
            (
                format!("https://al@ice:{pw}@github.com"),
                Some("github.com"),
            ),
            (
                format!("https://alice:{pw}@github.com:443/a@b"),
                Some("github.com:443"),
            ),
            (
                format!("https://alice:{pw}@[::1]:8443/"),
                Some("[::1]:8443"),
            ),
            (format!("https://alice:{pw}@host:x{CANARY}"), None),
            (format!("https://alice:{pw}@ho st"), None),
            (format!("https://alice:{pw}@\r"), None),
            (format!("https://alice:{pw}#@"), None),
            (
                format!("https://:{pw}@gitlab.example\r"),
                Some("gitlab.example"),
            ),
        ];
        for (line, host) in cases {
            let mut out = Emitter::default();
            GitCredentials
                .parse(SecretSlice::new(line.as_bytes()), &mut out)
                .unwrap();
            let a = &out.facts[0].1;
            let shown = format!("{a:?} {:?}", out.facts);
            assert!(!shown.contains(CANARY), "{line}: {shown}");
            assert!(!shown.contains("alice"), "{line}: {shown}");
            assert_eq!(a["inline_tokens"], AttrValue::Int(1), "{line}");
            let expected = host.map(|h| h.to_string()).unwrap_or_default();
            assert_eq!(a["hosts"].to_string(), expected, "{line}");
            let (key, value) = &out.values[0];
            assert_eq!(key.as_str(), host.unwrap_or("-"), "{line}");
            assert!(!key.as_str().contains(CANARY));
            let value = String::from_utf8_lossy(value.as_slice().expose()).into_owned();
            assert!(value.contains(CANARY), "{line}: password found");
            assert!(!value.contains("alice"), "{line}: {value}");
        }
    }

    #[test]
    fn lines_without_a_password_are_not_counted() {
        for line in [
            "https://github.com/x@y",
            "https://user@host",
            "no url",
            "https://h/#@",
        ] {
            let mut out = Emitter::default();
            GitCredentials
                .parse(SecretSlice::new(line.as_bytes()), &mut out)
                .unwrap();
            assert_eq!(out.facts[0].1["inline_tokens"], AttrValue::Int(0), "{line}");
            assert!(out.values.is_empty(), "{line}");
        }
    }
}
