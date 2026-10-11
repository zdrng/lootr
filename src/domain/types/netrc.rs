//! `netrc`: `~/.netrc` (curl, git over HTTPS, ftp, Heroku, ...).
//!
//! Tokens separated by whitespace: `machine <host>`, `default`, `login`,
//! `password`, `account`, `port`, and `macdef <name>` followed by a macro
//! that runs to the next empty line (skipped). `"quoted"` tokens and `#`
//! comments are understood. Every `password` is a stored credential,
//! emitted as a nested value at `<host>.password` (`default.password`). A
//! `default` entry sends its credentials to every host without an entry.

use crate::domain::format::is_text;
use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds, key_path};
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "netrc";

pub const ATTRS: &[AttrSpec] = &[
    creds::INLINE_TOKENS,
    creds::HOSTS,
    AttrSpec::new(
        "default_entry",
        AttrKind::Bool,
        "a `default` entry: its credentials go to every host without an entry",
    ),
];

pub struct Netrc;

/// Byte ranges of the tokens of `bytes`.
fn tokens(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'"' {
            let start = i + 1;
            let end = bytes[start..]
                .iter()
                .position(|&c| c == b'"')
                .map_or(bytes.len(), |n| start + n);
            out.push(start..end);
            i = end + 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        out.push(start..i);
        // A macro body runs to the next empty line.
        if &bytes[start..i] == b"macdef" {
            let line_end = bytes[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(bytes.len(), |n| i + n);
            out.push(i..line_end);
            i = bytes[line_end..]
                .windows(2)
                .position(|w| w == b"\n\n")
                .map_or(bytes.len(), |n| line_end + n + 2);
        }
    }
    out
}

impl DocumentType for Netrc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a .netrc file: stored passwords per machine"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let bytes = doc.expose();
        let toks = tokens(bytes);
        let mut stored = Creds::default();
        let mut default_entry = false;
        let mut host: Option<&str> = None;
        let mut i = 0;
        while i < toks.len() {
            let word = &bytes[toks[i].clone()];
            let next = toks.get(i + 1).cloned();
            match word {
                b"machine" => {
                    host = next
                        .and_then(|r| std::str::from_utf8(&bytes[r]).ok())
                        .and_then(creds::host_name);
                    i += 2;
                }
                b"default" => {
                    default_entry = true;
                    host = Some("default");
                    i += 1;
                }
                b"password" | b"passwd" => {
                    if let Some(v) = next.and_then(|r| doc.slice(r))
                        && !v.is_empty()
                    {
                        stored.add(host.filter(|h| *h != "default"));
                        out.value(key_path(&[host.unwrap_or("-"), "password"]), v);
                    }
                    i += 2;
                }
                b"login" | b"account" | b"port" | b"macdef" => i += 2,
                _ => i += 1,
            }
        }
        let mut attrs = Attrs::new();
        stored.insert_attrs(&mut attrs);
        attrs.insert("default_entry", AttrValue::Bool(default_entry));
        out.fact(attrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    #[test]
    fn machines_passwords_and_macros() {
        let text = format!(
            "# comment password nope\nmachine api.github.com login octo password {CANARY}gh\n\
             machine ftp.example\n  login anonymous\n  password \"{CANARY} spaced\"\n\
             macdef init\n  password inside-macro\n  quit\n\n\
             default login guest password {CANARY}d\n"
        );
        let mut out = Emitter::default();
        Netrc
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_tokens"], AttrValue::Int(3));
        assert_eq!(a["hosts"].to_string(), "api.github.com, ftp.example");
        assert_eq!(a["default_entry"], AttrValue::Bool(true));
        let values: Vec<(String, Vec<u8>)> = out
            .values
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_slice().expose().to_vec()))
            .collect();
        assert_eq!(values[0].0, "api.github.com.password");
        assert_eq!(values[1].1, format!("{CANARY} spaced").into_bytes());
        assert_eq!(values[2].0, "default.password");
    }

    #[test]
    fn hostile_input() {
        let mut out = Emitter::default();
        Netrc
            .parse(SecretSlice::new(b"machine\npassword"), &mut out)
            .unwrap();
        assert_eq!(out.facts[0].1["inline_tokens"], AttrValue::Int(0));
        let mut out = Emitter::default();
        Netrc
            .parse(SecretSlice::new(b"\"unterminated macdef"), &mut out)
            .unwrap();
    }
}
