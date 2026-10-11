//! INI-style files: AWS credentials and config, `.pypirc`, `.npmrc`,
//! `gradle.properties`, the `ini` extractor.
//!
//! The common subset of Python's `configparser`, npm's `ini` and Java
//! properties:
//!
//! - `[section]` headers (whitespace inside the brackets is trimmed);
//! - `key = value` or `key: value`, split at the **earliest** `=` or `:`
//!   ([`Delimiters::EqualsOrColon`], like Python's `configparser` and Java
//!   properties): `api_key: QUJDRA==` is key `api_key`, value `QUJDRA==`;
//!   `role_arn = arn:aws:...` is key `role_arn`. npm's parser splits at the
//!   first `=` only ([`Delimiters::Equals`]), because its keys contain `:`
//!   (`//registry.npmjs.org/:_authToken=...`, `@scope:registry=...`); the
//!   `npmrc` type uses that dialect. A value never ends up in a key;
//! - lines starting with `#` or `;` are comments, and so is everything from
//!   a ` #` / ` ;` (whitespace first) in a value;
//! - a value in matching single or double quotes loses the quotes;
//! - an indented line continues the previous entry: if that entry's value is
//!   empty and the line is `key = value`, it is a sub-key (`s3 =` /
//!   `  max_concurrent_requests = 10` in AWS config → key
//!   `s3.max_concurrent_requests`); otherwise the line is appended to the
//!   value (`configparser` multi-line values);
//! - anything else is ignored; parsing never fails.
//!
//! Values are slices of the file. Section names and keys must be UTF-8 (they
//! are names, never secrets); lines where they are not are skipped.

use std::borrow::Cow;

use crate::domain::secret::SecretSlice;

/// One `key = value` line.
pub struct IniEntry<'a> {
    /// The section the entry is in (`None` before the first header).
    pub section: Option<&'a str>,
    pub key: Cow<'a, str>,
    pub value: SecretSlice<'a>,
}

impl IniEntry<'_> {
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

/// Where a line splits into key and value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delimiters {
    /// The earliest `=` or `:` (`configparser`, Java properties, AWS,
    /// `.pypirc`, the `ini` extractor).
    EqualsOrColon,
    /// The first `=` only (npm's `ini`: keys contain `:`).
    Equals,
}

/// Every entry of `doc`, in file order, split with
/// [`Delimiters::EqualsOrColon`].
pub fn parse(doc: SecretSlice<'_>) -> Vec<IniEntry<'_>> {
    parse_with(doc, Delimiters::EqualsOrColon)
}

/// Every entry of `doc`, in file order.
pub fn parse_with(doc: SecretSlice<'_>, delimiters: Delimiters) -> Vec<IniEntry<'_>> {
    let bytes = doc.expose();
    let mut out: Vec<IniEntry<'_>> = Vec::new();
    let mut section: Option<&str> = None;
    // Index (in `out`) of the entry an indented line may continue, and
    // whether its value was empty when it was written.
    let mut last: Option<(usize, bool)> = None;
    let mut offset = 0;
    for raw in bytes.split(|&b| b == b'\n') {
        let start = offset;
        offset += raw.len() + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let indented = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        let lead = line.len() - line.trim_ascii_start().len();
        let content = line.trim_ascii();
        if content.is_empty() {
            last = None;
            continue;
        }
        if content[0] == b'#' || content[0] == b';' {
            continue;
        }
        let content_start = start + lead;
        if indented && let Some((idx, was_empty)) = last {
            let sub = split_key(content, delimiters)
                .filter(|(_, v)| was_empty && content.contains(&b'=') && !v.is_empty());
            if let Some((key, value)) = sub {
                // `parent =` followed by indented `key = value` lines.
                let parent = out.get(idx).map(|e| e.key.to_string());
                if let (Some(parent), Ok(key)) = (parent, std::str::from_utf8(key))
                    && let Some(value) = value_slice(doc, content_start, content, value)
                {
                    out.push(IniEntry {
                        section,
                        key: Cow::Owned(format!("{parent}.{key}")),
                        value,
                    });
                }
            } else if let Some(e) = out.get_mut(idx) {
                // Continuation: the value now runs to the end of this line.
                let from = if e.value.is_empty() {
                    content_start
                } else {
                    offset_in(bytes, e.value)
                };
                if let Some(v) = doc.slice(from..content_start + content.len()) {
                    e.value = v;
                }
            }
            continue;
        }
        if content[0] == b'[' {
            last = None;
            if let Some(end) = content.iter().position(|&b| b == b']')
                && let Ok(name) = std::str::from_utf8(&content[1..end])
            {
                section = Some(name.trim());
            }
            continue;
        }
        let Some((key, value)) = split_key(content, delimiters) else {
            last = None;
            continue;
        };
        let Ok(key) = std::str::from_utf8(key) else {
            last = None;
            continue;
        };
        let Some(value) = value_slice(doc, content_start, content, value) else {
            last = None;
            continue;
        };
        last = Some((out.len(), value.is_empty()));
        out.push(IniEntry {
            section,
            key: Cow::Borrowed(key),
            value,
        });
    }
    out
}

/// Byte offset of `value` inside `bytes` (it is always a sub-slice).
fn offset_in(bytes: &[u8], value: SecretSlice<'_>) -> usize {
    (value.expose().as_ptr() as usize).saturating_sub(bytes.as_ptr() as usize)
}

/// `key` and the raw value bytes of a line, split at the earliest
/// delimiter.
fn split_key(content: &[u8], delimiters: Delimiters) -> Option<(&[u8], &[u8])> {
    let at = content.iter().position(|&b| match delimiters {
        Delimiters::EqualsOrColon => b == b'=' || b == b':',
        Delimiters::Equals => b == b'=',
    })?;
    let key = content[..at].trim_ascii();
    if key.is_empty() {
        return None;
    }
    Some((key, &content[at + 1..]))
}

/// The value as a slice of the document: trimmed, inline comment removed,
/// matching quotes removed.
fn value_slice<'a>(
    doc: SecretSlice<'a>,
    content_start: usize,
    content: &[u8],
    raw: &[u8],
) -> Option<SecretSlice<'a>> {
    let raw_start = content_start + (raw.as_ptr() as usize - content.as_ptr() as usize);
    let lead = raw.len() - raw.trim_ascii_start().len();
    let mut v = &raw[lead..];
    let mut start = raw_start + lead;
    let quoted = v.len() >= 2 && (v[0] == b'"' || v[0] == b'\'') && v[v.len() - 1] == v[0];
    if quoted {
        v = &v[1..v.len() - 1];
        start += 1;
    } else {
        if let Some(c) = v
            .windows(2)
            .position(|w| (w[0] == b' ' || w[0] == b'\t') && (w[1] == b'#' || w[1] == b';'))
        {
            v = &v[..c];
        }
        v = v.trim_ascii_end();
    }
    doc.slice(start..start + v.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<(Option<String>, String, String)> {
        parse(SecretSlice::new(text.as_bytes()))
            .iter()
            .map(|e| {
                (
                    e.section.map(str::to_string),
                    e.key.to_string(),
                    String::from_utf8(e.value.expose().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    fn e(section: Option<&str>, key: &str, value: &str) -> (Option<String>, String, String) {
        (
            section.map(str::to_string),
            key.to_string(),
            value.to_string(),
        )
    }

    #[test]
    fn sections_keys_and_values() {
        let text = "top=1\n# c\n; c\n[ default ]\naws_access_key_id = AKIA # note\nkey: v:w\n\n[profile dev]\nregion=eu\nq = \"quoted # kept\"\n";
        assert_eq!(
            entries(text),
            [
                e(None, "top", "1"),
                e(Some("default"), "aws_access_key_id", "AKIA"),
                e(Some("default"), "key", "v:w"),
                e(Some("profile dev"), "region", "eu"),
                e(Some("profile dev"), "q", "quoted # kept"),
            ]
        );
    }

    fn npm_entries(text: &str) -> Vec<(Option<String>, String, String)> {
        parse_with(SecretSlice::new(text.as_bytes()), Delimiters::Equals)
            .iter()
            .map(|e| {
                (
                    e.section.map(str::to_string),
                    e.key.to_string(),
                    String::from_utf8(e.value.expose().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    /// The earliest delimiter wins: value bytes (base64 padding, URLs with
    /// `=`) never end up in the key.
    #[test]
    fn earliest_delimiter_splits() {
        let text = "api_key: QUJDRA==\npassword: abc=\nurl = https://h/?a=b\nk=v:w\n";
        assert_eq!(
            entries(text),
            [
                e(None, "api_key", "QUJDRA=="),
                e(None, "password", "abc="),
                e(None, "url", "https://h/?a=b"),
                e(None, "k", "v:w"),
            ]
        );
    }

    #[test]
    fn npm_keys_with_colons() {
        let text = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\r\n@scope:registry=https://npm.example/\n";
        assert_eq!(
            npm_entries(text),
            [
                e(None, "//registry.npmjs.org/:_authToken", "${NPM_TOKEN}"),
                e(None, "@scope:registry", "https://npm.example/"),
            ]
        );
    }

    #[test]
    fn sub_keys_and_continuations() {
        let text = "[default]\ns3 =\n  max_concurrent_requests = 10\n  region = x\nservers =\n    pypi\n    testpypi\nlong = a\n  b\nafter = 1\n";
        assert_eq!(
            entries(text),
            [
                e(Some("default"), "s3", ""),
                e(Some("default"), "s3.max_concurrent_requests", "10"),
                e(Some("default"), "s3.region", "x"),
                e(Some("default"), "servers", "pypi\n    testpypi"),
                e(Some("default"), "long", "a\n  b"),
                e(Some("default"), "after", "1"),
            ]
        );
    }

    #[test]
    fn values_are_slices_and_junk_is_ignored() {
        let text = "k = secret\n";
        let out = parse(SecretSlice::new(text.as_bytes()));
        assert_eq!(out[0].value.expose().as_ptr(), text[4..].as_ptr());
        assert!(entries("just words\n=novalue\n[unclosed\n  indented\n").is_empty());
        // A key that is not UTF-8 is skipped; values may be any bytes.
        let out = parse(SecretSlice::new(b"\xff=1\nk=\xfe\n"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value.expose(), b"\xfe");
    }
}
