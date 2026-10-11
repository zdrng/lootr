//! `dotenv`: `.env` files → `dotenv_entry` per `KEY=value` line.
//!
//! Syntax (the common subset of dotenv implementations):
//!
//! - `KEY=value`, optionally prefixed with `export `; spaces around `=` are
//!   allowed; keys are `[A-Za-z_][A-Za-z0-9_.-]*`;
//! - blank lines and lines starting with `#` are ignored;
//! - unquoted values end at the line end or at ` #` (inline comment) and are
//!   trimmed;
//! - `'single'`, `"double"` and `` `backtick` `` quoted values may span
//!   lines; in double quotes `\"` does not end the value. Escapes are not
//!   resolved: the value is a slice of the file, never a copy;
//! - lines that are not an assignment are skipped, an unterminated quote
//!   runs to the end of its line.

use crate::domain::extract::{Coverage, Entry, Extractor, key_ident};
use crate::domain::model::Ident;
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub const NAME: &str = "dotenv";
pub const ENTRY_TYPE: &str = "dotenv_entry";

pub struct Dotenv;

impl Extractor for Dotenv {
    fn name(&self) -> &'static str {
        NAME
    }

    fn entry_type(&self) -> &'static str {
        ENTRY_TYPE
    }

    fn doc(&self) -> &'static str {
        "an entry of a .env file"
    }

    fn extract<'a>(
        &self,
        doc: SecretSlice<'a>,
        out: &mut Vec<Entry<'a>>,
    ) -> Result<Coverage, ParseError> {
        let bytes = doc.expose();
        let mut p = Parser { bytes, pos: 0 };
        while p.pos < bytes.len() {
            if let Some((key, range)) = p.line()
                && let Some(value) = doc.slice(range)
            {
                out.push(Entry::borrowed(key, value));
            }
        }
        Ok(Coverage::Complete)
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_blanks(&mut self) {
        while self.peek().is_some_and(is_blank) {
            self.pos += 1;
        }
    }

    /// Moves past the end of the current line.
    fn next_line(&mut self) {
        while let Some(b) = self.peek() {
            self.pos += 1;
            if b == b'\n' {
                break;
            }
        }
    }

    /// Parses one logical line; returns the entry if it is an assignment.
    fn line(&mut self) -> Option<(Ident, std::ops::Range<usize>)> {
        self.skip_blanks();
        if self.bytes[self.pos..].starts_with(b"export") {
            let after = self.bytes.get(self.pos + 6).copied();
            if after.is_some_and(is_blank) {
                self.pos += 6;
                self.skip_blanks();
            }
        }
        let key_start = self.pos;
        while self
            .peek()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            self.pos += 1;
        }
        let key = &self.bytes[key_start..self.pos];
        self.skip_blanks();
        let valid_key = key
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_');
        if !valid_key || self.peek() != Some(b'=') {
            self.next_line();
            return None;
        }
        self.pos += 1;
        self.skip_blanks();
        let range = match self.peek() {
            Some(q @ (b'"' | b'\'' | b'`')) => self.quoted(q),
            _ => self.unquoted(),
        };
        self.next_line();
        let key = std::str::from_utf8(key).ok()?;
        Some((key_ident(key)?, range))
    }

    fn quoted(&mut self, quote: u8) -> std::ops::Range<usize> {
        let start = self.pos + 1;
        let mut i = start;
        while i < self.bytes.len() {
            let b = self.bytes[i];
            if b == b'\\' && quote == b'"' {
                i += 2;
                continue;
            }
            if b == quote {
                self.pos = i + 1;
                return start..i;
            }
            i += 1;
        }
        // Unterminated: the rest of the line.
        self.pos = start;
        let end = self.line_end();
        self.pos = end;
        start..trim_end(self.bytes, start, end)
    }

    fn unquoted(&mut self) -> std::ops::Range<usize> {
        let start = self.pos;
        let mut end = self.line_end();
        // ` #` starts a comment.
        if let Some(c) = self.bytes[start..end]
            .windows(2)
            .position(|w| is_blank(w[0]) && w[1] == b'#')
        {
            end = start + c;
        }
        self.pos = end;
        start..trim_end(self.bytes, start, end)
    }

    fn line_end(&self) -> usize {
        self.bytes[self.pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(self.bytes.len(), |n| self.pos + n)
    }
}

fn trim_end(bytes: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        Dotenv
            .extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        out.iter()
            .map(|e| {
                (
                    e.key.to_string(),
                    String::from_utf8(e.value.as_slice().expose().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn plain_assignments() {
        let text = "# comment\n\nA=1\nexport B = two words  \n  C=x # note\nD=a#b\nE=\r\nF=\n";
        assert_eq!(
            entries(text),
            pairs(&[
                ("A", "1"),
                ("B", "two words"),
                ("C", "x"),
                ("D", "a#b"),
                ("E", ""),
                ("F", "")
            ])
        );
    }

    #[test]
    fn quoted_values() {
        let text = "A='single # not a comment'\nB=\"dq \\\" esc\" # c\nC=\"multi\nline\"\nD=`bt`\nE=\"open\nF=after\n";
        assert_eq!(
            entries(text),
            pairs(&[
                ("A", "single # not a comment"),
                ("B", "dq \\\" esc"),
                ("C", "multi\nline"),
                ("D", "bt"),
                ("E", "open"),
                ("F", "after"),
            ])
        );
    }

    #[test]
    fn values_are_slices_of_the_file() {
        let text = "TOKEN=abc\n";
        let mut out = Vec::new();
        Dotenv
            .extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        assert_eq!(
            out[0].value.as_slice().expose().as_ptr(),
            text[6..].as_ptr()
        );
    }

    #[test]
    fn skips_non_assignments() {
        let text = "just text\n1A=x\n=x\nexport\nexportX=1\nkey.with-dash=ok\nü=x\n";
        assert_eq!(
            entries(text),
            pairs(&[("exportX", "1"), ("key.with-dash", "ok")])
        );
        assert!(entries("").is_empty());
        assert!(entries("A").is_empty());
    }
}
