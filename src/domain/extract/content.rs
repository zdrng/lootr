//! `content`: scans an arbitrary text file for embedded secrets (a hardcoded
//! token in source code, a key pasted into a YAML file, ...).
//!
//! The file is split into lines; every line into maximal runs of token
//! characters (ASCII letters, digits and `-_.+/~`, which cover base64,
//! base64url, hex and the punctuation token formats use; `=` and `:` split
//! runs, so `KEY=value` separates the name from the value). Each run is handed
//! to the value types, exactly like an environment variable, with the line
//! number as its key (`file.rs#L42`). Unlike the other extractors, `content`
//! does **not** emit a generic fact per run (see [`Extractor::generic_entry`]):
//! only the runs a value type recognized become facts, so the report is not
//! flooded with one entry per word.
//!
//! Binary files are not scanned (a NUL byte in the first [`BINARY_SNIFF`]
//! bytes): reported as skipped with reason `binary`. The file size is
//! already bounded by `max-file-size`. Runs shorter than [`MIN_TOKEN`] or
//! longer than [`MAX_TOKEN`] are ignored, and scanning stops after
//! [`MAX_ENTRIES`] runs: the runs found so far are classified and the file
//! is reported as skipped with reason `truncated` (not an error, not
//! silent).

use crate::domain::extract::{Coverage, Entry, Extractor, MAX_ENTRIES};
use crate::domain::model::Ident;
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub const NAME: &str = "content";
/// Content runs reuse the shared `config_entry` type for their (unused)
/// generic-fact slot; `generic_entry` is `false`, so none is ever emitted.
pub const ENTRY_TYPE: &str = super::CONFIG_ENTRY;

/// Bytes checked for a NUL before deciding a file is binary.
pub const BINARY_SNIFF: usize = 8192;
/// Shortest run handed to the value types (shorter strings are rarely keys
/// and would only add work).
pub const MIN_TOKEN: usize = 8;
/// Longest run considered (a base64 blob longer than this is not a token).
pub const MAX_TOKEN: usize = 4096;

pub struct Content;

impl Extractor for Content {
    fn name(&self) -> &'static str {
        NAME
    }

    fn entry_type(&self) -> &'static str {
        ENTRY_TYPE
    }

    fn doc(&self) -> &'static str {
        "a token-like run found while scanning a file's content for embedded secrets"
    }

    fn generic_entry(&self) -> bool {
        false
    }

    fn extract<'a>(
        &self,
        doc: SecretSlice<'a>,
        out: &mut Vec<Entry<'a>>,
    ) -> Result<Coverage, ParseError> {
        let bytes = doc.expose();
        if bytes[..bytes.len().min(BINARY_SNIFF)].contains(&0) {
            return Ok(Coverage::Partial {
                reason: "binary",
                detail: "a NUL byte in the first 8 KiB: not scanned as text",
            });
        }
        let mut line = 1u32;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\n' {
                line += 1;
                i += 1;
                continue;
            }
            if !is_token(b) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_token(bytes[i]) {
                i += 1;
            }
            let len = i - start;
            if (MIN_TOKEN..=MAX_TOKEN).contains(&len)
                && let Ok(key) = Ident::from_non_secret(&format!("L{line}"))
                && let Some(value) = doc.slice(start..i)
            {
                out.push(Entry::borrowed(key, value));
                if out.len() >= MAX_ENTRIES {
                    return Ok(Coverage::Partial {
                        reason: "truncated",
                        detail: "more than 10000 token runs: the rest of the file was not scanned",
                    });
                }
            }
        }
        Ok(Coverage::Complete)
    }
}

/// A character that may be part of a secret (base64, base64url, hex and the
/// punctuation token formats use).
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-_.+/~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(data: &[u8]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        Content.extract(SecretSlice::new(data), &mut out).unwrap();
        out.into_iter()
            .map(|e| {
                (
                    e.key.as_str().to_string(),
                    String::from_utf8_lossy(e.value.as_slice().expose()).into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn tokenizes_lines_and_records_line_numbers() {
        let data = b"let x = 5;\nconst token = \"abcdefghijklmnop\";\n";
        let got = runs(data);
        assert_eq!(got, [("L2".to_string(), "abcdefghijklmnop".to_string())]);
    }

    #[test]
    fn values_are_slices_of_the_input() {
        let data = b"API_KEY=sk-LOOTR0123456789abcdef";
        let out_strings = runs(data);
        // `sk-...` is one run (`-` is a token char); the whole run is kept.
        assert_eq!(out_strings[0].1, "sk-LOOTR0123456789abcdef");
    }

    #[test]
    fn short_runs_and_binary_files_are_skipped() {
        assert!(runs(b"a bb ccc dddd").is_empty()); // all shorter than MIN_TOKEN
        assert!(runs(b"text\x00with-a-long-enough-token-here").is_empty());
        let mut out = Vec::new();
        let coverage = Content
            .extract(
                SecretSlice::new(b"text\x00with-a-long-enough-token"),
                &mut out,
            )
            .unwrap();
        assert!(matches!(
            coverage,
            Coverage::Partial {
                reason: "binary",
                ..
            }
        ));
    }

    #[test]
    fn truncates_token_dense_input() {
        let mut data = Vec::new();
        for _ in 0..(MAX_ENTRIES + 100) {
            data.extend_from_slice(b"abcdefghij ");
        }
        let mut out = Vec::new();
        let coverage = Content.extract(SecretSlice::new(&data), &mut out).unwrap();
        assert_eq!(out.len(), MAX_ENTRIES);
        assert!(matches!(
            coverage,
            Coverage::Partial {
                reason: "truncated",
                ..
            }
        ));
    }
}
