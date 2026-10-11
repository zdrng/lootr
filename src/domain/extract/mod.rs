//! Extractors: split a file into named values (dotenv, ini, json, yaml,
//! toml). Pure functions over the file buffer; values are sub-slices of it.
//!
//! Every entry becomes a fact of the extractor's entry type (e.g.
//! `dotenv_entry`, with [`crate::domain::types::ENTRY_ATTRS`]) and is run
//! through all value types, exactly like an environment variable.
//!
//! Adding an extractor: implement [`Extractor`] in its own file here and
//! register it in [`crate::domain::types::Registry::builtin`].
//!
//! - [`dotenv`] - `.env` files → `dotenv_entry`
//! - [`ini`], [`json`], [`yaml`], [`toml`] - config files for custom file
//!   sources → `config_entry` (one shared entry type, keys are dotted
//!   paths: `section.key`, `a.b.0.c`)

pub mod content;
pub mod dotenv;
pub mod ini;
pub mod json;
pub mod toml;
pub mod yaml;

/// The entry type of the ini, json, yaml and toml extractors.
pub const CONFIG_ENTRY: &str = "config_entry";

use crate::domain::model::{IDENT_MAX_LEN, Ident};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{NestedValue, ParseError};

/// One named value inside a file.
pub struct Entry<'a> {
    /// Key or key path (`DATABASE_URL`, `profiles.default.token`). Keys are
    /// names, not secrets (see [`key_ident`]).
    pub key: Ident,
    /// A slice of the file, or a wiped copy where the format needed
    /// unescaping (JSON, TOML, YAML).
    pub value: NestedValue<'a>,
}

impl<'a> Entry<'a> {
    pub fn borrowed(key: Ident, value: SecretSlice<'a>) -> Entry<'a> {
        Entry {
            key,
            value: NestedValue::Borrowed(value),
        }
    }
}

/// The [`Ident`] for a key path: bytes an identifier cannot hold (spaces,
/// brackets, non-ASCII) become `_`. A path longer than an identifier may be
/// is cut and ends in `...`: the entry is still classified (a long key must
/// not hide its value). `None` only for an empty path.
pub fn key_ident(path: &str) -> Option<Ident> {
    let mut clean: String = path
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_-./:@+%".contains(&b) {
                char::from(b)
            } else {
                '_'
            }
        })
        .collect();
    if clean.len() > IDENT_MAX_LEN {
        // ASCII only after cleaning: any byte index is a char boundary.
        clean.truncate(IDENT_MAX_LEN - 3);
        clean.push_str("...");
    }
    Ident::from_non_secret(&clean).ok()
}

/// How much of a file an extractor looked at. Anything less than the whole
/// file is reported as skipped (with the reason) next to the entries that
/// were found: a partial scan must not look like a clean one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    /// Only part of the file (or none of it) was scanned. `reason` is a
    /// report code (`binary`, `truncated`), `detail` static text.
    Partial {
        reason: &'static str,
        detail: &'static str,
    },
}

/// Most entries one file may produce; more is a parse error (reported as
/// skipped), not a silent truncation.
pub const MAX_ENTRIES: usize = 10_000;

pub trait Extractor: Send + Sync {
    /// Name used in `extract = "..."`.
    fn name(&self) -> &'static str;
    /// Type of the generic fact every entry produces (`dotenv_entry`).
    fn entry_type(&self) -> &'static str;
    fn doc(&self) -> &'static str;
    /// Whether every entry also becomes a generic fact of [`Extractor::entry_type`].
    /// The `content` scanner sets this to `false`: it tokenizes arbitrary
    /// files and would otherwise flood the report with one fact per word; it
    /// keeps only the values that a value type recognized.
    fn generic_entry(&self) -> bool {
        true
    }
    /// Appends the file's entries to `out`. A file that cannot be parsed is
    /// an error (reported as skipped); one that was only partly scanned
    /// says so in the [`Coverage`].
    fn extract<'a>(
        &self,
        doc: SecretSlice<'a>,
        out: &mut Vec<Entry<'a>>,
    ) -> Result<Coverage, ParseError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_key_paths_are_cut_not_dropped() {
        let long = "a.".repeat(100) + "token";
        let key = key_ident(&long).unwrap();
        assert_eq!(key.as_str().len(), IDENT_MAX_LEN);
        assert!(key.as_str().ends_with("..."));
        assert_eq!(key_ident("a b[0]").unwrap().as_str(), "a_b_0_");
        assert!(key_ident("").is_none());
    }
}

#[cfg(test)]
pub(crate) mod test_extractors {
    use super::*;

    /// `KEY=value` per line; other lines are ignored. A file ending in
    /// `BROKEN` fails to parse.
    pub struct Lines;

    impl Extractor for Lines {
        fn name(&self) -> &'static str {
            "lines"
        }
        fn entry_type(&self) -> &'static str {
            "line_entry"
        }
        fn doc(&self) -> &'static str {
            "test extractor"
        }
        fn extract<'a>(
            &self,
            doc: SecretSlice<'a>,
            out: &mut Vec<Entry<'a>>,
        ) -> Result<Coverage, ParseError> {
            let bytes = doc.expose();
            if bytes.ends_with(b"BROKEN") {
                return Err(ParseError("broken test file"));
            }
            let mut offset = 0;
            for line in bytes.split(|&b| b == b'\n') {
                if let Some(eq) = line.iter().position(|&b| b == b'=') {
                    let key = std::str::from_utf8(&line[..eq]).ok();
                    let key = key.and_then(|k| Ident::from_non_secret(k).ok());
                    let value = doc.slice(offset + eq + 1..offset + line.len());
                    if let (Some(key), Some(value)) = (key, value) {
                        out.push(Entry::borrowed(key, value));
                    }
                }
                offset += line.len() + 1;
            }
            if bytes.ends_with(b"PARTIAL") {
                return Ok(Coverage::Partial {
                    reason: "truncated",
                    detail: "test: stopped early",
                });
            }
            Ok(Coverage::Complete)
        }
    }
}
