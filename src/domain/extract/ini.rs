//! `ini`: INI / properties files → `config_entry` per `key = value` line,
//! key `section.key` (see [`crate::domain::format::ini`] for the syntax).

use crate::domain::extract::{CONFIG_ENTRY, Coverage, Entry, Extractor, MAX_ENTRIES, key_ident};
use crate::domain::format::ini;
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub struct Ini;

impl Extractor for Ini {
    fn name(&self) -> &'static str {
        "ini"
    }

    fn entry_type(&self) -> &'static str {
        CONFIG_ENTRY
    }

    fn doc(&self) -> &'static str {
        "an entry of a config file read with the ini, json, yaml or toml extractor"
    }

    fn extract<'a>(
        &self,
        doc: SecretSlice<'a>,
        out: &mut Vec<Entry<'a>>,
    ) -> Result<Coverage, ParseError> {
        for e in ini::parse(doc) {
            if out.len() >= MAX_ENTRIES {
                return Err(ParseError("too many entries"));
            }
            let path = match e.section {
                Some(s) => format!("{s}.{}", e.key),
                None => e.key.to_string(),
            };
            if let Some(key) = key_ident(&path) {
                out.push(Entry::borrowed(key, e.value));
            }
        }
        Ok(Coverage::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_key_paths() {
        let text = "user=x\n[profile dev]\ntoken = abc\n";
        let mut out = Vec::new();
        Ini.extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let keys: Vec<&str> = out.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["user", "profile_dev.token"]);
        assert_eq!(out[1].value.as_slice().expose(), b"abc");
    }

    #[test]
    fn values_never_end_up_in_keys() {
        let text = "api_key: QUJDRA==\n[s]\ntoken: abc=def\n";
        let mut out = Vec::new();
        Ini.extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let keys: Vec<&str> = out.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["api_key", "s.token"]);
        assert_eq!(out[0].value.as_slice().expose(), b"QUJDRA==");
    }
}
