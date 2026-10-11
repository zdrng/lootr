//! `json`: JSON files → `config_entry` per string value, key path `a.b.0.c`
//! (see [`crate::domain::format::json::walk`]).

use crate::domain::extract::{CONFIG_ENTRY, Coverage, Entry, Extractor};
use crate::domain::format::json::{strip_bom, walk};
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub struct Json;

impl Extractor for Json {
    fn name(&self) -> &'static str {
        "json"
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
        let mut de = serde_json::Deserializer::from_slice(strip_bom(doc.expose()));
        let coverage = walk(&mut de, out).map_err(|_| ParseError("invalid JSON"))?;
        de.end().map_err(|_| ParseError("invalid JSON"))?;
        Ok(coverage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_leaves() {
        let text = br#"{"credentials":{"app.terraform.io":{"token":"abc"}},"n":1}"#;
        let mut out = Vec::new();
        Json.extract(SecretSlice::new(text), &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key.as_str(), "credentials.app.terraform.io.token");
        let mut out = Vec::new();
        assert!(Json.extract(SecretSlice::new(b"{} x"), &mut out).is_err());
    }

    /// Values deeper than the walk goes are reported, not dropped silently;
    /// long key paths are cut, not dropped.
    #[test]
    fn deep_values_are_reported_and_long_keys_kept() {
        let deep = format!("{}\"tok\"{}", "{\"a\":".repeat(70), "}".repeat(70));
        let mut out = Vec::new();
        let coverage = Json
            .extract(SecretSlice::new(deep.as_bytes()), &mut out)
            .unwrap();
        assert!(out.is_empty());
        assert!(matches!(
            coverage,
            Coverage::Partial {
                reason: "truncated",
                ..
            }
        ));
        let long = format!("{{\"{}\":\"tok\"}}", "k".repeat(300));
        let mut out = Vec::new();
        let coverage = Json
            .extract(SecretSlice::new(long.as_bytes()), &mut out)
            .unwrap();
        assert_eq!(coverage, Coverage::Complete);
        assert_eq!(out.len(), 1);
        assert!(out[0].key.as_str().ends_with("..."));
    }
}
