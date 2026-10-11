//! `toml`: TOML files → `config_entry` per string value, key path `a.b.0.c`
//! (see [`crate::domain::format::json::walk`]). The `toml` parser stops at
//! about 80 nested levels; its error messages quote the input, so they are
//! replaced by static text.

use crate::domain::extract::{CONFIG_ENTRY, Coverage, Entry, Extractor};
use crate::domain::format::json::walk;
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub struct Toml;

impl Extractor for Toml {
    fn name(&self) -> &'static str {
        "toml"
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
        let text =
            std::str::from_utf8(doc.expose()).map_err(|_| ParseError("TOML is not UTF-8"))?;
        let de = toml::de::Deserializer::parse(text).map_err(|_| ParseError("invalid TOML"))?;
        walk(de, out).map_err(|_| ParseError("invalid TOML"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_leaves_borrow_where_possible() {
        let text = "[registry]\ntoken = \"abc\"\n[registries.x]\ntoken = \"a\\tb\"\nn = 1\n";
        let mut out = Vec::new();
        Toml.extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let keys: Vec<&str> = out.iter().map(|e| e.key.as_str()).collect();
        // Tables come out sorted by key.
        assert_eq!(keys, ["registries.x.token", "registry.token"]);
        assert_eq!(
            out[1].value.as_slice().expose().as_ptr(),
            text[20..].as_ptr()
        );
        assert_eq!(out[0].value.as_slice().expose(), b"a\tb");
        let mut out = Vec::new();
        assert_eq!(
            Toml.extract(SecretSlice::new(b"a = [LOOTRCANARY"), &mut out),
            Err(ParseError("invalid TOML"))
        );
        let deep = format!("a = {}{}", "[".repeat(200), "]".repeat(200));
        assert!(
            Toml.extract(SecretSlice::new(deep.as_bytes()), &mut out)
                .is_err()
        );
    }
}
