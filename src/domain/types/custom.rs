//! Value types defined in the config (`[[type]]` with a regex `pattern`).
//!
//! They only match by regex and get the generic [`CUSTOM_ATTRS`]. Matching
//! uses `regex::bytes` directly on the secret buffer (linear time, no
//! backtracking). A config can use custom types as an oracle for secret
//! values, which is why they are listed in the report header and why config
//! is as trusted as code.

use regex::bytes::{Regex, RegexBuilder};

use crate::domain::model::{AttrValue, Attrs, Ident};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrSpec, CUSTOM_ATTRS, ValueType, charset, entropy_bits, len_attr};

/// Compiled size limit for custom patterns.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

pub struct CustomType {
    name: Ident,
    pattern: String,
    regex: Regex,
}

impl CustomType {
    /// Compiles `pattern`; the error is the regex crate's message.
    pub fn new(name: Ident, pattern: &str) -> Result<CustomType, String> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(CustomType {
            name,
            pattern: pattern.to_string(),
            regex,
        })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl ValueType for CustomType {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn doc(&self) -> &str {
        "custom type from the config (regex)"
    }

    fn schema(&self) -> &[AttrSpec] {
        CUSTOM_ATTRS
    }

    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
        if !self.regex.is_match(value.expose()) {
            return None;
        }
        let mut attrs = Attrs::new();
        attrs.insert("length", AttrValue::Int(len_attr(value)));
        attrs.insert("entropy", AttrValue::Int(entropy_bits(value)));
        attrs.insert("charset", AttrValue::Sym(charset(value)));
        Some(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_and_describes() {
        let t = CustomType::new(
            Ident::from_non_secret("acme_api_key").unwrap(),
            "^acme_[A-Za-z0-9]{8}$",
        )
        .unwrap();
        assert!(t.classify(SecretSlice::new(b"acme_short")).is_none());
        let attrs = t.classify(SecretSlice::new(b"acme_abcd1234")).unwrap();
        assert_eq!(attrs["length"], AttrValue::Int(13));
        assert_eq!(attrs["charset"], AttrValue::Sym("base64url"));
        assert_eq!(t.pattern(), "^acme_[A-Za-z0-9]{8}$");
    }

    #[test]
    fn rejects_bad_patterns() {
        let name = Ident::from_non_secret("x").unwrap();
        assert!(CustomType::new(name.clone(), "(").is_err());
        assert!(CustomType::new(name, "a{1000}{1000}").is_err());
    }
}
