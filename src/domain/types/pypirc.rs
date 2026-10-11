//! `pypirc`: the Python packaging upload config (`~/.pypirc`, INI).
//!
//! Every section but `[distutils]` is a repository; a `password` (for
//! PyPI an API token, `pypi-...`) is a stored credential and emitted as a
//! nested value at `<section>.password`. The host comes from `repository`,
//! or is `upload.pypi.org` / `test.pypi.org` for the `pypi` / `testpypi`
//! sections.

use std::collections::BTreeMap;

use crate::domain::format::{ini, is_text};
use crate::domain::model::Attrs;
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{self, Creds, key_path};
use crate::domain::types::{AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "pypirc";

pub const ATTRS: &[AttrSpec] = &[creds::INLINE_TOKENS, creds::HOSTS];

pub struct Pypirc;

impl DocumentType for Pypirc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a .pypirc file: stored package index passwords and API tokens"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        is_text(head)
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let entries = ini::parse(doc);
        let mut hosts: BTreeMap<&str, &str> = BTreeMap::new();
        for e in &entries {
            if let Some(s) = e.section
                && e.key == "repository"
                && let Some(h) = creds::url_host(e.value.expose())
            {
                hosts.insert(s, h);
            }
        }
        let mut stored = Creds::default();
        for e in &entries {
            let Some(section) = e.section.filter(|s| *s != "distutils") else {
                continue;
            };
            if e.key != "password" || e.is_empty() {
                continue;
            }
            let host = hosts.get(section).copied().or(match section {
                "pypi" => Some("upload.pypi.org"),
                "testpypi" => Some("test.pypi.org"),
                _ => None,
            });
            stored.add(host);
            out.value(key_path(&[section, "password"]), e.value);
        }
        let mut attrs = Attrs::new();
        stored.insert_attrs(&mut attrs);
        out.fact(attrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::AttrValue;
    use crate::testing::CANARY;

    #[test]
    fn passwords_per_repository() {
        let text = format!(
            "[distutils]\nindex-servers =\n    pypi\n    private\n\n[pypi]\nusername = __token__\npassword = pypi-{CANARY}\n\n\
             [private]\nrepository = https://user@pkgs.corp.example/simple/\nusername = me\npassword = {CANARY}pw\n\n[testpypi]\nusername = x\n"
        );
        let mut out = Emitter::default();
        Pypirc
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        let a = &out.facts[0].1;
        assert!(!format!("{a:?}").contains(CANARY));
        assert_eq!(a["inline_tokens"], AttrValue::Int(2));
        assert_eq!(a["hosts"].to_string(), "pkgs.corp.example, upload.pypi.org");
        let keys: Vec<String> = out.values.iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(keys, ["pypi.password", "private.password"]);
    }

    /// `password: <base64>=` (configparser's `:` delimiter): found, and
    /// the value never leaks into the key path.
    #[test]
    fn colon_delimiter_with_padding() {
        let text = format!("[pypi]\npassword: {CANARY}QUJDRA==\n");
        let mut out = Emitter::default();
        Pypirc
            .parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        assert_eq!(out.facts[0].1["inline_tokens"], AttrValue::Int(1));
        let keys: Vec<String> = out.values.iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(keys, ["pypi.password"]);
        assert_eq!(
            out.values[0].1.as_slice().expose(),
            format!("{CANARY}QUJDRA==").as_bytes()
        );
    }
}
