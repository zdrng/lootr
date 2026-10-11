//! `yaml`: YAML files → `config_entry` per scalar value, key path `a.b.0.c`
//! (array items by index; with several documents the key starts with the
//! document index). Uses the bounded loader in
//! [`crate::domain::format::yaml`] (depth, size and alias limits). Null
//! scalars and non-scalar keys are skipped.

use crate::domain::extract::{CONFIG_ENTRY, Coverage, Entry, Extractor, MAX_ENTRIES, key_ident};
use crate::domain::format::yaml::{MAX_DEPTH, Value, Yaml};
use crate::domain::secret::SecretSlice;
use crate::domain::types::ParseError;

pub struct YamlExtractor;

impl Extractor for YamlExtractor {
    fn name(&self) -> &'static str {
        "yaml"
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
        let yaml = Yaml::parse(doc)?;
        let several = yaml.documents().count() > 1;
        for (i, root) in yaml.documents().enumerate() {
            let prefix = if several {
                i.to_string()
            } else {
                String::new()
            };
            // Explicit stack instead of recursion; the loader already bounds
            // depth and the expanded size (aliases included).
            let mut stack = vec![(root, prefix, 0usize)];
            while let Some((node, path, depth)) = stack.pop() {
                if node.is_map() || node.is_seq() {
                    if depth >= MAX_DEPTH {
                        continue;
                    }
                    let mut children: Vec<(Value<'_, 'a>, String)> = Vec::new();
                    for (k, v) in node.entries() {
                        if let Some(k) = k.text() {
                            children.push((v, join(&path, k)));
                        }
                    }
                    for (n, v) in node.items().enumerate() {
                        children.push((v, join(&path, &n.to_string())));
                    }
                    // Reversed, so entries come out in file order.
                    stack.extend(children.into_iter().rev().map(|(v, p)| (v, p, depth + 1)));
                    continue;
                }
                let Some(value) = node.secret() else {
                    continue;
                };
                if out.len() >= MAX_ENTRIES {
                    return Err(ParseError("too many entries"));
                }
                if let Some(key) = key_ident(&path) {
                    out.push(Entry { key, value });
                }
            }
        }
        Ok(Coverage::Complete)
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        YamlExtractor
            .extract(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        out.iter().map(|e| e.key.to_string()).collect()
    }

    #[test]
    fn scalar_leaves_in_file_order() {
        assert_eq!(
            keys(":rubygems_api_key: abc\nlist:\n  - a\n  - {k: v, n: ~}\nempty:\n"),
            [":rubygems_api_key", "list.0", "list.1.k"]
        );
        assert_eq!(keys("a: 1\n---\nb: 2\n"), ["0.a", "1.b"]);
        assert!(keys("").is_empty());
    }

    #[test]
    fn aliases_are_bounded() {
        let mut text = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for (n, p) in [
            ("b", "a"),
            ("c", "b"),
            ("d", "c"),
            ("e", "d"),
            ("f", "e"),
            ("g", "f"),
        ] {
            text.push_str(&format!(
                "{n}: &{n} [{}]\n",
                vec![format!("*{p}"); 10].join(", ")
            ));
        }
        let mut out = Vec::new();
        assert!(
            YamlExtractor
                .extract(SecretSlice::new(text.as_bytes()), &mut out)
                .is_err()
        );
        // Within the expansion limit but over the entry limit.
        let text = "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n";
        let mut out = Vec::new();
        assert_eq!(
            YamlExtractor.extract(SecretSlice::new(text.as_bytes()), &mut out),
            Err(ParseError("too many entries"))
        );
    }
}
