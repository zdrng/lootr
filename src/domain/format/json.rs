//! JSON documents (`serde_json`) and a format-independent walker over
//! serde data (`json` and `toml` extractors).
//!
//! - [`parse`] deserializes a document into a type's own structs. Fields
//!   that may hold secrets are [`SecretValue`]s: a slice of the file when
//!   the JSON string has no escapes (serde borrows it), otherwise a wiped
//!   copy. Non-secret text is [`PlainText`]. Both accept any JSON type, so a
//!   field of an unexpected type is ignored instead of failing the file.
//! - `serde_json` stops at 128 nested levels; errors are mapped to static
//!   text (serde's messages can quote input).
//! - [`walk`] visits every string leaf of any self-describing serde format
//!   and produces extractor entries with dotted key paths (`a.b.0.c`).
//!
//! Best effort: `serde_json` unescapes strings in a scratch buffer of its
//! own, which is not wiped.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::domain::extract::{Coverage, Entry, MAX_ENTRIES, key_ident};
use crate::domain::secret::{SecretBuf, SecretSlice};
use crate::domain::types::{NestedValue, ParseError};

/// The document without a UTF-8 byte order mark (the Azure CLI writes one).
pub fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// The first byte that is not whitespace (after a byte order mark).
pub fn first_byte(head: &[u8]) -> Option<u8> {
    strip_bom(head)
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}

/// Deserializes a JSON document.
pub fn parse<'a, T: Deserialize<'a>>(doc: SecretSlice<'a>) -> Result<T, ParseError> {
    serde_json::from_slice(strip_bom(doc.expose())).map_err(|_| ParseError("invalid JSON"))
}

/// A string that may be secret. Other JSON types are [`SecretValue::Absent`].
#[derive(Default)]
pub enum SecretValue<'a> {
    #[default]
    Absent,
    Borrowed(&'a [u8]),
    Owned(SecretBuf),
}

impl<'a> SecretValue<'a> {
    /// A non-empty string.
    pub fn is_set(&self) -> bool {
        !self.as_slice().is_none_or(|s| s.is_empty())
    }

    pub fn as_slice(&self) -> Option<SecretSlice<'_>> {
        match self {
            SecretValue::Absent => None,
            SecretValue::Borrowed(b) => Some(SecretSlice::new(b)),
            SecretValue::Owned(b) => Some(b.as_slice()),
        }
    }

    /// The value for the value types (`None` if absent or empty).
    pub fn nested(self) -> Option<NestedValue<'a>> {
        if !self.is_set() {
            return None;
        }
        match self {
            SecretValue::Absent => None,
            SecretValue::Borrowed(b) => Some(NestedValue::Borrowed(SecretSlice::new(b))),
            SecretValue::Owned(b) => Some(NestedValue::Owned(b)),
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for SecretValue<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LeafVisitor(|leaf: Leaf<'de, '_>| match leaf {
            Leaf::Borrowed(s) => SecretValue::Borrowed(s.as_bytes()),
            Leaf::Transient(s) => SecretValue::Owned(SecretBuf::copy_from(s.as_bytes())),
            Leaf::Owned(s) => SecretValue::Owned(SecretBuf::take(s.into_bytes())),
            Leaf::Other => SecretValue::Absent,
        }))
    }
}

/// Non-secret text (an account type, an e-mail address of a service
/// account, a registry name). Other JSON types are `None`.
#[derive(Default)]
pub struct PlainText(pub Option<String>);

impl PlainText {
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl<'de> Deserialize<'de> for PlainText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LeafVisitor(|leaf: Leaf<'de, '_>| {
            PlainText(match leaf {
                Leaf::Borrowed(s) => Some(s.to_string()),
                Leaf::Transient(s) => Some(s.to_string()),
                Leaf::Owned(s) => Some(s),
                Leaf::Other => None,
            })
        }))
    }
}

/// What a leaf visitor saw.
enum Leaf<'de, 't> {
    Borrowed(&'de str),
    Transient(&'t str),
    Owned(String),
    Other,
}

/// Accepts any value: strings are handed to the closure, everything else
/// (numbers, booleans, null, arrays, objects) is skipped as `Leaf::Other`.
struct LeafVisitor<F>(F);

impl<'de, T, F: for<'t> FnOnce(Leaf<'de, 't>) -> T> Visitor<'de> for LeafVisitor<F> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<T, E> {
        Ok((self.0)(Leaf::Borrowed(v)))
    }
    fn visit_str<E>(self, v: &str) -> Result<T, E> {
        Ok((self.0)(Leaf::Transient(v)))
    }
    fn visit_string<E>(self, v: String) -> Result<T, E> {
        Ok((self.0)(Leaf::Owned(v)))
    }
    fn visit_bool<E>(self, _: bool) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_i64<E>(self, _: i64) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_u64<E>(self, _: u64) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_f64<E>(self, _: f64) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_unit<E>(self) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_none<E>(self) -> Result<T, E> {
        Ok((self.0)(Leaf::Other))
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok((self.0)(Leaf::Other))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok((self.0)(Leaf::Other))
    }
}

/// Deepest key path [`walk`] descends into; deeper values are skipped and
/// reported ([`Coverage::Partial`], `truncated`).
pub const MAX_WALK_DEPTH: usize = 64;

/// Visits every string leaf of a serde document and pushes it as an entry
/// with its dotted key path (`a.b.0.c`; array items by index). Numbers,
/// booleans and nulls are not values a secret hides in and are skipped.
/// Values nested deeper than [`MAX_WALK_DEPTH`] are not visited; the
/// result says so.
pub fn walk<'de, D: Deserializer<'de>>(
    d: D,
    out: &mut Vec<Entry<'de>>,
) -> Result<Coverage, D::Error> {
    let mut sink = Sink {
        out,
        too_deep: false,
    };
    Walk {
        path: String::new(),
        depth: 0,
        sink: &mut sink,
    }
    .deserialize(d)?;
    Ok(if sink.too_deep {
        Coverage::Partial {
            reason: "truncated",
            detail: "values nested deeper than 64 levels were not scanned",
        }
    } else {
        Coverage::Complete
    })
}

/// Where [`Walk`] puts entries, and whether it had to skip deep values.
struct Sink<'o, 'de> {
    out: &'o mut Vec<Entry<'de>>,
    too_deep: bool,
}

struct Walk<'s, 'o, 'de> {
    path: String,
    depth: usize,
    sink: &'s mut Sink<'o, 'de>,
}

impl<'o, 'de> Walk<'_, 'o, 'de> {
    fn child(&mut self, key: &str) -> Walk<'_, 'o, 'de> {
        let path = if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", self.path)
        };
        Walk {
            path,
            depth: self.depth + 1,
            sink: &mut *self.sink,
        }
    }

    fn push<E: de::Error>(self, value: NestedValue<'de>) -> Result<(), E> {
        if self.sink.out.len() >= MAX_ENTRIES {
            return Err(E::custom("too many entries"));
        }
        if let Some(key) = key_ident(&self.path) {
            self.sink.out.push(Entry { key, value });
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Walk<'_, '_, 'de> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_, '_, 'de> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<(), E> {
        self.push(NestedValue::Borrowed(SecretSlice::new(v.as_bytes())))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        self.push(NestedValue::Owned(SecretBuf::copy_from(v.as_bytes())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<(), E> {
        self.push(NestedValue::Owned(SecretBuf::take(v.into_bytes())))
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        let mut i = 0usize;
        loop {
            let more = if self.depth >= MAX_WALK_DEPTH {
                self.sink.too_deep = true;
                seq.next_element::<IgnoredAny>()?.is_some()
            } else {
                seq.next_element_seed(self.child(&i.to_string()))?.is_some()
            };
            if !more {
                return Ok(());
            }
            i += 1;
        }
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<PlainText>()? {
            match key.0 {
                Some(k) if self.depth < MAX_WALK_DEPTH => {
                    map.next_value_seed(self.child(&k))?;
                }
                Some(_) => {
                    self.sink.too_deep = true;
                    map.next_value::<IgnoredAny>()?;
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Doc<'a> {
        #[serde(borrow, default)]
        secret: SecretValue<'a>,
        #[serde(default)]
        name: PlainText,
    }

    #[test]
    fn secret_values_borrow_or_copy() {
        let text = br#"{"secret":"abc","name":"n","extra":[1,{"x":2}]}"#;
        let d: Doc<'_> = parse(SecretSlice::new(text)).unwrap();
        assert_eq!(d.name.as_deref(), Some("n"));
        match d.secret {
            SecretValue::Borrowed(b) => assert_eq!(b.as_ptr(), text[11..].as_ptr()),
            _ => panic!("expected a slice"),
        }
        let d: Doc<'_> = parse(SecretSlice::new(br#"{"secret":"a\nb","name":7}"#)).unwrap();
        assert!(matches!(d.secret, SecretValue::Owned(_)));
        assert!(d.name.as_deref().is_none());
        let d: Doc<'_> = parse(SecretSlice::new(b"\xEF\xBB\xBF{\"secret\":{\"a\":1}}")).unwrap();
        assert!(!d.secret.is_set());
        assert!(d.secret.nested().is_none());
        assert_eq!(
            parse::<Doc<'_>>(SecretSlice::new(b"{\"secret\": LOOTRCANARY")).err(),
            Some(ParseError("invalid JSON"))
        );
    }

    fn walked(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut de = serde_json::Deserializer::from_slice(text.as_bytes());
        walk(&mut de, &mut out).unwrap();
        out.iter()
            .map(|e| {
                (
                    e.key.to_string(),
                    String::from_utf8(e.value.as_slice().expose().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn walks_string_leaves() {
        assert_eq!(
            walked(
                r#"{"a":{"b":["x",{"c":"y"}],"n":1,"t":true,"z":null},"sp ace":"v","e":"q\"q"}"#
            ),
            [
                ("a.b.0".to_string(), "x".to_string()),
                ("a.b.1.c".to_string(), "y".to_string()),
                ("sp_ace".to_string(), "v".to_string()),
                ("e".to_string(), "q\"q".to_string()),
            ]
        );
        assert_eq!(walked(r#""top""#).len(), 0);
        // Too deep for the walker: skipped, not an error.
        let deep = format!("{}\"x\"{}", "[".repeat(100), "]".repeat(100));
        assert!(walked(&deep).is_empty());
    }

    #[test]
    fn walk_limits_entries() {
        let many = format!("[{}]", vec!["\"x\""; MAX_ENTRIES + 1].join(","));
        let mut out = Vec::new();
        let mut de = serde_json::Deserializer::from_slice(many.as_bytes());
        assert!(walk(&mut de, &mut out).is_err());
    }
}
