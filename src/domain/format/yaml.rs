//! A bounded YAML loader on top of the `saphyr-parser` event stream.
//!
//! The parser only produces events; this module builds the tree itself, so
//! every limit is under lootr's control:
//!
//! - nesting deeper than [`MAX_DEPTH`] is an error (checked per event,
//!   before the parser's own stacks grow further);
//! - more than [`MAX_NODES`] nodes is an error;
//! - aliases are not copied: an alias points at the anchored node, so the
//!   tree is a DAG. Every node carries its **expanded** size (aliases
//!   counted in full); a document whose expanded size exceeds
//!   [`MAX_EXPANDED`] is an error. That stops alias bombs ("billion laughs")
//!   while the tree is built, and bounds every later traversal;
//! - an alias to a node that is not complete yet (a recursive structure) is
//!   an error;
//! - at most [`MAX_DOCUMENTS`] documents per file.
//!
//! The parser hands every scalar over as an owned `String`. Where the
//! scalar's source text (between quotes, for quoted scalars) is exactly the
//! value, the loader keeps a slice of the file instead and wipes the string;
//! scalars the parser had to rewrite (escapes, folding, block scalars) are
//! moved into a wiped [`SecretBuf`]. Best effort: the parser's own scratch
//! buffers are not wiped. Tags are ignored. Errors are static text, never
//! file content.

use std::borrow::Cow;
use std::collections::HashMap;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};
use zeroize::Zeroize;

use crate::domain::secret::{SecretBuf, SecretSlice};
use crate::domain::types::{NestedValue, ParseError};

/// Deepest nesting of sequences and mappings.
pub const MAX_DEPTH: usize = 64;
/// Most nodes (scalars, sequences, mappings) in one file.
pub const MAX_NODES: usize = 100_000;
/// Largest size of all documents with every alias expanded, in nodes.
pub const MAX_EXPANDED: u64 = 200_000;
/// Most documents (`---`) in one file.
pub const MAX_DOCUMENTS: usize = 64;

enum Text<'a> {
    Borrowed(&'a str),
    Owned(SecretBuf),
}

enum Node<'a> {
    Scalar { text: Text<'a>, plain: bool },
    Seq(Vec<usize>),
    Map(Vec<(usize, usize)>),
}

/// A parsed YAML file.
pub struct Yaml<'a> {
    nodes: Vec<Node<'a>>,
    docs: Vec<usize>,
}

struct Frame {
    map: bool,
    anchor: usize,
    children: Vec<usize>,
    weight: u64,
}

#[derive(Default)]
struct Builder<'a> {
    nodes: Vec<Node<'a>>,
    weights: Vec<u64>,
    anchors: HashMap<usize, usize>,
    stack: Vec<Frame>,
    docs: Vec<usize>,
    total: u64,
}

const TOO_LARGE: ParseError = ParseError("YAML document too large");

impl<'a> Builder<'a> {
    fn push(&mut self, node: Node<'a>, weight: u64, anchor: usize) -> Result<usize, ParseError> {
        if self.nodes.len() >= MAX_NODES {
            return Err(TOO_LARGE);
        }
        self.nodes.push(node);
        self.weights.push(weight);
        let id = self.nodes.len() - 1;
        if anchor != 0 {
            self.anchors.insert(anchor, id);
        }
        Ok(id)
    }

    /// Adds a finished node (or an alias target) to the open collection, or
    /// as a document root.
    fn add(&mut self, id: usize) -> Result<(), ParseError> {
        let weight = self.weights.get(id).copied().unwrap_or(1);
        match self.stack.last_mut() {
            Some(top) => {
                top.children.push(id);
                top.weight = top.weight.saturating_add(weight);
                if top.weight > MAX_EXPANDED {
                    return Err(ParseError("YAML alias expansion too large"));
                }
            }
            None => {
                if self.docs.len() >= MAX_DOCUMENTS {
                    return Err(ParseError("too many YAML documents"));
                }
                self.total = self.total.saturating_add(weight);
                if self.total > MAX_EXPANDED {
                    return Err(ParseError("YAML alias expansion too large"));
                }
                self.docs.push(id);
            }
        }
        Ok(())
    }
}

impl<'a> Yaml<'a> {
    pub fn parse(doc: SecretSlice<'a>) -> Result<Yaml<'a>, ParseError> {
        let text =
            std::str::from_utf8(doc.expose()).map_err(|_| ParseError("YAML is not UTF-8"))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut parser = Parser::new_from_str(text);
        let mut b = Builder::default();
        while let Some(event) = parser.next_event() {
            let (event, span) = event.map_err(|_| ParseError("invalid YAML"))?;
            match event {
                Event::StreamEnd => break,
                Event::Scalar(value, style, anchor, _) => {
                    let text = match value {
                        Cow::Borrowed(s) => Text::Borrowed(s),
                        Cow::Owned(s) => match source_text(text, span, style) {
                            Some(raw) if raw == s => {
                                s.into_bytes().zeroize();
                                Text::Borrowed(raw)
                            }
                            _ => Text::Owned(SecretBuf::take(s.into_bytes())),
                        },
                    };
                    let plain = style == ScalarStyle::Plain;
                    let id = b.push(Node::Scalar { text, plain }, 1, anchor)?;
                    b.add(id)?;
                }
                Event::Alias(anchor) => {
                    let id = *b
                        .anchors
                        .get(&anchor)
                        .ok_or(ParseError("YAML alias to an unknown or enclosing anchor"))?;
                    b.add(id)?;
                }
                Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                    if b.stack.len() >= MAX_DEPTH {
                        return Err(ParseError("YAML nested too deeply"));
                    }
                    b.stack.push(Frame {
                        map: matches!(event, Event::MappingStart(..)),
                        anchor,
                        children: Vec::new(),
                        weight: 1,
                    });
                }
                Event::SequenceEnd | Event::MappingEnd => {
                    let frame = b.stack.pop().ok_or(ParseError("invalid YAML"))?;
                    let node = if frame.map {
                        Node::Map(
                            frame
                                .children
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|[k, v]| (*k, *v))
                                .collect(),
                        )
                    } else {
                        Node::Seq(frame.children)
                    };
                    let id = b.push(node, frame.weight, frame.anchor)?;
                    b.add(id)?;
                }
                Event::Nothing
                | Event::StreamStart
                | Event::DocumentStart(_)
                | Event::DocumentEnd => {}
            }
        }
        Ok(Yaml {
            nodes: b.nodes,
            docs: b.docs,
        })
    }

    /// The root of the first document.
    pub fn root(&self) -> Option<Value<'_, 'a>> {
        self.docs.first().map(|&id| Value { yaml: self, id })
    }

    /// The roots of all documents.
    pub fn documents(&self) -> impl Iterator<Item = Value<'_, 'a>> {
        self.docs.iter().map(|&id| Value { yaml: self, id })
    }
}

/// The source text of a scalar: the span, without quotes for quoted
/// scalars. Only used if it equals the parsed value, so it does not matter
/// whether the span counts bytes or characters.
fn source_text(text: &str, span: Span, style: ScalarStyle) -> Option<&str> {
    let raw = text.get(span.start.index()..span.end.index())?;
    match style {
        ScalarStyle::Plain => Some(raw),
        ScalarStyle::SingleQuoted => raw.strip_prefix('\'')?.strip_suffix('\''),
        ScalarStyle::DoubleQuoted => raw.strip_prefix('"')?.strip_suffix('"'),
        _ => None,
    }
}

/// A node of a [`Yaml`] tree.
#[derive(Clone, Copy)]
pub struct Value<'y, 'a> {
    yaml: &'y Yaml<'a>,
    id: usize,
}

impl<'y, 'a> Value<'y, 'a> {
    fn node(&self) -> Option<&'y Node<'a>> {
        self.yaml.nodes.get(self.id)
    }

    fn at(&self, id: usize) -> Value<'y, 'a> {
        Value {
            yaml: self.yaml,
            id,
        }
    }

    pub fn is_map(&self) -> bool {
        matches!(self.node(), Some(Node::Map(_)))
    }

    pub fn is_seq(&self) -> bool {
        matches!(self.node(), Some(Node::Seq(_)))
    }

    /// The value of `key` in a mapping (the last one if the key repeats).
    pub fn get(&self, key: &str) -> Option<Value<'y, 'a>> {
        let Some(Node::Map(pairs)) = self.node() else {
            return None;
        };
        pairs
            .iter()
            .rev()
            .find(|(k, _)| self.at(*k).text() == Some(key))
            .map(|(_, v)| self.at(*v))
    }

    /// The pairs of a mapping (empty for other nodes).
    pub fn entries(&self) -> impl Iterator<Item = (Value<'y, 'a>, Value<'y, 'a>)> + use<'y, 'a> {
        let pairs: &'y [(usize, usize)] = match self.node() {
            Some(Node::Map(pairs)) => pairs,
            _ => &[],
        };
        let this = *self;
        pairs.iter().map(move |(k, v)| (this.at(*k), this.at(*v)))
    }

    /// The items of a sequence (empty for other nodes).
    pub fn items(&self) -> impl Iterator<Item = Value<'y, 'a>> + use<'y, 'a> {
        let items: &'y [usize] = match self.node() {
            Some(Node::Seq(items)) => items,
            _ => &[],
        };
        let this = *self;
        items.iter().map(move |id| this.at(*id))
    }

    /// The text of a scalar. **Only for non-secret data** (keys, names,
    /// flags): secret values leave through [`Value::secret`].
    pub fn text(&self) -> Option<&'y str> {
        match self.node()? {
            Node::Scalar {
                text: Text::Borrowed(s),
                ..
            } => Some(s),
            Node::Scalar {
                text: Text::Owned(b),
                ..
            } => std::str::from_utf8(b.expose()).ok(),
            _ => None,
        }
    }

    /// A plain `null` / `~` / empty scalar.
    pub fn is_null(&self) -> bool {
        match self.node() {
            Some(Node::Scalar { plain: true, .. }) => {
                matches!(self.text(), Some("" | "~" | "null" | "Null" | "NULL"))
            }
            _ => false,
        }
    }

    /// A plain boolean true. YAML 1.1 spellings (`yes`, `on`) count too:
    /// Kubernetes tools read YAML 1.1.
    pub fn is_true(&self) -> bool {
        match self.node() {
            Some(Node::Scalar { plain: true, .. }) => matches!(
                self.text(),
                Some(
                    "true"
                        | "True"
                        | "TRUE"
                        | "yes"
                        | "Yes"
                        | "YES"
                        | "on"
                        | "On"
                        | "ON"
                        | "y"
                        | "Y"
                )
            ),
            _ => false,
        }
    }

    /// A non-empty, non-null scalar as a value for the value types: a slice
    /// of the file, or a wiped copy of a rewritten scalar.
    pub fn secret(&self) -> Option<NestedValue<'a>> {
        if self.is_null() {
            return None;
        }
        match self.node()? {
            Node::Scalar {
                text: Text::Borrowed(s),
                ..
            } if !s.is_empty() => Some(NestedValue::Borrowed(SecretSlice::new(s.as_bytes()))),
            Node::Scalar {
                text: Text::Owned(b),
                ..
            } if !b.is_empty() => Some(NestedValue::Owned(SecretBuf::copy_from(b.expose()))),
            _ => None,
        }
    }

    /// Whether the node is a non-empty, non-null scalar.
    pub fn has_value(&self) -> bool {
        !self.is_null() && self.text().is_some_and(|t| !t.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Yaml<'_>, ParseError> {
        Yaml::parse(SecretSlice::new(text.as_bytes()))
    }

    #[test]
    fn mappings_sequences_and_scalars() {
        let text = "a: 1\nb:\n  - x\n  - 'y'\n  - \"z\\tq\"\nc: {d: true, e: ~}\n";
        let y = parse(text).unwrap();
        let root = y.root().unwrap();
        assert!(root.is_map());
        assert_eq!(root.get("a").unwrap().text(), Some("1"));
        let items: Vec<&str> = root
            .get("b")
            .unwrap()
            .items()
            .filter_map(|v| v.text())
            .collect();
        assert_eq!(items, ["x", "y", "z\tq"]);
        let c = root.get("c").unwrap();
        assert!(c.get("d").unwrap().is_true());
        assert!(c.get("e").unwrap().is_null());
        assert!(c.get("missing").is_none());
        assert_eq!(root.entries().count(), 3);
        // Borrowed scalars are slices of the input, rewritten ones copies.
        match root.get("a").unwrap().secret().unwrap() {
            NestedValue::Borrowed(s) => assert_eq!(s.expose().as_ptr(), text[3..].as_ptr()),
            NestedValue::Owned(_) => panic!("expected a slice"),
        }
        let esc = root.get("b").unwrap().items().nth(2).unwrap();
        assert!(matches!(esc.secret(), Some(NestedValue::Owned(_))));
        assert!(c.get("e").unwrap().secret().is_none());
        let q = root.get("b").unwrap().items().nth(1).unwrap();
        assert!(matches!(q.secret(), Some(NestedValue::Borrowed(_))));
        // Quoted "true" is a string, not a boolean.
        let y = parse("a: 'true'\n").unwrap();
        assert!(!y.root().unwrap().get("a").unwrap().is_true());
    }

    #[test]
    fn aliases_share_nodes() {
        let y = parse("base: &b {k: v}\nother: *b\n").unwrap();
        let root = y.root().unwrap();
        assert_eq!(
            root.get("other").unwrap().get("k").unwrap().text(),
            Some("v")
        );
        // Repeated keys: the last one wins.
        let y = parse("k: 1\nk: 2\n").unwrap();
        assert_eq!(y.root().unwrap().get("k").unwrap().text(), Some("2"));
    }

    #[test]
    fn billion_laughs_is_rejected() {
        let mut text = String::from(
            "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n",
        );
        for (name, prev) in [
            ("b", "a"),
            ("c", "b"),
            ("d", "c"),
            ("e", "d"),
            ("f", "e"),
            ("g", "f"),
            ("h", "g"),
            ("i", "h"),
        ] {
            let refs = vec![format!("*{prev}"); 9].join(",");
            text.push_str(&format!("{name}: &{name} [{refs}]\n"));
        }
        assert_eq!(
            parse(&text).err(),
            Some(ParseError("YAML alias expansion too large"))
        );
        // A few levels are fine.
        let small: String = text.lines().take(3).map(|l| format!("{l}\n")).collect();
        assert!(parse(&small).is_ok());
    }

    #[test]
    fn limits() {
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(
            parse(&deep).err(),
            Some(ParseError("YAML nested too deeply"))
        );
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let block: String = (0..MAX_DEPTH + 2)
            .map(|i| format!("{}k:\n", "  ".repeat(i)))
            .collect();
        assert_eq!(
            parse(&block).err(),
            Some(ParseError("YAML nested too deeply"))
        );
        let many = "- x\n".repeat(MAX_NODES);
        assert_eq!(parse(&many).err(), Some(TOO_LARGE));
        let docs = "--- a\n".repeat(MAX_DOCUMENTS + 1);
        assert_eq!(
            parse(&docs).err(),
            Some(ParseError("too many YAML documents"))
        );
    }

    #[test]
    fn errors_carry_no_content() {
        assert_eq!(
            parse("a: [LOOTRCANARY").err(),
            Some(ParseError("invalid YAML"))
        );
        assert_eq!(
            parse("a: &x [*x]").err(),
            Some(ParseError("YAML alias to an unknown or enclosing anchor"))
        );
        assert!(parse("a: *nowhere").is_err());
        assert_eq!(
            Yaml::parse(SecretSlice::new(b"a: \xff")).err(),
            Some(ParseError("YAML is not UTF-8"))
        );
    }

    #[test]
    fn multiple_documents_and_bom() {
        let y = parse("\u{feff}a: 1\n---\nb: 2\n").unwrap();
        assert_eq!(y.documents().count(), 2);
        assert_eq!(y.root().unwrap().get("a").unwrap().text(), Some("1"));
        assert!(parse("").unwrap().root().is_none());
    }
}
