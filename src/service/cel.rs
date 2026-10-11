//! CEL: compiling rule conditions, checking them against a type's schema,
//! evaluating them over facts.
//!
//! Engine: the `cel` crate (cel-rust), stdlib only, `regex` feature only
//! (see PLAN.md, "Policy (CEL)").
//!
//! # What a condition sees
//!
//! - every attribute of the fact as a variable (`encrypted`, `bits`);
//! - `attrs`: a map of the same attributes, for optional ones:
//!   `has(attrs.lifetime_hours) && lifetime_hours > 24` (CEL's `has()` only
//!   works on field selections, not on bare variables);
//! - `type` and `source` (strings) and `location` (a map with `kind`
//!   = `"file" | "env" | "probe"` and `path`, `key_path`, `name` as present).
//!
//! Attributes are converted to CEL values: `Sym`, `Name`, `Text`, `Path` →
//! string, `List` → list, `Map` → map with string keys.
//!
//! # Load-time checks
//!
//! Every identifier is checked against the type's schema ([`compile`]):
//! unknown variables, unknown `attrs.<name>` fields and functions outside
//! the standard library are config errors. Comprehension variables
//! (`list.exists(x, ...)`) are in scope inside their macro only.
//!
//! # Limits
//!
//! CEL has no loops, but nested comprehensions over lists multiply
//! (`a.all(x, b.all(y, c.exists(z, ...)))`), and the parser recurses on
//! nesting. So [`compile`] rejects (as config errors) expressions longer
//! than [`MAX_EXPRESSION_LEN`] bytes, nested deeper than [`MAX_NESTING`]
//! brackets or [`MAX_AST_DEPTH`] AST levels, with comprehension macros
//! (`all`, `exists`, `exists_one`, `map`, `filter`) nested deeper than
//! [`MAX_COMPREHENSION_DEPTH`], or with list/map literals of more than
//! [`MAX_LITERAL_ELEMENTS`] elements. Fact lists are bounded by the types
//! (a few hundred items at most), so one condition costs at most about
//! `256² ` steps per fact.
//!
//! # Runtime
//!
//! An evaluation error (type mismatch, missing optional attribute without
//! `has()`) or a non-bool result is returned as `Err` and becomes a
//! `rule_error`: it never silently passes. CEL only ever sees facts, never
//! raw values, so error messages cannot contain secrets.

use std::collections::HashMap;
use std::sync::Arc;

use cel::common::ast::{EntryExpr, Expr};
use cel::{Context, Env, IdedExpr, Program, Value};

use crate::domain::model::{AttrValue, Fact, Location};
use crate::domain::types::{TypeInfo, attr_names};

/// Global functions of the standard environment (without `chrono`).
const GLOBAL_FUNCTIONS: &[&str] = &[
    "size",
    "matches",
    "string",
    "int",
    "uint",
    "double",
    "bytes",
    "bool",
    "type",
    "dyn",
    "optional.of",
    "optional.none",
];

/// Member functions (`x.f(...)`) of the standard environment.
const MEMBER_FUNCTIONS: &[&str] = &[
    "size",
    "contains",
    "startsWith",
    "endsWith",
    "matches",
    "hasValue",
    "value",
    "orValue",
];

/// Variables every condition can use besides the attributes.
const BUILTIN_VARIABLES: &[&str] = &["type", "source", "location", "attrs"];

/// Longest condition in bytes.
pub const MAX_EXPRESSION_LEN: usize = 4096;
/// Deepest nesting of `(`, `[` and `{` in a condition's text.
pub const MAX_NESTING: usize = 32;
/// Deepest AST (operators, calls, selections).
pub const MAX_AST_DEPTH: usize = 64;
/// Deepest nesting of comprehension macros (`all`, `exists`, `map`, ...).
pub const MAX_COMPREHENSION_DEPTH: usize = 2;
/// Most elements of one list or map literal.
pub const MAX_LITERAL_ELEMENTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CelError {
    #[error("invalid CEL expression: {0}")]
    Syntax(String),
    #[error("unknown attribute `{name}` for type `{type_}` (known: {known})")]
    UnknownAttribute {
        name: String,
        type_: String,
        known: String,
    },
    #[error("unknown function `{0}`")]
    UnknownFunction(String),
    #[error("expression too complex: {0}")]
    TooComplex(String),
}

/// The shared standard environment.
#[derive(Clone)]
pub struct Cel {
    env: Arc<Env>,
}

impl Default for Cel {
    fn default() -> Self {
        Cel::new()
    }
}

impl Cel {
    pub fn new() -> Cel {
        Cel {
            env: Arc::new(Env::stdlib()),
        }
    }
}

/// A compiled condition.
pub struct Condition {
    program: Program,
    env: Arc<Env>,
}

/// Compiles `source` and checks every identifier against `info`.
pub fn compile(cel: &Cel, source: &str, info: &TypeInfo) -> Result<Condition, CelError> {
    check_text(source)?;
    let program = cel
        .env
        .compile(source)
        .map_err(|e| CelError::Syntax(e.to_string().trim().to_string()))?;
    let mut scope = Vec::new();
    check(program.expression(), info, &mut scope, Depth::default())?;
    Ok(Condition {
        program,
        env: cel.env.clone(),
    })
}

fn unknown_attr(name: &str, info: &TypeInfo) -> CelError {
    CelError::UnknownAttribute {
        name: name.to_string(),
        type_: info.name.clone(),
        known: attr_names(info),
    }
}

/// Length and bracket nesting of the text, checked before parsing (the
/// parser recurses on nesting).
fn check_text(source: &str) -> Result<(), CelError> {
    if source.len() > MAX_EXPRESSION_LEN {
        return Err(CelError::TooComplex(format!(
            "longer than {MAX_EXPRESSION_LEN} bytes"
        )));
    }
    let mut depth = 0usize;
    let mut unary = 0usize;
    // Inside a string literal nothing nests (quote byte, escaped).
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for b in source.bytes() {
        if let Some(q) = quote {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                _ if b == q => quote = None,
                _ => {}
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = Some(b);
            unary = 0;
            continue;
        }
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        // Chains of unary operators (`!!!!x`, `- - -x`) nest like brackets.
        unary = match b {
            b'!' | b'-' => unary + 1,
            b' ' | b'\t' | b'\n' | b'\r' => unary,
            _ => 0,
        };
        if depth > MAX_NESTING || unary > MAX_NESTING {
            return Err(CelError::TooComplex(format!(
                "nested deeper than {MAX_NESTING} levels"
            )));
        }
    }
    Ok(())
}

/// Nesting while walking the AST.
#[derive(Clone, Copy, Default)]
struct Depth {
    ast: usize,
    comprehensions: usize,
}

/// Walks the AST. `scope` holds comprehension variables.
fn check(
    e: &IdedExpr,
    info: &TypeInfo,
    scope: &mut Vec<String>,
    depth: Depth,
) -> Result<(), CelError> {
    let mut depth = Depth {
        ast: depth.ast + 1,
        ..depth
    };
    if depth.ast > MAX_AST_DEPTH {
        return Err(CelError::TooComplex(format!(
            "nested deeper than {MAX_AST_DEPTH} levels"
        )));
    }
    let check = |e: &IdedExpr, scope: &mut Vec<String>, depth: Depth| check(e, info, scope, depth);
    match &e.expr {
        Expr::Ident(name) => {
            let known = scope.contains(name)
                || BUILTIN_VARIABLES.contains(&name.as_str())
                || info.attr(name).is_some();
            if !known {
                return Err(unknown_attr(name, info));
            }
        }
        Expr::Select(sel) => {
            // `attrs.<name>` must name an attribute of the type.
            if let Expr::Ident(root) = &sel.operand.expr
                && root == "attrs"
                && !scope.contains(root)
                && info.attr(&sel.field).is_none()
            {
                return Err(unknown_attr(&sel.field, info));
            }
            check(&sel.operand, scope, depth)?;
        }
        Expr::Call(call) => {
            let name = call.func_name.as_str();
            let operator =
                name.starts_with('_') || name.starts_with('@') || name == "!_" || name == "-_";
            let known = operator
                || match call.target {
                    Some(_) => MEMBER_FUNCTIONS.contains(&name),
                    None => GLOBAL_FUNCTIONS.contains(&name),
                };
            if !known {
                return Err(CelError::UnknownFunction(name.to_string()));
            }
            if let Some(target) = &call.target {
                check(target, scope, depth)?;
            }
            for arg in &call.args {
                check(arg, scope, depth)?;
            }
        }
        Expr::Comprehension(c) => {
            // The range and the initial value are outside the loop.
            check(&c.iter_range, scope, depth)?;
            check(&c.accu_init, scope, depth)?;
            depth.comprehensions += 1;
            if depth.comprehensions > MAX_COMPREHENSION_DEPTH {
                return Err(CelError::TooComplex(format!(
                    "comprehensions (all, exists, map, filter) nested deeper than \
                     {MAX_COMPREHENSION_DEPTH} levels"
                )));
            }
            let before = scope.len();
            scope.push(c.iter_var.clone());
            scope.extend(c.iter_var2.clone());
            scope.push(c.accu_var.clone());
            let result = [&c.loop_cond, &c.loop_step, &c.result]
                .into_iter()
                .try_for_each(|e| check(e, scope, depth));
            scope.truncate(before);
            result?;
        }
        Expr::List(list) => {
            literal_size(list.elements.len())?;
            for el in &list.elements {
                check(el, scope, depth)?;
            }
        }
        Expr::Map(map) => {
            literal_size(map.entries.len())?;
            for entry in &map.entries {
                match &entry.expr {
                    EntryExpr::MapEntry(m) => {
                        check(&m.key, scope, depth)?;
                        check(&m.value, scope, depth)?;
                    }
                    EntryExpr::StructField(f) => check(&f.value, scope, depth)?,
                }
            }
        }
        Expr::Struct(s) => {
            for entry in &s.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    check(&f.value, scope, depth)?;
                }
            }
        }
        Expr::Literal(_) | Expr::Unspecified => {}
    }
    Ok(())
}

fn literal_size(n: usize) -> Result<(), CelError> {
    if n > MAX_LITERAL_ELEMENTS {
        return Err(CelError::TooComplex(format!(
            "a list or map literal with more than {MAX_LITERAL_ELEMENTS} elements"
        )));
    }
    Ok(())
}

impl Condition {
    /// Evaluates the condition for `fact`. `Err` is a rule error.
    pub fn eval(&self, fact: &Fact) -> Result<bool, String> {
        let mut ctx = Context::with_env(self.env.clone());
        let mut attrs = HashMap::new();
        for (name, value) in &fact.attrs {
            let v = to_value(value);
            ctx.add_variable_from_value(*name, v.clone());
            attrs.insert(name.to_string(), v);
        }
        ctx.add_variable_from_value("attrs", attrs);
        ctx.add_variable_from_value("type", fact.type_.as_str());
        ctx.add_variable_from_value("source", fact.source.as_str());
        ctx.add_variable_from_value("location", location_value(&fact.location));
        match self.program.execute(&ctx) {
            Ok(Value::Bool(b)) => Ok(b),
            Ok(other) => Err(format!(
                "condition returned {:?} instead of a bool",
                other.type_of()
            )),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn to_value(v: &AttrValue) -> Value {
    match v {
        AttrValue::Bool(b) => Value::Bool(*b),
        AttrValue::Int(i) => Value::Int(*i),
        AttrValue::Sym(s) => Value::from(*s),
        AttrValue::Name(n) => Value::from(n.as_str()),
        AttrValue::Text(t) => Value::from(t.as_str()),
        AttrValue::Path(p) => Value::from(p.as_str()),
        AttrValue::List(items) => Value::from(items.iter().map(to_value).collect::<Vec<_>>()),
        AttrValue::Map(map) => {
            let m: HashMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.to_string(), to_value(v)))
                .collect();
            Value::from(m)
        }
    }
}

fn location_value(loc: &Location) -> Value {
    let mut m: HashMap<String, Value> = HashMap::new();
    m.insert("kind".into(), Value::from(loc.kind()));
    match loc {
        Location::File { path, key_path } => {
            m.insert("path".into(), Value::from(path.as_str()));
            if let Some(k) = key_path {
                m.insert("key_path".into(), Value::from(k.as_str()));
            }
        }
        Location::Env { name } | Location::Probe { name } => {
            m.insert("name".into(), Value::from(name.as_str()));
        }
    }
    Value::from(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::{Attrs, DisplayPath, Ident, PublicText};
    use crate::domain::types::test_types::registry;
    use std::path::Path;

    fn doc_fact(lines: i64, label: Option<&str>) -> Fact {
        let mut attrs = Attrs::new();
        attrs.insert("lines", AttrValue::Int(lines));
        attrs.insert("marked", AttrValue::Bool(true));
        attrs.insert("world_readable", AttrValue::Bool(false));
        if let Some(l) = label {
            attrs.insert("label", AttrValue::Text(PublicText::from_non_secret(l)));
        }
        Fact {
            type_: Ident::from_non_secret("test_doc").unwrap(),
            location: Location::File {
                path: DisplayPath::new(Path::new("/h/doc")),
                key_path: None,
            },
            source: Ident::from_non_secret("docs").unwrap(),
            attrs,
        }
    }

    fn compile_doc(src: &str) -> Result<Condition, CelError> {
        let info = registry().info("test_doc").unwrap();
        compile(&Cel::new(), src, &info)
    }

    fn eval(src: &str, fact: &Fact) -> Result<bool, String> {
        compile_doc(src).unwrap().eval(fact)
    }

    #[test]
    fn evaluates_attributes_and_builtins() {
        let f = doc_fact(3, Some("prod"));
        assert_eq!(eval("lines > 2 && marked", &f), Ok(true));
        assert_eq!(eval("!world_readable", &f), Ok(true));
        assert_eq!(
            eval(r#"type == "test_doc" && source == "docs""#, &f),
            Ok(true)
        );
        assert_eq!(eval(r#"location.kind == "file""#, &f), Ok(true));
        assert_eq!(eval(r#"location.path.startsWith("/h/")"#, &f), Ok(true));
        assert_eq!(eval(r#"label.matches("^pr")"#, &f), Ok(true));
        assert_eq!(eval("[1, 2].exists(x, x == lines - 1)", &f), Ok(true));
    }

    #[test]
    fn optional_attributes_need_has() {
        let without = doc_fact(1, None);
        assert_eq!(
            eval(r#"has(attrs.label) && label == "x""#, &without),
            Ok(false)
        );
        // Without has(): a rule error, never a silent pass.
        assert!(eval(r#"label == "x""#, &without).is_err());
    }

    #[test]
    fn type_errors_are_rule_errors() {
        let f = doc_fact(1, None);
        assert!(eval("lines > true", &f).is_err());
        let err = eval("lines", &f).unwrap_err();
        assert!(err.contains("instead of a bool"), "{err}");
    }

    #[test]
    fn schema_check_at_compile_time() {
        let err = compile_doc("bits < 3072").err().unwrap();
        assert!(
            matches!(&err, CelError::UnknownAttribute { name, .. } if name == "bits"),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("known: lines, marked, label, mode")
        );
        let err = compile_doc("has(attrs.nope)").err().unwrap();
        assert!(matches!(err, CelError::UnknownAttribute { name, .. } if name == "nope"));
        assert_eq!(
            compile_doc("foo(lines)").err(),
            Some(CelError::UnknownFunction("foo".into()))
        );
        assert_eq!(
            compile_doc("label.lowerAscii() == 'a'").err(),
            Some(CelError::UnknownFunction("lowerAscii".into()))
        );
        assert!(matches!(compile_doc("lines >"), Err(CelError::Syntax(_))));
        // Comprehension variables are only in scope inside the macro.
        assert!(compile_doc("[1].all(x, x > 0) && x > 0").is_err());
        assert!(compile_doc("[1].all(x, x > 0)").is_ok());
        assert!(compile_doc("{'a': 1}.exists(k, k == 'a')").is_ok());
    }

    #[test]
    fn maps_and_lists_convert() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            Ident::from_non_secret("packages").unwrap(),
            AttrValue::Sym("write"),
        );
        let v = to_value(&AttrValue::Map(map));
        let mut ctx = Context::default();
        ctx.add_variable_from_value("p", v);
        let p = Program::compile(r#"p["packages"] == "write""#).unwrap();
        assert_eq!(p.execute(&ctx), Ok(Value::Bool(true)));
    }

    /// Expressions that could cost a lot per fact (nested comprehensions,
    /// huge literals) or recurse deeply in the parser are config errors.
    #[test]
    fn complexity_limits() {
        let too_complex = |src: &str| matches!(compile_doc(src), Err(CelError::TooComplex(_)));
        // Two nested comprehensions are fine, three are not.
        assert!(compile_doc("[1, 2].all(x, [3].exists(y, x < y + lines))").is_ok());
        assert!(compile_doc("[1].map(x, x).all(y, [2].exists(z, y < z))").is_ok());
        assert!(too_complex(
            "[1].all(x, [2].all(y, [3].exists(z, x + y + z > lines)))"
        ));
        let list = |n: usize| format!("[{}]", vec!["1"; n].join(", "));
        assert!(compile_doc(&format!("lines in {}", list(MAX_LITERAL_ELEMENTS))).is_ok());
        assert!(too_complex(&format!(
            "lines in {}",
            list(MAX_LITERAL_ELEMENTS + 1)
        )));
        let map = (0..=MAX_LITERAL_ELEMENTS)
            .map(|i| format!("{i}: 1"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(too_complex(&format!("size({{{map}}}) > lines")));
        assert!(too_complex(&format!(
            "{}lines > 0{}",
            "(".repeat(MAX_NESTING + 1),
            ")".repeat(MAX_NESTING + 1)
        )));
        assert!(too_complex(&format!(
            "{}marked",
            "!".repeat(MAX_NESTING + 1)
        )));
        assert!(too_complex(&format!(
            "{}marked",
            "! ".repeat(MAX_NESTING + 1)
        )));
        assert!(too_complex(&format!(
            "lines > 0{}",
            " && lines > 0".repeat(MAX_EXPRESSION_LEN / 13 + 1)
        )));
        assert!(compile_doc(&format!("lines > 0{}", " || marked".repeat(40))).is_ok());
        // String literals do not nest.
        let dashes = "-".repeat(MAX_NESTING + 8);
        assert!(
            compile_doc(&format!(
                "label == \"{dashes}((\\\"[[\" || label == '{dashes}'"
            ))
            .is_ok()
        );
    }
}
