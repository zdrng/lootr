//! Types: pure interpreters that turn secret bytes into non-secret facts.
//!
//! - A [`DocumentType`] interprets a whole file (SSH key, kubeconfig,
//!   workflow). It may emit facts and nested values (kubeconfig token → jwt).
//! - A [`ValueType`] classifies a single value (GitHub token, JWT, custom
//!   regex type).
//! - Entry types (`env_var`, `dotenv_entry`, ...) are the generic facts every
//!   value from an env var or an extractor produces, whatever it is
//!   classified as ([`ENTRY_ATTRS`]).
//! - Fact types are produced by probes (service layer) and only need a
//!   schema here, so rules can be validated against them.
//!
//! Every type declares its attributes ([`AttrSpec`]). Rules are checked
//! against these schemas when the config is loaded, and `lootr types` lists
//! them for policy authors. Facts from files additionally get
//! [`FILE_ATTRS`].
//!
//! Adding a type: implement the trait in its own file next to this one and
//! register it in [`Registry::builtin`].
//!
//! Built-in document types: [`ssh_key`] (`ssh_private_key`), [`pem`],
//! [`aws`] (`aws_credentials`), [`gcp`] (`gcp_credentials`), [`azure`]
//! (`azure_profile`), [`kubeconfig`], [`docker_config`], [`npmrc`],
//! [`pypirc`], [`netrc`], [`git_credentials`], [`gh_hosts`],
//! [`github_workflow`]. Value types: [`github_token`], [`gitlab_token`],
//! [`aws`] (`aws_access_key_id`), [`api_key`], [`jwt`]; custom regex types
//! from the config: [`custom`]. [`creds`] holds helpers shared by the
//! credential-file types.

pub mod api_key;
pub mod aws;
pub mod azure;
pub mod creds;
pub mod custom;
pub mod docker_config;
pub mod gcp;
pub mod gh_hosts;
pub mod git_credentials;
pub mod github_token;
pub mod github_workflow;
pub mod gitlab_token;
pub mod jwt;
pub mod kubeconfig;
pub mod netrc;
pub mod npmrc;
pub mod pem;
pub mod pypirc;
pub mod ssh_key;
pub mod waiver;

use std::collections::BTreeMap;

use crate::domain::extract::{self, Extractor};
use crate::domain::model::{AttrValue, Attrs, FileMeta, Ident, PublicText};
use crate::domain::secret::{SecretBuf, SecretSlice};

/// The value kind of an attribute (documentation and `lootr types`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrKind {
    Bool,
    Int,
    /// One of a fixed set of strings from the binary.
    Sym,
    Name,
    Text,
    Path,
    List,
    Map,
}

/// One attribute in a type's schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AttrSpec {
    pub name: &'static str,
    pub kind: AttrKind,
    pub doc: &'static str,
    /// Not every fact of the type has it; rules must test it with
    /// `has(attrs.<name>)` first.
    pub optional: bool,
}

impl AttrSpec {
    pub const fn new(name: &'static str, kind: AttrKind, doc: &'static str) -> AttrSpec {
        AttrSpec {
            name,
            kind,
            doc,
            optional: false,
        }
    }

    pub const fn optional(name: &'static str, kind: AttrKind, doc: &'static str) -> AttrSpec {
        AttrSpec {
            name,
            kind,
            doc,
            optional: true,
        }
    }
}

/// Names every rule can use besides the attributes (see `service::cel`).
pub const RESERVED_NAMES: &[&str] = &["type", "source", "location", "attrs"];

/// Generic attributes of every fact that comes from a file. For document
/// types they are always present; for values found in files (dotenv entries,
/// tokens in a kubeconfig) only when the value came from a file.
pub const FILE_ATTRS: &[AttrSpec] = &[
    AttrSpec::new("mode", AttrKind::Int, "permission bits, e.g. 0o600 = 384"),
    AttrSpec::new("world_readable", AttrKind::Bool, "others may read the file"),
    AttrSpec::new(
        "group_readable",
        AttrKind::Bool,
        "the group may read the file",
    ),
    AttrSpec::new(
        "owner_is_self",
        AttrKind::Bool,
        "owned by the scanning user",
    ),
    AttrSpec::new(
        "age_days",
        AttrKind::Int,
        "days since the last modification",
    ),
    AttrSpec::new("size", AttrKind::Int, "file size in bytes"),
    AttrSpec::new(
        "in_git_repo",
        AttrKind::Bool,
        "the file is inside a git work tree (a parent directory has `.git`)",
    ),
    AttrSpec::new(
        "gitignored",
        AttrKind::Bool,
        "the repository's .gitignore files or .git/info/exclude ignore the file \
         (false outside a repository; global excludes are not considered)",
    ),
];

/// Attributes of the generic entry types (`env_var`, `dotenv_entry`, ...).
pub const ENTRY_ATTRS: &[AttrSpec] = &[
    AttrSpec::new("name", AttrKind::Name, "variable or key name"),
    AttrSpec::new("length", AttrKind::Int, "value length in bytes"),
    AttrSpec::new(
        "entropy",
        AttrKind::Int,
        "estimated entropy of the value in bits (length × Shannon entropy per byte)",
    ),
    AttrSpec::new(
        "classified_as",
        AttrKind::List,
        "names of the value types that matched",
    ),
];

/// Generic attributes of values that matched a custom regex type.
pub const CUSTOM_ATTRS: &[AttrSpec] = &[
    AttrSpec::new("length", AttrKind::Int, "value length in bytes"),
    AttrSpec::new(
        "entropy",
        AttrKind::Int,
        "estimated entropy of the value in bits (length × Shannon entropy per byte)",
    ),
    AttrSpec::new(
        "charset",
        AttrKind::Sym,
        "digits | hex | alnum | base64 | base64url | printable | binary",
    ),
];

/// The generic entry type of every environment variable.
pub const ENV_VAR: &str = "env_var";

/// Why a document could not be parsed. Static text only, so a parse error
/// can never carry file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(pub &'static str);

/// A value found inside a document (or by an extractor), to be classified by
/// the value types.
pub enum NestedValue<'a> {
    /// A sub-slice of the document buffer.
    Borrowed(SecretSlice<'a>),
    /// A decoded copy (base64 in a Docker config, an escaped JSON string),
    /// wiped on drop.
    Owned(SecretBuf),
}

impl NestedValue<'_> {
    pub fn as_slice(&self) -> SecretSlice<'_> {
        match self {
            NestedValue::Borrowed(s) => *s,
            NestedValue::Owned(b) => b.as_slice(),
        }
    }
}

/// Collects what a [`DocumentType`] finds.
#[derive(Default)]
pub struct Emitter<'a> {
    /// Facts of the document type, optionally at a key path inside the file.
    pub facts: Vec<(Option<PublicText>, Attrs)>,
    /// Values to run through the value types, with their key path.
    pub values: Vec<(PublicText, NestedValue<'a>)>,
}

impl<'a> Emitter<'a> {
    pub fn fact(&mut self, attrs: Attrs) {
        self.facts.push((None, attrs));
    }

    pub fn fact_at(&mut self, key_path: PublicText, attrs: Attrs) {
        self.facts.push((Some(key_path), attrs));
    }

    pub fn value(&mut self, key_path: PublicText, value: SecretSlice<'a>) {
        self.values.push((key_path, NestedValue::Borrowed(value)));
    }

    pub fn owned_value(&mut self, key_path: PublicText, value: SecretBuf) {
        self.values.push((key_path, NestedValue::Owned(value)));
    }

    pub fn nested(&mut self, key_path: PublicText, value: NestedValue<'a>) {
        self.values.push((key_path, value));
    }
}

/// A whole-file type (SSH key, kubeconfig, workflow).
pub trait DocumentType: Send + Sync {
    fn name(&self) -> &'static str;
    fn doc(&self) -> &'static str;
    fn schema(&self) -> &'static [AttrSpec];
    /// Cheap check on the first bytes; `false` skips the file silently.
    fn sniff(&self, head: &[u8]) -> bool;
    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError>;
}

/// A single-value type (GitHub token, JWT, custom regex type).
pub trait ValueType: Send + Sync {
    fn name(&self) -> &str;
    fn doc(&self) -> &str;
    fn schema(&self) -> &[AttrSpec];
    /// `Some(attrs)` if the value is of this type.
    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Document,
    Value,
    Custom,
    Entry,
    Probe,
    /// Made from the config itself (`waiver`).
    Config,
}

/// What a rule can know about a type.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TypeInfo {
    pub name: String,
    pub kind: TypeKind,
    pub doc: String,
    /// The type's own attributes.
    pub attrs: Vec<AttrSpec>,
    /// Whether facts of this type may carry [`FILE_ATTRS`].
    pub file_attrs: bool,
}

impl TypeInfo {
    /// Own attributes plus file attributes where they apply.
    pub fn all_attrs(&self) -> impl Iterator<Item = &AttrSpec> {
        let file: &[AttrSpec] = if self.file_attrs { FILE_ATTRS } else { &[] };
        self.attrs.iter().chain(file.iter())
    }

    pub fn attr(&self, name: &str) -> Option<&AttrSpec> {
        self.all_attrs().find(|a| a.name == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("type `{0}` is defined twice")]
    Duplicate(String),
    #[error("type `{0}` uses the reserved attribute name `{1}`")]
    ReservedAttr(String, &'static str),
}

/// A fact-only type registered by a probe.
#[derive(Clone, Copy, Debug)]
pub struct FactType {
    pub name: &'static str,
    pub doc: &'static str,
    pub schema: &'static [AttrSpec],
}

/// All types and extractors known to a run: built-in plus custom types from
/// the config.
#[derive(Default)]
pub struct Registry {
    documents: Vec<Box<dyn DocumentType>>,
    values: Vec<Box<dyn ValueType>>,
    customs: Vec<custom::CustomType>,
    extractors: Vec<Box<dyn Extractor>>,
    fact_types: Vec<FactType>,
    config_types: Vec<FactType>,
}

impl Registry {
    /// Everything compiled into the binary. `now` is the Unix time the scan
    /// started (for time-dependent attributes such as JWT expiry).
    pub fn builtin(now: i64) -> Registry {
        Registry {
            documents: vec![
                Box::new(ssh_key::SshPrivateKey),
                Box::new(pem::Pem),
                Box::new(aws::AwsCredentials),
                Box::new(gcp::GcpCredentials),
                Box::new(azure::AzureProfile),
                Box::new(kubeconfig::Kubeconfig),
                Box::new(docker_config::DockerConfig),
                Box::new(npmrc::Npmrc),
                Box::new(pypirc::Pypirc),
                Box::new(netrc::Netrc),
                Box::new(git_credentials::GitCredentials),
                Box::new(gh_hosts::GhHosts),
                Box::new(github_workflow::GithubWorkflow),
            ],
            values: vec![
                Box::new(github_token::GithubToken),
                Box::new(gitlab_token::GitlabToken),
                Box::new(aws::AwsAccessKeyId),
                Box::new(api_key::ApiKey),
                Box::new(jwt::Jwt::new(now)),
            ],
            customs: Vec::new(),
            extractors: vec![
                Box::new(extract::dotenv::Dotenv),
                Box::new(extract::ini::Ini),
                Box::new(extract::json::Json),
                Box::new(extract::yaml::YamlExtractor),
                Box::new(extract::toml::Toml),
                Box::new(extract::content::Content),
            ],
            fact_types: Vec::new(),
            config_types: vec![waiver::FACT_TYPE],
        }
    }

    pub fn add_document(&mut self, t: Box<dyn DocumentType>) -> Result<(), RegistryError> {
        self.check_new(t.name(), t.schema())?;
        self.documents.push(t);
        Ok(())
    }

    pub fn add_value(&mut self, t: Box<dyn ValueType>) -> Result<(), RegistryError> {
        self.check_new(t.name(), t.schema())?;
        self.values.push(t);
        Ok(())
    }

    pub fn add_custom(&mut self, t: custom::CustomType) -> Result<(), RegistryError> {
        self.check_new(t.name(), t.schema())?;
        self.customs.push(t);
        Ok(())
    }

    pub fn add_extractor(&mut self, e: Box<dyn Extractor>) -> Result<(), RegistryError> {
        if self.extractor(e.name()).is_some() {
            return Err(RegistryError::Duplicate(e.name().to_string()));
        }
        // Several extractors may share an entry type; it must not clash with
        // another kind of type.
        if self
            .info(e.entry_type())
            .is_some_and(|i| i.kind != TypeKind::Entry)
        {
            return Err(RegistryError::Duplicate(e.entry_type().to_string()));
        }
        self.extractors.push(e);
        Ok(())
    }

    pub fn add_fact_type(&mut self, t: FactType) -> Result<(), RegistryError> {
        self.check_new(t.name, t.schema)?;
        self.fact_types.push(t);
        Ok(())
    }

    fn check_new(&self, name: &str, schema: &[AttrSpec]) -> Result<(), RegistryError> {
        if self.info(name).is_some() {
            return Err(RegistryError::Duplicate(name.to_string()));
        }
        for attr in schema {
            if let Some(r) = RESERVED_NAMES.iter().find(|r| **r == attr.name) {
                return Err(RegistryError::ReservedAttr(name.to_string(), r));
            }
        }
        Ok(())
    }

    pub fn document(&self, name: &str) -> Option<&dyn DocumentType> {
        self.documents
            .iter()
            .find(|t| t.name() == name)
            .map(|t| t.as_ref())
    }

    pub fn extractor(&self, name: &str) -> Option<&dyn Extractor> {
        self.extractors
            .iter()
            .find(|e| e.name() == name)
            .map(|e| e.as_ref())
    }

    pub fn extractors(&self) -> impl Iterator<Item = &dyn Extractor> {
        self.extractors.iter().map(|e| e.as_ref())
    }

    /// Built-in value types first, then custom types.
    pub fn value_types(&self) -> impl Iterator<Item = &dyn ValueType> {
        let builtin = self.values.iter().map(|t| t.as_ref());
        builtin.chain(self.customs.iter().map(|t| t as &dyn ValueType))
    }

    /// Custom types from the config (listed in the report header).
    pub fn custom_types(&self) -> &[custom::CustomType] {
        &self.customs
    }

    /// Schema of any type by name.
    pub fn info(&self, name: &str) -> Option<TypeInfo> {
        self.types().into_iter().find(|t| t.name == name)
    }

    /// Every type, in a stable order (`lootr types`).
    pub fn types(&self) -> Vec<TypeInfo> {
        let mut out = vec![entry_info(ENV_VAR, "an environment variable", false)];
        for e in &self.extractors {
            if !out.iter().any(|t| t.name == e.entry_type()) {
                out.push(entry_info(e.entry_type(), e.doc(), true));
            }
        }
        out.extend(self.documents.iter().map(|t| TypeInfo {
            name: t.name().to_string(),
            kind: TypeKind::Document,
            doc: t.doc().to_string(),
            attrs: t.schema().to_vec(),
            file_attrs: true,
        }));
        let values = self.values.iter().map(|t| (TypeKind::Value, t.as_ref()));
        let customs = self
            .customs
            .iter()
            .map(|t| (TypeKind::Custom, t as &dyn ValueType));
        out.extend(values.chain(customs).map(|(kind, t)| TypeInfo {
            name: t.name().to_string(),
            kind,
            doc: t.doc().to_string(),
            attrs: t.schema().to_vec(),
            file_attrs: true,
        }));
        let probes = self.fact_types.iter().map(|t| (TypeKind::Probe, t));
        let config = self.config_types.iter().map(|t| (TypeKind::Config, t));
        out.extend(probes.chain(config).map(|(kind, t)| TypeInfo {
            name: t.name.to_string(),
            kind,
            doc: t.doc.to_string(),
            attrs: t.schema.to_vec(),
            file_attrs: false,
        }));
        out
    }
}

fn entry_info(name: &str, doc: &str, file_attrs: bool) -> TypeInfo {
    TypeInfo {
        name: name.to_string(),
        kind: TypeKind::Entry,
        doc: doc.to_string(),
        attrs: ENTRY_ATTRS.to_vec(),
        file_attrs,
    }
}

/// [`FILE_ATTRS`] for a file, seen by user `uid` at Unix time `now`.
pub fn file_attrs(meta: &FileMeta, uid: u32, now: i64) -> Attrs {
    let mut attrs = Attrs::new();
    attrs.insert("mode", AttrValue::Int(i64::from(meta.mode & 0o7777)));
    attrs.insert("world_readable", AttrValue::Bool(meta.mode & 0o004 != 0));
    attrs.insert("group_readable", AttrValue::Bool(meta.mode & 0o040 != 0));
    attrs.insert("owner_is_self", AttrValue::Bool(meta.uid == uid));
    attrs.insert(
        "age_days",
        AttrValue::Int(now.saturating_sub(meta.mtime).max(0) / 86_400),
    );
    attrs.insert(
        "size",
        AttrValue::Int(i64::try_from(meta.size).unwrap_or(i64::MAX)),
    );
    attrs
}

/// [`ENTRY_ATTRS`] for a value.
pub fn entry_attrs(name: &Ident, value: SecretSlice<'_>, classified_as: &[&str]) -> Attrs {
    let mut attrs = Attrs::new();
    attrs.insert("name", AttrValue::Name(name.clone()));
    attrs.insert("length", AttrValue::Int(len_attr(value)));
    attrs.insert("entropy", AttrValue::Int(entropy_bits(value)));
    let list = classified_as
        .iter()
        .filter_map(|n| Ident::from_non_secret(n).ok())
        .map(AttrValue::Name)
        .collect();
    attrs.insert("classified_as", AttrValue::List(list));
    attrs
}

pub fn len_attr(value: SecretSlice<'_>) -> i64 {
    i64::try_from(value.len()).unwrap_or(i64::MAX)
}

/// Estimated entropy in bits: length × Shannon entropy per byte, rounded
/// down. A random 32-character hex string is about 128 bits, a random
/// 40-character base64 string about 200-240 bits.
pub fn entropy_bits(value: SecretSlice<'_>) -> i64 {
    let bytes = value.expose();
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    let per_byte: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum();
    (per_byte * len).floor() as i64
}

/// The `charset` attribute: the smallest of the usual alphabets that
/// contains every byte.
pub fn charset(value: SecretSlice<'_>) -> &'static str {
    let bytes = value.expose();
    let all = |f: fn(u8) -> bool| bytes.iter().all(|&b| f(b));
    if all(|b| b.is_ascii_digit()) {
        "digits"
    } else if all(|b| b.is_ascii_hexdigit()) {
        "hex"
    } else if all(|b| b.is_ascii_alphanumeric()) {
        "alnum"
    } else if all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
        "base64"
    } else if all(|b| b.is_ascii_alphanumeric() || b"-_=".contains(&b)) {
        "base64url"
    } else if all(|b| b.is_ascii_graphic() || b == b' ') {
        "printable"
    } else {
        "binary"
    }
}

/// Attribute names of a type, for error messages.
pub fn attr_names(info: &TypeInfo) -> String {
    let names: Vec<&str> = info.all_attrs().map(|a| a.name).collect();
    names.join(", ")
}

/// Sorted map helper for `AttrValue::Map`.
pub type AttrMap = BTreeMap<Ident, AttrValue>;

#[cfg(test)]
pub(crate) mod test_types {
    //! Minimal types for tests of the registry, collector and policy. They
    //! never produce anything derived from the secret part of their input.

    use super::*;

    /// Documents starting with `TESTDOC`; each line `key=value` becomes a
    /// nested value at `key`, plus one fact with `lines` and `marked`.
    pub struct TestDoc;

    pub const TEST_DOC_ATTRS: &[AttrSpec] = &[
        AttrSpec::new("lines", AttrKind::Int, "number of lines"),
        AttrSpec::new("marked", AttrKind::Bool, "has a `!` line"),
        AttrSpec::optional("label", AttrKind::Text, "text after `label:`"),
    ];

    impl DocumentType for TestDoc {
        fn name(&self) -> &'static str {
            "test_doc"
        }
        fn doc(&self) -> &'static str {
            "test document"
        }
        fn schema(&self) -> &'static [AttrSpec] {
            TEST_DOC_ATTRS
        }
        fn sniff(&self, head: &[u8]) -> bool {
            head.starts_with(b"TESTDOC")
        }
        fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
            let bytes = doc.expose();
            if bytes.ends_with(b"BROKEN") {
                return Err(ParseError("broken test document"));
            }
            let mut lines = 0;
            let mut marked = false;
            let mut label = None;
            let mut offset = 0;
            for line in bytes.split(|&b| b == b'\n') {
                lines += 1;
                if line == b"!" {
                    marked = true;
                }
                if let Some(l) = line.strip_prefix(b"label:") {
                    label = Some(PublicText::from_non_secret(&String::from_utf8_lossy(l)));
                }
                if let Some(eq) = line.iter().position(|&b| b == b'=') {
                    let key = String::from_utf8_lossy(&line[..eq]);
                    if let Some(v) = doc.slice(offset + eq + 1..offset + line.len()) {
                        out.value(PublicText::from_non_secret(&key), v);
                    }
                }
                offset += line.len() + 1;
            }
            let mut attrs = Attrs::new();
            attrs.insert("lines", AttrValue::Int(lines));
            attrs.insert("marked", AttrValue::Bool(marked));
            if let Some(l) = label {
                attrs.insert("label", AttrValue::Text(l));
            }
            out.fact(attrs);
            Ok(())
        }
    }

    /// Values starting with `tok_`.
    pub struct TestToken;

    pub const TEST_TOKEN_ATTRS: &[AttrSpec] = &[
        AttrSpec::new("kind", AttrKind::Sym, "`long` (> 10 bytes) or `short`"),
        AttrSpec::new("length", AttrKind::Int, "length"),
    ];

    impl ValueType for TestToken {
        fn name(&self) -> &str {
            "test_token"
        }
        fn doc(&self) -> &str {
            "test token"
        }
        fn schema(&self) -> &[AttrSpec] {
            TEST_TOKEN_ATTRS
        }
        fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs> {
            if !value.expose().starts_with(b"tok_") {
                return None;
            }
            let mut attrs = Attrs::new();
            let kind = if value.len() > 10 { "long" } else { "short" };
            attrs.insert("kind", AttrValue::Sym(kind));
            attrs.insert("length", AttrValue::Int(len_attr(value)));
            Some(attrs)
        }
    }

    /// A registry with only the test types and the `lines` test extractor.
    pub fn registry() -> Registry {
        let mut r = Registry::default();
        r.add_document(Box::new(TestDoc)).unwrap();
        r.add_value(Box::new(TestToken)).unwrap();
        r.add_extractor(Box::new(crate::domain::extract::test_extractors::Lines))
            .unwrap();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::test_types::*;
    use super::*;

    #[test]
    fn registry_lists_all_types() {
        let r = registry();
        let names: Vec<String> = r.types().into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["env_var", "line_entry", "test_doc", "test_token"]);
        let doc = r.info("test_doc").unwrap();
        assert!(doc.attr("lines").is_some());
        assert!(doc.attr("world_readable").is_some());
        assert!(r.info("env_var").unwrap().attr("world_readable").is_none());
        assert!(
            r.info("line_entry")
                .unwrap()
                .attr("world_readable")
                .is_some()
        );
        assert!(r.document("test_doc").is_some());
        assert!(r.extractor("lines").is_some());
    }

    #[test]
    fn registry_rejects_duplicates_and_reserved_names() {
        let mut r = registry();
        assert_eq!(
            r.add_value(Box::new(TestToken)),
            Err(RegistryError::Duplicate("test_token".into()))
        );
        const BAD: &[AttrSpec] = &[AttrSpec::new("type", AttrKind::Int, "")];
        let err = r.add_fact_type(FactType {
            name: "bad",
            doc: "",
            schema: BAD,
        });
        assert_eq!(err, Err(RegistryError::ReservedAttr("bad".into(), "type")));
        let err = r.add_fact_type(FactType {
            name: "env_var",
            doc: "",
            schema: &[],
        });
        assert_eq!(err, Err(RegistryError::Duplicate("env_var".into())));
    }

    #[test]
    fn builtin_types_have_unique_names_and_valid_schemas() {
        let mut r = Registry::builtin(0);
        let names: Vec<String> = r.types().into_iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            [
                "env_var",
                "dotenv_entry",
                "config_entry",
                "ssh_private_key",
                "pem",
                "aws_credentials",
                "gcp_credentials",
                "azure_profile",
                "kubeconfig",
                "docker_config",
                "npmrc",
                "pypirc",
                "netrc",
                "git_credentials",
                "gh_hosts",
                "github_workflow",
                "github_token",
                "gitlab_token",
                "aws_access_key_id",
                "api_key",
                "jwt",
                "waiver",
            ]
        );
        // Adding them again fails: the names are taken.
        assert!(r.add_document(Box::new(ssh_key::SshPrivateKey)).is_err());
        for t in r.types() {
            for a in t.all_attrs() {
                assert!(!RESERVED_NAMES.contains(&a.name), "{}: {}", t.name, a.name);
            }
        }
    }

    #[test]
    fn file_attributes() {
        let meta = FileMeta {
            kind: crate::domain::model::FileKind::File,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 42,
            mtime: 0,
            dev: 1,
            ino: 7,
        };
        let a = file_attrs(&meta, 1000, 3 * 86_400 + 5);
        assert_eq!(a["mode"], AttrValue::Int(0o644));
        assert_eq!(a["world_readable"], AttrValue::Bool(true));
        assert_eq!(a["group_readable"], AttrValue::Bool(true));
        assert_eq!(a["owner_is_self"], AttrValue::Bool(true));
        assert_eq!(a["age_days"], AttrValue::Int(3));
        assert_eq!(a["size"], AttrValue::Int(42));
        let a = file_attrs(
            &FileMeta {
                mode: 0o600,
                ..meta
            },
            0,
            0,
        );
        assert_eq!(a["world_readable"], AttrValue::Bool(false));
        assert_eq!(a["owner_is_self"], AttrValue::Bool(false));
    }

    #[test]
    fn entropy_and_charset() {
        let s = |b: &'static [u8]| SecretSlice::new(b);
        assert_eq!(entropy_bits(s(b"")), 0);
        assert_eq!(entropy_bits(s(b"aaaa")), 0);
        assert_eq!(entropy_bits(s(b"abcd")), 8);
        assert_eq!(entropy_bits(s(b"0123456789abcdef")), 64);
        assert_eq!(charset(s(b"123")), "digits");
        assert_eq!(charset(s(b"12ab")), "hex");
        assert_eq!(charset(s(b"xyZ9")), "alnum");
        assert_eq!(charset(s(b"ab+/==")), "base64");
        assert_eq!(charset(s(b"ab-_")), "base64url");
        assert_eq!(charset(s(b"a b!")), "printable");
        assert_eq!(charset(s(b"a\x00")), "binary");
    }

    #[test]
    fn entry_attributes() {
        let name = Ident::from_non_secret("X").unwrap();
        let a = entry_attrs(&name, SecretSlice::new(b"abcd"), &["test_token"]);
        assert_eq!(a["length"], AttrValue::Int(4));
        assert_eq!(
            a["classified_as"],
            AttrValue::List(vec![AttrValue::Name(
                Ident::from_non_secret("test_token").unwrap()
            )])
        );
    }
}
