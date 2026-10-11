//! Facts, findings and the values they carry.
//!
//! The model is built so that secret material cannot reach a report:
//!
//! - [`AttrValue`] has no plain `String` variant. [`AttrValue::Sym`] is a
//!   `&'static str`, so it can only be a constant from the binary.
//! - Text that comes from scanned data must be wrapped in [`Ident`] or
//!   [`PublicText`], whose only constructors are named `from_non_secret`.
//!   Every call is a review point: types that parse secrets (tokens, keys)
//!   may not call them on the secret part.
//! - Facts never contain hashes of secrets (short tokens could be brute
//!   forced offline).
//!
//! # JSON shapes (part of the report, `schema_version` 1)
//!
//! - `Fact`: `{"type": "github_token", "location": {...}, "source": "dotenv",
//!   "attrs": {"kind": "classic", "length": 40}}`
//! - `Location`: `{"kind": "file", "path": "/home/u/.env", "key_path": "GH_TOKEN"}`
//!   (`key_path` only when set) | `{"kind": "env", "name": "GH_TOKEN"}` |
//!   `{"kind": "probe", "name": "process"}`
//! - `AttrValue`: plain JSON (`true`, `42`, `"rsa"`, `[...]`, `{...}`).
//! - `Severity`: `"info" | "low" | "medium" | "high" | "critical"`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize, Serializer};

/// Longest [`Ident`] in bytes.
pub const IDENT_MAX_LEN: usize = 128;
/// Longest [`PublicText`] in characters; longer text is cut.
pub const PUBLIC_TEXT_MAX_CHARS: usize = 256;

/// A validated identifier: rule ids, type names, source ids, env var names,
/// permission scopes, job ids. 1 to [`IDENT_MAX_LEN`] bytes of ASCII letters,
/// digits and `_ - . / : @ + %` (`%` for bash's exported functions,
/// `BASH_FUNC_name%%`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ident(String);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a valid identifier (1 to 128 characters: letters, digits, `_ - . / : @ + %`)"
)]
pub struct InvalidIdent(pub String);

impl Ident {
    /// The only constructor. `s` must not be secret material; see the module
    /// docs. The error message repeats `s`, so it must not be secret either.
    pub fn from_non_secret(s: &str) -> Result<Ident, InvalidIdent> {
        let valid = !s.is_empty()
            && s.len() <= IDENT_MAX_LEN
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-./:@+%".contains(&b));
        if valid {
            Ok(Ident(s.to_string()))
        } else {
            Err(InvalidIdent(PublicText::from_non_secret(s).0))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Ident {
    type Error = InvalidIdent;
    fn try_from(s: String) -> Result<Ident, InvalidIdent> {
        Ident::from_non_secret(&s)
    }
}

impl From<Ident> for String {
    fn from(i: Ident) -> String {
        i.0
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unicode format characters (category Cf: bidi embeddings, overrides and
/// isolates, zero-width spaces and joiners, the BOM, invisible operators,
/// tags, ...) and the line/paragraph separators. They are invisible or
/// reorder the text around them, so a scanned file name or key could hide
/// or disguise what a report says ("Trojan Source").
pub fn is_invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// Appends `c` made safe for display: a control character becomes U+FFFD,
/// an invisible format character a visible escape (`\u{202e}`), anything
/// else stays.
pub fn push_display_safe(out: &mut String, c: char) {
    if c.is_control() {
        out.push('\u{FFFD}');
    } else if is_invisible(c) {
        out.push_str(&format!("\\u{{{:x}}}", c as u32));
    } else {
        out.push(c);
    }
}

/// `s` with [`push_display_safe`] applied to every character.
pub fn display_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_display_safe(&mut out, c);
    }
    out
}

/// Non-secret free text from scanned data (a JWT issuer, a kube context
/// name, a key path). Control characters are replaced, invisible format
/// characters escaped (`\u{202e}`, see [`push_display_safe`]) and the text
/// is cut to [`PUBLIC_TEXT_MAX_CHARS`] characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PublicText(String);

impl PublicText {
    /// The only constructor. `s` must not be secret material; see the module
    /// docs.
    pub fn from_non_secret(s: &str) -> PublicText {
        let mut out = String::new();
        let mut chars = 0;
        let mut piece = String::new();
        for c in s.chars() {
            piece.clear();
            push_display_safe(&mut piece, c);
            let n = piece.chars().count();
            if chars + n > PUBLIC_TEXT_MAX_CHARS {
                // Cut, leaving room for the ellipsis.
                while chars >= PUBLIC_TEXT_MAX_CHARS {
                    out.pop();
                    chars -= 1;
                }
                out.push('…');
                return PublicText(out);
            }
            out.push_str(&piece);
            chars += n;
        }
        PublicText(out)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A path as shown in reports (lossy UTF-8, control characters replaced,
/// invisible format characters escaped, see [`push_display_safe`]). Paths
/// are not secret; `--redact-paths` (M5) hides them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DisplayPath(String);

impl DisplayPath {
    pub fn new(path: &Path) -> DisplayPath {
        DisplayPath(display_safe(&path.to_string_lossy()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An attribute value of a fact. Deliberately no plain `String` variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttrValue {
    Bool(bool),
    Int(i64),
    /// Closed vocabulary from the binary: `"classic"`, `"rsa"`, `"write"`.
    Sym(&'static str),
    /// Validated identifier: env var names, permission scopes, job ids.
    Name(Ident),
    /// Non-secret text: JWT issuer, kube context name.
    Text(PublicText),
    Path(DisplayPath),
    List(Vec<AttrValue>),
    /// e.g. workflow permissions (scope → level).
    Map(BTreeMap<Ident, AttrValue>),
}

impl Serialize for AttrValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            AttrValue::Bool(b) => s.serialize_bool(*b),
            AttrValue::Int(i) => s.serialize_i64(*i),
            AttrValue::Sym(v) => s.serialize_str(v),
            AttrValue::Name(v) => v.serialize(s),
            AttrValue::Text(v) => v.serialize(s),
            AttrValue::Path(v) => v.serialize(s),
            AttrValue::List(v) => v.serialize(s),
            AttrValue::Map(v) => v.serialize(s),
        }
    }
}

impl fmt::Display for AttrValue {
    /// Used for message placeholders: lists are comma separated, maps are
    /// `key=value` pairs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttrValue::Bool(b) => write!(f, "{b}"),
            AttrValue::Int(i) => write!(f, "{i}"),
            AttrValue::Sym(v) => f.write_str(v),
            AttrValue::Name(v) => write!(f, "{v}"),
            AttrValue::Text(v) => write!(f, "{v}"),
            AttrValue::Path(v) => write!(f, "{v}"),
            AttrValue::List(items) => {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                Ok(())
            }
            AttrValue::Map(map) => {
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}={v}")?;
                }
                Ok(())
            }
        }
    }
}

/// Attributes of a fact, keyed by names from the type's schema.
pub type Attrs = BTreeMap<&'static str, AttrValue>;

/// Where a fact was found.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    File {
        path: DisplayPath,
        /// Entry inside the file (dotenv key, YAML path, workflow job).
        #[serde(skip_serializing_if = "Option::is_none")]
        key_path: Option<PublicText>,
    },
    Env {
        name: Ident,
    },
    Probe {
        name: Ident,
    },
}

impl Location {
    /// The file path, for file locations.
    pub fn path(&self) -> Option<&DisplayPath> {
        match self {
            Location::File { path, .. } => Some(path),
            _ => None,
        }
    }

    /// The `{name}` placeholder: env var name, key path, probe name, or the
    /// file name.
    pub fn name(&self) -> String {
        match self {
            Location::File {
                key_path: Some(key),
                ..
            } => key.to_string(),
            Location::File { path, .. } => Path::new(path.as_str())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string()),
            Location::Env { name } | Location::Probe { name } => name.to_string(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Location::File { .. } => "file",
            Location::Env { .. } => "env",
            Location::Probe { .. } => "probe",
        }
    }
}

impl fmt::Display for Location {
    /// `/home/u/.env#GH_TOKEN`, `$GH_TOKEN`, `probe:process`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::File {
                path,
                key_path: None,
            } => write!(f, "{path}"),
            Location::File {
                path,
                key_path: Some(key),
            } => write!(f, "{path}#{key}"),
            Location::Env { name } => write!(f, "${name}"),
            Location::Probe { name } => write!(f, "probe:{name}"),
        }
    }
}

/// One interpreted artifact: derived, non-secret data only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fact {
    #[serde(rename = "type")]
    pub type_: Ident,
    pub location: Location,
    /// The config source that produced it.
    pub source: Ident,
    pub attrs: Attrs,
}

/// File metadata from `lstat`/`fstat`, never following symlinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub kind: FileKind,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: i64,
    /// Device id, for `one-file-system`.
    pub dev: u64,
    /// Inode number: with `dev` it identifies the file, so one file reached
    /// through two paths (`/var/run` → `/run`, hard links) is reported once.
    pub ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
    Unknown,
}

impl FileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::File => "file",
            FileKind::Dir => "dir",
            FileKind::Symlink => "symlink",
            FileKind::Fifo => "fifo",
            FileKind::Socket => "socket",
            FileKind::CharDevice => "char_device",
            FileKind::BlockDevice => "block_device",
            FileKind::Unknown => "unknown",
        }
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a file or directory could not be read. Not a failure of the run:
/// "not readable" is reported like any other result. Serialized as
/// `{"reason": "permission_denied"}`, `{"reason": "too_large", "size": 9}`, ...
#[derive(Clone, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum FsError {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("is a symlink (not followed)")]
    Symlink,
    #[error("not a regular file ({kind})")]
    NotRegular { kind: FileKind },
    #[error("larger than max-file-size ({size} bytes)")]
    TooLarge { size: u64 },
    /// Other OS errors (the errno description).
    #[error("{message}")]
    Io { message: String },
}

impl FsError {
    /// Stable code for the report (`permission_denied`, `too_large`, ...).
    pub fn code(&self) -> &'static str {
        match self {
            FsError::NotFound => "not_found",
            FsError::PermissionDenied => "permission_denied",
            FsError::Symlink => "symlink",
            FsError::NotRegular { .. } => "not_regular",
            FsError::TooLarge { .. } => "too_large",
            FsError::Io { .. } => "io_error",
        }
    }
}

/// Every [`Skipped::reason`] code lootr reports (`[scan] fail-on-skipped`
/// is validated against it).
pub const SKIP_REASONS: &[&str] = &[
    "not_found",
    "permission_denied",
    "symlink",
    "not_regular",
    "too_large",
    "io_error",
    "parse_error",
    "invalid_path",
    "not_recognized",
    "binary",
    "truncated",
    "depth_limit",
    "other_fs",
    "symlink_root",
];

/// Something a source selected but lootr could not interpret, completely or
/// at all: an unreadable file or directory, a symlink, a FIFO, a document
/// that did not parse, a file only partly scanned, a directory a limit kept
/// the walk out of. Reported, never fatal; `[scan] fail-on-skipped` makes
/// chosen reasons fail the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub source: Ident,
    pub location: Location,
    /// One of [`SKIP_REASONS`].
    pub reason: &'static str,
    /// Human-readable detail (static text or an OS error description; never
    /// file content).
    pub detail: String,
}

/// Severity of a rule. Ordered: `info < low < medium < high < critical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Severity, String> {
        Severity::ALL
            .into_iter()
            .find(|sev| sev.as_str() == s)
            .ok_or_else(|| format!("unknown severity `{s}` (info, low, medium, high, critical)"))
    }
}

/// A waiver that matched a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppliedWaiver {
    pub reason: PublicText,
    pub expires: Option<crate::domain::time::Date>,
}

/// A rule whose condition failed to evaluate for a fact (type mismatch,
/// missing optional attribute). Makes the run exit with 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleError {
    pub rule: Ident,
    #[serde(rename = "type")]
    pub type_: Ident,
    pub location: Location,
    /// The CEL error; built from fact values only.
    pub message: String,
}

/// A waiver past its `expires` date: ignored, and reported so it gets
/// renewed or removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpiredWaiver {
    pub rule: Ident,
    pub path: Option<String>,
    pub name: Option<String>,
    pub reason: String,
    pub expires: crate::domain::time::Date,
    /// Config layer that defined it.
    pub layer: String,
}

/// A rule that matched a fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: Ident,
    pub severity: Severity,
    /// Rendered from the rule's template; placeholders only see facts.
    pub message: String,
    pub remediation: String,
    pub tags: BTreeMap<Ident, Ident>,
    pub waived: Option<AppliedWaiver>,
    pub fact: Fact,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_validation() {
        assert!(Ident::from_non_secret("ssh-key-unencrypted").is_ok());
        assert!(Ident::from_non_secret("GH_TOKEN").is_ok());
        assert!(Ident::from_non_secret("5.2.x").is_ok());
        assert!(Ident::from_non_secret("").is_err());
        assert!(Ident::from_non_secret("has space").is_err());
        assert!(Ident::from_non_secret("ünï").is_err());
        assert!(Ident::from_non_secret(&"a".repeat(129)).is_err());
    }

    #[test]
    fn public_text_is_cut_and_cleaned() {
        assert_eq!(PublicText::from_non_secret("a\nb").as_str(), "a\u{FFFD}b");
        let long = "x".repeat(300);
        let t = PublicText::from_non_secret(&long);
        assert_eq!(t.as_str().chars().count(), PUBLIC_TEXT_MAX_CHARS);
        assert!(t.as_str().ends_with('…'));
        assert_eq!(
            PublicText::from_non_secret(&"y".repeat(256)).as_str().len(),
            256
        );
    }

    /// Bidi overrides, zero-width and other invisible format characters are
    /// shown as escapes, never silently kept or dropped.
    #[test]
    fn invisible_characters_are_escaped() {
        let t = PublicText::from_non_secret("a\u{202e}b\u{200b}c\u{2066}d\u{feff}");
        assert_eq!(t.as_str(), "a\\u{202e}b\\u{200b}c\\u{2066}d\\u{feff}");
        let p = DisplayPath::new(Path::new("/h/x\u{202e}cod.exe\n"));
        assert_eq!(p.as_str(), "/h/x\\u{202e}cod.exe\u{FFFD}");
        // Escapes count against the length cap.
        let t = PublicText::from_non_secret(&"\u{200b}".repeat(300));
        assert!(t.as_str().chars().count() <= PUBLIC_TEXT_MAX_CHARS);
        assert!(t.as_str().ends_with('…'));
        assert_eq!(display_safe("ünï ok"), "ünï ok");
    }

    #[test]
    fn attr_values_serialize_as_plain_json() {
        let mut map = BTreeMap::new();
        map.insert(
            Ident::from_non_secret("packages").unwrap(),
            AttrValue::Sym("write"),
        );
        let mut attrs = Attrs::new();
        attrs.insert("encrypted", AttrValue::Bool(false));
        attrs.insert("bits", AttrValue::Int(2048));
        attrs.insert("permissions", AttrValue::Map(map));
        attrs.insert("scopes", AttrValue::List(vec![AttrValue::Sym("a")]));
        let json = serde_json::to_string(&attrs).unwrap();
        assert_eq!(
            json,
            r#"{"bits":2048,"encrypted":false,"permissions":{"packages":"write"},"scopes":["a"]}"#
        );
    }

    #[test]
    fn locations() {
        let file = Location::File {
            path: DisplayPath::new(Path::new("/h/.env")),
            key_path: Some(PublicText::from_non_secret("TOKEN")),
        };
        assert_eq!(file.to_string(), "/h/.env#TOKEN");
        assert_eq!(file.name(), "TOKEN");
        assert_eq!(
            serde_json::to_string(&file).unwrap(),
            r#"{"kind":"file","path":"/h/.env","key_path":"TOKEN"}"#
        );
        let env = Location::Env {
            name: Ident::from_non_secret("GH_TOKEN").unwrap(),
        };
        assert_eq!(env.to_string(), "$GH_TOKEN");
        let plain = Location::File {
            path: DisplayPath::new(Path::new("/h/.ssh/id_rsa")),
            key_path: None,
        };
        assert_eq!(plain.name(), "id_rsa");
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Info < Severity::Critical);
        assert_eq!("high".parse::<Severity>(), Ok(Severity::High));
        assert!("severe".parse::<Severity>().is_err());
    }
}
