//! Config data: the raw `lootr.toml` layout ([`ConfigFile`]) as read with
//! serde, and the validated, merged result ([`ScanSettings`], [`Source`],
//! [`Rule`], [`Waiver`]) that the service layer works with.
//!
//! Raw specs use `Option` for everything a later layer may leave out, so
//! layers can be merged field by field (see `service::config`). Keys are
//! kebab-case; unknown keys are errors.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::domain::model::{Ident, Severity};
use crate::domain::time::Date;

/// The only config format version so far.
pub const CONFIG_VERSION: u32 = 1;

/// One `lootr.toml` file as written.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ConfigFile {
    pub version: Option<u32>,
    /// Local files, relative to this file, applied before it.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub scan: ScanSpec,
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceSpec>,
    #[serde(default, rename = "type")]
    pub types: Vec<TypeSpec>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleSpec>,
    #[serde(default, rename = "waiver")]
    pub waivers: Vec<WaiverSpec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ScanSpec {
    pub max_file_size: Option<ByteSize>,
    pub max_depth: Option<u32>,
    pub one_file_system: Option<bool>,
    /// Appended across layers.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Skip reasons (or `"*"`) that fail the run. Appended across layers.
    #[serde(default)]
    pub fail_on_skipped: Vec<String>,
    /// Later layers may not weaken `[scan]` (see `service::config`).
    pub locked: Option<bool>,
}

/// `1048576` or `"1MiB"`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ByteSize {
    Bytes(u64),
    Text(String),
}

impl ByteSize {
    /// Bytes; accepts `B`, `KiB`, `MiB`, `GiB`, `KB`, `MB`, `GB` suffixes.
    pub fn bytes(&self) -> Result<u64, String> {
        let text = match self {
            ByteSize::Bytes(n) => return Ok(*n),
            ByteSize::Text(t) => t.trim(),
        };
        let digits = text
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len());
        let (num, unit) = text.split_at(digits);
        let factor: u64 = match unit.trim() {
            "" | "B" => 1,
            "KiB" => 1 << 10,
            "MiB" => 1 << 20,
            "GiB" => 1 << 30,
            "KB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            _ => return Err(format!("`{text}` is not a size (e.g. 1MiB, 512KiB)")),
        };
        num.parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(factor))
            .ok_or_else(|| format!("`{text}` is not a size (e.g. 1MiB, 512KiB)"))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SourceSpec {
    pub id: String,
    /// `env` | `file` | `probe`.
    pub kind: Option<String>,
    pub names: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub extract: Option<String>,
    pub probes: Option<Vec<String>>,
    /// Probe sources: environment variables holding `:`-separated directory
    /// lists (`PATH`) whose entries are probed like literal `paths`.
    pub path_vars: Option<Vec<String>>,
    pub enabled: Option<bool>,
    /// Later layers may not weaken the source (see `service::config`).
    pub locked: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TypeSpec {
    pub name: String,
    /// Required for a new type; an override may leave it out (e.g. to only
    /// lock the type).
    pub pattern: Option<String>,
    /// Later layers may not change the pattern (see `service::config`).
    pub locked: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleSpec {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub when: Option<String>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub tags: Option<BTreeMap<String, String>>,
    pub locked: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct WaiverSpec {
    pub rule: String,
    /// Glob for the file path (`~` and relative paths expanded).
    pub path: Option<String>,
    /// Env var name or key path.
    pub name: Option<String>,
    pub reason: String,
    pub expires: Option<toml::value::Datetime>,
}

/// Validated `[scan]` settings after all layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanSettings {
    pub max_file_size: u64,
    pub max_depth: u32,
    pub one_file_system: bool,
    /// Path globs excluded from every file source.
    pub exclude: Vec<String>,
    /// Skip reasons that fail the run (exit code 1); `"*"` = any.
    pub fail_on_skipped: Vec<String>,
}

impl Default for ScanSettings {
    fn default() -> Self {
        ScanSettings {
            max_file_size: 1 << 20,
            max_depth: 16,
            one_file_system: true,
            exclude: Vec::new(),
            fail_on_skipped: Vec::new(),
        }
    }
}

/// A validated, enabled source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub id: Ident,
    pub kind: SourceKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Env var name globs.
    Env { names: Vec<String> },
    /// Path globs (`~` and relative paths expanded at discovery).
    File {
        paths: Vec<String>,
        exclude: Vec<String>,
        action: FileAction,
    },
    /// Built-in probes; `paths` (globs) and the entries of the `path_vars`
    /// environment variables are handed to probes that inspect file system
    /// objects (sockets, writable directories and files).
    Probe {
        probes: Vec<Ident>,
        paths: Vec<String>,
        exclude: Vec<String>,
        /// Names of environment variables with `:`-separated directory lists
        /// (`PATH`); each absolute entry is a literal path.
        path_vars: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileAction {
    /// Parse the file with this document type.
    Document(String),
    /// Split the file with this extractor.
    Extract(String),
}

/// A validated, enabled rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: Ident,
    pub type_: String,
    /// CEL expression.
    pub when: String,
    pub severity: Severity,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub tags: BTreeMap<Ident, Ident>,
    pub locked: bool,
    /// Layer that locked the rule (`locked = true` first set there).
    pub locked_by: Option<String>,
    /// Layer that defined the rule last (for messages).
    pub layer: String,
}

/// A validated waiver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiver {
    pub rule: Ident,
    /// Expanded path glob.
    pub path: Option<String>,
    /// The path glob as written in the config (for reports).
    pub path_pattern: Option<String>,
    pub name: Option<String>,
    pub reason: String,
    pub expires: Option<Date>,
    pub layer: String,
    /// Position among the layer's `[[waiver]]` entries (1-based).
    pub position: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes() {
        let t = |s: &str| ByteSize::Text(s.into()).bytes();
        assert_eq!(t("1MiB"), Ok(1 << 20));
        assert_eq!(t("512 KiB"), Ok(512 << 10));
        assert_eq!(t("10MB"), Ok(10_000_000));
        assert_eq!(t("123"), Ok(123));
        assert_eq!(ByteSize::Bytes(7).bytes(), Ok(7));
        assert!(t("1TiB").is_err());
        assert!(t("MiB").is_err());
        assert!(t("99999999999999GiB").is_err());
    }

    #[test]
    fn parses_the_plan_example() {
        let text = r#"
            version = 1
            [scan]
            max-file-size = "1MiB"
            exclude = ["~/Library/**"]
            [[source]]
            id = "dotenv"
            kind = "file"
            paths = ["./**/.env"]
            extract = "dotenv"
            [[type]]
            name = "acme_api_key"
            pattern = '^acme_[A-Za-z0-9]{32}$'
            [[rule]]
            id = "ssh-key-unencrypted"
            type = "ssh_private_key"
            when = '!encrypted'
            severity = "high"
            tags = { cis = "5.2.x" }
            locked = true
            [[waiver]]
            rule = "ssh-key-unencrypted"
            path = "~/.ssh/ci_deploy"
            reason = "Hardware-bound deploy key"
            expires = 2027-01-31
        "#;
        let file: ConfigFile = toml::from_str(text).unwrap();
        assert_eq!(file.version, Some(1));
        assert_eq!(file.sources[0].extract.as_deref(), Some("dotenv"));
        assert_eq!(file.rules[0].severity, Some(Severity::High));
        assert_eq!(file.waivers[0].expires.unwrap().to_string(), "2027-01-31");
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = toml::from_str::<ConfigFile>("version = 1\n[[rule]]\nid = \"x\"\nwhen2 = \"\"\n")
            .unwrap_err();
        assert!(err.to_string().contains("when2"), "{err}");
    }
}
