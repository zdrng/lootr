//! Collect: turns candidates into facts. This is the only stage that sees
//! secret bytes.
//!
//! - env candidates: the value is read into a `SecretBuf`, classified by
//!   every value type and always produces a generic `env_var` fact;
//! - file candidates with a document type: the file is read securely, the
//!   type sniffs the first bytes and parses it; nested values are
//!   classified by the value types;
//! - file candidates with an extractor: every entry produces a generic
//!   entry fact (`dotenv_entry`, ...) and is classified like an env var;
//! - probe candidates: the probe produces facts directly.
//!
//! Facts from files get the generic file attributes, including the git
//! context (`in_git_repo`, `gitignored`, see [`crate::service::git`]),
//! computed only for files that produce facts. Buffers are dropped (and
//! zeroized) before the next candidate is read; only facts leave.
//!
//! One file reached through two paths of the same source (`/var/run` →
//! `/run`, hard links, overlapping globs through a symlinked directory) is
//! collected once, at the first path, by device and inode.
//!
//! Partial results are reported as skipped next to the facts: a file whose
//! extractor stopped early or did not scan it (`truncated`, `binary`), and a
//! file named literally in a source (no glob) that its document type does
//! not recognize (`not_recognized`). For a glob, a file the type does not
//! recognize is simply not a match (`~/.ssh/**` with `ssh_private_key`
//! skips `known_hosts` and `config` quietly).

use std::collections::BTreeSet;
use std::path::Path;

use crate::domain::config::{FileAction, ScanSettings};
use crate::domain::extract::Coverage;
use crate::domain::model::{
    AttrValue, Attrs, DisplayPath, Fact, FileMeta, Ident, Location, PublicText, Skipped,
};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{ENV_VAR, Emitter, Registry, entry_attrs, file_attrs};
use crate::repository::{EnvRepository, FileRepository, SystemRepository};
use crate::service::discover::{Candidate, Target};
use crate::service::git::GitInspector;
use crate::service::probe::{Probe, ProbeContext};

/// Bytes a document type gets to sniff.
pub const SNIFF_LEN: usize = 512;

pub struct CollectContext<'a> {
    pub registry: &'a Registry,
    pub settings: &'a ScanSettings,
    pub probes: &'a [Box<dyn Probe>],
    pub files: &'a dyn FileRepository,
    pub env: &'a dyn EnvRepository,
    pub system: &'a dyn SystemRepository,
}

#[derive(Default)]
pub struct Collected {
    pub facts: Vec<Fact>,
    pub skipped: Vec<Skipped>,
}

pub fn collect(candidates: &[Candidate], ctx: &CollectContext<'_>) -> Collected {
    let mut out = Collected::default();
    let mut file_ctx = FileCtx {
        uid: ctx.system.uid(),
        now: ctx.system.now(),
        git: GitInspector::new(ctx.files),
        seen: BTreeSet::new(),
    };
    for c in candidates {
        match &c.target {
            Target::Env { name, os_name } => {
                // A variable that vanished since discovery is no finding.
                if let Some(value) = ctx.env.value(os_name) {
                    let value_ctx = ValueCtx {
                        registry: ctx.registry,
                        source: &c.source,
                        location: Location::Env { name: name.clone() },
                        file: None,
                    };
                    value_ctx.classify(Some((ENV_VAR, name)), value.as_slice(), &mut out.facts);
                }
            }
            Target::File {
                path,
                root,
                rel,
                action,
            } => collect_file(
                &c.source,
                &FileTarget { path, root, rel },
                action,
                ctx,
                &mut file_ctx,
                &mut out,
            ),
            Target::Probe { name, paths } => {
                if let Some(probe) = ctx.probes.iter().find(|p| p.name() == name.as_str()) {
                    let facts = probe.run(
                        &ProbeContext {
                            source: &c.source,
                            paths,
                            system: ctx.system,
                            files: ctx.files,
                            registry: ctx.registry,
                        },
                        &mut out.skipped,
                    );
                    out.facts.extend(facts);
                }
            }
        }
    }
    out
}

/// Per-run state for file candidates.
struct FileCtx<'a> {
    uid: u32,
    now: i64,
    git: GitInspector<'a>,
    /// (source, device, inode) of every file read.
    seen: BTreeSet<(Ident, u64, u64)>,
}

/// A file candidate: its reported path and where it is read from.
struct FileTarget<'a> {
    path: &'a Path,
    root: &'a Path,
    rel: &'a Path,
}

impl FileCtx<'_> {
    /// The generic file attributes of `path`.
    fn info(&mut self, path: &Path, display: &DisplayPath, meta: &FileMeta) -> FileInfo {
        let mut attrs = file_attrs(meta, self.uid, self.now);
        let git = self.git.inspect(path);
        attrs.insert("in_git_repo", AttrValue::Bool(git.in_repo));
        attrs.insert("gitignored", AttrValue::Bool(git.ignored));
        FileInfo {
            path: display.clone(),
            attrs,
        }
    }
}

fn collect_file(
    source: &Ident,
    target: &FileTarget<'_>,
    action: &FileAction,
    ctx: &CollectContext<'_>,
    file_ctx: &mut FileCtx<'_>,
    out: &mut Collected,
) {
    let path = target.path;
    let display = DisplayPath::new(path);
    let skip = |reason: &'static str, detail: String| Skipped {
        source: source.clone(),
        location: Location::File {
            path: display.clone(),
            key_path: None,
        },
        reason,
        detail,
    };
    // Resolve the file below its source's trusted literal prefix with
    // `openat`, so a symlink planted in a parent directory since discovery
    // is refused.
    let (meta, buf) =
        match ctx
            .files
            .read_file_beneath(target.root, target.rel, ctx.settings.max_file_size)
        {
            Ok(r) => r,
            Err(e) => {
                out.skipped.push(skip(e.code(), e.to_string()));
                return;
            }
        };
    if !file_ctx.seen.insert((source.clone(), meta.dev, meta.ino)) {
        return; // the same file, already collected through another path
    }
    let literal = target.rel.as_os_str().is_empty();
    let doc = buf.as_slice();
    match action {
        FileAction::Document(type_name) => {
            let Some(t) = ctx.registry.document(type_name) else {
                return;
            };
            let head = doc.slice(0..doc.len().min(SNIFF_LEN)).map(|h| h.expose());
            if !head.is_some_and(|h| t.sniff(h)) {
                if literal {
                    out.skipped.push(skip(
                        "not_recognized",
                        format!("{type_name}: the file does not look like this type"),
                    ));
                }
                return;
            }
            let mut emitter = Emitter::default();
            if let Err(e) = t.parse(doc, &mut emitter) {
                out.skipped
                    .push(skip("parse_error", format!("{type_name}: {e}")));
                return;
            }
            let Ok(type_) = Ident::from_non_secret(type_name) else {
                return;
            };
            let file = file_ctx.info(path, &display, &meta);
            for (key_path, mut attrs) in emitter.facts {
                attrs.extend(file.attrs.clone());
                out.facts.push(Fact {
                    type_: type_.clone(),
                    location: file.location(key_path),
                    source: source.clone(),
                    attrs,
                });
            }
            for (key_path, value) in emitter.values {
                let value_ctx = ValueCtx {
                    registry: ctx.registry,
                    source,
                    location: file.location(Some(key_path)),
                    file: Some(&file),
                };
                value_ctx.classify(None, value.as_slice(), &mut out.facts);
            }
        }
        FileAction::Extract(name) => {
            let Some(x) = ctx.registry.extractor(name) else {
                return;
            };
            let mut entries = Vec::new();
            match x.extract(doc, &mut entries) {
                Ok(Coverage::Complete) => {}
                Ok(Coverage::Partial { reason, detail }) => {
                    out.skipped.push(skip(reason, format!("{name}: {detail}")));
                }
                Err(e) => {
                    out.skipped
                        .push(skip("parse_error", format!("{name}: {e}")));
                    return;
                }
            }
            if entries.is_empty() {
                return;
            }
            let file = file_ctx.info(path, &display, &meta);
            let generic = x.generic_entry();
            for entry in entries {
                let value_ctx = ValueCtx {
                    registry: ctx.registry,
                    source,
                    location: file.location(Some(PublicText::from_non_secret(entry.key.as_str()))),
                    file: Some(&file),
                };
                let entry_fact = generic.then_some((x.entry_type(), &entry.key));
                value_ctx.classify(entry_fact, entry.value.as_slice(), &mut out.facts);
            }
        }
    }
    // `buf` is dropped (and wiped) here, before the next file is read.
}

struct FileInfo {
    path: DisplayPath,
    attrs: Attrs,
}

impl FileInfo {
    fn location(&self, key_path: Option<PublicText>) -> Location {
        Location::File {
            path: self.path.clone(),
            key_path,
        }
    }
}

struct ValueCtx<'a> {
    registry: &'a Registry,
    source: &'a Ident,
    location: Location,
    file: Option<&'a FileInfo>,
}

impl ValueCtx<'_> {
    /// Runs `value` through every value type. With `entry = Some((type,
    /// name))` also emits the generic entry fact, first.
    fn classify(
        &self,
        entry: Option<(&str, &Ident)>,
        value: SecretSlice<'_>,
        facts: &mut Vec<Fact>,
    ) {
        let mut matched = Vec::new();
        let mut typed = Vec::new();
        for vt in self.registry.value_types() {
            let Some(attrs) = vt.classify(value) else {
                continue;
            };
            let Ok(type_) = Ident::from_non_secret(vt.name()) else {
                continue;
            };
            matched.push(vt.name());
            typed.push(self.fact(type_, attrs));
        }
        if let Some((entry_type, name)) = entry
            && let Ok(type_) = Ident::from_non_secret(entry_type)
        {
            facts.push(self.fact(type_, entry_attrs(name, value, &matched)));
        }
        facts.extend(typed);
    }

    fn fact(&self, type_: Ident, mut attrs: Attrs) -> Fact {
        if let Some(file) = self.file {
            attrs.extend(file.attrs.clone());
        }
        Fact {
            type_,
            location: self.location.clone(),
            source: self.source.clone(),
            attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::{AttrValue, FileKind};
    use crate::domain::types::custom::CustomType;
    use crate::domain::types::test_types::registry;
    use crate::repository::fake::{FakeEnv, FakeFiles, FakeSystem};
    use std::path::PathBuf;

    fn id(s: &str) -> Ident {
        Ident::from_non_secret(s).unwrap()
    }

    fn env_candidate(name: &str) -> Candidate {
        Candidate {
            source: id("env"),
            target: Target::Env {
                name: id(name),
                os_name: name.into(),
            },
        }
    }

    fn file_candidate(path: &str, action: FileAction) -> Candidate {
        Candidate {
            source: id("files"),
            target: Target::File {
                path: PathBuf::from(path),
                root: PathBuf::from("/"),
                rel: PathBuf::from(path.trim_start_matches('/')),
                action,
            },
        }
    }

    fn run(candidates: &[Candidate], files: &FakeFiles, env: &FakeEnv) -> Collected {
        let mut reg = registry();
        reg.add_custom(CustomType::new(id("acme_key"), "^acme_[a-z]{4}$").unwrap())
            .unwrap();
        let settings = ScanSettings {
            max_file_size: 100,
            ..ScanSettings::default()
        };
        let ctx = CollectContext {
            registry: &reg,
            settings: &settings,
            probes: &[],
            files,
            env,
            system: &FakeSystem::default(),
        };
        collect(candidates, &ctx)
    }

    fn summary(facts: &[Fact]) -> Vec<String> {
        facts
            .iter()
            .map(|f| format!("{} @ {}", f.type_, f.location))
            .collect()
    }

    #[test]
    fn env_values_produce_generic_and_typed_facts() {
        let env = FakeEnv::new()
            .var("TOKEN", "tok_abcdefghij")
            .var("KEY", "acme_abcd")
            .var("HOME", "/home/user");
        let c = [
            env_candidate("TOKEN"),
            env_candidate("KEY"),
            env_candidate("HOME"),
            env_candidate("GONE"),
        ];
        let out = run(&c, &FakeFiles::new(), &env);
        assert_eq!(
            summary(&out.facts),
            [
                "env_var @ $TOKEN",
                "test_token @ $TOKEN",
                "env_var @ $KEY",
                "acme_key @ $KEY",
                "env_var @ $HOME",
            ]
        );
        let token_var = &out.facts[0];
        assert_eq!(token_var.attrs["length"], AttrValue::Int(14));
        assert_eq!(
            token_var.attrs["classified_as"],
            AttrValue::List(vec![AttrValue::Name(id("test_token"))])
        );
        assert_eq!(out.facts[1].attrs["kind"], AttrValue::Sym("long"));
        assert!(!out.facts[0].attrs.contains_key("mode"));
    }

    #[test]
    fn documents_are_sniffed_parsed_and_their_values_classified() {
        let files = FakeFiles::new()
            .file_with_mode(
                "/h/doc",
                "TESTDOC\n!\nlabel:prod\napi=tok_0123456789",
                0o644,
            )
            .file("/h/other", "not a test doc")
            .file("/h/broken", "TESTDOC BROKEN");
        let action = || FileAction::Document("test_doc".into());
        let c = [
            file_candidate("/h/doc", action()),
            file_candidate("/h/other", action()),
            file_candidate("/h/broken", action()),
        ];
        let out = run(&c, &files, &FakeEnv::new());
        assert_eq!(
            summary(&out.facts),
            ["test_doc @ /h/doc", "test_token @ /h/doc#api"]
        );
        let doc = &out.facts[0];
        assert_eq!(doc.attrs["lines"], AttrValue::Int(4));
        assert_eq!(doc.attrs["marked"], AttrValue::Bool(true));
        assert_eq!(doc.attrs["world_readable"], AttrValue::Bool(true));
        assert_eq!(out.facts[1].attrs["world_readable"], AttrValue::Bool(true));
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(out.skipped[0].reason, "parse_error");
        assert_eq!(out.skipped[0].detail, "test_doc: broken test document");
    }

    #[test]
    fn extracted_entries_are_classified_like_env_vars() {
        let files = FakeFiles::new().file("/w/.env", "A=tok_x\nB=plain\nnot an entry\n");
        let c = [file_candidate(
            "/w/.env",
            FileAction::Extract("lines".into()),
        )];
        let out = run(&c, &files, &FakeEnv::new());
        assert_eq!(
            summary(&out.facts),
            [
                "line_entry @ /w/.env#A",
                "test_token @ /w/.env#A",
                "line_entry @ /w/.env#B"
            ]
        );
        assert_eq!(out.facts[2].attrs["name"], AttrValue::Name(id("B")));
        assert_eq!(out.facts[2].attrs["mode"], AttrValue::Int(0o600));
    }

    #[test]
    fn unreadable_and_special_files_are_skipped() {
        let files = FakeFiles::new()
            .unreadable("/h/locked")
            .special("/h/fifo", FileKind::Fifo)
            .special("/h/link", FileKind::Symlink)
            .file("/h/big", "x".repeat(101));
        let action = || FileAction::Extract("lines".into());
        let c = [
            file_candidate("/h/locked", action()),
            file_candidate("/h/fifo", action()),
            file_candidate("/h/link", action()),
            file_candidate("/h/big", action()),
            file_candidate("/h/gone", action()),
        ];
        let out = run(&c, &files, &FakeEnv::new());
        assert!(out.facts.is_empty());
        let reasons: Vec<&str> = out.skipped.iter().map(|s| s.reason).collect();
        assert_eq!(
            reasons,
            [
                "permission_denied",
                "not_regular",
                "symlink",
                "too_large",
                "not_found"
            ]
        );
        assert_eq!(out.skipped[1].detail, "not a regular file (fifo)");
    }

    /// The same file through two paths of one source is collected once.
    #[test]
    fn one_file_through_two_paths_is_collected_once() {
        let files = FakeFiles::new()
            .file("/run/app/.env", "A=tok_abcdefghij\n")
            .alias("/var/run/app", "/run/app");
        let action = || FileAction::Extract("lines".into());
        let mut other = file_candidate("/var/run/app/.env", action());
        other.source = id("other");
        let c = [
            file_candidate("/run/app/.env", action()),
            file_candidate("/var/run/app/.env", action()),
            other,
        ];
        let out = run(&c, &files, &FakeEnv::new());
        assert_eq!(
            summary(&out.facts),
            [
                "line_entry @ /run/app/.env#A",
                "test_token @ /run/app/.env#A",
                // Another source may interpret the same file on its own.
                "line_entry @ /var/run/app/.env#A",
                "test_token @ /var/run/app/.env#A",
            ]
        );
        assert!(out.skipped.is_empty());
    }

    /// Partial results are visible: an extractor that stopped early, and a
    /// literally named file its type does not recognize. A glob match the
    /// type does not recognize is no match and stays quiet.
    #[test]
    fn partial_scans_and_unrecognized_literal_files_are_reported() {
        let files = FakeFiles::new()
            .file("/w/.env", "A=tok_abcdefghij\nPARTIAL")
            .file("/h/literal", "not a test doc")
            .file("/h/globbed", "not a test doc");
        let mut globbed = file_candidate("/h/globbed", FileAction::Document("test_doc".into()));
        if let Target::File { root, rel, .. } = &mut globbed.target {
            *root = PathBuf::from("/h");
            *rel = PathBuf::from("globbed");
        }
        let mut literal = file_candidate("/h/literal", FileAction::Document("test_doc".into()));
        if let Target::File { root, rel, .. } = &mut literal.target {
            *root = PathBuf::from("/h/literal");
            *rel = PathBuf::new();
        }
        let c = [
            file_candidate("/w/.env", FileAction::Extract("lines".into())),
            literal,
            globbed,
        ];
        let out = run(&c, &files, &FakeEnv::new());
        assert_eq!(
            summary(&out.facts),
            ["line_entry @ /w/.env#A", "test_token @ /w/.env#A"]
        );
        let reasons: Vec<(String, &str)> = out
            .skipped
            .iter()
            .map(|s| (s.location.to_string(), s.reason))
            .collect();
        assert_eq!(
            reasons,
            [
                ("/w/.env".to_string(), "truncated"),
                ("/h/literal".to_string(), "not_recognized"),
            ]
        );
    }
}
