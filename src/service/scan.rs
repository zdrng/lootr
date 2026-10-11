//! The scan pipeline: discover → collect → evaluate.

use std::path::PathBuf;

use crate::domain::model::{ExpiredWaiver, Fact, Finding, FsError, RuleError, Skipped};
use crate::domain::time::Date;
use crate::repository::{EnvRepository, FileRepository, SystemRepository};
use crate::service::collect::{CollectContext, collect};
use crate::service::config::LoadedConfig;
use crate::service::discover::{Paths, discover};
use crate::service::evaluate::evaluate;
use crate::service::probe::Probe;

/// Receives one line per finished stage (the CLI prints it on stderr).
pub trait Progress {
    fn step(&mut self, verb: &str, message: &str);
}

/// Ignores progress (tests).
pub struct NoProgress;

impl Progress for NoProgress {
    fn step(&mut self, _verb: &str, _message: &str) {}
}

/// Everything a run produced. Contains no secret material.
pub struct ScanResult {
    /// Unix time the scan started.
    pub started_at: i64,
    pub uid: u32,
    pub home: Option<PathBuf>,
    pub cwd: PathBuf,
    pub candidates: usize,
    pub facts: Vec<Fact>,
    pub findings: Vec<Finding>,
    pub rule_errors: Vec<RuleError>,
    pub expired_waivers: Vec<ExpiredWaiver>,
    pub skipped: Vec<Skipped>,
}

pub struct ScanService<'a> {
    pub files: &'a dyn FileRepository,
    pub env: &'a dyn EnvRepository,
    pub system: &'a dyn SystemRepository,
    pub probes: &'a [Box<dyn Probe>],
}

impl ScanService<'_> {
    pub fn run(
        &self,
        config: &LoadedConfig,
        progress: &mut dyn Progress,
    ) -> Result<ScanResult, FsError> {
        let started_at = self.system.now();
        let home = self.system.home_dir();
        let cwd = self.system.current_dir()?;

        let paths = Paths {
            home: home.as_deref(),
            cwd: &cwd,
            uid: self.system.uid(),
        };
        let discovery = discover(&config.sources, &config.scan, &paths, self.files, self.env);
        let n = discovery.candidates.len();
        progress.step("Discovered", &count(n, "candidate", "candidates"));

        let ctx = CollectContext {
            registry: &config.registry,
            settings: &config.scan,
            probes: self.probes,
            files: self.files,
            env: self.env,
            system: self.system,
        };
        let collected = collect(&discovery.candidates, &ctx);
        let mut skipped = discovery.skipped;
        skipped.extend(collected.skipped);
        let mut msg = count(collected.facts.len(), "fact", "facts");
        if !skipped.is_empty() {
            msg.push_str(&format!(", {} skipped", skipped.len()));
        }
        progress.step("Collected", &msg);

        let evaluation = evaluate(
            &collected.facts,
            &config.rules,
            &config.waivers,
            Date::from_unix(started_at),
        );
        progress.step(
            "Evaluated",
            &format!(
                "{} against {}",
                count(collected.facts.len(), "fact", "facts"),
                count(config.rules.len(), "rule", "rules")
            ),
        );

        let mut facts = collected.facts;
        facts.extend(evaluation.waiver_facts);
        Ok(ScanResult {
            started_at,
            uid: self.system.uid(),
            home,
            cwd,
            candidates: n,
            facts,
            findings: evaluation.findings,
            rule_errors: evaluation.rule_errors,
            expired_waivers: evaluation.expired_waivers,
            skipped,
        })
    }
}

/// `1 fact`, `2 facts`.
pub fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    //! The whole pipeline with the built-in default config on fakes.

    use std::path::Path;

    use super::*;
    use crate::domain::model::FileKind;
    use crate::repository::fake::{FakeConfig, FakeEnv, FakeFiles, FakeSystem};
    use crate::service::cel::Cel;
    use crate::service::config::{ConfigRequest, DEFAULT_CONFIG, load};
    use crate::service::probe::builtin;
    use crate::service::probe::writable::DIR_TYPE;

    /// Writable PATH directories (from `$PATH`) and shared caches others can
    /// write are found by the default `path-dirs` / `shared-caches` sources;
    /// private and root-owned `0755` ones produce no fact.
    #[test]
    fn default_config_finds_dirs_others_can_write() {
        let probes = builtin();
        let names: Vec<&str> = probes.iter().map(|p| p.name()).collect();
        let mut registry = crate::domain::types::Registry::builtin(0);
        for p in &probes {
            for t in p.fact_types() {
                registry.add_fact_type(*t).unwrap();
            }
        }
        let req = ConfigRequest {
            default: Some(DEFAULT_CONFIG),
            files: &[],
            cwd: Path::new("/work"),
            home: Some(Path::new("/home/user")),
            probes: &names,
        };
        let config = load(&FakeConfig::new(), &req, registry, &Cel::new()).unwrap();
        let files = FakeFiles::new()
            .dir("/work")
            // In $PATH, world-writable (root-owned, no sticky bit).
            .special_owned("/opt/shared/bin", FileKind::Dir, 0, 0, 0o777)
            // In $PATH, safe.
            .special_owned("/usr/bin", FileKind::Dir, 0, 0, 0o755)
            // Default `path-dirs` path, safe.
            .special_owned("/usr/local/bin", FileKind::Dir, 0, 0, 0o755)
            // Shared cache owned by another user, group-writable.
            .special_owned("/home/user/.cache/pip", FileKind::Dir, 1002, 1000, 0o2775)
            // Shared cache, private.
            .special_owned("/home/user/.npm", FileKind::Dir, 1000, 1000, 0o755)
            .file_with_mode("/home/user/.bashrc", "echo hi", 0o644);
        let env = FakeEnv::new().var("PATH", "/opt/shared/bin:/usr/bin:/missing/bin");
        let system = FakeSystem::default();
        let service = ScanService {
            files: &files,
            env: &env,
            system: &system,
            probes: &probes,
        };
        let result = service.run(&config, &mut NoProgress).unwrap();

        let mut dirs: Vec<(String, String)> = result
            .facts
            .iter()
            .filter(|f| f.type_.as_str() == DIR_TYPE)
            .map(|f| (f.source.to_string(), f.location.to_string()))
            .collect();
        dirs.sort();
        assert_eq!(
            dirs,
            [
                ("path-dirs".into(), "/opt/shared/bin".into()),
                ("shared-caches".into(), "/home/user/.cache/pip".into()),
            ]
        );
        assert!(
            !result
                .facts
                .iter()
                .any(|f| f.type_.as_str() == "writable_file"),
            "a private rc file is no fact"
        );
        let mut findings: Vec<(String, String)> = result
            .findings
            .iter()
            .filter(|f| f.fact.type_.as_str() == DIR_TYPE)
            .map(|f| (f.rule.to_string(), f.fact.location.to_string()))
            .collect();
        findings.sort();
        assert_eq!(
            findings,
            [
                (
                    "writable-cache-dir-group".into(),
                    "/home/user/.cache/pip".into()
                ),
                ("writable-path-dir-world".into(), "/opt/shared/bin".into()),
            ]
        );
    }
}
