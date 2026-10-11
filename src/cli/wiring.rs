//! Builds the real repositories, the probe list and the type registry.

use crate::domain::types::{Registry, RegistryError};
use crate::repository::config::RealConfig;
use crate::repository::env::RealEnv;
use crate::repository::fs::RealFiles;
use crate::repository::system::RealSystem;
use crate::repository::{ConfigRepository, EnvRepository, FileRepository, SystemRepository};
use crate::service::probe::{self, Probe};

/// Builds the type registry for a list of probes and the scan start time.
pub type RegistryBuilder = fn(&[Box<dyn Probe>], i64) -> Result<Registry, RegistryError>;

/// Everything a run reads from: real implementations in production, fakes
/// in tests.
pub struct Deps<'a> {
    pub files: &'a dyn FileRepository,
    pub env: &'a dyn EnvRepository,
    pub system: &'a dyn SystemRepository,
    pub config: &'a dyn ConfigRepository,
    pub probes: &'a [Box<dyn Probe>],
    /// Builds the type registry (tests add test types).
    pub registry: RegistryBuilder,
}

/// The real system.
pub struct Real {
    files: RealFiles,
    env: RealEnv,
    system: RealSystem,
    config: RealConfig,
    probes: Vec<Box<dyn Probe>>,
}

impl Real {
    pub fn new() -> Real {
        Real {
            files: RealFiles,
            env: RealEnv,
            system: RealSystem,
            config: RealConfig,
            probes: probe::builtin(),
        }
    }

    pub fn deps(&self) -> Deps<'_> {
        Deps {
            files: &self.files,
            env: &self.env,
            system: &self.system,
            config: &self.config,
            probes: &self.probes,
            registry,
        }
    }
}

impl Default for Real {
    fn default() -> Self {
        Real::new()
    }
}

/// Built-in types plus the fact types of the probes. `now` is the Unix time
/// the scan starts.
pub fn registry(probes: &[Box<dyn Probe>], now: i64) -> Result<Registry, RegistryError> {
    let mut registry = Registry::builtin(now);
    for p in probes {
        for t in p.fact_types() {
            registry.add_fact_type(*t)?;
        }
    }
    Ok(registry)
}
