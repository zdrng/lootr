//! Process hardening, done at startup before any file is opened:
//!
//! - `setrlimit(RLIMIT_CORE, 0)`: no core dumps that could contain secrets;
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)`: no core dumps and no `ptrace`
//!   attach by other processes of the same user (root still can).
//!
//! macOS has no unprivileged equivalent of `PR_SET_DUMPABLE` without
//! `unsafe` (`PT_DENY_ATTACH`); only the core limit applies there.

use rustix::process::{Resource, Rlimit, setrlimit};

#[derive(Debug, thiserror::Error)]
pub enum HardeningError {
    #[error("disabling core dumps failed: {0}")]
    CoreLimit(rustix::io::Errno),
    #[error("prctl(PR_SET_DUMPABLE, 0) failed: {0}")]
    Dumpable(rustix::io::Errno),
}

/// Applies all hardening steps. Failing is an error: lootr does not read
/// secrets in a process that could dump them.
pub fn harden() -> Result<(), HardeningError> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(HardeningError::CoreLimit)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(HardeningError::Dumpable)?;
    Ok(())
}
