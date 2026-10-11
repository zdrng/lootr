//! The real process environment. Values are copied into a `SecretBuf` one
//! at a time, only for variables a source selected, and the intermediate
//! `OsString` is zeroized. The process environment block itself cannot be
//! wiped (see README, "Honest limits").

#![allow(clippy::disallowed_methods)] // the one place that reads the environment

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;

use zeroize::Zeroize;

use crate::domain::secret::SecretBuf;
use crate::repository::EnvRepository;

pub struct RealEnv;

impl EnvRepository for RealEnv {
    fn names(&self) -> Vec<OsString> {
        // `vars_os` would copy every value; take the names only.
        let mut names: Vec<OsString> = std::env::vars_os()
            .map(|(name, value)| {
                value.into_vec().zeroize();
                name
            })
            .collect();
        names.sort();
        names
    }

    fn value(&self, name: &OsStr) -> Option<SecretBuf> {
        std::env::var_os(name).map(|v| SecretBuf::take(v.into_vec()))
    }

    fn setting(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}
