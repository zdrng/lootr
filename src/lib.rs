//! lootr: shows what a process can reach with the rights of the current
//! user (SSH keys, tokens, cloud credentials, ...), interprets every artifact
//! into non-secret facts and checks them against a CEL policy. See PLAN.md
//! for the design.
//!
//! # Layers
//!
//! ```text
//! presentation   cli/ (clap, wiring, exit codes), report/
//! service        scan pipeline: discover → collect → evaluate (no I/O)
//! repository     all data access: traits, real impls, in-memory fakes
//! domain         model, SecretBuf, types, extractors, config data (no I/O)
//!   os/          hardening, secure open (used by repository impls and cli)
//! ```
//!
//! Dependencies point downwards only; `domain` depends on nothing in the
//! crate. The library exists so fuzz targets and integration tests can call
//! the pure parts directly; the product is the `lootr` binary.

#![forbid(unsafe_code)]

pub mod cli;
pub mod domain;
pub mod os;
pub mod report;
pub mod repository;
pub mod service;
pub mod testing;
