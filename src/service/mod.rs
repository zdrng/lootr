//! Service layer: the scan pipeline (pipes and filters).
//!
//! ```text
//! config ──► discover ──► collect ──► evaluate ──► ScanResult
//!            names/paths   secrets →    facts →
//!                          facts        findings
//! ```
//!
//! Services have no I/O of their own: they reach the system only through the
//! repository traits, so every test runs on the in-memory fakes. Only
//! [`collect`] sees secret bytes; [`evaluate`] and [`cel`] only see facts.
//!
//! - [`config`] - layering, includes, validation against type schemas
//! - [`discover`] - sources → candidates
//! - [`collect`] - candidates → facts
//! - [`evaluate`] - facts + rules + waivers → findings
//! - [`cel`] - CEL compile, schema check, evaluation
//! - [`git`] - git work tree and `.gitignore` checks for file facts
//! - [`probe`] - built-in system probes
//! - [`scan`] - runs the stages in order

pub mod cel;
pub mod collect;
pub mod config;
pub mod discover;
pub mod evaluate;
pub mod git;
pub mod probe;
pub mod scan;
