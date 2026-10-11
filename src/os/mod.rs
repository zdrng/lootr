//! OS infrastructure: the only code besides repository implementations that
//! talks to the kernel. Used by `repository` (file access) and by `main` /
//! `cli` (hardening, writing the report). All calls go through `rustix`'s
//! safe wrappers; the crate forbids `unsafe`.

pub mod hardening;
pub mod open;
