//! Domain layer: the model and everything that is a pure function of it.
//!
//! No I/O at all and no dependency on any other module of the crate. Types
//! and extractors are pure interpreters over [`secret::SecretBuf`] contents,
//! so they can be unit tested and fuzzed directly.
//!
//! - [`model`] - `Fact`, `AttrValue`, `Ident`, `PublicText`, `Location`,
//!   `Finding`, `Severity`
//! - [`secret`] - `SecretBuf` / `SecretSlice`
//! - [`types`] - document and value types, their schemas, the registry
//! - [`extract`] - extractors (dotenv, ini, json, yaml, toml)
//! - [`format`] - shared parsers with limits (YAML, JSON helpers, INI)
//! - [`config`] - config file layout and validated config data
//! - [`gitignore`] - `.gitignore` patterns (the files are read by the service)
//! - [`codec`] - incremental base64, CRC32, base62
//! - [`glob`], [`template`], [`time`] - small helpers without dependencies

pub mod codec;
pub mod config;
pub mod extract;
pub mod format;
pub mod gitignore;
pub mod glob;
pub mod model;
pub mod secret;
pub mod template;
pub mod time;
pub mod types;
