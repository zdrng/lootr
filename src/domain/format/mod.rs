//! File formats shared by document types and extractors. Pure parsers with
//! limits (depth, size, alias expansion); values stay slices of the file
//! buffer where the format allows it, otherwise wiped copies.
//!
//! - [`yaml`] - bounded tree on top of `saphyr-parser` events
//! - [`json`] - `serde_json` helpers ([`json::SecretValue`]) and a walker
//!   over any serde format (json and toml extractors)
//! - [`ini`] - INI / properties lines

pub mod ini;
pub mod json;
pub mod yaml;

/// Text without NUL bytes: the cheap `sniff` of text-based document types.
pub fn is_text(head: &[u8]) -> bool {
    !head.contains(&0)
}
