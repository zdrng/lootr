//! `jwt` (and `github_token`, same input shape): classify arbitrary values.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::ValueType;
use lootr::domain::types::github_token::GithubToken;
use lootr::domain::types::jwt::Jwt;

fuzz_target!(|data: &[u8]| {
    let value = SecretSlice::new(data);
    if let Some(attrs) = Jwt::new(1_791_468_180).classify(value) {
        assert!(attrs.contains_key("alg") && attrs.contains_key("expired"));
    }
    let _ = GithubToken.classify(value);
});
