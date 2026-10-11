//! TOML: the `toml` extractor (the `toml` crate's parser plus lootr's
//! walker).
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::extract::Extractor;
use lootr::domain::extract::toml::Toml;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::NestedValue;

fuzz_target!(|data: &[u8]| {
    let mut entries = Vec::new();
    if Toml.extract(SecretSlice::new(data), &mut entries).is_ok() {
        let r = data.as_ptr_range();
        for e in &entries {
            if let NestedValue::Borrowed(s) = &e.value {
                let p = s.expose().as_ptr_range();
                assert!(r.start <= p.start && p.end <= r.end);
            }
        }
    }
});
