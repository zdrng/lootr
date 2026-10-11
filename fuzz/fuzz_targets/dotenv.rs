//! `dotenv` extractor: every entry must be a slice of the input.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::extract::Extractor;
use lootr::domain::extract::dotenv::Dotenv;
use lootr::domain::secret::SecretSlice;

fuzz_target!(|data: &[u8]| {
    let mut entries = Vec::new();
    if Dotenv.extract(SecretSlice::new(data), &mut entries).is_ok() {
        let range = data.as_ptr_range();
        for e in &entries {
            let v = e.value.as_slice().expose().as_ptr_range();
            assert!(range.start <= v.start && v.end <= range.end);
        }
    }
});
