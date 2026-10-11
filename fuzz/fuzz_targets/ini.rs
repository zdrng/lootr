//! INI: the `ini` extractor and every INI-based document type
//! (aws_credentials, pypirc, npmrc). INI parsing never fails; values must
//! be slices of the input.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::extract::Extractor;
use lootr::domain::extract::ini::Ini;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::aws::AwsCredentials;
use lootr::domain::types::npmrc::Npmrc;
use lootr::domain::types::pypirc::Pypirc;
use lootr::domain::types::{DocumentType, Emitter, NestedValue};

fn inside(data: &[u8], v: &NestedValue<'_>) {
    if let NestedValue::Borrowed(s) = v {
        let r = data.as_ptr_range();
        let p = s.expose().as_ptr_range();
        assert!(r.start <= p.start && p.end <= r.end);
    }
}

fuzz_target!(|data: &[u8]| {
    let doc = SecretSlice::new(data);
    let mut entries = Vec::new();
    if Ini.extract(doc, &mut entries).is_ok() {
        entries.iter().for_each(|e| inside(data, &e.value));
    }
    let types: [&dyn DocumentType; 3] = [&AwsCredentials, &Pypirc, &Npmrc];
    for t in types {
        let mut out = Emitter::default();
        assert!(t.parse(doc, &mut out).is_ok());
        assert!(out.facts.len() <= 1);
        out.values.iter().for_each(|(_, v)| inside(data, v));
    }
});
