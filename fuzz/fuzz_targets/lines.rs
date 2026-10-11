//! Line and token based credential files: netrc, git_credentials, and the
//! PEM block scanner (pem). None of them fails on bad input; every value
//! they pass on is a slice of the input or a decoded copy.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::git_credentials::GitCredentials;
use lootr::domain::types::netrc::Netrc;
use lootr::domain::types::pem::Pem;
use lootr::domain::types::{DocumentType, Emitter, NestedValue};

fuzz_target!(|data: &[u8]| {
    let doc = SecretSlice::new(data);
    let types: [&dyn DocumentType; 3] = [&Netrc, &GitCredentials, &Pem];
    for t in types {
        let _ = t.sniff(&data[..data.len().min(512)]);
        let mut out = Emitter::default();
        assert!(t.parse(doc, &mut out).is_ok());
        assert!(out.facts.len() <= 1);
        for (_, v) in &out.values {
            if let NestedValue::Borrowed(s) = v {
                let r = data.as_ptr_range();
                let p = s.expose().as_ptr_range();
                assert!(r.start <= p.start && p.end <= r.end);
            }
        }
    }
});
