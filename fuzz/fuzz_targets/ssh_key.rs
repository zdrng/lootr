//! `ssh_private_key`: sniff and parse arbitrary bytes (OpenSSH, PEM, PKCS#8
//! containers with hostile lengths and DER structures).
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::ssh_key::SshPrivateKey;
use lootr::domain::types::{DocumentType, Emitter};

fuzz_target!(|data: &[u8]| {
    let t = SshPrivateKey;
    let _ = t.sniff(&data[..data.len().min(512)]);
    let mut out = Emitter::default();
    if t.parse(SecretSlice::new(data), &mut out).is_ok() {
        // One fact per key file, never nested values.
        assert_eq!(out.facts.len(), 1);
        assert!(out.values.is_empty());
    }
});
