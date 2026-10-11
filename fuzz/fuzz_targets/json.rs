//! JSON: the `json` extractor and every JSON document type (gcp_credentials,
//! azure_profile, docker_config).
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::extract::Extractor;
use lootr::domain::extract::json::Json;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::azure::AzureProfile;
use lootr::domain::types::docker_config::DockerConfig;
use lootr::domain::types::gcp::GcpCredentials;
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
    if Json.extract(doc, &mut entries).is_ok() {
        entries.iter().for_each(|e| inside(data, &e.value));
    }
    let types: [&dyn DocumentType; 3] = [&GcpCredentials, &AzureProfile, &DockerConfig];
    for t in types {
        let _ = t.sniff(&data[..data.len().min(512)]);
        let mut out = Emitter::default();
        if t.parse(doc, &mut out).is_ok() {
            assert!(out.facts.len() <= 1);
            out.values.iter().for_each(|(_, v)| inside(data, v));
        }
    }
});
