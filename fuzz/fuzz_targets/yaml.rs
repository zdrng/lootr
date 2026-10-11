//! YAML: the bounded loader, the `yaml` extractor and every YAML document
//! type (kubeconfig, gh_hosts, github_workflow). Alias bombs, deep nesting
//! and huge documents must end in an error, never in a hang or a crash.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::extract::Extractor;
use lootr::domain::extract::yaml::YamlExtractor;
use lootr::domain::format::yaml::Yaml;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::gh_hosts::GhHosts;
use lootr::domain::types::github_workflow::GithubWorkflow;
use lootr::domain::types::kubeconfig::Kubeconfig;
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
    let _ = Yaml::parse(doc);
    let mut entries = Vec::new();
    if YamlExtractor.extract(doc, &mut entries).is_ok() {
        entries.iter().for_each(|e| inside(data, &e.value));
    }
    let types: [&dyn DocumentType; 3] = [&Kubeconfig, &GhHosts, &GithubWorkflow];
    for t in types {
        let _ = t.sniff(&data[..data.len().min(512)]);
        let mut out = Emitter::default();
        if t.parse(doc, &mut out).is_ok() {
            out.values.iter().for_each(|(_, v)| inside(data, v));
        }
    }
});
