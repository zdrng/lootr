//! Value types added in M3: api_key, gitlab_token, aws_access_key_id.
//! They run on every environment variable and extracted value.
#![no_main]
// `fuzz_target!` expands to libFuzzer debug output code that creates files.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use lootr::domain::secret::SecretSlice;
use lootr::domain::types::ValueType;
use lootr::domain::types::api_key::ApiKey;
use lootr::domain::types::aws::AwsAccessKeyId;
use lootr::domain::types::gitlab_token::GitlabToken;

fuzz_target!(|data: &[u8]| {
    let value = SecretSlice::new(data);
    if let Some(a) = ApiKey.classify(value) {
        assert!(a.contains_key("service") && a.contains_key("kind"));
    }
    if let Some(a) = GitlabToken.classify(value) {
        assert!(a.contains_key("kind"));
    }
    if AwsAccessKeyId.classify(value).is_some() {
        assert_eq!(data.len(), 20);
    }
});
