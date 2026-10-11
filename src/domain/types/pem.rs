//! `pem`: PEM files of any kind (TLS keys and certificates, `*.pem`,
//! `*.key`): what the file contains and whether its private keys are
//! encrypted.
//!
//! Every `-----BEGIN <label>-----` block with a matching END line is
//! counted. Private key blocks (labels ending in `PRIVATE KEY`) are read
//! with the `ssh_private_key` parser, which only decodes the non-secret
//! start of the structure; other blocks are only counted by label. One fact
//! per file; files without a PEM block produce none.

use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::ssh_key::SshPrivateKey;
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "pem";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new(
        "kind",
        AttrKind::Sym,
        "the most sensitive block: private_key | certificate | certificate_request | public_key | other",
    ),
    AttrSpec::new(
        "encrypted",
        AttrKind::Bool,
        "the file has private keys and all of them are passphrase protected",
    ),
    AttrSpec::new("private_keys", AttrKind::Int, "private key blocks"),
    AttrSpec::new("certificates", AttrKind::Int, "certificate blocks"),
    AttrSpec::optional(
        "key_type",
        AttrKind::Sym,
        "type of the first private key: rsa | dsa | ecdsa | ed25519 | ed448 | unknown",
    ),
];

const BEGIN: &[u8] = b"-----BEGIN ";
const DASHES: &[u8] = b"-----";
/// Most blocks looked at per file.
const MAX_BLOCKS: usize = 1024;

pub struct Pem;

/// One `BEGIN` ... `END` block: its label and byte range (both lines
/// included).
struct Block<'b> {
    label: &'b [u8],
    range: std::ops::Range<usize>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn blocks(bytes: &[u8]) -> Vec<Block<'_>> {
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < MAX_BLOCKS {
        let Some(i) = find(&bytes[from..], BEGIN).map(|i| from + i) else {
            break;
        };
        from = i + BEGIN.len();
        if i > 0 && bytes[i - 1] != b'\n' {
            continue;
        }
        let Some(label_len) = find(&bytes[from..], DASHES) else {
            break;
        };
        let label = &bytes[from..from + label_len];
        if label.contains(&b'\n') {
            continue;
        }
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(DASHES);
        let body = from + label_len + DASHES.len();
        let Some(end) = find(&bytes[body..], &end_marker).map(|e| body + e + end_marker.len())
        else {
            continue;
        };
        out.push(Block {
            label,
            range: i..end,
        });
        from = end;
    }
    out
}

impl DocumentType for Pem {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a PEM file (keys, certificates): kinds of blocks and whether private keys are encrypted"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        find(head, BEGIN).is_some()
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let bytes = doc.expose();
        let found = blocks(bytes);
        if found.is_empty() {
            return Ok(());
        }
        let (mut keys, mut certs, mut csrs, mut public) = (0, 0, 0, 0);
        let mut all_encrypted = true;
        let mut key_type = None;
        for b in &found {
            let label = b.label;
            if label.ends_with(b"PRIVATE KEY") {
                keys += 1;
                let (encrypted, kt) = private_key(doc, b);
                all_encrypted &= encrypted;
                key_type.get_or_insert(kt);
            } else if matches!(
                label,
                b"CERTIFICATE" | b"TRUSTED CERTIFICATE" | b"X509 CERTIFICATE"
            ) {
                certs += 1;
            } else if label.ends_with(b"CERTIFICATE REQUEST") {
                csrs += 1;
            } else if label.ends_with(b"PUBLIC KEY") {
                public += 1;
            }
        }
        let kind = if keys > 0 {
            "private_key"
        } else if certs > 0 {
            "certificate"
        } else if csrs > 0 {
            "certificate_request"
        } else if public > 0 {
            "public_key"
        } else {
            "other"
        };
        let mut attrs = Attrs::new();
        attrs.insert("kind", AttrValue::Sym(kind));
        attrs.insert("encrypted", AttrValue::Bool(keys > 0 && all_encrypted));
        attrs.insert("private_keys", AttrValue::Int(keys));
        attrs.insert("certificates", AttrValue::Int(certs));
        if let Some(kt) = key_type {
            attrs.insert("key_type", AttrValue::Sym(kt));
        }
        out.fact(attrs);
        Ok(())
    }
}

/// Whether a private key block is encrypted, and its key type.
fn private_key(doc: SecretSlice<'_>, block: &Block<'_>) -> (bool, &'static str) {
    let mut emitter = Emitter::default();
    let parsed = doc
        .slice(block.range.clone())
        .map(|s| SshPrivateKey.parse(s, &mut emitter));
    if let (Some(Ok(())), Some((_, attrs))) = (parsed, emitter.facts.pop()) {
        let encrypted = attrs.get("encrypted") == Some(&AttrValue::Bool(true));
        let kt = match attrs.get("key_type") {
            Some(AttrValue::Sym(s)) => s,
            _ => "unknown",
        };
        return (encrypted, kt);
    }
    // Labels the key parser does not know: only the header lines tell.
    let text = &doc.expose()[block.range.clone()];
    let encrypted = find(block.label, b"ENCRYPTED").is_some()
        || find(text, b"Proc-Type: 4,ENCRYPTED").is_some();
    (encrypted, "unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-envs/ssh");

    fn key(path: &str) -> String {
        #[allow(clippy::disallowed_methods)]
        std::fs::read_to_string(format!("{DIR}/{path}")).unwrap()
    }

    fn parse(text: &str) -> Attrs {
        let mut out = Emitter::default();
        Pem.parse(SecretSlice::new(text.as_bytes()), &mut out)
            .unwrap();
        assert!(out.values.is_empty());
        out.facts.pop().map(|f| f.1).unwrap_or_default()
    }

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    #[test]
    fn keys_and_certificates() {
        let bundle = format!("{CERT}{}", key("weak-rsa/home/.ssh/dummy_pem_rsa"));
        let a = parse(&bundle);
        assert_eq!(a["kind"], AttrValue::Sym("private_key"));
        assert_eq!(a["encrypted"], AttrValue::Bool(false));
        assert_eq!(a["private_keys"], AttrValue::Int(1));
        assert_eq!(a["certificates"], AttrValue::Int(1));
        assert_eq!(a["key_type"], AttrValue::Sym("rsa"));

        let a = parse(&key("encrypted-ed25519/home/.ssh/dummy_pkcs8_enc"));
        assert_eq!(a["encrypted"], AttrValue::Bool(true));
        let a = parse(&key("weak-rsa/home/.ssh/dummy_legacy_pem"));
        assert_eq!(a["encrypted"], AttrValue::Bool(true));

        let a = parse(&format!("{CERT}{CERT}"));
        assert_eq!(a["kind"], AttrValue::Sym("certificate"));
        assert_eq!(a["encrypted"], AttrValue::Bool(false));
        assert!(!a.contains_key("key_type"));
        let a = parse("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        assert_eq!(a["kind"], AttrValue::Sym("public_key"));
    }

    #[test]
    fn broken_blocks() {
        assert!(parse("-----BEGIN CERTIFICATE-----\nno end\n").is_empty());
        assert!(parse("x-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----").is_empty());
        let a = parse(
            "-----BEGIN FOO PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\n!!\n-----END FOO PRIVATE KEY-----\n",
        );
        assert_eq!(a["encrypted"], AttrValue::Bool(true));
        assert_eq!(a["key_type"], AttrValue::Sym("unknown"));
        let a = parse("-----BEGIN RSA PRIVATE KEY-----\n!!\n-----END RSA PRIVATE KEY-----\n");
        assert_eq!(a["encrypted"], AttrValue::Bool(false));
    }
}
