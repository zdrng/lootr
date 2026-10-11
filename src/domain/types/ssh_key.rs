//! `ssh_private_key`: private key files in OpenSSH, PEM (`RSA`/`DSA`/`EC
//! PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`) format.
//!
//! Only non-secret bytes are interpreted:
//!
//! - OpenSSH (`openssh-key-v1`): cipher, KDF and its options and the
//!   **public** keys come before the private section, so the base64 body is
//!   decoded only up to the end of the first public key ([`Base64Reader`]
//!   decodes on demand). The private section (with the key comment) is never
//!   decoded.
//! - PEM: the `Proc-Type` / `DEK-Info` header lines. For unencrypted RSA and
//!   DSA keys, the DER structure starts with the version and the public
//!   modulus (`p` for DSA); the body is decoded up to the first byte of it
//!   to get `bits`. EC keys store the curve after the private scalar, so
//!   they have no `bits`.
//! - PKCS#8: the algorithm identifier (key type, curve, DSA `p`, the RSA
//!   modulus at the start of the embedded RSA key). Encrypted PKCS#8 only
//!   tells the encryption scheme (PBES2 with PBKDF2/scrypt, cipher,
//!   iterations); the key type is `unknown`.

use crate::domain::codec::{Alphabet, Base64Reader};
use crate::domain::model::{AttrValue, Attrs};
use crate::domain::secret::SecretSlice;
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "ssh_private_key";

/// Upper bound for the decoded public prefix (an RSA-16384 public key is
/// about 2 KiB).
const MAX_DECODE: usize = 16 * 1024;

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("format", AttrKind::Sym, "openssh | pem | pkcs8"),
    AttrSpec::new(
        "encrypted",
        AttrKind::Bool,
        "the private key is protected by a passphrase",
    ),
    AttrSpec::new(
        "cipher",
        AttrKind::Sym,
        "none, an OpenSSH cipher (aes256-ctr, chacha20-poly1305@openssh.com, ...), \
         a PEM/PKCS#8 cipher (aes-128-cbc, aes-256-cbc, des-ede3-cbc, ...) or other",
    ),
    AttrSpec::new(
        "kdf",
        AttrKind::Sym,
        "key derivation: none | bcrypt | md5 (legacy PEM) | pbkdf2 | scrypt | pbes1 | other",
    ),
    AttrSpec::optional(
        "kdf_rounds",
        AttrKind::Int,
        "bcrypt rounds (OpenSSH) or PBKDF2 iterations (PKCS#8)",
    ),
    AttrSpec::new(
        "key_type",
        AttrKind::Sym,
        "rsa | dsa | ecdsa | ed25519 | ed448 | ecdsa-sk | ed25519-sk | unknown",
    ),
    AttrSpec::optional(
        "bits",
        AttrKind::Int,
        "key size in bits; absent when only the secret part would tell \
         (encrypted PEM/PKCS#8, PEM EC keys)",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Container {
    OpenSsh,
    /// Traditional PEM with the key type in the label.
    Pem(&'static str),
    Pkcs8,
    Pkcs8Encrypted,
}

const LABELS: &[(&[u8], Container)] = &[
    (b"OPENSSH PRIVATE KEY", Container::OpenSsh),
    (b"RSA PRIVATE KEY", Container::Pem("rsa")),
    (b"DSA PRIVATE KEY", Container::Pem("dsa")),
    (b"EC PRIVATE KEY", Container::Pem("ecdsa")),
    (b"PRIVATE KEY", Container::Pkcs8),
    (b"ENCRYPTED PRIVATE KEY", Container::Pkcs8Encrypted),
];

const BEGIN: &[u8] = b"-----BEGIN ";
const DASHES: &[u8] = b"-----";

pub struct SshPrivateKey;

impl DocumentType for SshPrivateKey {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a private key file (OpenSSH, PEM or PKCS#8); only the non-secret parts are read"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        find_begin(head).is_some()
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let bytes = doc.expose();
        let (container, body_start) = find_begin(bytes).ok_or(ParseError("no private key"))?;
        let label = LABELS
            .iter()
            .find(|(_, c)| *c == container)
            .map(|(l, _)| *l)
            .ok_or(ParseError("no private key"))?;
        let body_end = find_end(&bytes[body_start..], label)
            .map(|e| body_start + e)
            .ok_or(ParseError("missing END line"))?;
        let body = doc
            .slice(body_start..body_end)
            .ok_or(ParseError("missing END line"))?;
        let key = match container {
            Container::OpenSsh => parse_openssh(body)?,
            Container::Pem(key_type) => parse_pem(body, key_type)?,
            Container::Pkcs8 => parse_pkcs8(body)?,
            Container::Pkcs8Encrypted => parse_pkcs8_encrypted(body)?,
        };
        out.fact(key.attrs());
        Ok(())
    }
}

/// The first `-----BEGIN <private key label>-----` at the start of a line:
/// the container and the offset after the line.
fn find_begin(bytes: &[u8]) -> Option<(Container, usize)> {
    let mut from = 0;
    while let Some(i) = find(&bytes[from..], BEGIN).map(|i| from + i) {
        from = i + BEGIN.len();
        if i > 0 && bytes[i - 1] != b'\n' {
            continue;
        }
        let rest = &bytes[from..];
        let end = find(rest, DASHES)?;
        let label = &rest[..end];
        if let Some((_, c)) = LABELS.iter().find(|(l, _)| *l == label) {
            let after = from + end + DASHES.len();
            return Some((*c, after));
        }
    }
    None
}

/// Offset of `-----END <label>-----` in `bytes`.
fn find_end(bytes: &[u8], label: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = find(&bytes[from..], b"-----END ").map(|i| from + i) {
        let rest = &bytes[i + 9..];
        if rest.starts_with(label) && rest[label.len()..].starts_with(DASHES) {
            return Some(i);
        }
        from = i + 9;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// What a key file tells without its secret part.
#[derive(Debug, PartialEq, Eq)]
struct KeyInfo {
    format: &'static str,
    cipher: &'static str,
    kdf: &'static str,
    kdf_rounds: Option<i64>,
    key_type: &'static str,
    bits: Option<i64>,
}

impl KeyInfo {
    fn new(format: &'static str) -> KeyInfo {
        KeyInfo {
            format,
            cipher: "none",
            kdf: "none",
            kdf_rounds: None,
            key_type: "unknown",
            bits: None,
        }
    }

    fn attrs(&self) -> Attrs {
        let mut a = Attrs::new();
        a.insert("format", AttrValue::Sym(self.format));
        a.insert("encrypted", AttrValue::Bool(self.cipher != "none"));
        a.insert("cipher", AttrValue::Sym(self.cipher));
        a.insert("kdf", AttrValue::Sym(self.kdf));
        if let Some(r) = self.kdf_rounds {
            a.insert("kdf_rounds", AttrValue::Int(r));
        }
        a.insert("key_type", AttrValue::Sym(self.key_type));
        if let Some(b) = self.bits {
            a.insert("bits", AttrValue::Int(b));
        }
        a
    }
}

/// Picks the constant equal to `name`, or `other`.
fn sym(name: &[u8], known: &[&'static str], other: &'static str) -> &'static str {
    known
        .iter()
        .find(|k| k.as_bytes() == name)
        .copied()
        .unwrap_or(other)
}

/// A cursor over the decoded prefix: every read decodes just enough.
struct Cursor<'r, 'a> {
    r: &'r mut Base64Reader<'a>,
    pos: usize,
}

const TRUNCATED: ParseError = ParseError("truncated key");

impl Cursor<'_, '_> {
    fn byte(&mut self) -> Result<u8, ParseError> {
        self.r.ensure(self.pos + 1)?;
        let b = *self.r.decoded().expose().get(self.pos).ok_or(TRUNCATED)?;
        self.pos += 1;
        Ok(b)
    }

    /// The next `len` bytes (decoded now).
    fn take(&mut self, len: usize) -> Result<&[u8], ParseError> {
        let end = self.pos.checked_add(len).ok_or(TRUNCATED)?;
        self.r.ensure(end)?;
        let start = self.pos;
        self.pos = end;
        self.r.decoded().expose().get(start..end).ok_or(TRUNCATED)
    }

    /// Skips `len` bytes without looking at them (they are decoded by the
    /// next read; only used for public data).
    fn skip(&mut self, len: usize) -> Result<(), ParseError> {
        self.pos = self.pos.checked_add(len).ok_or(TRUNCATED)?;
        Ok(())
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// SSH wire `string`: its length.
    fn ssh_len(&mut self) -> Result<usize, ParseError> {
        usize::try_from(self.u32()?).map_err(|_| TRUNCATED)
    }

    /// Bit length of an unsigned big-endian integer of `len` bytes, reading
    /// only up to its first non-zero byte.
    fn uint_bits(&mut self, len: usize) -> Result<Option<i64>, ParseError> {
        for i in 0..len {
            let b = self.byte()?;
            if b != 0 {
                let rest = i64::try_from(len - i - 1).map_err(|_| TRUNCATED)?;
                return Ok(Some(rest * 8 + i64::from(8 - b.leading_zeros())));
            }
        }
        Ok(None)
    }

    /// DER tag and length.
    fn der(&mut self) -> Result<(u8, usize), ParseError> {
        let tag = self.byte()?;
        let first = self.byte()?;
        if first < 0x80 {
            return Ok((tag, usize::from(first)));
        }
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return Err(ParseError("unsupported DER length"));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | usize::from(self.byte()?);
        }
        Ok((tag, len))
    }

    /// A DER element with tag `tag`: its content length.
    fn expect(&mut self, tag: u8) -> Result<usize, ParseError> {
        let (t, len) = self.der()?;
        if t != tag {
            return Err(ParseError("unexpected DER structure"));
        }
        Ok(len)
    }

    /// A small DER INTEGER value (iteration counts).
    fn small_int(&mut self, len: usize) -> Result<Option<i64>, ParseError> {
        if len == 0 || len > 7 {
            self.skip(len)?;
            return Ok(None);
        }
        let mut v = 0i64;
        for &b in self.take(len)? {
            v = (v << 8) | i64::from(b);
        }
        Ok(Some(v))
    }
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;

fn reader(body: SecretSlice<'_>) -> Base64Reader<'_> {
    Base64Reader::new(body, Alphabet::Standard, MAX_DECODE)
}

// ---- OpenSSH ------------------------------------------------------------------

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

const OPENSSH_CIPHERS: &[&str] = &[
    "none",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "3des-cbc",
];

fn parse_openssh(body: SecretSlice<'_>) -> Result<KeyInfo, ParseError> {
    let mut r = reader(body);
    let mut c = Cursor { r: &mut r, pos: 0 };
    if c.take(OPENSSH_MAGIC.len())? != OPENSSH_MAGIC {
        return Err(ParseError("not an openssh-key-v1 key"));
    }
    let mut info = KeyInfo::new("openssh");
    let len = c.ssh_len()?;
    info.cipher = sym(c.take(len)?, OPENSSH_CIPHERS, "other");
    let len = c.ssh_len()?;
    info.kdf = sym(c.take(len)?, &["none", "bcrypt"], "other");
    let options_len = c.ssh_len()?;
    if info.kdf == "bcrypt" && options_len >= 8 {
        // string salt, uint32 rounds.
        let salt = c.ssh_len()?;
        c.skip(salt)?;
        info.kdf_rounds = Some(i64::from(c.u32()?));
    } else {
        c.skip(options_len)?;
    }
    if c.u32()? == 0 {
        return Err(ParseError("no keys in the file"));
    }
    // The first public key blob; reading stops inside it.
    let _blob_len = c.ssh_len()?;
    let len = c.ssh_len()?;
    let key_type = c.take(len)?.to_vec();
    let (name, bits) = match key_type.as_slice() {
        b"ssh-rsa" => {
            let e = c.ssh_len()?;
            c.skip(e)?;
            let n = c.ssh_len()?;
            ("rsa", c.uint_bits(n)?)
        }
        b"ssh-dss" => {
            let p = c.ssh_len()?;
            ("dsa", c.uint_bits(p)?)
        }
        b"ecdsa-sha2-nistp256" => ("ecdsa", Some(256)),
        b"ecdsa-sha2-nistp384" => ("ecdsa", Some(384)),
        b"ecdsa-sha2-nistp521" => ("ecdsa", Some(521)),
        b"ssh-ed25519" => ("ed25519", Some(256)),
        b"ssh-ed448" => ("ed448", Some(456)),
        b"sk-ecdsa-sha2-nistp256@openssh.com" => ("ecdsa-sk", Some(256)),
        b"sk-ssh-ed25519@openssh.com" => ("ed25519-sk", Some(256)),
        _ => ("unknown", None),
    };
    info.key_type = name;
    info.bits = bits;
    Ok(info)
}

// ---- PEM ----------------------------------------------------------------------

const PEM_CIPHERS: &[&str] = &[
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "des-ede3-cbc",
    "des-cbc",
];

fn parse_pem(body: SecretSlice<'_>, key_type: &'static str) -> Result<KeyInfo, ParseError> {
    let mut info = KeyInfo::new("pem");
    info.key_type = key_type;
    let bytes = body.expose();
    // RFC 1421 headers: `Name: value` lines up to an empty line.
    let mut offset = 0;
    let mut encrypted = false;
    let mut cipher = None;
    let mut lines = bytes.split(|&b| b == b'\n').peekable();
    if lines
        .peek()
        .is_some_and(|l| l.iter().all(|b| b.is_ascii_whitespace()))
    {
        offset += lines.next().map_or(0, |l| l.len() + 1);
    }
    if lines.peek().is_some_and(|l| l.contains(&b':')) {
        for line in lines.by_ref() {
            offset += line.len() + 1;
            let line = line.trim_ascii();
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix(b"Proc-Type:") {
                encrypted = v.trim_ascii().ends_with(b"ENCRYPTED");
            } else if let Some(v) = line.strip_prefix(b"DEK-Info:") {
                let alg = v.trim_ascii().split(|&b| b == b',').next().unwrap_or(b"");
                cipher = Some(sym(&alg.to_ascii_lowercase(), PEM_CIPHERS, "other"));
            }
        }
    }
    if encrypted {
        info.cipher = cipher.unwrap_or("other");
        // EVP_BytesToKey: one round of MD5 over passphrase and salt.
        info.kdf = "md5";
        return Ok(info);
    }
    let rest = body
        .slice(offset.min(bytes.len())..bytes.len())
        .ok_or(TRUNCATED)?;
    if key_type == "rsa" || key_type == "dsa" {
        // RSAPrivateKey / DSA: SEQUENCE { version, n (or p), ... }.
        let mut r = reader(rest);
        let mut c = Cursor { r: &mut r, pos: 0 };
        c.expect(SEQUENCE)?;
        let version = c.expect(INTEGER)?;
        c.skip(version)?;
        let n = c.expect(INTEGER)?;
        info.bits = c.uint_bits(n)?;
    }
    Ok(info)
}

// ---- PKCS#8 -------------------------------------------------------------------

const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_DSA: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2B, 0x65, 0x71];

const CURVES: &[(&[u8], i64)] = &[
    (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], 256), // P-256
    (&[0x2B, 0x81, 0x04, 0x00, 0x22], 384),                   // P-384
    (&[0x2B, 0x81, 0x04, 0x00, 0x23], 521),                   // P-521
    (&[0x2B, 0x81, 0x04, 0x00, 0x0A], 256),                   // secp256k1
];

const OID_PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
const OID_SCRYPT: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x04, 0x0B];
/// PKCS#5 v1 and PKCS#12 password-based encryption arcs.
const OID_PBES1_PREFIXES: &[&[u8]] = &[
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05],
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01],
];

const PKCS8_CIPHERS: &[(&[u8], &str)] = &[
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02],
        "aes-128-cbc",
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16],
        "aes-192-cbc",
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        "aes-256-cbc",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07],
        "des-ede3-cbc",
    ),
];

/// PrivateKeyInfo: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING key }.
fn parse_pkcs8(body: SecretSlice<'_>) -> Result<KeyInfo, ParseError> {
    let mut info = KeyInfo::new("pkcs8");
    let mut r = reader(body);
    let mut c = Cursor { r: &mut r, pos: 0 };
    c.expect(SEQUENCE)?;
    let version = c.expect(INTEGER)?;
    c.skip(version)?;
    let alg_len = c.expect(SEQUENCE)?;
    let alg_end = c.pos.saturating_add(alg_len);
    let oid_len = c.expect(OID)?;
    let oid = c.take(oid_len)?.to_vec();
    if oid == OID_RSA || oid == OID_RSA_PSS {
        info.key_type = "rsa";
        // The embedded RSAPrivateKey starts with version and modulus.
        c.pos = alg_end;
        c.expect(OCTET_STRING)?;
        c.expect(SEQUENCE)?;
        let version = c.expect(INTEGER)?;
        c.skip(version)?;
        let n = c.expect(INTEGER)?;
        info.bits = c.uint_bits(n)?;
    } else if oid == OID_EC {
        info.key_type = "ecdsa";
        let (tag, len) = c.der()?;
        info.bits = match tag {
            OID => {
                let curve = c.take(len)?;
                CURVES.iter().find(|(o, _)| *o == curve).map(|(_, b)| *b)
            }
            // Explicit parameters: SEQUENCE { version, FieldID { prime-field
            // OID, prime p }, ... }; the size of p is the curve size.
            SEQUENCE => {
                let version = c.expect(INTEGER)?;
                c.skip(version)?;
                c.expect(SEQUENCE)?;
                let field = c.expect(OID)?;
                c.skip(field)?;
                let p = c.expect(INTEGER)?;
                c.uint_bits(p)?
            }
            _ => None,
        };
    } else if oid == OID_DSA {
        info.key_type = "dsa";
        // Dss-Parms: SEQUENCE { p, q, g }.
        if c.expect(SEQUENCE).is_ok() {
            let p = c.expect(INTEGER)?;
            info.bits = c.uint_bits(p)?;
        }
    } else if oid == OID_ED25519 {
        info.key_type = "ed25519";
        info.bits = Some(256);
    } else if oid == OID_ED448 {
        info.key_type = "ed448";
        info.bits = Some(456);
    }
    Ok(info)
}

/// EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }.
/// Only the algorithm identifier is read.
fn parse_pkcs8_encrypted(body: SecretSlice<'_>) -> Result<KeyInfo, ParseError> {
    let mut info = KeyInfo::new("pkcs8");
    info.cipher = "other";
    info.kdf = "other";
    let mut r = reader(body);
    let mut c = Cursor { r: &mut r, pos: 0 };
    c.expect(SEQUENCE)?;
    c.expect(SEQUENCE)?;
    let oid_len = c.expect(OID)?;
    let oid = c.take(oid_len)?.to_vec();
    if OID_PBES1_PREFIXES.iter().any(|p| oid.starts_with(p)) && oid != OID_PBES2 {
        info.kdf = "pbes1";
        return Ok(info);
    }
    if oid != OID_PBES2 {
        return Ok(info);
    }
    // PBES2-params: SEQUENCE { keyDerivationFunc, encryptionScheme }.
    c.expect(SEQUENCE)?;
    let kdf_len = c.expect(SEQUENCE)?;
    let kdf_end = c.pos.saturating_add(kdf_len);
    let kdf_oid_len = c.expect(OID)?;
    let kdf_oid = c.take(kdf_oid_len)?.to_vec();
    if kdf_oid == OID_PBKDF2 {
        info.kdf = "pbkdf2";
        // PBKDF2-params: SEQUENCE { salt OCTET STRING, iterationCount, ... }.
        c.expect(SEQUENCE)?;
        let salt = c.expect(OCTET_STRING)?;
        c.skip(salt)?;
        let n = c.expect(INTEGER)?;
        info.kdf_rounds = c.small_int(n)?;
    } else if kdf_oid == OID_SCRYPT {
        info.kdf = "scrypt";
    }
    c.pos = kdf_end;
    c.expect(SEQUENCE)?;
    let enc_len = c.expect(OID)?;
    let enc = c.take(enc_len)?;
    info.cipher = PKCS8_CIPHERS
        .iter()
        .find(|(o, _)| *o == enc)
        .map_or("other", |(_, name)| *name);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-envs/ssh");

    fn key(path: &str) -> Vec<u8> {
        #[allow(clippy::disallowed_methods)]
        std::fs::read(format!("{DIR}/{path}")).unwrap()
    }

    fn info(data: &[u8]) -> Attrs {
        let t = SshPrivateKey;
        assert!(t.sniff(&data[..data.len().min(512)]));
        let mut out = Emitter::default();
        t.parse(SecretSlice::new(data), &mut out).unwrap();
        assert!(out.values.is_empty());
        assert_eq!(out.facts.len(), 1);
        let attrs = out.facts.pop().unwrap().1;
        // The comment (with the canary) is in the private section.
        let text = format!("{attrs:?}");
        assert!(!text.contains(CANARY), "{text}");
        attrs
    }

    fn summary(a: &Attrs) -> String {
        let mut parts = Vec::new();
        for name in [
            "format",
            "encrypted",
            "cipher",
            "kdf",
            "kdf_rounds",
            "key_type",
            "bits",
        ] {
            parts.push(a.get(name).map_or("-".to_string(), |v| v.to_string()));
        }
        parts.join(" ")
    }

    #[test]
    fn openssh_keys() {
        let k = |p| summary(&info(&key(p)));
        assert_eq!(
            k("unencrypted/home/.ssh/dummy_id_ed25519"),
            "openssh false none none - ed25519 256"
        );
        assert_eq!(
            k("unencrypted/home/.ssh/dummy_id_ecdsa"),
            "openssh false none none - ecdsa 384"
        );
        assert_eq!(
            k("encrypted-ed25519/home/.ssh/dummy_id_ed25519"),
            "openssh true aes256-ctr bcrypt 24 ed25519 256"
        );
        assert_eq!(
            k("weak-rsa/home/.ssh/dummy_id_rsa_1024"),
            "openssh true aes256-ctr bcrypt 24 rsa 1024"
        );
        assert_eq!(
            k("weak-rsa/home/.ssh/dummy_id_rsa_3072"),
            "openssh false none none - rsa 3072"
        );
    }

    #[test]
    fn pem_keys() {
        let k = |p| summary(&info(&key(p)));
        assert_eq!(
            k("weak-rsa/home/.ssh/dummy_legacy_pem"),
            "pem true aes-128-cbc md5 - rsa -"
        );
        assert_eq!(
            k("weak-rsa/home/.ssh/dummy_pem_rsa"),
            "pem false none none - rsa 2048"
        );
    }

    #[test]
    fn pkcs8_keys() {
        let k = |p| summary(&info(&key(p)));
        assert_eq!(
            k("in-documents/home/Documents/keys/dummy_deploy_key"),
            "pkcs8 false none none - ecdsa 256"
        );
        assert_eq!(
            k("in-documents/home/Documents/keys/dummy_ec_explicit"),
            "pkcs8 false none none - ecdsa 256"
        );
        assert_eq!(
            k("in-documents/home/Documents/keys/dummy_pkcs8_rsa"),
            "pkcs8 false none none - rsa 2048"
        );
        assert_eq!(
            k("encrypted-ed25519/home/.ssh/dummy_pkcs8_enc"),
            "pkcs8 true aes-256-cbc pbkdf2 2048 unknown -"
        );
    }

    /// The parser decodes the OpenSSH body only up to the public key: the
    /// private section after it may be garbage.
    #[test]
    fn openssh_private_section_is_never_decoded() {
        let data = key("unencrypted/home/.ssh/dummy_id_ed25519");
        let text = String::from_utf8(data).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Header (15) + cipher (8) + kdf (8) + options (4) + nkeys (4) +
        // blob (4 + 51) = 94 bytes: the first 128 base64 characters (96
        // bytes) cover it; everything after is replaced by invalid base64.
        let body: String = lines[1..lines.len() - 1].concat();
        let broken = format!(
            "{}\n{}{}\n{}\n",
            lines[0],
            &body[..128],
            "*".repeat(body.len() - 128),
            lines[lines.len() - 1]
        );
        assert_eq!(
            summary(&info(broken.as_bytes())),
            "openssh false none none - ed25519 256"
        );
    }

    #[test]
    fn sniff_and_errors() {
        let t = SshPrivateKey;
        assert!(!t.sniff(b"ssh-ed25519 AAAAC3Nza... user@host"));
        assert!(!t.sniff(b"-----BEGIN CERTIFICATE-----\n"));
        assert!(!t.sniff(b"x-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(t.sniff(b"Bag Attributes\n-----BEGIN PRIVATE KEY-----\n"));
        let parse = |s: &str| {
            let mut out = Emitter::default();
            t.parse(SecretSlice::new(s.as_bytes()), &mut out)
        };
        assert_eq!(
            parse("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"),
            Err(ParseError("missing END line"))
        );
        assert!(
            parse("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
                .is_err()
        );
        assert!(
            parse("-----BEGIN RSA PRIVATE KEY-----\n!!\n-----END RSA PRIVATE KEY-----").is_err()
        );
        assert!(parse("-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----").is_err());
    }

    #[test]
    fn encrypted_pem_without_dek_info() {
        let pem = "-----BEGIN DSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END DSA PRIVATE KEY-----\n";
        assert_eq!(summary(&info(pem.as_bytes())), "pem true other md5 - dsa -");
    }
}
