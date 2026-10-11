//! Small decoders used by the types: incremental base64 into a
//! [`SecretBuf`], CRC32 and base62 (GitHub token checksums).
//!
//! [`Base64Reader`] decodes on demand: a type asks for the first `n` bytes
//! and the reader decodes only as many 4-character groups as needed. That is
//! how the SSH key parser reads the public header of a key without decoding
//! the private part (at most the 2 bytes that share the last group with the
//! requested range are decoded beyond it).

use crate::domain::secret::{SecretBuf, SecretSlice};
use crate::domain::types::ParseError;

/// The two base64 alphabets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alphabet {
    /// `A-Z a-z 0-9 + /`, `=` padding, whitespace between groups ignored
    /// (PEM bodies).
    Standard,
    /// `A-Z a-z 0-9 - _`, no padding, no whitespace (JWT segments).
    UrlNoPad,
}

fn sextet(c: u8, alphabet: Alphabet) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' if alphabet == Alphabet::Standard => Some(62),
        b'/' if alphabet == Alphabet::Standard => Some(63),
        b'-' if alphabet == Alphabet::UrlNoPad => Some(62),
        b'_' if alphabet == Alphabet::UrlNoPad => Some(63),
        _ => None,
    }
}

/// Decodes base64 text into a fixed-capacity [`SecretBuf`] on demand.
pub struct Base64Reader<'a> {
    text: &'a [u8],
    pos: usize,
    alphabet: Alphabet,
    out: SecretBuf,
    /// End of input or padding seen.
    done: bool,
}

const TRUNCATED: ParseError = ParseError("truncated base64 data");
const INVALID: ParseError = ParseError("invalid base64 data");

impl<'a> Base64Reader<'a> {
    /// A reader over `text` that decodes at most `max` bytes.
    pub fn new(text: SecretSlice<'a>, alphabet: Alphabet, max: usize) -> Base64Reader<'a> {
        let estimate = text.len() / 4 * 3 + 3;
        Base64Reader {
            text: text.expose(),
            pos: 0,
            alphabet,
            out: SecretBuf::with_capacity(estimate.min(max)),
            done: false,
        }
    }

    /// Decodes until at least `n` bytes are available. Fails if the input
    /// ends first, contains invalid characters or `n` exceeds the limit.
    pub fn ensure(&mut self, n: usize) -> Result<(), ParseError> {
        while self.out.len() < n {
            if self.done || !self.decode_group()? {
                return Err(TRUNCATED);
            }
        }
        Ok(())
    }

    /// Decodes everything (up to the limit).
    pub fn decode_all(mut self) -> Result<SecretBuf, ParseError> {
        while !self.done && self.decode_group()? {}
        if self.done && self.pos < self.text.len() {
            // Only whitespace (or padding) may follow the end.
            let rest = &self.text[self.pos..];
            if !rest.iter().all(|&c| c == b'=' || c.is_ascii_whitespace()) {
                return Err(INVALID);
            }
        }
        Ok(self.out)
    }

    /// The bytes decoded so far.
    pub fn decoded(&self) -> SecretSlice<'_> {
        self.out.as_slice()
    }

    /// Decodes the next group of up to 4 characters. `Ok(false)` at the end
    /// of the input.
    fn decode_group(&mut self) -> Result<bool, ParseError> {
        let mut group = [0u8; 4];
        let mut n = 0;
        while n < 4 && self.pos < self.text.len() {
            let c = self.text[self.pos];
            self.pos += 1;
            if c.is_ascii_whitespace() && self.alphabet == Alphabet::Standard {
                continue;
            }
            if c == b'=' && self.alphabet == Alphabet::Standard {
                self.done = true;
                break;
            }
            group[n] = sextet(c, self.alphabet).ok_or(INVALID)?;
            n += 1;
        }
        if n < 4 {
            self.done = true;
        }
        let bytes = match n {
            0 => return Ok(false),
            1 => return Err(INVALID),
            2 => 1,
            3 => 2,
            _ => 3,
        };
        let word = u32::from(group[0]) << 18
            | u32::from(group[1]) << 12
            | u32::from(group[2]) << 6
            | u32::from(group[3]);
        let decoded = [(word >> 16) as u8, (word >> 8) as u8, word as u8];
        let mut src = &decoded[..bytes];
        let full = self.out.fill_with(|free| -> Result<usize, ParseError> {
            let k = src.len().min(free.len());
            free[..k].copy_from_slice(&src[..k]);
            src = &src[k..];
            Ok(k)
        })?;
        if full && !src.is_empty() {
            return Err(ParseError("encoded data too large"));
        }
        Ok(true)
    }
}

/// CRC-32 (IEEE 802.3, as in zlib/gzip).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `n` in base62 (`0-9A-Za-z`), left-padded with `0` to 6 characters (the
/// width of a GitHub token checksum; every `u32` fits).
pub fn base62_6(mut n: u32) -> [u8; 6] {
    let mut out = [b'0'; 6];
    for slot in out.iter_mut().rev() {
        *slot = BASE62[(n % 62) as usize];
        n /= 62;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: &str, alphabet: Alphabet) -> Result<Vec<u8>, ParseError> {
        let r = Base64Reader::new(SecretSlice::new(text.as_bytes()), alphabet, 1024);
        r.decode_all().map(|b| b.expose().to_vec())
    }

    #[test]
    fn decodes_standard_and_url_alphabets() {
        assert_eq!(decode("aGVsbG8=", Alphabet::Standard).unwrap(), b"hello");
        assert_eq!(decode("aGVs\nbG8h", Alphabet::Standard).unwrap(), b"hello!");
        assert_eq!(decode("aGk", Alphabet::UrlNoPad).unwrap(), b"hi");
        assert_eq!(decode("-_8", Alphabet::UrlNoPad).unwrap(), [0xfb, 0xff]);
        assert!(decode("a", Alphabet::UrlNoPad).is_err());
        assert!(decode("aGk=", Alphabet::UrlNoPad).is_err());
        assert!(decode("a b", Alphabet::UrlNoPad).is_err());
        assert!(decode("aGVsbG8=x", Alphabet::Standard).is_err());
        assert!(decode("a*bc", Alphabet::Standard).is_err());
    }

    #[test]
    fn decodes_only_what_is_asked_for() {
        // "public" followed by a "secret" part.
        let text = "cHVibGljc2VjcmV0";
        let mut r = Base64Reader::new(SecretSlice::new(text.as_bytes()), Alphabet::Standard, 64);
        // Whole 4-character groups: 4 bytes need 2 groups (6 bytes).
        r.ensure(4).unwrap();
        assert_eq!(r.decoded().expose(), b"public");
        r.ensure(6).unwrap();
        assert_eq!(r.decoded().expose(), b"public");
        r.ensure(7).unwrap();
        assert_eq!(r.decoded().expose(), b"publicsec");
        assert_eq!(r.ensure(13), Err(TRUNCATED));
    }

    #[test]
    fn respects_the_limit() {
        let text = "aGVsbG8gd29ybGQ=";
        let r = Base64Reader::new(SecretSlice::new(text.as_bytes()), Alphabet::Standard, 4);
        assert!(r.decode_all().is_err());
        let mut r = Base64Reader::new(SecretSlice::new(text.as_bytes()), Alphabet::Standard, 4);
        assert!(r.ensure(5).is_err());
    }

    #[test]
    fn crc32_and_base62() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(&base62_6(0), b"000000");
        assert_eq!(&base62_6(61), b"00000z");
        assert_eq!(&base62_6(62), b"000010");
        assert_eq!(&base62_6(u32::MAX), b"4gfFC3");
    }
}
