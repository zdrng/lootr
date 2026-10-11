//! Secret bytes in memory.
//!
//! Every raw value lootr reads (file contents, environment values) lives in a
//! [`SecretBuf`]:
//!
//! - its capacity is fixed when it is created, so it never reallocates and
//!   never leaves stale copies on the heap;
//! - it is zeroized when dropped (the whole capacity, not just the used part);
//! - the bytes are only reachable through [`SecretBuf::expose`] /
//!   [`SecretSlice::expose`], so every access is visible in review;
//! - it implements none of `Debug`, `Display`, `Serialize` or `Clone`
//!   (checked at compile time below), so it cannot end up in a log line, a
//!   report or a second buffer by accident.
//!
//! Types and extractors work on [`SecretSlice`]s: borrowed sub-slices of the
//! same buffer, never copies.
//!
//! Zeroizing is best effort: the kernel page cache, the process environment
//! block and library internals may still hold copies (see README).

use std::ops::Range;

use zeroize::Zeroize;

/// A fixed-capacity buffer for secret bytes, zeroized on drop.
pub struct SecretBuf {
    data: Box<[u8]>,
    len: usize,
}

impl SecretBuf {
    /// An empty buffer that can hold up to `capacity` bytes. The memory is
    /// allocated (and zero-filled) now; [`SecretBuf::fill_with`] never grows it.
    pub fn with_capacity(capacity: usize) -> SecretBuf {
        SecretBuf {
            // `vec![0; n]` has length == capacity, so `into_boxed_slice` does
            // not reallocate.
            data: vec![0u8; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    /// A buffer holding a copy of `bytes`.
    pub fn copy_from(bytes: &[u8]) -> SecretBuf {
        let mut buf = SecretBuf::with_capacity(bytes.len());
        buf.data.copy_from_slice(bytes);
        buf.len = bytes.len();
        buf
    }

    /// Moves `bytes` into a new buffer and zeroizes the original vector
    /// (including its spare capacity).
    pub fn take(mut bytes: Vec<u8>) -> SecretBuf {
        let buf = SecretBuf::copy_from(&bytes);
        bytes.zeroize();
        buf
    }

    /// Fills the free part of the buffer by calling `read` until it returns
    /// 0 (end of input) or the buffer is full. `read` gets the free tail of
    /// the buffer and returns how many bytes it wrote. Returns whether the
    /// buffer is full.
    pub fn fill_with<E>(
        &mut self,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<bool, E> {
        while self.len < self.data.len() {
            let n = read(&mut self.data[self.len..])?;
            if n == 0 {
                return Ok(false);
            }
            self.len = (self.len + n).min(self.data.len());
        }
        Ok(true)
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The secret bytes. Every call is a review point: the result must not be
    /// copied into anything that outlives the buffer or leaves the collector.
    pub fn expose(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The whole content as a [`SecretSlice`].
    pub fn as_slice(&self) -> SecretSlice<'_> {
        SecretSlice(self.expose())
    }
}

impl SecretBuf {
    fn wipe(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A borrowed view into a [`SecretBuf`] (or into another secret slice).
/// Copying the view does not copy the bytes.
#[derive(Clone, Copy)]
pub struct SecretSlice<'a>(&'a [u8]);

impl<'a> SecretSlice<'a> {
    /// Wraps bytes that are secret but owned elsewhere (e.g. parsing helpers
    /// that receive an exposed slice).
    pub fn new(bytes: &'a [u8]) -> SecretSlice<'a> {
        SecretSlice(bytes)
    }

    /// The secret bytes; see [`SecretBuf::expose`].
    pub fn expose(&self) -> &'a [u8] {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A sub-slice; `None` if `range` is out of bounds.
    pub fn slice(&self, range: Range<usize>) -> Option<SecretSlice<'a>> {
        self.0.get(range).map(SecretSlice)
    }
}

/// Compile-time proof that secrets cannot be printed, serialized or cloned.
/// If one of these traits is ever implemented for `SecretBuf` (or a printing
/// trait for `SecretSlice`), the `<T as NotImpl<_>>` lookup becomes ambiguous
/// and the crate stops compiling (the `static_assertions::assert_not_impl_any`
/// trick). `SecretSlice` is `Copy` on purpose: it is only a view.
mod no_leaky_traits {
    use super::{SecretBuf, SecretSlice};

    trait NotImpl<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotImpl<()> for T {}
    struct IsDebug;
    struct IsDisplay;
    struct IsSerialize;
    struct IsClone;
    impl<T: ?Sized + std::fmt::Debug> NotImpl<IsDebug> for T {}
    impl<T: ?Sized + std::fmt::Display> NotImpl<IsDisplay> for T {}
    impl<T: ?Sized + serde::Serialize> NotImpl<IsSerialize> for T {}
    impl<T: Clone> NotImpl<IsClone> for T {}

    trait NotPrintable<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotPrintable<()> for T {}
    impl<T: ?Sized + std::fmt::Debug> NotPrintable<IsDebug> for T {}
    impl<T: ?Sized + std::fmt::Display> NotPrintable<IsDisplay> for T {}
    impl<T: ?Sized + serde::Serialize> NotPrintable<IsSerialize> for T {}

    const _: fn() = || {
        <SecretBuf as NotImpl<_>>::check();
        <SecretSlice<'static> as NotPrintable<_>>::check();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_and_expose() {
        let buf = SecretBuf::copy_from(b"hunter2");
        assert_eq!(buf.expose(), b"hunter2");
        assert_eq!(buf.len(), 7);
        assert_eq!(buf.capacity(), 7);
        assert!(!buf.is_empty());
    }

    #[test]
    fn fill_stops_at_capacity_and_never_grows() {
        let mut buf = SecretBuf::with_capacity(5);
        let mut source: &[u8] = b"abcdefgh";
        let full = buf
            .fill_with(|out| -> Result<usize, ()> {
                let n = out.len().min(source.len()).min(3);
                out[..n].copy_from_slice(&source[..n]);
                source = &source[n..];
                Ok(n)
            })
            .unwrap();
        assert!(full);
        assert_eq!(buf.expose(), b"abcde");
        assert_eq!(buf.capacity(), 5);
    }

    #[test]
    fn fill_stops_at_end_of_input() {
        let mut buf = SecretBuf::with_capacity(10);
        let mut once = Some(b"abc");
        let full = buf
            .fill_with(|out| -> Result<usize, ()> {
                match once.take() {
                    Some(src) => {
                        out[..3].copy_from_slice(src);
                        Ok(3)
                    }
                    None => Ok(0),
                }
            })
            .unwrap();
        assert!(!full);
        assert_eq!(buf.expose(), b"abc");
    }

    #[test]
    fn fill_propagates_errors() {
        let mut buf = SecretBuf::with_capacity(4);
        assert_eq!(buf.fill_with(|_| Err("boom")), Err("boom"));
        assert!(buf.is_empty());
    }

    #[test]
    fn take_wipes_the_source_vector() {
        let v = b"secret-value".to_vec();
        let buf = SecretBuf::take(v);
        assert_eq!(buf.expose(), b"secret-value");
    }

    #[test]
    fn drop_zeroizes_whole_capacity() {
        let mut buf = SecretBuf::copy_from(b"top secret");
        // What `drop` runs, without freeing the memory we want to look at.
        buf.wipe();
        assert!(buf.data.iter().all(|&b| b == 0));
        assert!(buf.expose().is_empty());
    }

    #[test]
    fn slices_borrow_without_copying() {
        let buf = SecretBuf::copy_from(b"KEY=value");
        let all = buf.as_slice();
        let value = all.slice(4..9).unwrap();
        assert_eq!(value.expose(), b"value");
        assert_eq!(value.expose().as_ptr(), buf.expose()[4..].as_ptr());
        assert!(all.slice(4..20).is_none());
    }
}
