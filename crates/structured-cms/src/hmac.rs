//! Incremental [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) HMAC.
//!
//! Callers select the algorithm, enforce key and tag length policy, and admit
//! work proportional to the key length and the input fed to each update.
//! State and tags use fixed storage.
//!
//! ```
//! use structured_cms::hmac::{Algorithm, Mac};
//!
//! let mut mac = Mac::begin(Algorithm::Sha256, b"example key")?;
//! mac.update(b"message ");
//! mac.update(b"chunks");
//! let tag = mac.finalize();
//! assert_eq!(tag.as_bytes().len(), 32);
//! # Ok::<(), structured_cms::hmac::Error>(())
//! ```

use ::hmac::{KeyInit, Mac as _};
use ctutils::CtEq;

/// A digest used by HMAC, independent of wire identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC with SHA-1.
    Sha1,
    /// HMAC with SHA-224.
    Sha224,
    /// HMAC with SHA-256.
    Sha256,
    /// HMAC with SHA-384.
    Sha384,
    /// HMAC with SHA-512.
    Sha512,
    /// HMAC with MD5, enabled by `legacy-hmac`.
    #[cfg(feature = "legacy-hmac")]
    Md5,
    /// HMAC with RIPEMD-160, enabled by `legacy-hmac`.
    #[cfg(feature = "legacy-hmac")]
    Ripemd160,
}

impl Algorithm {
    /// Full tag size in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            #[cfg(feature = "legacy-hmac")]
            Self::Md5 => 16,
            #[cfg(feature = "legacy-hmac")]
            Self::Ripemd160 => 20,
        }
    }
}

/// HMAC initialization or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The HMAC implementation rejected the key.
    #[error("HMAC key rejected")]
    InvalidKey,
    /// The bit count is out of range or disagrees with the provided tag length.
    #[error("invalid HMAC tag length")]
    InvalidTagLength,
    /// The tag does not authenticate the input.
    #[error("HMAC tag mismatch")]
    Mismatch,
}

/// A full-width HMAC tag stored without heap allocation.
pub struct Tag {
    bytes: [u8; 64],
    len: usize,
}

impl Tag {
    /// The full tag bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Verify a bit prefix in constant time with respect to tag contents.
    ///
    /// The bit count must be nonzero and at most the full width. Supply
    /// exactly enough octets to hold those bits. Unused low bits in the
    /// last octet are ignored.
    pub fn verify_truncated(&self, expected: &[u8], bits: usize) -> Result<(), Error> {
        verify_prefix(self.as_bytes(), expected, bits)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut tag = Self {
            bytes: [0; 64],
            len: bytes.len(),
        };
        tag.bytes[..tag.len].copy_from_slice(bytes);
        tag
    }
}

fn verify_prefix(full: &[u8], expected: &[u8], bits: usize) -> Result<(), Error> {
    if bits == 0 || expected.len() != bits.div_ceil(8) || expected.len() > full.len() {
        return Err(Error::InvalidTagLength);
    }
    let last = expected.len() - 1;
    // RFC 2104 section 5 selects the leftmost bits, including a partial octet.
    let mask = u8::MAX << ((8 - bits % 8) % 8);
    let body = full[..last].ct_eq(&expected[..last]);
    let tail = (full[last] & mask).ct_eq(&(expected[last] & mask));
    if (body & tail).into() {
        Ok(())
    } else {
        Err(Error::Mismatch)
    }
}

/// Running HMAC for one key and algorithm.
pub struct Mac {
    state: State,
}

macro_rules! states {
    ($($(#[$attr:meta])* $variant:ident => $digest:ty),+ $(,)?) => {
        enum State {
            $($(#[$attr])* $variant(::hmac::Hmac<$digest>),)+
        }

        impl Mac {
            /// Start an HMAC. RFC 2104 permits keys of any length.
            pub fn begin(algorithm: Algorithm, key: &[u8]) -> Result<Self, Error> {
                let state = match algorithm {
                    $($(#[$attr])* Algorithm::$variant => State::$variant(
                        ::hmac::Hmac::<$digest>::new_from_slice(key)
                            .map_err(|_| Error::InvalidKey)?,
                    ),)+
                };
                Ok(Self { state })
            }

            /// Absorb the next chunk.
            pub fn update(&mut self, data: &[u8]) {
                match &mut self.state {
                    $($(#[$attr])* State::$variant(mac) => mac.update(data),)+
                }
            }

            /// Return the full-width tag.
            #[must_use]
            pub fn finalize(self) -> Tag {
                match self.state {
                    $($(#[$attr])* State::$variant(mac) =>
                        Tag::from_bytes(&mac.finalize().into_bytes()),)+
                }
            }

            /// Verify exactly the leftmost `bits` of the tag.
            ///
            /// See [`Tag::verify_truncated`] for the length and timing contract.
            pub fn verify_truncated(self, expected: &[u8], bits: usize) -> Result<(), Error> {
                if bits == 0 || bits.div_ceil(8) != expected.len() {
                    return Err(Error::InvalidTagLength);
                }
                match self.state {
                    $($(#[$attr])* State::$variant(mac) => {
                        if expected.len() > Algorithm::$variant.output_len() {
                            return Err(Error::InvalidTagLength);
                        }
                        verify_prefix(&mac.finalize().into_bytes(), expected, bits)
                    },)+
                }
            }
        }
    };
}

states! {
    Sha1 => sha1::Sha1,
    Sha224 => sha2::Sha224,
    Sha256 => sha2::Sha256,
    Sha384 => sha2::Sha384,
    Sha512 => sha2::Sha512,
    #[cfg(feature = "legacy-hmac")]
    Md5 => md5::Md5,
    #[cfg(feature = "legacy-hmac")]
    Ripemd160 => ripemd::Ripemd160,
}

/// Compute a full-width HMAC in one call.
pub fn authenticate(algorithm: Algorithm, key: &[u8], data: &[u8]) -> Result<Tag, Error> {
    let mut mac = Mac::begin(algorithm, key)?;
    mac.update(data);
    Ok(mac.finalize())
}
