//! Optional `RustCrypto` prehash verification over the raw, validated public key.
//!
//! This interface does not select a hash, rehash, allocate or admit resources.
//! Fund the bounded kernel operation before calling it. Applications requiring
//! typed processing/resource outcomes use the existing `accounted` interface;
//! `RustCrypto` deliberately exposes an opaque signature-verification error.
//!
//! Use a generic `PrehashVerifier` bound or UFCS: the inherent low-level method
//! additionally accepts byte order as a separate argument.
//!
//! ```
//! use structured_dstu4145::{domain::PublicKey, rustcrypto::{Signature, signature}};
//! use signature::hazmat::PrehashVerifier;
//!
//! fn check<'a, V: PrehashVerifier<Signature<'a>>>(
//!     key: &V, digest: &[u8], signature: &Signature<'a>,
//! ) -> Result<(), signature::Error> {
//!     key.verify_prehash(digest, signature)
//! }
//!
//! fn with_prepared_key(key: &PublicKey, digest: &[u8], signature: &Signature<'_>)
//!     -> Result<(), signature::Error>
//! {
//!     check(key, digest, signature)
//! }
//! ```

use crate::{ByteOrder, Error, domain::PublicKey};

pub use signature;

/// Borrowed raw signature payload with its explicitly selected representation.
/// This is the OCTET payload, without ASN.1 framing or an inferred key encoding.
#[derive(Debug, Clone, Copy)]
pub struct Signature<'a> {
    bytes: &'a [u8],
    byte_order: ByteOrder,
}

impl<'a> Signature<'a> {
    /// Checks bounded component framing without copying or interpreting scalars.
    /// Key-dependent minimum width is checked during verification.
    pub fn new(bytes: &'a [u8], byte_order: ByteOrder) -> Result<Self, Error> {
        if bytes.len() < 2 || bytes.len() > 128 || !bytes.len().is_multiple_of(2) {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self { bytes, byte_order })
    }

    /// Original byte order of the complete raw signature, independent of hash.
    #[must_use]
    pub fn byte_order(self) -> ByteOrder {
        self.byte_order
    }
}

impl AsRef<[u8]> for Signature<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl signature::hazmat::PrehashVerifier<Signature<'_>> for PublicKey {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &Signature<'_>,
    ) -> Result<(), signature::Error> {
        match Self::verify_prehash(self, prehash, signature.bytes, signature.byte_order) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(signature::Error::new()),
        }
    }
}
