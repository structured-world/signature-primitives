//! The public key a certificate carries.
//!
//! The key stays as it was encoded. Interpreting it is the algorithm
//! registry's work, and re-encoding it here would change what a key identifier
//! is computed over.

use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::{BitString, Element, Reader, Tag, universal};

/// A public key and the algorithm it belongs to.
#[derive(Debug, Clone, Copy)]
pub struct PublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    key: BitString<'a>,
    der: &'a [u8],
}

impl<'a> PublicKeyInfo<'a> {
    /// Which algorithm this key belongs to.
    #[must_use]
    pub fn algorithm(self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }

    /// The key itself.
    #[must_use]
    pub fn key(self) -> BitString<'a> {
        self.key
    }

    /// The key bytes, where the key is a whole number of octets, which it is
    /// for every algorithm a certificate carries.
    #[must_use]
    pub fn key_octets(self) -> Option<&'a [u8]> {
        self.key.octets()
    }

    /// The whole structure as it was encoded.
    ///
    /// What a fingerprint over the key information is taken of. The key
    /// identifier the profile describes is a digest of [`Self::key_octets`]
    /// instead, and the two are different values over different bytes.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.der
    }
    /// Reads SPKI from an element in the caller's reader, retaining its budget.
    ///
    /// The structure follows RFC 5280 section 4.1.2.7:
    /// <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7>.
    /// Algorithm-specific restrictions belong to the cryptographic consumer.
    /// No key bytes are copied or re-encoded, and no new parser budget is created.
    ///
    /// # Errors
    ///
    /// Reports malformed structure, trailing fields or an exhausted parent budget.
    pub fn read_element(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<PublicKeyInfo<'a>> {
        let fail = |code| Error::new(code, field, element.span().start);

        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }

        let mut inside = parent.enter(element).field(field)?;
        let algorithm_element = inside
            .next_element()
            .field(field)?
            .ok_or_else(|| fail(ErrorCode::MissingField))?;
        let algorithm = algorithm::read(&inside, &algorithm_element, field)?;
        let key = inside.read_bit_string().field(field)?;

        if !inside.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        Ok(PublicKeyInfo {
            algorithm,
            key,
            der: element.as_bytes(),
        })
    }
}

#[cfg(test)]
mod tests;
