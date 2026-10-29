//! The public key a certificate carries.
//!
//! The key stays as it was encoded: re-encoding it here would change what a
//! key identifier is computed over. [`rsa`], [`ec`], [`dsa`] and [`rfc8410`]
//! read its structure in place; whether a key is usable remains the algorithm
//! registry's decision.

use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::memory::Work;
use structured_asn1::{BitString, Element, Oid, ScopedReader, Tag, universal};

pub mod dsa;
pub mod dstu4145;
pub mod ec;
pub mod effective;
pub mod ml_dsa;
pub mod rfc8410;
pub mod rsa;

/// A public key and the algorithm it belongs to.
#[derive(Debug, Clone, Copy)]
pub struct PublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    key: BitString<'a>,
    der: &'a [u8],
    // Document offset of the first key octet, after the unused-bits octet.
    key_offset: u64,
}

impl<'a> PublicKeyInfo<'a> {
    /// Fund deferred key operations from this original source and current Work.
    /// No source bytes are scanned and no reader, account or allocation is created.
    pub fn execution_in<'operation, W: structured_asn1::memory::Work>(
        &self,
        work: &'operation W,
    ) -> structured_asn1::memory::Execution<'operation>
    where
        'a: 'operation,
    {
        self.algorithm.query_in(work)
    }

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

    /// Where the first key octet sits in the whole document.
    #[must_use]
    pub fn key_offset(self) -> u64 {
        self.key_offset
    }

    /// Whole key octets, or a located refusal of a padded bit string.
    pub(crate) fn whole_octets(self, field: &'static str) -> Result<&'a [u8]> {
        self.key_octets()
            .ok_or_else(|| Error::new(ErrorCode::MalformedValue, field, self.key_offset))
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
        parent: &ScopedReader<'a, '_>,
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
        let key_element = inside
            .expect(Tag::primitive(universal::BIT_STRING))
            .field(field)?;
        let key = inside.bit_string(&key_element).field(field)?;

        if !inside.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        Ok(PublicKeyInfo {
            algorithm,
            key,
            der: element.as_bytes(),
            // A primitive BIT STRING: one unused-bits octet, then the bits.
            key_offset: key_element.contents_span().start + 1,
        })
    }
}

/// Paid identity of two OIDs: the length check, then the octets compared.
pub(crate) fn same_oid<W: Work>(
    left: Oid<'_>,
    right: Oid<'_>,
    execution: &W,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    let charge = |amount| {
        execution
            .charge_work(amount)
            .map_err(|reason| Error::resource(reason, field, at))
    };
    charge(1)?;
    if left.as_bytes().len() != right.as_bytes().len() {
        return Ok(false);
    }
    charge(left.as_bytes().len() as u64)?;
    Ok(left == right)
}

#[cfg(test)]
mod tests;
