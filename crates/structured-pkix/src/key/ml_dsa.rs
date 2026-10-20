//! Original raw ML-DSA public keys, without decoding lattice coefficients.
//!
//! RFC 9881 §4 carries raw bytes directly in SPKI's BIT STRING. Neither an
//! OCTET STRING wrapper nor ASN.1 decoding of the raw key is appropriate.
//! <https://www.rfc-editor.org/rfc/rfc9881#section-4>

use super::PublicKeyInfo;
use crate::algorithm::ml_dsa::{self, ParameterSet};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;

/// Original key octets and exact parameter-set identity.
///
/// A structurally readable key is not a mathematical, usage or trust verdict.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    parameter_set: ParameterSet,
    bytes: &'a [u8],
    offset: u64,
}

impl<'a> PublicKey<'a> {
    /// The distinct parameter set named by the original SPKI.
    #[must_use]
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Exact raw key octets, borrowed without a copy or ASN.1 wrapper.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// First raw key octet in the original source's coordinate system.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Reads pure ML-DSA SPKI identity, absent parameters and exact raw framing.
///
/// Original and current work limits apply before metadata decisions; no cursor,
/// allocation, refcount increment or payload scan is needed. The borrowed key
/// can outlive the short current operation. Parameters are never inherited.
///
/// # Errors
/// `UnexpectedField` for another identity, `MalformedValue` for parameters,
/// padded bits or wrong width, or the original located resource refusal.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{PublicKeyInfo, key::ml_dsa};
/// let work = Memory::new(Arc::new(MemoryAccount::new(4096, 10000)));
/// let parser = Parser::der(work.clone());
/// let mut bytes = vec![0x30,0x82,5,0x32,0x30,11,6,9,96,134,72,1,101,3,4,3,17,
///                      3,0x82,5,0x21,0];
/// bytes.extend([0; 1312]); // framing only, not a usable or trusted key
/// let mut reader = parser.read(&bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let spki = PublicKeyInfo::read_element(&reader, &element, "key")?;
/// let key = ml_dsa::read(spki, &work)?;
/// assert_eq!(key.as_bytes().len(), 1312);
/// assert_eq!(key.offset(), 422);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(key: PublicKeyInfo<'a>, execution: &W) -> Result<PublicKey<'a>> {
    let identifier = key.algorithm();
    let parameter_set = ml_dsa::resolve(identifier, execution)?.ok_or_else(|| {
        Error::new(
            ErrorCode::UnexpectedField,
            "subjectPublicKey.mlDsa",
            identifier.offset(),
        )
    })?;
    let bytes = key.whole_octets("subjectPublicKey.mlDsa")?;
    let offset = key.key_offset();
    if bytes.len() != parameter_set.public_key_len() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            "subjectPublicKey.mlDsa",
            offset,
        ));
    }
    Ok(PublicKey {
        parameter_set,
        bytes,
        offset,
    })
}
