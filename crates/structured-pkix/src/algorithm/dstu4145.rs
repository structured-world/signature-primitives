//! DSTU 4145 wire profiles, without field arithmetic or a hash engine.
//!
//! The pinned Ukrainian OID table distinguishes basis, byte order and digest.
//! Its historical encoding profile remains useful for reading signed objects;
//! the 2012 regulatory act was repealed in 2020, so recognition is not a claim
//! of current legal compliance. SPKI's identifier does not restrict the digest
//! of a signature made with that key (§3.11.1.2.2).
//! <https://zakon.rada.gov.ua/laws/show/z1399-12>
//! <https://zakon.rada.gov.ua/laws/show/z1398-12>

use super::{AlgorithmIdentifier, digest};
use crate::{Error, Result};
use structured_asn1::memory::Work;

pub mod parameters;
pub use parameters::{Curve, ExplicitCurve, NamedCurve, Parameters, Reduction, read_parameters};

/// Representation of a binary field, not proof that a backend implements it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Polynomial basis.
    Polynomial,
    /// Optimal normal basis; this module performs no basis conversion.
    OptimalNormal,
}

/// Byte order of field elements and the complete signature bit string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least significant octet first.
    LittleEndian,
    /// Most significant octet first.
    BigEndian,
}

/// Exactly recognized identifier facts, independent of key and math validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    digest: digest::Algorithm,
    basis: Basis,
    byte_order: ByteOrder,
}

impl Profile {
    /// The signature OID's digest. A key OID imposes no signature digest.
    #[must_use]
    pub const fn digest(self) -> digest::Algorithm {
        self.digest
    }

    /// Field representation selected by this identifier.
    #[must_use]
    pub const fn basis(self) -> Basis {
        self.basis
    }

    /// Octet representation selected by this identifier.
    #[must_use]
    pub const fn byte_order(self) -> ByteOrder {
        self.byte_order
    }
}

/// Identifies the exact OID under its original and current execution ceilings.
///
/// Parameters remain role-specific: signatures require absence through
/// [`super::signature::with_algorithm`]; SPKI uses [`read_parameters`]. Unknown
/// OIDs, including a recognized prefix with extra arcs, return `None`.
///
/// # Errors
/// Located terminal resource refusal before classification, never `None`.
pub fn identify<W: Work>(
    identifier: AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Option<Profile>> {
    let bytes = identifier.algorithm().as_bytes();
    identifier
        .query_in(execution)
        .charge_work(bytes.len() as u64 + 1)
        .map_err(|reason| Error::resource(reason, identifier.field, identifier.offset()))?;
    Ok(from_octets(bytes))
}

/// The original OID traversal was already admitted by the caller.
pub(super) fn from_octets(bytes: &[u8]) -> Option<Profile> {
    use digest::Algorithm::{Gost34311, Kupyna256, Kupyna384, Kupyna512};
    let (digest, basis, tail) = match bytes {
        [0x2a, 0x86, 0x24, 2, 1, 1, 1, 1, 3, 1, basis, tail @ ..] => (Gost34311, basis, tail),
        [
            0x2a,
            0x86,
            0x24,
            2,
            1,
            1,
            1,
            1,
            3,
            6,
            hash,
            basis,
            tail @ ..,
        ] => {
            let digest = match hash {
                1 => Kupyna256,
                2 => Kupyna384,
                3 => Kupyna512,
                _ => return None,
            };
            (digest, basis, tail)
        }
        _ => return None,
    };
    let basis = match basis {
        1 => Basis::Polynomial,
        2 => Basis::OptimalNormal,
        _ => return None,
    };
    let byte_order = match tail {
        [] => ByteOrder::LittleEndian,
        [1, 1] => ByteOrder::BigEndian,
        _ => return None,
    };
    Some(Profile {
        digest,
        basis,
        byte_order,
    })
}

/// Original fixed-width unsigned octets, without copying or normalization.
///
/// Padding and zero remain visible. This is not a validated group element or
/// a scalar range check. As with ASN.1 raw views, callers fund their own byte
/// iteration; constructing an iterator performs no scan or allocation.
#[derive(Debug, Clone, Copy)]
pub struct Octets<'a> {
    bytes: &'a [u8],
    byte_order: ByteOrder,
    offset: u64,
}

impl<'a> Octets<'a> {
    pub(crate) const fn new(bytes: &'a [u8], byte_order: ByteOrder, offset: u64) -> Self {
        Self {
            bytes,
            byte_order,
            offset,
        }
    }

    /// Exact original octets, including all width padding.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// The original byte order, not a host-endian interpretation.
    #[must_use]
    pub const fn byte_order(self) -> ByteOrder {
        self.byte_order
    }

    /// First original payload octet in the producing source coordinates.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Unsigned magnitude, most significant octet first, retaining width.
    pub fn big_endian(self) -> impl ExactSizeIterator<Item = u8> + DoubleEndedIterator + 'a {
        let bytes = self.bytes;
        (0..bytes.len()).map(move |index| match self.byte_order {
            ByteOrder::BigEndian => bytes[index],
            ByteOrder::LittleEndian => bytes[bytes.len() - 1 - index],
        })
    }
}
