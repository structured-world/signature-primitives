//! Which digest an ASN.1 `AlgorithmIdentifier` names, resolved once for OCSP,
//! CMS and every other ASN.1 consumer.
//!
//! The identifier is matched exactly. Parameters are read under the encoding
//! of the document they came from: absent and NULL both mean none, NULL is
//! recognised under BER, and any other value of a known identifier is
//! malformed. An identifier this table does not know is unsupported. Execution
//! then goes through the provider's [`Digest`] implementation.

use super::AlgorithmIdentifier;
use crate::error::{Error, Result};
use crate::oid;
use structured_asn1::Oid;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::Work;

/// A digest algorithm named by a standard ASN.1 identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// SHA-1, FIPS 180-4.
    Sha1,
    /// SHA-224, FIPS 180-4.
    Sha224,
    /// SHA-256, FIPS 180-4.
    Sha256,
    /// SHA-384, FIPS 180-4.
    Sha384,
    /// SHA-512, FIPS 180-4.
    Sha512,
    /// SHA-512/224, FIPS 180-4.
    Sha512_224,
    /// SHA-512/256, FIPS 180-4.
    Sha512_256,
}

impl Algorithm {
    /// Output width in octets.
    #[must_use]
    pub const fn width(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha512_224 => 28,
            Self::Sha256 | Self::Sha512_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The identifier this algorithm is written under.
    #[must_use]
    pub const fn identifier(self) -> Oid<'static> {
        match self {
            Self::Sha1 => oid::SHA1,
            Self::Sha224 => oid::SHA224,
            Self::Sha256 => oid::SHA256,
            Self::Sha384 => oid::SHA384,
            Self::Sha512 => oid::SHA512,
            Self::Sha512_224 => oid::SHA512_224,
            Self::Sha512_256 => oid::SHA512_256,
        }
    }
}

/// A [`Digest`] provider's identities for standard ASN.1 digest algorithms.
pub trait AsnDigest<'a>: Digest<'a> {
    /// This provider's identity for `algorithm`, or `None` when it does not
    /// implement it or its policy refuses it. O(1); no work is spent.
    fn identity(&self, algorithm: Algorithm) -> Option<Self::Identity>;
}

/// Reads which standard digest `identifier` names.
///
/// Every algorithm here takes no parameters: the field "should generally be
/// omitted, but if present, it shall have a value of type NULL"
/// (RFC 8017 Appendix B.1; RFC 5754 §2 and RFC 3370 §2.1 require receivers to
/// accept both). NULL is the primitive NULL the producing reader validated
/// under the document's own encoding, so a BER long-form length is NULL too
/// (RFC 5652 §1: a signed message is BER).
///
/// # Errors
///
/// A located resource refusal when `execution` cannot pay for the comparison;
/// never `Malformed` or `Unsupported`.
///
/// # Examples
///
/// ```
/// # extern crate alloc;
/// # use alloc::sync::Arc;
/// # use structured_asn1::{Parser, Tag, universal, digest::Resolution};
/// # use structured_asn1::memory::{Memory, MemoryAccount};
/// use structured_pkix::algorithm::{self, digest};
/// # let execution = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
/// # let parser = Parser::der(execution.clone());
/// // SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
/// let der = [0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00];
/// # let mut reader = parser.read(&der, 0).unwrap();
/// # let element = reader.expect(Tag::constructed(universal::SEQUENCE)).unwrap();
/// let identifier = algorithm::read(&reader, &element, "digestAlgorithm")?;
/// assert_eq!(
///     digest::algorithm(&identifier, &execution)?,
///     Resolution::Supported(digest::Algorithm::Sha256),
/// );
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn algorithm<W: Work>(
    identifier: &AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Resolution<Algorithm>> {
    let written = identifier.algorithm().as_bytes();
    // One length dispatch and at most one look at each written byte, which is
    // exactly what this charge pays for; the OID is a slice of the parsed
    // input, so its length plus one fits. The patterns are the bytes of the
    // `oid` constants that `Algorithm::identifier` names.
    execution
        .charge_work(written.len() as u64 + 1)
        .map_err(|reason| Error::resource(reason, identifier.field, identifier.offset))?;
    let algorithm = match written {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Algorithm::Sha1,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last] => match last {
            0x01 => Algorithm::Sha256,
            0x02 => Algorithm::Sha384,
            0x03 => Algorithm::Sha512,
            0x04 => Algorithm::Sha224,
            0x05 => Algorithm::Sha512_224,
            0x06 => Algorithm::Sha512_256,
            _ => return Ok(Resolution::Unsupported),
        },
        _ => return Ok(Resolution::Unsupported),
    };
    if identifier.parameters().is_some() && !identifier.has_null_parameter() {
        return Ok(Resolution::Malformed);
    }
    Ok(Resolution::Supported(algorithm))
}

/// Resolves `identifier` to `digest`'s own identity: [`algorithm`], then the
/// provider's [`AsnDigest::identity`].
///
/// # Errors
///
/// As [`algorithm`].
pub fn resolve<'a, D: AsnDigest<'a> + ?Sized, W: Work>(
    digest: &D,
    identifier: &AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Resolution<D::Identity>> {
    Ok(match algorithm(identifier, execution)? {
        Resolution::Supported(algorithm) => supported(digest, algorithm),
        Resolution::Unsupported => Resolution::Unsupported,
        Resolution::Malformed => Resolution::Malformed,
    })
}

/// The provider's identity for an algorithm a schema imposes without writing
/// an identifier, such as SHA-1 for an OCSP `ResponderID` byKey.
pub fn supported<'a, D: AsnDigest<'a> + ?Sized>(
    digest: &D,
    algorithm: Algorithm,
) -> Resolution<D::Identity> {
    digest
        .identity(algorithm)
        .map_or(Resolution::Unsupported, Resolution::Supported)
}
