//! Original password-protection parameters; no KDF, password or cipher engine.
//!
//! Wide iteration/key-length values stay borrowed INTEGERs. A selected backend
//! must admit its complete KDF/cipher cost before work, including dependencies.
//! Recognized parameter syntax is checked even for an unsupported backend.

use super::{algorithm, encoding, end, equal_oid, invalid, number, positive, sequence};
use crate::{Error, ErrorCode, Octets, Result, signer::required};
use structured_asn1::{Integer, Oid, Reader, Tag, universal};
use structured_pkix::AlgorithmIdentifier;

const FIELD: &str = "personal.protection";
/// PBES2, RFC8018 Appendix A.4.
pub const PBES2: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 5, 13]);
/// PBMAC1, RFC8018 Appendix A.5 / RFC9879.
pub const PBMAC1: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 5, 14]);
/// PBKDF2, RFC8018 Appendix A.2.
pub const PBKDF2: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 5, 12]);
const SHA1: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 7]);

/// PBKDF2 salt CHOICE; unknown source remains a real original identifier.
pub enum Salt<'a> {
    /// Explicit logical salt octets, possibly BER segmented.
    Specified(Octets<'a>),
    /// Explicit source algorithm, never replaced by an empty/default salt.
    Source(AlgorithmIdentifier<'a>),
}
/// PBKDF2 PRF with honest DEFAULT provenance.
#[derive(Debug, Clone, Copy)]
pub enum Prf<'a> {
    /// The ASN.1 default HMAC-SHA1 with NULL parameters, not fabricated DER.
    DefaultSha1,
    /// Original written PRF and parameters.
    Written(AlgorithmIdentifier<'a>),
}
/// RFC8018 PBKDF2-params, independent of a backend's numeric limits.
pub struct Pbkdf2<'a> {
    /// The original specified salt or salt-source choice.
    pub salt: Salt<'a>,
    /// Strictly positive, arbitrary-width iterationCount.
    pub iterations: Integer<'a>,
    /// Optional strictly positive output length in octets.
    pub key_length: Option<Integer<'a>>,
    /// Default or original written PRF identity.
    pub prf: Prf<'a>,
}
impl<'a> Pbkdf2<'a> {
    /// Reads parameters through their original `AlgorithmIdentifier` provenance.
    /// A different Parser is a terminal processing error before parameter work.
    pub fn read(identifier: AlgorithmIdentifier<'a>, parent: &Reader<'a>) -> Result<Self> {
        session(identifier, parent)?;
        if !equal_oid(parent, identifier.algorithm(), PBKDF2)? {
            return Err(Error::schema(
                ErrorCode::AlgorithmSyntax,
                FIELD,
                identifier.offset(),
            ));
        }
        let mut reader = parameters(identifier, parent)?;
        let value = required(&mut reader, FIELD)?;
        let mut inside = sequence(&reader, &value)?;
        end(&reader)?;
        let salt_element = required(&mut inside, FIELD)?;
        let salt = if salt_element.tag() == Tag::constructed(universal::SEQUENCE) {
            Salt::Source(
                structured_pkix::algorithm::read(&inside, &salt_element, FIELD)
                    .map_err(Error::pkix)?,
            )
        } else {
            Salt::Specified(Octets::read(&inside, &salt_element, FIELD)?)
        };
        let iterations = number(&mut inside)?;
        positive(iterations, &value)?;
        let mut next = inside.next_element().map_err(encoding)?;
        let key_length =
            if let Some(element) = next.filter(|v| v.tag() == Tag::primitive(universal::INTEGER)) {
                let length = inside.integer(&element).map_err(encoding)?;
                positive(length, &element)?;
                next = inside.next_element().map_err(encoding)?;
                Some(length)
            } else {
                None
            };
        let prf = if let Some(element) = next {
            let written =
                structured_pkix::algorithm::read(&inside, &element, FIELD).map_err(Error::pkix)?;
            hmac_width(written, &inside)?;
            if equal_oid(&inside, written.algorithm(), SHA1)? && written.has_null_parameter() {
                // RFC8018 A.2's DEFAULT contains a present NULL. Appendix C
                // makes parameters OPTIONAL: a written absent parameter is
                // a distinct ASN.1 value, not an invented NULL/default.
                if inside.encoding().is_der() {
                    return Err(invalid(ErrorCode::DefaultWritten, &element));
                }
            }
            Prf::Written(written)
        } else {
            Prf::DefaultSha1
        };
        end(&inside)?;
        Ok(Self {
            salt,
            iterations,
            key_length,
            prf,
        })
    }
}

/// PBES2 / PBMAC1's common two-algorithm parameter grammar.
pub struct Pair<'a> {
    /// Original keyDerivationFunc; an unknown mechanism stays explicit.
    pub derivation: AlgorithmIdentifier<'a>,
    /// Original encryptionScheme or messageAuthScheme.
    pub scheme: AlgorithmIdentifier<'a>,
    /// Parsed PBKDF2 parameters when that KDF is actually written.
    pub pbkdf2: Option<Pbkdf2<'a>>,
}
impl<'a> Pair<'a> {
    /// Reads the pair belonging to this original PBES2/PBMAC1 identifier.
    pub fn read(identifier: AlgorithmIdentifier<'a>, parent: &Reader<'a>) -> Result<Self> {
        session(identifier, parent)?;
        if !equal_oid(parent, identifier.algorithm(), PBES2)?
            && !equal_oid(parent, identifier.algorithm(), PBMAC1)?
        {
            return Err(Error::schema(
                ErrorCode::AlgorithmSyntax,
                FIELD,
                identifier.offset(),
            ));
        }
        let mut reader = parameters(identifier, parent)?;
        let value = required(&mut reader, FIELD)?;
        let mut inside = sequence(&reader, &value)?;
        end(&reader)?;
        let derivation = algorithm(&mut inside)?;
        let scheme = algorithm(&mut inside)?;
        end(&inside)?;
        let pbkdf2 = if equal_oid(&inside, derivation.algorithm(), PBKDF2)? {
            Some(Pbkdf2::read(derivation, &inside)?)
        } else {
            None
        };
        Ok(Self {
            derivation,
            scheme,
            pbkdf2,
        })
    }
}

/// Salt/iteration parameter grammar shared by PBES1 and legacy PKCS#12 PBE.
pub struct Legacy<'a> {
    /// Original salt; PBES1 alone requires exactly eight octets.
    pub salt: Octets<'a>,
    /// Strictly positive original work factor, with no machine-width clamp.
    pub iterations: Integer<'a>,
}
/// Structural protection classification, independent of algorithm permission.
#[expect(
    clippy::large_enum_variant,
    reason = "one protection descriptor is consumed inline; boxing PBES2 would add an allocation for every password operation"
)]
pub enum Protection<'a> {
    /// PBES2 key derivation and encryption scheme.
    Pbes2(Pair<'a>),
    /// PKCS#5 PBES1 (MD2/MD5/SHA1 with DES/RC2).
    Pbes1(Legacy<'a>),
    /// RFC7292 Appendix C legacy algorithms 1 through 6.
    Pkcs12(Legacy<'a>),
    /// Original unknown algorithm; no fallback or implicit PBES2.
    Other(AlgorithmIdentifier<'a>),
}
impl<'a> Protection<'a> {
    /// Reads recognized parameters before any password/provider side effects.
    pub fn read(identifier: AlgorithmIdentifier<'a>, parent: &Reader<'a>) -> Result<Self> {
        session(identifier, parent)?;
        if equal_oid(parent, identifier.algorithm(), PBES2)? {
            return Pair::read(identifier, parent).map(Self::Pbes2);
        }
        let mut pbes1 = false;
        for last in [1, 3, 4, 6, 10, 11] {
            pbes1 |= equal_oid(
                parent,
                identifier.algorithm(),
                Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 5, last]),
            )?;
        }
        let mut pkcs12 = false;
        for last in 1..=6 {
            pkcs12 |= equal_oid(
                parent,
                identifier.algorithm(),
                Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 12, 1, last]),
            )?;
        }
        if !pbes1 && !pkcs12 {
            // Session was checked before dispatch. An unknown mechanism needs
            // no second parameter cursor; its original open value stays intact.
            return Ok(Self::Other(identifier));
        }
        let mut reader = parameters(identifier, parent)?;
        let value = required(&mut reader, FIELD)?;
        let mut inside = sequence(&reader, &value)?;
        end(&reader)?;
        let salt_value = required(&mut inside, FIELD)?;
        let salt = Octets::read(&inside, &salt_value, FIELD)?;
        let iterations = number(&mut inside)?;
        positive(iterations, &value)?;
        end(&inside)?;
        if pbes1 && salt.len() != 8 {
            return Err(invalid(ErrorCode::MalformedValue, &salt_value));
        }
        let result = Legacy { salt, iterations };
        Ok(if pbes1 {
            Self::Pbes1(result)
        } else {
            Self::Pkcs12(result)
        })
    }
}

fn parameters<'a>(identifier: AlgorithmIdentifier<'a>, parent: &Reader<'a>) -> Result<Reader<'a>> {
    identifier
        .parameters_reader_in(parent, FIELD)
        .map_err(Error::pkix)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, FIELD, identifier.offset()))
}

fn session(identifier: AlgorithmIdentifier<'_>, parent: &Reader<'_>) -> Result<()> {
    if !identifier.same_session(parent) {
        return Err(Error::pkix(structured_pkix::Error::new(
            structured_pkix::ErrorCode::ForeignReader,
            FIELD,
            identifier.offset(),
        )));
    }
    Ok(())
}

pub(super) fn hmac_width(
    identifier: AlgorithmIdentifier<'_>,
    parent: &Reader<'_>,
) -> Result<Option<usize>> {
    session(identifier, parent)?;
    let bytes = identifier.algorithm().as_bytes();
    parent.charge(bytes.len() as u64 + 1).map_err(encoding)?;
    let width = match bytes {
        [42, 134, 72, 134, 247, 13, 2, 7] => 20,
        [42, 134, 72, 134, 247, 13, 2, 8 | 12] => 28,
        [42, 134, 72, 134, 247, 13, 2, 9 | 13] => 32,
        [42, 134, 72, 134, 247, 13, 2, 10] => 48,
        [42, 134, 72, 134, 247, 13, 2, 11] => 64,
        _ => return Ok(None),
    };
    // RFC8018 A.2 registers NULL as the parameter type, while Appendix C's
    // AlgorithmIdentifier makes the field OPTIONAL. Validate a present value
    // without fabricating NULL when it is absent.
    // https://www.rfc-editor.org/rfc/rfc8018#appendix-C
    if identifier.parameters().is_some() && !identifier.has_null_parameter() {
        return Err(Error::schema(
            ErrorCode::AlgorithmSyntax,
            FIELD,
            identifier.offset(),
        ));
    }
    Ok(Some(width))
}
