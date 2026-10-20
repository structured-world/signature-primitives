//! The RSA public key a certificate carries, read in place.
//!
//! RFC 8017 A.1.1 defines `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
//! publicExponent INTEGER }`; RFC 4055 §1.2 carries the same structure for
//! `rsaEncryption` and `id-RSASSA-PSS` keys. [`read`] returns the original
//! magnitudes and where they were written. Key size, exponent policy and every
//! arithmetic check belong to the provider that verifies with the key.
//! <https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1>

use super::{PublicKeyInfo, same_oid};
use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::memory::Work;
use structured_asn1::{Element, ScopedReader, Tag, universal};

const FIELD: &str = "subjectPublicKey.rsa";

/// A positive integer as its big-endian magnitude, without the sign octet.
#[derive(Debug, Clone, Copy)]
pub struct Magnitude<'a> {
    bytes: &'a [u8],
    offset: u64,
}

impl<'a> Magnitude<'a> {
    /// Big-endian magnitude; the first octet is never zero.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Where the first magnitude octet sits in the whole document.
    #[must_use]
    pub fn offset(self) -> u64 {
        self.offset
    }

    /// The exact number of significant bits. A 256-octet modulus whose first
    /// octet is `0x01` has 2041 bits, not 2048.
    #[must_use]
    pub fn bits(self) -> u64 {
        // Nonempty with a nonzero first octet by construction.
        (self.bytes.len() as u64 - 1) * 8 + u64::from(8 - self.bytes[0].leading_zeros())
    }
}

/// The two components of an RSA public key, as the certificate wrote them.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    element: Element<'a>,
    modulus: Magnitude<'a>,
    exponent: Magnitude<'a>,
}

impl<'a> PublicKey<'a> {
    /// The whole original `RSAPublicKey` SEQUENCE inside the key bits.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }

    /// The modulus `n`.
    #[must_use]
    pub fn modulus(self) -> Magnitude<'a> {
        self.modulus
    }

    /// The public exponent `e`.
    #[must_use]
    pub fn exponent(self) -> Magnitude<'a> {
        self.exponent
    }
}

/// Reads the RSA key carried by `key` under the current `execution`.
///
/// The key's algorithm must be `rsaEncryption` or `id-RSASSA-PSS`. The key
/// bits are decoded with their original parser session, offsets, encoding and
/// depth; `execution` pays for every step and the source ceilings still apply.
/// Key bytes and components remain borrowed; nested-reader metadata uses
/// the existing accounted scratch path.
///
/// # Errors
///
/// `UnexpectedField` for another algorithm, `MalformedValue` for padded key
/// bits or a non-positive component, `TrailingData` for anything after the
/// structure or its two fields, and the located encoding or resource error
/// otherwise. A resource refusal happens before the work it would fund.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{PublicKeyInfo, key::rsa};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let parser = Parser::der(memory.clone());
/// // rsaEncryption, NULL; RSAPublicKey { 0x00c3 (195), 65537 }
/// let spki = b"\x30\x1d\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\
///              \x03\x0c\x00\x30\x09\x02\x02\x00\xc3\x02\x03\x01\x00\x01";
/// let mut reader = parser.read(spki, 0).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let key = PublicKeyInfo::read_element(&reader, &element, "subjectPublicKeyInfo")?;
/// let rsa = rsa::read(key, &memory)?;
/// assert_eq!(rsa.modulus().as_bytes(), [0xc3]);
/// assert_eq!(rsa.modulus().bits(), 8);
/// assert_eq!(rsa.modulus().offset(), 25);
/// assert_eq!(rsa.exponent().as_bytes(), [1, 0, 1]);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(key: PublicKeyInfo<'a>, execution: &W) -> Result<PublicKey<'a>> {
    let identifier = key.algorithm();
    let at = identifier.offset();
    let algorithm = identifier.algorithm();
    // Deferred OID decisions share the source ceiling with the nested key
    // decoder; a separately funded operation must not reset that ceiling.
    let query = identifier.query_in(execution);
    if !same_oid(algorithm, crate::oid::RSA_ENCRYPTION, &query, FIELD, at)?
        && !same_oid(algorithm, crate::oid::RSASSA_PSS, &query, FIELD, at)?
    {
        return Err(Error::new(ErrorCode::UnexpectedField, FIELD, at));
    }
    let octets = key.whole_octets(FIELD)?;
    let (reader, element) = identifier
        .nested(octets, key.key_offset())
        .open(execution, FIELD)?;
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            FIELD,
            element.span().start,
        ));
    }
    let mut fields = reader.enter(&element).field(FIELD)?;
    let modulus = magnitude(&mut fields)?;
    let exponent = magnitude(&mut fields)?;
    if !fields.is_empty() {
        return Err(Error::new(ErrorCode::TrailingData, FIELD, fields.offset()));
    }
    Ok(PublicKey {
        element,
        modulus,
        exponent,
    })
}

fn magnitude<'a>(fields: &mut ScopedReader<'a, '_>) -> Result<Magnitude<'a>> {
    let element = fields
        .expect(Tag::primitive(universal::INTEGER))
        .field(FIELD)?;
    let integer = fields.integer(&element).field(FIELD)?;
    // X.690 §8.3.2 leaves at most one leading zero octet, the sign of a
    // positive value whose top bit is set. Zero and negative values are not
    // RSA components (RFC 8017 §3.1).
    let start = element.contents_span().start;
    let (bytes, offset) = match integer.as_bytes() {
        [0x00, rest @ ..] => (rest, start + 1),
        all => (all, start),
    };
    if integer.is_negative() || bytes.is_empty() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            element.span().start,
        ));
    }
    Ok(Magnitude { bytes, offset })
}
