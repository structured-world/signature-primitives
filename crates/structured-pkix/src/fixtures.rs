//! Building DER by hand, so a test says what it is testing.
//!
//! A certificate written as one array of bytes hides which byte a test is
//! about. These build the same bytes from named pieces, and the pieces are the
//! only thing a negative test has to change.

use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn memory() -> structured_asn1::memory::Memory {
    // Trusted fixture setup isolates existing parser-local budget regressions.
    structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(256 * 1024 * 1024, 1_000_000_000),
    ))
}

/// One element: a tag byte, a definite length in the fewest bytes, contents.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = contents.len();
    if let Ok(short) = u8::try_from(length)
        && short < 0x80
    {
        out.push(short);
    } else {
        let bytes = length.to_be_bytes();
        let significant = bytes.iter().position(|byte| *byte != 0).unwrap_or(0);
        let bytes = &bytes[significant..];
        let count = u8::try_from(bytes.len()).expect("a length is at most eight bytes");
        out.push(0x80 | count);
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// The pieces one after another, which is what a constructed element holds.
pub fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

/// SEQUENCE.
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &cat(parts))
}

/// SET.
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &cat(parts))
}

/// A context-specific element holding other elements.
pub fn context(number: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa0 | number, &cat(parts))
}

/// A context-specific element holding a value whose own tag its position
/// replaced.
pub fn implicit(number: u8, contents: &[u8]) -> Vec<u8> {
    tlv(0x80 | number, contents)
}

/// INTEGER, from a small non-negative value.
pub fn int(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let significant = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let mut contents = bytes[significant..].to_vec();
    // A leading zero keeps a value whose top bit is set from reading as
    // negative, which is the sign byte a serial number carries.
    if contents.first().is_some_and(|first| first & 0x80 != 0) {
        contents.insert(0, 0x00);
    }
    tlv(0x02, &contents)
}

/// OBJECT IDENTIFIER, from the encoded arcs one of the constants holds.
pub fn oid(identifier: structured_asn1::Oid<'_>) -> Vec<u8> {
    tlv(0x06, identifier.as_bytes())
}

/// BIT STRING with no padding.
pub fn bits(contents: &[u8]) -> Vec<u8> {
    tlv(0x03, &cat(&[vec![0x00], contents.to_vec()]))
}

/// OCTET STRING.
pub fn octets(contents: &[u8]) -> Vec<u8> {
    tlv(0x04, contents)
}

/// BOOLEAN, in the one spelling DER has.
pub fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

/// NULL.
pub fn null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// `UTF8String`.
pub fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

/// `PrintableString`.
pub fn printable(text: &str) -> Vec<u8> {
    tlv(0x13, text.as_bytes())
}

/// `IA5String`.
pub fn ia5(text: &str) -> Vec<u8> {
    tlv(0x16, text.as_bytes())
}

/// `UTCTime`.
pub fn utc_time(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

/// `GeneralizedTime`.
pub fn generalized_time(text: &str) -> Vec<u8> {
    tlv(0x18, text.as_bytes())
}

/// One extension, with the flag left out when it is false, which is how a
/// certificate writes it.
pub fn extension(kind: structured_asn1::Oid<'_>, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(kind)];
    if critical {
        parts.push(boolean(true));
    }
    parts.push(octets(value));
    seq(&parts)
}

/// An algorithm identifier with a null where the algorithm takes no
/// parameters, which is how the RSA identifiers are written.
pub fn algorithm(kind: structured_asn1::Oid<'_>) -> Vec<u8> {
    seq(&[oid(kind), null()])
}

/// The pieces of a certificate, each replaceable on its own so a test that is
/// about one of them changes only that one.
pub struct CertificateParts {
    /// The version, as the number the field carries, or `None` to leave the
    /// field out the way a first-version certificate does.
    pub version: Option<u32>,
    /// The serial number.
    pub serial: Vec<u8>,
    /// The algorithm identifier inside the signed bytes.
    pub inner_algorithm: Vec<u8>,
    /// The issuer's name.
    pub issuer: Vec<u8>,
    /// The interval.
    pub validity: Vec<u8>,
    /// The subject's name.
    pub subject: Vec<u8>,
    /// The public key information.
    pub key: Vec<u8>,
    /// The issuer's unique identifier, which the later versions dropped.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// The subject's unique identifier.
    pub subject_unique_id: Option<Vec<u8>>,
    /// The extensions, as the sequence that holds them.
    pub extensions: Option<Vec<u8>>,
    /// The algorithm identifier outside the signed bytes.
    pub outer_algorithm: Vec<u8>,
    /// The signature value.
    pub signature: Vec<u8>,
}

impl Default for CertificateParts {
    fn default() -> Self {
        let name =
            |common: &str| seq(&[set(&[seq(&[oid(crate::oid::COMMON_NAME), utf8(common)])])]);
        Self {
            version: Some(2),
            serial: int(0x0102_0304),
            inner_algorithm: algorithm(crate::oid::RSA_ENCRYPTION),
            issuer: name("Test Issuer"),
            validity: seq(&[utc_time("240101000000Z"), utc_time("260101000000Z")]),
            subject: name("Test Subject"),
            key: seq(&[
                algorithm(crate::oid::RSA_ENCRYPTION),
                bits(&[0xde, 0xad, 0xbe, 0xef]),
            ]),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(seq(&[extension(
                crate::oid::BASIC_CONSTRAINTS,
                true,
                &seq(&[boolean(true)]),
            )])),
            outer_algorithm: algorithm(crate::oid::RSA_ENCRYPTION),
            signature: bits(&[0x5f, 0x1c]),
        }
    }
}

impl CertificateParts {
    /// The signed part.
    pub fn tbs(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        if let Some(version) = self.version {
            parts.push(context(0, &[int(version)]));
        }
        parts.push(self.serial.clone());
        parts.push(self.inner_algorithm.clone());
        parts.push(self.issuer.clone());
        parts.push(self.validity.clone());
        parts.push(self.subject.clone());
        parts.push(self.key.clone());
        if let Some(identifier) = &self.issuer_unique_id {
            parts.push(implicit(1, identifier));
        }
        if let Some(identifier) = &self.subject_unique_id {
            parts.push(implicit(2, identifier));
        }
        if let Some(extensions) = &self.extensions {
            parts.push(context(3, core::slice::from_ref(extensions)));
        }
        seq(&parts)
    }

    /// The whole certificate.
    pub fn build(&self) -> Vec<u8> {
        seq(&[
            self.tbs(),
            self.outer_algorithm.clone(),
            self.signature.clone(),
        ])
    }
}

/// Reads a certificate carrying the one extension `value` and hands its
/// extension list to the test body. The certificate borrows the encoded
/// bytes, which live here, so the body asserts on borrowed structures in
/// place and hands out only what it owns.
pub fn with_extension<R>(value: Vec<u8>, read: impl FnOnce(&crate::Extensions<'_>) -> R) -> R {
    let der = CertificateParts {
        extensions: Some(seq(&[value])),
        ..CertificateParts::default()
    }
    .build();
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    let certificate = crate::Certificate::read(&parser, &der, 0).unwrap();
    read(certificate.tbs().extensions())
}

/// The shape of a negative extension test: the certificate carries the one
/// extension, and the named accessor refuses its value. Takes the accessor
/// as a name, which a function cannot, so the unwrap chain lives here once.
macro_rules! extension_error {
    ($value:expr, $accessor:ident) => {
        crate::fixtures::with_extension($value, |list| list.$accessor(list.memory()).unwrap_err())
    };
}
pub(crate) use extension_error;
