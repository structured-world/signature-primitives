//! The identifiers that say which key signed a certificate and which key it
//! carries.
//!
//! These are hints for finding a candidate issuer, not proof of one. A path is
//! built by verifying signatures and matching names; an identifier that
//! matches only says which certificate to try first, and a certificate whose
//! identifier matches nothing may still be the right one.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::general_name::{self, GeneralName};
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{Element, Integer, Tag, universal};

/// An identifier for the key this certificate carries.
#[derive(Debug, Clone, Copy)]
pub struct SubjectKeyIdentifier<'a> {
    bytes: &'a [u8],
}

impl<'a> SubjectKeyIdentifier<'a> {
    /// The identifier, as the issuer computed it. How it was computed is the
    /// issuer's choice and is not stated in the certificate, so it is compared
    /// rather than recomputed.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Reads the value of a subject key identifier extension.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.subjectKeyIdentifier";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut reader = extension.reader(execution).field(FIELD)?;
        let element = reader
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| fail(ErrorCode::MissingField))?;
        if element.tag() != Tag::primitive(universal::OCTET_STRING) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        if !reader.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        Ok(Self {
            bytes: element.contents(),
        })
    }
}

/// An identifier for the key that signed this certificate.
#[derive(Debug)]
pub struct AuthorityKeyIdentifier<'a> {
    key_id: Option<&'a [u8]>,
    issuer: OwnedVec<GeneralName<'a>>,
    serial: Option<Integer<'a>>,
}

impl<'a> AuthorityKeyIdentifier<'a> {
    /// The identifier of the signing key, where the issuer wrote one.
    #[must_use]
    pub fn key_id(&self) -> Option<&'a [u8]> {
        self.key_id
    }

    /// The names of the certificate that carries the signing key, where the
    /// issuer wrote them.
    #[must_use]
    pub fn issuer(&self) -> &[GeneralName<'a>] {
        &self.issuer
    }

    /// The serial number of that certificate, which is written with the names
    /// or not at all.
    #[must_use]
    pub fn serial(&self) -> Option<Integer<'a>> {
        self.serial
    }

    /// Reads the value of an authority key identifier extension.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.authorityKeyIdentifier";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let mut identifier = Self {
            key_id: None,
            issuer: inside.memory().vector(),
            serial: None,
        };

        // The three fields are written in the order of their numbers, once
        // each: a tag at or below the last one read is not this schema.
        let mut last_number = None;
        while let Some(field) = inside.next_element().field(FIELD)? {
            let tag = extension::context_of(field.tag());
            match tag {
                Some((0, false)) if last_number.is_none() => {
                    identifier.key_id = Some(field.contents());
                }
                Some((1, true)) if last_number < Some(1) => {
                    identifier.issuer = general_name::read_all(&inside, &field, FIELD)?;
                }
                Some((2, false)) if last_number < Some(2) => {
                    identifier.serial = Some(inside.integer(&field).field(FIELD)?);
                }
                _ => return Err(at(FIELD, ErrorCode::UnexpectedField, &field)),
            }
            last_number = tag.map(|(number, _)| number);
        }

        // The names and the serial number identify one certificate together.
        // Either alone names a certificate the issuer did not mean: a serial
        // number is unique within one issuer and says nothing without it.
        if identifier.issuer.is_empty() != identifier.serial.is_none() {
            return Err(fail(ErrorCode::MalformedValue));
        }

        // The issuer half of the pair stands for the issuer field of the
        // identified certificate, which is a distinguished name: without at
        // least one directory name beside the serial, the pair names no
        // certificate issuer while claiming to.
        if !identifier.issuer.is_empty()
            && !identifier
                .issuer
                .iter()
                .any(|name| matches!(name, general_name::GeneralName::Directory(_)))
        {
            return Err(fail(ErrorCode::MalformedValue));
        }

        // Empty, the structure names no issuing key and no certificate while
        // wearing the extension that exists to name one: at least the key
        // identifier or the complete issuer-and-serial pair is required.
        if identifier.key_id.is_none() && identifier.serial.is_none() {
            return Err(fail(ErrorCode::MalformedValue));
        }

        Ok(identifier)
    }
}

fn at(field: &'static str, code: ErrorCode, element: &Element<'_>) -> Error {
    Error::new(code, field, element.span().start)
}

#[cfg(test)]
mod tests;
