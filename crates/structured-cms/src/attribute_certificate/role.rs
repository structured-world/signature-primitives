//! Original role assertions (RFC5755 §4.4.5 / Appendix B).
//!
//! Decoding neither authenticates the role authority nor grants a permission.
//! A role specification certificate need not exist; no URI is dereferenced.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.4.5>

use super::{end, names, sequence, tag};
use crate::attribute::Attribute;
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, ScopedReader, Tag};
use structured_pkix::general_name::{self, GeneralName};

const FIELD: &str = "attributeCertificate.role";

/// `id-at-role` (2.5.4.72), RFC5755 §4.4.5 / Appendix B.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 4, 72]);

/// A complete DER role assertion, borrowing the original document. Authority
/// metadata retains its capacity charge independently of the shorter query.
#[derive(Debug)]
pub struct RoleSyntax<'a> {
    element: Element<'a>,
    authority_element: Option<Element<'a>>,
    authority: Option<OwnedVec<GeneralName<'a>>>,
    name_wrapper: Element<'a>,
    name_element: Element<'a>,
    name: &'a str,
}

impl<'a> RoleSyntax<'a> {
    /// Reads exactly one standalone role value. AC signed information is DER
    /// even when a BER envelope carries it (RFC5755 §4.1).
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let reading = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(reading)
    }

    /// Reads an original element under its producing source/depth and current
    /// execution. All fields and trailing bytes are checked before success.
    pub fn read_element(parent: &ScopedReader<'a, '_>, element: &Element<'a>) -> Result<Self> {
        let mut der = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut der, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&der, FIELD)?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, FIELD))?;
        let mut next = required(&mut inside, FIELD)?;
        let (authority_element, authority) = if next.tag() == Tag::context(true, 0) {
            // Appendix B is IMPLICIT TAGS: replace the GeneralNames SEQUENCE
            // tag, but retain the GeneralName CHOICE tag inside [1] below.
            let authority = names(&inside, &next, FIELD)?;
            let original = next;
            next = required(&mut inside, FIELD)?;
            (Some(original), Some(authority))
        } else {
            (None, None)
        };
        tag(&next, Tag::context(true, 1), FIELD)?;
        end(&inside, FIELD)?;
        let mut wrapped = inside.enter(&next).map_err(|e| Error::encoding(e, FIELD))?;
        let name_element = required(&mut wrapped, FIELD)?;
        // RFC5755 §4.4.5 requires the URI CHOICE, not an arbitrary GeneralName.
        // Preflight the tag before decoding an unrelated allocating Name.
        tag(&name_element, Tag::context(false, 6), FIELD)?;
        end(&wrapped, FIELD)?;
        let GeneralName::Uri(name) =
            general_name::read(&wrapped, &name_element, FIELD).map_err(Error::pkix)?
        else {
            unreachable!("URI tag preflight")
        };
        Ok(Self {
            element,
            authority_element,
            authority,
            name_wrapper: next,
            name_element,
            name,
        })
    }

    /// Reads every value of one registered `id-at-role` Attribute in source
    /// order. RFC5755 §4.4.5 permits multiple values, unlike group/charging
    /// singleton syntax. Empty or invalid later values refuse the whole read;
    /// no successful partial catalogue or authorization fact is returned.
    pub fn read_attribute<W: Work>(attribute: &Attribute<'a>, work: &W) -> Result<OwnedVec<Self>> {
        let execution = attribute.query_in(work);
        // One fixed-width OID comparison and cardinality metadata. Longer
        // attacker-selected OIDs fail on length, without scanning their bytes.
        execution
            .charge_work(4)
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        if attribute.kind() != IDENTIFIER {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                FIELD,
                attribute.span().start,
            ));
        }
        if attribute.values().is_empty() {
            return Err(Error::schema(
                ErrorCode::AttributeCardinality,
                FIELD,
                attribute.span().start,
            ));
        }
        let mut values = execution.vector();
        for index in 0..attribute.values().len() {
            let mut reader = attribute
                .value_reader_scoped(index, &execution, FIELD)?
                .ok_or_else(|| {
                    Error::schema(
                        ErrorCode::AttributeCardinality,
                        FIELD,
                        attribute.span().start,
                    )
                })?;
            let at = reader.offset();
            values
                .try_reserve(1)
                .map_err(|e| Error::resource(e, FIELD, at))?;
            let value = Self::read(&mut reader)?;
            values
                .try_push(value)
                .map_err(|e| Error::resource(e, FIELD, at))?;
        }
        Ok(values.into_owned())
    }

    /// Original whole `RoleSyntax` encoding.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Optional original authority names, not authenticated by this reader.
    #[must_use]
    pub fn authority(&self) -> Option<&[GeneralName<'a>]> {
        self.authority.as_deref()
    }
    /// Original `[0] IMPLICIT GeneralNames`, if written.
    #[must_use]
    pub fn authority_element(&self) -> Option<Element<'a>> {
        self.authority_element
    }
    /// Original mandatory `[1] EXPLICIT GeneralName` wrapper.
    #[must_use]
    pub fn name_wrapper(&self) -> Element<'a> {
        self.name_wrapper
    }
    /// Original URI CHOICE element, inside the explicit wrapper.
    #[must_use]
    pub fn name_element(&self) -> Element<'a> {
        self.name_element
    }
    /// Original validated URI, without normalization, copying or acquisition.
    #[must_use]
    pub fn name(&self) -> &'a str {
        self.name
    }
}
