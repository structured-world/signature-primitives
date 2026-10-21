//! Original IETF group/charging attribute values (RFC5755 §4.4).
//!
//! These are assertions, not authenticated memberships or authorization facts.
//! A policy authority is distinct from the AC issuer, and is not discovered or
//! trusted by decoding its name. No value is normalized or re-encoded.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.4>

use super::{end, names, sequence, tag};
use crate::attribute::Attribute;
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, ScopedReader, Tag, universal};
use structured_pkix::general_name::GeneralName;

const FIELD: &str = "attributeCertificate.ietfAttrSyntax";

/// `id-aca-chargingIdentity`, RFC5755 §4.4.3 / Appendix B.
pub const CHARGING_IDENTITY: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 10, 3]);
/// `id-aca-group`, RFC5755 §4.4.4 / Appendix B.
pub const GROUP: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 10, 4]);

/// The syntax selected by every member of the values sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Primitive DER OCTET STRING.
    Octets,
    /// ASN.1 OBJECT IDENTIFIER, validated by the common reader.
    Oid,
    /// Primitive DER `UTF8String`, without text normalization.
    Utf8,
}

/// One borrowed, validated value; no allocating or lossy text projection.
#[derive(Debug, Clone, Copy)]
pub enum Value<'a> {
    /// Original octet contents, including empty octets.
    Octets(&'a [u8]),
    /// Original identifier octets, without a decimal string conversion.
    Oid(Oid<'a>),
    /// Original UTF-8 text, including empty text.
    Utf8(&'a str),
}
impl Value<'_> {
    /// This member's syntax. All members of a reading have the same choice.
    #[must_use]
    pub fn choice(self) -> Choice {
        match self {
            Self::Octets(_) => Choice::Octets,
            Self::Oid(_) => Choice::Oid,
            Self::Utf8(_) => Choice::Utf8,
        }
    }
}

/// A typed value and its entire original encoding/location.
#[derive(Debug, Clone, Copy)]
pub struct Member<'a> {
    /// Original whole member, without stripping its source range.
    pub element: Element<'a>,
    /// Borrowed validated contents.
    pub value: Value<'a>,
}

/// Fully decoded `IetfAttrSyntax` with independently retained metadata storage.
/// The original document must remain alive; a shorter query need not.
#[derive(Debug)]
pub struct IetfAttrSyntax<'a> {
    element: Element<'a>,
    authority: Option<OwnedVec<GeneralName<'a>>>,
    authority_element: Option<Element<'a>>,
    values: OwnedVec<Member<'a>>,
    choice: Option<Choice>,
}

impl<'a> IetfAttrSyntax<'a> {
    /// Reads one complete standalone DER value. A BER envelope does not relax
    /// the DER requirement of AC signed information (RFC5755 §4.1).
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let reading = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(reading)
    }

    /// Decodes a whole original element in its producing context. Root headers
    /// and contents follow DER, preserving source offsets, nesting and current
    /// execution. No replacement Parser or retagged bytes are manufactured.
    pub fn read_element(parent: &ScopedReader<'a, '_>, element: &Element<'a>) -> Result<Self> {
        let mut der = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut der, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&der, FIELD)?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, FIELD))?;
        let mut first = required(&mut inside, FIELD)?;
        let (authority, authority_element) = if first.tag() == Tag::context(true, 0) {
            // RFC5755 Appendix B uses IMPLICIT TAGS. GeneralNames is a
            // SEQUENCE, so [0] replaces its tag; no explicit inner SEQUENCE.
            let authority = names(&inside, &first, FIELD)?;
            let encoded = first;
            first = required(&mut inside, FIELD)?;
            (Some(authority), Some(encoded))
        } else {
            (None, None)
        };
        tag(&first, sequence(), FIELD)?;
        end(&inside, FIELD)?;
        let mut members = inside
            .enter(&first)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let execution = inside.execution();
        let mut values = execution.vector();
        let mut choice = None;
        while let Some(encoded) = members
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?
        {
            let selected = match encoded.tag() {
                t if t == Tag::primitive(universal::OCTET_STRING) => Choice::Octets,
                t if t == Tag::primitive(universal::OID) => Choice::Oid,
                t if t == Tag::primitive(universal::UTF8_STRING) => Choice::Utf8,
                _ => {
                    return Err(Error::schema(
                        ErrorCode::UnexpectedTag,
                        FIELD,
                        encoded.span().start,
                    ));
                }
            };
            // RFC5755 §4.4 requires one syntax across ALL values. Do not
            // accept a valid prefix and silently discard a later mixed choice.
            if let Some(previous) = choice
                && previous != selected
            {
                return Err(Error::schema(
                    ErrorCode::AttributeSyntax,
                    FIELD,
                    encoded.span().start,
                ));
            }
            let value = match selected {
                Choice::Octets => Value::Octets(encoded.contents()),
                Choice::Oid => Value::Oid(
                    members
                        .oid(&encoded)
                        .map_err(|e| Error::encoding(e, FIELD))?,
                ),
                Choice::Utf8 => {
                    members
                        .charge(encoded.contents().len() as u64)
                        .map_err(|e| Error::encoding(e, FIELD))?;
                    Value::Utf8(core::str::from_utf8(encoded.contents()).map_err(|e| {
                        Error::schema(
                            ErrorCode::MalformedValue,
                            FIELD,
                            encoded.contents_span().start + e.valid_up_to() as u64,
                        )
                    })?)
                }
            };
            values
                .try_push(Member {
                    element: encoded,
                    value,
                })
                .map_err(|e| Error::resource(e, FIELD, encoded.span().start))?;
            choice = Some(selected);
        }
        // The values SEQUENCE OF in §4.4 has no SIZE constraint. GeneralNames
        // itself is nonempty, but an empty values sequence has no chosen type.
        Ok(Self {
            element,
            authority,
            authority_element,
            values: values.into_owned(),
            choice,
        })
    }

    /// Reads a registered group or chargingIdentity Attribute. RFC5755
    /// §§4.4.3–4.4.4 permit exactly one outer `AttributeValue`, with multiplicity
    /// inside `IetfAttrSyntax`. OID/cardinality checks precede value decoding.
    /// This does not infer group membership, authority trust or charging policy.
    pub fn read_attribute<W: Work>(attribute: &Attribute<'a>, work: &W) -> Result<Self> {
        let execution = attribute.query_in(work);
        // Two fixed-width identifier comparisons plus cardinality metadata;
        // an attacker-selected longer OID is rejected by length, not scanned.
        execution
            .charge_work(17)
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        if attribute.kind() != GROUP && attribute.kind() != CHARGING_IDENTITY {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                FIELD,
                attribute.span().start,
            ));
        }
        if attribute.values().len() != 1 {
            return Err(Error::schema(
                ErrorCode::AttributeCardinality,
                FIELD,
                attribute.span().start,
            ));
        }
        let mut reader = attribute
            .value_reader_scoped(0, &execution, FIELD)?
            .ok_or_else(|| {
                Error::schema(
                    ErrorCode::AttributeCardinality,
                    FIELD,
                    attribute.span().start,
                )
            })?;
        Self::read(&mut reader)
    }

    /// Original whole syntax value, without canonicalization.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Original policyAuthority names, separate from AC issuer/trust.
    #[must_use]
    pub fn authority(&self) -> Option<&[GeneralName<'a>]> {
        self.authority.as_deref()
    }
    /// Original IMPLICIT authority encoding, including its actual source range.
    #[must_use]
    pub fn authority_element(&self) -> Option<Element<'a>> {
        self.authority_element
    }
    /// Original values in order. Callers admit their own traversal; reading
    /// this borrowed slice neither copies storage nor performs matching.
    #[must_use]
    pub fn values(&self) -> &[Member<'a>] {
        &self.values
    }
    /// Common syntax, or None for an empty original values sequence.
    #[must_use]
    pub fn choice(&self) -> Option<Choice> {
        self.choice
    }
}
