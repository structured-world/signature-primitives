//! Original clearance assertions (RFC5755 §4.4.6), without authorization policy.
//!
//! Both corrected and historical RFC3281 encodings can be inspected. No legacy
//! encoding is emitted. Classification meaning and category syntax belong to
//! the named security policy, not to this format reader.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.4.6>

use super::{end, sequence, tag};
use crate::attribute::Attribute;
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{BitString, Element, Encoding, Oid, Parser, ScopedReader, Tag, universal};

const FIELD: &str = "attributeCertificate.clearance";
/// Current `id-at-clearance`, 2.5.4.55 (RFC5755 §4.4.6).
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[85, 4, 55]);
/// Historical registration, 2.5.1.5.55, readable but never emitted here.
pub const LEGACY_IDENTIFIER: Oid<'static> = Oid::from_bytes(&[85, 1, 5, 55]);

/// Which original field-tag convention was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// Corrected untagged fields, mandatory for the current registration.
    Current,
    /// Deprecated RFC3281 context-tagged fields.
    Legacy,
}

/// An opaque, policy-specific security category, never a permission.
#[derive(Debug, Clone, Copy)]
pub struct SecurityCategory<'a> {
    parser: &'a Parser,
    depth: u32,
    /// Original complete category SEQUENCE.
    pub element: Element<'a>,
    /// Validated original `[0] IMPLICIT OBJECT IDENTIFIER`.
    pub kind: Oid<'a>,
    /// Original identifier encoding.
    pub kind_element: Element<'a>,
    /// Original `[1] EXPLICIT` open-type wrapper.
    pub wrapper: Element<'a>,
    /// Exactly one original DER value. Its type-specific meaning is unknown.
    pub value: Element<'a>,
}

impl<'a> SecurityCategory<'a> {
    /// Opens the whole original policy-specific value, including its tag, at
    /// its actual source depth under the current operation. The policy adapter
    /// can interpret it without a fresh Parser or resetting either budget.
    /// No temporary reader borrow is stored in the returned original facts.
    pub fn value_reader<'operation, W: Work>(
        &self,
        work: &'operation W,
    ) -> Result<ScopedReader<'a, 'operation>>
    where
        'a: 'operation,
    {
        work.read_scoped_source(
            self.parser,
            self.value.as_bytes(),
            self.value.span().start,
            Encoding::Der,
            self.depth,
        )
        .map_err(|e| Error::encoding(e, FIELD))
    }
}

/// Complete original clearance. Absence of classList means unclassified;
/// absence of securityCategories differs from a present empty SET.
#[derive(Debug)]
pub struct Clearance<'a> {
    /// Original whole SEQUENCE.
    pub element: Element<'a>,
    /// Original field-tag convention, not a policy choice.
    pub syntax: Syntax,
    /// Security policy identifier, not a trust assertion.
    pub policy: Oid<'a>,
    /// Original policy identifier field.
    pub policy_element: Element<'a>,
    /// Original named bits, including policy-defined positions beyond bit5.
    pub classes: Option<BitString<'a>>,
    /// Original classList field, absent for the schema default.
    pub classes_element: Option<Element<'a>>,
    /// Original categories SET, absent independently of its cardinality.
    pub categories_element: Option<Element<'a>>,
    /// Categories in original SET order, with retained capacity accounting.
    pub categories: OwnedVec<SecurityCategory<'a>>,
}

impl<'a> Clearance<'a> {
    /// Reads exactly one complete current or deprecated clearance syntax.
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let result = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(result)
    }

    /// Reads original DER fields without retagging or resetting source limits.
    pub fn read_element(parent: &ScopedReader<'a, '_>, element: &Element<'a>) -> Result<Self> {
        let mut der = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut der, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&der, FIELD)?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, FIELD))?;
        let policy_element = required(&mut inside, FIELD)?;
        let syntax = if policy_element.tag() == Tag::context(false, 0) {
            Syntax::Legacy
        } else {
            tag(&policy_element, Tag::primitive(universal::OID), FIELD)?;
            Syntax::Current
        };
        let policy = inside
            .oid(&policy_element)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let class_tag = match syntax {
            Syntax::Current => Tag::primitive(universal::BIT_STRING),
            Syntax::Legacy => Tag::context(false, 1),
        };
        let set_tag = match syntax {
            Syntax::Current => Tag::constructed(universal::SET),
            Syntax::Legacy => Tag::context(true, 2),
        };
        let mut next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?;
        let classes_element = super::optional(&mut inside, &mut next, class_tag, FIELD)?;
        let classes = classes_element
            .map(|encoded| {
                let bits = inside
                    .bit_string(&encoded)
                    .map_err(|e| Error::encoding(e, FIELD))?;
                // X.690 §11.2.2: a named-bit list omits trailing zero bits. This
                // does not impose a six-bit cap: RFC5755 allows policy extensions.
                if !bits.is_empty() && !bits.bit(bits.len() - 1) {
                    return Err(Error::schema(
                        ErrorCode::MalformedValue,
                        FIELD,
                        encoded.span().start,
                    ));
                }
                // X.690 §11.5 omits the complete DEFAULT {unclassified}, not every
                // class list that happens to contain that bit.
                if bits.len() == 2 && bits.as_bytes() == [0x40] {
                    return Err(Error::schema(
                        ErrorCode::DefaultWritten,
                        FIELD,
                        encoded.span().start,
                    ));
                }
                Ok(bits)
            })
            .transpose()?;
        let categories_element = next;
        let execution = inside.execution();
        let mut categories = execution.vector();
        if let Some(set) = categories_element {
            tag(&set, set_tag, FIELD)?;
            let mut entries = inside.enter(&set).map_err(|e| Error::encoding(e, FIELD))?;
            let mut previous = None;
            while let Some(entry) = entries
                .next_element()
                .map_err(|e| Error::encoding(e, FIELD))?
            {
                if let Some(before) = previous
                    && !structured_pkix::der::set_ordered(&entries, before, &entry, FIELD)
                        .map_err(Error::pkix)?
                {
                    return Err(Error::schema(
                        ErrorCode::SetOrder,
                        FIELD,
                        entry.span().start,
                    ));
                }
                categories
                    .try_reserve(1)
                    .map_err(|e| Error::resource(e, FIELD, entry.span().start))?;
                categories
                    .try_push(category(&entries, &entry)?)
                    .map_err(|e| Error::resource(e, FIELD, entry.span().start))?;
                previous = Some(entry.as_bytes());
            }
        }
        end(&inside, FIELD)?;
        Ok(Self {
            element,
            syntax,
            policy,
            policy_element,
            classes,
            classes_element,
            categories_element,
            categories: categories.into_owned(),
        })
    }

    /// Reads every registered value. Current OID forbids historical tagging;
    /// historical OID supports both original and corrected syntax (§4.4.6).
    pub fn read_attribute<W: Work>(attribute: &Attribute<'a>, work: &W) -> Result<OwnedVec<Self>> {
        let execution = attribute.query_in(work);
        execution
            .charge_work(8)
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
        let current = attribute.kind() == IDENTIFIER;
        if !current && attribute.kind() != LEGACY_IDENTIFIER {
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
        let mut result = execution.vector();
        result
            .try_reserve_exact(attribute.values().len())
            .map_err(|e| Error::resource(e, FIELD, attribute.span().start))?;
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
            let value = Self::read(&mut reader)?;
            if current && value.syntax == Syntax::Legacy {
                return Err(Error::schema(
                    ErrorCode::AttributeSyntax,
                    FIELD,
                    value.policy_element.span().start,
                ));
            }
            result
                .try_push(value)
                .map_err(|e| Error::resource(e, FIELD, reader.offset()))?;
        }
        Ok(result.into_owned())
    }

    /// Effective bit, including the unclassified default when classList is absent.
    /// O(1) metadata access; no security-policy ranking is inferred.
    #[must_use]
    pub fn has_class(&self, position: u64) -> bool {
        match self.classes {
            Some(bits) => bits.bit(position),
            None => position == 1,
        }
    }
}

fn category<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
) -> Result<SecurityCategory<'a>> {
    tag(element, sequence(), FIELD)?;
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let kind_element = required(&mut inside, FIELD)?;
    tag(&kind_element, Tag::context(false, 0), FIELD)?;
    let kind = inside
        .oid(&kind_element)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let wrapper = required(&mut inside, FIELD)?;
    tag(&wrapper, Tag::context(true, 1), FIELD)?;
    end(&inside, FIELD)?;
    let mut nested = inside
        .enter(&wrapper)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let value = required(&mut nested, FIELD)?;
    end(&nested, FIELD)?;
    structured_pkix::der::conforms(&nested, &value, FIELD).map_err(Error::pkix)?;
    Ok(SecurityCategory {
        parser: parent.parser(),
        depth: nested.depth(),
        element: *element,
        kind,
        kind_element,
        wrapper,
        value,
    })
}
