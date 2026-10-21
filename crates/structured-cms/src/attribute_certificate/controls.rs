//! `AAControls` syntax and per-extension attribute restriction (RFC5755 §7.4).
//!
//! This does not establish an AA CA trust anchor or validate its certificate
//! path. Callers apply every control from that trusted path, including to
//! decrypted attributes and encAttrs. A readable control is not authority.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-7.4>

use super::{end, sequence, tag};
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Integer, Oid, Parser, ScopedReader, Tag, universal};
use structured_pkix::Extension;

const FIELD: &str = "attributeCertificate.aaControls";
/// `id-pe-aaControls`, 1.3.6.1.5.5.7.1.6.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 1, 6]);

/// Complete original `AAControls`. Absence and an explicitly empty `AttrSpec` are
/// preserved; neither grants an attribute independently of other path controls.
#[derive(Debug)]
pub struct AaControls<'a> {
    parser: &'a Parser,
    /// Original whole value SEQUENCE.
    pub element: Element<'a>,
    /// Original unbounded nonnegative path constraint; never truncated.
    pub path_length: Option<Integer<'a>>,
    /// Original pathLenConstraint encoding.
    pub path_length_element: Option<Element<'a>>,
    /// Original `[0] IMPLICIT AttrSpec`, absent independently of its contents.
    pub permitted_element: Option<Element<'a>>,
    /// Original permitted identifiers in sequence order, without deduplication.
    pub permitted: OwnedVec<Oid<'a>>,
    /// Original `[1] IMPLICIT AttrSpec`.
    pub excluded_element: Option<Element<'a>>,
    /// Original excluded identifiers, which override permitted entries.
    pub excluded: OwnedVec<Oid<'a>>,
    /// Original BOOLEAN, absent for the schema default TRUE.
    pub unspecified_element: Option<Element<'a>>,
    /// Effective permitUnSpecified, including its normative default.
    pub permit_unspecified: bool,
}

impl<'a> AaControls<'a> {
    /// Reads a complete original DER value with inherited source/current limits.
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let result = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(result)
    }

    /// Reads one original whole element, without a replacement Parser.
    pub fn read_element(parent: &ScopedReader<'a, '_>, element: &Element<'a>) -> Result<Self> {
        let mut der = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut der, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&der, FIELD)?;
        let mut inside = der.enter(&element).map_err(|e| Error::encoding(e, FIELD))?;
        let mut next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?;
        let path_length_element = super::optional(
            &mut inside,
            &mut next,
            Tag::primitive(universal::INTEGER),
            FIELD,
        )?;
        let path_length = path_length_element
            .map(|encoded| {
                let number = inside
                    .integer(&encoded)
                    .map_err(|e| Error::encoding(e, FIELD))?;
                if number.is_negative() {
                    return Err(Error::schema(
                        ErrorCode::MalformedValue,
                        FIELD,
                        encoded.span().start,
                    ));
                }
                Ok(number)
            })
            .transpose()?;
        let permitted_element =
            super::optional(&mut inside, &mut next, Tag::context(true, 0), FIELD)?;
        let excluded_element =
            super::optional(&mut inside, &mut next, Tag::context(true, 1), FIELD)?;
        let unspecified_element = super::optional(
            &mut inside,
            &mut next,
            Tag::primitive(universal::BOOLEAN),
            FIELD,
        )?;
        super::no_pending(next, FIELD)?;
        let permit_unspecified = match unspecified_element {
            Some(encoded) => {
                let value = inside
                    .boolean(&encoded)
                    .map_err(|e| Error::encoding(e, FIELD))?;
                // RFC5755 §7.4 + X.690 §11.5: TRUE is the DEFAULT and must
                // be omitted in DER. Explicit FALSE is a distinct restriction.
                if value {
                    return Err(Error::schema(
                        ErrorCode::DefaultWritten,
                        FIELD,
                        encoded.span().start,
                    ));
                }
                false
            }
            None => true,
        };
        let permitted = identifiers(&inside, permitted_element)?;
        let excluded = identifiers(&inside, excluded_element)?;
        Ok(Self {
            parser: parent.parser(),
            element,
            path_length,
            path_length_element,
            permitted_element,
            permitted,
            excluded_element,
            excluded,
            unspecified_element,
            permit_unspecified,
        })
    }

    /// Reads a registered PKC extension. Criticality MAY be TRUE (§7.4), so
    /// either value is accepted; no PKC or trust assertion is fabricated.
    pub fn read_extension<W: Work>(extension: &Extension<'a>, work: &W) -> Result<Self> {
        let execution = work.execution_for(extension.parser());
        execution
            .charge_work(9)
            .map_err(|e| Error::resource(e, FIELD, extension.span().start))?;
        if extension.kind() != IDENTIFIER {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                FIELD,
                extension.span().start,
            ));
        }
        let mut reader = extension
            .reader_scoped(&execution)
            .map_err(|e| Error::encoding(e, FIELD))?;
        Self::read(&mut reader)
    }

    /// This extension's attribute restriction only. Exclusions win even when
    /// an OID also appears in permittedAttrs. Apply the intersection of all
    /// required trusted-path controls; this predicate proves no path or trust.
    pub fn allows<W: Work>(&self, kind: Oid<'_>, work: &W) -> Result<bool> {
        let execution = work.execution_for(self.parser);
        execution
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, self.element.span().start))?;
        // §7.4 disallows excluded types for every issuer below the AA CA.
        // A simultaneous permitted entry cannot override that prohibition.
        // https://www.rfc-editor.org/rfc/rfc5755#section-7.4
        for (list, answer) in [(&self.excluded, false), (&self.permitted, true)] {
            for identifier in list {
                let amount = identifier.as_bytes().len().min(kind.as_bytes().len()) as u64 + 1;
                execution
                    .charge_work(amount)
                    .map_err(|e| Error::resource(e, FIELD, self.element.span().start))?;
                if *identifier == kind {
                    return Ok(answer);
                }
            }
        }
        Ok(self.permit_unspecified)
    }

    /// Compares a caller's already-established path distance to this one bound.
    /// RFC5280 path-length counting and selecting the AA CA remain caller work.
    /// Wide positive constraints exceed every u64 distance rather than wrapping.
    pub fn permits_distance<W: Work>(&self, distance: u64, work: &W) -> Result<bool> {
        let execution = work.execution_for(self.parser);
        execution
            .charge_work(10)
            .map_err(|e| Error::resource(e, FIELD, self.element.span().start))?;
        Ok(match self.path_length {
            None => true,
            Some(number) => match number.as_u64() {
                Some(bound) => distance <= bound,
                None => true,
            },
        })
    }
}

fn identifiers<'a>(
    parent: &ScopedReader<'a, '_>,
    element: Option<Element<'a>>,
) -> Result<OwnedVec<Oid<'a>>> {
    let execution = parent.execution();
    let mut result = execution.vector();
    if let Some(encoded) = element {
        let mut inside = parent
            .enter(&encoded)
            .map_err(|e| Error::encoding(e, FIELD))?;
        while let Some(value) = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?
        {
            tag(&value, Tag::primitive(universal::OID), FIELD)?;
            result
                .try_reserve(1)
                .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
            let identifier = inside.oid(&value).map_err(|e| Error::encoding(e, FIELD))?;
            result
                .try_push(identifier)
                .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
        }
    }
    Ok(result.into_owned())
}
