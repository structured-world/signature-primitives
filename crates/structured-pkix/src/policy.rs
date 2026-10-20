//! The policies a certificate was issued under.
//!
//! A policy identifier is what a trusted list points at when it says which
//! service issued a certificate, so these are identity rather than
//! description. The qualifiers beside them are kept as they were encoded: one
//! of them is a location, and a location is data here.

use crate::error::{Error, ErrorCode, Located, Result, gate};
use crate::extension::{self, Extension};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Oid, Parser, Tag, universal};

/// One policy, and whatever was written beside it.
#[derive(Debug)]
pub struct PolicyInformation<'a> {
    policy: Oid<'a>,
    qualifiers: OwnedVec<PolicyQualifier<'a>>,
    at: u64,
}

impl<'a> PolicyInformation<'a> {
    /// Which policy.
    #[must_use]
    pub fn policy(&self) -> Oid<'a> {
        self.policy
    }

    /// What was written beside it.
    #[must_use]
    pub fn qualifiers(&self) -> &[PolicyQualifier<'a>] {
        &self.qualifiers
    }
}

/// One qualifier: what kind it is, and its value as encoded.
#[derive(Debug, Clone, Copy)]
pub struct PolicyQualifier<'a> {
    kind: Oid<'a>,
    value: &'a [u8],
    /// Where the value sits in the document, so an error found while
    /// re-parsing it points at the qualifier rather than at the front of the
    /// certificate.
    at: u64,
    /// Depth above the qualifier pair, retained for its later decode.
    outer: u32,
}

impl<'a> PolicyQualifier<'a> {
    /// What kind of qualifier this is.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }

    /// The value, as it was encoded. A practice statement qualifier holds a
    /// location, which stays a string of bytes here.
    #[must_use]
    pub fn value(self) -> &'a [u8] {
        self.value
    }
}

/// The policies of one certificate.
#[derive(Debug)]
pub struct CertificatePolicies<'a> {
    policies: OwnedVec<PolicyInformation<'a>>,
}

impl<'a> CertificatePolicies<'a> {
    /// Every policy, in order.
    #[must_use]
    pub fn policies(&self) -> &[PolicyInformation<'a>] {
        &self.policies
    }

    /// Whether one policy is among them.
    ///
    /// The identifier that stands for any policy is not treated as matching
    /// everything: whether it does depends on where in a path this certificate
    /// sits, which is not a question this layer can answer.
    pub fn has<W: Work>(&self, policy: Oid<'_>, execution: &W) -> Result<bool> {
        for information in &self.policies {
            let work = 1 + information
                .policy
                .as_bytes()
                .len()
                .max(policy.as_bytes().len()) as u64;
            execution.charge_work(work).map_err(|reason| {
                Error::resource(reason, "extensions.certificatePolicies", information.at)
            })?;
            if information.policy == policy {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reads the value of a certificate policies extension.
    pub fn read<W: Work>(extension: &Extension<'a>, execution: &W) -> Result<Self> {
        const FIELD: &str = "extensions.certificatePolicies";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let work = inside.execution_in(execution.memory());
        let mut policies = work.vector();
        let mut identifiers = work.map::<Oid<'a>, ()>();

        while let Some(entry) = inside.next_element().field(FIELD)? {
            let at = |code| Error::new(code, FIELD, entry.span().start);
            if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(at(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }

            let mut information = inside.enter(&entry).field(FIELD)?;
            let policy = information.read_oid().field(FIELD)?;
            let mut qualifiers = work.vector();

            if let Some(list) = information.next_element().field(FIELD)? {
                if list.tag() != Tag::constructed(universal::SEQUENCE) {
                    return Err(at(ErrorCode::Encoding(
                        structured_asn1::ErrorCode::UnexpectedTag,
                    )));
                }
                let mut each = information.enter(&list).field(FIELD)?;
                while let Some(qualifier) = each.next_element().field(FIELD)? {
                    if qualifier.tag() != Tag::constructed(universal::SEQUENCE) {
                        return Err(at(ErrorCode::Encoding(
                            structured_asn1::ErrorCode::UnexpectedTag,
                        )));
                    }
                    let mut pair = each.enter(&qualifier).field(FIELD)?;
                    let kind = pair.read_oid().field(FIELD)?;
                    let value = pair
                        .next_element()
                        .field(FIELD)?
                        .ok_or_else(|| at(ErrorCode::MissingField))?;
                    if !pair.is_empty() {
                        return Err(at(ErrorCode::TrailingData));
                    }
                    // The value is preserved for whoever knows the kind, and
                    // a policy is what a trusted list points at when it names
                    // the service that issued a certificate, so what is kept
                    // has to be the encoding the document claims all the way
                    // down. The outer header alone would leave a second
                    // spelling of a value one level lower, arriving at the
                    // same reader by the same route.
                    crate::name::walk_der(&pair, &value, FIELD, crate::name::Strings::Checked)?;
                    qualifiers
                        .try_push(PolicyQualifier {
                            kind,
                            value: value.as_bytes(),
                            at: value.span().start,
                            outer: each.depth(),
                        })
                        .map_err(|reason| Error::resource(reason, FIELD, qualifier.span().start))?;
                }
                if qualifiers.is_empty() {
                    return Err(at(ErrorCode::EmptySequence));
                }
            }

            if !information.is_empty() {
                return Err(at(ErrorCode::TrailingData));
            }

            // One policy written twice leaves no answer to which qualifiers
            // belong to it. A set rather than a scan, so a long list costs
            // the work its size says and not its square.
            if identifiers
                .try_insert(policy, ())
                .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?
                .is_some()
            {
                return Err(at(ErrorCode::MalformedValue));
            }

            policies
                .try_push(PolicyInformation {
                    policy,
                    qualifiers: qualifiers.into_owned(),
                    at: entry.span().start,
                })
                .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
        }

        if policies.is_empty() {
            return Err(fail(ErrorCode::EmptySequence));
        }
        Ok(Self {
            policies: policies.into_owned(),
        })
    }
}

/// A policy of one domain treated as equivalent to a policy of another.
#[derive(Debug, Clone, Copy)]
pub struct PolicyMapping<'a> {
    issuer_domain: Oid<'a>,
    subject_domain: Oid<'a>,
}

impl<'a> PolicyMapping<'a> {
    /// The policy as the issuer of this certificate names it.
    #[must_use]
    pub fn issuer_domain(self) -> Oid<'a> {
        self.issuer_domain
    }

    /// The policy it stands for below this certificate.
    #[must_use]
    pub fn subject_domain(self) -> Oid<'a> {
        self.subject_domain
    }
}

/// The mappings of one certificate.
#[derive(Debug)]
pub struct PolicyMappings<'a> {
    mappings: OwnedVec<PolicyMapping<'a>>,
}

impl<'a> PolicyMappings<'a> {
    /// Every mapping, in order.
    #[must_use]
    pub fn mappings(&self) -> &[PolicyMapping<'a>] {
        &self.mappings
    }

    /// Reads the value of a policy mappings extension.
    pub fn read<W: Work>(extension: &Extension<'a>, execution: &W) -> Result<Self> {
        const FIELD: &str = "extensions.policyMappings";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let work = inside.execution_in(execution.memory());
        let mut mappings = work.vector();
        let mut seen = work.map::<(Oid<'a>, Oid<'a>), ()>();

        while let Some(entry) = inside.next_element().field(FIELD)? {
            let at = |code| Error::new(code, FIELD, entry.span().start);
            if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(at(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }

            let mut pair = inside.enter(&entry).field(FIELD)?;
            let issuer_domain = pair.read_oid().field(FIELD)?;
            let subject_domain = pair.read_oid().field(FIELD)?;
            if !pair.is_empty() {
                return Err(at(ErrorCode::TrailingData));
            }

            // Mapping the identifier that stands for any policy would make
            // every policy below this certificate equivalent to one of them.
            if issuer_domain == crate::oid::ANY_POLICY || subject_domain == crate::oid::ANY_POLICY {
                return Err(at(ErrorCode::MalformedValue));
            }

            // A repeated issuer domain with distinct subjects is legitimate:
            // path processing takes the set of subject policies equivalent to
            // one issuer policy (RFC 5280 6.1.4 (b)(1)), and repeating the
            // issuer is how that set is written. The exact pair written twice
            // maps what one occurrence maps, and the list is a SEQUENCE OF
            // with no uniqueness constraint: the repeat is folded away rather
            // than refused, so a valid certificate is not blocked over it.
            if seen
                .try_insert((issuer_domain, subject_domain), ())
                .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?
                .is_none()
            {
                mappings
                    .try_push(PolicyMapping {
                        issuer_domain,
                        subject_domain,
                    })
                    .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
            }
        }

        if mappings.is_empty() {
            return Err(fail(ErrorCode::EmptySequence));
        }
        Ok(Self {
            mappings: mappings.into_owned(),
        })
    }
}

impl CertificatePolicies<'_> {
    /// Whether every qualifier was actually interpreted, for the gate that
    /// decides what a critical extension blocked.
    ///
    /// RFC 5280 4.2.1.4 defines two qualifiers, the practice-statement
    /// pointer and the user notice. A kind outside those, or a known kind
    /// whose payload does not have its shape, is a critical qualifier this
    /// run never understood. An error is a spent budget and only that.
    pub(crate) fn understood<W: Work>(&self, parser: &Parser, execution: &W) -> Result<bool> {
        for qualifier in self.policies.iter().flat_map(PolicyInformation::qualifiers) {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, QUALIFIER_FIELD, qualifier.at))?;
            if !retained_qualifier_understood(parser, *qualifier, execution)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// The field the qualifier gates below report a spent budget in.
const QUALIFIER_FIELD: &str = "extensions.certificatePolicies";

fn retained_qualifier_understood<W: Work>(
    parser: &Parser,
    qualifier: PolicyQualifier<'_>,
    execution: &W,
) -> Result<bool> {
    // Re-parsed from where the value sits, so the one error that leaves
    // here, a spent budget, carries a document offset as the error type
    // promises. Malformation still answers no.
    let Some(mut reader) = gate(
        execution
            .read_nested(
                parser,
                qualifier.value,
                qualifier.at,
                structured_asn1::Encoding::Der,
                qualifier.outer,
            )
            .field(QUALIFIER_FIELD),
    )?
    else {
        return Ok(false);
    };
    let Some(Some(value)) = gate(reader.next_element().field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    if !reader.is_empty() {
        return Ok(false);
    }

    qualifier_understood(&reader, qualifier.kind, &value)
}

#[derive(Clone, Copy)]
enum QualifierKind {
    Cps,
    Notice,
}

/// Checks a DER policy qualifier's selected schema (RFC5280 §4.2.1.4).
///
/// `parent` is the producing reader, with the current execution account and
/// original parser-local cumulative work/depth ceilings. A known value from
/// a BER envelope is reread under DER with those same ceilings and offsets.
/// No value bytes are copied, no URI is fetched and no application policy is selected.
/// Unknown kinds and malformed known payloads return `false`; callers decide
/// independently whether an unknown qualifier is permitted or preserved.
///
/// # Errors
/// Resource refusals remain located errors, separately from `false`.
pub fn qualifier_understood<'a>(
    parent: &structured_asn1::ScopedReader<'a, '_>,
    kind: Oid<'_>,
    value: &structured_asn1::Element<'a>,
) -> Result<bool> {
    let work = (kind
        .as_bytes()
        .len()
        .max(crate::oid::CPS_QUALIFIER.as_bytes().len()) as u64)
        .checked_mul(2)
        .and_then(|cost| cost.checked_add(1))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                QUALIFIER_FIELD,
                value.span().start,
            )
        })?;
    qualifier_charge(parent, value, work)?;
    let kind = if kind == crate::oid::CPS_QUALIFIER {
        QualifierKind::Cps
    } else if kind == crate::oid::USER_NOTICE_QUALIFIER {
        QualifierKind::Notice
    } else {
        return Ok(false);
    };
    if parent.encoding().is_der() {
        return qualifier_schema(parent, kind, value);
    }
    let Some(mut reader) = gate(
        parent
            .reread(value, structured_asn1::Encoding::Der)
            .field(QUALIFIER_FIELD),
    )?
    else {
        return Ok(false);
    };
    let Some(Some(value)) = gate(reader.next_element().field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    if !reader.is_empty() {
        return Ok(false);
    }
    qualifier_schema(&reader, kind, &value)
}

fn qualifier_charge(
    reader: &structured_asn1::ScopedReader<'_, '_>,
    value: &structured_asn1::Element<'_>,
    work: u64,
) -> Result<()> {
    reader.charge(work).map_err(|error| {
        Error::new(
            ErrorCode::Encoding(error.code()),
            QUALIFIER_FIELD,
            value.span().start,
        )
    })
}

fn qualifier_schema(
    reader: &structured_asn1::ScopedReader<'_, '_>,
    kind: QualifierKind,
    value: &structured_asn1::Element<'_>,
) -> Result<bool> {
    Ok(match kind {
        QualifierKind::Cps => {
            // A pointer to the practice statement: one IA5String holding a URI
            // (RFC 5280 4.2.1.4, CPSuri). Text that is not a URI points at
            // nothing while wearing the qualifier. Read, never fetched. The
            // scans below touch every content byte and CPSuri has no local size
            // ceiling, so the length is charged to the shared work budget first.
            if value.tag() != Tag::primitive(universal::IA5_STRING) {
                return Ok(false);
            }
            // ASCII/UTF8 checks and all URI component/authority scans are linear;
            // admit their complete possible passes before examining the contents.
            let work = (value.contents().len() as u64)
                .checked_mul(12)
                .and_then(|cost| cost.checked_add(1))
                .ok_or_else(|| {
                    Error::resource(
                        structured_asn1::memory::MemoryError::WorkExceeded,
                        QUALIFIER_FIELD,
                        value.span().start,
                    )
                })?;
            qualifier_charge(reader, value, work)?;
            crate::name::is_ia5(value.contents())
                && core::str::from_utf8(value.contents()).is_ok_and(crate::general_name::is_cps_uri)
        }
        QualifierKind::Notice => user_notice_understood::<true>(reader, value)?,
    })
}

/// Whether a user notice has its shape: an optional notice reference, then
/// optional explicit text. Both members are optional (RFC 5280 4.2.1.4):
/// the empty sequence says nothing, but it is inside the schema, and
/// refusing it would block an otherwise valid critical policy.
fn user_notice_understood<const IA5: bool>(
    parent: &structured_asn1::ScopedReader<'_, '_>,
    value: &structured_asn1::Element<'_>,
) -> Result<bool> {
    if value.tag() != Tag::constructed(universal::SEQUENCE) {
        return Ok(false);
    }
    let Some(mut inside) = gate(parent.enter(value).field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    let Some(mut next) = gate(inside.next_element().field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    if let Some(reference) = next
        && reference.tag() == Tag::constructed(universal::SEQUENCE)
    {
        if !notice_reference_understood::<IA5>(&inside, &reference)? {
            return Ok(false);
        }
        let Some(following) = gate(inside.next_element().field(QUALIFIER_FIELD))? else {
            return Ok(false);
        };
        next = following;
    }
    if let Some(text) = next
        && !is_display_text::<IA5>(&inside, &text)?
    {
        return Ok(false);
    }
    Ok(inside.is_empty())
}

/// The reference half of a user notice: the organization's display text,
/// then a sequence of notice numbers (which may be empty).
fn notice_reference_understood<const IA5: bool>(
    parent: &structured_asn1::ScopedReader<'_, '_>,
    reference: &structured_asn1::Element<'_>,
) -> Result<bool> {
    let Some(mut inside) = gate(parent.enter(reference).field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    let Some(Some(organization)) = gate(inside.next_element().field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    if !is_display_text::<IA5>(&inside, &organization)? {
        return Ok(false);
    }
    let Some(Some(numbers)) = gate(inside.next_element().field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    if numbers.tag() != Tag::constructed(universal::SEQUENCE) || !inside.is_empty() {
        return Ok(false);
    }
    let Some(mut each) = gate(inside.enter(&numbers).field(QUALIFIER_FIELD))? else {
        return Ok(false);
    };
    loop {
        match gate(each.next_element().field(QUALIFIER_FIELD))? {
            Some(Some(number)) => {
                // The schema says SEQUENCE OF INTEGER (RFC 5280 4.2.1.4);
                // the decoding helper is tag-agnostic for implicitly tagged
                // fields, so the tag is required here.
                if number.tag() != Tag::primitive(universal::INTEGER)
                    || gate(each.integer(&number).field(QUALIFIER_FIELD))?.is_none()
                {
                    return Ok(false);
                }
            }
            // noticeNumbers is SEQUENCE OF INTEGER with no minimum size
            // (RFC 5280 4.2.1.4): reaching the end is understood even when
            // nothing was inside, the way an empty UserNotice is.
            Some(None) => return Ok(true),
            None => return Ok(false),
        }
    }
}

/// Whether an element is one of the display text types of RFC 5280 4.2.1.4,
/// decoding under its declared type to between one and two hundred
/// characters, the SIZE (1..200) the schema puts on every choice. Bytes that
/// do not decode wear the tag without being the type.
fn is_display_text<const IA5: bool>(
    reader: &structured_asn1::ScopedReader<'_, '_>,
    element: &structured_asn1::Element<'_>,
) -> Result<bool> {
    let tag = element.tag();
    let contents = element.contents();
    // The ceiling is checked on the encoded bytes before any text is
    // materialized: no choice here spends more than four bytes per
    // character, so contents past four times the character bound can never
    // fit it and are refused without walking the value.
    if contents.len() > 200 * 4 {
        return Ok(false);
    }
    // The per-value ceiling does not bound the aggregate: a policy may carry
    // as many notices as the document has room for, so each scan is charged
    // to the shared work budget before it runs.
    // UTF8 validation and scalar counting are separate passes. The other
    // choices fit this same bound without constructing decoded text.
    qualifier_charge(reader, element, (contents.len() as u64) * 2 + 1)?;
    let characters = if IA5 && tag == Tag::primitive(universal::IA5_STRING) {
        // The 128-character IRV (X.680, 41.4).
        contents.iter().all(u8::is_ascii).then_some(contents.len())
    } else if tag == Tag::primitive(universal::UTF8_STRING) {
        core::str::from_utf8(contents)
            .ok()
            .map(|text| text.chars().count())
    } else if tag == Tag::primitive(26) {
        // VisibleString, whose number this schema layer names itself since
        // nothing below it needs it: the printing characters and space.
        contents
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e))
            .then_some(contents.len())
    } else if tag == Tag::primitive(30) {
        // BMPString, two bytes a character, so the size constraint counts
        // characters rather than bytes. Counted rather than decoded: the
        // gate asks how many characters there are, and building the text to
        // answer that would allocate a copy of the value.
        crate::name::wide_char_count(contents, 2)
    } else {
        return Ok(false);
    };
    Ok(characters.is_some_and(|count| (1..=200).contains(&count)))
}

/// Checks the `AdES` `SPUserNotice` schema with the existing notice kernel.
/// Its `DisplayText` omits PKIX's `IA5String` choice (EN319122-1 §5.2.9.2,
/// Annex D); `VisibleString`/`BMPString`/`UTF8String` retain SIZE(1..200).
/// Original coordinates and current local/aggregate execution are preserved.
/// No signature policy is selected or accepted by understanding its notice.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub fn signature_notice_understood<'a>(
    parent: &structured_asn1::ScopedReader<'a, '_>,
    value: &structured_asn1::Element<'a>,
) -> Result<bool> {
    qualifier_charge(parent, value, 1)?;
    user_notice_understood::<false>(parent, value)
}

#[cfg(test)]
mod tests;
