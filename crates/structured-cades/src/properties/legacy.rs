//! Annex A value schemas, composed from the producing ASN.1/ESS/PKIX kernels.
//! Embedded evidence is read, never authenticated here. Reference timestamp
//! syntax uses the common timestamp inspection pass so mapped failures survive.

use super::{Fault, end, next, sequence, syntax};
use crate::{Error, Result};
use structured_asn1::{
    Element, Oid, Reader, Span, Tag,
    memory::{OwnedVec, Work},
    universal,
};
use structured_cms::{Octets, attribute::Attribute};
use structured_pkix::{
    Certificate, algorithm,
    crl::CertificateList,
    ocsp::{BasicResponse, ResponderId},
};

// EN319122-1 AnnexA/Table1: certificate/revocation references and values,
// reference timestamps, and credential references. These are wire identifiers.
pub(crate) const LEGACY: [Oid<'static>; 8] = [
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 23]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 24]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 25]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 26]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 44]),
    Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 45]),
];
const FIELD: &str = "cades.legacy";

pub(super) fn inspect<'d, W: Work>(
    attribute: &Attribute<'d>,
    parent: &Reader<'d>,
    faults: &mut OwnedVec<Fault, W>,
    hints: &mut OwnedVec<Span, W>,
    values: &mut Option<super::values::Values<'d, W>>,
    work: &W,
) -> Result<()> {
    for (ordinal, kind) in LEGACY.into_iter().enumerate() {
        parent
            .charge(1 + attribute.kind().as_bytes().len().min(kind.as_bytes().len()) as u64)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if attribute.kind() != kind {
            continue;
        }
        // Cardinality is reported by the common catalogue. Reference timestamps
        // are inspected with TSTInfo/SourceMap by prepare::tokens, not reparsed
        // or downgraded to a bare SEQUENCE here.
        if attribute.values().len() != 1 || matches!(ordinal, 4 | 5) {
            return Ok(());
        }
        let reading = read_attribute(attribute, ordinal, parent, hints, values, work);
        if let Err(cause) = reading {
            if cause.is_terminal() {
                return Err(cause);
            }
            let at = cause.offset();
            faults
                .try_push(Fault {
                    attribute: kind,
                    field: FIELD,
                    cause,
                })
                .map_err(|cause| Error::resource(cause, FIELD, at))?;
        }
        return Ok(());
    }
    Ok(())
}

fn read_attribute<'d, W: Work>(
    attribute: &Attribute<'d>,
    ordinal: usize,
    parent: &Reader<'d>,
    hints: &mut OwnedVec<Span, W>,
    values: &mut Option<super::values::Values<'d, W>>,
    work: &W,
) -> Result<()> {
    let mut reader = attribute
        .value_reader_in(0, parent, FIELD)?
        .ok_or_else(|| syntax(FIELD, attribute.span().start))?;
    let value = next(&mut reader, FIELD)?;
    end(&reader, FIELD)?;
    // AnnexA.1.1–A.1.4 and normative AnnexD define all four shapes below.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    match ordinal {
        0 => certificate_refs(&reader, &value, Some(hints)),
        6 => certificate_refs::<W>(&reader, &value, None),
        1 | 7 => revocation_refs(&reader, &value),
        2 => certificate_values(
            &reader,
            &value,
            attribute.span(),
            values.get_or_insert_with(|| super::values::Values::new(work)),
        ),
        3 => revocation_values(
            &reader,
            &value,
            attribute.span(),
            values.get_or_insert_with(|| super::values::Values::new(work)),
        ),
        _ => Err(Error::Foreign {
            at: value.span().start,
        }),
    }
}

fn certificate_refs<W: Work>(
    parent: &Reader<'_>,
    value: &Element<'_>,
    mut hints: Option<&mut OwnedVec<Span, W>>,
) -> Result<()> {
    let mut list = sequence(parent, value, FIELD)?;
    while let Some(value) = list
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        let mut fields = sequence(&list, &value, FIELD)?;
        let hash = next(&mut fields, FIELD)?;
        other_hash(&fields, &hash)?;
        if let Some(issuer) = fields
            .next_element()
            .map_err(|cause| Error::encoding(cause, FIELD))?
        {
            // Table1(g) names complete-certificate-references specifically.
            // Retain the original hint before decoding it: malformed issuer
            // fields still exist and also receive their independent fault.
            if let Some(hints) = hints.as_mut() {
                hints
                    .try_push(issuer.span())
                    .map_err(|cause| Error::resource(cause, FIELD, issuer.span().start))?;
            }
            let reading = structured_cms::ess::IssuerSerialReading::read(&fields, &issuer, FIELD)?;
            let (_, faults) = reading.into_parts();
            fields
                .charge(1)
                .map_err(|cause| Error::encoding(cause, FIELD))?;
            if let Some(cause) = faults.into_iter().next() {
                return Err(Error::Cms(cause));
            }
        }
        end(&fields, FIELD)?;
    }
    Ok(())
}

fn other_hash(parent: &Reader<'_>, value: &Element<'_>) -> Result<()> {
    if value.tag() == Tag::primitive(universal::OCTET_STRING)
        || value.tag() == Tag::constructed(universal::OCTET_STRING)
    {
        Octets::read(parent, value, FIELD)?;
    } else {
        let mut fields = sequence(parent, value, FIELD)?;
        let identifier = next(&mut fields, FIELD)?;
        let algorithm = algorithm::read(&fields, &identifier, FIELD).map_err(Error::Pkix)?;
        let md5 = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
        fields
            .charge(
                1 + algorithm
                    .algorithm()
                    .as_bytes()
                    .len()
                    .min(md5.as_bytes().len()) as u64,
            )
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        // EN319122-1 §6.2.1 forbids MD5 in actual digest use, including
        // advisory legacy references. OID recognition is not provider policy.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
        if algorithm.algorithm() == md5 {
            return Err(Error::Syntax {
                code: structured_cms::ErrorCode::AlgorithmSyntax,
                field: "cades.legacy.digest",
                at: identifier.span().start,
            });
        }
        let hash = next(&mut fields, FIELD)?;
        Octets::read(&fields, &hash, FIELD)?;
        end(&fields, FIELD)?;
    }
    Ok(())
}

fn certificate_values<'d, W: Work>(
    parent: &Reader<'d>,
    value: &Element<'d>,
    property: Span,
    saved: &mut super::values::Values<'d, W>,
) -> Result<()> {
    let mut list = sequence(parent, value, FIELD)?;
    let enclosure = crate::source::Node::of(value.span());
    let mut ordinal = 0;
    while let Some(value) = list
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        let certificate = Certificate::read_element(&list, &value).map_err(Error::Pkix)?;
        saved
            .certificates
            .try_push(super::values::Located {
                property: crate::source::Node::of(property),
                enclosure,
                ordinal,
                value: certificate,
            })
            .map_err(|cause| Error::resource(cause, FIELD, value.span().start))?;
        ordinal += 1;
    }
    Ok(())
}

fn explicit<'a>(parent: &Reader<'a>, value: &Element<'a>, number: u32) -> Result<Reader<'a>> {
    if value.tag() != Tag::context(true, number) {
        return Err(syntax(FIELD, value.span().start));
    }
    let mut wrapper = parent
        .enter(value)
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    let value = next(&mut wrapper, FIELD)?;
    end(&wrapper, FIELD)?;
    sequence(&wrapper, &value, FIELD)
}

fn next_choice(previous: &mut Option<u32>, value: &Element<'_>) -> Result<u32> {
    let Some(number) = value.tag().number() else {
        return Err(syntax(FIELD, value.span().start));
    };
    if number > 2
        || value.tag() != Tag::context(true, number)
        || previous.is_some_and(|previous| number <= previous)
    {
        return Err(syntax(FIELD, value.span().start));
    }
    *previous = Some(number);
    Ok(number)
}

fn revocation_values<'d, W: Work>(
    parent: &Reader<'d>,
    value: &Element<'d>,
    property: Span,
    saved: &mut super::values::Values<'d, W>,
) -> Result<()> {
    let mut fields = sequence(parent, value, FIELD)?;
    let enclosure = crate::source::Node::of(value.span());
    let mut previous = None;
    while let Some(value) = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        let number = next_choice(&mut previous, &value)?;
        let mut entries = explicit(&fields, &value, number)?;
        if number == 2 {
            let (kind, values) = open_revocation(&mut entries)?;
            saved
                .other
                .try_push(super::values::OtherRevocation {
                    property: crate::source::Node::of(property),
                    kind,
                    enclosure: value,
                    values,
                })
                .map_err(|cause| Error::resource(cause, FIELD, value.span().start))?;
        } else {
            let mut ordinal = 0;
            while let Some(entry) = entries
                .next_element()
                .map_err(|cause| Error::encoding(cause, FIELD))?
            {
                if number == 0 {
                    let value =
                        CertificateList::read_element(&entries, &entry).map_err(Error::Pkix)?;
                    saved
                        .crls
                        .try_push(super::values::Located {
                            property: crate::source::Node::of(property),
                            enclosure,
                            ordinal,
                            value,
                        })
                        .map_err(|cause| Error::resource(cause, FIELD, entry.span().start))?;
                } else {
                    let value =
                        BasicResponse::read_element(&entries, &entry).map_err(Error::Pkix)?;
                    saved
                        .ocsp
                        .try_push(super::values::Located {
                            property: crate::source::Node::of(property),
                            enclosure,
                            ordinal,
                            value,
                        })
                        .map_err(|cause| Error::resource(cause, FIELD, entry.span().start))?;
                }
                ordinal += 1;
            }
        }
    }
    Ok(())
}

fn revocation_refs(parent: &Reader<'_>, value: &Element<'_>) -> Result<()> {
    let mut list = sequence(parent, value, FIELD)?;
    while let Some(value) = list
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        let mut fields = sequence(&list, &value, FIELD)?;
        let mut previous = None;
        while let Some(value) = fields
            .next_element()
            .map_err(|cause| Error::encoding(cause, FIELD))?
        {
            let number = next_choice(&mut previous, &value)?;
            let mut entries = explicit(&fields, &value, number)?;
            if number == 2 {
                open_revocation(&mut entries)?;
            } else {
                let list = next(&mut entries, FIELD)?;
                end(&entries, FIELD)?;
                let mut list = sequence(&entries, &list, FIELD)?;
                while let Some(entry) = list
                    .next_element()
                    .map_err(|cause| Error::encoding(cause, FIELD))?
                {
                    if number == 0 {
                        crl_reference(&list, &entry)?;
                    } else {
                        ocsp_reference(&list, &entry)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn crl_reference(parent: &Reader<'_>, value: &Element<'_>) -> Result<()> {
    let mut fields = sequence(parent, value, FIELD)?;
    let hash = next(&mut fields, FIELD)?;
    other_hash(&fields, &hash)?;
    if let Some(identifier) = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        let mut identifier = sequence(&fields, &identifier, FIELD)?;
        let issuer = next(&mut identifier, FIELD)?;
        structured_pkix::name::read(&identifier, &issuer, FIELD).map_err(Error::Pkix)?;
        let time = next(&mut identifier, FIELD)?;
        time_value(&identifier, &time, universal::UTC_TIME)?;
        if !identifier.is_empty() {
            identifier
                .read_integer()
                .map_err(|cause| Error::encoding(cause, FIELD))?;
        }
        end(&identifier, FIELD)?;
    }
    end(&fields, FIELD)
}

fn ocsp_reference(parent: &Reader<'_>, value: &Element<'_>) -> Result<()> {
    let mut fields = sequence(parent, value, FIELD)?;
    let identifier = next(&mut fields, FIELD)?;
    let mut identifier = sequence(&fields, &identifier, FIELD)?;
    let responder = next(&mut identifier, FIELD)?;
    ResponderId::read_element(&identifier, &responder).map_err(Error::Pkix)?;
    let time = next(&mut identifier, FIELD)?;
    time_value(&identifier, &time, universal::GENERALIZED_TIME)?;
    end(&identifier, FIELD)?;
    if let Some(hash) = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        other_hash(&fields, &hash)?;
    }
    end(&fields, FIELD)
}

fn time_value(parent: &Reader<'_>, value: &Element<'_>, number: u32) -> Result<()> {
    if value.tag() != Tag::primitive(number) && value.tag() != Tag::constructed(number) {
        return Err(syntax(FIELD, value.span().start));
    }
    // A reference uses its declared ASN.1 time under the producing BER/DER
    // rules. Embedded certificate/CRL/OCSP models retain their own DER profile.
    // Despite its module name, conforms follows parent.encoding(); it does
    // NOT reread under DER. BER useful times inherit VisibleString's
    // constructed OCTET STRING fragments (X.690 §§8.23, 8.25), which DER
    // alone forbids (§10.2). Forcing DER here would reject valid AnnexA data.
    // https://www.itu.int/rec/T-REC-X.690-202102-I/en
    structured_pkix::der::conforms(parent, value, FIELD).map_err(Error::Pkix)
}

fn open_revocation<'d>(fields: &mut Reader<'d>) -> Result<(Oid<'d>, crate::source::Value<'d>)> {
    let kind = fields
        .read_oid()
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    let values = next(fields, FIELD)?;
    end(fields, FIELD)?;
    let original = crate::source::Value::of(fields, values, FIELD);
    let mut values = sequence(fields, &values, FIELD)?;
    while let Some(value) = values
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        // AnnexD defines a SEQUENCE OF open values. Their OID-owned semantics
        // remain outside this format; original ASN.1 syntax is still accounted.
        structured_pkix::der::conforms(&values, &value, FIELD).map_err(Error::Pkix)?;
    }
    Ok((kind, original))
}
