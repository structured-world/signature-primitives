//! Exact XSD1.0 identifier time labels against original whole-second PKIX time.

use super::{ReferenceIdentifier, ReferenceProperty};
use crate::{
    properties::{CalendarFact, CalendarValue, CalendarXml},
    reference::VisitError,
    xml::{Access, AccessError},
};
use structured_asn1::{
    ScopedReader,
    memory::{MemoryError, Work},
};
use structured_pkix::Time;

/// A complete comparison or an explicit missing interpretation; no UTC default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceTime {
    /// Original time, timezone and all fractional digits identify this label.
    Matches,
    /// Completed comparison identifies a different label.
    Differs,
    /// No timezone was written; the hint does not establish UTC equality.
    TimezoneUnstated,
    /// Original XML is not a readable XSD1.0 dateTime.
    Malformed,
    /// The XML owner's complete schema interpretation is unavailable.
    Unsupported,
}

/// Original processing refusals remain terminal, independent of label equality.
#[derive(Debug)]
pub enum ReferenceTimeError<E, N> {
    /// Original source/generation/current dispatch failure.
    Access(AccessError<E, N>),
    /// XML-owner lexical/joining/resource failure.
    Xml(E),
    /// No original reference exists at this caller-selected ordinal.
    Index {
        /// Requested catalogue ordinal, not a physical XML location.
        index: usize,
    },
    /// Common comparison admission was refused before scanning/projecting.
    Resource {
        /// Original `IssueTime` or `ProducedAt` enclosure.
        node: N,
        /// Original refusal.
        cause: MemoryError,
    },
}

/// Compare original CRL `IssueTime` or OCSP `ProducedAt` with its actual PKIX time.
/// Annex A.1.2 requires the referenced response's production time. XSD1.0
/// Datatypes §3.2.7 uses 1 BCE=-0001, end-of-day24 and arbitrary fractions;
/// §§3.2.7.3–4 define timezone conversion. These are label comparisons, not
/// authenticated occurrence, freshness or historical trust.
/// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime>
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn matches_reference_time<X: CalendarXml>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    actual: Time,
    operation: &ScopedReader<'_, '_>,
) -> Result<Option<ReferenceTime>, ReferenceTimeError<X::Error, X::Id>> {
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(ReferenceTimeError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(ReferenceTimeError::Index { index });
    };
    let (ReferenceIdentifier::Crl { time: node, .. }
    | ReferenceIdentifier::Ocsp { time: node, .. }) = entry.identifier()
    else {
        return Ok(None);
    };
    let compared = access
        .query(node, |xml, snapshot, work| {
            Ok(xml.with_calendar(snapshot, node, work, |value| {
                let answer = match value {
                    CalendarFact::Malformed => ReferenceTime::Malformed,
                    CalendarFact::Unsupported => ReferenceTime::Unsupported,
                    CalendarFact::Value(value) => compare(value, actual, work)
                        .map_err(|cause| ReferenceTimeError::Resource { node, cause })?,
                };
                Ok(Some(answer))
            }))
        })
        .map_err(ReferenceTimeError::Access)?;
    compared.map_err(|cause| match cause {
        VisitError::Processing(cause) => ReferenceTimeError::Xml(cause),
        VisitError::Visitor(cause) => cause,
    })
}

fn compare<W: Work>(
    value: CalendarValue<'_>,
    actual: Time,
    work: &W,
) -> Result<ReferenceTime, MemoryError> {
    let length = value
        .year_digits
        .len()
        .checked_add(value.fraction_digits.map_or(0, str::len))
        .and_then(|length| length.checked_add(32))
        .ok_or(MemoryError::WorkExceeded)?;
    work.charge_work(u64::try_from(length).map_err(|_| MemoryError::WorkExceeded)?)?;
    let Some(offset) = value.timezone_minutes else {
        return Ok(ReferenceTime::TimezoneUnstated);
    };
    if !(-840..=840).contains(&offset) {
        return Ok(ReferenceTime::Malformed);
    }
    // A parsed PKIX label and these bounded offsets can reach at most year10000.
    // Arbitrarily wider valid XSD years differ without machine-width narrowing.
    if value.year_digits.len() > 5 {
        return Ok(ReferenceTime::Differs);
    }
    let mut year = 0i64;
    for digit in value.year_digits.bytes() {
        if !digit.is_ascii_digit() {
            return Ok(ReferenceTime::Malformed);
        }
        year = year * 10 + i64::from(digit - b'0');
    }
    let mut nanos = 0u32;
    let mut digits = 0;
    if let Some(fraction) = value.fraction_digits {
        for digit in fraction.bytes() {
            if !digit.is_ascii_digit() {
                return Ok(ReferenceTime::Malformed);
            }
            if digits < 9 {
                nanos = nanos * 10 + u32::from(digit - b'0');
            } else if digit != b'0' {
                return Ok(ReferenceTime::Differs);
            }
            digits += 1;
        }
    }
    while digits < 9 {
        nanos *= 10;
        digits += 1;
    }
    let written = structured_pkix::time::Xsd10Label {
        year: if value.negative_year { -year } else { year },
        month: value.month,
        day: value.day,
        hour: value.hour,
        minute: value.minute,
        second: value.second,
        nanos,
    };
    // Compare both operands in the SAME XSD1.0 value space. Applying a UTC
    // Gregorian offset first would inherit astronomical BCE leap rules and
    // would lose XSD Appendix E's second60 normalization.
    let Some(written) = written.at_utc(offset, work)? else {
        return Ok(ReferenceTime::Malformed);
    };
    let Some(expected) = actual.xsd10_label(work)?.at_utc(0, work)? else {
        // Some astronomical BCE dates have no valid XSD1.0 field label. They
        // cannot match a valid written hint; this does not alter PKIX parsing.
        return Ok(ReferenceTime::Differs);
    };
    Ok(if written == expected {
        ReferenceTime::Matches
    } else {
        ReferenceTime::Differs
    })
}
