use super::{Instant, Reading};
use crate::error::{Error, ErrorCode, Result};
use crate::time::{days_from_civil, days_in_month, fields_of, number, split};
use structured_asn1::memory::{MemoryError, Work};
use structured_asn1::{Element, Reader, Tag, universal};

/// Read a zoned `GeneralizedTime`, preserving leap labels and decimal precision.
///
/// X.680 (2021) §46.2 permits optional minutes/seconds and a fraction of the
/// last component. Local time without a zone has no unique UTC reading and
/// returns `MalformedTime`. This reader does not enforce DER spelling or
/// authenticate an occurrence of a leap second; those are separate checks.
/// <https://www.itu.int/rec/T-REC-X.680-202102-I/en>
/// Primitive and constructed BER forms are accepted. Constructed contents
/// use OCTET STRING fragments, including nested and indefinite forms.
///
/// `parent` must belong to the session and source that produced `element`.
/// This is a caller precondition, not a provenance check. It supplies the
/// current execution account and original parser-local cumulative ceiling.
/// Two work units per content octet plus one fixed decode unit are admitted
/// before scanning, covering forward digit validation and reverse conversion.
/// Constructed traversal, copying and temporary capacity are admitted separately;
/// scratch storage is released before this independent reading is returned.
///
/// # Errors
/// Returns malformed-time or calendar errors, or a located resource refusal
/// before an unfunded scan. Resource errors never become malformed timestamps.
pub fn read_generalized(
    parent: &Reader<'_>,
    element: &Element<'_>,
    field: &'static str,
) -> Result<Reading> {
    if element.tag() == Tag::constructed(universal::GENERALIZED_TIME) {
        // X.680 §46.3 defines GeneralizedTime as IMPLICIT VisibleString;
        // X.690 §§8.25, 8.23.3 and 8.23.6 inherit OCTET STRING construction.
        // The primitive requirement in §8.26 concerns the distinct TIME type.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        let execution = parent.execution();
        let mut contents = execution.vector();
        crate::name::segments::walk_in(
            parent,
            element,
            field,
            false,
            Some(&mut contents),
            &execution,
        )?;
        admit_label(parent, contents.len(), element.span().start, field)?;
        return generalized_label(&contents, element.span().start, field);
    }
    if element.tag() != Tag::primitive(universal::GENERALIZED_TIME) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    admit_generalized(parent, element, field)?;
    generalized(element, field)
}

/// Admit the shared semantic core separately from a caller's DER spelling scan.
pub(crate) fn admit_generalized(
    parent: &Reader<'_>,
    element: &Element<'_>,
    field: &'static str,
) -> Result<()> {
    admit_label(
        parent,
        element.contents().len(),
        element.span().start,
        field,
    )
}

fn admit_label(parent: &Reader<'_>, length: usize, offset: u64, field: &'static str) -> Result<()> {
    let work = u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_mul(2))
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, field, offset))?;
    parent
        .charge(work)
        .map_err(|error| Error::new(ErrorCode::Encoding(error.code()), field, offset))
}

/// Semantic core for callers that have already admitted their complete scan.
pub(crate) fn generalized(element: &Element<'_>, field: &'static str) -> Result<Reading> {
    if element.tag() != Tag::primitive(universal::GENERALIZED_TIME) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    generalized_label(element.contents(), element.span().start, field)
}

fn generalized_label(contents: &[u8], offset: u64, field: &'static str) -> Result<Reading> {
    let fail = |code| Error::new(code, field, offset);
    let (year, rest) = split(contents, 4).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
    let year = number(year).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
    let ([month, day, hour], mut rest) =
        fields_of(rest).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
    let (mut minute, mut second, mut unit) = (0, 0, 3_600_000_000_000i128);
    if let Some((digits, tail)) = split(rest, 2) {
        minute = number(digits).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
        (rest, unit) = (tail, 60_000_000_000);
        if let Some((digits, tail)) = split(rest, 2) {
            second = number(digits).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
            (rest, unit) = (tail, 1_000_000_000);
        }
    }
    let (mut fraction, mut exact) = (0i128, true);
    if let Some((b'.' | b',', tail)) = rest.split_first() {
        let count = tail.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if count == 0 {
            return Err(fail(ErrorCode::MalformedTime));
        }
        let (digits, after) = tail.split_at(count);
        // Reverse decimal multiplication gives the exact floor and residual
        // for any number of digits, without a big integer or discarded carry.
        // The carry stays below unit; each temporary is below 10 * unit.
        let mut carry = 0i128;
        for digit in digits.iter().rev() {
            let product = i128::from(digit - b'0') * unit + carry;
            exact &= product % 10 == 0;
            carry = product / 10;
        }
        fraction = carry;
        rest = after;
    }
    let offset = zone(rest).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(fail(ErrorCode::TimeOutOfRange));
    }
    let local = days_from_civil(i64::from(year), month, day) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second.min(59));
    let seconds = local - offset;
    let start = if second == 60 {
        // Offset normalization preserves the insertion's preceding second.
        // Whether it actually occurred is decided by the supplied LeapTable.
        Instant::leap_after(
            seconds,
            u32::try_from(fraction).map_err(|_| fail(ErrorCode::TimeOutOfRange))?,
        )
    } else {
        Instant::new(
            seconds
                + i64::try_from(fraction / super::NANOS)
                    .map_err(|_| fail(ErrorCode::TimeOutOfRange))?,
            u32::try_from(fraction % super::NANOS).map_err(|_| fail(ErrorCode::TimeOutOfRange))?,
        )
    }
    .ok_or_else(|| fail(ErrorCode::TimeOutOfRange))?;
    Ok(Reading {
        start,
        subnanosecond: !exact,
    })
}

fn zone(rest: &[u8]) -> Option<i64> {
    match rest {
        [b'Z'] => Some(0),
        [sign @ (b'+' | b'-'), zone @ ..] => {
            let ([hours, minutes], tail) = match zone.len() {
                2 => fields_of::<1>(zone).map(|([hours], tail)| ([hours, 0], tail)),
                4 => fields_of::<2>(zone),
                _ => None,
            }?;
            if !tail.is_empty() || hours > 23 || minutes > 59 {
                return None;
            }
            let seconds = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
            Some(if *sign == b'+' { seconds } else { -seconds })
        }
        _ => None,
    }
}
