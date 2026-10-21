//! Original MIME type descriptions, including the complete header form.

use super::Syntax;
use structured_asn1::memory::{MemoryError, Work};

/// Accepts a media type or header fields containing one explicit Content-Type.
///
/// This checks RFC822 field framing/folding and delegates Content-Type to the
/// same RFC2045 grammar as [`Syntax`]. Other field bodies remain opaque ASCII:
/// this neither decodes transfer encodings nor interprets extension fields.
/// Original CRLF is required; the last field may end at the enclosing value's
/// boundary. An optional final empty separator is accepted, never message data.
/// No allocation, normalization, or copy is performed.
///
/// # Errors
/// Current work refuses before the corresponding input scan. Invalid syntax
/// returns `false`; resource refusal never selects another interpretation.
pub fn media_type_or_headers<W: Work>(value: &[u8], work: &W) -> Result<bool, MemoryError> {
    // EN319122-1 §5.2.4.2 and Annex E.3 permit BOTH a bare media type and the
    // complete MIME header. Header structure is RFC822 §§3.1.1/3.2, inherited
    // by RFC2045 §3; only Content-Type determines this description's type.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    // https://www.rfc-editor.org/rfc/rfc822#section-3.2
    let mut media = Syntax::<false>::new();
    if media.feed(value, work)? && media.complete() {
        return Ok(true);
    }
    let cost = u64::try_from(value.len())
        .ok()
        .and_then(|length| length.checked_mul(4))
        .ok_or(MemoryError::WorkExceeded)?;
    // Framing plus case-insensitive field-name comparison is linear. The
    // nested type grammar admits its own work separately before scanning.
    work.charge_work(cost)?;
    let mut at = 0;
    let mut content_type = false;
    while at < value.len() {
        if value[at] == b'\r' && value.get(at + 1) == Some(&b'\n') {
            return Ok(content_type && at + 2 == value.len());
        }
        let start = at;
        while at < value.len() && value[at] != b':' {
            if !matches!(value[at], 33..=126) {
                return Ok(false);
            }
            at += 1;
        }
        if at == start || at == value.len() {
            return Ok(false);
        }
        let name = &value[start..at];
        at += 1;
        let body = at;
        while at < value.len() {
            if value[at] == b'\r' {
                if value.get(at + 1) != Some(&b'\n') {
                    return Ok(false);
                }
                if !matches!(value.get(at + 2), Some(b' ' | b'\t')) {
                    break;
                }
                at += 2;
            } else if value[at] == b'\n' || !value[at].is_ascii() {
                return Ok(false);
            }
            at += 1;
        }
        if name.eq_ignore_ascii_case(b"Content-Type") {
            if content_type {
                return Ok(false);
            }
            let mut media = Syntax::<false>::new();
            if !media.feed(&value[body..at], work)? || !media.complete() {
                return Ok(false);
            }
            content_type = true;
        }
        if at < value.len() {
            at += 2;
        }
    }
    Ok(content_type)
}
