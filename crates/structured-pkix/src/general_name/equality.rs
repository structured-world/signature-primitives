//! Identity comparison shared by retained queries and producing readers.

use super::GeneralName;
use crate::error::{Error, ErrorCode, Result};
use structured_asn1::Reader;
use structured_asn1::memory::{MemoryError, Work};

pub(super) fn matches<W: Work>(
    left: &GeneralName<'_>,
    right: &GeneralName<'_>,
    execution: &W,
    parent: Option<&Reader<'_>>,
    at: u64,
    field: &'static str,
) -> Result<bool> {
    let fail = |reason| Error::resource(reason, field, at);
    execution.charge_work(1).map_err(fail)?;
    let (left, right) = match (left, right) {
        (GeneralName::Directory(left), GeneralName::Directory(right)) => {
            return left
                .matches_with(right, execution, parent)
                .map_err(|error| Error::new(error.code(), field, at));
        }
        (GeneralName::Uri(left), GeneralName::Uri(right)) => {
            return super::uri::matches_in(left, right, execution, at, field);
        }
        (GeneralName::Dns(left), GeneralName::Dns(right)) => {
            text_work(left, right, execution).map_err(fail)?;
            // RFC9549 §2.3 replaces RFC5280 §7.2's IDNA baseline while
            // retaining whole-name ASCII case-insensitive exact equality.
            // https://www.rfc-editor.org/rfc/rfc9549#section-2.3
            return Ok(left.eq_ignore_ascii_case(right));
        }
        (GeneralName::Email(left), GeneralName::Email(right)) => {
            text_work(left, right, execution).map_err(fail)?;
            // RFC9549 §2.5 / RFC5280 §7.5.1: no local-part folding.
            // https://www.rfc-editor.org/rfc/rfc9549#section-2.5
            let (Some((left_local, left_host)), Some((right_local, right_host))) =
                (mail_parts(left), mail_parts(right))
            else {
                return Err(Error::new(ErrorCode::MalformedValue, field, at));
            };
            // RFC5321 §4.1.2 requires quoted spellings of the same local-part
            // to compare equivalently. Decode quoting, preserving every literal
            // octet and its case; never normalize or case-fold the local-part.
            // https://www.rfc-editor.org/rfc/rfc5321#section-4.1.2
            return Ok(local_octets(left_local).eq(local_octets(right_local))
                && left_host.eq_ignore_ascii_case(right_host));
        }
        (GeneralName::X400(left), GeneralName::X400(right))
        | (GeneralName::EdiParty(left), GeneralName::EdiParty(right))
        | (GeneralName::IpAddress(left), GeneralName::IpAddress(right)) => (*left, *right),
        (GeneralName::RegisteredId(left), GeneralName::RegisteredId(right)) => {
            (left.as_bytes(), right.as_bytes())
        }
        (
            GeneralName::Other {
                type_id: left_kind,
                value: left,
            },
            GeneralName::Other {
                type_id: right_kind,
                value: right,
            },
        ) => {
            execution
                .charge_work(left_kind.as_bytes().len().max(right_kind.as_bytes().len()) as u64)
                .map_err(fail)?;
            if left_kind != right_kind {
                return Ok(false);
            }
            (*left, *right)
        }
        _ => return Ok(false),
    };
    execution
        .charge_work(left.len().max(right.len()) as u64)
        .map_err(fail)?;
    Ok(left == right)
}

fn text_work<W: Work>(
    left: &str,
    right: &str,
    execution: &W,
) -> core::result::Result<(), MemoryError> {
    let work = (left.len().max(right.len()) as u64)
        .checked_mul(6)
        .and_then(|work| work.checked_add(1))
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(work)
}

fn mail_parts(text: &str) -> Option<(&str, &str)> {
    let (mut quoted, mut escaped) = (false, false);
    for (index, byte) in text.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b'@' {
            return Some((&text[..index], &text[index + 1..]));
        }
    }
    None
}

fn local_octets(local: &str) -> LocalOctets<'_> {
    let quoted = local.starts_with('"') && local.ends_with('"') && local.len() >= 2;
    let bytes = if quoted {
        &local.as_bytes()[1..local.len() - 1]
    } else {
        local.as_bytes()
    };
    LocalOctets {
        bytes: bytes.iter(),
        quoted,
    }
}

struct LocalOctets<'a> {
    bytes: core::slice::Iter<'a, u8>,
    quoted: bool,
}

impl Iterator for LocalOctets<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.next()?;
        if self.quoted && byte == b'\\' {
            self.bytes.next().copied()
        } else {
            Some(byte)
        }
    }
}
