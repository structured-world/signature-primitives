//! LDAP CRL pointers, preserved without server selection or search execution.

use crate::error::{Error, Located, Result};
use crate::name::attribute_type_syntax_fits as oid;
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{Element, Reader};

// RFC5280 §4.2.1.13 requires a DN and one appropriate CRL attribute. LDAP
// URL components use RFC4516 §2; filter grammar is RFC4515 §3; CRL attribute
// types and binary transfer are RFC4523 §§4.4–4.6.
// <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
// <https://www.rfc-editor.org/rfc/rfc4516#section-2>
// <https://www.rfc-editor.org/rfc/rfc4515#section-3>
// <https://www.rfc-editor.org/rfc/rfc4523#section-4.4>
pub(super) fn valid(
    parent: &Reader<'_>,
    element: &Element<'_>,
    text: &str,
    field: &'static str,
) -> Result<bool> {
    let Some(after) = text
        .split_once(':')
        .and_then(|(_, rest)| rest.strip_prefix("//"))
    else {
        return Ok(false);
    };
    let Some((authority, rest)) = after.split_once('/') else {
        return Ok(false);
    };
    if authority.contains('@') || authority.starts_with(':') || rest.contains('#') {
        return Ok(false);
    }
    let mut fields = [""; 5];
    let mut count = 0;
    for part in rest.split('?') {
        if count == fields.len() {
            return Ok(false);
        }
        fields[count] = part;
        count += 1;
    }
    // An empty DN selects server-specific root DSE metadata (RFC4512 §5.1),
    // not the named CRL-holding entry required by RFC5280 §4.2.1.13. Refuse
    // that missing selection here, before copying; generic RFC4514 still
    // permits an empty DN in its other contexts.
    // <https://www.rfc-editor.org/rfc/rfc4512#section-5.1>
    if count < 2 || fields[0].is_empty() || fields[1].is_empty() {
        return Ok(false);
    }
    let execution = parent.memory();
    let at = element.span().start;
    {
        let dn = decode(fields[0], execution, field, at)?;
        let Ok(dn) = core::str::from_utf8(&dn) else {
            return Ok(false);
        };
        let work = u64::try_from(dn.len())
            .ok()
            .and_then(|n| n.checked_mul(64))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                Error::resource(
                    structured_asn1::memory::MemoryError::WorkExceeded,
                    field,
                    at,
                )
            })?;
        parent.charge(work).field(field)?;
        if !crate::name::dn_syntax_fits(dn) {
            return Ok(false);
        }
    }
    {
        let attribute = decode(fields[1], execution, field, at)?;
        let Ok(attribute) = core::str::from_utf8(&attribute) else {
            return Ok(false);
        };
        if !crl_attribute(attribute) {
            return Ok(false);
        }
    }
    {
        let scope = decode(fields[2], execution, field, at)?;
        if !scope.is_empty()
            && ![b"base".as_slice(), b"one", b"sub"]
                .iter()
                .any(|name| scope.eq_ignore_ascii_case(name))
        {
            return Ok(false);
        }
    }
    {
        let filter = decode(fields[3], execution, field, at)?;
        let Ok(filter) = core::str::from_utf8(&filter) else {
            return Ok(false);
        };
        if !filter.is_empty() && !filter_valid(filter, execution, field, at)? {
            return Ok(false);
        }
    }
    if !fields[4].is_empty() {
        for part in fields[4].split(',') {
            let bytes = decode(part, execution, field, at)?;
            let Ok(text) = core::str::from_utf8(&bytes) else {
                return Ok(false);
            };
            let text = text.strip_prefix('!').unwrap_or(text);
            let kind = text.split_once('=').map_or(text, |(kind, _)| kind);
            if !oid(kind) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

enum Decoded<'a> {
    Borrowed(&'a [u8]),
    Owned(OwnedVec<u8>),
}

impl core::ops::Deref for Decoded<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

fn decode<'a>(
    text: &'a str,
    execution: &Memory,
    field: &'static str,
    at: u64,
) -> Result<Decoded<'a>> {
    // Generic URI validation already checked percent pairs. Reserve once before
    // copying; decoded commas/questions cannot change URL component boundaries.
    // Components without escapes retain the original borrowed view, including
    // absent optional fields; they neither copy nor acquire an account handle.
    let escapes = text.bytes().filter(|byte| *byte == b'%').count();
    if escapes == 0 {
        return Ok(Decoded::Borrowed(text.as_bytes()));
    }
    let fail = |reason| Error::resource(reason, field, at);
    let mut output = execution.vector();
    // Each validated escape consumes three source bytes and emits one byte.
    debug_assert!(escapes <= text.len() / 3);
    let decoded_len = text.len() - 2 * escapes;
    output.try_reserve_exact(decoded_len).map_err(fail)?;
    let mut bytes = text.as_bytes();
    while let Some((&byte, rest)) = bytes.split_first() {
        if byte == b'%' {
            output
                .try_push(hex(rest[0]) * 16 + hex(rest[1]))
                .map_err(fail)?;
            bytes = &rest[2..];
        } else {
            output.try_push(byte).map_err(fail)?;
            bytes = rest;
        }
    }
    Ok(Decoded::Owned(output))
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated URI percent escape"),
    }
}

fn attribute(text: &str) -> bool {
    let mut parts = text.split(';');
    if !oid(parts.next().expect("one component")) {
        return false;
    }
    parts.all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn crl_attribute(text: &str) -> bool {
    if !attribute(text) {
        return false;
    }
    let mut parts = text.split(';');
    let kind = parts.next().expect("validated attribute");
    let recognized = [
        "certificateRevocationList",
        "authorityRevocationList",
        "deltaRevocationList",
        "2.5.4.39",
        "2.5.4.38",
        "2.5.4.53",
    ]
    .iter()
    .any(|candidate| kind.eq_ignore_ascii_case(candidate));
    recognized && parts.any(|part| part.eq_ignore_ascii_case("binary"))
}

struct Frame {
    kind: u8,
    children: usize,
}

fn filter_valid(text: &str, execution: &Memory, field: &'static str, offset: u64) -> Result<bool> {
    // Iterative prefix grammar: each byte is visited a constant number of times,
    // and every nesting frame is admitted and retains its own capacity charge.
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'(') {
        return Ok(false);
    }
    if !matches!(bytes.get(1), Some(b'&' | b'|' | b'!')) {
        // A leaf uses the same assertion grammar without acquiring a frame
        // account. Raw inner parentheses are rejected by that grammar.
        return Ok(text[1..].strip_suffix(')').is_some_and(item));
    }
    let mut frames: OwnedVec<Frame> = execution.vector();
    let mut at = 0;
    loop {
        if bytes.get(at) != Some(&b'(') {
            return Ok(false);
        }
        at += 1;
        if let Some(&kind @ (b'&' | b'|' | b'!')) = bytes.get(at) {
            frames
                .try_push(Frame { kind, children: 0 })
                .map_err(|reason| Error::resource(reason, field, offset))?;
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && bytes[at] != b')' {
            if bytes[at] == b'(' {
                return Ok(false);
            }
            at += 1;
        }
        if at == bytes.len() || !item(&text[start..at]) {
            return Ok(false);
        }
        at += 1;
        loop {
            let Some(frame) = frames.last_mut() else {
                return Ok(at == bytes.len());
            };
            debug_assert!(frame.children < bytes.len());
            frame.children += 1;
            match bytes.get(at) {
                Some(b'(') if frame.kind != b'!' => break,
                Some(b')') if frame.children > 0 && (frame.kind != b'!' || frame.children == 1) => {
                    frames.pop();
                    at += 1;
                }
                _ => return Ok(false),
            }
        }
    }
}

fn item(text: &str) -> bool {
    let Some((left, value)) = text.split_once('=') else {
        return false;
    };
    let substring = if let Some(prefix) = left.strip_suffix(':') {
        if !extensible(prefix) {
            return false;
        }
        false
    } else if let Some(prefix) = left.strip_suffix(['~', '>', '<']) {
        if !attribute(prefix) {
            return false;
        }
        false
    } else {
        if !attribute(left) {
            return false;
        }
        true
    };
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
            {
                return false;
            }
        } else if matches!(byte, 0 | b'(' | b')') || (!substring && byte == b'*') {
            return false;
        }
    }
    true
}

fn extensible(text: &str) -> bool {
    let mut parts = text.split(':');
    let attr = parts.next().expect("one component");
    if !attr.is_empty() && !attribute(attr) {
        return false;
    }
    let mut next = parts.next();
    if next.is_some_and(|part| part.eq_ignore_ascii_case("dn")) {
        next = parts.next();
    }
    let has_rule = match next {
        Some(rule) => oid(rule),
        None => false,
    };
    parts.next().is_none() && (has_rule || (next.is_none() && !attr.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_filter_grammar_handles_boolean_and_extensible_forms() {
        // RFC4515 prefix operators and matching-rule assertions share the
        // iterative grammar; invalid arity, escapes and operators stay invalid.
        let execution = crate::fixtures::memory();
        for (filter, valid) in [
            ("(&(cn=A)(|(sn=B)(mail=C)))", true),
            ("(!(cn=A))", true),
            ("(!(cn=A)(cn=B))", false),
            ("(&)", false),
            ("(|)", false),
            ("(cn~=A*)", false),
            ("(cn:=x)", true),
            ("(:dn:1.2.3:=x)", true),
            ("(:dn:=x)", false),
            ("(cn:dn:=x)", true),
            ("(cn:1.2.3:=x)", true),
            ("(cn::=x)", false),
            ("(cn=A\\28B)", true),
            ("(cn=A\\q)", false),
            ("(cn=)(sn=B)", false),
        ] {
            execution
                .charge_work(32 * filter.len() as u64 + 256)
                .unwrap();
            assert_eq!(
                filter_valid(filter, &execution, "dp", 801).unwrap(),
                valid,
                "{filter}"
            );
            assert_eq!(execution.used(), 0);
        }
    }

    #[test]
    fn deep_filter_frames_are_iterative_and_pre_admitted() {
        // Nesting never consumes the native call stack, and refusing a frame
        // allocation preserves the resource class/source and releases scratch.
        let filter = alloc::format!("{}(cn=A){}", "(!".repeat(400), ")".repeat(400));
        let execution = crate::fixtures::memory();
        execution
            .charge_work(32 * filter.len() as u64 + 256)
            .unwrap();
        assert!(filter_valid(&filter, &execution, "dp", 801).unwrap());
        assert_eq!(execution.used(), 0);
        let execution = Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 1_000_000),
        ));
        execution
            .charge_work(32 * filter.len() as u64 + 256)
            .unwrap();
        let error = filter_valid(&filter, &execution, "dp", 801).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "dp");
        assert_eq!(error.offset(), 801);
        assert_eq!(execution.used(), 0);
    }
}
