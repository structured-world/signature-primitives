//! Complete RFC 4514 output; display truncation never enters this codec.

use super::{Attribute, Encoding, Error, Name, OwnedString, Result};
use structured_asn1::memory::Memory;

impl Name<'_> {
    /// Formats a reversible RFC 4514 name, preserving every original value
    /// as `#BER`. Types use registered descriptors or exact numeric OIDs; RDN order
    /// is reversed as required by RFC 4514 §2.1. No value is truncated.
    /// The returned string independently retains its storage charge.
    pub fn rfc4514(&self, execution: &Memory) -> Result<OwnedString> {
        render(self, execution, false)
    }

    /// Formats a complete readable RFC 4514 name. Known, fully decoded
    /// attribute syntax uses escaped text; unknown/nontext values use
    /// original `#BER`. Text follows the declared attribute syntax; matching
    /// remains a separate fallible operation. This form does not preserve
    /// the original ASN.1 string tag or promise a canonical identity string.
    /// This convenience form is for metadata; use `rfc4514` for reversibility.
    pub fn rfc4514_readable(&self, execution: &Memory) -> Result<OwnedString> {
        render(self, execution, true)
    }
}

fn render(name: &Name<'_>, execution: &Memory, readable: bool) -> Result<OwnedString> {
    let fail = |reason| Error::resource(reason, name.field, name.offset);
    let mut output = execution.string();
    execution
        .charge_work(name.parts.len() as u64)
        .map_err(fail)?;
    for (part_at, part) in name.parts.iter().rev().enumerate() {
        if part_at != 0 {
            output.try_push(',').map_err(fail)?;
        }
        execution
            .charge_work(part.attributes.len() as u64)
            .map_err(fail)?;
        for (at, attribute) in part.attributes.iter().enumerate() {
            if at != 0 {
                output.try_push('+').map_err(fail)?;
            }
            execution
                .charge_work(
                    (attribute.kind.as_bytes().len() as u64)
                        .checked_mul(9)
                        .ok_or_else(|| fail(structured_asn1::memory::MemoryError::WorkExceeded))?,
                )
                .map_err(fail)?;
            let descriptor = super::selector::registered_name(attribute.kind);
            if let Some(descriptor) = descriptor {
                output.try_push_str(descriptor).map_err(fail)?;
            } else {
                let oid = attribute.kind.text(execution).map_err(fail)?;
                output
                    .try_push_str(oid.as_str(execution).map_err(fail)?)
                    .map_err(fail)?;
            }
            output.try_push('=').map_err(fail)?;
            // RFC 4514 §§2.3–2.4 requires #BER with a numeric type. A
            // registered descriptor allows the LDAP text form; reversibility
            // may still select #BER even for that descriptor.
            // https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4
            if readable && descriptor.is_some() && text(*attribute, &mut output, execution)? {
                continue;
            }
            output.try_push('#').map_err(fail)?;
            execution
                .charge_work(attribute.value.der.len() as u64)
                .map_err(fail)?;
            for &byte in attribute.value.der {
                hex(byte, &mut output).map_err(fail)?;
            }
        }
    }
    Ok(output)
}

fn text(attribute: Attribute<'_>, output: &mut OwnedString, execution: &Memory) -> Result<bool> {
    let value = attribute.value;
    let fail = |reason| Error::resource(reason, "name.attribute", value.offset);
    let work = (attribute.kind.as_bytes().len() as u64)
        .checked_mul(64)
        .and_then(|kind| {
            (value.contents.len() as u64)
                .checked_mul(6)
                .and_then(|n| kind.checked_add(n))
        })
        .ok_or_else(|| fail(structured_asn1::memory::MemoryError::WorkExceeded))?;
    execution.charge_work(work).map_err(fail)?;
    // Only defined LDAP string syntax is rendered. Teletex outside its
    // invariant ASCII subset stays BER; there is no guessed Latin-1 decode.
    if !super::permits(attribute.kind, value.encoding())
        || !super::well_formed(&attribute)
        || value.validated_count(|_| true).is_none()
        || value.encoding() == Encoding::Other
    {
        return Ok(false);
    }
    // Once validated, this character iterator is total and untruncated.
    let mut characters = value.decoded_chars().peekable();
    let mut first = true;
    while let Some(character) = characters.next() {
        let last = characters.peek().is_none();
        if character == '\0' || character.is_control() {
            let mut bytes = [0; 4];
            for &byte in character.encode_utf8(&mut bytes).as_bytes() {
                output.try_push('\\').map_err(fail)?;
                hex(byte, output).map_err(fail)?;
            }
        } else {
            // RFC 4514 §2.4: escaped leading #/space, trailing space and
            // separators. '=' may be left literal, but escaping is permitted.
            if matches!(character, '"' | '+' | ',' | ';' | '<' | '=' | '>' | '\\')
                || (first && matches!(character, ' ' | '#'))
                || (last && character == ' ')
            {
                output.try_push('\\').map_err(fail)?;
            }
            output.try_push(character).map_err(fail)?;
        }
        first = false;
    }
    Ok(true)
}

fn hex(
    byte: u8,
    output: &mut OwnedString,
) -> core::result::Result<(), structured_asn1::memory::MemoryError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.try_push(char::from(HEX[usize::from(byte >> 4)]))?;
    output.try_push(char::from(HEX[usize::from(byte & 15)]))
}

// Keep codec tests beside its public operations rather than display helpers.
#[cfg(test)]
mod tests {
    use crate::name::Selector;
    use crate::{fixtures, name, oid};
    use structured_asn1::Parser;

    #[test]
    fn reversible_and_readable_names_match_without_changing_original_tags() {
        // Both forms reverse RDN order and preserve unordered membership.
        // Only #BER guarantees the PrintableString tag remains recoverable.
        let memory = fixtures::memory();
        let parser = Parser::der(memory.clone());
        let bytes = fixtures::seq(&[
            fixtures::set(&[fixtures::seq(&[
                fixtures::oid(oid::COUNTRY),
                fixtures::tlv(0x13, b"UA"),
            ])]),
            fixtures::set(&[fixtures::seq(&[
                fixtures::oid(oid::COMMON_NAME),
                fixtures::utf8("A,+B=\\C"),
            ])]),
        ]);
        let mut reader = parser.read(&bytes, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let name = name::read(&reader, &element, "name").unwrap();
        let exact = name.rfc4514(&memory).unwrap();
        assert_eq!(
            exact.as_str(&memory).unwrap(),
            "CN=#0C07412C2B423D5C43,C=#13025541"
        );
        let readable = name.rfc4514_readable(&memory).unwrap();
        assert_eq!(
            readable.as_str(&memory).unwrap(),
            "CN=A\\,\\+B\\=\\\\C,C=UA"
        );
        for text in [&exact, &readable] {
            let selected = Selector::parse(text.as_str(&memory).unwrap(), &memory).unwrap();
            assert!(selected.matches_name(&name, &memory).unwrap());
        }
    }

    #[test]
    fn readable_output_never_uses_the_display_truncation_ceiling() {
        // userId has no schema upper bound here. The metadata formatter must
        // preserve its full text beyond Attribute::text's display ceiling;
        // semantic preparation may independently decline such an assertion.
        let memory = fixtures::memory();
        let parser = Parser::der(memory.clone());
        let text = "a".repeat(40_000);
        let bytes = fixtures::seq(&[fixtures::set(&[fixtures::seq(&[
            fixtures::oid(oid::USER_ID),
            fixtures::utf8(&text),
        ])])]);
        let mut reader = parser.read(&bytes, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let name = name::read(&reader, &element, "name").unwrap();
        let output = name.rfc4514_readable(&memory).unwrap();
        let rendered = output.as_str(&memory).unwrap();
        assert_eq!(rendered, alloc::format!("UID={text}"));
        let exact = name.rfc4514(&memory).unwrap();
        let selector = Selector::parse(exact.as_str(&memory).unwrap(), &memory).unwrap();
        assert!(selector.matches_name(&name, &memory).unwrap());
    }
}
