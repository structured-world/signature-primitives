//! Strict RFC 4514 lexical identities, independent of input/parser lifetimes.

use super::{Attribute, AttributeValue, Name, Strings, Syntax, prepared, segments};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::oid;
use core::cmp::Ordering;
use core::ops::Range;
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{Class, Oid, OwnedOid, Parser, Tag, universal};

const FIELD: &str = "name.selector";

/// An independently owned RFC 4514 distinguished-name assertion.
///
/// Parsing is strict: separator whitespace is not implicitly discarded.
/// Values retain their decoded assertion octets or complete original BER.
/// RDN order and unordered membership use the certificate Name's shared
/// comparison core. Storage remains charged after the parser/account handle
/// is dropped; each subsequent operation takes its own execution account.
#[derive(Debug)]
pub struct Selector {
    parts: OwnedVec<OwnedVec<Selected>>,
}

#[derive(Debug)]
struct Selected {
    kind: Kind,
    bytes: OwnedVec<u8>,
    value: Value,
    offset: u64,
}

#[derive(Debug)]
enum Kind {
    Known(Oid<'static>),
    Numeric(OwnedOid),
}

impl Kind {
    fn as_oid(&self) -> Oid<'_> {
        match self {
            Self::Known(kind) => *kind,
            Self::Numeric(kind) => kind.as_oid(),
        }
    }
}

#[derive(Debug)]
enum Value {
    Assertion,
    Ber {
        tag: Tag,
        contents: Range<usize>,
        joined: Option<OwnedVec<u8>>,
    },
}

impl Selector {
    /// Parses the grammar of RFC 4514 §3 without compatibility trimming.
    /// Unknown numeric types are preserved. An unknown descriptor, malformed
    /// escape, incomplete BER value or syntax violation is a located error;
    /// unavailable equality semantics remain distinct at comparison time.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// use structured_pkix::name::Selector;
    /// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
    /// let left = Selector::parse("CN=A\\,B,O=Example", &memory)?;
    /// let right = Selector::parse("cn=A\\2CB,o=example", &memory)?;
    /// assert!(left.matches(&right, &memory)?);
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn parse(text: &str, execution: &Memory) -> Result<Self> {
        // Lexical validation precedes allocation. This admits all fixed
        // descriptor comparisons and both source passes before scanning.
        let work = (text.len() as u64)
            .checked_mul(64)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                Error::resource(structured_asn1::memory::MemoryError::WorkExceeded, FIELD, 0)
            })?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, FIELD, 0))?;
        scan(text, |_, _, _, _| Ok(()))?;
        let parser = Parser::ber(execution.clone());
        let mut parts = execution.vector();
        let mut current = execution.vector();
        scan(text, |label, value, offset, last| {
            current
                .try_push(selected(label, value, offset, &parser, execution)?)
                .map_err(|reason| Error::resource(reason, FIELD, offset))?;
            if last {
                parts
                    .try_push(core::mem::replace(&mut current, execution.vector()))
                    .map_err(|reason| Error::resource(reason, FIELD, offset))?;
            }
            Ok(())
        })?;
        execution
            .charge_work(parts.len() as u64)
            .map_err(|reason| Error::resource(reason, FIELD, 0))?;
        parts.reverse(); // RFC 4514 §2.1: textual last RDN is ASN.1 first.
        Ok(Self { parts })
    }

    /// Compares directly with a certificate Name without serializing it.
    /// Unknown LDAP assertion syntax returns `UnsupportedNameSyntax` when
    /// semantic preparation is needed; it is never guessed as `UTF8String`.
    pub fn matches_name(&self, name: &Name<'_>, execution: &Memory) -> Result<bool> {
        if self.parts.len() != name.parts().len() {
            return Ok(false);
        }
        for (selected, part) in self.parts.iter().zip(name.parts()) {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, FIELD, 0))?;
            let fail = |reason| Error::resource(reason, FIELD, 0);
            let order = prepared::compare_views(
                selected.iter().map(|item| project(item, execution)),
                part.attributes()
                    .iter()
                    .copied()
                    .map(|attribute| prepared::Prepared::of(attribute, execution)),
                execution,
                fail,
            )?;
            if order != Ordering::Equal {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Compares two independently owned selectors under the same Name rules.
    pub fn matches(&self, other: &Self, execution: &Memory) -> Result<bool> {
        if self.parts.len() != other.parts.len() {
            return Ok(false);
        }
        for (left, right) in self.parts.iter().zip(&other.parts) {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, FIELD, 0))?;
            if prepared::compare_views(
                left.iter().map(|item| project(item, execution)),
                right.iter().map(|item| project(item, execution)),
                execution,
                |reason| Error::resource(reason, FIELD, 0),
            )? != Ordering::Equal
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn selected(
    label: &str,
    value: &str,
    offset: u64,
    parser: &Parser,
    execution: &Memory,
) -> Result<Selected> {
    let kind = match descriptor(label) {
        Some(kind) => Kind::Known(kind),
        None => Kind::Numeric(OwnedOid::parse(label, execution).map_err(|error| {
            Error::new(
                ErrorCode::Encoding(error.code()),
                FIELD,
                offset + error.offset(),
            )
        })?),
    };
    let mut bytes = execution.vector();
    let value = if let Some(hex) = value.strip_prefix('#') {
        for pair in hex.as_bytes().as_chunks::<2>().0 {
            bytes
                .try_push(
                    (digit(pair[0]).expect("validated hex") << 4)
                        | digit(pair[1]).expect("validated hex"),
                )
                .map_err(|reason| Error::resource(reason, FIELD, offset))?;
        }
        ber(&bytes, kind.as_oid(), parser, execution).map_err(|error| {
            Error::new(
                error.code(),
                FIELD,
                offset + label.len() as u64 + 2 + 2 * error.offset(),
            )
        })?
    } else {
        let mut at = 0;
        let input = value.as_bytes();
        while at < input.len() {
            let byte = if input[at] == b'\\' {
                at += 1;
                if let Some(high) = digit(input[at]) {
                    at += 1;
                    (high << 4) | digit(input[at]).expect("validated escape")
                } else {
                    input[at]
                }
            } else {
                input[at]
            };
            bytes
                .try_push(byte)
                .map_err(|reason| Error::resource(reason, FIELD, offset))?;
            at += 1;
        }
        Value::Assertion
    };
    Ok(Selected {
        kind,
        bytes,
        value,
        offset,
    })
}

fn ber(bytes: &[u8], kind: Oid<'_>, parser: &Parser, execution: &Memory) -> Result<Value> {
    let mut reader = parser.read(bytes, 0).field(FIELD)?;
    let element = reader
        .next_element()
        .field(FIELD)?
        .ok_or_else(|| malformed(0))?;
    if !reader.is_empty() {
        return Err(malformed(element.span().end()));
    }
    super::walk_der(&reader, &element, FIELD, Strings::Checked)?;
    let tag = element.tag();
    let start = element.as_bytes().len()
        - element.contents().len()
        - if element.is_indefinite() { 2 } else { 0 };
    let contents = start..start + element.contents().len();
    execution
        .charge_work(
            (kind.as_bytes().len() as u64)
                .checked_mul(40)
                .ok_or_else(|| {
                    Error::resource(structured_asn1::memory::MemoryError::WorkExceeded, FIELD, 0)
                })?,
        )
        .map_err(|reason| Error::resource(reason, FIELD, 0))?;
    let logical_encoding = match tag.number() {
        Some(number) => super::AttributeValue {
            tag: Tag::primitive(number),
            contents: &[],
            der: &[],
            offset: 0,
        }
        .encoding(),
        None => super::Encoding::Other,
    };
    let joined = if tag.class() == Class::Universal
        && tag.is_constructed()
        && tag.number().is_some_and(super::segmented_universal_type)
        && tag.number() != Some(universal::BIT_STRING)
        && super::permits(kind, logical_encoding)
    {
        let mut joined = execution.vector();
        segments::walk(&reader, &element, FIELD, false, Some(&mut joined))?;
        Some(joined)
    } else {
        None
    };
    Ok(Value::Ber {
        tag,
        contents,
        joined,
    })
}

fn project<'a>(item: &'a Selected, execution: &Memory) -> Result<prepared::Prepared<'a>> {
    let kind = item.kind.as_oid();
    let value = match &item.value {
        Value::Assertion => {
            execution
                .charge_work((kind.as_bytes().len() as u64) * 40)
                .map_err(|reason| Error::resource(reason, FIELD, item.offset))?;
            let tag = match super::syntax_of(kind) {
                Some(Syntax::Directory) => universal::UTF8_STRING,
                Some(Syntax::Printable) => universal::PRINTABLE_STRING,
                Some(Syntax::Ia5) => universal::IA5_STRING,
                None => {
                    return Err(Error::new(
                        ErrorCode::UnsupportedNameSyntax,
                        FIELD,
                        item.offset,
                    ));
                }
            };
            AttributeValue {
                tag: Tag::primitive(tag),
                contents: &item.bytes,
                der: &[],
                offset: item.offset,
            }
        }
        Value::Ber {
            tag,
            contents,
            joined,
        } => AttributeValue {
            tag: if joined.is_some() {
                Tag::primitive(tag.number().expect("universal string"))
            } else {
                *tag
            },
            contents: joined.as_deref().unwrap_or(&item.bytes[contents.clone()]),
            der: &item.bytes,
            offset: item.offset,
        },
    };
    let attribute = Attribute { kind, value };
    if matches!(item.value, Value::Assertion) {
        let work = (kind.as_bytes().len() as u64)
            .checked_mul(64)
            .and_then(|kinds| {
                (value.contents.len() as u64)
                    .checked_mul(2)
                    .and_then(|contents| kinds.checked_add(contents))
            })
            .and_then(|work| work.checked_add(1))
            .ok_or_else(|| {
                Error::resource(
                    structured_asn1::memory::MemoryError::WorkExceeded,
                    FIELD,
                    item.offset,
                )
            })?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, FIELD, item.offset))?;
        if !super::well_formed(&attribute) {
            return Err(Error::new(ErrorCode::MalformedValue, FIELD, item.offset));
        }
    }
    let prepared = prepared::Prepared::of(attribute, execution)?;
    if matches!(item.value, Value::Assertion) && !prepared.is_prepared() {
        return Err(Error::new(
            ErrorCode::UnsupportedNameSyntax,
            FIELD,
            item.offset,
        ));
    }
    Ok(prepared)
}

fn malformed(offset: u64) -> Error {
    Error::new(ErrorCode::MalformedValue, FIELD, offset)
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn label_fits(label: &str, offset: u64) -> Result<()> {
    let Some(first) = label.as_bytes().first() else {
        return Err(malformed(offset));
    };
    if first.is_ascii_digit() {
        let mut count = 0;
        for component in label.split('.') {
            if component.is_empty()
                || !component.bytes().all(|b| b.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
            {
                return Err(malformed(offset));
            }
            count += 1;
        }
        if count < 2 {
            return Err(malformed(offset));
        }
    } else if !first.is_ascii_alphabetic()
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(malformed(offset));
    } else if descriptor(label).is_none() {
        return Err(Error::new(ErrorCode::UnsupportedNameSyntax, FIELD, offset));
    }
    Ok(())
}

// RFC 4514 §3. Decode escaped octets only after finding delimiters; an
// escaped comma is part of one value, not a separator to scan a second time.
fn scan(text: &str, mut visit: impl FnMut(&str, &str, u64, bool) -> Result<()>) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    let bytes = text.as_bytes();
    let mut at = 0;
    loop {
        let start = at;
        while at < bytes.len() && bytes[at] != b'=' {
            at += 1;
        }
        if at == bytes.len() {
            return Err(malformed(start as u64));
        }
        let label = &text[start..at];
        label_fits(label, start as u64)?;
        at += 1;
        let value = at;
        if bytes.get(at) == Some(&b'#') {
            at += 1;
            let hex = at;
            while at < bytes.len() && !matches!(bytes[at], b',' | b'+') {
                if digit(bytes[at]).is_none() {
                    return Err(malformed(at as u64));
                }
                at += 1;
            }
            if at == hex || !(at - hex).is_multiple_of(2) {
                return Err(malformed(hex as u64));
            }
        } else {
            let mut last_space = false;
            while at < bytes.len() && !matches!(bytes[at], b',' | b'+') {
                let byte = bytes[at];
                if byte == b'\\' {
                    at += 1;
                    let Some(&escaped) = bytes.get(at) else {
                        return Err(malformed(at as u64));
                    };
                    if digit(escaped).is_some() {
                        at += 1;
                        if bytes.get(at).copied().and_then(digit).is_none() {
                            return Err(malformed(at as u64));
                        }
                    } else if !matches!(
                        escaped,
                        b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'\\'
                    ) {
                        return Err(malformed(at as u64));
                    }
                    last_space = false;
                } else {
                    if matches!(byte, 0 | b'"' | b';' | b'<' | b'>')
                        || (at == value && matches!(byte, b' ' | b'#'))
                    {
                        return Err(malformed(at as u64));
                    }
                    last_space = byte == b' ';
                }
                at += 1;
            }
            if last_space {
                return Err(malformed((at - 1) as u64));
            }
        }
        let last = bytes.get(at) != Some(&b'+');
        visit(label, &text[value..at], start as u64, last)?;
        if at == bytes.len() {
            return Ok(());
        }
        at += 1;
        if at == bytes.len() {
            return Err(malformed(at as u64));
        }
    }
}

const DESCRIPTORS: &[(&str, Oid<'static>)] = &[
    ("CN", oid::COMMON_NAME),
    ("L", oid::LOCALITY),
    ("ST", oid::STATE_OR_PROVINCE),
    ("O", oid::ORGANIZATION),
    ("OU", oid::ORGANIZATIONAL_UNIT),
    ("C", oid::COUNTRY),
    ("STREET", oid::STREET_ADDRESS),
    ("DC", oid::DOMAIN_COMPONENT),
    ("UID", oid::USER_ID),
    ("emailAddress", oid::EMAIL_ADDRESS),
    ("serialNumber", oid::SERIAL_NUMBER),
    ("surname", oid::SURNAME),
    ("givenName", oid::GIVEN_NAME),
    ("initials", oid::INITIALS),
    ("generationQualifier", oid::GENERATION_QUALIFIER),
    ("title", oid::TITLE),
    ("dnQualifier", oid::DN_QUALIFIER),
    ("pseudonym", oid::PSEUDONYM),
    ("organizationIdentifier", oid::ORGANIZATION_IDENTIFIER),
];

/// RFC 4514 §3's mandatory registered names. Input aliases do not imply
/// that an arbitrary short name is registered for serialization (§2.3).
pub(super) fn registered_name(kind: Oid<'_>) -> Option<&'static str> {
    DESCRIPTORS[..9]
        .iter()
        .find(|(_, oid)| *oid == kind)
        .map(|(name, _)| *name)
}

fn descriptor(text: &str) -> Option<Oid<'static>> {
    DESCRIPTORS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(text))
        .map(|(_, oid)| *oid)
}
