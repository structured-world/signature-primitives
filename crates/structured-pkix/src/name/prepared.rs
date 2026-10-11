//! Fallible name preparation with separately charged execution and storage.

use core::cmp::Ordering;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec};

use super::{
    Asking, Attribute, Direction, Mapped, RelativeName, Spaced, inside_syntax, prohibited,
};

#[derive(Debug)]
pub(super) struct Prepared<'a> {
    attribute: Attribute<'a>,
    canonical: Option<Canonical<'a>>,
}

#[derive(Debug)]
pub(super) struct PreparedName<'a> {
    attributes: OwnedVec<Prepared<'a>>,
    lengths: OwnedVec<usize>,
}

impl<'a> PreparedName<'a> {
    pub(super) fn of(parts: &[RelativeName<'a>], memory: &Memory) -> Result<Self, MemoryError> {
        let mut attributes = memory.vector();
        let mut lengths = memory.vector();
        memory.charge_work(parts.len() as u64)?;
        for relative in parts {
            let prepared = part(relative, memory)?;
            lengths.try_push(prepared.len())?;
            for attribute in prepared {
                attributes.try_push(attribute)?;
            }
        }
        Ok(Self {
            attributes,
            lengths,
        })
    }

    pub(super) fn order(
        &self,
        other: &PreparedName<'_>,
        memory: &Memory,
    ) -> Result<Ordering, MemoryError> {
        let parts = self.lengths.len().cmp(&other.lengths.len());
        if parts != Ordering::Equal {
            return Ok(parts);
        }
        let (mut ours, mut theirs) = (0, 0);
        for (left, right) in self.lengths.iter().zip(&other.lengths) {
            memory.charge_work(1)?;
            let length = left.cmp(right);
            if length != Ordering::Equal {
                return Ok(length);
            }
            for (left, right) in self.attributes[ours..ours + left]
                .iter()
                .zip(&other.attributes[theirs..theirs + right])
            {
                let order = left.order(right, memory)?;
                if order != Ordering::Equal {
                    return Ok(order);
                }
            }
            ours += left;
            theirs += right;
        }
        Ok(Ordering::Equal)
    }
}

#[derive(Debug)]
enum Canonical<'a> {
    // ASCII NFKC is identity; folding and whitespace handling stream without
    // a canonical copy, which avoids per-attribute allocations on this path.
    Ascii(&'a str),
    Unicode(OwnedVec<char>),
}

impl<'a> Prepared<'a> {
    pub(super) fn of(attribute: Attribute<'a>, memory: &Memory) -> Result<Self, MemoryError> {
        Ok(Self {
            attribute,
            canonical: canonical(attribute, memory)?,
        })
    }

    pub(super) fn order(
        &self,
        other: &Prepared<'_>,
        memory: &Memory,
    ) -> Result<Ordering, MemoryError> {
        let left = self.attribute.kind.as_bytes();
        let right = other.attribute.kind.as_bytes();
        memory.charge_work(left.len().max(right.len()) as u64)?;
        let kind = left.cmp(right);
        if kind != Ordering::Equal {
            return Ok(kind);
        }
        match (&self.canonical, &other.canonical) {
            (Some(left), Some(right)) => {
                memory.charge_work(
                    left.work()
                        .checked_add(right.work())
                        .ok_or(MemoryError::WorkExceeded)?,
                )?;
                Ok(left.characters().cmp(right.characters()))
            }
            (None, None) => {
                let left = self.attribute.value.der;
                let right = other.attribute.value.der;
                memory.charge_work(left.len().max(right.len()) as u64)?;
                Ok(left.cmp(right))
            }
            (Some(_), None) => Ok(Ordering::Less),
            (None, Some(_)) => Ok(Ordering::Greater),
        }
    }
}

impl Canonical<'_> {
    fn work(&self) -> u64 {
        match self {
            Self::Ascii(text) => text.len() as u64,
            Self::Unicode(characters) => characters.len() as u64,
        }
    }

    fn characters(&self) -> Characters<'_> {
        match self {
            Self::Ascii(text) => Characters::Ascii(Spaced::over(Mapped::over(text.chars()))),
            Self::Unicode(characters) => Characters::Unicode(characters.iter().copied()),
        }
    }
}

enum Characters<'a> {
    Ascii(Spaced<Mapped<core::str::Chars<'a>>>),
    Unicode(core::iter::Copied<core::slice::Iter<'a, char>>),
}

impl Iterator for Characters<'_> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        match self {
            Self::Ascii(characters) => characters.next(),
            Self::Unicode(characters) => characters.next(),
        }
    }
}

pub(super) fn folds(attribute: Attribute<'_>, memory: &Memory) -> Result<bool, MemoryError> {
    Ok(canonical(attribute, memory)?.is_some())
}

fn canonical<'a>(
    attribute: Attribute<'a>,
    memory: &Memory,
) -> Result<Option<Canonical<'a>>, MemoryError> {
    // The schema's fixed OID table examines at most forty kind-byte passes.
    // UTF-8 validation, alphabet/count validation, ASCII detection and decoding
    // each visit the value once. Admit these before any of those scans.
    let work = (attribute.kind.as_bytes().len() as u64)
        .checked_mul(40)
        .and_then(|kind| {
            (attribute.value.contents.len() as u64)
                .checked_mul(4)
                .and_then(|value| kind.checked_add(value))
        })
        .ok_or(MemoryError::WorkExceeded)?;
    memory.charge_work(work)?;
    // An unknown kind has no defined case-insensitive matching rule. Shape
    // validation preserves it, but preservation must not authorize folding.
    if !super::permits(attribute.kind, attribute.value.encoding()) {
        return Ok(None);
    }
    if !inside_syntax(&attribute, Asking::Folding, |character| {
        !prohibited(character)
    }) {
        return Ok(None);
    }
    if !matches!(
        attribute.value.encoding(),
        super::Encoding::Bmp | super::Encoding::Universal
    ) && attribute.value.contents.is_ascii()
    {
        let text = core::str::from_utf8(attribute.value.contents).expect("ASCII is valid UTF-8");
        return Ok(Some(Canonical::Ascii(text)));
    }
    let normalized = super::normalize::nfkc(memory, Mapped::over(attribute.value.decoded_chars()))?;
    memory.charge_work(normalized.len() as u64)?;
    let mut direction = Direction::default();
    for &character in &normalized {
        direction.see(character);
    }
    if !direction.settled() {
        return Ok(None);
    }
    memory.charge_work(normalized.len() as u64)?;
    let mut canonical = memory.vector();
    for character in Spaced::over(Mapped::over(normalized.iter().copied())) {
        canonical.try_push(character)?;
    }
    Ok(Some(Canonical::Unicode(canonical)))
}

pub(super) fn part<'a>(
    part: &RelativeName<'a>,
    memory: &Memory,
) -> Result<OwnedVec<Prepared<'a>>, MemoryError> {
    let mut attributes = memory.vector();
    for &attribute in part.attributes() {
        attributes.try_push(Prepared::of(attribute, memory)?)?;
    }
    attributes
        .try_sort_unstable_by(|left, right| left.order(right, memory))
        .map_err(MemoryError::from)?;
    Ok(attributes)
}

pub(super) fn compare_parts(
    left: &RelativeName<'_>,
    right: &RelativeName<'_>,
    execution: &Memory,
) -> Result<Ordering, MemoryError> {
    let length = left.attributes.len().cmp(&right.attributes.len());
    if length != Ordering::Equal {
        return Ok(length);
    }
    if let ([left], [right]) = (&left.attributes[..], &right.attributes[..]) {
        return Prepared::of(*left, execution)?.order(&Prepared::of(*right, execution)?, execution);
    }
    let left = part(left, execution)?;
    let right = part(right, execution)?;
    for (left, right) in left.iter().zip(&right) {
        let order = left.order(right, execution)?;
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixtures, name, oid};
    use structured_asn1::Parser;

    #[test]
    fn prepared_names_preserve_multiset_and_part_order() {
        // Compare against the original implementation before replacing it:
        // order inside an RDN is irrelevant, while RDN sequence, duplicates,
        // different kinds and unpreparable values remain distinguishable.
        let memory = fixtures::memory();
        let parser = Parser::der(memory.clone());
        let attribute = |kind, value| fixtures::seq(&[fixtures::oid(kind), fixtures::utf8(value)]);
        let a = attribute(oid::COMMON_NAME, "A");
        let lower = attribute(oid::COMMON_NAME, "a");
        let b = attribute(oid::ORGANIZATION, "B");
        let mut both = alloc::vec![a.clone(), b.clone()];
        both.sort();
        let names = [
            fixtures::seq(&[]),
            fixtures::seq(&[fixtures::set(core::slice::from_ref(&a))]),
            fixtures::seq(&[fixtures::set(&[lower])]),
            fixtures::seq(&[fixtures::set(&both)]),
            fixtures::seq(&[fixtures::set(&[a.clone(), a.clone()])]),
            fixtures::seq(&[fixtures::set(&[a]), fixtures::set(&[b])]),
            fixtures::seq(&[fixtures::set(&[attribute(oid::COMMON_NAME, "\u{e000}")])]),
        ];
        for left in &names {
            for right in &names {
                let read = |der| {
                    let mut reader = parser.read(der, 0).unwrap();
                    let element = reader.next_element().unwrap().unwrap();
                    name::read(&reader, &element, "name").unwrap()
                };
                let left = read(left);
                let right = read(right);
                let prepared_left = PreparedName::of(left.parts(), &memory).unwrap();
                let prepared_right = PreparedName::of(right.parts(), &memory).unwrap();
                // The retained test oracle uses the original per-RDN ordering,
                // independent of the new PreparedName implementation.
                let expected = left.parts.len().cmp(&right.parts.len()).then_with(|| {
                    left.parts
                        .iter()
                        .zip(&right.parts)
                        .map(|(left, right)| left.order(right))
                        .find(|order| *order != Ordering::Equal)
                        .unwrap_or(Ordering::Equal)
                });
                assert_eq!(
                    prepared_left.order(&prepared_right, &memory).unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn accounted_preparation_preserves_name_matching_semantics() {
        // Compare the replacement against the existing full preparation at
        // syntax, mapping, bidi, composition and binary-only boundaries.
        let memory = fixtures::memory();
        let parser = Parser::der(memory.clone());
        for (left, right) in [
            ("ROOT", "root"),
            ("  A B  ", "a  b"),
            ("Straße", "STRASSE"),
            ("A\u{030a}\u{0301}", "\u{01fb}"),
            ("\u{2121}", "tel"),
            ("\u{05d0}\u{2121}\u{05d0}", "\u{05d0}tel\u{05d0}"),
            ("\u{e000}", "\u{e000}"),
            ("\u{ac01}", "\u{1100}\u{1161}\u{11a8}"),
        ] {
            let encoding = |text| {
                fixtures::seq(&[fixtures::set(&[fixtures::seq(&[
                    fixtures::oid(oid::COMMON_NAME),
                    fixtures::utf8(text),
                ])])])
            };
            let left_der = encoding(left);
            let right_der = encoding(right);
            let read = |der| {
                let mut reader = parser.read(der, 0).unwrap();
                let element = reader.next_element().unwrap().unwrap();
                name::read(&reader, &element, "name").unwrap()
            };
            let left = read(&left_der);
            let right = read(&right_der);
            let ours = part(&left.parts()[0], &memory).unwrap();
            let theirs = part(&right.parts()[0], &memory).unwrap();
            assert_eq!(
                ours[0].order(&theirs[0], &memory).unwrap() == Ordering::Equal,
                left.parts[0].matches(&right.parts[0])
            );
        }
    }

    #[test]
    fn ascii_preparation_keeps_a_borrowed_canonical_view() {
        // The common path must avoid a canonical allocation while still
        // charging the new request rather than the parsed Name's old account.
        let storage = fixtures::memory();
        let parser = Parser::der(storage);
        let der = fixtures::seq(&[fixtures::set(&[fixtures::seq(&[
            fixtures::oid(oid::COMMON_NAME),
            fixtures::utf8(" ROOT "),
        ])])]);
        let mut reader = parser.read(&der, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let name = name::read(&reader, &element, "name").unwrap();
        let execution = fixtures::memory();
        assert!(folds(*name.attributes().next().unwrap(), &execution).unwrap());
        assert_eq!(execution.used(), 0);
        assert!(execution.work_used() > 0);
    }

    #[test]
    fn ascii_bytes_in_a_wide_encoding_do_not_become_ascii_characters() {
        // U+0141's BMP octets are both below 0x80; interpreting those octets as
        // ASCII would drop 0x01 and falsely identify Ł as the letter A.
        let memory = fixtures::memory();
        let parser = Parser::der(memory.clone());
        let encode = |value| {
            fixtures::seq(&[fixtures::set(&[fixtures::seq(&[
                fixtures::oid(oid::COMMON_NAME),
                value,
            ])])])
        };
        let wide = encode(fixtures::tlv(0x1e, &[1, 0x41]));
        let narrow = encode(fixtures::utf8("A"));
        let read = |der| {
            let mut reader = parser.read(der, 0).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            name::read(&reader, &element, "name").unwrap()
        };
        let wide = read(&wide);
        let narrow = read(&narrow);
        let left = part(&wide.parts()[0], &memory).unwrap();
        let right = part(&narrow.parts()[0], &memory).unwrap();
        assert_ne!(left[0].order(&right[0], &memory).unwrap(), Ordering::Equal);
    }
}
