//! Fallible name preparation with separately charged execution and storage.

use crate::error::{Error, Located};
use core::cmp::Ordering;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};

use super::{
    Asking, Attribute, Direction, Mapped, RelativeName, Spaced, inside_syntax, prohibited,
};

#[derive(Debug)]
pub(super) struct Prepared<'a, W: Work = Memory> {
    attribute: Attribute<'a>,
    canonical: Option<Canonical<'a, W>>,
}

#[derive(Debug)]
pub(super) struct PreparedName<'a, W: Work = Memory> {
    attributes: OwnedVec<Prepared<'a, W>, W>,
    lengths: OwnedVec<usize, W>,
}

impl<'a, W: Work> PreparedName<'a, W> {
    pub(super) fn of(parts: &[RelativeName<'a>], memory: &W) -> Result<Self, Error> {
        Self::of_in(parts, memory, None)
    }

    pub(super) fn of_in(
        parts: &[RelativeName<'a>],
        memory: &W,
        parent: Option<&structured_asn1::Reader<'_>>,
    ) -> Result<Self, Error> {
        let mut attributes = memory.vector();
        let mut lengths = memory.vector();
        if parts.is_empty() {
            return Ok(Self {
                attributes,
                lengths,
            });
        }
        let offset = parts[0].attributes[0].value.offset;
        let fail = |reason| Error::resource(reason, "name.attribute", offset);
        memory.charge_work(parts.len() as u64).map_err(fail)?;
        for relative in parts {
            let prepared = part_in(relative, memory, parent)?;
            lengths.try_push(prepared.len()).map_err(fail)?;
            for attribute in prepared {
                attributes.try_push(attribute).map_err(fail)?;
            }
        }
        Ok(Self {
            attributes,
            lengths,
        })
    }

    pub(super) fn order<V: Work, E: Work>(
        &self,
        other: &PreparedName<'_, V>,
        memory: &E,
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
enum Canonical<'a, W: Work> {
    // ASCII NFKC is identity; folding and whitespace handling stream without
    // a canonical copy, which avoids per-attribute allocations on this path.
    Ascii(&'a str),
    CaseExactAscii(&'a str),
    // DN IA5 identities have exact ASCII case-insensitive rules, without
    // DirectoryString's whitespace mapping/compression or Unicode preparation.
    ExactAscii(&'a str),
    Unicode(OwnedVec<char, W>),
}

impl<'a, W: Work> Prepared<'a, W> {
    pub(super) fn is_prepared(&self) -> bool {
        self.canonical.is_some()
    }
    pub(super) fn of(attribute: Attribute<'a>, memory: &W) -> Result<Self, Error> {
        Self::of_in(attribute, memory, None)
    }

    fn of_in(
        attribute: Attribute<'a>,
        memory: &W,
        parent: Option<&structured_asn1::Reader<'_>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            attribute,
            canonical: canonical(attribute, memory, parent)?,
        })
    }

    pub(super) fn order<V: Work, E: Work>(
        &self,
        other: &Prepared<'_, V>,
        memory: &E,
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

impl<W: Work> Canonical<'_, W> {
    fn work(&self) -> u64 {
        match self {
            Self::Ascii(text) | Self::CaseExactAscii(text) | Self::ExactAscii(text) => {
                text.len() as u64
            }
            Self::Unicode(characters) => characters.len() as u64,
        }
    }

    fn characters(&self) -> Characters<'_> {
        match self {
            Self::Ascii(text) => Characters::Ascii(Spaced::over(Mapped::over(text.chars()))),
            Self::CaseExactAscii(text) => {
                Characters::CaseExactAscii(Spaced::over(Mapped::over(text.chars())))
            }
            Self::ExactAscii(text) => Characters::ExactAscii(text.bytes()),
            Self::Unicode(characters) => Characters::Unicode(characters.iter().copied()),
        }
    }
}

enum Characters<'a> {
    Ascii(Spaced<Mapped<core::str::Chars<'a>>>),
    CaseExactAscii(Spaced<Mapped<core::str::Chars<'a>, false>>),
    ExactAscii(core::str::Bytes<'a>),
    Unicode(core::iter::Copied<core::slice::Iter<'a, char>>),
}

impl Iterator for Characters<'_> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        match self {
            Self::Ascii(characters) => characters.next(),
            Self::CaseExactAscii(characters) => characters.next(),
            Self::ExactAscii(bytes) => Some(char::from(bytes.next()?.to_ascii_lowercase())),
            Self::Unicode(characters) => characters.next(),
        }
    }
}

pub(super) fn folds(attribute: Attribute<'_>, memory: &Memory) -> Result<bool, Error> {
    Ok(canonical(attribute, memory, None)?.is_some())
}

fn canonical<'a, W: Work>(
    attribute: Attribute<'a>,
    memory: &W,
    parent: Option<&structured_asn1::Reader<'_>>,
) -> Result<Option<Canonical<'a, W>>, Error> {
    let value = attribute.value;
    let fail = |reason| Error::resource(reason, "name.attribute", value.offset);
    if value.tag.is_constructed()
        && value.tag.class() == structured_asn1::Class::Universal
        && value
            .tag
            .number()
            .is_some_and(super::segmented_universal_type)
        && value.tag.number() != Some(structured_asn1::universal::BIT_STRING)
    {
        memory
            .charge_work(
                (attribute.kind.as_bytes().len() as u64)
                    .checked_mul(40)
                    .ok_or_else(|| fail(MemoryError::WorkExceeded))?,
            )
            .map_err(fail)?;
        let tag = structured_asn1::Tag::primitive(value.tag.number().expect("universal string"));
        let encoding = super::AttributeValue { tag, ..value }.encoding();
        if !super::permits(attribute.kind, encoding) {
            return Ok(None);
        }
        if let Some(parent) = parent {
            // Name attributes are read inside SEQUENCE/RDN/attribute frames.
            // Re-enter at the retained original depth, using the same parser
            // session and current account before any deferred BER scanning.
            debug_assert!(value.depth > 0);
            let reader = parent
                .parser()
                .read_nested_query_in(
                    parent,
                    value.der,
                    value.offset,
                    structured_asn1::Encoding::Ber,
                    value.depth - 1,
                )
                .field("name.attribute")?;
            return canonical_segmented(attribute, memory, reader);
        }
        // A retained query has no producing parser argument. Physical input
        // size bounds this temporary source's headers/nesting; the Work bridge
        // also preserves any current operation ceiling, not just its account.
        // No default profile may silently reject a previously accepted deep
        // value, and neither account nor current operation is reset.
        let length = u64::try_from(value.der.len()).map_err(|_| fail(MemoryError::WorkExceeded))?;
        let max_work = u64::try_from(memory.memory().work_remaining())
            .map_err(|_| fail(MemoryError::WorkExceeded))?;
        let depth = (length / 2).min(u64::from(u32::MAX));
        let parser = structured_asn1::Parser::new(
            structured_asn1::Encoding::Ber,
            structured_asn1::Limits {
                max_depth: u32::try_from(depth).expect("bounded by depth counter representation"),
                max_elements: length / 2,
                max_element_length: length,
                max_work,
            },
            memory.memory().clone(),
        );
        let reader = memory
            .read_source(
                &parser,
                value.der,
                value.offset,
                structured_asn1::Encoding::Ber,
                0,
            )
            .field("name.attribute")?;
        return canonical_segmented(attribute, memory, reader);
    }
    canonical_primitive(attribute, memory).map_err(fail)
}

fn canonical_segmented<'a, W: Work>(
    attribute: Attribute<'a>,
    memory: &W,
    mut reader: structured_asn1::Reader<'_>,
) -> Result<Option<Canonical<'a, W>>, Error> {
    let value = attribute.value;
    let fail = |reason| Error::resource(reason, "name.attribute", value.offset);
    let element = reader
        .next_element()
        .field("name.attribute")?
        .expect("validated attribute contains one value");
    let mut contents = memory.vector();
    super::segments::walk_in(
        &reader,
        &element,
        "name.attribute",
        false,
        Some(&mut contents),
        memory,
    )?;
    let logical = Attribute {
        kind: attribute.kind,
        value: super::AttributeValue {
            tag: structured_asn1::Tag::primitive(value.tag.number().expect("universal string")),
            contents: &contents,
            der: value.der,
            offset: value.offset,
            depth: value.depth,
        },
    };
    let Some(prepared) = canonical_primitive(logical, memory).map_err(fail)? else {
        return Ok(None);
    };
    // The flattened bytes are scratch. Canonical characters own their
    // storage, avoiding references into an allocation that will move/drop.
    if let Canonical::Unicode(characters) = prepared {
        return Ok(Some(Canonical::Unicode(characters)));
    }
    memory.charge_work(prepared.work()).map_err(fail)?;
    let mut characters = memory.vector();
    for character in prepared.characters() {
        characters.try_push(character).map_err(fail)?;
    }
    Ok(Some(Canonical::Unicode(characters)))
}

fn canonical_primitive<'a, W: Work>(
    attribute: Attribute<'a>,
    memory: &W,
) -> Result<Option<Canonical<'a, W>>, MemoryError> {
    // Syntax, size and identity rules examine at most 64 kind-byte passes.
    // UTF-8 validation, alphabet/count validation, ASCII detection and decoding
    // each visit the value once. Admit these before any of those scans.
    let work = (attribute.kind.as_bytes().len() as u64)
        .checked_mul(64)
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
    if attribute.kind == crate::oid::EMAIL_ADDRESS || attribute.kind == crate::oid::DOMAIN_COMPONENT
    {
        // emailAddress: RFC2985 §§5.2.1/6.1, whole-value pkcs9CaseIgnoreMatch.
        // domainComponent: RFC5280 §7.3, case-insensitive exact comparison.
        // The mailbox local-part rule of §7.5 belongs to GeneralName.rfc822Name.
        // https://www.rfc-editor.org/rfc/rfc2985.html#section-6.1
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-7.3
        if !inside_syntax(&attribute, Asking::Shape, |_| true) {
            return Ok(None);
        }
        let text =
            core::str::from_utf8(attribute.value.contents).expect("validated IA5String is ASCII");
        return Ok(Some(Canonical::ExactAscii(text)));
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
        return Ok(Some(if attribute.kind == crate::oid::PSEUDONYM {
            Canonical::CaseExactAscii(text)
        } else {
            Canonical::Ascii(text)
        }));
    }
    // RFC2985 §5.2.9 assigns caseExactMatch to pseudonym (2.5.4.65).
    // RFC4517 §4.2.4 keeps mapping, NFKC and space handling but omits case
    // folding. Both rules use the same preparation kernel, specialized here.
    // https://www.rfc-editor.org/rfc/rfc2985.html#section-5.2.9
    // https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.4
    if attribute.kind == crate::oid::PSEUDONYM {
        unicode::<false, W>(attribute, memory)
    } else {
        unicode::<true, W>(attribute, memory)
    }
}

fn unicode<const FOLD_CASE: bool, W: Work>(
    attribute: Attribute<'_>,
    memory: &W,
) -> Result<Option<Canonical<'static, W>>, MemoryError> {
    let normalized = super::normalize::nfkc(
        memory,
        Mapped::<_, FOLD_CASE>::over(attribute.value.decoded_chars()),
    )?;
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
    for character in Spaced::over(Mapped::<_, FOLD_CASE>::over(normalized.iter().copied())) {
        canonical.try_push(character)?;
    }
    Ok(Some(Canonical::Unicode(canonical)))
}

fn part_in<'a, W: Work>(
    part: &RelativeName<'a>,
    memory: &W,
    parent: Option<&structured_asn1::Reader<'_>>,
) -> Result<OwnedVec<Prepared<'a, W>, W>, Error> {
    let mut attributes = memory.vector();
    let fail = |reason| Error::resource(reason, "name.attribute", part.attributes[0].value.offset);
    for &attribute in part.attributes() {
        attributes
            .try_push(Prepared::of_in(attribute, memory, parent)?)
            .map_err(fail)?;
    }
    attributes
        .try_sort_unstable_by(|left, right| left.order(right, memory))
        .map_err(|reason| fail(MemoryError::from(reason)))?;
    Ok(attributes)
}

pub(super) fn compare_parts<W: Work>(
    left: &RelativeName<'_>,
    right: &RelativeName<'_>,
    execution: &W,
) -> Result<Ordering, Error> {
    compare_parts_in(left, right, execution, None)
}

pub(super) fn compare_parts_in<W: Work>(
    left: &RelativeName<'_>,
    right: &RelativeName<'_>,
    execution: &W,
    parent: Option<&structured_asn1::Reader<'_>>,
) -> Result<Ordering, Error> {
    compare_views(
        left.attributes
            .iter()
            .copied()
            .map(|attribute| Prepared::of_in(attribute, execution, parent)),
        right
            .attributes
            .iter()
            .copied()
            .map(|attribute| Prepared::of_in(attribute, execution, parent)),
        execution,
        |reason| Error::resource(reason, "name.attribute", left.attributes[0].value.offset),
    )
}

/// Borrowed projections are evaluated only as preparation requires them.
/// Singleton RDNs allocate no catalogue; multi-valued RDNs allocate only
/// the prepared sorting scratch shared with certificate Name comparison.
pub(super) fn compare_views<'a, 'b, E, W: Work>(
    mut left: impl ExactSizeIterator<Item = Result<Prepared<'a, W>, E>>,
    mut right: impl ExactSizeIterator<Item = Result<Prepared<'b, W>, E>>,
    execution: &W,
    fail: impl Fn(MemoryError) -> E + Copy,
) -> Result<Ordering, E> {
    let length = left.len().cmp(&right.len());
    if length != Ordering::Equal {
        return Ok(length);
    }
    if left.len() == 1 {
        return left
            .next()
            .expect("one attribute")?
            .order(&right.next().expect("one attribute")?, execution)
            .map_err(fail);
    }
    let left = prepare_view(left, execution, fail)?;
    let right = prepare_view(right, execution, fail)?;
    for (left, right) in left.iter().zip(&right) {
        let order = left.order(right, execution).map_err(fail)?;
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(Ordering::Equal)
}

fn prepare_view<'a, E, W: Work>(
    attributes: impl ExactSizeIterator<Item = Result<Prepared<'a, W>, E>>,
    execution: &W,
    fail: impl Fn(MemoryError) -> E + Copy,
) -> Result<OwnedVec<Prepared<'a, W>, W>, E> {
    execution
        .charge_work(attributes.len() as u64)
        .map_err(fail)?;
    let mut prepared = execution.vector();
    for attribute in attributes {
        prepared.try_push(attribute?).map_err(fail)?;
    }
    prepared
        .try_sort_unstable_by(|left, right| left.order(right, execution))
        .map_err(|reason| fail(MemoryError::from(reason)))?;
    Ok(prepared)
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
            let ours = part_in(&left.parts()[0], &memory, None).unwrap();
            let theirs = part_in(&right.parts()[0], &memory, None).unwrap();
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
        let left = part_in(&wide.parts()[0], &memory, None).unwrap();
        let right = part_in(&narrow.parts()[0], &memory, None).unwrap();
        assert_ne!(left[0].order(&right[0], &memory).unwrap(), Ordering::Equal);
    }
}
