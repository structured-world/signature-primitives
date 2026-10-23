//! The one iterative BER base-string walker used by validation and codecs.

use super::{AttributeValue, Encoding, Error, ErrorCode, Located, OwnedVec, Result, Strings};
use structured_asn1::memory::Work;
use structured_asn1::{Class, Element, ScopedReader as Reader, Tag, universal};
use zeroize::Zeroize;

// Opaque values can be secret bag contents. Erasing only the enclosing
// plaintext is insufficient if this validator has materialized another copy.
// Capacity is fixed before copying, so no realloc can abandon an earlier copy;
// Drop covers validation and current-work refusal as well as successful reads.
struct Scratch<W: Work>(OwnedVec<u8, W>);
impl<W: Work> Drop for Scratch<W> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) fn implicit<'a>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    bits: bool,
) -> Result<bool> {
    if element.tag().is_constructed() {
        if parent.encoding().is_der() {
            return Ok(false);
        }
        walk(parent, element, field, bits)?;
    } else if bits {
        return super::reads(parent.bit_string(element), field);
    }
    Ok(true)
}

pub(super) fn validate<'a>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    strings: Strings,
) -> Result<()> {
    let number = element.tag().number().expect("assigned universal string");
    let time = matches!(number, universal::UTC_TIME | universal::GENERALIZED_TIME);
    if (strings == Strings::Checked && !matches!(number, 3 | 4)) || time {
        let execution = parent.execution();
        let length = walk_length(parent, element, field, false, None, &execution, |_, _| {
            Ok(())
        })?;
        execution
            .charge_work(length as u64)
            .map_err(|reason| Error::resource(reason, field, element.span().start))?;
        let mut contents = Scratch(execution.vector());
        contents
            .0
            .try_reserve_exact(length)
            .map_err(|reason| Error::resource(reason, field, element.span().start))?;
        walk_in(
            parent,
            element,
            field,
            false,
            Some(&mut contents.0),
            &execution,
        )?;
        let work = (contents.0.len() as u64).checked_mul(3).ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                element.span().start,
            )
        })?;
        parent.charge(work).field(field)?;
        let value = AttributeValue {
            tag: Tag::primitive(number),
            contents: &contents.0,
            der: element.as_bytes(),
            offset: element.span().start,
            depth: parent.depth(),
        };
        let valid = if time {
            crate::time::ber_fits(&contents.0, number == universal::GENERALIZED_TIME)
        } else {
            matches!(value.encoding(), Encoding::Other | Encoding::Teletex)
                || value.validated_count(|_| true).is_some()
        };
        if !valid {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                field,
                element.span().start,
            ));
        }
    } else {
        walk(parent, element, field, number == 3)?;
    }
    Ok(())
}

struct Frame<'a: 'operation, 'operation> {
    reader: Reader<'a, 'operation>,
    unused: u8,
}

/// A known implicitly or universally tagged string has base-type children:
/// BIT STRING children for bits, OCTET STRING children for all other strings.
/// X.690 §§8.6.4, 8.7.3.2, 8.23.3. Nested final padding propagates outward;
/// a following empty child does not make earlier padding permissible.
/// <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
fn walk<'a>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    bits: bool,
) -> Result<()> {
    walk_in(parent, element, field, bits, None, &parent.execution())
}

/// Uses the same walker with parser-bound scratch admission when preparation
/// belongs to the producing parse, rather than an independent retained query.
pub(crate) fn walk_in<'a, W: Work>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    bits: bool,
    output: Option<&mut OwnedVec<u8, W>>,
    execution: &W,
) -> Result<()> {
    walk_length(parent, element, field, bits, output, execution, |_, _| {
        Ok(())
    })
    .map(|_| ())
}

fn walk_length<'a, W: Work>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    bits: bool,
    mut output: Option<&mut OwnedVec<u8, W>>,
    execution: &W,
    mut on_bit: impl FnMut(Element<'a>, structured_asn1::BitString<'a>) -> Result<()>,
) -> Result<usize> {
    let mut length = 0;
    let mut frames = execution.vector();
    frames
        .try_push(Frame {
            reader: parent.enter(element).field(field)?,
            unused: 0,
        })
        .map_err(|reason| Error::resource(reason, field, element.span().start))?;
    let base = if bits {
        universal::BIT_STRING
    } else {
        universal::OCTET_STRING
    };
    while let Some(frame) = frames.last_mut() {
        frame.reader.charge(1).field(field)?;
        let Some(child) = frame.reader.next_element().field(field)? else {
            let unused = frame.unused;
            frames.pop();
            if let Some(outer) = frames.last_mut() {
                outer.unused = unused;
            }
            continue;
        };
        if frame.unused != 0
            || child.tag().class() != Class::Universal
            || child.tag().number() != Some(base)
        {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                field,
                child.span().start,
            ));
        }
        if child.tag().is_constructed() {
            let reader = frame.reader.enter(&child).field(field)?;
            frames
                .try_push(Frame { reader, unused: 0 })
                .map_err(|reason| Error::resource(reason, field, child.span().start))?;
        } else if bits {
            let bits = frame.reader.bit_string(&child).field(field)?;
            frame.unused = bits.unused_bits();
            on_bit(child, bits)?;
        } else {
            // Primitive fragments are disjoint subranges of this immutable
            // element. Their total cannot exceed its original contents size.
            debug_assert!(child.contents().len() <= element.contents().len() - length);
            length += child.contents().len();
            let Some(bytes) = output.as_deref_mut() else {
                continue;
            };
            // The caller's Work-backed output admits both copying and growth
            // before either begins. Producing paths pass Execution, so the
            // same charge reaches local and aggregate ceilings once. Retained
            // queries use their explicitly supplied current aggregate owner.
            bytes
                .try_extend_from_slice(child.contents())
                .map_err(|reason| Error::resource(reason, field, child.span().start))?;
        }
    }
    Ok(length)
}

pub(crate) fn bit_fragments<'a>(
    parent: &Reader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
    mut visitor: impl FnMut(Element<'a>, structured_asn1::BitString<'a>) -> Result<()>,
) -> Result<()> {
    if element.tag() == Tag::primitive(universal::BIT_STRING) {
        return visitor(*element, parent.bit_string(element).field(field)?);
    }
    if element.tag() != Tag::constructed(universal::BIT_STRING) || parent.encoding().is_der() {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    walk_length(
        parent,
        element,
        field,
        true,
        None,
        &parent.execution(),
        visitor,
    )
    .map(|_| ())
}
