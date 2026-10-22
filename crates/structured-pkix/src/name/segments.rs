//! The one iterative BER base-string walker used by validation and codecs.

use super::{AttributeValue, Encoding, Error, ErrorCode, Located, OwnedVec, Result, Strings};
use structured_asn1::memory::Work;
use structured_asn1::{Class, Element, ScopedReader as Reader, Tag, universal};

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
        let mut contents = execution.vector();
        walk_in(
            parent,
            element,
            field,
            false,
            Some(&mut contents),
            &execution,
        )?;
        let work = (contents.len() as u64).checked_mul(3).ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                element.span().start,
            )
        })?;
        parent.charge(work).field(field)?;
        let value = AttributeValue {
            tag: Tag::primitive(number),
            contents: &contents,
            der: element.as_bytes(),
            offset: element.span().start,
            depth: parent.depth(),
        };
        let valid = if time {
            crate::time::ber_fits(&contents, number == universal::GENERALIZED_TIME)
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
    mut output: Option<&mut OwnedVec<u8, W>>,
    execution: &W,
) -> Result<()> {
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
            frame.reader.bit_string(&child).field(field)?;
            frame.unused = child.contents()[0];
        } else if let Some(bytes) = output.as_deref_mut() {
            // The caller's Work-backed output admits both copying and growth
            // before either begins. Producing paths pass Execution, so the
            // same charge reaches local and aggregate ceilings once. Retained
            // queries use their explicitly supplied current aggregate owner.
            bytes
                .try_extend_from_slice(child.contents())
                .map_err(|reason| Error::resource(reason, field, child.span().start))?;
        }
    }
    Ok(())
}
