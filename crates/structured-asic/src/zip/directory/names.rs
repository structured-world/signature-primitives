//! Exact pooled names, streaming UTF-8 inspection and paid name ordering.

use super::super::framing::{fixed_at, u32_at};
use super::{Entry, Fault, FaultKind, fault};
use crate::error::{Error, resource};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::{RangeSource, Window},
};

pub(super) async fn load<S: RangeSource, W: Work>(
    window: &mut Window<'_, S>,
    entries: &[Entry],
    names: &mut OwnedVec<u8, W>,
    faults: &mut OwnedVec<Fault, W>,
) -> Result<(), Error<S::Error>> {
    for (ordinal, entry) in entries.iter().enumerate() {
        let mut at = entry.name_span.start;
        while at < entry.name_span.end() {
            let bytes = window.chunk_at(at, entry.name_span.end()).await?;
            names
                .try_extend_from_slice(bytes)
                .map_err(|cause| resource(entry.name_span, cause))?;
            at += bytes.len() as u64;
        }
        let name = entry.name.get(names);
        window
            .execution()
            .charge_work(name.len() as u64 * 4 + 2)
            .map_err(|cause| resource(entry.name_span, cause))?;
        if core::str::from_utf8(name).is_err() {
            fault(faults, ordinal, entry.name_span, FaultKind::Utf8)?;
        }
        // APPNOTE6.3.3 §4.4.17.1 prohibits drive/device prefixes, leading
        // slashes and backslashes. Dot components are retained, not normalized
        // or rejected by an operating-system extraction policy.
        if name.is_empty()
            || name[0] == b'/'
            || name.contains(&b'\\')
            || (name.len() > 1 && name[1] == b':')
        {
            fault(faults, ordinal, entry.name_span, FaultKind::Name)?;
        }
        if entry.flags & 0x0800 == 0 && !name.is_ascii() {
            fault(faults, ordinal, entry.name_span, FaultKind::IsoProfile)?;
        }
        match text(window, entry.comment).await? {
            Text::Malformed => fault(faults, ordinal, entry.comment, FaultKind::Utf8)?,
            Text::Unicode if entry.flags & 0x0800 == 0 => {
                // APPNOTE6.3.3 Appendix D: bit11 applies to BOTH filename
                // and comment, not merely to the original File Name field.
                fault(faults, ordinal, entry.comment, FaultKind::IsoProfile)?;
            }
            Text::Ascii | Text::Unicode => {}
        }
        if let Some(span) = entry.unicode
            && !unicode(window, span, name).await?
        {
            fault(faults, ordinal, span, FaultKind::UnicodeName)?;
        }
    }
    Ok(())
}

pub(super) enum Text {
    Ascii,
    Unicode,
    Malformed,
}

pub(super) async fn text<S: RangeSource>(
    window: &mut Window<'_, S>,
    range: Span,
) -> Result<Text, Error<S::Error>> {
    let work = window.execution();
    let mut pending = [0_u8; 4];
    let mut used = 0;
    let mut ascii = true;
    let mut at = range.start;
    while at < range.end() {
        let bytes = window.chunk_at(at, range.end()).await?;
        work.charge_work(bytes.len() as u64 * 4 + 1)
            .map_err(|cause| resource(range, cause))?;
        at += bytes.len() as u64;
        if used == 0 && bytes.is_ascii() {
            continue;
        }
        ascii = false;
        let mut start = 0;
        while used != 0 && start < bytes.len() {
            pending[used] = bytes[start];
            used += 1;
            start += 1;
            match core::str::from_utf8(&pending[..used]) {
                Ok(_) => used = 0,
                Err(error) if error.error_len().is_some() => return Ok(Text::Malformed),
                Err(_) => debug_assert!(used < 4),
            }
        }
        if start == bytes.len() {
            continue;
        }
        match core::str::from_utf8(&bytes[start..]) {
            Ok(_) => {}
            Err(error) if error.error_len().is_some() => return Ok(Text::Malformed),
            Err(error) => {
                let tail = &bytes[start + error.valid_up_to()..];
                debug_assert!(tail.len() < 4);
                pending[..tail.len()].copy_from_slice(tail);
                used = tail.len();
            }
        }
    }
    Ok(if used != 0 {
        Text::Malformed
    } else if ascii {
        Text::Ascii
    } else {
        Text::Unicode
    })
}

pub(super) async fn unicode<S: RangeSource>(
    window: &mut Window<'_, S>,
    range: Span,
    name: &[u8],
) -> Result<bool, Error<S::Error>> {
    if range.length < 5 {
        return Ok(false);
    }
    let header = fixed_at::<5, _>(window, range.start, range.end()).await?;
    // APPNOTE6.3.3 §4.6.9: unknown versions and stale CRCs are ignored,
    // never substituted for the actual original File Name field.
    if header[0] != 1 {
        return Ok(true);
    }
    window
        .execution()
        .charge_work(name.len() as u64)
        .map_err(|cause| resource(range, cause))?;
    if crc32fast::hash(name) != u32_at(&header, 1) {
        return Ok(true);
    }
    equal(
        window,
        Span {
            start: range.start + 5,
            length: range.length - 5,
        },
        name,
    )
    .await
}

pub(super) async fn equal<S: RangeSource>(
    window: &mut Window<'_, S>,
    range: Span,
    expected: &[u8],
) -> Result<bool, Error<S::Error>> {
    if range.length != expected.len() as u64 {
        return Ok(false);
    }
    let work = window.execution();
    let mut at = range.start;
    let mut compared = 0;
    while at < range.end() {
        let bytes = window.chunk_at(at, range.end()).await?;
        work.charge_work(bytes.len() as u64 * 2 + 1)
            .map_err(|cause| resource(range, cause))?;
        if bytes != &expected[compared..compared + bytes.len()] {
            return Ok(false);
        }
        at += bytes.len() as u64;
        compared += bytes.len();
    }
    Ok(true)
}

pub(super) fn order<E, W: Work>(
    entries: &[Entry],
    names: &[u8],
    order: &mut OwnedVec<usize, W>,
    faults: &mut OwnedVec<Fault, W>,
    work: &W,
    range: Span,
) -> Result<(), Error<E>> {
    order
        .try_sort_unstable_by(|left, right| {
            let a = entries[*left].name.get(names);
            let b = entries[*right].name.get(names);
            work.charge_work(a.len().min(b.len()) as u64 + 1)?;
            Ok::<_, structured_asn1::memory::MemoryError>(a.cmp(b).then_with(|| left.cmp(right)))
        })
        .map_err(|cause| resource(range, cause.into()))?;
    let mut duplicate = false;
    for position in 1..order.len() {
        let a = &entries[order[position - 1]];
        let b = &entries[order[position]];
        work.charge_work(a.name.length.min(b.name.length) as u64 + 1)
            .map_err(|cause| resource(range, cause))?;
        if a.name.get(names) == b.name.get(names) {
            if !duplicate {
                fault(
                    faults,
                    order[position - 1],
                    a.name_span,
                    FaultKind::DuplicateName,
                )?;
            }
            fault(
                faults,
                order[position],
                b.name_span,
                FaultKind::DuplicateName,
            )?;
            duplicate = true;
        } else {
            duplicate = false;
        }
    }
    Ok(())
}
