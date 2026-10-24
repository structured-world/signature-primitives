//! Original local records and descriptor interpretations, not extracted paths.

use super::super::framing::{Cursor, fixed_at, u16_at, u32_at, u64_at};
use super::{Entry, Fault, FaultKind, extra, fault, names};
use crate::error::{Error, Syntax, resource, syntax};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::{RangeSource, Window},
};

pub(super) async fn bind<S: RangeSource, W: Work>(
    window: Window<'_, S>,
    entries: &mut [Entry],
    order: &[usize],
    names: &[u8],
    faults: &mut OwnedVec<Fault, W>,
) -> Result<(), Error<S::Error>> {
    let work = window.execution();
    let end = window.bounds().end();
    let mut cursor = Cursor { window, at: 0, end };
    for ordinal in order.iter().copied() {
        let entry = &mut entries[ordinal];
        work.charge_work(1)
            .map_err(|cause| resource(entry.central, cause))?;
        cursor.end = end;
        match record(&mut cursor, entry, names).await {
            Ok(()) => {}
            Err(Error::Syntax { kind, range }) => {
                entry.readable = false;
                fault(
                    faults,
                    ordinal,
                    range,
                    if kind == Syntax::Local {
                        FaultKind::LocalMismatch
                    } else {
                        FaultKind::LocalBounds
                    },
                )?;
            }
            Err(cause) => return Err(cause),
        }
    }
    Ok(())
}

async fn record<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    entry: &mut Entry,
    names: &[u8],
) -> Result<(), Error<S::Error>> {
    cursor.at = entry.local;
    let fixed = cursor.fixed::<30>().await?;
    let header = Span {
        start: entry.local,
        length: 30,
    };
    if u32_at(&fixed, 0) != 0x0403_4b50 {
        return Err(syntax(header, Syntax::Local));
    }
    let name = cursor.skip(u64::from(u16_at(&fixed, 26)))?;
    let fields = cursor.skip(u64::from(u16_at(&fixed, 28)))?;
    entry.local_extra = Some(fields);
    let at = cursor.at;
    if at > cursor.end || entry.compressed > cursor.end - at {
        return Err(syntax(header, Syntax::Bounds));
    }
    let data = Span {
        start: at,
        length: entry.compressed,
    };
    entry.data = Some(data);
    let local = extra::local(cursor, fields, u32_at(&fixed, 22), u32_at(&fixed, 18)).await?;
    let mut end = data.end();
    let descriptor = entry.flags & 8 != 0;
    if descriptor {
        end = description(&mut cursor.window, entry, end, local.zip64 || entry.zip64).await?;
    }
    entry.enclosure = Some(Span {
        start: entry.local,
        length: end - entry.local,
    });
    if u16_at(&fixed, 4) != entry.needed
        || u16_at(&fixed, 6) != entry.flags
        || u16_at(&fixed, 8) != entry.method
        || !names::equal(&mut cursor.window, name, entry.name.get(names)).await?
    {
        return Err(syntax(header, Syntax::Local));
    }
    if let Some(span) = local.unicode
        && !names::unicode(&mut cursor.window, span, entry.name.get(names)).await?
    {
        return Err(syntax(span, Syntax::Local));
    }
    if !descriptor
        && (u32_at(&fixed, 14) != entry.crc
            || local.compressed != entry.compressed
            || local.decoded != entry.decoded)
    {
        return Err(syntax(header, Syntax::Local));
    }
    if descriptor
        && ((u32_at(&fixed, 14) != 0 && u32_at(&fixed, 14) != entry.crc)
            || (local.compressed != 0 && local.compressed != entry.compressed)
            || (local.decoded != 0 && local.decoded != entry.decoded))
    {
        return Err(syntax(header, Syntax::Local));
    }
    Ok(())
}

async fn description<S: RangeSource>(
    window: &mut Window<'_, S>,
    entry: &Entry,
    at: u64,
    zip64: bool,
) -> Result<u64, Error<S::Error>> {
    // APPNOTE6.3.3 §§4.3.9.2-4: the signature is optional. A CRC can itself
    // equal 0x08074b50, so both complete interpretations must be considered.
    let end = window.bounds().end();
    let size = if zip64 { 20 } else { 12 };
    let mut unsigned = false;
    let mut signed = false;
    if at <= end && size <= end - at {
        if zip64 {
            let bytes = fixed_at::<20, _>(window, at, end).await?;
            unsigned = matches_description(&bytes, entry, true);
        } else {
            let bytes = fixed_at::<12, _>(window, at, end).await?;
            unsigned = matches_description(&bytes, entry, false);
        }
    }
    if at <= end && size + 4 <= end - at {
        let marker = fixed_at::<4, _>(window, at, end).await?;
        if u32_at(&marker, 0) == 0x0807_4b50 {
            if zip64 {
                let bytes = fixed_at::<20, _>(window, at + 4, end).await?;
                signed = matches_description(&bytes, entry, true);
            } else {
                let bytes = fixed_at::<12, _>(window, at + 4, end).await?;
                signed = matches_description(&bytes, entry, false);
            }
        }
    }
    if unsigned == signed {
        return Err(syntax(
            Span {
                start: at,
                length: 0,
            },
            Syntax::Local,
        ));
    }
    Ok(at + size + if signed { 4 } else { 0 })
}

fn matches_description(bytes: &[u8], entry: &Entry, zip64: bool) -> bool {
    if u32_at(bytes, 0) != entry.crc {
        return false;
    }
    if zip64 {
        u64_at(bytes, 4) == entry.compressed && u64_at(bytes, 12) == entry.decoded
    } else {
        u64::from(u32_at(bytes, 4)) == entry.compressed
            && u64::from(u32_at(bytes, 8)) == entry.decoded
    }
}

pub(super) fn physical_order<E, W: Work>(
    entries: &[Entry],
    order: &mut OwnedVec<usize, W>,
    work: &W,
    range: Span,
) -> Result<(), Error<E>> {
    let mut sorted = true;
    for ordinal in 1..entries.len() {
        work.charge_work(1)
            .map_err(|cause| resource(range, cause))?;
        if entries[ordinal - 1].local > entries[ordinal].local {
            sorted = false;
            break;
        }
    }
    if sorted {
        return Ok(());
    }
    order
        .try_sort_unstable_by(|left, right| {
            let a = entries[*left].local;
            let b = entries[*right].local;
            Ok::<_, structured_asn1::memory::MemoryError>(a.cmp(&b).then_with(|| left.cmp(right)))
        })
        .map_err(|cause| resource(range, cause.into()))?;
    Ok(())
}

pub(super) fn overlaps<E, W: Work>(
    entries: &mut [Entry],
    order: &[usize],
    faults: &mut OwnedVec<Fault, W>,
    work: &W,
    range: Span,
) -> Result<(), Error<E>> {
    let mut preceding: Option<usize> = None;
    for ordinal in order.iter().copied() {
        work.charge_work(1)
            .map_err(|cause| resource(range, cause))?;
        let Some(span) = entries[ordinal].enclosure else {
            continue;
        };
        if let Some(previous) = preceding {
            let before = entries[previous]
                .enclosure
                .expect("selected complete enclosure");
            if span.start < before.end() {
                for selected in [previous, ordinal] {
                    if !entries[selected].overlap {
                        fault(
                            faults,
                            selected,
                            entries[selected].enclosure.expect("complete enclosure"),
                            FaultKind::Overlap,
                        )?;
                        entries[selected].overlap = true;
                    }
                    entries[selected].readable = false;
                }
            }
            if before.end() >= span.end() {
                continue;
            }
        }
        preceding = Some(ordinal);
    }
    Ok(())
}
