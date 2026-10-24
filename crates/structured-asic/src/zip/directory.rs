//! Complete central-directory framing, pooled names and local-record binding.

use super::framing::{Cursor, u16_at, u32_at};
use super::{Archive, Bytes, Entry, Fault, FaultKind};
use crate::{
    Session,
    error::{Error, Syntax, resource, syntax},
};
use structured_asn1::{
    Span,
    memory::{Execution, MemoryError, OwnedVec, Work},
    range::{RangeSource, Stamp, Window},
};

mod end;
mod extra;
mod local;
mod names;

pub(super) async fn read<'s, S: RangeSource, W: Work>(
    source: &'s S,
    session: &'s Session,
    current: &W,
) -> Result<Archive<'s, S>, Error<S::Error>> {
    let stamp = source.stamp();
    let work = session.query(current);
    let whole = Span {
        start: 0,
        length: stamp.length,
    };
    let window = Window::new(source, stamp, whole, work)?;
    let mut cursor = Cursor {
        window,
        at: 0,
        end: stamp.length,
    };
    let candidates = end::candidates(&mut cursor.window, &work).await?;
    let mut selected = None;
    let mut last = None;
    for at in candidates {
        work.charge_work(1)
            .map_err(|cause| resource(whole, cause))?;
        let directory = match end::read(&mut cursor, at).await {
            Ok(directory) => directory,
            Err(cause @ (Error::Syntax { .. } | Error::Unsupported { .. })) => {
                last = Some(cause);
                continue;
            }
            Err(cause) => return Err(cause),
        };
        match catalogue(source, session, stamp, &work, directory, &mut cursor.window).await {
            Ok(archive) => {
                if selected.is_some() {
                    return Err(syntax(
                        Span {
                            start: at,
                            length: 22,
                        },
                        Syntax::AmbiguousDirectory,
                    ));
                }
                selected = Some(archive);
            }
            Err(cause @ (Error::Syntax { .. } | Error::Unsupported { .. })) => last = Some(cause),
            Err(cause) => return Err(cause),
        }
    }
    match selected {
        Some(archive) => {
            archive.admit(&work, whole)?;
            Ok(archive)
        }
        None => Err(last.unwrap_or_else(|| syntax(whole, Syntax::End))),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the central-directory transaction retains pooled names and exact local associations together, and returns no partial catalogue on refusal"
)]
async fn catalogue<'s, S: RangeSource>(
    source: &'s S,
    session: &'s Session,
    stamp: Stamp<S::Document, S::Generation>,
    work: &Execution<'_>,
    directory: end::Directory,
    original: &mut Window<'_, S>,
) -> Result<Archive<'s, S>, Error<S::Error>> {
    let range = directory.range;
    if directory.count > range.length / 46 {
        return Err(syntax(range, Syntax::Directory));
    }
    session.entries(directory.count, range)?;
    let count = usize::try_from(directory.count)
        .map_err(|_| resource(range, MemoryError::LimitExceeded))?;
    let mut entries = work.vector();
    entries
        .try_reserve_exact(count)
        .map_err(|cause| resource(range, cause))?;
    let mut faults = work.vector();
    if matches!(
        names::text(original, directory.comment).await?,
        names::Text::Malformed
    ) {
        faults
            .try_push(Fault {
                member: None,
                range: directory.comment,
                kind: FaultKind::Utf8,
            })
            .map_err(|cause| resource(directory.comment, cause))?;
    }
    let mut cursor = Cursor {
        window: Window::new(source, stamp, range, *work)?,
        at: range.start,
        end: range.end(),
    };
    let mut name_bytes = 0_usize;
    for ordinal in 0..count {
        let mut entry = central(&mut cursor).await?;
        entry.name = Bytes {
            start: name_bytes,
            length: usize::try_from(entry.name_span.length)
                .map_err(|_| resource(entry.name_span, MemoryError::LimitExceeded))?,
        };
        name_bytes = name_bytes
            .checked_add(entry.name.length)
            .ok_or_else(|| resource(entry.name_span, MemoryError::LimitExceeded))?;
        extra::central(&mut cursor, &mut entry).await?;
        if entry.method == 0 && entry.compressed != entry.decoded {
            entry.readable = false;
            fault(&mut faults, ordinal, entry.central, FaultKind::StoredLength)?;
        }
        if entry.flags & 0x2041 != 0 {
            entry.readable = false;
            fault(&mut faults, ordinal, entry.central, FaultKind::Encrypted)?;
        }
        if entry.method != 0 && entry.method != 8 {
            fault(&mut faults, ordinal, entry.central, FaultKind::Compression)?;
        }
        // ISO21320-1:2015 table1 restricts these capabilities only for the
        // baseline profile, independently of general ASiC inspection.
        if entry.needed > 45
            || entry.flags & 0xf7f1 != 0
            || (entry.method != 0 && entry.method != 8)
        {
            fault(&mut faults, ordinal, entry.central, FaultKind::IsoProfile)?;
        }
        entries
            .try_push(entry)
            .map_err(|cause| resource(range, cause))?;
    }
    if cursor.at != cursor.end {
        let start = cursor.at;
        let signature = cursor.fixed::<6>().await?;
        if u32_at(&signature, 0) != 0x0505_4b50 {
            return Err(syntax(range, Syntax::Directory));
        }
        cursor.skip(u64::from(u16_at(&signature, 4)))?;
        if cursor.at != cursor.end {
            return Err(syntax(range, Syntax::Directory));
        }
        faults
            .try_push(Fault {
                member: None,
                range: Span {
                    start,
                    length: cursor.at - start,
                },
                kind: FaultKind::DirectorySignature,
            })
            .map_err(|cause| resource(range, cause))?;
    }
    let mut names = work.vector();
    names
        .try_reserve_exact(name_bytes)
        .map_err(|cause| resource(range, cause))?;
    names::load(&mut cursor.window, &entries, &mut names, &mut faults).await?;
    let mut order = work.vector();
    order
        .try_reserve_exact(count)
        .map_err(|cause| resource(range, cause))?;
    for ordinal in 0..count {
        order
            .try_push(ordinal)
            .map_err(|cause| resource(range, cause))?;
    }
    local::physical_order(&entries, &mut order, work, range)?;
    let whole = Span {
        start: 0,
        length: range.start,
    };
    let original = Window::new(source, stamp, whole, *work)?;
    local::bind(original, &mut entries, &order, &names, &mut faults).await?;
    local::overlaps(&mut entries, &order, &mut faults, work, range)?;
    names::order(&entries, &names, &mut order, &mut faults, work, range)?;
    Ok(Archive {
        source,
        session,
        stamp,
        directory: range,
        comment: directory.comment,
        entries: entries.into_owned(),
        names: names.into_owned(),
        order: order.into_owned(),
        faults: faults.into_owned(),
    })
}

async fn central<S: RangeSource>(cursor: &mut Cursor<'_, S>) -> Result<Entry, Error<S::Error>> {
    let start = cursor.at;
    let fixed = cursor.fixed::<46>().await?;
    if u32_at(&fixed, 0) != 0x0201_4b50 {
        return Err(syntax(Span { start, length: 46 }, Syntax::Directory));
    }
    let name_span = cursor.skip(u64::from(u16_at(&fixed, 28)))?;
    let extra = cursor.skip(u64::from(u16_at(&fixed, 30)))?;
    let comment = cursor.skip(u64::from(u16_at(&fixed, 32)))?;
    Ok(Entry {
        central: Span {
            start,
            length: cursor.at - start,
        },
        name_span,
        extra,
        comment,
        name: Bytes {
            start: 0,
            length: 0,
        },
        needed: u16_at(&fixed, 6),
        flags: u16_at(&fixed, 8),
        method: u16_at(&fixed, 10),
        crc: u32_at(&fixed, 16),
        compressed: u64::from(u32_at(&fixed, 20)),
        decoded: u64::from(u32_at(&fixed, 24)),
        local: u64::from(u32_at(&fixed, 42)),
        data: None,
        enclosure: None,
        local_extra: None,
        zip64: false,
        readable: true,
        disk: u32::from(u16_at(&fixed, 34)),
        unicode: None,
        overlap: false,
    })
}

fn fault<E, W: Work>(
    faults: &mut OwnedVec<Fault, W>,
    ordinal: usize,
    range: Span,
    kind: FaultKind,
) -> Result<(), Error<E>> {
    faults
        .try_push(Fault {
            member: Some(ordinal),
            range,
            kind,
        })
        .map_err(|cause| resource(range, cause))
}
