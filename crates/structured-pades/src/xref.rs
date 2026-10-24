//! Cross-reference records retain historical revision and original row identity.
//!
//! ISO 32000-1:2008 §§7.5.4 and 7.5.8 define the fixed-width table records
//! and stream replacement. Resolution selects the latest entry, including a
//! free entry, before checking generation; it never falls back to an old key.

use crate::arena::{Arena, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, get, required, unsigned};
use crate::range::RangeSource;
use crate::source::Location;
use crate::syntax::{Cursor, read_into};
use structured_asn1::memory::{Memory, OwnedVec, Work};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Free { next: u64, generation: u16 },
    File { offset: u64, generation: u16 },
    Compressed { stream: u64, index: u64 },
    Null,
}

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub(crate) number: u64,
    pub(crate) revision: usize,
    pub(crate) target: Target,
    pub(crate) location: Location,
    pub(crate) priority: u8,
}

#[derive(Clone, Copy)]
pub(crate) struct Section {
    pub(crate) trailer: NodeId,
    pub(crate) previous: Option<u64>,
    pub(crate) hybrid: Option<u64>,
    pub(crate) end: u64,
    pub(crate) length: Option<DeferredLength>,
}

#[derive(Clone, Copy)]
pub(crate) struct DeferredLength {
    pub(crate) number: u64,
    pub(crate) generation: u16,
    pub(crate) actual: u64,
    pub(crate) revision: usize,
    pub(crate) location: Location,
}

pub(crate) async fn table<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    arena: Arena<Memory>,
    entries: &mut OwnedVec<Entry, W>,
    revision: usize,
    priority: u8,
) -> Result<(Arena<Memory>, Section), ReadFailure<S::Error>> {
    cursor.keyword(b"xref").await?;
    let work = cursor.reader.execution();
    let first_entry = entries.len();
    loop {
        cursor.skip().await?;
        if cursor.looking(b"trailer").await? {
            break;
        }
        let start = cursor.natural().await?;
        let gap = cursor.at;
        cursor.space().await?;
        if cursor.at == gap {
            return Err(cursor.failure(Syntax::CrossReference, gap));
        }
        let count = cursor.natural().await?;
        let end = start
            .checked_add(count)
            .ok_or_else(|| cursor.failure(Syntax::CrossReference, gap))?;
        // A record occupies exactly 20 bytes. Reject impossible counts before
        // reserving storage or scanning attacker-controlled declared rows.
        cursor.space().await?;
        let remaining = cursor.reader.stamp().length - cursor.at;
        if count > remaining / 20 {
            return Err(cursor.failure(Syntax::CrossReference, cursor.at));
        }
        for number in start..end {
            let at = cursor.at;
            cursor.reader.session().object(cursor.location(at, 20))?;
            let mut row = [0_u8; 20];
            for byte in &mut row {
                *byte = cursor
                    .take()
                    .await?
                    .ok_or_else(|| cursor.failure(Syntax::CrossReference, cursor.at))?;
            }
            if row[10] != b' '
                || row[16] != b' '
                || !matches!(&row[18..], b"\r\n" | b" \n" | b" \r")
            {
                return Err(cursor.failure(Syntax::CrossReference, at));
            }
            let offset =
                decimal(&row[..10]).ok_or_else(|| cursor.failure(Syntax::CrossReference, at))?;
            let generation = decimal(&row[11..16])
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| cursor.failure(Syntax::CrossReference, at + 11))?;
            let target = match row[17] {
                b'n' => Target::File { offset, generation },
                b'f' => Target::Free {
                    next: offset,
                    generation,
                },
                _ => return Err(cursor.failure(Syntax::CrossReference, at + 17)),
            };
            let location = cursor.location(at, 20);
            entries
                .try_push(Entry {
                    number,
                    revision,
                    target,
                    location,
                    priority,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
        }
    }
    cursor.keyword(b"trailer").await?;
    let session = cursor.reader.session();
    let (arena, trailer) = read_into(cursor, session, arena).await?;
    let size = unsigned(&arena, required(&arena, trailer, b"Size", &work)?, &work)?;
    for entry in &entries[first_entry..] {
        admit(&work, entry.location, 1)?;
        if entry.number >= size {
            return Err(cursor.failure(Syntax::CrossReference, entry.location.span().start));
        }
    }
    let previous = get(&arena, trailer, b"Prev", &work)?
        .map(|node| unsigned(&arena, node, &work))
        .transpose()?;
    let hybrid = get(&arena, trailer, b"XRefStm", &work)?
        .map(|node| unsigned(&arena, node, &work))
        .transpose()?;
    let section = Section {
        trailer,
        previous,
        hybrid,
        end: cursor.at,
        length: None,
    };
    Ok((arena, section))
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u64::from(byte - b'0');
    }
    Some(value)
}

pub(crate) async fn stream<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    arena: Arena<Memory>,
    entries: &mut OwnedVec<Entry, W>,
    revision: usize,
    priority: u8,
) -> Result<(Arena<Memory>, Section), ReadFailure<S::Error>> {
    let work = cursor.reader.execution();
    let (arena, object) = crate::stream::open(cursor, arena).await?;
    let dictionary = object.value;
    let location = arena.nodes[dictionary.0].location;
    let Some(start) = object.stream else {
        return Err(cursor.failure(Syntax::CrossReference, object.start));
    };
    if !crate::model::named(
        &arena,
        required(&arena, dictionary, b"Type", &work)?,
        b"XRef",
        &work,
    )? {
        return Err(cursor.failure(Syntax::CrossReference, object.start));
    }
    let size = unsigned(&arena, required(&arena, dictionary, b"Size", &work)?, &work)?;
    let widths = numbers(&arena, required(&arena, dictionary, b"W", &work)?, &work)?;
    if widths.len() != 3 {
        return Err(cursor.failure(Syntax::CrossReference, object.start));
    }
    let mut index = if let Some(node) = get(&arena, dictionary, b"Index", &work)? {
        numbers(&arena, node, &work)?
    } else {
        let mut index = work.vector();
        index
            .try_push(0)
            .and_then(|()| index.try_push(size))
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        index
    };
    if index.is_empty() || index.len() % 2 != 0 {
        return Err(cursor.failure(Syntax::CrossReference, object.start));
    }
    let row = widths[0]
        .checked_add(widths[1])
        .and_then(|value| value.checked_add(widths[2]))
        .ok_or_else(|| cursor.failure(Syntax::CrossReference, object.start))?;
    if row == 0 {
        return Err(cursor.failure(Syntax::CrossReference, object.start));
    }
    let mut count = 0_u64;
    let mut previous_end = 0;
    for pair in index.as_chunks_mut::<2>().0 {
        admit(&work, location, 1)?;
        let end = pair[0]
            .checked_add(pair[1])
            .ok_or_else(|| cursor.failure(Syntax::CrossReference, object.start))?;
        if pair[0] < previous_end || end > size {
            return Err(cursor.failure(Syntax::CrossReference, object.start));
        }
        previous_end = end;
        count = count
            .checked_add(pair[1])
            .ok_or_else(|| cursor.failure(Syntax::CrossReference, object.start))?;
    }
    let expected = row
        .checked_mul(count)
        .ok_or_else(|| cursor.failure(Syntax::CrossReference, object.start))?;
    let StreamBody {
        body,
        decoded,
        length,
    } = stream_body(cursor, &arena, dictionary, start, expected, revision, &work).await?;
    if decoded.len() as u64 != expected {
        return Err(cursor.failure(Syntax::CrossReference, start));
    }
    stream_rows(
        cursor,
        &decoded,
        entries,
        StreamLayout {
            widths: &widths,
            index: &index,
            row,
            body,
            revision,
            priority,
        },
        &work,
    )?;
    let previous = get(&arena, dictionary, b"Prev", &work)?
        .map(|node| unsigned(&arena, node, &work))
        .transpose()?;
    Ok((
        arena,
        Section {
            trailer: dictionary,
            previous,
            hybrid: None,
            end: cursor.at,
            length,
        },
    ))
}

struct StreamBody {
    body: structured_asn1::Span,
    decoded: OwnedVec<u8, Memory>,
    length: Option<DeferredLength>,
}

async fn stream_body<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    arena: &Arena<Memory>,
    dictionary: NodeId,
    start: u64,
    expected: u64,
    revision: usize,
    work: &impl Work,
) -> Result<StreamBody, ReadFailure<S::Error>> {
    let length_node = required(arena, dictionary, b"Length", work)?;
    // Table 17 requires its own fields and filter controls to be direct,
    // but Table 5 still permits an indirect Length. Decode to the filter's
    // explicit end, then validate that reference against the completed index.
    // ISO 32000-1:2008 §7.5.8.2 and Tables 5/17.
    let (body, decoded, length) = if let crate::arena::Kind::Reference { number, generation } =
        arena.nodes[length_node.0].kind
    {
        let filtered = get(arena, dictionary, b"Filter", work)?.is_some();
        let available = if filtered {
            cursor.reader.stamp().length - start
        } else {
            expected
        };
        let extent = structured_asn1::Span {
            start,
            length: available,
        };
        let (decoded, actual) = crate::stream::decoded_extent(
            &mut cursor.reader,
            extent,
            arena,
            dictionary,
            revision,
            false,
        )
        .await?;
        let body = crate::stream::close(cursor, start, actual).await?;
        (
            body,
            decoded,
            Some(DeferredLength {
                number,
                generation,
                actual,
                revision,
                location: arena.nodes[length_node.0].location,
            }),
        )
    } else {
        let length = unsigned(arena, length_node, work)?;
        let body = crate::stream::close(cursor, start, length).await?;
        let decoded =
            crate::stream::decoded(&mut cursor.reader, body, arena, dictionary, revision).await?;
        (body, decoded, None)
    };
    Ok(StreamBody {
        body,
        decoded,
        length,
    })
}

#[derive(Clone, Copy)]
struct StreamLayout<'a> {
    widths: &'a [u64],
    index: &'a [u64],
    row: u64,
    body: structured_asn1::Span,
    revision: usize,
    priority: u8,
}

fn stream_rows<S: RangeSource, W: Work>(
    cursor: &Cursor<'_, S>,
    decoded: &[u8],
    entries: &mut OwnedVec<Entry, W>,
    layout: StreamLayout<'_>,
    work: &impl Work,
) -> Result<(), ReadFailure<S::Error>> {
    let StreamLayout {
        widths,
        index,
        row,
        body,
        revision,
        priority,
    } = layout;
    let start = body.start;
    let mut at = 0;
    for pair in index.as_chunks::<2>().0 {
        for number in pair[0]..pair[0] + pair[1] {
            let place = crate::source::Location::new(
                crate::source::Source::Decoded {
                    stream: body,
                    revision,
                    stage: 0,
                },
                at as u64,
                row,
            )
            .expect("validated decoded row");
            cursor.reader.session().object(place)?;
            admit(work, place, row)?;
            let mut fields = [0_u64; 3];
            let type_width = usize::try_from(widths[0])
                .map_err(|_| cursor.failure(Syntax::CrossReference, start))?;
            let mut kind = u16::from(type_width == 0);
            for &byte in &decoded[at..at + type_width] {
                if kind <= 2 {
                    kind = kind * 256 + u16::from(byte);
                }
            }
            at += type_width;
            for (field, &width) in fields[1..].iter_mut().zip(widths[1..].iter()) {
                let width = usize::try_from(width)
                    .map_err(|_| cursor.failure(Syntax::CrossReference, start))?;
                if kind <= 2 {
                    for &byte in &decoded[at..at + width] {
                        *field = field
                            .checked_mul(256)
                            .and_then(|value| value.checked_add(u64::from(byte)))
                            .ok_or(Error {
                                kind: ErrorKind::Unsupported(
                                    crate::error::Unsupported::NumericRange,
                                ),
                                location: place,
                            })?;
                    }
                }
                at += width;
            }
            let target = match kind {
                0 => Target::Free {
                    next: fields[1],
                    generation: u16::try_from(fields[2])
                        .map_err(|_| cursor.failure(Syntax::CrossReference, start))?,
                },
                1 => Target::File {
                    offset: fields[1],
                    generation: u16::try_from(fields[2])
                        .map_err(|_| cursor.failure(Syntax::CrossReference, start))?,
                },
                2 => Target::Compressed {
                    stream: fields[1],
                    index: fields[2],
                },
                // §7.5.8.3 explicitly gives unknown future entry types null
                // semantics, rather than a fallback to a preceding revision.
                _ => Target::Null,
            };
            entries
                .try_push(Entry {
                    number,
                    revision,
                    target,
                    location: place,
                    priority,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: place,
                })?;
        }
    }
    Ok(())
}

fn numbers<W: Work, Q: Work>(
    arena: &Arena<W>,
    node: NodeId,
    work: &Q,
) -> crate::Result<OwnedVec<u64, Q>> {
    let location = arena.nodes[node.0].location;
    let crate::arena::Kind::Array(children) = arena.nodes[node.0].kind else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::CrossReference),
            location,
        });
    };
    let mut output = work.vector();
    let mut next = children.first;
    while let Some(index) = next {
        admit(work, location, 1)?;
        let link = arena.links[index];
        output
            .try_push(unsigned(arena, link.value, work)?)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        next = link.next;
    }
    Ok(output)
}
