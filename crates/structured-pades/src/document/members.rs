//! Full object-stream census with one decoded owner and one flat member arena.

use super::{Document, Reading};
use crate::{
    arena::{Arena, NodeId},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    model::admit,
    object::Value,
    range::{RangeReader, RangeSource, Slice},
    source::{Location, Source},
    syntax::{Cursor, read_into},
};
use structured_asn1::{
    Span,
    memory::{HashWork, Memory, MemoryError, OwnedVec, Work},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Number(u64);
impl HashWork for Number {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

pub(super) struct Member {
    pub(super) number: u64,
    pub(super) root: NodeId,
    pub(super) nodes: core::ops::Range<usize>,
}

pub(super) struct Slot {
    pub(super) number: u64,
    pub(super) span: Span,
}

impl<'s, S: RangeSource> Document<'s, S> {
    pub(super) async fn all_members<W: Work>(
        &self,
        container: &Reading<'s, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<
        Option<(
            Reading<'s, S::Document, S::Generation>,
            OwnedVec<Member, Memory>,
        )>,
        ReadFailure<S::Error>,
    > {
        let work = self.session.query(operation);
        let decoded = self.stream_data(container, true, &work).await?;
        let body = decoded.body;
        let (count, first) = decoded.layout.expect("object-stream controls");
        let decoded = decoded.bytes;
        let (value, members) = group(
            self.session,
            self.stamp,
            &decoded,
            body,
            (count, first),
            container.revision,
            &work,
        )
        .await
        .map_err(super::resolve::convert)?;
        let Some(value) = value else { return Ok(None) };
        Ok(Some((
            Reading {
                value,
                decoded: Some(decoded),
                stream: None,
                number: container.number,
                generation: container.generation,
                revision: container.revision,
            },
            members,
        )))
    }
}

fn directory_bounds(
    length: u64,
    count: u64,
    first: u64,
    domain: Source,
) -> crate::Result<Location> {
    let location = Location::new(domain, 0, length).expect("decoded extent");
    if first > length || count > first / 4 {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        });
    }
    Ok(location)
}

pub(super) async fn directory<D: Copy + Eq, G: Copy + Eq>(
    session: &crate::Session,
    stamp: crate::range::Stamp<D, G>,
    decoded: &[u8],
    body: Span,
    (count, first): (u64, u64),
    revision: usize,
    work: &impl Work,
) -> Result<OwnedVec<Slot>, ReadFailure<core::convert::Infallible>> {
    let domain = Source::Decoded {
        stream: body,
        revision,
        stage: 0,
    };
    let location = directory_bounds(decoded.len() as u64, count, first, domain)?;
    let resource = |cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    };
    let slice = Slice::new(decoded, stamp.snapshot);
    let mut cursor = Cursor {
        reader: RangeReader::in_region(
            &slice,
            session,
            work,
            domain,
            Span {
                start: 0,
                length: first,
            },
        )?,
        at: 0,
    };
    let mut slots = work.vector();
    let mut seen = work.map();
    for _ in 0..count {
        cursor.skip().await?;
        let number = cursor.natural().await?;
        let gap = cursor.at;
        cursor.skip().await?;
        if gap == cursor.at || number == 0 {
            return Err(cursor.failure(Syntax::Object, gap));
        }
        let offset = cursor.natural().await?;
        if seen
            .try_insert(Number(number), ())
            .map_err(resource)?
            .is_some()
        {
            return Err(Error {
                kind: ErrorKind::Ambiguous(Syntax::Object),
                location,
            }
            .into());
        }
        slots
            .try_push(Slot {
                number,
                span: Span {
                    start: offset,
                    length: 0,
                },
            })
            .map_err(resource)?;
    }
    cursor.skip().await?;
    if cursor.peek().await?.is_some() {
        return Err(cursor.failure(Syntax::Object, cursor.at));
    }
    drop(cursor);
    drop(seen);
    let prefix_end = if let Some(slot) = slots.first() {
        first.checked_add(slot.span.start).ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        })?
    } else {
        decoded.len() as u64
    };
    if prefix_end > decoded.len() as u64 {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        }
        .into());
    }
    if prefix_end > first {
        whitespace(
            &slice,
            session,
            domain,
            Span {
                start: first,
                length: prefix_end - first,
            },
            work,
        )
        .await?;
    }
    finish_ranges(decoded, &mut slots, first, location, work)?;
    Ok(slots.into_owned())
}

async fn whitespace<D: Copy + Eq, G: Copy + Eq>(
    slice: &Slice<'_, D, G>,
    session: &crate::Session,
    domain: Source,
    span: Span,
    work: &impl Work,
) -> Result<(), ReadFailure<core::convert::Infallible>> {
    let mut prefix = Cursor {
        reader: RangeReader::in_region(slice, session, work, domain, span)?,
        at: span.start,
    };
    prefix.skip().await?;
    if prefix.peek().await?.is_some() {
        return Err(prefix.failure(Syntax::Object, prefix.at));
    }
    Ok(())
}

fn finish_ranges<W: Work>(
    decoded: &[u8],
    slots: &mut OwnedVec<Slot, W>,
    first: u64,
    location: Location,
    work: &impl Work,
) -> Result<(), ReadFailure<core::convert::Infallible>> {
    for ordinal in 0..slots.len() {
        admit(work, location, 1)?;
        let start = first.checked_add(slots[ordinal].span.start).ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        })?;
        let end = if let Some(next) = slots.get(ordinal + 1) {
            first.checked_add(next.span.start).ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location,
            })?
        } else {
            decoded.len() as u64
        };
        if start >= end || end > decoded.len() as u64 {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location,
            }
            .into());
        }
        for cut in [start, end] {
            if cut != 0 && cut < decoded.len() as u64 {
                let at = usize::try_from(cut).expect("bounded decoded index");
                admit(work, location, 2)?;
                if !boundary(decoded[at - 1], decoded[at]) {
                    return Err(Error {
                        kind: ErrorKind::Ambiguous(Syntax::Object),
                        location,
                    }
                    .into());
                }
            }
        }
        slots[ordinal].span = Span {
            start,
            length: end - start,
        };
    }
    Ok(())
}

async fn group<'s, D: Copy + Eq, G: Copy + Eq>(
    session: &'s crate::Session,
    stamp: crate::range::Stamp<D, G>,
    decoded: &[u8],
    body: Span,
    layout: (u64, u64),
    revision: usize,
    work: &impl Work,
) -> Result<(Option<Value<'s, D, G>>, OwnedVec<Member>), ReadFailure<core::convert::Infallible>> {
    let slots = directory(session, stamp, decoded, body, layout, revision, work).await?;
    let domain = Source::Decoded {
        stream: body,
        revision,
        stage: 0,
    };
    let location = Location::new(domain, 0, decoded.len() as u64).expect("decoded extent");
    let slice = Slice::new(decoded, stamp.snapshot);
    let mut arena = Arena::new(work).into_owned();
    let mut members = work.vector();
    let mut first_root = None;
    for slot in slots {
        let begin_nodes = arena.nodes.len();
        let mut cursor = Cursor {
            reader: RangeReader::in_region(&slice, session, work, domain, slot.span)?,
            at: slot.span.start,
        };
        let (next, root) = read_into(&mut cursor, session, arena).await?;
        arena = next;
        first_root.get_or_insert(root);
        cursor.skip().await?;
        if cursor.peek().await?.is_some() {
            return Err(cursor.failure(Syntax::Object, cursor.at));
        }
        members
            .try_push(Member {
                number: slot.number,
                root,
                nodes: begin_nodes..arena.nodes.len(),
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
    }
    let value = first_root.map(|root: NodeId| Value {
        arena,
        root,
        session,
        stamp,
        end: decoded.len() as u64,
    });
    Ok((value, members.into_owned()))
}

pub(super) async fn selected<'s, D: Copy + Eq, G: Copy + Eq>(
    session: &'s crate::Session,
    stamp: crate::range::Stamp<D, G>,
    decoded: &[u8],
    body: Span,
    slot: &Slot,
    revision: usize,
    work: &impl Work,
) -> Result<Value<'s, D, G>, ReadFailure<core::convert::Infallible>> {
    let domain = Source::Decoded {
        stream: body,
        revision,
        stage: 0,
    };
    let slice = Slice::new(decoded, stamp.snapshot);
    let mut cursor = Cursor {
        reader: RangeReader::in_region(&slice, session, work, domain, slot.span)?,
        at: slot.span.start,
    };
    let (arena, root) = read_into(&mut cursor, session, Arena::new(work).into_owned()).await?;
    cursor.skip().await?;
    if cursor.peek().await?.is_some() {
        return Err(cursor.failure(Syntax::Object, cursor.at));
    }
    Ok(Value {
        arena,
        root,
        session,
        stamp,
        end: cursor.at,
    })
}

fn boundary(left: u8, right: u8) -> bool {
    crate::bytes::is_space(left)
        || crate::bytes::is_space(right)
        || b"()<>[]{}/%".contains(&left)
        || b"()<>[]{}/%".contains(&right)
}
