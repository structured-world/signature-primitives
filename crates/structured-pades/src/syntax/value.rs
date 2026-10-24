//! Shared parse-into-owner kernel for direct and decoded PDF values.

use super::{Container, Cursor, Frame, check_depth, refused};
use crate::Session;
use crate::arena::{Arena, Children, Fields, Kind, Node, NodeId};
use crate::bytes::Form;
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::range::RangeSource;
use structured_asn1::memory::{Memory, OwnedVec, Work};

pub(crate) async fn read_into<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    session: &Session,
    owner: Arena<Memory>,
) -> Result<(Arena<Memory>, NodeId), ReadFailure<S::Error>> {
    if !core::ptr::eq(cursor.reader.session(), session) {
        return Err(Error {
            kind: ErrorKind::Foreign,
            location: cursor.location(cursor.at, 0),
        }
        .into());
    }
    let work = cursor.reader.execution();
    let mut arena = owner.with_execution(&work).map_err(|_| Error {
        kind: ErrorKind::Foreign,
        location: cursor.location(cursor.at, 0),
    })?;
    let mut frames: OwnedVec<Frame, _> = work.vector();
    let mut root = None;
    loop {
        if frames.is_empty() && root.is_some() {
            break;
        }
        cursor.skip().await?;
        let start = cursor.at;
        let Some(byte) = cursor.peek().await? else {
            return Err(cursor.failure(Syntax::End, start));
        };
        if byte == b']' || byte == b'>' {
            let Some(frame) = frames.last().copied() else {
                return Err(cursor.failure(Syntax::Token, start));
            };
            match (frame.kind, byte) {
                (Container::Array, b']') => cursor.at += 1,
                (Container::Dictionary, b'>') => {
                    cursor.at += 1;
                    if cursor.take().await? != Some(b'>') || frame.children.length % 2 != 0 {
                        return Err(cursor.failure(Syntax::Dictionary, start));
                    }
                }
                _ => return Err(cursor.failure(Syntax::Token, start)),
            }
            let at = cursor.location(frame.start, cursor.at - frame.start);
            work.charge_work(1).map_err(|cause| refused(cause, at))?;
            let kind = match frame.kind {
                Container::Array => Kind::Array(frame.children),
                Container::Dictionary => {
                    let fields = crate::dictionary::finish(
                        &mut arena,
                        frame.children,
                        at,
                        &mut cursor.reader,
                    )
                    .await?;
                    Kind::Dictionary(frame.children, fields)
                }
            };
            arena.nodes[frame.node.0] = Node { location: at, kind };
            frames.pop();
            continue;
        }
        if let Some(Frame {
            kind: Container::Dictionary,
            children,
            ..
        }) = frames.last()
            && children.length % 2 == 0
            && byte != b'/'
        {
            return Err(cursor.failure(Syntax::Dictionary, start));
        }
        session.object(cursor.location(start, 1))?;
        let (kind, opening) = token(cursor, session, &mut arena, byte, frames.len() as u64).await?;
        let at = cursor.location(start, cursor.at - start);
        if opening.is_some() {
            check_depth(session, frames.len() as u64 + 1, at)?;
        }
        let node = arena.node(Node { kind, location: at })?;
        if let Some(parent) = frames.last_mut() {
            arena.append(&mut parent.children, node, &work)?;
        } else {
            root = Some(node);
        }
        if let Some(kind) = opening {
            frames
                .try_push(Frame {
                    node,
                    kind,
                    start,
                    children: Children::default(),
                })
                .map_err(|cause| refused(cause, at))?;
        }
    }
    cursor.reader.check(cursor.location(cursor.at, 0))?;
    Ok((arena.into_owned(), root.expect("completed root")))
}

async fn token<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    session: &Session,
    arena: &mut Arena<W>,
    byte: u8,
    depth: u64,
) -> Result<(Kind, Option<Container>), ReadFailure<S::Error>> {
    let start = cursor.at;
    let mut opening = None;
    let kind = match byte {
        b'[' => {
            cursor.at += 1;
            opening = Some(Container::Array);
            Kind::Array(Children::default())
        }
        b'<' => {
            cursor.at += 1;
            if cursor.peek().await? == Some(b'<') {
                cursor.at += 1;
                opening = Some(Container::Dictionary);
                Kind::Dictionary(Children::default(), Fields::default())
            } else {
                cursor.hexadecimal().await?;
                Kind::String(Form::Hexadecimal)
            }
        }
        b'(' => {
            cursor.literal(session, depth).await?;
            Kind::String(Form::Literal)
        }
        b'/' => Kind::Name(cursor.name(&mut arena.names).await?),
        b't' => {
            cursor.keyword(b"true").await?;
            Kind::Boolean(true)
        }
        b'f' => {
            cursor.keyword(b"false").await?;
            Kind::Boolean(false)
        }
        b'n' => {
            cursor.keyword(b"null").await?;
            Kind::Null
        }
        b'+' | b'-' | b'.' | b'0'..=b'9' => {
            let (integer, real) = cursor.number().await?;
            if let super::NumberKind::Real { fractional } = real {
                Kind::Real {
                    integer,
                    fractional,
                }
            } else if !integer.negative {
                let end = cursor.at;
                if let Some((number, generation)) = cursor.reference(integer).await? {
                    Kind::Reference { number, generation }
                } else {
                    cursor.at = end;
                    Kind::Integer(integer)
                }
            } else {
                Kind::Integer(integer)
            }
        }
        _ => return Err(cursor.failure(Syntax::Token, start)),
    };
    Ok((kind, opening))
}

#[cfg(test)]
mod tests;
