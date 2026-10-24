//! Cross-revision comparisons use the same typed equality as dictionary reading.

use super::{Document, GraphObject, Reading};
use crate::arena::{Children, Fields, Kind, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure};
use crate::range::{RangeReader, RangeSource, ReadError, Stamp};
use structured_asn1::memory::{HashWork, MemoryError, Work};
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Pair {
    a_owner: usize,
    a_node: usize,
    b_owner: usize,
    b_node: usize,
}
impl HashWork for Pair {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(4)
    }
}

#[derive(Clone, Copy)]
enum Compare<'q, 's, D, G> {
    Values(GraphObject<'q, 's, D, G>, GraphObject<'q, 's, D, G>),
    Array {
        a: GraphObject<'q, 's, D, G>,
        b: GraphObject<'q, 's, D, G>,
        left: Option<usize>,
        right: Option<usize>,
    },
    Dictionary {
        a: GraphObject<'q, 's, D, G>,
        b: GraphObject<'q, 's, D, G>,
        left: Fields,
        right: Fields,
        x: usize,
        y: usize,
    },
}

struct ValueAt<'a, 's, D, G> {
    reading: &'a Reading<'s, D, G>,
    decoded: Option<&'a [u8]>,
    node: NodeId,
}

enum NextPair<'q, 's, D, G> {
    End,
    Different,
    Pair(GraphObject<'q, 's, D, G>, GraphObject<'q, 's, D, G>),
}

fn advance_pair<'q, 's, D: Copy + Eq, G: Copy + Eq, W: Work>(
    frame: Compare<'q, 's, D, G>,
    pending: &mut structured_asn1::memory::OwnedVec<Compare<'q, 's, D, G>, W>,
    work: &W,
    location: crate::source::Location,
) -> crate::Result<NextPair<'q, 's, D, G>> {
    let pair = match frame {
        Compare::Values(a, b) => (a, b),
        Compare::Array { a, b, left, right } => {
            let (Some(left), Some(right)) = (left, right) else {
                if left.is_some() != right.is_some() {
                    return Ok(NextPair::Different);
                }
                return Ok(NextPair::End);
            };
            let aa = &a.direct().owner.arena;
            let bb = &b.direct().owner.arena;
            let left = aa.links[left];
            let right = bb.links[right];
            pending
                .try_push(Compare::Array {
                    a,
                    b,
                    left: left.next,
                    right: right.next,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            (
                GraphObject {
                    node: left.value,
                    ..a
                },
                GraphObject {
                    node: right.value,
                    ..b
                },
            )
        }
        Compare::Dictionary {
            a,
            b,
            left,
            right,
            mut x,
            mut y,
        } => {
            let aa = next_field(a, left, &mut x, work)?;
            let bb = next_field(b, right, &mut y, work)?;
            let (Some((a_key, a_value)), Some((b_key, b_value))) = (aa, bb) else {
                if aa.is_some() != bb.is_some() {
                    return Ok(NextPair::Different);
                }
                return Ok(NextPair::End);
            };
            let first = &a.direct().owner.arena;
            let second = &b.direct().owner.arena;
            if crate::dictionary::compare_names_between(first, a_key, second, b_key, work)?
                != core::cmp::Ordering::Equal
            {
                return Ok(NextPair::Different);
            }
            pending
                .try_push(Compare::Dictionary {
                    a,
                    b,
                    left,
                    right,
                    x,
                    y,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            (a_value, b_value)
        }
    };
    Ok(NextPair::Pair(pair.0, pair.1))
}

fn next_field<'q, 's, D: Copy + Eq, G: Copy + Eq>(
    object: GraphObject<'q, 's, D, G>,
    fields: Fields,
    at: &mut usize,
    work: &impl Work,
) -> crate::Result<Option<(NodeId, GraphObject<'q, 's, D, G>)>> {
    let arena = &object.graph.nodes[object.owner]
        .reading
        .as_ref()
        .expect("graph owner")
        .value
        .arena;
    while *at < fields.length {
        crate::model::admit(work, object.direct().location(), 1)?;
        let field = arena.fields[fields.start + *at];
        *at += 1;
        let Some(value) = (GraphObject {
            node: field.value,
            ..object
        })
        .resolved(work)?
        else {
            continue;
        };
        if value.direct().kind() != crate::object::Type::Null {
            return Ok(Some((field.key, value)));
        }
    }
    Ok(None)
}

struct Domain<'a, S: RangeSource> {
    original: &'a S,
    decoded: Option<&'a [u8]>,
}

impl<S: RangeSource> RangeSource for Domain<'_, S> {
    type Document = S::Document;
    type Generation = S::Generation;
    type Error = S::Error;
    fn stamp(&self) -> Stamp<Self::Document, Self::Generation> {
        let mut stamp = self.original.stamp();
        if let Some(bytes) = self.decoded {
            stamp.length = bytes.len() as u64;
        }
        stamp
    }
    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        work: &'q W,
    ) -> Result<usize, ReadError<Self::Error>> {
        if let Some(bytes) = self.decoded {
            let Ok(at) = usize::try_from(offset) else {
                return Ok(0);
            };
            if at >= bytes.len() {
                return Ok(0);
            }
            let count = output.len().min(bytes.len() - at);
            output[..count].copy_from_slice(&bytes[at..at + count]);
            Ok(count)
        } else {
            self.original.read_at(offset, output, work).await
        }
    }
}

impl<S: RangeSource> Document<'_, S> {
    pub(crate) async fn same_dictionary_except<'q, 's>(
        &self,
        a: GraphObject<'q, 's, S::Document, S::Generation>,
        b: GraphObject<'q, 's, S::Document, S::Generation>,
        omitted: &[&[u8]],
        operation: &impl Work,
    ) -> Result<bool, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = b.direct().location();
        if !core::ptr::eq(a.graph.session, self.session)
            || !core::ptr::eq(b.graph.session, self.session)
            || a.graph.stamp != self.stamp
            || b.graph.stamp != self.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        let aa = &a.graph.nodes[a.owner]
            .reading
            .as_ref()
            .expect("graph owner")
            .value
            .arena;
        let bb = &b.graph.nodes[b.owner]
            .reading
            .as_ref()
            .expect("graph owner")
            .value
            .arena;
        let (Kind::Dictionary(_, left), Kind::Dictionary(_, right)) =
            (aa.nodes[a.node.0].kind, bb.nodes[b.node.0].kind)
        else {
            return Ok(false);
        };
        let mut x = 0;
        let mut y = 0;
        loop {
            let first = next_selected(a, left, &mut x, omitted, &work)?;
            let second = next_selected(b, right, &mut y, omitted, &work)?;
            let (Some((first_key, first)), Some((second_key, second))) = (first, second) else {
                self.check(&work, location)?;
                return Ok(first.is_none() && second.is_none());
            };
            if crate::dictionary::compare_names_between(aa, first_key, bb, second_key, &work)?
                != core::cmp::Ordering::Equal
                || !self.same_graph_values(first, second, &work).await?
            {
                return Ok(false);
            }
        }
    }

    pub(crate) async fn same_graph_values<'q, 's, W: Work>(
        &self,
        a: GraphObject<'q, 's, S::Document, S::Generation>,
        b: GraphObject<'q, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<bool, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = b.direct().location();
        if a.graph.stamp != self.stamp
            || b.graph.stamp != self.stamp
            || !core::ptr::eq(a.graph.session, self.session)
            || !core::ptr::eq(b.graph.session, self.session)
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        self.check(&work, location)?;
        let mut seen = work.map();
        let mut pending = work.vector();
        pending
            .try_push(Compare::Values(a, b))
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        while let Some(frame) = pending.pop() {
            crate::model::admit(&work, location, 1)?;
            let pair = match advance_pair(frame, &mut pending, &work, location)? {
                NextPair::End => continue,
                NextPair::Different => return Ok(false),
                NextPair::Pair(a, b) => (a, b),
            };
            let a = pair.0.resolved(&work)?;
            let b = pair.1.resolved(&work)?;
            let (Some(a), Some(b)) = (a, b) else {
                if a.is_none() && b.is_none() {
                    continue;
                }
                let remaining = a.or(b).expect("one non-null operand");
                if remaining.direct().kind() == crate::object::Type::Null {
                    continue;
                }
                return Ok(false);
            };
            let key = Pair {
                a_owner: a.owner,
                a_node: a.node.0,
                b_owner: b.owner,
                b_node: b.node.0,
            };
            if seen
                .try_insert(key, ())
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .is_some()
            {
                continue;
            }
            if !self
                .queue_comparison(a, b, &mut pending, location, &work)
                .await?
            {
                return Ok(false);
            }
        }
        self.check(&work, location)?;
        Ok(true)
    }

    async fn queue_comparison<'q, 's, W: Work>(
        &self,
        a: GraphObject<'q, 's, S::Document, S::Generation>,
        b: GraphObject<'q, 's, S::Document, S::Generation>,
        pending: &mut structured_asn1::memory::OwnedVec<
            Compare<'q, 's, S::Document, S::Generation>,
            W,
        >,
        location: crate::source::Location,
        work: &W,
    ) -> Result<bool, ReadFailure<S::Error>> {
        let resource = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        let aa = a.graph.nodes[a.owner]
            .reading
            .as_ref()
            .expect("graph owner");
        let bb = b.graph.nodes[b.owner]
            .reading
            .as_ref()
            .expect("graph owner");
        let first_stream = if a.node.0 == aa.value.root.0 {
            aa.stream
        } else {
            None
        };
        let second_stream = if b.node.0 == bb.value.root.0 {
            bb.stream
        } else {
            None
        };
        if (first_stream.is_some() || second_stream.is_some())
            && !self
                .same_streams_in(first_stream, second_stream, location, work)
                .await?
        {
            return Ok(false);
        }
        match (
            aa.value.arena.nodes[a.node.0].kind,
            bb.value.arena.nodes[b.node.0].kind,
        ) {
            (
                Kind::Array(Children {
                    first: left,
                    length: a_len,
                    ..
                }),
                Kind::Array(Children {
                    first: right,
                    length: b_len,
                    ..
                }),
            ) => {
                if a_len != b_len {
                    return Ok(false);
                }
                pending
                    .try_push(Compare::Array { a, b, left, right })
                    .map_err(resource)?;
            }
            (Kind::Dictionary(_, left), Kind::Dictionary(_, right)) => {
                pending
                    .try_push(Compare::Dictionary {
                        a,
                        b,
                        left,
                        right,
                        x: 0,
                        y: 0,
                    })
                    .map_err(resource)?;
            }
            _ => {
                if !self
                    .same_values_in(
                        ValueAt {
                            reading: aa,
                            decoded: a.graph.decoded(a.owner),
                            node: a.node,
                        },
                        ValueAt {
                            reading: bb,
                            decoded: b.graph.decoded(b.owner),
                            node: b.node,
                        },
                        work,
                    )
                    .await?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    async fn same_values_in<W: Work>(
        &self,
        first: ValueAt<'_, '_, S::Document, S::Generation>,
        second: ValueAt<'_, '_, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<bool, ReadFailure<S::Error>> {
        let ValueAt {
            reading: a,
            decoded: a_source,
            node: left,
        } = first;
        let ValueAt {
            reading: b,
            decoded: b_source,
            node: right,
        } = second;
        let location = b.value.arena.nodes[right.0].location;
        if !core::ptr::eq(a.value.session, self.session)
            || !core::ptr::eq(b.value.session, self.session)
            || a.value.stamp != self.stamp
            || b.value.stamp != self.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        self.check(operation, location)?;
        if let Some(equal) = crate::dictionary::scalar(
            &a.value.arena,
            left,
            &b.value.arena,
            right,
            &self.session.query(operation),
        )? {
            return Ok(equal);
        }
        if (a.value.arena.nodes[left.0].location.source() == crate::source::Source::File)
            != a_source.is_none()
            || (location.source() == crate::source::Source::File) != b_source.is_none()
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        let first = Domain {
            original: self.source,
            decoded: a_source,
        };
        let second = Domain {
            original: self.source,
            decoded: b_source,
        };
        let mut first_reader = RangeReader::in_source(
            &first,
            self.session,
            operation,
            a.value.arena.nodes[left.0].location.source(),
        )?;
        let mut second_reader = Some(RangeReader::in_source(
            &second,
            self.session,
            operation,
            location.source(),
        )?);
        let equal = crate::dictionary::same_between(
            &a.value.arena,
            left,
            &b.value.arena,
            right,
            &mut first_reader,
            &mut second_reader,
        )
        .await?;
        self.check(operation, location)?;
        Ok(equal)
    }

    pub(crate) async fn same_readings_in<W: Work>(
        &self,
        a: &Reading<'_, S::Document, S::Generation>,
        a_source: Option<&[u8]>,
        b: &Reading<'_, S::Document, S::Generation>,
        b_source: Option<&[u8]>,
        operation: &W,
    ) -> Result<bool, ReadFailure<S::Error>> {
        if !self
            .same_values_in(
                ValueAt {
                    reading: a,
                    decoded: a_source,
                    node: a.value.root,
                },
                ValueAt {
                    reading: b,
                    decoded: b_source,
                    node: b.value.root,
                },
                operation,
            )
            .await?
        {
            return Ok(false);
        }
        self.same_streams_in(a.stream, b.stream, b.value.root().location(), operation)
            .await
    }

    async fn same_streams_in(
        &self,
        left: Option<structured_asn1::Span>,
        right: Option<structured_asn1::Span>,
        location: crate::source::Location,
        operation: &impl Work,
    ) -> Result<bool, ReadFailure<S::Error>> {
        crate::model::admit(operation, location, 1)?;
        let (Some(left), Some(right)) = (left, right) else {
            return Ok(left.is_none() && right.is_none());
        };
        if left.length != right.length {
            return Ok(false);
        }
        if left == right {
            self.check(operation, location)?;
            return Ok(true);
        }
        let mut first = RangeReader::new(self.source, self.session, operation)?;
        let mut second = first.fork()?;
        for offset in 0..left.length {
            if first.byte_at(left.start + offset).await?
                != second.byte_at(right.start + offset).await?
            {
                return Ok(false);
            }
        }
        self.check(operation, location)?;
        Ok(true)
    }
}

fn next_selected<'q, 's, D: Copy + Eq, G: Copy + Eq>(
    object: GraphObject<'q, 's, D, G>,
    fields: Fields,
    at: &mut usize,
    omitted: &[&[u8]],
    work: &impl Work,
) -> crate::Result<Option<(NodeId, GraphObject<'q, 's, D, G>)>> {
    while let Some((key, value)) = next_field(object, fields, at, work)? {
        let name = crate::object::Object {
            owner: object.direct().owner,
            node: key,
        };
        let mut skip = false;
        for &excluded in omitted {
            if name.name_equals(excluded, work)? {
                skip = true;
                break;
            }
        }
        if !skip {
            return Ok(Some((key, value)));
        }
    }
    Ok(None)
}
