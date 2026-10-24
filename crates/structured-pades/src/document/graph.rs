//! One historical indirect graph, using stable indices and flat ownership.

use super::{Document, Reading};
use crate::arena::{Kind, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::admit;
use crate::object::Object;
use crate::range::{RangeSource, Stamp};
use structured_asn1::memory::{HashWork, Memory, MemoryError, OwnedMap, OwnedVec, Work};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) number: u64,
    pub(crate) generation: u16,
}

impl HashWork for Key {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

pub(crate) struct Node<'s, D, G> {
    pub(crate) key: Key,
    pub(crate) reading: Option<Reading<'s, D, G>>,
    source: Option<usize>,
}

struct Cached {
    bytes: OwnedVec<u8>,
    body: structured_asn1::Span,
    slots: OwnedVec<super::members::Slot>,
}

/// Full indirect closure of a historical catalog, including null references.
/// Backlinks do not recurse or create reference-counted ownership cycles.
pub struct Graph<'s, D, G> {
    pub(crate) stamp: Stamp<D, G>,
    pub(crate) revision: usize,
    pub(crate) nodes: OwnedVec<Node<'s, D, G>, Memory>,
    pub(crate) index: OwnedMap<Key, usize, Memory>,
    pub(crate) session: &'s crate::Session,
    streams: OwnedVec<Cached>,
}

impl<'s, D: Copy + Eq, G: Copy + Eq> Graph<'s, D, G> {
    pub(crate) fn decoded(&self, owner: usize) -> Option<&[u8]> {
        let node = &self.nodes[owner];
        match node.source {
            Some(index) => Some(&self.streams[index].bytes),
            None => node
                .reading
                .as_ref()
                .and_then(|reading| reading.decoded.as_deref()),
        }
    }
    /// Immutable original file identity used for the complete closure.
    #[must_use]
    pub fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }
    /// Historical ordinal used for every indirect resolution.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }
    /// Actual historical catalog root, without cloning its parsed model.
    ///
    /// # Panics
    /// Panics if the completed graph loses its validated catalog owner.
    #[must_use]
    pub fn root(&self) -> GraphObject<'_, 's, D, G> {
        let reading = self.nodes[0].reading.as_ref().expect("validated catalog");
        GraphObject {
            graph: self,
            owner: 0,
            node: reading.value.root,
        }
    }
}

/// A node inside the actual graph owner. Resolution cannot substitute a node
/// from another revision or silently use a newer generation's definition.
#[derive(Clone, Copy)]
pub struct GraphObject<'a, 's, D, G> {
    pub(crate) graph: &'a Graph<'s, D, G>,
    pub(crate) owner: usize,
    pub(crate) node: NodeId,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> GraphObject<'a, 's, D, G> {
    /// Direct value metadata and paid scalar queries use the same object core.
    ///
    /// # Panics
    /// Panics if an internally issued graph object loses its owning reading.
    #[must_use]
    pub fn direct(self) -> Object<'a, 's, D, G> {
        Object {
            owner: &self.graph.nodes[self.owner]
                .reading
                .as_ref()
                .expect("graph object owner")
                .value,
            node: self.node,
        }
    }

    /// Original indirect owner identity, independent of this direct node.
    #[must_use]
    pub fn identity(self) -> (u64, u16) {
        let key = self.graph.nodes[self.owner].key;
        (key.number, key.generation)
    }

    /// Resolves a direct reference using the already completed graph index.
    /// No I/O, parsing, fallback generation or retained-cache mutation occurs.
    ///
    /// # Panics
    /// Panics if the completed reference-closure index omits an admitted reference.
    pub fn resolved(self, operation: &impl Work) -> crate::Result<Option<Self>> {
        let work = self.graph.session.query(operation);
        let raw = self.direct();
        admit(&work, raw.location(), 1)?;
        let Some((number, generation)) = raw.reference() else {
            return Ok(Some(self));
        };
        let index = self
            .graph
            .index
            .get(&Key { number, generation }, &work)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: raw.location(),
            })?
            .copied()
            .expect("complete reference closure");
        Ok(self.graph.nodes[index]
            .reading
            .as_ref()
            .map(|reading| Self {
                graph: self.graph,
                owner: index,
                node: reading.value.root,
            }))
    }

    /// Selects a dictionary field and resolves its actual original reference.
    pub fn get(self, key: &[u8], operation: &impl Work) -> crate::Result<Option<Self>> {
        let Some(node) = self.direct().get(key, operation)? else {
            return Ok(None);
        };
        Self {
            graph: self.graph,
            owner: self.owner,
            node: node.node,
        }
        .resolved(operation)
    }

    /// Visits direct array members with current admission before every step.
    /// Returned objects can be resolved separately through this same graph.
    pub fn members<'q>(self, operation: &'q impl Work) -> Option<GraphMembers<'a, 's, 'q, D, G>>
    where
        's: 'q,
    {
        Some(GraphMembers {
            object: self,
            members: self.direct().members(operation)?,
        })
    }
}

/// Paid fused direct member traversal using the existing linked-member core.
pub struct GraphMembers<'a, 's, 'q, D, G> {
    object: GraphObject<'a, 's, D, G>,
    members: crate::object::Members<'a, 's, 'q, D, G>,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Iterator for GraphMembers<'a, 's, '_, D, G> {
    type Item = crate::Result<GraphObject<'a, 's, D, G>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.members.next().map(|result| {
            result.map(|node| GraphObject {
                graph: self.object.graph,
                owner: self.object.owner,
                node: node.node,
            })
        })
    }
}
impl<D: Copy + Eq, G: Copy + Eq> core::iter::FusedIterator for GraphMembers<'_, '_, '_, D, G> {}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Resolves one complete historical closure with one cache per object stream.
    ///
    /// # Panics
    /// Panics if an internally decoded root is not an object-stream member.
    pub async fn graph<W: Work>(
        &self,
        revision: usize,
        operation: &W,
    ) -> Result<Graph<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let mut root = self.root(revision, &work).await?;
        let location = root.value.root().location();
        let key = Key {
            number: root.number,
            generation: root.generation,
        };
        let mut cache = StreamCache {
            values: work.vector(),
            index: work.map(),
        };
        let source = if let Some(bytes) = root.decoded.take() {
            let Some(crate::xref::Target::Compressed { stream, .. }) =
                self.target(revision, key.number, key.generation, &work)?
            else {
                unreachable!("a decoded root is an object-stream member")
            };
            Some(
                cache
                    .ensure(self, revision, stream, Some(bytes), location, &work)
                    .await?,
            )
        } else {
            None
        };
        let mut nodes = work.vector();
        let mut index = work.map();
        let resource = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        index.try_insert(key, 0).map_err(resource)?;
        nodes
            .try_push(Node {
                key,
                reading: Some(root),
                source,
            })
            .map_err(resource)?;
        let mut at = 0;
        while at < nodes.len() {
            admit(&work, location, 1)?;
            if nodes[at].reading.is_none() {
                nodes[at] = cache
                    .load(self, revision, nodes[at].key, location, &work)
                    .await?;
            }
            // Move the owner out before growth, so discovery writes directly
            // to the owning queue without another pending-node allocation.
            if let Some(reading) = nodes[at].reading.take() {
                discover(&reading, &mut nodes, &mut index, &work)?;
                nodes[at].reading = Some(reading);
            }
            at += 1;
        }
        let graph = Graph {
            stamp: self.stamp,
            revision,
            nodes: nodes.into_owned(),
            index: index.into_owned(),
            session: self.session,
            streams: cache.values.into_owned(),
        };
        graph.validate(location, &work)?;
        self.check(&work, location)?;
        Ok(graph)
    }
}

struct StreamCache<W: Work> {
    values: OwnedVec<Cached, W>,
    index: OwnedMap<Key, usize, W>,
}
impl<W: Work> StreamCache<W> {
    async fn ensure<S: RangeSource>(
        &mut self,
        document: &Document<'_, S>,
        revision: usize,
        stream: u64,
        bytes: Option<OwnedVec<u8>>,
        location: crate::source::Location,
        work: &W,
    ) -> Result<usize, ReadFailure<S::Error>> {
        let key = Key {
            number: stream,
            generation: 0,
        };
        let resource = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        if let Some(&index) = self.index.get(&key, work).map_err(resource)? {
            return Ok(index);
        }
        let container = document
            .object(revision, stream, 0, work)
            .await?
            .ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location,
            })?;
        let value = cached(document, container, bytes, revision, work).await?;
        let index = self.values.len();
        self.values.try_push(value).map_err(resource)?;
        self.index.try_insert(key, index).map_err(resource)?;
        Ok(index)
    }

    async fn load<'s, S: RangeSource>(
        &mut self,
        document: &Document<'s, S>,
        revision: usize,
        key: Key,
        location: crate::source::Location,
        work: &W,
    ) -> Result<Node<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        if let Some(crate::xref::Target::Compressed { stream, index }) =
            document.target(revision, key.number, key.generation, work)?
        {
            let ordinal = self
                .ensure(document, revision, stream, None, location, work)
                .await?;
            let cache = &self.values[ordinal];
            let slot = usize::try_from(index)
                .ok()
                .and_then(|index| cache.slots.get(index))
                .ok_or(Error {
                    kind: ErrorKind::Syntax(Syntax::Object),
                    location,
                })?;
            if slot.number != key.number {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Object),
                    location,
                }
                .into());
            }
            let value = super::members::selected(
                document.session,
                document.stamp,
                &cache.bytes,
                cache.body,
                slot,
                revision,
                work,
            )
            .await
            .map_err(super::resolve::convert)?;
            Ok(Node {
                key,
                reading: Some(Reading {
                    value,
                    decoded: None,
                    stream: None,
                    number: key.number,
                    generation: key.generation,
                    revision,
                }),
                source: Some(ordinal),
            })
        } else {
            Ok(Node {
                key,
                reading: document
                    .object(revision, key.number, key.generation, work)
                    .await?,
                source: None,
            })
        }
    }
}

fn discover<'s, D, G, W: Work>(
    reading: &Reading<'s, D, G>,
    nodes: &mut OwnedVec<Node<'s, D, G>, W>,
    index: &mut OwnedMap<Key, usize, W>,
    work: &W,
) -> crate::Result<()> {
    for node in &reading.value.arena.nodes {
        admit(work, node.location, 1)?;
        if let Kind::Reference { number, generation } = node.kind {
            let key = Key { number, generation };
            let resource = |cause| Error {
                kind: ErrorKind::Resource(cause),
                location: node.location,
            };
            if index.get(&key, work).map_err(resource)?.is_none() {
                index.try_insert(key, nodes.len()).map_err(resource)?;
                nodes
                    .try_push(Node {
                        key,
                        reading: None,
                        source: None,
                    })
                    .map_err(resource)?;
            }
        }
    }
    Ok(())
}

impl<D: Copy + Eq, G: Copy + Eq> Graph<'_, D, G> {
    fn validate(&self, location: crate::source::Location, work: &impl Work) -> crate::Result<()> {
        let malformed = || Error {
            kind: ErrorKind::Syntax(Syntax::Trailer),
            location,
        };
        let reading = self
            .nodes
            .first()
            .and_then(|node| node.reading.as_ref())
            .ok_or_else(malformed)?;
        if reading.stream.is_some() {
            return Err(malformed());
        }
        let root = self.root();
        if root.direct().kind() != crate::object::Type::Dictionary {
            return Err(malformed());
        }
        let kind = root.get(b"Type", work)?.ok_or_else(malformed)?;
        if !kind.direct().name_equals(b"Catalog", work)? {
            return Err(malformed());
        }
        Ok(())
    }
}

async fn cached<'s, S: RangeSource>(
    document: &Document<'s, S>,
    container: Reading<'s, S::Document, S::Generation>,
    bytes: Option<OwnedVec<u8>>,
    revision: usize,
    work: &impl Work,
) -> Result<Cached, ReadFailure<S::Error>> {
    let (bytes, body, count, first) = if let Some(bytes) = bytes {
        let prepared = document.stream_plan(&container, true, work).await?;
        let (count, first) = prepared.layout.expect("object-stream controls");
        (bytes, prepared.body, count, first)
    } else {
        let decoded = document.stream_data(&container, true, work).await?;
        let (count, first) = decoded.layout.expect("object-stream controls");
        (decoded.bytes, decoded.body, count, first)
    };
    let slots = super::members::directory(
        document.session,
        document.stamp,
        &bytes,
        body,
        (count, first),
        revision,
        work,
    )
    .await
    .map_err(super::resolve::convert)?;
    Ok(Cached { bytes, body, slots })
}
