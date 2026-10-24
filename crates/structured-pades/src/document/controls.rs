//! Ordinary stream controls resolved by the document's existing frame engine.

use super::Reading;
use crate::{
    arena::{Kind, Node, NodeId},
    error::{Error, ErrorKind, Syntax},
    model::admit,
    stream::plan::{Builder, Failure, Input},
};
use structured_asn1::memory::{HashWork, Memory, MemoryError, OwnedMap, OwnedVec, Work};

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(super) struct Key {
    pub(super) number: u64,
    pub(super) generation: u16,
}
impl HashWork for Key {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}
#[derive(Clone, Copy)]
pub(super) struct At {
    owner: usize,
    node: NodeId,
}

#[expect(
    clippy::large_enum_variant,
    reason = "an owned stream reading transfers its funded arena directly; boxing it would add a fallible allocation to each reference resolution"
)]
pub(super) enum Owner<'b, 's, D, G> {
    Borrowed(&'b Reading<'s, D, G>),
    Owned(Reading<'s, D, G>),
}
impl<'s, D, G> core::ops::Deref for Owner<'_, 's, D, G> {
    type Target = Reading<'s, D, G>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}

pub(super) struct Controls<'b, 's, D, G> {
    pub(super) container: Owner<'b, 's, D, G>,
    values: OwnedVec<Reading<'s, D, G>>,
    index: OwnedMap<Key, Option<usize>, Memory>,
    builder: Option<Builder<At>>,
    pub(super) layout: Option<(u64, u64)>,
    object_stream: bool,
    waiting: Option<Key>,
}
impl<'b, 's, D: Copy + Eq, G: Copy + Eq> Controls<'b, 's, D, G> {
    pub(super) fn new(
        container: Owner<'b, 's, D, G>,
        object_stream: bool,
        work: &impl Work,
    ) -> Self {
        let location = container.value.root().location();
        Self {
            container,
            values: work.vector().into_owned(),
            index: work.map().into_owned(),
            builder: Some(Builder::new(work, location)),
            layout: None,
            object_stream,
            waiting: None,
        }
    }
    pub(super) fn waiting(&self) -> bool {
        self.waiting.is_some()
    }
    pub(super) fn supply(
        &mut self,
        value: Option<Reading<'s, D, G>>,
        work: &impl Work,
    ) -> crate::Result<()> {
        let key = self.waiting.take().expect("suspended control dependency");
        let location = self.container.value.root().location();
        let ordinal = if let Some(value) = value {
            let stored = core::mem::replace(&mut self.values, work.vector().into_owned());
            let mut values = stored.with_execution(work).map_err(|_| Error {
                kind: ErrorKind::Foreign,
                location,
            })?;
            let ordinal = values.len();
            values.try_push(value).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            self.values = values.into_owned();
            Some(ordinal)
        } else {
            None
        };
        let stored = core::mem::replace(&mut self.index, work.map().into_owned());
        let mut index = stored.with_execution(work).map_err(|_| Error {
            kind: ErrorKind::Foreign,
            location,
        })?;
        index.try_insert(key, ordinal).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        self.index = index.into_owned();
        Ok(())
    }
    pub(super) fn advance(&mut self, work: &impl Work) -> Result<(), Failure> {
        let result = self.advance_inner(work);
        if let Err(Failure::Need { number, generation }) = result {
            self.waiting = Some(Key { number, generation });
        }
        result
    }
    fn advance_inner(&mut self, work: &impl Work) -> Result<(), Failure> {
        if self.object_stream && self.layout.is_none() {
            let root = self.root();
            let location = self.node(root).location;
            let malformed = || Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location,
            };
            let kind = self.get(root, b"Type", work)?.ok_or_else(malformed)?;
            if !self.named(kind, b"ObjStm", work)? {
                return Err(malformed().into());
            }
            let count = self.get(root, b"N", work)?.ok_or_else(malformed)?;
            let count = self.unsigned(count, work)?;
            let first = self.get(root, b"First", work)?.ok_or_else(malformed)?;
            let first = self.unsigned(first, work)?;
            if count > first / 4 {
                return Err(malformed().into());
            }
            self.layout = Some((count, first));
        }
        let mut builder = self.builder.take().expect("unfinished control builder");
        let result = builder.advance(self, work);
        self.builder = Some(builder);
        result
    }
    pub(super) fn plans(&mut self) -> OwnedVec<crate::stream::Step> {
        self.builder
            .take()
            .expect("finished control builder")
            .finish()
    }
    fn arena(&self, at: At) -> &crate::arena::Arena<Memory> {
        if at.owner == 0 {
            &self.container.value.arena
        } else {
            &self.values[at.owner - 1].value.arena
        }
    }
}
impl<D: Copy + Eq, G: Copy + Eq> Input for Controls<'_, '_, D, G> {
    type At = At;
    fn root(&self) -> At {
        At {
            owner: 0,
            node: self.container.value.root,
        }
    }
    fn node(&self, at: At) -> Node {
        self.arena(at).nodes[at.node.0]
    }
    fn resolve(&self, at: At, work: &impl Work) -> Result<Option<At>, Failure> {
        let node = self.node(at);
        admit(work, node.location, 1)?;
        match node.kind {
            Kind::Reference { number, generation } => {
                match self
                    .index
                    .get(&Key { number, generation }, work)
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: node.location,
                    })? {
                    None => Err(Failure::Need { number, generation }),
                    Some(None) => Ok(None),
                    Some(Some(owner)) => {
                        let reading = &self.values[*owner];
                        let value = &reading.value;
                        if reading.stream.is_some() {
                            return Err(Error {
                                kind: ErrorKind::Syntax(Syntax::Stream),
                                location: value.root().location(),
                            }
                            .into());
                        }
                        if matches!(value.arena.nodes[value.root.0].kind, Kind::Null) {
                            return Ok(None);
                        }
                        Ok(Some(At {
                            owner: owner + 1,
                            node: value.root,
                        }))
                    }
                }
            }
            Kind::Null => Ok(None),
            _ => Ok(Some(at)),
        }
    }
    fn get(&self, at: At, key: &[u8], work: &impl Work) -> Result<Option<At>, Failure> {
        crate::model::get(self.arena(at), at.node, key, work)?
            .map(|node| {
                self.resolve(
                    At {
                        owner: at.owner,
                        node,
                    },
                    work,
                )
            })
            .transpose()
            .map(Option::flatten)
    }
    fn named(&self, at: At, name: &[u8], work: &impl Work) -> Result<bool, Failure> {
        Ok(crate::model::named(self.arena(at), at.node, name, work)?)
    }
    fn unsigned(&self, at: At, work: &impl Work) -> Result<u64, Failure> {
        Ok(crate::model::unsigned(self.arena(at), at.node, work)?)
    }
    fn link(&self, owner: At, link: usize) -> (At, Option<usize>) {
        let link = self.arena(owner).links[link];
        (
            At {
                owner: owner.owner,
                node: link.value,
            },
            link.next,
        )
    }
}
