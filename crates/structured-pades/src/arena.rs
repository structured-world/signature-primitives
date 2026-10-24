//! Flat object ownership: nodes and edges never own another node's storage.
//!
//! Destruction, even after a deep parse failure, walks ordinary flat buffers;
//! it neither recurses through input nor allocates a work stack while dropping.

use crate::bytes::Form;
use crate::error::{Error, ErrorKind, Result};
use crate::source::Location;
use structured_asn1::memory::{Memory, OwnedVec, Work};

#[derive(Clone, Copy)]
pub(crate) struct NodeId(pub(crate) usize);

#[derive(Clone, Copy, Default)]
pub(crate) struct Children {
    pub(crate) first: Option<usize>,
    last: Option<usize>,
    pub(crate) length: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct Integer {
    pub(crate) negative: bool,
    // None means a syntactically valid integer wider than this scalar query,
    // NOT a malformed PDF object or a silently saturated maximum value.
    pub(crate) magnitude: Option<u64>,
}

#[derive(Clone, Copy)]
pub(crate) struct Name {
    pub(crate) start: usize,
    pub(crate) length: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Fields {
    pub(crate) start: usize,
    pub(crate) length: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub(crate) key: NodeId,
    pub(crate) value: NodeId,
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Null,
    Boolean(bool),
    Integer(Integer),
    Real { integer: Integer, fractional: bool },
    Name(Name),
    String(Form),
    Array(Children),
    Dictionary(Children, Fields),
    Reference { number: u64, generation: u16 },
}

#[derive(Clone, Copy)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    pub(crate) location: Location,
}

#[derive(Clone, Copy)]
pub(crate) struct Link {
    pub(crate) value: NodeId,
    pub(crate) next: Option<usize>,
}

pub(crate) struct Arena<W: Work> {
    pub(crate) nodes: OwnedVec<Node, W>,
    pub(crate) links: OwnedVec<Link, W>,
    pub(crate) names: OwnedVec<u8, W>,
    pub(crate) fields: OwnedVec<Entry, W>,
    pub(crate) faults: OwnedVec<crate::error::Fault, W>,
}

impl<W: Work> Arena<W> {
    pub(crate) fn new(work: &W) -> Self {
        Self {
            nodes: work.vector(),
            links: work.vector(),
            names: work.vector(),
            fields: work.vector(),
            faults: work.vector(),
        }
    }

    pub(crate) fn node(&mut self, node: Node) -> Result<NodeId> {
        let id = NodeId(self.nodes.len());
        self.nodes.try_push(node).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: node.location,
        })?;
        Ok(id)
    }

    pub(crate) fn append(
        &mut self,
        children: &mut Children,
        value: NodeId,
        work: &W,
    ) -> Result<()> {
        let location = self.nodes[value.0].location;
        // Admit the existing-link/frame updates BEFORE either is mutated.
        // try_push separately admits its actual allocation and element copy.
        work.charge_work(1).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        let next = self.links.len();
        self.links
            .try_push(Link { value, next: None })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        if let Some(last) = children.last {
            self.links[last].next = Some(next);
        } else {
            children.first = Some(next);
        }
        children.last = Some(next);
        // One link per child, bounded by the successfully allocated vector.
        debug_assert!(children.length < self.links.len());
        children.length += 1;
        Ok(())
    }

    pub(crate) fn into_owned(self) -> Arena<Memory> {
        Arena {
            nodes: self.nodes.into_owned(),
            links: self.links.into_owned(),
            names: self.names.into_owned(),
            fields: self.fields.into_owned(),
            faults: self.faults.into_owned(),
        }
    }
}

impl Arena<Memory> {
    // Parsing another original/decoded object borrows the ACTIVE execution
    // for every future growth/copy, including spare-capacity writes. Transfer
    // the existing buffers rather than copy a tree or retain an old query.
    #[expect(
        clippy::result_large_err,
        reason = "account mismatch returns every original buffer unchanged without allocating or copying an arena"
    )]
    pub(crate) fn with_execution<W: Work>(self, work: &W) -> core::result::Result<Arena<W>, Self> {
        if !self.nodes.memory().same_account(work.memory())
            || !self.links.memory().same_account(work.memory())
            || !self.names.memory().same_account(work.memory())
            || !self.fields.memory().same_account(work.memory())
            || !self.faults.memory().same_account(work.memory())
        {
            return Err(self);
        }
        Ok(Arena {
            nodes: self
                .nodes
                .with_execution(work)
                .unwrap_or_else(|_| unreachable!("prechecked account")),
            links: self
                .links
                .with_execution(work)
                .unwrap_or_else(|_| unreachable!("prechecked account")),
            names: self
                .names
                .with_execution(work)
                .unwrap_or_else(|_| unreachable!("prechecked account")),
            fields: self
                .fields
                .with_execution(work)
                .unwrap_or_else(|_| unreachable!("prechecked account")),
            faults: self
                .faults
                .with_execution(work)
                .unwrap_or_else(|_| unreachable!("prechecked account")),
        })
    }
}

#[cfg(test)]
mod tests;
