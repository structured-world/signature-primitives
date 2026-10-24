//! One live original PDF generation and its current LTV operation.

use crate::{document::Document, range::RangeSource, timestamp::Node};
use structured_asn1::memory::{Execution, Work};
use structured_ltv::source::{Query as QueryContract, ScopeError, Snapshot};

/// Metadata-only generation guard shared by material lookup and archive input
/// coverage. It cannot replace the original document's source or execution.
pub struct Query<'q, 's, S: RangeSource> {
    document: &'q Document<'s, S>,
    execution: Execution<'q>,
}

impl<S: RangeSource> Query<'_, '_, S> {
    pub(crate) fn document(&self) -> &Document<'_, S> {
        self.document
    }
    pub(crate) fn belongs(&self, session: &crate::Session) -> bool {
        core::ptr::eq(self.document.session, session)
    }
}

impl<'q, S: RangeSource> QueryContract for Query<'q, '_, S> {
    type Id = Node;
    type Document = S::Document;
    type Generation = S::Generation;
    type Work = Execution<'q>;
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation> {
        self.document.stamp.snapshot
    }
    fn execution(&self) -> &Self::Work {
        &self.execution
    }
    fn admit(&self, node: Node, units: u64) -> Result<(), ScopeError<Node>> {
        if self.document.source.stamp() != self.document.stamp {
            return Err(ScopeError::Changed { node });
        }
        self.execution
            .charge_work(units)
            .map_err(|cause| ScopeError::Resource { node, cause })?;
        if self.document.source.stamp() != self.document.stamp {
            return Err(ScopeError::Changed { node });
        }
        Ok(())
    }
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Borrows the actual original file and current operation for common LTV
    /// queries. No parsing, source copy, allocation or account clone occurs.
    pub fn query<'q, W: Work>(&'q self, operation: &'q W) -> Query<'q, 's, S> {
        Query {
            document: self,
            execution: self.session.query(operation),
        }
    }
}
