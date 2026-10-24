//! One original archive identity and current query for existing LTV mechanisms.

use crate::zip::Archive;
use structured_asn1::{
    memory::{Execution, HashWork, MemoryError, Work},
    range::RangeSource,
};
use structured_ltv::source::{Query as QueryTrait, ScopeError, Snapshot};

/// An archive root and its original members have distinct identity kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Node {
    /// This actual complete immutable archive, not a selected successful file.
    Root,
    /// One original central-directory occurrence, including negative inputs.
    Member(usize),
}
impl HashWork for Node {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

/// Identity of this actual borrowed original archive/session. Keeping the
/// archive borrow prevents address reuse from becoming another live document.
pub struct DocumentId<'v, 's, S: RangeSource>(&'v Archive<'s, S>);
impl<S: RangeSource> Copy for DocumentId<'_, '_, S> {}
impl<S: RangeSource> Clone for DocumentId<'_, '_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: RangeSource> PartialEq for DocumentId<'_, '_, S> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}
impl<S: RangeSource> Eq for DocumentId<'_, '_, S> {}
impl<S: RangeSource> core::fmt::Debug for DocumentId<'_, '_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DocumentId")
            .field(&core::ptr::from_ref(self.0))
            .finish()
    }
}
/// Current original/archive admission used by shared material/path/time work.
/// Node identities distinguish root/member; no logical byte coordinate is
/// passed off as a physical ZIP span.
pub struct Query<'q, 'v, 's, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    execution: Execution<'q>,
}
impl<'s, S: RangeSource> Archive<'s, S> {
    /// Borrows this actual source with no allocation or account clone.
    #[must_use]
    pub fn ltv_query<'q, 'v, W: Work>(&'v self, work: &'q W) -> Query<'q, 'v, 's, S>
    where
        'v: 'q,
    {
        Query {
            archive: self,
            execution: self.session().query(work),
        }
    }
}
impl<'q, 'v, 's, S: RangeSource> QueryTrait for Query<'q, 'v, 's, S> {
    type Id = Node;
    type Document = DocumentId<'v, 's, S>;
    type Generation = ();
    type Work = Execution<'q>;
    fn snapshot(&self) -> Snapshot<Self::Document, ()> {
        Snapshot {
            document: DocumentId(self.archive),
            generation: (),
        }
    }
    fn execution(&self) -> &Self::Work {
        &self.execution
    }
    fn admit(&self, node: Node, units: u64) -> Result<(), ScopeError<Node>> {
        if !self.archive.unchanged() {
            return Err(ScopeError::Changed { node });
        }
        self.execution
            .charge_work(units)
            .map_err(|cause| ScopeError::Resource { node, cause })?;
        if !self.archive.unchanged() {
            return Err(ScopeError::Changed { node });
        }
        Ok(())
    }
}
