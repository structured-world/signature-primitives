//! Per-actor dependency attribution through the existing authority kernel.
use super::closure::{Key, follow};
use super::{AuthorityClosure, AuthorityClosureError, AuthorityNode, AuthorityOrigin};
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};

/// Complete traversal or an unchanged visitor/processing refusal. A visitor
/// may have external side effects; no rollback of those effects is promised.
#[derive(Debug)]
pub enum AuthorityVisitError<E> {
    /// Current dependency lookup, traversal or scratch admission failed.
    Processing(AuthorityClosureError),
    /// First original visitor refusal; no subsequent roots are visited.
    Visitor(E),
}

struct VisitState {
    index: usize,
    root: Option<usize>,
}
struct Pending<'view, 'document, W: Work> {
    index: OwnedMap<Key<'view, 'document>, VisitState, W>,
    queue: OwnedVec<usize, W>,
}
impl<'view, 'document, W: Work> Pending<'view, 'document, W> {
    fn need(
        &mut self,
        key: Key<'view, 'document>,
        root: usize,
        origin: AuthorityOrigin,
        work: &W,
    ) -> Result<(), AuthorityClosureError> {
        let state = self
            .index
            .get_mut(&key, work)?
            .ok_or(AuthorityClosureError::MissingPath { origin })?;
        work.charge_work(1)?;
        if state.root != Some(root) {
            self.queue.try_push(state.index)?;
            state.root = Some(root);
        }
        Ok(())
    }
}

impl<'view, 'certificate, 'document> AuthorityClosure<'view, 'certificate, 'document> {
    /// Visit each root's exact reachable authority nodes once, including the
    /// root itself. The root ordinal retains individual actor attribution even
    /// when different TSA/signature/credential actors share a path. This is the
    /// relation needed for EN319132-1 §6.3(x), not aggregate TSA-purpose bits.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    ///
    /// Reuses the SAME complete/delta/OCSP dependency kernel as closure and role
    /// propagation. No parsing, provider, cryptographic/status check is replayed.
    /// One current-operation index and iterative queue are reused across roots;
    /// cycles terminate, shared paths remain attributed to each original root.
    /// Work admits each edge/lookup/visitor dispatch, and scratch capacity is
    /// released on success/refusal. The visitor funds its own dependent work.
    /// No partial returned collection or baseline/Good verdict is manufactured.
    pub fn visit_roots<E, W: Work>(
        &self,
        work: &W,
        mut visitor: impl FnMut(
            usize,
            &'view AuthorityNode<'view, 'certificate, 'document>,
        ) -> Result<(), E>,
    ) -> Result<(), AuthorityVisitError<E>> {
        let processing = AuthorityVisitError::Processing;
        let resource = |cause: MemoryError| processing(AuthorityClosureError::Resource(cause));
        work.charge_work(1).map_err(resource)?;
        let mut pending = Pending {
            index: work.map(),
            queue: work.vector(),
        };
        let mut responders = work.map();
        for (index, node) in self.nodes().iter().enumerate() {
            work.charge_work(1).map_err(resource)?;
            let key = Key {
                path: node.statuses.path(),
                at: node.statuses.evaluated_at(),
            };
            if pending
                .index
                .try_insert(key, VisitState { index, root: None })
                .map_err(resource)?
                .is_some()
            {
                return Err(processing(AuthorityClosureError::DuplicateNode { index }));
            }
            for responder in node.responders {
                work.charge_work(1).map_err(resource)?;
                let key = core::ptr::from_ref(responder.target()).addr();
                if responders
                    .try_insert(key, *responder)
                    .map_err(resource)?
                    .is_some()
                {
                    return Err(processing(AuthorityClosureError::DuplicateResponder {
                        node: index,
                    }));
                }
            }
        }
        for (root, statuses) in self.roots().iter().enumerate() {
            work.charge_work(1).map_err(resource)?;
            pending.queue.clear();
            pending
                .need(
                    Key {
                        path: statuses.path(),
                        at: statuses.evaluated_at(),
                    },
                    root,
                    AuthorityOrigin::Root { index: root },
                    work,
                )
                .map_err(processing)?;
            let mut cursor = 0;
            while cursor < pending.queue.len() {
                work.charge_work(1).map_err(resource)?;
                let index = pending.queue[cursor];
                let node = self.nodes()[index];
                visitor(root, node).map_err(AuthorityVisitError::Visitor)?;
                follow(
                    node.statuses,
                    index,
                    &responders,
                    &mut |path, at, origin, work| {
                        pending.need(Key { path, at }, root, origin, work)
                    },
                    work,
                )
                .map_err(processing)?;
                cursor += 1;
            }
        }
        Ok(())
    }
}
