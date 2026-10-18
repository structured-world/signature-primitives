//! Iterative closure of the actual validation authorities used by path statuses.

use super::{CheckedPath, CrlAuthorities, CrlAuthority, MemberStatus, PathStatuses, ResponderPath};
use core::hash::{Hash, Hasher};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};
use structured_pkix::{ocsp::AuthoritySource, temporal::Reading};

/// Supplied original status census and the actual delegated-responder bindings
/// selected for its OCSP inputs. Construction is not evidence of completeness;
/// `close_authorities` derives and checks every reachable dependency.
pub struct AuthorityNode<'view, 'certificate, 'document> {
    /// Same actual path, exact evaluation label and complete per-member inputs.
    pub statuses: &'view PathStatuses<'view, 'certificate, 'document>,
    /// Original-root bindings for delegated OCSP inputs, without source copies.
    pub responders: &'view [&'view ResponderPath<'view, 'view, 'certificate, 'document>],
}

/// Original obligation that required an additional authority path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityOrigin {
    /// Ordinal in the explicitly selected root-status inputs.
    Root {
        /// Original root ordinal.
        index: usize,
    },
    /// One complete/delta contributor to an actual member's CRL reason union.
    Crl {
        /// Ordinal in the supplied authority-node catalogue.
        node: usize,
        /// Original non-anchor member ordinal.
        member: usize,
        /// Original reason contributor ordinal.
        source: usize,
        /// Whether this is the updating delta rather than the complete list.
        delta: bool,
    },
    /// Actual directly delegated OCSP signer for this original member.
    Responder {
        /// Ordinal in the supplied authority-node catalogue.
        node: usize,
        /// Original non-anchor member ordinal.
        member: usize,
    },
}

/// Caller input or resource refusal, not a certificate/status rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClosureError {
    /// No original actor path was selected.
    Roots,
    /// Two nodes claim the same live path receipt and exact evaluation label.
    DuplicateNode {
        /// Second supplied node ordinal.
        index: usize,
    },
    /// More than one responder binding was selected for the same OCSP target.
    DuplicateResponder {
        /// Supplied node containing the conflicting selection.
        node: usize,
    },
    /// A required original path/label has no complete status census.
    MissingPath {
        /// Exact original dependency, not an invented byte offset.
        origin: AuthorityOrigin,
    },
    /// A root was replaced by a different status-census receipt.
    ForeignRoot {
        /// Original root ordinal.
        index: usize,
    },
    /// The original delegated response has no selected full-path binding.
    MissingResponder {
        /// Actual source member requiring the binding.
        origin: AuthorityOrigin,
    },
    /// Current execution refused before traversal, hashing, growth or copying.
    Resource(MemoryError),
}

impl From<MemoryError> for AuthorityClosureError {
    fn from(value: MemoryError) -> Self {
        Self::Resource(value)
    }
}

/// Complete reachable authority-input set, not a baseline level or Good verdict.
/// Every borrowed node retains the original status, freshness, nonce, configured
/// trust and noCheck facts. Only reached nodes are retained; temporary indexes
/// are released before return. No provider/parse/signature callback is replayed.
pub struct AuthorityClosure<'view, 'certificate, 'document> {
    roots: &'view [&'view PathStatuses<'view, 'certificate, 'document>],
    nodes: OwnedVec<&'view AuthorityNode<'view, 'certificate, 'document>>,
}

impl<'view, 'certificate, 'document> AuthorityClosure<'view, 'certificate, 'document> {
    /// Actual selected actor inputs; actor-to-signature association is separate.
    #[must_use]
    pub fn roots(&self) -> &'view [&'view PathStatuses<'view, 'certificate, 'document>] {
        self.roots
    }
    /// All reached original paths, each once per exact evaluation label.
    #[must_use]
    pub fn nodes(&self) -> &[&'view AuthorityNode<'view, 'certificate, 'document>] {
        &self.nodes
    }
}

#[derive(Clone, Copy)]
pub(super) struct Key<'view, 'document> {
    pub(super) path: &'view CheckedPath<'document>,
    pub(super) at: Reading,
}

impl PartialEq for Key<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.path, other.path) && self.at == other.at
    }
}
impl Eq for Key<'_, '_> {}
impl Hash for Key<'_, '_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only live, immovably borrowed, nonzero-sized receipts are indexed.
        // This is operation-local receipt identity, never document identity.
        core::ptr::from_ref(self.path).hash(state);
        self.at.start().seconds().hash(state);
        self.at.start().nanos().hash(state);
        self.at.start().is_leap_second().hash(state);
        self.at.has_subnanosecond_remainder().hash(state);
    }
}
impl HashWork for Key<'_, '_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(6)
    }
}
struct State {
    index: usize,
    queued: bool,
}

struct Pending<'view, 'certificate, 'document, W: Work> {
    supplied: &'view [AuthorityNode<'view, 'certificate, 'document>],
    index: OwnedMap<Key<'view, 'document>, State, W>,
    queue: OwnedVec<&'view AuthorityNode<'view, 'certificate, 'document>, W>,
}

impl<'view, 'document, W: Work> Pending<'view, '_, 'document, W> {
    fn need(
        &mut self,
        path: &'view CheckedPath<'document>,
        at: Reading,
        origin: AuthorityOrigin,
        work: &W,
    ) -> Result<usize, AuthorityClosureError> {
        let Some(state) = self.index.get_mut(&Key { path, at }, work)? else {
            return Err(AuthorityClosureError::MissingPath { origin });
        };
        work.charge_work(1)?;
        if !state.queued {
            self.queue.try_push(&self.supplied[state.index])?;
            state.queued = true;
        }
        Ok(state.index)
    }
}

/// Derive all actual status-authority paths from selected original actor inputs.
/// EN319132-1 V1.3.1 §6.3(aa) requires the validation data actually needed for
/// the actors, including status authorities, rather than an arbitrary nonempty
/// collection. Every complete/delta authority is followed. Delegated responses
/// need their actual full-path receipt; direct issuer/configured branches remain
/// explicit in the original input. A valid noCheck exempts only its responder's
/// status, as already enforced by the shared status census.
///
/// The queue is iterative and deduplicates exact live path/Reading pairs;
/// repeated dependencies and cycles neither recurse nor replay verification.
/// Missing inputs and resource refusal drop all partial output and scratch.
/// This proves input closure, not status usability, application trust, or a
/// complete signer/counter/credential/timestamp actor census.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only if the private queue/index invariant is violated. Entries are queued
/// exclusively after insertion and the index is never removed during traversal.
pub fn close_authorities<'view, 'certificate, 'document, W: Work>(
    roots: &'view [&'view PathStatuses<'view, 'certificate, 'document>],
    supplied: &'view [AuthorityNode<'view, 'certificate, 'document>],
    work: &W,
) -> Result<AuthorityClosure<'view, 'certificate, 'document>, AuthorityClosureError> {
    work.charge_work(1)?;
    if roots.is_empty() {
        return Err(AuthorityClosureError::Roots);
    }
    let mut pending = Pending {
        supplied,
        index: work.map(),
        queue: work.vector(),
    };
    let mut responders = work.map();
    for (index, node) in supplied.iter().enumerate() {
        work.charge_work(1)?;
        let key = Key {
            path: node.statuses.path(),
            at: node.statuses.evaluated_at(),
        };
        if pending
            .index
            .try_insert(
                key,
                State {
                    index,
                    queued: false,
                },
            )?
            .is_some()
        {
            return Err(AuthorityClosureError::DuplicateNode { index });
        }
        for responder in node.responders {
            work.charge_work(1)?;
            let key = core::ptr::from_ref(responder.target()).addr();
            if responders.try_insert(key, *responder)?.is_some() {
                return Err(AuthorityClosureError::DuplicateResponder { node: index });
            }
        }
    }
    for (index, root) in roots.iter().enumerate() {
        work.charge_work(1)?;
        let node = pending.need(
            root.path(),
            root.evaluated_at(),
            AuthorityOrigin::Root { index },
            work,
        )?;
        if !core::ptr::eq(supplied[node].statuses, *root) {
            return Err(AuthorityClosureError::ForeignRoot { index });
        }
    }
    let mut cursor = 0;
    while cursor < pending.queue.len() {
        work.charge_work(1)?;
        let inputs = pending.queue[cursor].statuses;
        let key = Key {
            path: inputs.path(),
            at: inputs.evaluated_at(),
        };
        let index = pending
            .index
            .get(&key, work)?
            .expect("queued node has its index")
            .index;
        follow(
            inputs,
            index,
            &responders,
            &mut |path, at, origin, work| pending.need(path, at, origin, work).map(|_| ()),
            work,
        )?;
        cursor += 1;
    }
    Ok(AuthorityClosure {
        roots,
        nodes: pending.queue.into_owned(),
    })
}

pub(super) fn follow<'view, 'certificate, 'document, W: Work>(
    inputs: &'view PathStatuses<'view, 'certificate, 'document>,
    index: usize,
    responders: &OwnedMap<usize, &'view ResponderPath<'view, 'view, 'certificate, 'document>, W>,
    need: &mut impl FnMut(
        &'view CheckedPath<'document>,
        Reading,
        AuthorityOrigin,
        &W,
    ) -> Result<(), AuthorityClosureError>,
    work: &W,
) -> Result<(), AuthorityClosureError> {
    for (member, input) in inputs.entries().iter().enumerate() {
        work.charge_work(1)?;
        match input {
            MemberStatus::Crl(bound) => {
                for (source, authority) in bound.authorities().iter().enumerate() {
                    work.charge_work(1)?;
                    follow_crl(
                        (index, member, source),
                        *authority,
                        inputs.evaluated_at(),
                        need,
                        work,
                    )?;
                }
            }
            MemberStatus::CrlReading(bound) => follow_crl(
                (index, member, 0),
                bound.authorities(),
                inputs.evaluated_at(),
                need,
                work,
            )?,
            MemberStatus::Ocsp(target) => {
                if matches!(target.authority(), AuthoritySource::Delegate { .. }) {
                    let origin = AuthorityOrigin::Responder {
                        node: index,
                        member,
                    };
                    let key = core::ptr::from_ref(*target).addr();
                    let responder = responders
                        .get(&key, work)?
                        .ok_or(AuthorityClosureError::MissingResponder { origin })?;
                    need(responder.path(), inputs.evaluated_at(), origin, work)?;
                }
            }
            MemberStatus::ResponderNoCheck(_) => (),
        }
    }
    Ok(())
}

fn follow_crl<'view, 'document, W: Work>(
    position: (usize, usize, usize),
    authorities: CrlAuthorities<'view, 'document>,
    at: Reading,
    visit: &mut impl FnMut(
        &'view CheckedPath<'document>,
        Reading,
        AuthorityOrigin,
        &W,
    ) -> Result<(), AuthorityClosureError>,
    work: &W,
) -> Result<(), AuthorityClosureError> {
    let (node, member, source) = position;
    let mut need = |authority, delta| {
        if let CrlAuthority::Path(path) = authority {
            visit(
                path,
                at,
                AuthorityOrigin::Crl {
                    node,
                    member,
                    source,
                    delta,
                },
                work,
            )?;
        }
        Ok::<_, AuthorityClosureError>(())
    };
    match authorities {
        CrlAuthorities::Complete(authority) => need(authority, false),
        CrlAuthorities::Delta { base, delta } => {
            need(base, false)?;
            need(delta, true)
        }
    }
}
