//! Actual actor uses propagated through the common status-authority graph.

use super::closure::{Key, follow};
use super::{
    AuthorityClosureError, AuthorityNode, AuthorityOrigin, Participant, ParticipantAuthority,
    ParticipantClosure,
};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::{OwnedMap, OwnedVec, Work};

/// Actual validation purposes, not configurable policy or an authorization flag.
/// Several purposes can apply to the same path or artifact. In particular a
/// shared CA cannot be called exclusive to TSA/credentials merely because it
/// was first encountered through one of those actors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uses(u8);

impl Uses {
    pub(crate) fn participant<N: Copy>(participant: Participant<N>) -> Self {
        match participant {
            Participant::Signer(_) | Participant::Counter { .. } => Self(1),
            Participant::Credential { .. } => Self(2),
            Participant::Timestamp { .. } => Self(4),
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Used for the actual root signer or an incorporated countersignature.
    #[must_use]
    pub fn signature(self) -> bool {
        self.0 & 1 != 0
    }
    /// Used by an actual protected credential and its validation authorities.
    #[must_use]
    pub fn credential(self) -> bool {
        self.0 & 2 != 0
    }
    /// Used by an actual TSA in the selected scope and its validation authorities.
    #[must_use]
    pub fn timestamp(self) -> bool {
        self.0 & 4 != 0
    }
}

/// One reached original authority with all its actual transitive actor uses.
pub struct AuthorityUse<'view, 'certificate, 'document> {
    node: &'view AuthorityNode<'view, 'certificate, 'document>,
    uses: Uses,
    pending: u8,
}

impl<'view, 'certificate, 'document> AuthorityUse<'view, 'certificate, 'document> {
    /// Same original status inputs and responder associations, never re-evaluated.
    #[must_use]
    pub fn node(&self) -> &'view AuthorityNode<'view, 'certificate, 'document> {
        self.node
    }
    /// All actor roles reaching this exact path/evaluation-label pair.
    #[must_use]
    pub fn uses(&self) -> Uses {
        self.uses
    }
}

/// Complete role propagation for the original participant closure. It establishes
/// neither status usability nor material placement, and never normalizes bytes.
pub struct AuthorityUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G> {
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>,
    entries: OwnedVec<AuthorityUse<'view, 'certificate, 'document>>,
}

impl<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
    AuthorityUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
{
    /// Same complete source-bound actor and status-authority input set.
    #[must_use]
    pub fn inputs(
        &self,
    ) -> &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G> {
        self.inputs
    }
    /// Each reached node once, preserving original closure order.
    #[must_use]
    pub fn entries(&self) -> &[AuthorityUse<'view, 'certificate, 'document>] {
        &self.entries
    }
}

/// Source/refusal errors cannot be interpreted as exclusive material use.
#[derive(Debug)]
pub enum UsesError<E, N> {
    /// Current original XML source refused.
    Access(AccessError<E, N>),
    /// Participant source/generation differs from this operation.
    Foreign,
    /// Actual graph, indexing or admitted storage/work refused.
    Closure(AuthorityClosureError),
}

/// Purpose propagation result in the XML owner's original identity domain.
pub type UsesResult<'closure, 'requirements, 'view, 'certificate, 'document, X> = Result<
    AuthorityUses<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    UsesError<<X as Xml>::Error, <X as Xml>::Id>,
>;

struct Flow<'view, 'certificate, 'document, W: Work> {
    index: OwnedMap<Key<'view, 'document>, usize, W>,
    entries: OwnedVec<AuthorityUse<'view, 'certificate, 'document>, W>,
    queue: OwnedVec<usize, W>,
}

impl<'view, 'document, W: Work> Flow<'view, '_, 'document, W> {
    fn need(
        &mut self,
        key: Key<'view, 'document>,
        uses: u8,
        origin: AuthorityOrigin,
        work: &W,
    ) -> Result<(), AuthorityClosureError> {
        let index = *self
            .index
            .get(&key, work)?
            .ok_or(AuthorityClosureError::MissingPath { origin })?;
        work.charge_work(1)?;
        let entry = &mut self.entries[index];
        let added = uses & !entry.uses.0;
        if added == 0 {
            return Ok(());
        }
        if entry.pending == 0 {
            self.queue.try_push(index)?;
        }
        entry.uses.0 |= added;
        entry.pending |= added;
        Ok(())
    }
}

/// Propagate actual root/counter/credential/TSA uses through the SAME dependency
/// kernel as `close_authorities`. §5.4.2/§5.4.3's exclusive-use rules concern all
/// uses, including indirect CRL/OCSP signers, not the first path that found a CA.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// One indexed graph, an iterative queue and three fixed purpose bits bound
/// propagation: each bit is admitted at each node at most once, including cycles.
/// Only newly added bits propagate. No parser/provider/status check is repeated;
/// direct anchors and certificate-free credentials remain separate requirements.
/// Scratch drops before return; failure cannot return a successful role subset.
///
/// # Panics
/// Only if a private queue invariant is violated: a queue index was admitted
/// after its node's insertion and nodes are never removed during propagation.
pub fn authority_uses<'closure, 'requirements, 'view, 'certificate, 'document, X: Xml, W: Work>(
    inputs: &'closure ParticipantClosure<
        'requirements,
        'view,
        'certificate,
        'document,
        X::Id,
        X::Document,
        X::Generation,
    >,
    access: &Access<'_, X, W>,
) -> UsesResult<'closure, 'requirements, 'view, 'certificate, 'document, X> {
    let requirements = inputs.requirements();
    if requirements.scope().location().snapshot != access.snapshot() {
        return Err(UsesError::Foreign);
    }
    access
        .query(requirements.signature(), |_, _, _| Ok(()))
        .map_err(UsesError::Access)?;
    derive(inputs, access.execution()).map_err(UsesError::Closure)
}

fn derive<
    'closure,
    'requirements,
    'view,
    'certificate,
    'document,
    N: Copy,
    D: Copy,
    G: Copy,
    W: Work,
>(
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>,
    work: &W,
) -> Result<
    AuthorityUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>,
    AuthorityClosureError,
> {
    let mut flow = Flow {
        index: work.map(),
        entries: work.vector(),
        queue: work.vector(),
    };
    let mut responders = work.map();
    flow.entries
        .try_reserve_exact(inputs.authorities().nodes().len())?;
    flow.queue
        .try_reserve_exact(inputs.authorities().nodes().len())?;
    for (index, node) in inputs.authorities().nodes().iter().enumerate() {
        work.charge_work(1)?;
        let key = Key {
            path: node.statuses.path(),
            at: node.statuses.evaluated_at(),
        };
        if flow.index.try_insert(key, index)?.is_some() {
            return Err(AuthorityClosureError::DuplicateNode { index });
        }
        flow.entries.try_push(AuthorityUse {
            node,
            uses: Uses(0),
            pending: 0,
        })?;
        for responder in node.responders {
            work.charge_work(1)?;
            let key = core::ptr::from_ref(responder.target()).addr();
            if responders.try_insert(key, *responder)?.is_some() {
                return Err(AuthorityClosureError::DuplicateResponder { node: index });
            }
        }
    }
    let mut root = 0;
    for entry in inputs.requirements().entries() {
        work.charge_work(1)?;
        let ParticipantAuthority::Path(_) = entry.authority() else {
            continue;
        };
        let statuses = inputs.authorities().roots()[root];
        let uses = Uses::participant(entry.participant()).0;
        flow.need(
            Key {
                path: statuses.path(),
                at: statuses.evaluated_at(),
            },
            uses,
            AuthorityOrigin::Root { index: root },
            work,
        )?;
        root += 1;
    }
    debug_assert_eq!(root, inputs.authorities().roots().len());
    while !flow.queue.is_empty() {
        work.charge_work(1)?;
        let index = flow.queue.pop().expect("nonempty queue");
        let node = flow.entries[index].node;
        let added = flow.entries[index].pending;
        flow.entries[index].pending = 0;
        follow(
            node.statuses,
            index,
            &responders,
            &mut |path, at, origin, work| flow.need(Key { path, at }, added, origin, work),
            work,
        )?;
    }
    Ok(AuthorityUses {
        inputs,
        entries: flow.entries.into_owned(),
    })
}
