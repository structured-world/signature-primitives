//! Baseline MD5 guard over actual XML-owner hash-use receipts.

use crate::binding::{Bound, SignatureXml};
use crate::reference::{Parent, VisitError};
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, Work};

mod participants;
pub use participants::{
    ParticipantBinding, ParticipantHashes, ParticipantProblem, check_participants,
};

/// Actual selected hash classification, NOT a URI/width-based resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashClass {
    /// The selected native digest is MD5, whatever its original spelling.
    Md5,
    /// A known selected native digest other than MD5. This does not declare
    /// deployment acceptance; algorithm-suite SHOULDs are not new format bans.
    OtherKnown,
    /// Pure signature suite with no external digest; no prehash downgrade.
    Intrinsic,
}

/// Original component selecting an actual digest use, including PSS defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashOrigin<N> {
    /// Original selected signature method.
    SignatureMessage {
        /// Original instruction/enclosure, even when its method is malformed.
        instruction: N,
        /// Actual written method when available; no fake node for a default.
        method: Option<N>,
    },
    /// Original PSS/MGF source; implicit defaults keep their real enclosure.
    MaskGeneration {
        /// Original selecting instruction/enclosure.
        instruction: N,
        /// Actual written method, independently of its implicit default.
        method: Option<N>,
    },
    /// Actual direct or authenticated Manifest reference and its digest method.
    Reference {
        /// Original authenticated instruction.
        instruction: N,
        /// Original method, never a fabricated node for a default.
        method: Option<N>,
        /// Exact selected instruction parent.
        parent: Parent<N>,
    },
}

impl<N: Copy> HashOrigin<N> {
    /// Real selecting instruction/enclosure. Optional exact method identity
    /// remains separately available in the origin; None is not a fake node.
    #[must_use]
    pub fn node(self) -> N {
        match self {
            Self::SignatureMessage { instruction, .. }
            | Self::MaskGeneration { instruction, .. }
            | Self::Reference { instruction, .. } => instruction,
        }
    }
}

/// Actual selected/processed state; an unused advertisement is not Complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashUseState {
    /// Completed digest computation or selected signature-suite fact.
    Complete(HashClass),
    /// Original algorithm is unsupported; it is not `OtherKnown`.
    Unsupported,
    /// Original instruction remains unprocessed; no digest fact is inferred.
    Unprocessed,
}

/// One original selected-operation fact; contains no callback-local strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashUse<N> {
    /// Exact selected signature whose operation produced this fact.
    pub signature: N,
    /// Actual original selection location/role.
    pub origin: HashOrigin<N>,
    /// Actual native state, without reconstructing a provider/hash operation.
    pub state: HashUseState,
}

/// Discovery completeness is distinct from each instruction's processed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashCompleteness<N> {
    /// Entire original message/MGF/reference catalogue was visited.
    Complete,
    /// Original frontier could not be completed with the selected capability.
    Unsupported(N),
    /// Required original instructions have not been processed.
    Unprocessed(N),
}

/// XML-owned projection from ONE existing selected verification operation.
pub trait HashXml: SignatureXml {
    /// Preserve original message/PSS-MGF/direct/signed-Manifest uses and full
    /// identity/default semantics from the actual parsed method/receipts. Never
    /// reparse SignedInfo/PSS, resolve another provider, rehash/reverify payload,
    /// classify by digest width, or map an unknown URI into `OtherKnown`. Intrinsic
    /// belongs only to a pure `SignatureMessage`; PH suites name their real digest.
    /// Current Work admits all lookup/traversal and any retention. Visitor and
    /// processing refusals remain sticky separate original causes. Partial or
    /// empty unprocessed catalogues must not be relabelled Complete.
    fn visit_hash_uses<VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        execution: &W,
        visitor: impl FnMut(HashUse<Self::Id>) -> Result<(), VE>,
    ) -> Result<HashCompleteness<Self::Id>, VisitError<Self::Error, VE>>;
}

/// Mandatory format failure/incompleteness, separate from application policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFailure {
    /// EN319132-1 6.2.1 prohibits actual MD5 digest use.
    ProhibitedMd5,
    /// An actual method is not supported.
    Unsupported,
    /// An actual instruction has not been processed.
    Unprocessed,
}

/// An original failed field or incomplete discovery boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashProblem<N> {
    /// Actual field and its completed failure/incomplete state.
    Use {
        /// Original selecting role.
        origin: HashOrigin<N>,
        /// Original semantic outcome.
        cause: HashFailure,
    },
    /// Original discovery frontier, without inventing a method.
    Catalogue {
        /// Actual original frontier/enclosure.
        node: N,
        /// Unsupported and unprocessed discovery remain distinct.
        cause: HashFailure,
    },
}

/// No-MD5/complete-use fact for one selected original XML operation. It asserts
/// no application policy, key trust, certificate status or timestamp outcome.
pub struct Hashes<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
}

impl<N: Copy, D: Copy, G: Copy> Hashes<N, D, G> {
    /// Original immutable source generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Same selected signature, never a global any-signature lookup.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
}

/// Complete guard or explicit nonconforming/incomplete original operation.
pub enum HashBinding<N, D, G> {
    /// Every actual original use was qualified and no prohibited MD5 was used.
    Bound(Hashes<N, D, G>),
    /// No positive guard receipt; not a processing/resource failure.
    Unproven(HashProblem<N>),
}

/// Terminal source/current-operation/adapter errors, not semantic allowances.
#[derive(Debug)]
pub enum HashError<E, N> {
    /// Original XML generation/processing/owner resource cause.
    Access(AccessError<E, N>),
    /// Actual receipt was substituted from another selected signature/source.
    Foreign {
        /// Original selected/enclosing node.
        node: N,
    },
    /// Current metadata/identity comparison was not admitted.
    Resource {
        /// Actual selecting method/enclosure.
        node: N,
        /// Original admission refusal.
        cause: MemoryError,
    },
    /// Claimed-complete projection omitted/duplicated the message suite or
    /// assigned Intrinsic to an external digest use. Not malformed document data.
    Projection {
        /// Actual original enclosing method/signature.
        node: N,
    },
}

/// Complete result with the owner's exact original identity/error types.
pub type HashResult<X> = Result<
    HashBinding<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    HashError<<X as Xml>::Error, <X as Xml>::Id>,
>;

enum Stop<N> {
    Problem(HashProblem<N>),
    Resource(N, MemoryError),
    Foreign(N),
    Projection(N),
}

/// Check EN319132-1 6.2.1 against ACTUAL original hash uses, including PSS/MGF
/// and authenticated Manifest references. This performs no new hash/provider/
/// replay operation; it consumes the same selected XML owner's typed receipts.
/// SHA1/other suite recommendations do not become extra unconditional bans.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check<X: HashXml, W: Work>(
    bound: &Bound<X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> HashResult<X> {
    let layout = bound.containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() {
        return Err(HashError::Foreign { node: signature });
    }
    check_selected(signature, access)
}

// Plain XMLDSig counters have no root SignedProperties/baseline containers.
// Their privately checked original counter edge supplies selection provenance;
// the same actual-use kernel applies without manufacturing an XAdES binding.
fn check_selected<X: HashXml, W: Work>(
    signature: X::Id,
    access: &Access<'_, X, W>,
) -> HashResult<X> {
    let mut message = false;
    let visited = access.query_fallible(signature, |xml, snapshot, work| {
        xml.visit_hash_uses(snapshot, signature, work, |actual| {
            let node = actual.origin.node();
            work.charge_work(1)
                .map_err(|cause| Stop::Resource(node, cause))?;
            if !access
                .equal_id(actual.signature, signature)
                .map_err(|cause| Stop::Resource(node, cause))?
            {
                return Err(Stop::Foreign(node));
            }
            if matches!(actual.origin, HashOrigin::SignatureMessage { .. }) {
                if message {
                    return Err(Stop::Projection(node));
                }
                message = true;
            }
            let cause = match actual.state {
                HashUseState::Complete(HashClass::Intrinsic) => {
                    if !matches!(actual.origin, HashOrigin::SignatureMessage { .. }) {
                        return Err(Stop::Projection(node));
                    }
                    return Ok(());
                }
                HashUseState::Complete(HashClass::OtherKnown) => return Ok(()),
                HashUseState::Complete(HashClass::Md5) => HashFailure::ProhibitedMd5,
                HashUseState::Unsupported => HashFailure::Unsupported,
                HashUseState::Unprocessed => HashFailure::Unprocessed,
            };
            Err(Stop::Problem(HashProblem::Use {
                origin: actual.origin,
                cause,
            }))
        })
    });
    let completeness = match visited {
        Ok(complete) => complete,
        Err(AccessError::Changed { node }) => {
            return Err(HashError::Access(AccessError::Changed { node }));
        }
        Err(AccessError::Resource { node, cause }) => {
            return Err(HashError::Access(AccessError::Resource { node, cause }));
        }
        Err(AccessError::Xml(VisitError::Processing(cause))) => {
            return Err(HashError::Access(AccessError::Xml(cause)));
        }
        Err(AccessError::Xml(VisitError::Visitor(stop))) => {
            return match stop {
                Stop::Problem(problem) => Ok(HashBinding::Unproven(problem)),
                Stop::Resource(node, cause) => Err(HashError::Resource { node, cause }),
                Stop::Foreign(node) => Err(HashError::Foreign { node }),
                Stop::Projection(node) => Err(HashError::Projection { node }),
            };
        }
    };
    match completeness {
        HashCompleteness::Complete => {}
        HashCompleteness::Unsupported(node) => {
            return Ok(HashBinding::Unproven(HashProblem::Catalogue {
                node,
                cause: HashFailure::Unsupported,
            }));
        }
        HashCompleteness::Unprocessed(node) => {
            return Ok(HashBinding::Unproven(HashProblem::Catalogue {
                node,
                cause: HashFailure::Unprocessed,
            }));
        }
    }
    if !message {
        return Err(HashError::Projection { node: signature });
    }
    Ok(HashBinding::Bound(Hashes {
        snapshot: access.snapshot(),
        signature,
    }))
}
