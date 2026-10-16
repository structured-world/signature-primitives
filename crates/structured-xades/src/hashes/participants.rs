//! Complete original root/counter hash-use qualification.

use super::{HashBinding, HashError, HashProblem, HashXml, Hashes, check, check_selected};
use crate::pki::CounterPaths;
use crate::prepare::Prepared;
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Original actor whose completed hash guard remained negative/incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipantProblem<N> {
    /// Exact original signature, including a plain `XMLDSig` counter.
    pub signature: N,
    /// Actual selected method/use or incomplete discovery boundary.
    pub cause: HashProblem<N>,
}

/// Complete root plus every original incorporated counter. Construction is
/// private; a root-only receipt cannot stand for this whole participant set.
pub struct ParticipantHashes<N, D, G> {
    root: Hashes<N, D, G>,
    counters: OwnedVec<Hashes<N, D, G>>,
}

impl<N: Copy, D: Copy, G: Copy> ParticipantHashes<N, D, G> {
    /// Original immutable source generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.root.snapshot()
    }
    /// Original selected root, not an arbitrary discovered signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.root.signature()
    }
    /// Root's complete actual-use guard.
    #[must_use]
    pub fn root(&self) -> &Hashes<N, D, G> {
        &self.root
    }
    /// Every counter once in its original complete counter-census order.
    #[must_use]
    pub fn counters(&self) -> &[Hashes<N, D, G>] {
        &self.counters
    }
}

/// Whole-set completion or one original negative/incomplete actor. No partial
/// successful participant set is returned after a late child refusal.
pub enum ParticipantBinding<N, D, G> {
    /// Root and all original counters qualified through the same hash kernel.
    Bound(ParticipantHashes<N, D, G>),
    /// Original prohibition/unsupported/unprocessed fact, not a resource error.
    Unproven(ParticipantProblem<N>),
}

/// Whole-set hash query result preserving original source/processing causes.
pub type Result<X> = core::result::Result<
    ParticipantBinding<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    HashError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Qualify actual message/MGF/reference/Manifest uses for the selected root and
/// its COMPLETE checked counter census, including plain `XMLDSig` children. The
/// EN319132-1 §6.2.1 MD5 guard is shared with the root and timestamp checks;
/// this never invents child B-level properties or applies new suite policy.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Foreign selections fail before owner callbacks. Current Work admits storage
/// and every dispatch before querying the original owner; no signature/hash/
/// payload operation is repeated. All partial retained metadata drops on failure.
pub fn check_participants<X: HashXml, W: Work>(
    prepared: &Prepared<X>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> Result<X> {
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() || counters.snapshot() != access.snapshot() {
        return Err(HashError::Foreign { node: signature });
    }
    if !access
        .equal_id(signature, counters.signature())
        .map_err(|cause| HashError::Resource {
            node: signature,
            cause,
        })?
    {
        return Err(HashError::Foreign { node: signature });
    }
    let mut children = access.execution().vector();
    children
        .try_reserve_exact(counters.actors().len())
        .map_err(|cause| HashError::Resource {
            node: signature,
            cause,
        })?;
    let root = match check(prepared.bound(), access)? {
        HashBinding::Bound(root) => root,
        HashBinding::Unproven(cause) => {
            return Ok(ParticipantBinding::Unproven(ParticipantProblem {
                signature,
                cause,
            }));
        }
    };
    for actor in counters.actors() {
        let signature = actor.signer().counter().original().child();
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| HashError::Resource {
                node: signature,
                cause,
            })?;
        match check_selected(signature, access)? {
            HashBinding::Bound(receipt) => {
                children
                    .try_push(receipt)
                    .map_err(|cause| HashError::Resource {
                        node: signature,
                        cause,
                    })?;
            }
            HashBinding::Unproven(cause) => {
                return Ok(ParticipantBinding::Unproven(ParticipantProblem {
                    signature,
                    cause,
                }));
            }
        }
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(HashError::Access)?;
    Ok(ParticipantBinding::Bound(ParticipantHashes {
        root,
        counters: children.into_owned(),
    }))
}
