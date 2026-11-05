//! Recomputed Manifest digests before an archive is requested.

use super::check::{self, Input, Mode};
use crate::{
    binding::{Bound, Status},
    certificate::{self, Agreement, DigestProvider},
    digest,
    produce::{Emit, Error, Transaction},
    reference::ObjectLocation,
    timestamp::{TimestampXml, XADES_141},
    xml::{Access, Snapshot},
};
use structured_asn1::{
    digest::Resolution,
    memory::{OwnedVec, Work},
};

/// One original authenticated Manifest instruction offered to the caller's
/// algorithm-longevity decision. The format does not invent a weak-hash policy.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<N> {
    /// Original Reference instruction, not its detached target.
    pub reference: N,
    /// Actual resolver-observed origin, not inferred from URI spelling.
    pub location: ObjectLocation,
    /// Completed original reference outcome.
    pub status: Status,
}

/// Failure before a complete renewal can be returned or written.
#[derive(Debug)]
pub enum CreationError<E, PE, N, D, G> {
    /// Original append-position traversal/source/resource refusal.
    Input(crate::timestamp::InputError<E, N>),
    /// Original source, method, provider, traversal or streaming failure.
    Processing(super::CheckError<E, PE, N, D, G>),
    /// Selected old/new algorithm is unsupported, malformed or prohibited.
    Algorithm {
        /// Actual offending method.
        method: N,
        /// Completed algorithm classification.
        answer: Agreement,
    },
    /// Selected instruction is not an actual successfully checked detached reference.
    Ineligible {
        /// Original instruction.
        reference: N,
    },
    /// New and old semantic digest identities are equal.
    Unchanged {
        /// Original instruction whose digest was not strengthened.
        reference: N,
    },
}

struct Pair<N, O> {
    reference: N,
    instruction: O,
    object: O,
}

/// Complete recomputed pairs from the selected original Manifest instructions.
/// Output ownership is that of the existing selected digest provider. No whole
/// detached input is buffered, and no URI-based algorithm dispatcher is added.
pub struct Renewal<N, D, G, O> {
    snapshot: Snapshot<D, G>,
    signature: N,
    parent: Option<N>,
    canonicalization: N,
    digest: N,
    pairs: OwnedVec<Pair<N, O>>,
}

impl<N: Copy, D: Copy + Eq, G: Copy + Eq, O: AsRef<[u8]>> Renewal<N, D, G, O> {
    /// Number of actual selected original instructions, not a success subset.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }
    /// No selected expiring digest means no property should be written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Append the original computed pairs in selection order. The transaction
    /// copies complete original method elements, preserving parameters.
    /// EN319132-1 §5.5.3 requires ordinary `ReferenceOutput` for `NewSDODigestValue`
    /// and canonicalized Reference XML for `OriginalRefDigest`, in that order.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: Transaction<Id = N, Document = D, Generation = G>, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>>
    where
        N: structured_asn1::memory::HashWork,
    {
        work.charge_work(1).map_err(Error::Resource)?;
        if writer.base() != self.snapshot
            || !structured_ltv::source::equal_id(writer.signature(), self.signature, work)
                .map_err(Error::Resource)?
            || !crate::produce::same_parent(writer.unsigned_parent(), self.parent, work)
                .map_err(Error::Resource)?
        {
            return Err(Error::Foreign);
        }
        if self.pairs.is_empty() {
            return Ok(());
        }
        let mut emit = Emit { writer, work };
        emit.begin(XADES_141, "RenewedDigestsV2")?;
        work.charge_work(1).map_err(Error::Resource)?;
        emit.writer
            .method(self.canonicalization, work)
            .map_err(Error::Writer)?;
        work.charge_work(1).map_err(Error::Resource)?;
        emit.writer
            .method(self.digest, work)
            .map_err(Error::Writer)?;
        for pair in &self.pairs {
            emit.begin(XADES_141, "RecomputedDigestValue")?;
            emit.binary(XADES_141, "NewSDODigestValue", pair.object.as_ref())?;
            emit.binary(XADES_141, "OriginalRefDigest", pair.instruction.as_ref())?;
            emit.end()?;
        }
        emit.end()?;
        work.charge_work(1).map_err(Error::Resource)?;
        if emit.writer.base() != self.snapshot
            || !structured_ltv::source::equal_id(emit.writer.signature(), self.signature, work)
                .map_err(Error::Resource)?
            || !crate::produce::same_parent(emit.writer.unsigned_parent(), self.parent, work)
                .map_err(Error::Resource)?
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    /// Actual original instruction ordinal-to-identity mapping, without copying.
    pub fn references(&self) -> impl ExactSizeIterator<Item = N> + '_ {
        self.pairs.iter().map(|p| p.reference)
    }
}

/// Creation result in the XML owner's source and error domain.
pub type CreationResult<T, X, PE> = Result<
    T,
    CreationError<
        <X as crate::xml::Xml>::Error,
        PE,
        <X as crate::xml::Xml>::Id,
        <X as crate::xml::Xml>::Document,
        <X as crate::xml::Xml>::Generation,
    >,
>;
/// Complete new renewal with the selected provider's actual output storage.
pub type Created<'p, X, P> = Renewal<
    <X as crate::xml::Xml>::Id,
    <X as crate::xml::Xml>::Document,
    <X as crate::xml::Xml>::Generation,
    <P as structured_asn1::digest::Digest<'p>>::Output,
>;

/// Resolve every selected method before starting any digest/source callback.
/// Selection examines the complete authenticated Manifest census under Work;
/// unknown origin/unchecked/invalid selected instructions refuse, never skip.
/// Both hashes reuse validation's source and digest kernels. Strength beyond
/// semantic inequality is the caller's explicit algorithm-longevity policy.
pub fn create<'p, X, P, W>(
    xml: &X,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    canonicalization: X::Id,
    new_method: X::Id,
    provider: &'p P,
    work: &W,
    selected: impl FnMut(Candidate<X::Id>, &W) -> Result<bool, P::Error>,
) -> CreationResult<Created<'p, X, P>, X, P::Error>
where
    X: TimestampXml,
    P: DigestProvider<'p, X>,
    W: Work,
{
    let layout = bound.containers();
    let access = Access::new(xml, layout.snapshot(), work);
    let processing = CreationError::Processing;
    let resource = |cause| {
        processing(super::CheckError::Resource {
            node: new_method,
            cause,
        })
    };
    let parent = match layout.unsigned() {
        Some(unsigned) => crate::timestamp::optional(
            &access,
            unsigned,
            crate::container::XADES,
            "UnsignedSignatureProperties",
        )
        .map_err(CreationError::Input)?,
        None => None,
    };
    access
        .query(layout.signature(), |_, _, _| Ok(()))
        .map_err(|e| processing(super::CheckError::Access(e)))?;
    if !access
        .has_name(
            canonicalization,
            crate::xml::Name {
                namespace: crate::container::DS,
                local: "CanonicalizationMethod",
            },
        )
        .map_err(|e| processing(super::CheckError::Access(e)))?
    {
        return Err(CreationError::Ineligible {
            reference: canonicalization,
        });
    }
    if let Some(answer) = certificate::preflight_method(&access, new_method)
        .map_err(|e| processing(super::CheckError::Access(e)))?
    {
        return Err(CreationError::Algorithm {
            method: new_method,
            answer,
        });
    }
    let identity = match check::resolve(&access, new_method, provider).map_err(processing)? {
        certificate::Expected::Ready(identity) => identity,
        certificate::Expected::Answer(answer) => {
            return Err(CreationError::Algorithm {
                method: new_method,
                answer,
            });
        }
    };
    let choices = choose(
        &access,
        layout.signature(),
        new_method,
        &identity,
        provider,
        selected,
    )?;
    let mut pairs = work.vector();
    pairs.try_reserve_exact(choices.len()).map_err(resource)?;
    for reference in choices {
        let mut source = Input {
            xml,
            snapshot: layout.snapshot(),
            mode: Mode::Canonical {
                node: reference,
                method: canonicalization,
            },
        };
        let instruction = computed(&identity, &mut source, provider, work, reference)?;
        source.mode = Mode::Reference {
            signature: layout.signature(),
            node: reference,
        };
        let object = computed(&identity, &mut source, provider, work, reference)?;
        pairs
            .try_push(Pair {
                reference,
                instruction,
                object,
            })
            .map_err(resource)?;
    }
    access
        .query(layout.signature(), |_, _, _| Ok(()))
        .map_err(|e| processing(super::CheckError::Access(e)))?;
    Ok(Renewal {
        snapshot: layout.snapshot(),
        signature: layout.signature(),
        parent,
        canonicalization,
        digest: new_method,
        pairs: pairs.into_owned(),
    })
}

fn choose<'p, X: TimestampXml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    new_method: X::Id,
    identity: &certificate::FormatDigest<P::Identity>,
    provider: &P,
    mut selected: impl FnMut(Candidate<X::Id>, &W) -> Result<bool, P::Error>,
) -> CreationResult<OwnedVec<X::Id>, X, P::Error> {
    let work = access.execution();
    let processing = CreationError::Processing;
    let resource = |cause| {
        processing(super::CheckError::Resource {
            node: new_method,
            cause,
        })
    };
    let instructions = check::inventory(access, signature, new_method).map_err(processing)?;
    let mut choices = work.vector();
    for instruction in instructions {
        work.charge_work(1).map_err(resource)?;
        let choose = selected(
            Candidate {
                reference: instruction.node,
                location: instruction.location,
                status: instruction.status,
            },
            work,
        )
        .map_err(|cause| {
            processing(super::CheckError::Provider {
                node: instruction.node,
                cause,
            })
        })?;
        if !choose {
            continue;
        }
        if instruction.location != ObjectLocation::Detached || instruction.status != Status::Valid {
            return Err(CreationError::Ineligible {
                reference: instruction.node,
            });
        }
        let method = check::original_method(access, instruction.node)
            .map_err(|e| processing(super::CheckError::Property(e)))?;
        let old = match check::resolve(access, method, provider).map_err(processing)? {
            certificate::Expected::Ready(identity) => identity,
            certificate::Expected::Answer(answer) => {
                return Err(CreationError::Algorithm { method, answer });
            }
        };
        work.charge_work(1).map_err(resource)?;
        if provider
            .compare(old.identity(), identity.identity(), work)
            .map_err(|cause| {
                processing(super::CheckError::Provider {
                    node: method,
                    cause,
                })
            })?
            == core::cmp::Ordering::Equal
        {
            return Err(CreationError::Unchanged {
                reference: instruction.node,
            });
        }
        choices.try_push(instruction.node).map_err(resource)?;
    }
    Ok(choices.into_owned())
}

fn computed<'p, X: TimestampXml, P: DigestProvider<'p, X>, W: Work>(
    identity: &certificate::FormatDigest<P::Identity>,
    source: &mut Input<'_, X>,
    provider: &'p P,
    work: &W,
    node: X::Id,
) -> CreationResult<P::Output, X, P::Error> {
    match digest::compute_resolved::<P, _, _>(identity, source, provider, work)
        .map_err(|cause| CreationError::Processing(super::CheckError::Digest { node, cause }))?
    {
        Resolution::Supported(output) => Ok(output),
        Resolution::Unsupported => Err(CreationError::Algorithm {
            method: node,
            answer: Agreement::Unsupported,
        }),
        Resolution::Malformed => Err(CreationError::Algorithm {
            method: node,
            answer: Agreement::MalformedMethod,
        }),
    }
}
