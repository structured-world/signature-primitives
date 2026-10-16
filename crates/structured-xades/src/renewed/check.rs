//! EN319132-1 §5.5.3 processing over original authenticated Manifest inputs.

use super::{Catalogue, Pair};
use crate::{
    binary,
    certificate::{self, Agreement},
    container::DS,
    digest::{self, StreamingDigest},
    properties,
    reference::{
        Completeness, ObjectLocation, Parent, ReferenceXml, Replay, ReplayOutcome, VisitError,
    },
    timestamp::TimestampXml,
    xml::{Access, AccessError, Name, Snapshot, Xml},
};
use core::cmp::Ordering;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_cms::{
    provider::Resolution,
    stream::{Receiver, Source},
};

/// Completed processing state, independent of archive coverage or policy trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Every pair was examined; inspect each outcome before accepting renewal.
    Processed,
    /// No authenticated Manifest instruction references a detached resource.
    NoDetachedManifest,
    /// Actual resource provenance cannot establish the required detached case.
    UnclassifiedManifest,
    /// The selected new digest method/capability could not be used.
    Algorithm(Agreement),
}

/// Per-pair result; an unavailable explicit source is not a terminal refusal.
#[derive(Debug)]
pub enum PairOutcome<E> {
    /// Actual new digest agrees with the original declared value.
    Matches,
    /// Actual new digest differs from the declared value.
    Differs,
    /// No canonical original instruction has the declared reference digest.
    MissingReference,
    /// More than one original instruction has the declared reference digest.
    AmbiguousReference,
    /// The matching instruction does not name a proven detached resource.
    NotDetached,
    /// Old/new resolved algorithm identities are equal, contrary to §5.5.3.
    SameAlgorithm,
    /// Original/new method syntax, capability or declared width is unusable.
    Algorithm(Agreement),
    /// Explicit detached bytes are absent; subsequent pairs were still examined.
    Unavailable(E),
}

/// Original pair, uniquely selected reference when known, and completed result.
#[derive(Debug)]
pub struct PairCheck<N, E> {
    /// Original property/pair digest nodes.
    pub pair: Pair<N>,
    /// Unique original Manifest Reference, never reconstructed from a URI.
    pub reference: Option<N>,
    /// Historical old-target digest outcome, separate from authenticated parent
    /// instruction discovery and this new digest. None means no unique match.
    pub old_target_status: Option<crate::binding::Status>,
    /// Completed semantic result, separate from source/provider/resource errors.
    pub outcome: PairOutcome<E>,
}

/// Independently retained diagnostic results; no baseline level is asserted.
pub struct Report<N, D, G, E> {
    snapshot: Snapshot<D, G>,
    signature: N,
    property: N,
    state: State,
    pairs: OwnedVec<PairCheck<N, E>>,
    agrees: bool,
}
impl<N: Copy, D: Copy, G: Copy, E> Report<N, D, G, E> {
    /// Original source generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Signature authenticating the Manifest instructions.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original renewal property.
    #[must_use]
    pub fn property(&self) -> N {
        self.property
    }
    /// Completed property-level processing state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }
    /// Every pair in original order, including unavailable/mismatching inputs.
    #[must_use]
    pub fn pairs(&self) -> &[PairCheck<N, E>] {
        &self.pairs
    }
    /// O(1) summary of the new digest comparisons. This does not turn an
    /// unchecked/failed old-target result into success or assert a B level.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.agrees
    }
}

/// Original input-source refusal, including explicit immutable request absence.
#[derive(Debug)]
pub enum SourceError<E, N> {
    /// Original XML/current operation processing failed.
    Access(AccessError<E, N>),
    /// Explicit detached bytes were unavailable, never a generic URI failure.
    Unavailable {
        /// Original detached-object reference instruction.
        node: N,
        /// Exact immutable-request acquisition cause.
        cause: E,
    },
}

/// Terminal failures retain source/provider causes and real original nodes.
#[derive(Debug)]
pub enum CheckError<E, PE, N, D, G> {
    /// Original XML/source/current-operation refusal.
    Access(AccessError<E, N>),
    /// Original instruction shape could not supply a unique digest method.
    Property(properties::Error<E, N>),
    /// Declared digest lexical decoding/copy failed before provider effects.
    Binary(binary::Error<E, MemoryError, N, D, G>),
    /// Original selected-provider failure.
    Provider {
        /// Original method or value associated with provider processing.
        node: N,
        /// Original selected-provider cause.
        cause: PE,
    },
    /// Streaming source/provider/processing refusal at the real enclosing node.
    Digest {
        /// Original reference/value enclosure, not a logical stream offset.
        node: N,
        /// Exact original source/provider/driver cause.
        cause: digest::Error<SourceError<E, N>, PE>,
    },
    /// Metadata/capacity refused before traversal/storage growth.
    Resource {
        /// Original metadata/storage enclosure.
        node: N,
        /// Exact current admission refusal.
        cause: MemoryError,
    },
    /// Authenticated reference catalogue was incomplete or unchecked.
    Incomplete(Completeness<N>),
}

/// Original identity-domain processing result.
pub type CheckResult<T, X, PE> = Result<
    T,
    CheckError<<X as Xml>::Error, PE, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;
/// Report using the XML owner's source identity and original error type.
pub type Checked<X> =
    Report<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, <X as Xml>::Error>;

struct Instruction<N> {
    node: N,
    location: ObjectLocation,
    status: crate::binding::Status,
}
struct Expected<N> {
    pair: Pair<N>,
    reference: OwnedVec<u8>,
    object: OwnedVec<u8>,
}
struct Candidate<N, I, O> {
    instruction: Instruction<N>,
    old: certificate::Expected<I>,
    output: O,
}

type Candidates<X, P> = OwnedVec<
    Candidate<
        <X as Xml>::Id,
        <P as certificate::DigestProvider<X>>::Identity,
        <P as StreamingDigest<X>>::Output,
    >,
>;

fn memoize<X: TimestampXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    access: &Access<'_, X, W>,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    instructions: &[Instruction<X::Id>],
    identity: &certificate::FormatDigest<P::Identity>,
    provider: &P,
) -> CheckResult<Resolution<Candidates<X, P>>, X, P::Error> {
    let work = access.execution();
    let mut candidates = work.vector();
    let mut ordinal = 0;
    while ordinal < instructions.len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: reading.node,
            cause,
        })?;
        let instruction = &instructions[ordinal];
        let method = original_method(access, instruction.node).map_err(CheckError::Property)?;
        let old = resolve(access, method, provider)?;
        let mut source = Input {
            xml,
            snapshot: reading.snapshot,
            mode: Mode::Canonical {
                node: instruction.node,
                method: reading.canonicalization,
            },
        };
        let output =
            match digest::compute_resolved::<X, P, _, _>(identity, &mut source, provider, work)
                .map_err(|cause| CheckError::Digest {
                    node: instruction.node,
                    cause,
                })? {
                Resolution::Supported(output) => output,
                Resolution::Unsupported => return Ok(Resolution::Unsupported),
                Resolution::Malformed => return Ok(Resolution::Malformed),
            };
        candidates
            .try_push(Candidate {
                instruction: Instruction {
                    node: instruction.node,
                    location: instruction.location,
                    status: instruction.status,
                },
                old,
                output,
            })
            .map_err(|cause| CheckError::Resource {
                node: instruction.node,
                cause,
            })?;
        ordinal += 1;
    }
    Ok(Resolution::Supported(candidates.into_owned()))
}

enum Mode<N> {
    Canonical { node: N, method: N },
    Reference { signature: N, node: N },
}
struct Input<'a, X: TimestampXml> {
    xml: &'a X,
    snapshot: Snapshot<X::Document, X::Generation>,
    mode: Mode<X::Id>,
}
impl<X: TimestampXml> Source for Input<'_, X> {
    type Error = SourceError<X::Error, X::Id>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let access = Access::new(self.xml, self.snapshot, work);
        match self.mode {
            Mode::Canonical { node, method } => access
                .query(node, |xml, snapshot, work| {
                    xml.canonicalize(snapshot, node, method, receiver, work)
                })
                .map_err(SourceError::Access),
            Mode::Reference { signature, node } => {
                match access
                    .query(node, |xml, snapshot, work| {
                        xml.replay_reference(
                            snapshot,
                            signature,
                            node,
                            Replay::ReferenceOutput,
                            receiver,
                            work,
                        )
                    })
                    .map_err(SourceError::Access)?
                {
                    ReplayOutcome::Complete => Ok(()),
                    ReplayOutcome::Unavailable(cause) => {
                        Err(SourceError::Unavailable { node, cause })
                    }
                }
            }
        }
    }
}

/// Executes §5.5.3 over one complete authenticated instruction inventory.
/// Canonical instruction digests are computed once per reference, separately
/// from ordinary `ReferenceOutput` for the detached object. Every comparison is
/// provider/full-identity aware; there is no URI/width identity shortcut, second
/// XML parser, implicit acquisition or whole-input collector. Source unavailability
/// is retained per pair and continues; policy/resource/receiver errors terminate.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check<X: TimestampXml + binary::BinaryXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    provider: &P,
    work: &W,
) -> CheckResult<Checked<X>, X, P::Error> {
    let result = check_inner(xml, reading, provider, work)?;
    Access::new(xml, reading.snapshot, work)
        .query(reading.node, |_, _, _| Ok(()))
        .map_err(CheckError::Access)?;
    Ok(result)
}

fn check_inner<X: TimestampXml + binary::BinaryXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    provider: &P,
    work: &W,
) -> CheckResult<Checked<X>, X, P::Error> {
    let access = Access::new(xml, reading.snapshot, work);
    access
        .query(reading.node, |_, _, _| Ok(()))
        .map_err(CheckError::Access)?;
    if let Some(answer) =
        certificate::preflight_method(&access, reading.digest).map_err(CheckError::Access)?
    {
        return Ok(report(
            reading,
            State::Algorithm(answer),
            work.vector().into_owned(),
            false,
        ));
    }
    let expected = read_expected(xml, reading, work)?;
    let instructions = inventory(&access, reading)?;
    if let Some(state) = manifest_state::<X, W, P::Error>(&instructions, reading.node, work)? {
        return Ok(report(reading, state, work.vector().into_owned(), false));
    }
    let identity = match resolve(&access, reading.digest, provider)? {
        certificate::Expected::Ready(identity) => identity,
        certificate::Expected::Answer(answer) => {
            return Ok(report(
                reading,
                State::Algorithm(answer),
                work.vector().into_owned(),
                false,
            ));
        }
    };
    let width = provider.width(identity.identity());
    let mut usable = false;
    // Inspect every declared width before canonicalization/hash side effects.
    // Invalid pairs remain diagnostics; only other usable pairs justify work.
    for ordinal in 0..expected.len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: reading.node,
            cause,
        })?;
        let pair = &expected[ordinal];
        if let Some(width) = width
            && (pair.reference.len() != width || pair.object.len() != width)
        {
            continue;
        }
        usable = true;
    }
    let candidates = if usable {
        match memoize(xml, &access, reading, &instructions, &identity, provider)? {
            Resolution::Supported(candidates) => candidates,
            Resolution::Unsupported => {
                return Ok(report(
                    reading,
                    State::Algorithm(Agreement::Unsupported),
                    work.vector().into_owned(),
                    false,
                ));
            }
            Resolution::Malformed => {
                return Ok(report(
                    reading,
                    State::Algorithm(Agreement::MalformedMethod),
                    work.vector().into_owned(),
                    false,
                ));
            }
        }
    } else {
        work.vector().into_owned()
    };
    finish_pairs(
        xml,
        reading,
        &expected,
        &candidates,
        &identity,
        provider,
        work,
    )
}

fn manifest_state<X: Xml, W: Work, PE>(
    instructions: &[Instruction<X::Id>],
    node: X::Id,
    work: &W,
) -> CheckResult<Option<State>, X, PE> {
    let mut unknown = false;
    let mut ordinal = 0;
    while ordinal < instructions.len() {
        work.charge_work(1)
            .map_err(|cause| CheckError::Resource { node, cause })?;
        let instruction = &instructions[ordinal];
        if instruction.location == ObjectLocation::Detached {
            return Ok(None);
        }
        if instruction.location == ObjectLocation::Unknown {
            unknown = true;
        }
        ordinal += 1;
    }
    Ok(Some(if unknown {
        State::UnclassifiedManifest
    } else {
        State::NoDetachedManifest
    }))
}

fn finish_pairs<X: TimestampXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    expected: &[Expected<X::Id>],
    candidates: &[Candidate<X::Id, P::Identity, P::Output>],
    identity: &certificate::FormatDigest<P::Identity>,
    provider: &P,
    work: &W,
) -> CheckResult<Checked<X>, X, P::Error> {
    let mut results = work.vector();
    let mut agrees = true;
    let mut ordinal = 0;
    while ordinal < expected.len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: reading.node,
            cause,
        })?;
        let pair = &expected[ordinal];
        let result = process_pair(xml, reading, pair, candidates, identity, provider, work)?;
        agrees &= matches!(result.outcome, PairOutcome::Matches);
        results
            .try_push(result)
            .map_err(|cause| CheckError::Resource {
                node: pair.pair.node,
                cause,
            })?;
        ordinal += 1;
    }
    Ok(report(
        reading,
        State::Processed,
        results.into_owned(),
        agrees,
    ))
}

fn report<N: Copy, D: Copy, G: Copy, E>(
    reading: &Catalogue<N, D, G>,
    state: State,
    pairs: OwnedVec<PairCheck<N, E>>,
    agrees: bool,
) -> Report<N, D, G, E> {
    Report {
        snapshot: reading.snapshot,
        signature: reading.signature,
        property: reading.node,
        state,
        pairs,
        agrees,
    }
}

fn resolve<X: Xml, P: StreamingDigest<X>, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    provider: &P,
) -> CheckResult<certificate::Expected<P::Identity>, X, P::Error> {
    let resolved = access
        .query(node, |_, _, _| Ok(provider.resolve(access, node)))
        .map_err(CheckError::Access)?
        .map_err(|cause| CheckError::Provider { node, cause })?;
    Ok(match resolved {
        Resolution::Supported(identity) => certificate::baseline_digest::<X, P>(identity, provider),
        Resolution::Unsupported => certificate::Expected::Answer(Agreement::Unsupported),
        Resolution::Malformed => certificate::Expected::Answer(Agreement::MalformedMethod),
    })
}

fn original_method<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> properties::PropertyResult<X::Id, X> {
    let mut method = None;
    for child in access.children(node) {
        let child = child.map_err(properties::Error::Child)?;
        if access
            .has_name(
                child,
                Name {
                    namespace: DS,
                    local: "DigestMethod",
                },
            )
            .map_err(properties::Error::Access)?
        {
            if method.is_some() {
                return Err(properties::Error::Duplicate { node: child });
            }
            method = Some(child);
        }
    }
    method.ok_or(properties::Error::Missing {
        parent: node,
        local: "DigestMethod",
    })
}

fn inventory<X: ReferenceXml, W: Work, PE>(
    access: &Access<'_, X, W>,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
) -> CheckResult<OwnedVec<Instruction<X::Id>>, X, PE> {
    let work = access.execution();
    let mut entries = work.vector();
    let complete = access
        .query(reading.node, |xml, snapshot, work| {
            Ok(xml.visit_authenticated_references(
                snapshot,
                reading.signature,
                work,
                |descriptor| {
                    if matches!(descriptor.parent, Parent::Manifest(_)) {
                        entries
                            .try_push(Instruction {
                                node: descriptor.reference.node,
                                location: descriptor.object_location,
                                status: descriptor.reference.status,
                            })
                            .map_err(|cause| CheckError::Resource {
                                node: descriptor.reference.node,
                                cause,
                            })?;
                    }
                    Ok::<_, CheckError<X::Error, PE, X::Id, X::Document, X::Generation>>(())
                },
            ))
        })
        .map_err(CheckError::Access)?;
    let complete = match complete {
        Ok(complete) => complete,
        Err(VisitError::Processing(cause)) => {
            return Err(CheckError::Access(AccessError::Xml(cause)));
        }
        Err(VisitError::Visitor(cause)) => return Err(cause),
    };
    if complete != Completeness::Complete {
        return Err(CheckError::Incomplete(complete));
    }
    Ok(entries.into_owned())
}

fn read_expected<X: binary::BinaryXml, W: Work, PE>(
    xml: &X,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    work: &W,
) -> CheckResult<OwnedVec<Expected<X::Id>>, X, PE> {
    let mut expected = work.vector();
    for ordinal in 0..reading.pairs.len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: reading.node,
            cause,
        })?;
        let pair = reading.pairs[ordinal];
        let copy = |node| {
            binary::with_octets(
                xml,
                binary::Location {
                    snapshot: reading.snapshot,
                    node,
                },
                work,
                |bytes| {
                    let mut owned = work.vector();
                    owned.try_extend_from_slice(bytes)?;
                    Ok(owned.into_owned())
                },
            )
            .map_err(CheckError::Binary)
        };
        let reference = copy(pair.reference)?;
        let object = copy(pair.object)?;
        expected
            .try_push(Expected {
                pair,
                reference,
                object,
            })
            .map_err(|cause| CheckError::Resource {
                node: pair.node,
                cause,
            })?;
    }
    Ok(expected.into_owned())
}

fn process_pair<X: TimestampXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    reading: &Catalogue<X::Id, X::Document, X::Generation>,
    pair: &Expected<X::Id>,
    candidates: &[Candidate<X::Id, P::Identity, P::Output>],
    identity: &certificate::FormatDigest<P::Identity>,
    provider: &P,
    work: &W,
) -> CheckResult<PairCheck<X::Id, X::Error>, X, P::Error> {
    let width = provider.width(identity.identity());
    let mut result = PairCheck {
        pair: pair.pair,
        reference: None,
        old_target_status: None,
        outcome: PairOutcome::MissingReference,
    };
    if let Some(width) = width
        && (pair.reference.len() != width || pair.object.len() != width)
    {
        result.outcome = PairOutcome::Algorithm(Agreement::MalformedValue);
        return Ok(result);
    }
    let mut selected = None;
    let mut ordinal = 0;
    while ordinal < candidates.len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: pair.pair.node,
            cause,
        })?;
        let candidate = &candidates[ordinal];
        ordinal += 1;
        if provider
            .matches_output(
                identity.identity(),
                &candidate.output,
                &pair.reference,
                work,
            )
            .map_err(|cause| CheckError::Provider {
                node: pair.pair.reference,
                cause,
            })?
        {
            if selected.is_some() {
                result.outcome = PairOutcome::AmbiguousReference;
                return Ok(result);
            }
            selected = Some(candidate);
        }
    }
    let Some(candidate) = selected else {
        return Ok(result);
    };
    let node = candidate.instruction.node;
    result.reference = Some(node);
    result.old_target_status = Some(candidate.instruction.status);
    if candidate.instruction.location != ObjectLocation::Detached {
        result.outcome = PairOutcome::NotDetached;
        return Ok(result);
    }
    // EN319132-1 §5.5.3 step3/note2 processes the signed instruction WITHOUT
    // computing its old target digest. In particular, unavailable old bytes
    // must reach step3/6 even if their historical target outcome is Invalid.
    // The authenticated Manifest parent, not that target outcome, establishes
    // original instruction integrity; preserve both facts independently.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let old = match &candidate.old {
        certificate::Expected::Ready(old) => old,
        certificate::Expected::Answer(answer) => {
            result.outcome = PairOutcome::Algorithm(*answer);
            return Ok(result);
        }
    };
    if provider
        .compare(identity.identity(), old.identity(), work)
        .map_err(|cause| CheckError::Provider { node, cause })?
        == Ordering::Equal
    {
        result.outcome = PairOutcome::SameAlgorithm;
        return Ok(result);
    }
    let mut source = Input {
        xml,
        snapshot: reading.snapshot,
        mode: Mode::Reference {
            signature: reading.signature,
            node,
        },
    };
    result.outcome = match digest::run_resolved::<X, P, _, _>(
        identity,
        &pair.object,
        &mut source,
        provider,
        work,
    ) {
        Ok(Agreement::Matches) => PairOutcome::Matches,
        Ok(Agreement::Differs) => PairOutcome::Differs,
        Ok(answer) => PairOutcome::Algorithm(answer),
        Err(digest::Error::Source(SourceError::Unavailable { cause, .. })) => {
            PairOutcome::Unavailable(cause)
        }
        Err(cause) => {
            return Err(CheckError::Digest {
                node: pair.pair.object,
                cause,
            });
        }
    };
    Ok(result)
}
