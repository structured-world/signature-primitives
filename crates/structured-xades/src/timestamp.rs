//! Timestamp input selection and streaming over original XML owner ranges.

use crate::binary::{self, BinaryXml, Location};
use crate::binding::{Bound, Coverage, Status};
use crate::container::{DS, XADES};
use crate::reference::{Boolean, LexicalSource, ReferenceXml, ReplayOutcome, Resolution};
use crate::xml::{Access, AccessError, ChildError, Name, Snapshot, Xml};
use crate::{ISSUER, Xades};
use structured_asn1::{
    Reader,
    memory::{Execution, MemoryError, OwnedVec, Work},
};
use structured_cms::stream::{Receiver, Refused, Source};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{CheckContext, CheckedTimestamp, TokenExtension},
};
use structured_ltv::timestamp::{CheckedActor, Purpose, Verified};

/// Namespace of the current archive timestamp property.
pub const XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

mod counters;
mod coverage;
mod material;
pub use counters::{
    CounterStamp, CounterTimestampError, CounterTimestampResult, CounterTimestamps,
    counter_timestamps,
};
pub use coverage::{CoverageError, CoverageFor};
mod profile;
mod selection;
mod tokens;
pub use material::{Carried, CarriedCause, CarriedError, CarriedMaterial, OtherCarried};
pub use profile::{DigestError, DigestUse};
pub use selection::{
    RequirementError, RequirementResult, TimestampSelection, requirements,
    requirements_with_counters,
};
pub use tokens::{
    TokenEntry, TokenPipelineError, TokenPipelineResult, TokenReading, TokenSource, TokenView,
    with_counter_tokens, with_tokens,
};

/// An implicit timestamp input prescribed by the current baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Canonical original `SignatureValue` element, not decoded signature octets.
    Signature,
    /// Direct `SignedInfo` reference outputs, excluding `SignedProperties`.
    AllDataObjects,
    /// Explicit Include order over authenticated SignedInfo/Manifest references.
    IndividualDataObjects,
    /// `SignatureValue`, earlier signature timestamps and validation references.
    SignatureAndReferences,
    /// Earlier validation references, without signature or data-object input.
    ReferencesOnly,
    /// Original reference outputs and earlier signature/validation components.
    Archive,
}

impl Role {
    /// What a timestamp of this role proves the existence of.
    #[must_use]
    pub fn purpose(self) -> Purpose {
        match self {
            Self::AllDataObjects | Self::IndividualDataObjects => Purpose::Content,
            Self::Signature => Purpose::Signature,
            Self::SignatureAndReferences | Self::ReferencesOnly => Purpose::ValidationData,
            Self::Archive => Purpose::Archive,
        }
    }
}

/// Failure to select or acquire an original timestamp input.
#[derive(Debug)]
pub enum InputError<E, N> {
    /// The streaming driver retains the original callback refusal.
    Receiver(Refused),
    /// XML processing, generation or current resource refusal.
    Access(AccessError<E, N>),
    /// Original detached bytes are not available in the immutable request.
    /// This is incomplete input, not a resource refusal or successful timestamp.
    Unavailable {
        /// Actual original reference instruction.
        node: N,
        /// Original typed acquisition cause supplied by the XML owner.
        cause: E,
    },
    /// Original direct-child traversal failure.
    Child(ChildError<E, N>),
    /// Accounted metadata retention refused before storage growth.
    Resource {
        /// Original timestamp container.
        node: N,
        /// Original admission refusal.
        cause: MemoryError,
    },
    /// Required schema role is missing.
    Missing {
        /// Original enclosing node.
        node: N,
        /// Required role's local name.
        local: &'static str,
    },
    /// A node has no role in this baseline timestamp container.
    Unexpected {
        /// Original node identity.
        node: N,
    },
    /// A singleton field or `SignatureTimeStamp` token is repeated.
    Duplicate {
        /// Repeated original node.
        node: N,
    },
    /// The original `CanonicalizationMethod` occurs after token content.
    Order {
        /// Original out-of-order method.
        node: N,
    },
    /// Timestamp is not a direct unsigned property of the selected signature.
    Foreign {
        /// Original requested timestamp.
        node: N,
    },
    /// Individual Include requires an explicitly written true boolean.
    ReferencedData {
        /// Original Include node.
        node: N,
        /// Presence/value classification from the XML lexical owner.
        value: Boolean,
    },
    /// Include did not identify an authenticated eligible reference instruction.
    Reference {
        /// Original Include, not a fabricated URI byte offset.
        node: N,
        /// Precise original lookup outcome.
        resolution: Resolution<()>,
    },
}

/// XML-owned canonicalization and reference replay, using the actual source view.
///
/// Each call rejects foreign/stale identities at access and enforces both XML
/// policy and current Work. Method is the original `CanonicalizationMethod` node,
/// including parameters such as Exclusive C14N `PrefixList`; no second algorithm
/// dispatcher or fabricated parameter representation is introduced here.
pub trait TimestampXml: ReferenceXml {
    /// Streams the original element and its content under the timestamp method.
    /// Ancestor namespace/xml context and method parameters are owner obligations.
    /// Successful return means complete output; receiver refusal must stop work.
    fn canonicalize<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        method: Self::Id,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error>;
}

/// One original timestamp container, before RFC3161 mathematical/authority checks.
#[derive(Debug)]
pub struct Stamp<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    parent: N,
    method: N,
    role: Role,
    tokens: OwnedVec<N>,
    includes: OwnedVec<N>,
}

impl<N: Copy, D: Copy, G: Copy> Stamp<N, D, G> {
    /// Original root or nested signature whose actual input is timestamped.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original timestamp location in its exact XML generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original timestamp container identity.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original canonicalization method and parameters, owned by the XML adapter.
    #[must_use]
    pub fn method(&self) -> N {
        self.method
    }
    /// Exact input role; this is not proof of an attained signature level.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
    /// Original `EncapsulatedTimeStamp` nodes in their source order.
    #[must_use]
    pub fn tokens(&self) -> &[N] {
        &self.tokens
    }
}

/// Timestamp metadata using this XML owner's stable source identity types.
pub type Timestamp<X> = Stamp<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// Independently retained positive timestamp using original XML identities.
pub type VerifiedTimestamp<X> =
    Verified<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, Xades>;
/// Successful timestamp bound to the exact certificate/key used for checking.
pub type TimestampActor<'certificate, 'document, X> = CheckedActor<
    'certificate,
    'document,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
    Xades,
>;
/// Original cause and node location survive timestamp preparation failures.
pub type InputResult<T, X> = Result<T, InputError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Complete common timestamp execution with original XML input selection.
///
/// The caller selects the TSA certificate/key and supplies explicit UTC facts.
/// The resulting common facts/evidence still require caller path, revocation and
/// algorithm-policy acceptance; this object never chooses a trusted certificate.
pub struct Check<'xml, 'document, 'certificate, 'context, X, P> {
    /// Original XML owner, not a serialized or reconstructed document.
    pub xml: &'xml X,
    /// One selected provider for token signature, ESS and covered-input imprint.
    pub provider: &'context P,
    /// Original candidate certificate/key, producing reader and explicit time facts.
    pub context: &'context CheckContext<'document, 'certificate>,
}

/// Original timestamp selection or complete-check refusal.
#[derive(Debug)]
pub enum CheckError<E, N, D, G, PE, RE> {
    /// Original input selection, snapshot or resource refusal.
    Input(InputError<E, N>),
    /// Caller requested a token ordinal not present in this parsed timestamp.
    TokenIndex {
        /// Original timestamp container.
        node: N,
        /// Requested ordinal; it is not a document byte offset.
        index: usize,
    },
    /// Unchanged common cause and binary-source/XML coordinate context.
    Token(TokenCheckError<E, N, D, G, PE, RE>),
}

/// Common timestamp-check cause nested in its binary-source/XML enclosure.
pub type TokenCheckError<E, N, D, G, PE, RE> = binary::Error<
    E,
    binary::TokenError<
        structured_cms::timestamp::ProfileCheckError<InputError<E, N>, PE, RE, DigestError>,
    >,
    N,
    D,
    G,
>;

/// Complete-check result using the XML owner's original identity types.
pub type CheckResult<R, X, PE, RE> = Result<
    R,
    CheckError<
        <X as Xml>::Error,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
        PE,
        RE,
    >,
>;

impl<'document, 'certificate, X: TimestampXml + BinaryXml, P>
    Check<'_, 'document, 'certificate, '_, X, P>
{
    /// Retains positive evidence with the actual selected certificate/key.
    ///
    /// A later path/status phase cannot silently replace this signer or its
    /// inherited parameters. The same complete token/input kernel runs once;
    /// no certificate bytes, provider state or temporary context are copied.
    /// Path/status/UTC chronology and application trust remain separate.
    #[expect(
        clippy::result_large_err,
        reason = "retain original opaque causes and source maps without allocating on refusal"
    )]
    pub fn retain_actor<PE, RE>(
        &self,
        bound: &Bound<X::Id, X::Document, X::Generation>,
        stamp: &Timestamp<X>,
        index: usize,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> CheckResult<Option<TimestampActor<'certificate, 'document, X>>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        Ok(self
            .retain(bound, stamp, index, operation, recognizes)?
            .map(|verified| {
                CheckedActor::new(ISSUER, verified, self.context.certificate, self.context.key)
            }))
    }

    /// Retains positive common evidence together with its actual XML input role,
    /// selected signature and original token identity, without copying evidence.
    /// No positive record is returned for a completed negative check. TSA trust,
    /// path/status, material completeness and baseline attainment remain separate.
    #[expect(
        clippy::result_large_err,
        reason = "retain original opaque causes and source maps without allocating on refusal"
    )]
    pub fn retain<PE, RE>(
        &self,
        bound: &Bound<X::Id, X::Document, X::Generation>,
        stamp: &Timestamp<X>,
        index: usize,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> CheckResult<Option<VerifiedTimestamp<X>>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        fn evidence(checked: CheckedTimestamp<'_>) -> Option<structured_cms::timestamp::Evidence> {
            checked.into_evidence()
        }
        let located = self.run(bound, stamp, index, operation, recognizes, evidence)?;
        Ok(located.value.map(|evidence| {
            Verified::new(
                ISSUER,
                located.location,
                stamp.signature,
                stamp.node,
                stamp.role.purpose(),
                evidence,
            )
        }))
    }

    /// Checks one actual RFC3161 token against its prescribed original XML input.
    ///
    /// The scoped visitor receives the common complete-check facts. It may move
    /// independently retained Evidence out, but cannot retain borrowed token or
    /// decoded XML-buffer models. A readable malformed token remains a common
    /// nonconformance refusal rather than producing successful timestamp evidence.
    #[expect(
        clippy::result_large_err,
        reason = "preserve opaque original failures and admitted source maps without allocating while handling a refusal"
    )]
    pub fn run<R, PE, RE>(
        &self,
        bound: &Bound<X::Id, X::Document, X::Generation>,
        stamp: &Timestamp<X>,
        index: usize,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        visitor: impl for<'checked> FnOnce(CheckedTimestamp<'checked>) -> R,
    ) -> CheckResult<binary::LocatedValue<R, X>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if index >= stamp.tokens().len() {
            return Err(CheckError::TokenIndex {
                node: stamp.node(),
                index,
            });
        }
        let execution = operation.execution();
        let input =
            Input::prepare(self.xml, bound, stamp, &execution).map_err(CheckError::Input)?;
        self.run_prepared(stamp, index, operation, input, recognizes, visitor)
    }

    /// Check a timestamp belonging to an actual nested countersignature. Its
    /// privately bound source scope selects the CHILD input through the root's
    /// same token/profile kernel, without inventing a child baseline binding.
    #[expect(
        clippy::result_large_err,
        reason = "retain original source maps and opaque callback causes"
    )]
    pub fn retain_counter_actor<PE, RE>(
        &self,
        counter: &CounterStamp<X::Id, X::Document, X::Generation>,
        index: usize,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> CheckResult<Option<TimestampActor<'certificate, 'document, X>>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if index >= counter.stamp().tokens().len() {
            return Err(CheckError::TokenIndex {
                node: counter.stamp().node(),
                index,
            });
        }
        let execution = operation.execution();
        let input = counter
            .input(self.xml, &execution)
            .map_err(CheckError::Input)?;
        let stamp = counter.stamp();
        let located = self.run_prepared(stamp, index, operation, input, recognizes, |checked| {
            checked.into_evidence()
        })?;
        Ok(located.value.map(|evidence| {
            CheckedActor::new(
                ISSUER,
                Verified::new(
                    ISSUER,
                    located.location,
                    stamp.signature,
                    stamp.node,
                    stamp.role.purpose(),
                    evidence,
                ),
                self.context.certificate,
                self.context.key,
            )
        }))
    }

    /// Reuse an already decoded/parsed original child token from the frozen
    /// pool. The SAME common profile/check kernel supplies evidence; a fresh
    /// source reader preserves original and current ceilings without reparsing.
    /// Original signature/property/token/role are paid and matched BEFORE any
    /// provider or input replay. No receipt can relabel a sibling/root token.
    #[expect(
        clippy::result_large_err,
        reason = "retain original source maps and opaque callback causes"
    )]
    pub fn retain_counter_from<PE, RE>(
        &self,
        counter: &CounterStamp<X::Id, X::Document, X::Generation>,
        entry: TokenEntry<'_, '_, X::Id, X::Document, X::Generation>,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> CheckResult<Option<TimestampActor<'certificate, 'document, X>>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let stamp = counter.stamp();
        let execution = operation.execution();
        let access = Access::new(self.xml, stamp.snapshot, &execution);
        access
            .query(stamp.node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(|cause| CheckError::Input(InputError::Access(cause)))?
            .map_err(|cause| {
                CheckError::Input(InputError::Resource {
                    node: stamp.node,
                    cause,
                })
            })?;
        let source = entry.source;
        let equal = |left, right| {
            access.equal_id(left, right).map_err(|cause| {
                CheckError::Input(InputError::Resource {
                    node: stamp.node,
                    cause,
                })
            })
        };
        let expected = stamp.tokens.get(source.token_index());
        if source.location().snapshot != stamp.snapshot
            || !equal(source.signature(), stamp.signature)?
            || !equal(source.property(), stamp.node)?
            || source.role() != stamp.role
            || match expected {
                Some(expected) => !equal(source.location().node, *expected)?,
                None => true,
            }
        {
            return Err(CheckError::Input(InputError::Foreign {
                node: source.location().node,
            }));
        }
        let mut input = counter
            .input(self.xml, &execution)
            .map_err(CheckError::Input)?;
        let location = source.location();
        let reader = entry.reader_in(operation).map_err(|cause| {
            CheckError::Token(binary::Error::ReaderCreation { location, cause })
        })?;
        let checked = entry
            .reading
            .token()
            .check_with_profile(
                self.provider,
                &reader,
                self.context,
                &mut input,
                recognizes,
                |fields| profile::check(&fields),
            )
            .map_err(|cause| {
                CheckError::Token(binary::Error::Callback {
                    location,
                    cause: binary::TokenError::Callback(cause),
                })
            })?;
        let evidence = checked.into_evidence();
        access
            .query(stamp.node, |_, _, _| Ok(()))
            .map_err(|cause| CheckError::Input(InputError::Access(cause)))?;
        Ok(evidence.map(|evidence| {
            CheckedActor::new(
                ISSUER,
                Verified::new(
                    ISSUER,
                    location,
                    stamp.signature,
                    stamp.node,
                    stamp.role.purpose(),
                    evidence,
                ),
                self.context.certificate,
                self.context.key,
            )
        }))
    }

    #[expect(
        clippy::result_large_err,
        reason = "retain original source maps and opaque callback causes"
    )]
    fn run_prepared<R, PE, RE>(
        &self,
        stamp: &Timestamp<X>,
        index: usize,
        operation: &Reader<'_>,
        mut input: Input<'_, X>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        visitor: impl for<'checked> FnOnce(CheckedTimestamp<'checked>) -> R,
    ) -> CheckResult<binary::LocatedValue<R, X>, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let Some(&node) = stamp.tokens.get(index) else {
            return Err(CheckError::TokenIndex {
                node: stamp.node,
                index,
            });
        };
        let location = Location {
            snapshot: stamp.snapshot,
            node,
        };
        binary::with_token(self.xml, location, operation, |token, reader| {
            let checked = token.check_with_profile(
                self.provider,
                reader,
                self.context,
                &mut input,
                recognizes,
                |fields| profile::check(&fields),
            )?;
            Ok(binary::Located {
                location,
                value: visitor(checked),
            })
        })
        .map_err(CheckError::Token)
    }
}

/// Reads an implicit baseline timestamp belonging to the bound selected signature.
///
/// Explicit/distributed Include forms are not baseline direct-incorporation inputs.
/// XML timestamps are not RFC3161 tokens. Missing canonicalization is preserved
/// as a baseline violation rather than selecting an undocumented method default.
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    node: X::Id,
) -> InputResult<Timestamp<X>, X> {
    read_in(access, bound.containers(), node)
}

fn read_in<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
    node: X::Id,
) -> InputResult<Timestamp<X>, X> {
    let parent = unsigned_parent_in(access, layout, node)?;
    let mut contained = false;
    for child in access.children(parent) {
        let child = child.map_err(InputError::Child)?;
        if access
            .equal_id(child, node)
            .map_err(|cause| InputError::Resource { node: child, cause })?
        {
            contained = true;
        }
    }
    if !contained {
        return Err(InputError::Foreign { node });
    }
    let role = if named(access, node, XADES, "SignatureTimeStamp")? {
        Role::Signature
    } else if named(access, node, XADES_141, "ArchiveTimeStamp")? {
        Role::Archive
    } else if named(access, node, XADES_141, "SigAndRefsTimeStampV2")? {
        Role::SignatureAndReferences
    } else if named(access, node, XADES_141, "RefsOnlyTimeStampV2")? {
        Role::ReferencesOnly
    } else {
        return Err(InputError::Unexpected { node });
    };
    read_fields(access, layout.signature(), parent, node, role)
}

pub(crate) fn unsigned_parent<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    node: X::Id,
) -> InputResult<X::Id, X> {
    unsigned_parent_in(access, bound.containers(), node)
}

fn unsigned_parent_in<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
    node: X::Id,
) -> InputResult<X::Id, X> {
    if layout.snapshot() != access.snapshot() {
        return Err(InputError::Access(AccessError::Changed { node }));
    }
    let unsigned = layout.unsigned().ok_or(InputError::Foreign { node })?;
    singleton(access, unsigned, XADES, "UnsignedSignatureProperties")
}

/// Reads an implicit `AllDataObjectsTimeStamp` from the selected signature's
/// authenticated data-object properties. Explicit `Individual` Include selection
/// is a different processing contract and cannot be inferred from this input.
pub fn read_all_data_objects<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &crate::properties::Reading<X>,
    node: X::Id,
) -> InputResult<Timestamp<X>, X> {
    read_data_objects(access, bound, signed, node, Role::AllDataObjects)
}

/// Reads explicit Individual inputs only from authenticated signed properties.
/// Include resolution is deferred to input preparation, before replay or hashing.
pub fn read_individual_data_objects<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &crate::properties::Reading<X>,
    node: X::Id,
) -> InputResult<Timestamp<X>, X> {
    read_data_objects(access, bound, signed, node, Role::IndividualDataObjects)
}

fn read_data_objects<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &crate::properties::Reading<X>,
    node: X::Id,
    role: Role,
) -> InputResult<Timestamp<X>, X> {
    let layout = bound.containers();
    if signed.snapshot() != layout.snapshot() {
        return Err(InputError::Foreign { node });
    }
    if !access
        .equal_id(signed.signature(), layout.signature())
        .map_err(|cause| InputError::Resource { node, cause })?
    {
        return Err(InputError::Foreign { node });
    }
    if access.snapshot() != signed.snapshot() {
        return Err(InputError::Access(AccessError::Changed { node }));
    }
    let objects = signed.data_objects().ok_or(InputError::Foreign { node })?;
    read_object_fields(access, layout, objects, node, role)
}

fn read_object_fields<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
    objects: &crate::properties::DataObjects<X::Id>,
    node: X::Id,
    role: Role,
) -> InputResult<Timestamp<X>, X> {
    let mut contained = false;
    for index in 0..objects.entries().len() {
        access
            .query(node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(|cause| InputError::Resource { node, cause })?;
        let entry = objects.entries()[index];
        if access
            .equal_id(entry.node, node)
            .map_err(|cause| InputError::Resource { node, cause })?
        {
            let expected = if role == Role::IndividualDataObjects {
                crate::properties::DataObjectRole::IndividualTimestamp
            } else {
                crate::properties::DataObjectRole::AllTimestamp
            };
            if entry.role != expected {
                return Err(InputError::Unexpected { node });
            }
            contained = true;
            break;
        }
    }
    if !contained {
        return Err(InputError::Foreign { node });
    }
    read_fields(access, layout.signature(), objects.parent(), node, role)
}

fn read_fields<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    parent: X::Id,
    node: X::Id,
    role: Role,
) -> InputResult<Timestamp<X>, X> {
    let mut method = None;
    let mut tokens = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(InputError::Access)?;
    let mut includes = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(InputError::Access)?;
    for child in access.children(node) {
        let child = child.map_err(InputError::Child)?;
        if named(access, child, XADES, "Include")? {
            if role != Role::IndividualDataObjects {
                return Err(InputError::Unexpected { node: child });
            }
            if method.is_some() || !tokens.is_empty() {
                return Err(InputError::Order { node: child });
            }
            includes
                .try_push(child)
                .map_err(|cause| InputError::Resource { node, cause })?;
        } else if named(access, child, DS, "CanonicalizationMethod")? {
            if method.is_some() {
                return Err(InputError::Duplicate { node: child });
            }
            if !tokens.is_empty() {
                return Err(InputError::Order { node: child });
            }
            method = Some(child);
        } else if named(access, child, XADES, "EncapsulatedTimeStamp")? {
            if role == Role::Signature && !tokens.is_empty() {
                return Err(InputError::Duplicate { node: child });
            }
            tokens
                .try_push(child)
                .map_err(|cause| InputError::Resource { node, cause })?;
        } else {
            return Err(InputError::Unexpected { node: child });
        }
    }
    // EN319132-1 §§4.5/5.3/6.3(n): explicit method for generated baseline,
    // and exactly one RFC3161 token per SignatureTimeStamp. Archive and
    // AllDataObjectsTimeStamp (§5.2.8.1) may each carry multiple tokens.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let method = method.ok_or(InputError::Missing {
        node,
        local: "CanonicalizationMethod",
    })?;
    if tokens.is_empty() {
        return Err(InputError::Missing {
            node,
            local: "EncapsulatedTimeStamp",
        });
    }
    if role == Role::IndividualDataObjects && includes.is_empty() {
        return Err(InputError::Missing {
            node,
            local: "Include",
        });
    }
    Ok(Stamp {
        snapshot: access.snapshot(),
        signature,
        node,
        parent,
        method,
        role,
        tokens: tokens.into_owned(),
        includes: includes.into_owned(),
    })
}

#[derive(Debug, Clone, Copy)]
enum Part<N> {
    Element(N),
    Reference { node: N, covered: Option<N> },
}

/// Prepared original input sequence; no canonical XML is buffered here.
pub struct Input<'a, X: TimestampXml> {
    xml: &'a X,
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    timestamp: X::Id,
    method: X::Id,
    role: Role,
    parts: OwnedVec<Part<X::Id>>,
}

impl<'a, X: TimestampXml> Input<'a, X> {
    /// Selects every original input part before C14N, hashing or source callbacks.
    pub fn prepare<W: Work>(
        xml: &'a X,
        bound: &Bound<X::Id, X::Document, X::Generation>,
        stamp: &Timestamp<X>,
        execution: &W,
    ) -> InputResult<Self, X> {
        Self::prepare_in(xml, bound.containers(), stamp, execution)
    }

    fn prepare_in<W: Work>(
        xml: &'a X,
        layout: &crate::container::Layout<X>,
        stamp: &Timestamp<X>,
        execution: &W,
    ) -> InputResult<Self, X> {
        if stamp.snapshot != layout.snapshot() {
            return Err(InputError::Foreign { node: stamp.node });
        }
        let access = Access::new(xml, stamp.snapshot, execution);
        let refusal = |cause| InputError::Resource {
            node: stamp.node,
            cause,
        };
        if !access
            .equal_id(stamp.signature, layout.signature())
            .map_err(refusal)?
        {
            return Err(InputError::Foreign { node: stamp.node });
        }
        let mut parts = execution.vector();
        match stamp.role {
            Role::Signature => {
                let value = singleton(&access, stamp.signature, DS, "SignatureValue")?;
                parts.try_push(Part::Element(value)).map_err(refusal)?;
            }
            Role::AllDataObjects => {
                // EN319132-1 §5.2.8.1: direct SignedInfo references only, in order,
                // except those referencing SignedProperties. A signed Manifest's
                // referenced targets do not add another traversal to this input.
                // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
                append_references(&access, stamp, Some(layout.signed()), &mut parts)?;
            }
            Role::IndividualDataObjects => {
                append_includes(&access, stamp, layout.signed(), &mut parts)?;
            }
            Role::SignatureAndReferences | Role::ReferencesOnly => {
                append_validation_references(&access, stamp, &mut parts)?;
            }
            Role::Archive => {
                // EN319132-1 §5.5.2.3: Reference outputs, SignedInfo, SignatureValue,
                // optional KeyInfo, earlier unsigned properties, other Objects.
                append_references(&access, stamp, None, &mut parts)?;
                let value = singleton(&access, stamp.signature, DS, "SignatureValue")?;
                let signed_info = singleton(&access, stamp.signature, DS, "SignedInfo")?;
                parts
                    .try_push(Part::Element(signed_info))
                    .map_err(refusal)?;
                parts.try_push(Part::Element(value)).map_err(refusal)?;
                if let Some(key) = optional(&access, stamp.signature, DS, "KeyInfo")? {
                    parts.try_push(Part::Element(key)).map_err(refusal)?;
                }
                let mut reached = false;
                for child in access.children(stamp.parent) {
                    let node = child.map_err(InputError::Child)?;
                    if access.equal_id(node, stamp.node).map_err(refusal)? {
                        reached = true;
                        break;
                    }
                    parts.try_push(Part::Element(node)).map_err(refusal)?;
                }
                if !reached {
                    return Err(InputError::Foreign { node: stamp.node });
                }
                for child in access.children(stamp.signature) {
                    let node = child.map_err(InputError::Child)?;
                    if !access.equal_id(node, layout.object()).map_err(refusal)?
                        && named(&access, node, DS, "Object")?
                    {
                        parts.try_push(Part::Element(node)).map_err(refusal)?;
                    }
                }
            }
        }
        Ok(Self {
            xml,
            snapshot: stamp.snapshot,
            signature: stamp.signature,
            timestamp: stamp.node,
            method: stamp.method,
            role: stamp.role,
            parts: parts.into_owned(),
        })
    }

    /// Original enclosing XML location for a logical streamed-source failure.
    /// A logical stream offset must never be reported as a physical XML byte offset.
    #[must_use]
    pub fn location(&self) -> (Snapshot<X::Document, X::Generation>, X::Id) {
        (self.snapshot, self.timestamp)
    }
}

fn append_validation_references<X: TimestampXml, W: Work>(
    access: &Access<'_, X, W>,
    stamp: &Timestamp<X>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    // EN319132-1 A.1.5.1.2/A.1.5.2.2: implicit same-parent input uses
    // ORIGINAL preceding property order, not the order of the role list.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let refusal = |cause| InputError::Resource {
        node: stamp.node,
        cause,
    };
    let with_signature = stamp.role == Role::SignatureAndReferences;
    if with_signature {
        let value = singleton(access, stamp.signature, DS, "SignatureValue")?;
        parts.try_push(Part::Element(value)).map_err(refusal)?;
    }
    let mut found = [false; 4];
    let roles = [
        (XADES_141, "CompleteCertificateRefsV2"),
        (XADES, "CompleteRevocationRefs"),
        (XADES_141, "AttributeCertificateRefsV2"),
        (XADES, "AttributeRevocationRefs"),
    ];
    let mut reached = false;
    for child in access.children(stamp.parent) {
        let node = child.map_err(InputError::Child)?;
        if access.equal_id(node, stamp.node).map_err(refusal)? {
            reached = true;
            break;
        }
        let mut selected = with_signature && named(access, node, XADES, "SignatureTimeStamp")?;
        for (index, (namespace, local)) in roles.iter().enumerate() {
            if named(access, node, namespace, local)? {
                if found[index] {
                    return Err(InputError::Duplicate { node });
                }
                found[index] = true;
                selected = true;
                break;
            }
        }
        if selected {
            parts.try_push(Part::Element(node)).map_err(refusal)?;
        }
    }
    if !reached {
        return Err(InputError::Foreign { node: stamp.node });
    }
    for index in 0..2 {
        if !found[index] {
            return Err(InputError::Missing {
                node: stamp.node,
                local: roles[index].1,
            });
        }
    }
    Ok(())
}

fn append_includes<X: TimestampXml, W: Work>(
    access: &Access<'_, X, W>,
    stamp: &Timestamp<X>,
    signed_properties: X::Id,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    // EN319132-1 §5.2.8.2: explicit Include order, true referencedData,
    // SignedInfo OR signed Manifest references; SignedProperties excluded.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    for index in 0..stamp.includes.len() {
        access
            .query(stamp.node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(|cause| InputError::Resource {
                node: stamp.node,
                cause,
            })?;
        let include = stamp.includes[index];
        let value = access
            .query(include, |xml, snapshot, work| {
                xml.boolean_attribute(
                    snapshot,
                    include,
                    Name {
                        namespace: "",
                        local: "referencedData",
                    },
                    work,
                )
            })
            .map_err(InputError::Access)?;
        if value != Boolean::Value(true) {
            return Err(InputError::ReferencedData {
                node: include,
                value,
            });
        }
        let resolved = access
            .query(include, |xml, snapshot, work| {
                xml.resolve_reference(
                    snapshot,
                    stamp.signature,
                    include,
                    LexicalSource::Attribute(Name {
                        namespace: "",
                        local: "URI",
                    }),
                    work,
                    |descriptor| {
                        let r = descriptor.reference;
                        (r.node, r.target, r.status, r.coverage)
                    },
                )
            })
            .map_err(InputError::Access)?;
        let reference = match resolved {
            Resolution::Resolved((node, target, Status::Valid, coverage)) => {
                if let Some(target) = target
                    && access
                        .equal_id(target, signed_properties)
                        .map_err(|cause| InputError::Resource {
                            node: include,
                            cause,
                        })?
                {
                    return Err(InputError::Reference {
                        node: include,
                        resolution: Resolution::Resolved(()),
                    });
                }
                Part::Reference {
                    node,
                    covered: if coverage == Coverage::ElementContent {
                        target
                    } else {
                        None
                    },
                }
            }
            other => {
                return Err(InputError::Reference {
                    node: include,
                    resolution: other.map(|_| ()),
                });
            }
        };
        parts
            .try_push(reference)
            .map_err(|cause| InputError::Resource {
                node: include,
                cause,
            })?;
    }
    Ok(())
}

fn append_references<X: TimestampXml, W: Work>(
    access: &Access<'_, X, W>,
    stamp: &Timestamp<X>,
    excluded: Option<X::Id>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    let count = access
        .query(stamp.signature, |xml, snapshot, work| {
            xml.reference_count(snapshot, stamp.signature, work)
        })
        .map_err(InputError::Access)?;
    for ordinal in 0..count {
        let (part, target) = access
            .query(stamp.signature, |xml, snapshot, work| {
                xml.reference(snapshot, stamp.signature, ordinal, work, |r| {
                    (
                        Part::Reference {
                            node: r.node,
                            covered: if r.status == Status::Valid
                                && r.coverage == Coverage::ElementContent
                            {
                                r.target
                            } else {
                                None
                            },
                        },
                        r.target,
                    )
                })
            })
            .map_err(InputError::Access)?;
        if let (Some(target), Some(excluded)) = (target, excluded)
            && access
                .equal_id(target, excluded)
                .map_err(|cause| InputError::Resource {
                    node: stamp.node,
                    cause,
                })?
        {
            continue;
        }
        parts.try_push(part).map_err(|cause| InputError::Resource {
            node: stamp.node,
            cause,
        })?;
    }
    Ok(())
}

impl<X: TimestampXml> Source for Input<'_, X> {
    type Error = InputError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        let access = Access::new(self.xml, self.snapshot, execution);
        let mut receiver = Stop {
            receiver,
            refused: false,
        };
        for index in 0..self.parts.len() {
            execution
                .charge_work(1)
                .map_err(|cause| InputError::Resource {
                    node: self.timestamp,
                    cause,
                })?;
            match self.parts[index] {
                Part::Element(node) => access
                    .query(node, |xml, snapshot, work| {
                        xml.canonicalize(snapshot, node, self.method, &mut receiver, work)
                    })
                    .map_err(InputError::Access)?,
                Part::Reference { node, .. } => {
                    let outcome = access
                        .query(node, |xml, snapshot, work| {
                            xml.replay_reference(
                                snapshot,
                                self.signature,
                                node,
                                crate::reference::Replay::Timestamp(self.method),
                                &mut receiver,
                                work,
                            )
                        })
                        .map_err(InputError::Access)?;
                    if let ReplayOutcome::Unavailable(cause) = outcome {
                        return Err(InputError::Unavailable { node, cause });
                    }
                }
            }
            if receiver.refused {
                return Err(InputError::Receiver(Refused));
            }
        }
        Ok(())
    }
}

struct Stop<'a, R: Receiver> {
    receiver: &'a mut R,
    refused: bool,
}

impl<R: Receiver> Receiver for Stop<'_, R> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        if self.refused {
            return Err(Refused);
        }
        if self.receiver.write(bytes).is_err() {
            self.refused = true;
            return Err(Refused);
        }
        Ok(())
    }
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> InputResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(InputError::Access)
}

pub(crate) fn singleton<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    namespace: &str,
    local: &'static str,
) -> InputResult<X::Id, X> {
    optional(access, parent, namespace, local)?.ok_or(InputError::Missing {
        node: parent,
        local,
    })
}

fn optional<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    namespace: &str,
    local: &str,
) -> InputResult<Option<X::Id>, X> {
    let mut found = None;
    for child in access.children(parent) {
        let node = child.map_err(InputError::Child)?;
        if named(access, node, namespace, local)? {
            if found.is_some() {
                return Err(InputError::Duplicate { node });
            }
            found = Some(node);
        }
    }
    Ok(found)
}
