//! Complete ERS sequence execution; historical acceptance is explicitly injected.

mod engine;

use super::{
    ArchiveTimeStamp, EvidenceRecord, FIELD, Membership, PriorSequence, TimeStamp,
    input::InputError,
};
use crate::{
    Error, ErrorCode,
    content_source::ContentError,
    digest::PassError,
    provider::SignatureProvider,
    stream::{RangesError, Source},
    timestamp::{
        self, CheckContext, CheckedTimestamp, Evidence, InfoError, ProfileCheckError,
        ProfileFailure, TokenExtension,
    },
};
use core::convert::Infallible;
use structured_asn1::{
    Reader,
    digest::Resolution,
    memory::{Execution, OwnedVec, Work},
};
use structured_pkix::{
    Certificate,
    algorithm::digest::{self, Algorithm},
    path::WorkingKey,
    temporal::{Instant, LeapTable},
};

/// Actual certificate and effective key to use for this timestamp's common check.
pub struct Selection<'a> {
    /// Original selected candidate, still subject to SID/ESS/TSA checking.
    pub certificate: &'a Certificate<'a>,
    /// That certificate's own producing source and resource ceiling.
    pub certificate_parent: &'a Reader<'a>,
    /// Effective parameters from the selected candidate's actual path.
    pub key: WorkingKey<'a>,
}
impl<'a> Selection<'a> {
    fn historical_context<'s>(&'s self, utc: &'s LeapTable<'a>) -> CheckContext<'a, 's> {
        CheckContext {
            certificate: self.certificate,
            certificate_parent: self.certificate_parent,
            key: self.key,
            requested: None,
            utc,
            reference: None,
            window: None,
        }
    }
}
/// Caller selection; the ERS mechanism executes the check on the actual token.
pub trait Authorities<'document> {
    /// Original selection/provider-policy refusal.
    type Error;
    /// Selects a candidate for this exact original timestamp ordinal.
    fn select<'a, W: Work>(
        &'a self,
        index: usize,
        stamp: &'a ArchiveTimeStamp<'document>,
        work: &W,
    ) -> Result<Selection<'a>, Self::Error>
    where
        'document: 'a;
}

/// Caller-established historical validation of the supplied actual participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Path/status, signed ESS restrictions and algorithm suitability all hold.
    Valid,
    /// At least one required historical fact is known to fail.
    Invalid,
    /// Required historical evidence is unavailable or uncertain.
    Unknown,
}
/// Facts for historical validation, never a request to infer trust from genTime.
pub struct Historical<'a, 'token> {
    /// Original flat timestamp ordinal.
    pub index: usize,
    /// Complete common result for the actual selected original token.
    pub current: &'a CheckedTimestamp<'token>,
    /// Candidate/key used by this same common check.
    pub selection: &'a Selection<'token>,
    /// Next token's successful mathematical facts, when present.
    pub following: Option<&'a Evidence>,
    /// First token of the next chain: the tree algorithm must remain suitable
    /// through this renewal, even for earlier tokens in the current chain.
    pub following_chain: Option<&'a Evidence>,
    /// Explicit current verification reference for the final timestamp.
    pub verification_time: Instant,
}

/// Failed preflight retains the actual original source and carried source map.
#[derive(Debug)]
pub enum PlanError {
    /// Source/work/schema refusal before covered content is accessed.
    Processing(Error),
    /// Original carried `TSTInfo` refusal and its independently retained source.
    Information(ContentError<InfoError<AlgorithmError>>),
    /// Retained envelope/ESS/CMS facts already prevent a conforming token.
    Nonconforming {
        /// Actual original timestamp ordinal.
        index: usize,
        /// Honest original envelope enclosure.
        span: structured_asn1::Span,
    },
    /// An alternative timestamp format has no selected execution mechanism.
    UnsupportedTimestamp {
        /// Actual original archive timestamp ordinal.
        index: usize,
    },
    /// A digest is unknown to the shared standard algorithm resolver.
    UnsupportedAlgorithm {
        /// Actual original enclosing position.
        at: u64,
    },
}
/// Algorithm inspection preserves unavailable capability separately from syntax
/// and resource errors, including inside a temporary carried `TSTInfo` source.
#[derive(Debug)]
pub enum AlgorithmError {
    /// Unchanged original schema/encoding/resource refusal.
    Processing(Error),
    /// The written digest has no standard semantic resolver.
    Unsupported {
        /// Original source-relative algorithm position.
        at: u64,
    },
}

/// Complete operation refusal; no successful partial sequence is returned.
#[derive(Debug)]
pub enum VerificationError<SE, PE, RE, AE, HE, FE = Infallible> {
    /// The declared first hash list cannot cover this actual object/group.
    Membership {
        /// Original archive timestamp ordinal.
        index: usize,
    },
    /// Original preflight failure before covered-source I/O.
    Plan(PlanError),
    /// Common capacity/work/source refusal.
    Processing(Error),
    /// Actual object acquisition or selected-provider hashing failed.
    Acquisition(PassError<SE, PE>),
    /// Selection refused this exact original token.
    Selection {
        /// Original flat timestamp ordinal.
        index: usize,
        /// Unchanged selector refusal.
        cause: AE,
    },
    /// Complete common check over cached actual object digests refused.
    Timestamp {
        /// Original flat timestamp ordinal.
        index: usize,
        /// Unchanged common/input/provider/recognition failure.
        cause: ProfileCheckError<InputError<SE, PE>, PE, RE, FE>,
    },
    /// Complete common check over the preceding timestamp refused.
    Renewal {
        /// Original flat timestamp ordinal.
        index: usize,
        /// Unchanged renewal check failure.
        cause: ProfileCheckError<InputError<RangesError, PE>, PE, RE, FE>,
    },
    /// Historical validator failed to execute; not a negative document finding.
    Historical {
        /// Original flat timestamp ordinal.
        index: usize,
        /// Unchanged validator refusal.
        cause: HE,
    },
}

/// Complete record result with unchanged acquisition, provider, selector,
/// recognizer, historical and profile causes; diagnostics allocate nothing.
pub type VerificationResult<'a, 'd, SE, PE, RE, AE, HE, FE = Infallible> =
    Result<Report<'a, 'd>, VerificationError<SE, PE, RE, AE, HE, FE>>;

/// Result for one original token; editing public facts cannot create a receipt.
pub struct Checked<'a> {
    index: usize,
    common: CheckedTimestamp<'a>,
    selection: Selection<'a>,
    history: Decision,
}
impl<'a> Checked<'a> {
    /// Original flat timestamp ordinal, independent of verification order.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
    /// Complete common timestamp result, including negative/unsupported facts.
    #[must_use]
    pub fn timestamp(&self) -> &CheckedTimestamp<'_> {
        &self.common
    }
    /// Actual original selected candidate/key from that check.
    #[must_use]
    pub fn selection(&self) -> &Selection<'_> {
        &self.selection
    }
    /// Explicit caller-established historical answer.
    #[must_use]
    pub fn historical(&self) -> Decision {
        self.history
    }
    /// Moves the SAME common result for a format adapter's actor construction.
    /// No signature is rechecked and no retained evidence is copied. Selection
    /// references are deliberately discarded by adapters with their own sealed
    /// path model; callers must preserve this original index/source binding.
    pub fn into_parts(self) -> (usize, CheckedTimestamp<'a>, Selection<'a>, Decision) {
        (self.index, self.common, self.selection, self.history)
    }
}

/// Complete, possibly negative sequence report, bound to this original record.
pub struct Report<'a, 'document> {
    record: &'a EvidenceRecord<'document>,
    checks: OwnedVec<Checked<'a>>,
    ordering: OwnedVec<OrderFinding>,
    complete: bool,
}
/// One actual adjacent pair whose required chronological order is not proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderFinding {
    /// Original earlier archive timestamp ordinal.
    pub earlier: usize,
    /// Original next archive timestamp ordinal.
    pub later: usize,
    /// Reversal, overlap or missing information, independently of trust facts.
    pub cause: OrderCause,
}
/// Complete temporal comparison outcome; uncertainty is never positive order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderCause {
    /// Authenticated generation facts contradict the declared chain order.
    Reversed,
    /// Accuracy intervals overlap without a same-TSA ordering assertion.
    Overlap,
    /// Supplied UTC facts cannot establish the exact generation order.
    Utc(structured_pkix::temporal::Uncertainty),
    /// At least one timestamp has no successful complete mathematical evidence.
    UnprovenTimestamp,
    /// A generation endpoint is uncertain (for example accuracy is unstated).
    Bounds {
        /// Earlier participant's unavailable bound.
        earlier: Option<timestamp::BoundUncertainty>,
        /// Later participant's unavailable bound.
        later: Option<timestamp::BoundUncertainty>,
    },
}
/// Closed complete record receipt. This incorporates the caller's historical
/// decisions; it does not choose application trust or claim `CAdES` conformance.
pub struct Verified<'report, 'record, 'document>(&'report Report<'record, 'document>);
impl<'a, 'd> Report<'a, 'd> {
    /// Moves complete results for a higher-level source-bound format adapter.
    /// Order is the stored reverse execution order; each checked index remains
    /// original. The boolean is this report's private computed closure result,
    /// not a constructor for another common receipt.
    pub fn into_parts(
        self,
    ) -> (
        &'a EvidenceRecord<'d>,
        OwnedVec<Checked<'a>>,
        OwnedVec<OrderFinding>,
        bool,
    ) {
        (self.record, self.checks, self.ordering, self.complete)
    }
    /// Results in ORIGINAL order, although historical checks run newest first.
    pub fn checks(&self) -> impl DoubleEndedIterator<Item = &Checked<'a>> + ExactSizeIterator {
        self.checks.iter().rev()
    }
    /// Every failed/uncertain adjacent comparison, with original ordinals.
    #[must_use]
    pub fn ordering(&self) -> &[OrderFinding] {
        &self.ordering
    }
    /// Present only when every required check and chronology was established.
    #[must_use]
    pub fn verified(&self) -> Option<Verified<'_, 'a, 'd>> {
        if self.complete {
            Some(Verified(self))
        } else {
            None
        }
    }
}
impl<'a, 'd> Verified<'_, 'a, 'd> {
    /// Original record to which all participants and renewal inputs were bound.
    #[must_use]
    pub fn record(&self) -> &'a EvidenceRecord<'d> {
        self.0.record
    }
    /// Every actual checked timestamp, in original order.
    pub fn checks(&self) -> impl DoubleEndedIterator<Item = &Checked<'a>> + ExactSizeIterator {
        self.0.checks()
    }
}

/// Original-bound schema preflight and exact chain-algorithm request mapping.
/// A format-derived input can prepare its per-algorithm recipe once and reuse
/// this SAME plan for execution, without reparsing timestamp information.
pub struct InputPlan<'record, 'document> {
    record: &'record EvidenceRecord<'document>,
    chains: OwnedVec<Algorithm>,
}
impl<'r, 'd> InputPlan<'r, 'd> {
    #[expect(
        clippy::result_large_err,
        reason = "a carried algorithm failure retains its original source map and cause inline, including when no diagnostic allocation can succeed"
    )]
    fn read(record: &'r EvidenceRecord<'d>, operation: &Reader<'_>) -> Result<Self, PlanError> {
        let origin = record
            .original
            .reader_in(operation)
            .map_err(PlanError::Processing)?;
        let work = origin.execution_query(operation);
        let mut declared = work.vector();
        for identifier in &record.algorithms {
            let value = known(identifier, &work).map_err(original_algorithm_error)?;
            insert_algorithm(&mut declared, value, &work, identifier.offset())
                .map_err(PlanError::Processing)?;
        }
        let mut chains = work.vector();
        let mut chain_index = 0;
        for (index, stamp) in record.timestamps.iter().enumerate() {
            work.charge_work(1).map_err(|cause| {
                PlanError::Processing(Error::resource(
                    cause,
                    FIELD,
                    stamp.original.element.span().start,
                ))
            })?;
            let TimeStamp::Rfc3161(token) = &stamp.token else {
                return Err(PlanError::UnsupportedTimestamp { index });
            };
            if !token.faults().is_empty()
                || !token.message().faults().is_empty()
                || !token.signer().faults().is_empty()
            {
                return Err(PlanError::Nonconforming {
                    index,
                    span: token.message().span(),
                });
            }
            let parent = stamp
                .timestamp
                .reader_in(operation)
                .map_err(PlanError::Processing)?;
            let timestamp_algorithm =
                token_algorithm(token, &parent).map_err(PlanError::Information)?;
            let value = if let Some(identifier) = stamp.algorithm {
                known(&identifier, &work).map_err(original_algorithm_error)?
            } else {
                timestamp_algorithm
            };
            require_width(stamp, value.width(), &work).map_err(PlanError::Processing)?;
            let chain = &record.chains[chain_index];
            if index == chain.first {
                chains.try_push(value).map_err(|cause| {
                    PlanError::Processing(Error::resource(
                        cause,
                        FIELD,
                        chain.original.element.span().start,
                    ))
                })?;
            } else if chains[chain_index] != value {
                return Err(PlanError::Processing(Error::schema(
                    ErrorCode::AlgorithmProtection,
                    FIELD,
                    stamp.original.element.span().start,
                )));
            }
            if index + 1 == chain.end {
                chain_index += 1;
            }
        }
        let mut used = work.vector();
        for algorithm in &chains {
            insert_algorithm(
                &mut used,
                *algorithm,
                &work,
                record.original.element.span().start,
            )
            .map_err(PlanError::Processing)?;
        }
        require_union(
            &declared,
            &used,
            &work,
            record.original.element.span().start,
        )
        .map_err(PlanError::Processing)?;
        Ok(Self {
            record,
            chains: chains.into_owned(),
        })
    }
    /// Original chain order, including repeated algorithms. The digest batch
    /// retains this ordinal mapping when equal full identities are deduplicated.
    #[must_use]
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.chains
    }
    /// SAME original record for this immutable plan.
    #[must_use]
    pub fn record(&self) -> &'r EvidenceRecord<'d> {
        self.record
    }

    /// Executes asynchronous original objects with the same admitted plan,
    /// profile-before-input ordering, renewal recipes and historical closure.
    /// All chain algorithms share one complete pass over each object. Batch
    /// owners may inspect those actual outputs without acquiring bytes again.
    #[expect(
        clippy::too_many_arguments,
        reason = "the asynchronous driver retains distinct original/provider/authority/UTC inputs and scoped format callbacks"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "suspension preserves the same source-mapped and opaque failures as resident verification"
    )]
    pub async fn verify_async_with_profile<'a, P, PE, A, S, RE, HE, FE>(
        &self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: S,
        membership: Membership,
        mut recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        mut historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        mut profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'd, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'd, S::Error, PE, RE, A::Error, HE, FE>
    where
        'r: 'a,
        'd: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: super::AsyncObjects<'a, P>,
    {
        let record = self.record;
        let plan = self;
        engine::execute!(
            suspending,
            record,
            plan,
            provider,
            operation,
            authorities,
            utc,
            reference,
            objects,
            membership,
            recognizes,
            historical,
            profile
        )
    }

    fn token(&self, index: usize) -> (&'r ArchiveTimeStamp<'d>, &'r timestamp::Token<'d>) {
        let record = self.record;
        let stamp = &record.timestamps[index];
        let TimeStamp::Rfc3161(token) = &stamp.token else {
            unreachable!("the immutable input plan admitted every timestamp format")
        };
        (stamp, token)
    }

    /// Executes literal original objects with this SAME checked input plan.
    /// Selection callbacks need not cause a second schema/information parse.
    #[expect(
        clippy::too_many_arguments,
        reason = "the immutable plan keeps source, provider, authority and UTC contexts independent of the three differently scoped callbacks"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "the literal-source entry preserves mapped timestamp and opaque callback failures without a diagnostic allocation"
    )]
    pub fn verify_with_profile<'a, P, PE, A, S, RE, HE, FE>(
        &self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: &mut [S],
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'd, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'd, S::Error, PE, RE, A::Error, HE, FE>
    where
        'r: 'a,
        'd: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
    {
        self.record.verify_plan_sources(
            self,
            provider,
            operation,
            authorities,
            utc,
            reference,
            super::objects::Streams(objects),
            membership,
            recognizes,
            historical,
            profile,
        )
    }

    /// Executes per-algorithm format inputs with this already checked plan.
    /// Every common/token/profile/history check still runs on the actual source.
    #[expect(
        clippy::too_many_arguments,
        reason = "algorithm-dependent source execution has separate producing-reader, provider, authority and callback lifetimes"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "request-source refusal keeps the actual mapped timestamp and caller causes inline on exhaustion"
    )]
    pub fn verify_requests_with_profile<'a, P, PE, A, S, RE, HE, FE>(
        &self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: &mut [S],
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'd, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'd, S::Error, PE, RE, A::Error, HE, FE>
    where
        'r: 'a,
        'd: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: crate::digest::RequestSource<'a, P>,
    {
        self.record.verify_plan_sources(
            self,
            provider,
            operation,
            authorities,
            utc,
            reference,
            super::objects::Requests(objects),
            membership,
            recognizes,
            historical,
            profile,
        )
    }
}
/// Resolves the actual carried imprint with the same source-mapped syntax
/// preflight used by ERS. Unknown capability, malformed fields and resource
/// refusal remain distinct; this does not establish timestamp mathematics.
#[expect(
    clippy::result_large_err,
    reason = "the actual carried information/source-map failure must survive before provider or covered-source side effects"
)]
pub fn token_algorithm<'d>(
    token: &timestamp::Token<'d>,
    parent: &Reader<'d>,
) -> Result<Algorithm, ContentError<InfoError<AlgorithmError>>> {
    token.with_info(parent, |info, reader, _| {
        if info.has_faults() {
            return Err(AlgorithmError::Processing(Error::schema(
                ErrorCode::MalformedValue,
                FIELD,
                info.span().start,
            )));
        }
        let timestamp::HashAlgorithmReading::Identifier(identifier) = info.imprint().algorithm()
        else {
            return Err(AlgorithmError::Processing(Error::schema(
                ErrorCode::AlgorithmSyntax,
                FIELD,
                info.imprint().span().start,
            )));
        };
        known(identifier, &reader.execution())
    })
}
fn known<W: Work>(
    identifier: &structured_pkix::AlgorithmIdentifier<'_>,
    work: &W,
) -> Result<Algorithm, AlgorithmError> {
    match digest::algorithm(identifier, work)
        .map_err(|cause| AlgorithmError::Processing(Error::pkix(cause)))?
    {
        Resolution::Supported(value) => Ok(value),
        Resolution::Unsupported => Err(AlgorithmError::Unsupported {
            at: identifier.offset(),
        }),
        Resolution::Malformed => Err(AlgorithmError::Processing(Error::schema(
            ErrorCode::AlgorithmSyntax,
            FIELD,
            identifier.offset(),
        ))),
    }
}
fn original_algorithm_error(cause: AlgorithmError) -> PlanError {
    match cause {
        AlgorithmError::Processing(cause) => PlanError::Processing(cause),
        AlgorithmError::Unsupported { at } => PlanError::UnsupportedAlgorithm { at },
    }
}
fn insert_algorithm<W: Work>(
    set: &mut OwnedVec<Algorithm, W>,
    value: Algorithm,
    work: &W,
    at: u64,
) -> crate::Result<()> {
    // The set contains DISTINCT variants of the shared finite algorithm enum.
    // Duplicate advertisements cannot cause declared_count*timestamp_count
    // comparisons. Every possible member comparison is admitted before access.
    for member in &*set {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, at))?;
        if *member == value {
            return Ok(());
        }
    }
    set.try_push(value)
        .map_err(|cause| Error::resource(cause, FIELD, at))
}

fn require_width<W: Work>(
    stamp: &ArchiveTimeStamp<'_>,
    width: usize,
    work: &W,
) -> crate::Result<()> {
    if let Some(tree) = &stamp.tree {
        for level in tree {
            for hash in &level.hashes {
                work.charge_work(1)
                    .map_err(|cause| Error::resource(cause, FIELD, hash.span().start))?;
                if hash.len() != width {
                    return Err(Error::schema(
                        ErrorCode::DigestWidth,
                        FIELD,
                        hash.span().start,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_union<W: Work>(
    declared: &[Algorithm],
    used: &[Algorithm],
    work: &W,
    at: u64,
) -> crate::Result<()> {
    // RFC4998 §3.1 requires a union, not an arbitrary advertisement. Both
    // sets already contain distinct shared variants, bounding this pass.
    for (left, right) in [(declared, used), (used, declared)] {
        for requested in left {
            let mut found = false;
            for actual in right {
                work.charge_work(1)
                    .map_err(|cause| Error::resource(cause, FIELD, at))?;
                if requested == actual {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(Error::schema(ErrorCode::AlgorithmProtection, FIELD, at));
            }
        }
    }
    Ok(())
}

impl<'document> EvidenceRecord<'document> {
    /// Validates every timestamp format/tree width/digest advertisement and
    /// same-chain algorithm before covered-object acquisition or provider work.
    #[expect(
        clippy::result_large_err,
        reason = "preflight returns the carried-source diagnostic even when no diagnostic allocation can succeed"
    )]
    pub fn input_plan(
        &self,
        operation: &Reader<'_>,
    ) -> Result<InputPlan<'_, 'document>, PlanError> {
        InputPlan::read(self, operation)
    }
    /// Verifies every timestamp, both renewal relations, the digest union and
    /// actual chronology. Objects are read ONCE with all chain algorithms in
    /// `DigestBatch`'s shared fan-out. Reverse execution exposes the next
    /// already checked participant to the caller's historical validator.
    ///
    /// Historical Valid must cover actual path/status, signed ESS restrictions,
    /// signature/hash suitability at the next token and tree suitability through
    /// the next chain's first token. The last participant is validated at the
    /// explicit verification reference. Unprotected hints never satisfy this.
    #[expect(
        clippy::too_many_arguments,
        reason = "standalone verification receives explicit source/group, provider, authority, UTC and historical/recognition boundaries"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "standalone verification retains original failure categories without allocating error storage on resource refusal"
    )]
    pub fn verify<'a, P, PE, A, S, RE, HE>(
        &'a self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: &mut [S],
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
    ) -> VerificationResult<'a, 'document, S::Error, PE, RE, A::Error, HE>
    where
        'document: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'document>,
        S: Source,
    {
        self.verify_with_profile(
            provider,
            operation,
            authorities,
            utc,
            reference,
            objects,
            membership,
            recognizes,
            historical,
            |_, _| Ok::<_, ProfileFailure<Infallible>>(()),
        )
    }

    /// Same complete sequence check with one schema/profile callback per actual
    /// timestamp. It sees the SAME ESS and `TSTInfo` readings before signature
    /// or covered-input callbacks; no second token parse or provider is used.
    #[expect(
        clippy::too_many_arguments,
        reason = "profiled standalone verification keeps original provider/key/UTC inputs and three independently scoped callbacks explicit"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "the complete carried mapping and profile/caller causes survive on the nonallocating failure path"
    )]
    pub fn verify_with_profile<'a, P, PE, A, S, RE, HE, FE>(
        &'a self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: &mut [S],
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'document, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'document, S::Error, PE, RE, A::Error, HE, FE>
    where
        'document: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'document>,
        S: Source,
    {
        self.verify_sources(
            provider,
            operation,
            authorities,
            utc,
            reference,
            super::objects::Streams(objects),
            membership,
            recognizes,
            historical,
            profile,
        )
    }

    /// Checks schema-defined algorithm-dependent object preimages (for example
    /// the TS101733 `PoE` eight-hash recipe) through the SAME sequence kernel.
    /// Request ordinals refer to original chains; repeated identities share
    /// their completed output. No arbitrary finalized digest is accepted.
    #[expect(
        clippy::too_many_arguments,
        reason = "schema-derived request sources retain their original authority, execution and callback boundaries without a second dispatcher"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "format-source errors and mapped token/profile refusals remain distinct without allocating error storage"
    )]
    pub fn verify_requests_with_profile<'a, P, PE, A, S, RE, HE, FE>(
        &'a self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: &mut [S],
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'document, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'document, S::Error, PE, RE, A::Error, HE, FE>
    where
        'document: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'document>,
        S: crate::digest::RequestSource<'a, P>,
    {
        self.verify_sources(
            provider,
            operation,
            authorities,
            utc,
            reference,
            super::objects::Requests(objects),
            membership,
            recognizes,
            historical,
            profile,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one dispatch forwards the same literal/request-source verification contexts and separately scoped callbacks"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "forwarding cannot replace preflight, source-map or opaque caller errors with an allocating wrapper"
    )]
    fn verify_sources<'a, P, PE, A, S, RE, HE, FE>(
        &'a self,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: S,
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'document, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'document, S::Error, PE, RE, A::Error, HE, FE>
    where
        'document: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'document>,
        S: super::objects::Sources<'a, P>,
    {
        let plan = InputPlan::read(self, operation).map_err(VerificationError::Plan)?;
        self.verify_plan_sources(
            &plan,
            provider,
            operation,
            authorities,
            utc,
            reference,
            objects,
            membership,
            recognizes,
            historical,
            profile,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the single execution kernel binds the original plan and all already-admitted source/provider/callback contexts"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "token, renewal, selector and source-map refusals are returned unchanged when allocation is unavailable"
    )]
    fn verify_plan_sources<'a, P, PE, A, S, RE, HE, FE>(
        &'a self,
        plan: &InputPlan<'a, 'document>,
        provider: &'a P,
        operation: &Reader<'a>,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: S,
        membership: Membership,
        mut recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        mut historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        mut profile: impl for<'view, 'scope> FnMut(
            usize,
            timestamp::ProfileInput<'view, 'document, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> VerificationResult<'a, 'document, S::Error, PE, RE, A::Error, HE, FE>
    where
        'document: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'document>,
        S: super::objects::Sources<'a, P>,
    {
        engine::execute!(
            resident,
            self,
            plan,
            provider,
            operation,
            authorities,
            utc,
            reference,
            objects,
            membership,
            recognizes,
            historical,
            profile
        )
    }
}

enum GroupError {
    Processing(Error),
    Membership(usize),
}
fn admit_membership<W: Work>(
    record: &EvidenceRecord<'_>,
    objects: usize,
    membership: Membership,
    work: &W,
) -> Result<(), GroupError> {
    let at = record.original.element.span().start;
    if objects == 0 || (membership == Membership::Object && objects != 1) {
        return Err(GroupError::Processing(Error::schema(
            ErrorCode::MissingField,
            FIELD,
            at,
        )));
    }
    for chain in &record.chains {
        work.charge_work(1)
            .map_err(|cause| GroupError::Processing(Error::resource(cause, FIELD, at)))?;
        if !super::input::membership_shape(&record.timestamps[chain.first], objects, membership) {
            return Err(GroupError::Membership(chain.first));
        }
    }
    Ok(())
}
type Prefixes<'r, 'd> = OwnedVec<Option<PriorSequence<'r, 'd>>>;
fn prior_views<'r, 'd, W: Work>(
    record: &'r EvidenceRecord<'d>,
    projected: &'r [crate::encoding::Projection<'d>],
    operation: &Reader<'_>,
    work: &W,
) -> crate::Result<Prefixes<'r, 'd>> {
    let resource = |cause| Error::resource(cause, FIELD, record.original.element.span().start);
    let mut prefixes = work.vector();
    prefixes
        .try_reserve_exact(record.chains.len())
        .map_err(resource)?;
    prefixes.try_push(None).map_err(resource)?;
    for index in 1..record.chains.len() {
        prefixes
            .try_push(Some(PriorSequence::borrowed(
                record, index, projected, operation,
            )?))
            .map_err(resource)?;
    }
    Ok(prefixes.into_owned())
}
fn order_findings<W: Work>(
    checks: &[Checked<'_>],
    utc: &LeapTable<'_>,
    operation: &Reader<'_>,
    work: &W,
    at: u64,
) -> crate::Result<OwnedVec<OrderFinding>> {
    let resource = |cause| Error::resource(cause, FIELD, at);
    let mut findings = work.vector();
    for pair in checks.windows(2) {
        work.charge_work(1).map_err(resource)?;
        if let Some(cause) = order(&pair[1], &pair[0], utc, operation)? {
            findings
                .try_push(OrderFinding {
                    earlier: pair[1].index,
                    later: pair[0].index,
                    cause,
                })
                .map_err(resource)?;
        }
    }
    Ok(findings.into_owned())
}

fn history_input<'v, 'a>(
    record: &EvidenceRecord<'_>,
    chain: usize,
    index: usize,
    current: &'v CheckedTimestamp<'a>,
    selection: &'v Selection<'a>,
    checks: &'v [Checked<'a>],
    reference: Instant,
) -> Historical<'v, 'a> {
    let following = checks.last().and_then(|next| next.common.evidence());
    let following_chain = record
        .chains
        .get(chain + 1)
        .and_then(|next| checks.get(record.timestamps.len() - 1 - next.first))
        .and_then(|next| next.common.evidence());
    Historical {
        index,
        current,
        selection,
        following,
        following_chain,
        verification_time: reference,
    }
}

fn order(
    earlier: &Checked<'_>,
    later: &Checked<'_>,
    utc: &LeapTable<'_>,
    operation: &Reader<'_>,
) -> crate::Result<Option<OrderCause>> {
    let work = operation.execution();
    let (Some(a), Some(b)) = (earlier.common.evidence(), later.common.evidence()) else {
        return Ok(Some(OrderCause::UnprovenTimestamp));
    };
    order_evidence(
        a,
        earlier.selection.certificate,
        b,
        later.selection.certificate,
        utc,
        &work,
    )
}

/// Orders two actual authenticated TSA facts using RFC3161 §2.4.2's SAME-TSA
/// ordering rule or complete stated-accuracy intervals. This is shared by
/// in-record ERS renewal and `CAdES` cross-proof preservation closure. A readable
/// unsigned poeDate is never substituted for either authenticated generation.
pub fn order_evidence<W: Work>(
    a: &Evidence,
    left: &Certificate<'_>,
    b: &Evidence,
    right: &Certificate<'_>,
    utc: &LeapTable<'_>,
    work: &W,
) -> crate::Result<Option<OrderCause>> {
    let resource = |cause| Error::resource(cause, FIELD, a.source().carrier().start);
    if a.facts().ordering() && b.facts().ordering() {
        let first = left.execution_in(work);
        let second = right.execution_in(work);
        first.charge_work(1).map_err(resource)?;
        second.charge_work(1).map_err(resource)?;
        let same = if core::ptr::eq(left, right) {
            true
        } else if left.as_bytes().len() != right.as_bytes().len() {
            false
        } else {
            first
                .charge_work(left.as_bytes().len() as u64)
                .map_err(resource)?;
            second
                .charge_work(right.as_bytes().len() as u64)
                .map_err(resource)?;
            left.as_bytes() == right.as_bytes()
        };
        if same {
            // RFC3161 §2.4.2: ordering=true for the SAME authenticated TSA
            // permits genTime ordering irrespective of stated accuracy. Exact
            // retained decimal tails prevent subnanosecond labels collapsing.
            // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
            return match a.facts().compare_generation(b.facts(), utc, work) {
                Ok(core::cmp::Ordering::Greater) => Ok(Some(OrderCause::Reversed)),
                Ok(_) => Ok(None),
                Err(timestamp::GenerationOrderError::Resource(cause)) => Err(resource(cause)),
                Err(timestamp::GenerationOrderError::Uncertain(cause)) => {
                    Ok(Some(OrderCause::Utc(cause)))
                }
            };
        }
    }
    let a = match timestamp::interval_in(a.facts().gen_time(), a.facts().accuracy(), utc, work) {
        Ok(value) => Ok(value),
        Err(timestamp::IntervalError::Resource(cause)) => return Err(resource(cause)),
        Err(timestamp::IntervalError::Uncertain(cause)) => Err(cause),
    };
    let b = match timestamp::interval_in(b.facts().gen_time(), b.facts().accuracy(), utc, work) {
        Ok(value) => Ok(value),
        Err(timestamp::IntervalError::Resource(cause)) => return Err(resource(cause)),
        Err(timestamp::IntervalError::Uncertain(cause)) => Err(cause),
    };
    match (a, b) {
        (Ok(a), Ok(b)) if a.latest <= b.earliest => Ok(None),
        (Ok(a), Ok(b)) if a.earliest > b.latest => Ok(Some(OrderCause::Reversed)),
        (Ok(_), Ok(_)) => Ok(Some(OrderCause::Overlap)),
        (a, b) => Ok(Some(OrderCause::Bounds {
            earlier: a.err(),
            later: b.err(),
        })),
    }
}
