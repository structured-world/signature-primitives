//! Complete common timestamp checks; path/status/policy acceptance stays external.

mod asynchronous;

use super::profile::{
    self, MappedProfileCheckError, ProfileCheckError, ProfileFailure, ProfileInput,
};
use super::{
    AuthorityFacts, ComputedInput, ImprintAgreement, RawInput, RecognitionError, Request,
    RequestAgreement, RequestFields, RequestWindow, RetainedFacts, SignatureError, Timeliness,
    Token, TokenExtension, TokenSignature, TsaIdentity, TsaUsage,
};
use crate::{
    Error, ErrorCode,
    content_source::{ContentError, SourceMap},
    directory, ess,
    provider::{SignatureAnswer, SignatureProvider},
    stream::Source,
    verify,
};
use core::convert::Infallible;
use structured_asn1::{
    Reader,
    memory::{Execution, OwnedVec, Work},
    value::OwnedOid,
};
use structured_pkix::{
    Certificate,
    path::WorkingKey,
    temporal::{Instant, LeapTable},
};

/// Original parsed request and its producing reader, not reconstructed tuples.
pub struct Requested<'a, 'r> {
    /// Complete original request.
    pub request: &'r Request<'a>,
    /// Its own original producing session.
    pub parent: &'r Reader<'a>,
}

/// Explicit caller selection/time facts; this does not select a trusted path.
pub struct CheckContext<'a, 'r> {
    /// Caller-selected candidate, independently subject to trust/path checks.
    pub certificate: &'r Certificate<'a>,
    /// That certificate's own original producing reader.
    pub certificate_parent: &'r Reader<'a>,
    /// Effective key retaining independently established inherited parameters.
    pub key: WorkingKey<'a>,
    /// Complete live request, absent for archived evidence.
    pub requested: Option<Requested<'a, 'r>>,
    /// Explicit UTC correction facts, without implicit clock lookup.
    pub utc: &'r LeapTable<'a>,
    /// Caller-supplied comparison instant, when available.
    pub reference: Option<Instant>,
    /// Caller-established outstanding-imprint uniqueness/window fact.
    pub window: Option<RequestWindow>,
}

/// Scoped execution refusal retaining the actual source/operand and cause.
#[derive(Debug)]
pub enum InfoCheckError<SE, PE, RE> {
    /// Inspection retained schema faults; complete execution did not start.
    Nonconforming {
        /// Original information range, interpreted through the accompanying map.
        span: structured_asn1::Span,
    },
    /// Original CMS execution failed after information syntax preflight.
    Signature(SignatureError<PE>),
    /// Original ESS execution failed after information syntax preflight.
    Ess(ess::BindingError<PE>),
    /// Original token processing/resource refusal.
    Processing(Error),
    /// Source-map retention refusal already located at a physical carrier.
    /// Do not project this offset again as a logical token coordinate.
    Provenance(Error),
    /// Covered-content acquisition or selected digest execution failed.
    Imprint(super::ImprintError<SE, PE>),
    /// Complete request-imprint comparison failed.
    RequestImprint(super::RequestImprintError<PE>),
    /// Request nonce/policy comparison failed.
    RequestField(super::RequestFieldError),
    /// Token/certificate source role and original refusal.
    Authority(super::AuthorityError),
    /// Original extension handler refusal.
    Recognition(RecognitionError<RE>),
}

/// Execution refusal, never a semantic partial success.
#[derive(Debug)]
pub enum CheckError<SE, PE, RE> {
    /// Original envelope/ESS inspection faults prevent complete execution.
    Nonconforming {
        /// Original outer field enclosure, not a resource error.
        span: structured_asn1::Span,
    },
    /// Original outer processing/resource refusal.
    Processing(Error),
    /// Caller supplied a different original SPKI for the selected certificate.
    KeyMismatch {
        /// Honest enclosure of the selected certificate, not a document fault.
        certificate: structured_asn1::Span,
    },
    /// Certificate hint comparison failed, not a mismatch.
    Identifier(directory::Error),
    /// Request source role and original refusal are preserved.
    RequestField(super::RequestFieldError),
    /// Scoped original cause accompanied by independently retained source map.
    Information(ContentError<super::InfoError<InfoCheckError<SE, PE, RE>>>),
}

/// A check in a logical CMS envelope retains its own source context separately
/// from the inner `TSTInfo` map. CMS errors must not use `TSTInfo` coordinates.
#[derive(Debug)]
pub enum MappedCheckError<SE, PE, RE> {
    /// Caller source/session mismatch, refused before map admission or work.
    /// The original operand identifies its reader; no copied map is required.
    Preflight(CheckError<SE, PE, RE>),
    /// Envelope map admission failed at its already physical carrier.
    Provenance(Error),
    /// Original cause and independently retained envelope coordinate context.
    Execution {
        /// Maps the original CMS envelope's coordinates, not inner `TSTInfo`.
        envelope: SourceMap,
        /// Original check cause; source/operand variants select its context.
        source: CheckError<SE, PE, RE>,
    },
}

/// Independently retained cryptographic/time evidence, not a trust verdict.
/// The caller must establish TSA path/status, enforce signed ESS restrictions
/// and apply algorithm/policy permissions before granting product acceptance.
#[derive(Debug)]
pub struct Evidence {
    facts: RetainedFacts,
    source: SourceMap,
}

/// Independent-copy refusal retains the coordinate context of its cause.
#[derive(Debug)]
pub enum EvidenceCopyError {
    /// Map admission failed at its already physical carrier enclosure.
    Provenance(Error),
    /// Fact admission failed in logical/original fact coordinates.
    Facts {
        /// Original refusal, unchanged and distinct from verification failure.
        source: Error,
        /// Independent map surviving source evidence/parser drop.
        context: SourceMap,
    },
}
impl Evidence {
    /// Makes a genuine independently charged copy, without infallible Clone.
    /// Map admission precedes fact copying so an inner refusal can retain its
    /// provenance without allocating while already handling that refusal.
    #[expect(
        clippy::result_large_err,
        reason = "retain admitted source metadata with the original copy refusal; an error box would itself require unavailable capacity"
    )]
    pub fn try_copy_in<W: Work>(&self, work: &W) -> Result<Self, EvidenceCopyError> {
        let context = self
            .source
            .try_copy_in(work)
            .map_err(EvidenceCopyError::Provenance)?;
        match self.facts.try_copy_in(work) {
            Ok(facts) => Ok(Self {
                facts,
                source: context,
            }),
            Err(source) => Err(EvidenceCopyError::Facts { source, context }),
        }
    }
    /// Generation/imprint facts bound to this successfully checked token.
    #[must_use]
    pub fn facts(&self) -> &RetainedFacts {
        &self.facts
    }
    /// Independent original physical projection of logical facts.
    #[must_use]
    pub fn source(&self) -> &SourceMap {
        &self.source
    }
}

/// Common check facts including original ESS validation-set restrictions.
pub struct CheckedTimestamp<'a> {
    /// Actual CMS signature/content or explicit unusable preparation answer.
    pub signature: TokenSignature<'a>,
    /// Selected-certificate hint agreement, not pool uniqueness/trust.
    pub identifier: directory::CertificateAgreement,
    /// Original independent V1/V2 identifiers and signed path restrictions.
    pub ess: ess::SigningAttributes<'a>,
    /// Independent selected-certificate binding answers.
    pub bindings: ess::Bindings,
    /// Required TSA purpose and optional name agreement.
    pub authority: AuthorityFacts,
    /// Complete caller-covered-content agreement.
    pub imprint: ImprintAgreement,
    /// Complete live request-imprint equality, when supplied.
    pub requested_imprint: Option<RequestAgreement>,
    /// Independent requested nonce/policy agreement.
    pub requested_fields: Option<RequestFields>,
    /// Certificate carriage requirement, when requested.
    pub carried: Option<bool>,
    /// Explicit freshness answer, without an implicitly read clock.
    pub timeliness: Timeliness,
    /// Readable Accuracy scalar refusal, without clamping/narrowing.
    pub accuracy_error: Option<super::DeviationError>,
    /// Unknown critical identifiers with independently retained charges.
    pub unknown_critical: OwnedVec<OwnedOid>,
    evidence: Option<Evidence>,
}
impl CheckedTimestamp<'_> {
    /// Moves independently retained evidence out while keeping every original
    /// negative/check fact available to a scoped format adapter. No copy or
    /// second signature/content pass occurs, and mutable public facts still
    /// cannot manufacture evidence.
    pub fn take_evidence(&mut self) -> Option<Evidence> {
        self.evidence.take()
    }
    /// Moves retained evidence without deep copy or another storage charge.
    pub fn into_evidence(self) -> Option<Evidence> {
        self.evidence
    }
    /// Only the checker constructs evidence; editing public facts cannot do so.
    #[must_use]
    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }
}

struct Information {
    authority: AuthorityFacts,
    imprint: ImprintAgreement,
    requested_imprint: Option<RequestAgreement>,
    requested_fields: Option<RequestFields>,
    timeliness: Timeliness,
    accuracy_error: Option<super::DeviationError>,
    unknown: OwnedVec<OwnedOid>,
    evidence: Option<Evidence>,
}
#[derive(Clone, Copy)]
enum CheckPurpose {
    Ordinary,
    Historical,
}

impl Information {
    fn holds(&self, purpose: CheckPurpose) -> bool {
        self.accuracy_error.is_none()
            && matches!(self.authority.usage, TsaUsage::TimeStampingOnly)
            && matches!(
                self.authority.identity,
                TsaIdentity::Absent | TsaIdentity::Matches
            )
            && self.imprint == ImprintAgreement::Matches
            && self
                .requested_imprint
                .is_none_or(|answer| answer == RequestAgreement::Matches)
            && self
                .requested_fields
                .is_none_or(|fields| fields.nonce != Some(false) && fields.policy != Some(false))
            && self.unknown.is_empty()
            && match purpose {
                CheckPurpose::Ordinary => matches!(
                    self.timeliness,
                    Timeliness::NotRequested | Timeliness::LocalWindow | Timeliness::RequestNonce
                ),
                // RFC4998 §5.3 qualifies archival TSA/path/algorithm validity
                // through its explicit historical validator and next token.
                // This pass asserts no live request/current-clock freshness.
                CheckPurpose::Historical => self.timeliness == Timeliness::Unverified,
            }
    }
}

struct Inspection<'a, 'r, P, S, R> {
    provider: &'a P,
    context: &'r CheckContext<'a, 'r>,
    covered: &'r mut S,
    recognizes: &'r mut R,
    common_holds: bool,
    purpose: CheckPurpose,
}

impl<P, S, R> Inspection<'_, '_, P, S, R> {
    fn inspect<'scope, PE, RE>(
        &mut self,
        info: &super::TokenInfo<'scope>,
        inside: &Reader<'scope>,
        source: &SourceMap,
    ) -> Result<Information, InfoCheckError<S::Error, PE, RE>>
    where
        P: for<'input> SignatureProvider<'input, Error = PE>,
        S: ComputedInput<P, PE>,
        R: FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    {
        let authority = info
            .authority(
                self.context.certificate,
                inside,
                self.context.certificate_parent,
            )
            .map_err(InfoCheckError::Authority)?;
        let requested_fields = self
            .context
            .requested
            .as_ref()
            .map(|request| info.matches_request_fields(request.request, inside, request.parent))
            .transpose()
            .map_err(InfoCheckError::RequestField)?;
        let unknown = unrecognized(info, inside, self.recognizes)?;
        let (imprint, requested_imprint) = match &self.context.requested {
            Some(request) => {
                let (imprint, agreement) = info
                    .imprint()
                    .check_requested_input(
                        request.request.imprint(),
                        self.provider,
                        (inside, request.parent),
                        self.covered,
                    )
                    .map_err(|error| match error {
                        super::RequestedContentError::Request(source) => {
                            InfoCheckError::RequestImprint(source)
                        }
                        super::RequestedContentError::Content(source) => {
                            InfoCheckError::Imprint(source)
                        }
                    })?;
                (imprint, Some(agreement))
            }
            None => (
                info.imprint()
                    .check_input(self.provider, inside, self.covered)
                    .map_err(InfoCheckError::Imprint)?,
                None,
            ),
        };
        finish_information(
            info,
            inside,
            source,
            self.context,
            InformationFacts {
                authority,
                imprint,
                requested_imprint,
                requested_fields,
                unknown,
            },
            self.common_holds,
            self.purpose,
        )
    }
}

struct InformationFacts {
    authority: AuthorityFacts,
    imprint: ImprintAgreement,
    requested_imprint: Option<RequestAgreement>,
    requested_fields: Option<RequestFields>,
    unknown: OwnedVec<OwnedOid>,
}

fn finish_information<SE, PE, RE>(
    info: &super::TokenInfo<'_>,
    inside: &Reader<'_>,
    source: &SourceMap,
    context: &CheckContext<'_, '_>,
    facts: InformationFacts,
    common_holds: bool,
    purpose: CheckPurpose,
) -> Result<Information, InfoCheckError<SE, PE, RE>> {
    let InformationFacts {
        authority,
        imprint,
        requested_imprint,
        requested_fields,
        unknown,
    } = facts;
    let (accuracy, accuracy_error) = match info
        .accuracy()
        .map(super::AccuracyReading::deviation)
        .transpose()
    {
        Ok(accuracy) => (accuracy, None),
        Err(error) => (None, Some(error)),
    };
    let timeliness = super::timeliness(
        info.gen_time(),
        accuracy,
        context.utc,
        context.reference,
        context.requested.is_some(),
        requested_fields.and_then(|fields| fields.nonce),
        context.window,
    );
    let mut information = Information {
        authority,
        imprint,
        requested_imprint,
        requested_fields,
        timeliness,
        accuracy_error,
        unknown,
        evidence: None,
    };
    if common_holds && !info.has_faults() && information.holds(purpose) {
        information.evidence = Some(Evidence {
            facts: info
                .retain_facts(inside)
                .map_err(InfoCheckError::Processing)?,
            source: source
                .try_copy_in(&inside.execution())
                .map_err(InfoCheckError::Provenance)?,
        });
    }
    Ok(information)
}

fn unrecognized<SE, PE, RE>(
    info: &super::TokenInfo<'_>,
    inside: &Reader<'_>,
    recognizes: &mut impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
) -> Result<OwnedVec<OwnedOid>, InfoCheckError<SE, PE, RE>> {
    let scoped = inside.execution();
    let mut unknown = scoped.vector();
    if let Some(extensions) = info.extensions() {
        for kind in extensions
            .unrecognized_critical(inside, recognizes)
            .map_err(InfoCheckError::Recognition)?
        {
            let owned = OwnedOid::from_oid_in(kind, &scoped).map_err(|reason| {
                InfoCheckError::Processing(Error::resource(
                    reason,
                    "tstInfo.extensions",
                    extensions.span().start,
                ))
            })?;
            unknown.try_push(owned).map_err(|reason| {
                InfoCheckError::Processing(Error::resource(
                    reason,
                    "tstInfo.extensions",
                    extensions.span().start,
                ))
            })?;
        }
    }
    Ok(unknown.into_owned())
}

fn common_holds(
    signature: &TokenSignature<'_>,
    bindings: ess::Bindings,
    identifier: &directory::CertificateAgreement,
    carried: Option<bool>,
) -> bool {
    matches!(signature, TokenSignature::Checked(checked)
        if checked.signature() == Some(SignatureAnswer::Valid)
        && matches!(checked.content(), verify::ContentAgreement::Matches | verify::ContentAgreement::Direct))
        && (bindings.v1 == Some(ess::Binding::Matches)
            || bindings.v2 == Some(ess::Binding::Matches))
        && bindings
            .v1
            .is_none_or(|binding| binding == ess::Binding::Matches)
        && bindings
            .v2
            .is_none_or(|binding| binding == ess::Binding::Matches)
        && matches!(identifier, directory::CertificateAgreement::Matches)
        && carried != Some(false)
}

impl<'doc> Token<'doc> {
    /// Checks original CMS, ESS, TSA, content, request and time together.
    ///
    /// Caller path/status/policy and signed ESS restriction enforcement remain
    /// external. Semantic negatives remain facts, never evidence. Processing,
    /// provider and source refusals abort. Provider errors are source-independent
    /// so a temporary joined information buffer cannot escape in their type.
    /// Optional rejection of unlisted digest algorithms (RFC5652 §5.3) belongs
    /// to caller policy. Evidence does not assert that every sender SHOULD or
    /// application-profile requirement was satisfied.
    #[expect(
        clippy::result_large_err,
        reason = "preserve original cause and accounted source context without allocating on refusal"
    )]
    pub fn check<'a, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<CheckedTimestamp<'a>, CheckError<S::Error, PE, RE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_with_profile(provider, parent, context, covered, recognizes, |_| {
            Ok::<(), ProfileFailure<Infallible>>(())
        })
        .map_err(ProfileCheckError::into_common)
    }

    /// Checks the same common timestamp once, with a scoped profile inspection
    /// before any ESS binding, provider resolution, signature/content execution
    /// or extension-recognition callback. Original syntax faults still refuse
    /// first. The profile sees original fields, both producing readers and
    /// their coordinate contexts; it must fund its own work before execution.
    /// Refusal is terminal and cannot borrow a temporary information buffer.
    /// The common core does not roll back external side effects of the profile.
    #[expect(
        clippy::result_large_err,
        reason = "keep opaque common/profile refusal and its source context without allocating while returning an error"
    )]
    pub fn check_with_profile<'a, P, S: Source, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<S::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_input_with_profile(
            provider,
            parent,
            context,
            &mut RawInput::new(covered),
            recognizes,
            profile,
        )
    }

    /// Same complete timestamp, with a computed imprint rather than raw bytes.
    /// Common CMS/ESS/authority/time/profile checks execute once; only the
    /// recipe defines the normative hash input. A closed completed comparison
    /// is required before mathematical timestamp evidence can be retained.
    #[expect(
        clippy::result_large_err,
        reason = "retain opaque input/provider/profile failures and original source maps"
    )]
    pub fn check_input_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: ComputedInput<P, PE>,
    {
        self.check_in(
            provider,
            (parent, None),
            (context, CheckPurpose::Ordinary),
            covered,
            recognizes,
            profile,
        )
    }

    /// Archival mathematical/profile pass for ERS and historical `CAdES` `PoE`.
    /// Its evidence establishes the bound mathematical timestamp, not current
    /// trust/status or a complete archive. The format composition MUST close
    /// historical authority, algorithm suitability and renewal chronology
    /// independently before issuing its own complete preservation receipt.
    /// Current-clock/live-request assertions are forbidden rather than ignored.
    #[expect(
        clippy::result_large_err,
        reason = "historical checking preserves the same original mapped input and profile causes as the complete token check, without allocating on refusal"
    )]
    pub fn check_historical_input_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        parent: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: ComputedInput<P, PE>,
    {
        if context.requested.is_some() || context.reference.is_some() || context.window.is_some() {
            return Err(CheckError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                "tstInfo.historical",
                self.message().span().start,
            ))
            .into());
        }
        self.check_in(
            provider,
            (parent, None),
            (context, CheckPurpose::Historical),
            covered,
            recognizes,
            profile,
        )
    }

    /// Checks a token decoded in another joined source using the same core.
    /// The map corresponds to its producing envelope reader. Child `TSTInfo`
    /// maps are composed to physical fragments; outer CMS errors separately
    /// retain the envelope map instead of borrowing a temporary joined buffer.
    #[expect(
        clippy::result_large_err,
        reason = "preserve both source frames and original opaque refusal without a fallible error box"
    )]
    pub fn check_mapped<'a, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        source: (&Reader<'a>, &SourceMap),
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<CheckedTimestamp<'a>, MappedCheckError<S::Error, PE, RE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_mapped_with_profile(provider, source, context, covered, recognizes, |_| {
            Ok::<(), ProfileFailure<Infallible>>(())
        })
        .map_err(MappedProfileCheckError::into_common)
    }

    /// Same profile/core kernel for a logically joined CMS envelope. Both
    /// independent maps survive refusal; an outer profile location must use
    /// the envelope map rather than the inner information map. Reader/session
    /// misuse is refused before map admission or profile/provider dispatch.
    #[expect(
        clippy::result_large_err,
        reason = "preserve both independently retained source frames and the original opaque refusal without a fallible error allocation"
    )]
    pub fn check_mapped_with_profile<'a, P, S: Source, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        source: (&Reader<'a>, &SourceMap),
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, MappedProfileCheckError<S::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_mapped_input_with_profile(
            provider,
            source,
            context,
            &mut RawInput::new(covered),
            recognizes,
            profile,
        )
    }

    /// Computed input with the same independent envelope/information source
    /// maps as the raw path. Foreign sessions refuse before profile dispatch.
    #[expect(
        clippy::result_large_err,
        reason = "preserve both source frames and opaque refusal without allocating on failure"
    )]
    pub fn check_mapped_input_with_profile<'a, P, I, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        source: (&Reader<'a>, &SourceMap),
        context: &CheckContext<'a, '_>,
        covered: &mut I,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, MappedProfileCheckError<I::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        I: ComputedInput<P, PE>,
    {
        let (parent, source) = source;
        preflight_sessions(self, parent, context)
            .map_err(|error| MappedProfileCheckError::Preflight(error.into()))?;
        let envelope = source
            .try_copy_in(&parent.execution())
            .map_err(MappedProfileCheckError::Provenance)?;
        self.check_in(
            provider,
            (parent, Some(source)),
            (context, CheckPurpose::Ordinary),
            covered,
            recognizes,
            profile,
        )
        .map_err(|source| MappedProfileCheckError::Execution { envelope, source })
    }

    #[expect(
        clippy::result_large_err,
        reason = "retain original cause and accounted source context on refusal"
    )]
    fn check_in<'a, P, S, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        origin: (&Reader<'a>, Option<&SourceMap>),
        context: (&CheckContext<'a, '_>, CheckPurpose),
        covered: &mut S,
        mut recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedTimestamp<'a>, ProfileCheckError<S::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        S: ComputedInput<P, PE>,
    {
        let (parent, source) = origin;
        let (context, purpose) = context;
        preflight(self, parent, context).map_err(CheckError::from)?;
        let certificate = context.certificate;
        let identifier =
            directory::matches_certificate_in(self.signer().sid(), certificate, parent)
                .map_err(CheckError::Identifier)?;
        let ess =
            ess::SigningAttributes::read(self.signer(), parent).map_err(CheckError::Processing)?;
        let carried = context
            .requested
            .as_ref()
            .map(|requested| {
                self.matches_cert_req(
                    requested.request,
                    Some(certificate),
                    parent,
                    requested.parent,
                )
            })
            .transpose()
            .map_err(CheckError::RequestField)?;
        if !self.faults().is_empty()
            || !self.message().faults().is_empty()
            || !self.signer().faults().is_empty()
            || !ess.faults().is_empty()
            || ess.v1().is_some_and(|reading| !reading.faults().is_empty())
            || ess.v2().is_some_and(|reading| !reading.faults().is_empty())
        {
            return Err(CheckError::Nonconforming {
                span: self.message().span(),
            }
            .into());
        }
        let inspect = |info: &super::TokenInfo<'_>,
                       inside: &Reader<'_>,
                       information: &SourceMap|
         -> Result<_, profile::InformationFailure<S::Error, PE, RE, FE>> {
            if info.has_faults() {
                return Err(InfoCheckError::Nonconforming { span: info.span() }.into());
            }
            profile(ProfileInput {
                token: self,
                parent,
                envelope: source,
                ess: &ess,
                info,
                reader: inside,
                source: information,
            })
            .map_err(profile::InformationFailure::Profile)?;
            let bindings = ess
                .bind_certificate(provider, certificate, parent)
                .map_err(InfoCheckError::Ess)?;
            let signature = self
                .check_signature(provider, context.key, parent)
                .map_err(InfoCheckError::Signature)?;
            let common_holds = common_holds(&signature, bindings, &identifier, carried);
            let mut inspection = Inspection {
                provider,
                context,
                covered,
                recognizes: &mut recognizes,
                common_holds,
                purpose,
            };
            let checked = inspection.inspect(info, inside, information)?;
            Ok((signature, bindings, checked))
        };
        let (signature, bindings, information) = match source {
            Some(source) => self.with_info_mapped(parent, source, inspect),
            None => self.with_info(parent, inspect),
        }
        .map_err(profile::information_error)?;
        Ok(CheckedTimestamp {
            signature,
            identifier,
            ess,
            bindings,
            authority: information.authority,
            imprint: information.imprint,
            requested_imprint: information.requested_imprint,
            requested_fields: information.requested_fields,
            carried,
            timeliness: information.timeliness,
            accuracy_error: information.accuracy_error,
            unknown_critical: information.unknown,
            evidence: information.evidence,
        })
    }
}

enum PreflightError {
    Processing(Error),
    Requested(super::RequestFieldError),
    KeyMismatch(structured_asn1::Span),
}

impl<SE, PE, RE> From<PreflightError> for CheckError<SE, PE, RE> {
    fn from(error: PreflightError) -> Self {
        match error {
            PreflightError::Processing(error) => Self::Processing(error),
            PreflightError::Requested(error) => Self::RequestField(error),
            PreflightError::KeyMismatch(certificate) => Self::KeyMismatch { certificate },
        }
    }
}

fn preflight(
    token: &Token<'_>,
    parent: &Reader<'_>,
    context: &CheckContext<'_, '_>,
) -> Result<(), PreflightError> {
    preflight_sessions(token, parent, context)?;
    let certificate = context.certificate;
    let written = certificate.tbs().public_key().as_bytes();
    let key = context.key.key().as_bytes();
    let length = u64::try_from(written.len().max(key.len()))
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            PreflightError::Processing(Error::schema(
                ErrorCode::LengthOverflow,
                "certificate.subjectPublicKeyInfo",
                certificate.span().start,
            ))
        })?;
    parent.execution().charge_work(length).map_err(|reason| {
        PreflightError::Processing(Error::resource(
            reason,
            "certificate.subjectPublicKeyInfo",
            certificate.span().start,
        ))
    })?;
    if written != key {
        return Err(PreflightError::KeyMismatch(certificate.span()));
    }
    Ok(())
}

fn preflight_sessions(
    token: &Token<'_>,
    parent: &Reader<'_>,
    context: &CheckContext<'_, '_>,
) -> Result<(), PreflightError> {
    token
        .signer()
        .require_session(parent, "signerInfo")
        .map_err(PreflightError::Processing)?;
    let certificate = context.certificate;
    if !certificate
        .tbs()
        .public_key()
        .algorithm()
        .same_session(context.certificate_parent)
    {
        return Err(PreflightError::Processing(Error::pkix(
            structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                "certificate",
                certificate.span().start,
            ),
        )));
    }
    if let Some(requested) = &context.requested
        && !requested.request.same_session(requested.parent)
    {
        return Err(PreflightError::Requested(super::RequestFieldError {
            operand: super::ImprintOperand::Requested,
            source: Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                "timeStampReq",
                requested.request.span().start,
            )),
        }));
    }
    Ok(())
}
