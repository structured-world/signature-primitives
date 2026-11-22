//! ETSI EN 319 102-1 V1.4.1 clause 5.6 over established validation facts.
//!
//! Object ordinals identify exact original objects in a single caller catalogue.
//! The caller establishes format coverage, applicability of revocation data,
//! cryptographic checks and prospective RFC 5280 path results.

mod past;
mod poe;

use super::{
    Basis, Facts, Hash, Indication, Material, Outcome, Requirements, Retry, SubIndication,
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::{crl::Reason, temporal::Instant};

/// An original object in the operation's single, dense catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object(pub usize);

/// An authenticated upper bound for the existence of an original object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// Object whose bytes were covered.
    pub object: Object,
    /// The object existed by this instant.
    pub at: Instant,
}

/// A completed ETSI building block indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The building block passed.
    Passed,
    /// The Table 6 finding deciding the block.
    Finding(SubIndication),
}

impl Decision {
    /// Main indication for reporting.
    #[must_use]
    pub const fn indication(self) -> Indication {
        match self {
            Self::Passed => Indication::TotalPassed,
            Self::Finding(sub) => sub.indication(),
        }
    }

    /// Table 7 condition, where one is defined.
    #[must_use]
    pub const fn retry(self) -> Option<Retry> {
        match self {
            Self::Passed => None,
            Self::Finding(sub) => sub.retry(),
        }
    }
}

impl From<Outcome> for Decision {
    fn from(value: Outcome) -> Self {
        value.sub.map_or(Self::Passed, Self::Finding)
    }
}

/// Failure to process facts, separate from a completed ETSI decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Current or original execution refused storage or work.
    Resource(MemoryError),
    /// An object ordinal was outside the catalogue.
    ForeignObject(Object),
    /// A proof or timestamp exceeds the supplied current time.
    FutureTime(Instant),
}

impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Resource(value)
    }
}

/// Whether a candidate path uses shell or chain validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidityModel {
    /// All certificates must be valid at the validation time.
    Shell,
    /// Issuers must be valid at their applicable certificate issuance times.
    Chain,
}

/// Certificate validity interval, inclusive at both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// Beginning of validity.
    pub not_before: Instant,
    /// End of validity.
    pub not_after: Instant,
}

impl Validity {
    fn contains(self, at: Instant) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}

/// An upper limit for historically reliable validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Horizon {
    /// Proofs at this instant are admissible.
    Through(Instant),
    /// Proofs must strictly predate this instant (e.g., a compromise).
    Before(Instant),
}

impl Horizon {
    /// The boundary instant.
    #[must_use]
    pub const fn time(self) -> Instant {
        match self {
            Self::Through(at) | Self::Before(at) => at,
        }
    }

    /// Whether the instant is admitted by this boundary.
    #[must_use]
    pub fn admits(self, at: Instant) -> bool {
        match self {
            Self::Through(end) => at <= end,
            Self::Before(end) => at < end,
        }
    }

    fn tighten(&mut self, limit: Self) {
        if !limit.admits(self.time()) && limit.time() <= self.time() {
            *self = limit;
        }
    }
}

/// Algorithm and key-size facts bound to the exact material they describe.
#[derive(Debug, Clone, Copy)]
pub struct CryptoObject {
    /// The original signed object.
    pub object: Object,
    /// Mechanisms established by the format or PKIX processor.
    pub material: Material,
}

/// Established status in one applicable piece of authenticated revocation data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// The certificate is known not to have been revoked.
    Clear,
    /// The certificate was revoked or suspended.
    Revoked {
        /// Time this status starts.
        at: Instant,
        /// The reason, if specified in the source.
        reason: Option<Reason>,
    },
}

/// Revocation evidence already authenticated and applicable to its target.
#[derive(Debug, Clone, Copy)]
pub struct RevocationData<'a> {
    /// Original CRL or OCSP response.
    pub object: Object,
    /// Original certificate that issued the data.
    pub issuer: Object,
    /// Issuer validity for the historical proof check.
    pub issuer_validity: Validity,
    /// Issuance of the status, e.g. OCSP thisUpdate.
    pub issued: Instant,
    /// Exclusive freshness horizon from the caller's selected X.509
    /// constraints or nextUpdate as specified by clause 5.2.5.4.
    pub fresh_before: Option<Instant>,
    /// The recorded finding.
    pub status: Revocation,
    /// Signature mechanisms for this revocation data.
    pub crypto: &'a [CryptoObject],
    /// Historical limit for a separately validated delegated issuer chain.
    /// Absent when the issuer is validated by the same path.
    pub delegated: Option<Horizon>,
}

/// One non-anchor certificate, in issuer-to-target path order.
#[derive(Debug, Clone, Copy)]
pub struct Member<'a> {
    /// Original certificate.
    pub object: Object,
    /// Cryptographic constraints to check for this certificate's material.
    pub crypto: &'a [CryptoObject],
    /// Revocation evidence or an explicit waiver in the selected policy.
    pub revocations: RevocationCheck<'a>,
}

/// The selected X.509 revocation constraint for one member.
#[derive(Debug, Clone, Copy)]
pub enum RevocationCheck<'a> {
    /// Authenticated applicable evidence. An empty catalogue cannot pass.
    Required(&'a [RevocationData<'a>]),
    /// The selected constraints explicitly waive revocation for this member.
    Waived,
}

/// One caller-established historical candidate path.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// RFC 5280 and chain constraint facts, with the historical validity model.
    pub chain: super::Chain,
    /// Whether the caller recognizes this anchor for historical validation.
    pub recognized: bool,
    /// Anchor sunset, if supplied by the caller.
    pub anchor_sunset: Option<Instant>,
    /// Validity intersection for shell, target validity alone for chain.
    pub validity: Validity,
    /// Path members in issuer-to-target order, excluding the anchor.
    pub members: &'a [Member<'a>],
}

/// Exact original coverage, including references authenticated by this token.
#[derive(Debug, Clone, Copy)]
pub enum Covered {
    /// Directly covered object, including any established contained objects.
    Direct(Object),
    /// Covered reference to a matching object established by the format layer.
    Reference {
        /// Object identity of the protected hash value.
        digest: Object,
        /// Exact original target bound to the reference.
        target: Object,
        /// Mechanism that produced the reference digest.
        hash: Hash,
    },
}

/// Evidence Record result established by its format implementation.
#[derive(Debug, Clone, Copy)]
pub struct EvidenceRecord<'a> {
    /// Completed record result, including the checks of its renewal tokens.
    pub decision: Decision,
    /// Initial archive timestamp time.
    pub initial: Instant,
    /// Objects bound by the completed record.
    pub covered: &'a [Object],
}

/// Source of a recoverable `TRY_LATER` finding.
#[derive(Debug, Clone, Copy)]
pub enum RetryCause<'a> {
    /// A signer suspension was established.
    Suspension {
        /// Retry time carried by the deciding status evidence.
        retry_at: Option<Instant>,
    },
    /// These exact status facts failed freshness at the current time.
    Freshness {
        /// Status evidence to check again at best-signature-time.
        record: &'a RevocationData<'a>,
        /// Retry time carried by the deciding status evidence.
        retry_at: Option<Instant>,
    },
    /// No historical recovery rule for the supplied finding.
    Other,
}

/// Supplied facts for the past signature building block.
#[derive(Debug, Clone, Copy)]
pub struct Signature<'a> {
    /// Original signature value.
    pub value: Object,
    /// Signer validity.
    pub validity: Validity,
    /// Historical prospective paths.
    pub candidates: &'a [Candidate<'a>],
    /// The selected validity model.
    pub model: ValidityModel,
    /// Timing of a revoked CA when the current finding names it.
    pub revoked_ca_at: Option<Instant>,
    /// Recorded target evidence for the current chain, where available.
    pub revocations: &'a [RevocationData<'a>],
    /// Records containing the mechanisms concerned by a crypto failure.
    pub affected_crypto: &'a [CryptoObject],
    /// Cause of the supplied try-later finding.
    pub retry: RetryCause<'a>,
}

/// Authenticated coverage and preliminary results for one timestamp.
#[derive(Debug, Clone, Copy)]
pub struct Timestamp<'a> {
    /// Original timestamp token protected by subsequent evidence.
    pub object: Object,
    /// Generation-time upper bound, including any RFC 3161 accuracy.
    pub generated: Instant,
    /// Proven generation-time lower bound, if known.
    pub not_before: Option<Instant>,
    /// Hash used in messageImprint.
    pub imprint: Hash,
    /// Clause 5.4 result established by the producer.
    pub current: Decision,
    /// Past signature inputs when a recoverable timestamp finding is reported.
    pub past: Option<Signature<'a>>,
    /// Signature mechanisms for the clause 5.2.8 check after historical recovery.
    pub acceptance: &'a [Material],
    /// Objects and bound references covered by the authenticated token.
    pub covered: &'a [Covered],
    /// Whether the caller requires this attribute to validate.
    pub required: bool,
}

/// Caller-established inputs for clause 5.6.3.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// Original object catalogue size.
    pub object_count: usize,
    /// Objects present at current time.
    pub present: &'a [Object],
    /// External authenticated proofs, such as from a trusted archive.
    pub initial: &'a [Proof],
    /// Current validation facts consumed by the common basic/with-time process.
    pub current: &'a Facts<'a>,
    /// Original signature and its historical validation inputs.
    pub signature: Signature<'a>,
    /// Completed Evidence Record checks in caller order.
    pub records: &'a [EvidenceRecord<'a>],
    /// Timestamp attributes in the producer's newest-first processing order.
    /// Use established generation order, rather than sorting accuracy bounds.
    pub timestamps: &'a [Timestamp<'a>],
    /// Whether there are long-term availability attributes, including any
    /// unavailable or invalid ones recorded by the caller.
    pub has_long_term_attributes: bool,
    /// Whether the selected constraints require long-term attributes to validate.
    pub require_long_term_attributes: bool,
}

/// Past certificate building block answer, including the decisive path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PastCertificate {
    /// Selected historical candidate and validation limit.
    Passed {
        /// Index into the supplied candidates.
        path: usize,
        /// Last admissible time for this path.
        horizon: Horizon,
    },
    /// Last candidate failure, or no known path.
    Finding {
        /// Table 6 sub-indication.
        sub: SubIndication,
        /// Candidate index, if a candidate was examined.
        path: Option<usize>,
        /// Exact signed object needing proof, when a candidate exposed one.
        missing_proof: Option<Object>,
    },
}

/// Independent past signature and past certificate building block answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PastSignature {
    /// Past signature decision.
    pub decision: Decision,
    /// Result of historical certificate processing, when used.
    pub certificate: Option<PastCertificate>,
    /// Whether a suitable proof of the signature value was found.
    pub signature_poe: Option<bool>,
    /// Whether target revocation evidence has suitable issuer proof.
    pub revocation_poe: Option<bool>,
    /// Retry suggestion from the deciding evidence if `TRY_LATER` remains.
    pub retry_at: Option<Instant>,
}

/// One timestamp's current and historical results in processing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampAnswer {
    /// Its original ordinal in the supplied timestamp list.
    pub index: usize,
    /// The supplied current result.
    pub current: Decision,
    /// Historical result, if invoked.
    pub past: Option<PastSignature>,
    /// Final attribute result, including imprint reliability or acceptance.
    pub decision: Decision,
    /// Token needing proof of existence for the deciding `NO_POE`.
    pub missing_proof: Option<Object>,
}

/// The building block deciding the long-term indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The with-time result is conclusive or no archival attributes exist.
    WithTime,
    /// A required or required-to-pass attribute failed.
    Timestamp(usize),
    /// Historical signature verification decided the result.
    PastSignature,
    /// Recovered proof predates the signing certificate.
    SignerValidity,
    /// The timestamp ordering check decided the result.
    TimestampOrder,
    /// The final timestamp delay check decided the result.
    TimestampDelay,
    /// Final signature acceptance.
    SignatureAcceptance,
}

/// Results in clause order. Unprocessed timestamps have no answer entry.
pub struct Report<W: Work> {
    /// Initial basic/with-time result and its independent axes.
    pub current: Outcome,
    /// Overall ETSI indication and sub-indication.
    pub decision: Decision,
    /// Processing stage producing the final indication.
    pub stage: Stage,
    /// Earliest established existence of the signature value.
    pub best_signature_time: Instant,
    /// Past signature result, when reached.
    pub past: Option<PastSignature>,
    timestamps: OwnedVec<TimestampAnswer, W>,
}

impl<W: Work> Report<W> {
    /// Results of the processed timestamp attributes, in clause order.
    #[must_use]
    pub fn timestamps(&self) -> &[TimestampAnswer] {
        &self.timestamps
    }
}

fn retry_timestamp(sub: SubIndication) -> bool {
    use SubIndication as S;
    matches!(
        sub,
        S::RevokedNoPoe
            | S::RevokedCaNoPoe
            | S::OutOfBoundsNoPoe
            | S::OutOfBoundsNotRevoked
            | S::CryptoConstraintsFailureNoPoe
            | S::RevocationOutOfBoundsNoPoe
    )
}

fn retry_signature(decision: Decision) -> bool {
    match decision {
        Decision::Passed => true,
        Decision::Finding(sub) => {
            retry_timestamp(sub)
                || matches!(
                    sub,
                    SubIndication::SigConstraintsFailure | SubIndication::TryLater
                )
        }
    }
}

fn accept(
    materials: &[Material],
    at: Instant,
    lower: Option<Instant>,
    crypto: &poe::Crypto<'_>,
    work: &impl Work,
) -> Result<Decision, Error> {
    for &material in materials {
        if let Err(unmet) = crypto.assess(material, at, lower, work)? {
            return Ok(Decision::Finding(if unmet.proven_after {
                SubIndication::CryptoConstraintsFailure
            } else {
                SubIndication::CryptoConstraintsFailureNoPoe
            }));
        }
    }
    Ok(Decision::Passed)
}

fn process_timestamp<W: Work>(
    timestamp: &Timestamp<'_>,
    index: usize,
    now: Instant,
    requirements: &Requirements<'_>,
    proofs: &mut poe::Proofs<W>,
    crypto: &poe::Crypto<'_>,
    work: &W,
) -> Result<TimestampAnswer, Error> {
    let mut answer = TimestampAnswer {
        index,
        current: timestamp.current,
        past: None,
        decision: timestamp.current,
        missing_proof: None,
    };
    if let Decision::Finding(sub) = timestamp.current
        && retry_timestamp(sub)
        && let Some(signature) = timestamp.past
    {
        let historical = past::signature(&signature, timestamp.current, now, proofs, crypto, work)?;
        answer.past = Some(historical);
        answer.decision = historical.decision;
        if answer.decision == Decision::Passed {
            answer.decision = if let Some(at) = proofs.earliest(timestamp.object, work)? {
                accept(timestamp.acceptance, at, None, crypto, work)?
            } else {
                answer.missing_proof = Some(timestamp.object);
                Decision::Finding(SubIndication::NoPoe)
            };
        }
    }
    if answer.decision == Decision::Passed {
        let proof = proofs.earliest(timestamp.object, work)?;
        let limit = poe::hash_limit(&requirements.crypto, timestamp.imprint, now, work)?;
        // EN 319 102-1 5.6.3.4 step 5 tests hash reliability at the proof
        // time. The generation upper bound can include timestamp accuracy.
        if proof.is_some_and(|at| limit.is_some_and(|end| end.admits(at))) {
            proofs.extract(
                timestamp.covered,
                timestamp.generated.min(now),
                &requirements.crypto,
                work,
            )?;
        } else {
            answer.missing_proof = Some(timestamp.object);
            answer.decision = Decision::Finding(SubIndication::NoPoe);
        }
    }
    Ok(answer)
}

/// Proof input for a standalone past-signature building block invocation.
/// During Evidence Record renewal callers may include temporary proofs from
/// the next timestamp and discard them if the record fails.
#[derive(Debug, Clone, Copy)]
pub struct PastInputs<'a> {
    /// Size of the original object catalogue.
    pub object_count: usize,
    /// Established proof bounds.
    pub proofs: &'a [Proof],
    /// Current caller-supplied validation time.
    pub now: Instant,
    /// Current-time indication of this signature or timestamp.
    pub current: Decision,
    /// Exact historical facts for this signature.
    pub signature: Signature<'a>,
}

/// Perform clause 5.6.2.4 with caller-supplied historical proof facts.
/// The proof store is local to the invocation and drops on every return.
pub fn validate_past_signature<W: Work>(
    input: &PastInputs<'_>,
    requirements: &Requirements<'_>,
    work: &W,
) -> Result<PastSignature, Error> {
    let mut proofs = poe::Proofs::new(input.object_count, input.now, work)?;
    for proof in input.proofs {
        proofs.add(*proof, work)?;
    }
    let crypto = poe::Crypto::new(&requirements.crypto, work)?;
    past::signature(
        &input.signature,
        input.current,
        input.now,
        &proofs,
        &crypto,
        work,
    )
}

fn collect_proofs<W: Work>(
    inputs: &Inputs<'_>,
    current: &Outcome,
    work: &W,
) -> Result<poe::Proofs<W>, Error> {
    let now = inputs.current.now;
    let mut proofs = poe::Proofs::new(inputs.object_count, now, work)?;
    for proof in inputs.initial {
        proofs.add(*proof, work)?;
    }
    // 5.6.3.4 steps 1 and 2: passing records contribute their coverage,
    // and original objects present now have proof at now.
    for record in inputs.records {
        work.charge_work(1)?;
        if record.decision == Decision::Passed {
            for &object in record.covered {
                proofs.add(
                    Proof {
                        object,
                        at: record.initial,
                    },
                    work,
                )?;
            }
        }
    }
    for &object in inputs.present {
        proofs.add(Proof { object, at: now }, work)?;
    }
    proofs.add(
        Proof {
            object: inputs.signature.value,
            at: current.best_signature_time,
        },
        work,
    )?;
    Ok(proofs)
}

/// Perform EN 319 102-1 V1.4.1 clause 5.6.3 in processing order.
///
/// Covered objects are supplied by the authenticated format layer. Evidence
/// Record checks, including any temporary next-record proofs used during
/// renewal validation, arrive as completed facts. Only passing records can
/// seed this process. The caller supplies the joined current and original
/// resource domain and the exact proof-object catalogue for one operation.
///
/// # Errors
/// Returns invalid catalogue or time facts, or an original resource refusal.
pub fn validate<W: Work>(
    inputs: &Inputs<'_>,
    requirements: &Requirements<'_>,
    work: &W,
) -> Result<Report<W>, Error> {
    let current = super::validate(inputs.current, requirements, work)?;
    let decision = Decision::from(current);
    let mut report = Report {
        current,
        decision,
        stage: Stage::WithTime,
        best_signature_time: current.best_signature_time,
        past: None,
        timestamps: work.vector(),
    };
    if !inputs.has_long_term_attributes
        || !retry_signature(decision)
        || (decision == Decision::Passed && !inputs.require_long_term_attributes)
    {
        return Ok(report);
    }
    let now = inputs.current.now;
    let mut proofs = collect_proofs(inputs, &current, work)?;
    let crypto = poe::Crypto::new(&requirements.crypto, work)?;
    for (index, timestamp) in inputs.timestamps.iter().enumerate() {
        work.charge_work(8)?;
        // EN 319 102-1 §5.6.3.4 step 5(a) consumes the established order.
        // RFC 3161 §2.4.2 accuracy bounds neither establish ordering nor
        // prove future generation unless the lower bound is in the future.
        // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
        if let Some(lower) = timestamp.not_before
            && lower > now
        {
            return Err(Error::FutureTime(lower));
        }
        let answer = process_timestamp(
            timestamp,
            index,
            now,
            requirements,
            &mut proofs,
            &crypto,
            work,
        )?;
        report.timestamps.try_push(answer)?;
        if timestamp.required && answer.decision != Decision::Passed {
            report.decision = answer.decision;
            report.stage = Stage::Timestamp(index);
            return Ok(report);
        }
    }
    if let Some(best) = proofs.earliest(inputs.signature.value, work)? {
        report.best_signature_time = best;
    }
    // The preliminary process reaches timestamp delay only after all earlier
    // checks pass. Clause 5.6.3.4 step 8 checks it with the newly proven time.
    // Preserve the preliminary finding in the report and keep every other
    // signature constraint effective during past validation.
    let past_input = match (decision, current.basis) {
        (Decision::Finding(SubIndication::SigConstraintsFailure), Some(Basis::TimestampDelay)) => {
            Decision::Passed
        }
        _ => decision,
    };
    let past = past::signature(&inputs.signature, past_input, now, &proofs, &crypto, work)?;
    report.past = Some(past);
    report.decision = past.decision;
    report.stage = Stage::PastSignature;
    if past.decision != Decision::Passed {
        return Ok(report);
    }
    // Earlier archival proof can contradict a validity check that passed at
    // the preliminary bound, including when only delay originally failed.
    if inputs
        .current
        .signer
        .is_some_and(|signer| report.best_signature_time < signer.not_before)
    {
        report.stage = Stage::SignerValidity;
        report.decision = Decision::Finding(SubIndication::NotYetValid);
        return Ok(report);
    }
    if let Err(failure) = super::validate::timestamp_order(inputs.current.order) {
        report.stage = Stage::TimestampOrder;
        report.decision = Decision::Finding(failure.sub);
        return Ok(report);
    }
    super::admission::admit_delay(inputs.current, requirements, work)?;
    if let Err(failure) =
        super::validate::timestamp_delay(inputs.current, report.best_signature_time, requirements)
    {
        report.stage = Stage::TimestampDelay;
        report.decision = Decision::Finding(failure.sub);
        return Ok(report);
    }
    report.stage = Stage::SignatureAcceptance;
    report.decision = final_acceptance(
        inputs.current,
        report.best_signature_time,
        requirements,
        &crypto,
        work,
    )?;
    Ok(report)
}

fn final_acceptance(
    facts: &Facts<'_>,
    best: Instant,
    requirements: &Requirements<'_>,
    crypto: &poe::Crypto<'_>,
    work: &impl Work,
) -> Result<Decision, Error> {
    // §5.6.3.4 step 9(b) refers to step 7, whose past-signature process
    // returns an indication (§5.6.2.4.3). NOTE 6 identifies the acceptance
    // time as best-signature-time, the input to that process. The path's
    // separate control-time remains in PastCertificate.
    if requirements
        .elements
        .first_missing(facts.elements)
        .is_some()
    {
        return Ok(Decision::Finding(SubIndication::SigConstraintsFailure));
    }
    let value = accept(facts.materials, best, facts.content_timestamp, crypto, work)?;
    if value != Decision::Passed {
        return Ok(value);
    }
    accept(facts.signed_attribute_materials, best, None, crypto, work)
}

#[cfg(test)]
mod tests;
