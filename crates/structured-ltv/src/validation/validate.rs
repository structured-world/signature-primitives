//! The validation process of ETSI EN 319 102-1 V1.4.1, clauses 5.3.4 and
//! 5.5.4, over facts that other stages established.
//!
//! The clauses are followed in their order, which decides which of several
//! findings is the one reported. What the signature itself depends on is
//! compared with best-signature-time, the upper bound proven for it or the
//! current time where none is (5.5.4 step 1): its certificate's validity
//! and revocation and its own algorithms. What the chain depends on, the
//! anchor's trust and the algorithms of the certificates and revocation data,
//! is compared with the current time, as the basic validation of 5.5.4 step
//! 2 compares it and nothing later in the clause revisits. What held across
//! the whole interval is reported in [`Axes`] and never changes the
//! indication.

use super::Recognition as Conclusion;
use super::crypto::{Constraints, Material, Unmet};
use super::indication::{Custom, Indication, SubIndication};
use super::policy::{Element, Elements, Requirements};
use crate::pki::status::{Status, When};
use structured_pkix::temporal::{Instant, LeapTable};

/// The caller's validation-context initialization (EN 319 102-1 5.2.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// The policy was selected and its constraints were processed.
    Ready,
    /// The mapped policy document could not be obtained.
    PolicyUnavailable,
    /// The policy document could not be parsed or processed.
    PolicyProcessingError,
}

/// The certificate that authenticated one item of revocation data used by a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationIssuer {
    /// Start of its validity, inclusive (RFC 5280 4.1.2.5).
    pub not_before: Instant,
    /// End of its validity, inclusive.
    pub not_after: Instant,
}

/// Whether the signature can be processed at all (5.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Conformant enough for the cryptographic verification to run.
    Conformant,
    /// Not, so that nothing can be verified.
    Malformed,
}

/// What verifying one signed data object's hash established (5.2.7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference {
    /// The hash matches.
    Intact,
    /// The hash does not match.
    Mismatch,
    /// The signed data was not among what was supplied.
    Missing,
}

/// What verifying the signature value established (5.2.7.4 steps 3 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// It verifies under the signing certificate's key.
    Verified,
    /// It does not.
    Mismatch,
    /// Its algorithm is not one this build computes, so it was not checked.
    Unsupported,
}

/// What is proven about when the signature was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    /// The signature was made strictly after this: a timestamp over
    /// something it covers. Usually unknown.
    pub after: Option<Instant>,
    /// The signature existed by this: the earliest timestamp or other token
    /// made over it. This is best-signature-time where present.
    pub before: Option<Instant>,
}

/// The signing certificate's facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    /// Start of validity, inclusive (RFC 5280 4.1.2.5).
    pub not_before: Instant,
    /// End of validity, inclusive.
    pub not_after: Instant,
    /// What the revocation evidence says across the interval.
    pub revocation: Status,
}

/// What path validation (RFC 5280 6.1) established about one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// It validates.
    Valid,
    /// It validates and does not meet the certificate constraints (5.2.6.4
    /// step 5).
    ConstraintsFailure,
    /// It does not validate (5.2.6.4 step 4e).
    GeneralFailure,
}

/// What the trusted list says about the service a chain ends in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// Recognition at the current time, which decides the indication
    /// (5.2.6.4 step 3, with the validation time of the basic process).
    pub current: Conclusion,
    /// Recognition across the whole interval, which is reported.
    pub over_interval: Conclusion,
}

/// One certification path built for the signing certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Path<'a> {
    /// Path validation's answer.
    pub chain: Chain,
    /// The trusted list's answer about its anchor.
    pub anchor: Anchor,
    /// The revocation status of each authority between the signer and the
    /// anchor.
    pub authorities: &'a [Status],
    /// Certificates and revocation data used to validate it, judged at the
    /// current time. A proof that one existed earlier is the long-term
    /// process's to use (5.5.4 step 10 and NOTE 7, clause 5.6), which this
    /// one is not.
    pub materials: &'a [Material],
    /// Every certificate that authenticated CRL/OCSP data used by this path,
    /// including the signing certificate's revocation data. These are checked
    /// at the current validation time (EN 319 102-1 5.2.6.4 step 8).
    pub revocation_issuers: &'a [RevocationIssuer],
}

/// Whether the timestamps respect their ordering (5.5.4 step 4e).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// They do, or there is at most one.
    Coherent,
    /// A signature timestamp is not later than a content timestamp.
    Violated,
}

/// What changed in the document after the revision the signature covers,
/// as its format reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changes {
    /// The format has no later revisions to speak of.
    NotApplicable,
    /// Nothing was added after the signed revision.
    None,
    /// Later revisions only make changes the signature permits.
    Permitted,
    /// A later revision makes a change the signature does not permit.
    Unpermitted,
    /// Later revisions exist and what they change could not be determined.
    Undetermined,
}

/// Everything known about one signature.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Whether it could be processed.
    pub format: Format,
    /// Whether the caller initialized the selected validation policy.
    pub context: Context,
    /// The signing certificate, where one was identified.
    pub signer: Option<Signer>,
    /// Each signed data object, in signature order.
    pub references: &'a [Reference],
    /// The signature value.
    pub value: Value,
    /// The signature value and its signed attributes, judged at
    /// best-signature-time.
    pub materials: &'a [Material],
    /// The signature elements it carries in a form that passed their own
    /// checks, for the policy's element constraints (5.2.8.4).
    pub elements: Elements,
    /// What is proven about when it was made.
    pub time: Time,
    /// Every path built, in the order they were built.
    pub paths: &'a [Path<'a>],
    /// Whether the path builder stopped before trying every candidate.
    pub truncated: bool,
    /// Whether the timestamps are ordered.
    pub order: Order,
    /// Whether a signature time-stamp token is present. A proof supplied by
    /// the application or another kind of token does not imply this.
    pub signature_timestamp: bool,
    /// The signed claimed signing time, kept separate from proven bounds.
    pub claimed_signing_time: Option<Instant>,
    /// Caller-approved UTC corrections for the time-stamp delay calculation.
    /// Absence or insufficient coverage remains uncertainty.
    pub utc: Option<&'a LeapTable<'a>>,
    /// What changed after the signed revision. Reported as its own axis:
    /// EN 319 102-1 validates what the signature covers, and nothing after
    /// it decides the indication.
    pub changes: Changes,
    /// The current time, from the caller's clock.
    pub now: Instant,
}

/// Which validation process was used (5.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Process {
    /// Basic signatures (5.3), at the current time.
    Basic,
    /// Signatures with time (5.5), at a proven time.
    WithTime,
}

/// The fact that decided the indication, for the report to point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The signature's format.
    Format,
    /// Initialization of the selected validation policy.
    PolicyContext,
    /// The signing certificate's identification.
    SigningCertificate,
    /// A signed data object, by its index in [`Facts::references`].
    Reference(usize),
    /// The signature value.
    SignatureValue,
    /// The set of paths, none of which was built.
    Paths,
    /// One path, by index.
    Path(usize),
    /// One authority of a path.
    Authority {
        /// The path.
        path: usize,
        /// The authority's index in [`Path::authorities`].
        index: usize,
    },
    /// One piece of material used to validate a path.
    PathMaterial {
        /// The path.
        path: usize,
        /// The material's index in [`Path::materials`].
        index: usize,
    },
    /// One certificate in a path's revocation-data issuer catalogue.
    RevocationIssuer {
        /// The path.
        path: usize,
        /// The index in [`Path::revocation_issuers`].
        index: usize,
    },
    /// The signing certificate's revocation status.
    SignerRevocation,
    /// The signing certificate's validity.
    SignerValidity,
    /// One piece of the signature's own material, by index.
    Material(usize),
    /// A signature element the policy requires and the signature lacks.
    Element(Element),
    /// The timestamps.
    Timestamps,
    /// The configured delay between the claimed signing time and timestamp.
    TimestampDelay,
}

/// What the cryptographic verification found, without ranking the findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// Every hash and the signature value verified.
    Intact,
    /// A hash or the signature value did not.
    Broken,
    /// A signed data object is missing, and nothing supplied failed.
    Incomplete,
    /// The signature value could not be computed, and nothing supplied
    /// failed or was missing.
    Unsupported,
}

/// Where the interval stands against a period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The whole interval lies inside it.
    Whole,
    /// The whole interval lies outside it.
    Outside,
    /// An end is unknown, or the interval crosses the period's edge.
    Undecided,
}

/// Each property's own answer, kept separate even where an indication is
/// derived from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Axes {
    /// The cryptographic verification.
    pub integrity: Integrity,
    /// The signing certificate's validity across the whole interval.
    pub validity: Option<Coverage>,
    /// The signing certificate's revocation across the interval.
    pub revocation: Option<Status>,
    /// The anchor's recognition across the whole interval, for the path the
    /// indication was decided on.
    pub trust: Option<Conclusion>,
    /// The first constraint the signature's own material does not meet at
    /// best-signature-time, whatever decided the indication. The material of
    /// the path the indication was decided on met its constraints, or the
    /// path would not have been chosen.
    pub crypto: Option<(Basis, Unmet)>,
    /// What changed after the signed revision.
    pub changes: Changes,
}

/// The outcome for one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The main status indication.
    pub indication: Indication,
    /// Its sub-indication, absent only when it passed.
    pub sub: Option<SubIndication>,
    /// The fact that decided it, absent only when it passed.
    pub basis: Option<Basis>,
    /// The constraint not met, for the cryptographic sub-indications.
    pub unmet: Option<Unmet>,
    /// The path the decision was taken on, where one was.
    pub path: Option<usize>,
    /// The time the status was determined for (5.1.3).
    pub best_signature_time: Instant,
    /// The process used (5.1.3).
    pub process: Process,
    /// Whether the path builder stopped before trying every candidate.
    pub truncated: bool,
    /// Each property's own answer.
    pub axes: Axes,
}

/// A finding that ends the process, with what it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) sub: SubIndication,
    basis: Basis,
    unmet: Option<Unmet>,
}

impl Verdict {
    const fn on(sub: SubIndication, basis: Basis) -> Self {
        Self {
            sub,
            basis,
            unmet: None,
        }
    }
}

/// Validates one signature under `policy`.
#[must_use]
pub(super) fn compute(facts: &Facts<'_>, policy: &Requirements<'_>) -> Outcome {
    // 5.5.4 step 1: best-signature-time starts as the current time and moves
    // to the earliest proven existence.
    let best = facts.time.before.unwrap_or(facts.now);
    let constraints = policy.crypto;
    let initialized = initialize(facts.context);
    let selected = initialized.and_then(|()| select(facts, &constraints));
    // The signature's own material at best-signature-time, a content
    // timestamp proving it made after; judged once, for the decision and the
    // axis alike.
    let own = if initialized.is_ok() {
        facts
            .materials
            .iter()
            .enumerate()
            .find_map(|(index, material)| {
                constraints
                    .assess(*material, best, facts.time.after)
                    .err()
                    .map(|unmet| (Basis::Material(index), unmet))
            })
    } else {
        None
    };
    let decided = decide(facts, best, selected, own, policy, initialized);
    let path = match (decided, selected) {
        (Err(Verdict { basis, .. }), _) => match basis {
            Basis::Path(path)
            | Basis::Authority { path, .. }
            | Basis::PathMaterial { path, .. }
            | Basis::RevocationIssuer { path, .. } => Some(path),
            _ => selected.ok(),
        },
        (Ok(()), _) => selected.ok(),
    };
    let axes = Axes {
        integrity: integrity(facts),
        validity: facts.signer.map(|signer| coverage(facts.time, signer)),
        revocation: facts.signer.map(|signer| signer.revocation),
        // The path the outcome names, chosen or the last one tried.
        trust: path
            .and_then(|index| facts.paths.get(index))
            .map(|path| path.anchor.over_interval),
        crypto: own,
        changes: facts.changes,
    };
    let (indication, sub, basis, unmet) = match decided {
        Ok(()) => (Indication::TotalPassed, None, None, None),
        Err(verdict) => (
            verdict.sub.indication(),
            Some(verdict.sub),
            Some(verdict.basis),
            verdict.unmet,
        ),
    };
    Outcome {
        indication,
        sub,
        basis,
        unmet,
        path,
        best_signature_time: best,
        process: if facts.time.before.is_some() {
            Process::WithTime
        } else {
            Process::Basic
        },
        truncated: facts.truncated,
        axes,
    }
}

fn decide(
    facts: &Facts<'_>,
    best: Instant,
    selected: Result<usize, Verdict>,
    own: Option<(Basis, Unmet)>,
    policy: &Requirements<'_>,
    initialized: Result<(), Verdict>,
) -> Result<(), Verdict> {
    // 5.3.4 step 1.
    if facts.format == Format::Malformed {
        return Err(Verdict::on(SubIndication::FormatFailure, Basis::Format));
    }
    // 5.3.4 step 2.
    let Some(signer) = facts.signer else {
        return Err(Verdict::on(
            SubIndication::NoSigningCertificateFound,
            Basis::SigningCertificate,
        ));
    };
    // EN 319 102-1 V1.4.1 5.3.4 step 3, before cryptographic verification.
    initialized?;
    // 5.3.4 step 5: a cryptographic verification that did not pass is
    // reported whatever the certificate validation found.
    verify(facts)?;
    // 5.3.4 step 4, with the comparisons of 5.5.4 step 4.
    selected?;
    certificate(facts, signer, best)?;
    // 5.5.4 step 4c, and steps 8 and 9, and 5.3.4 step 6: the signature's own
    // material at best-signature-time, before the order of step 4e.
    if let Some((basis, unmet)) = own {
        return Err(crypto(unmet, basis));
    }
    // 5.3.4 step 6 and 5.2.8.4: a required element missing or malformed is
    // SIG_CONSTRAINTS_FAILURE, which 5.5.4 step 2 returns before step 4e.
    if let Some(element) = policy.elements.first_missing(facts.elements) {
        return Err(Verdict::on(
            SubIndication::SigConstraintsFailure,
            Basis::Element(element),
        ));
    }
    timestamp_order(facts.order)?;
    timestamp_delay(facts, best, policy)
}

// EN 319 102-1 V1.4.1 5.5.4 step 4e also applies to timestamps retained
// when past validation lets a signature reach the final time checks.
pub(super) fn timestamp_order(order: Order) -> Result<(), Verdict> {
    match order {
        Order::Coherent => Ok(()),
        Order::Violated => Err(Verdict::on(
            SubIndication::TimestampOrderFailure,
            Basis::Timestamps,
        )),
    }
}

/// EN 319 102-1 V1.4.1 5.2.4.4: acquisition/parsing is the caller's job;
/// failure to initialize constraints must not validate under another policy.
fn initialize(context: Context) -> Result<(), Verdict> {
    let sub = match context {
        Context::Ready => return Ok(()),
        Context::PolicyUnavailable => SubIndication::SignaturePolicyNotAvailable,
        Context::PolicyProcessingError => SubIndication::PolicyProcessingError,
    };
    Err(Verdict::on(sub, Basis::PolicyContext))
}

/// EN 319 102-1 V1.4.1 5.5.4 step 5 follows timestamp ordering. A claim
/// remains a claim: it never becomes best-signature-time or a proven bound.
pub(super) fn timestamp_delay(
    facts: &Facts<'_>,
    best: Instant,
    policy: &Requirements<'_>,
) -> Result<(), Verdict> {
    if !facts.signature_timestamp {
        return Ok(());
    }
    let Some(delay) = policy.timestamp_delay else {
        return Ok(());
    };
    let failure = Verdict::on(SubIndication::SigConstraintsFailure, Basis::TimestampDelay);
    let Some(claimed) = facts.claimed_signing_time else {
        return Err(failure);
    };
    let uncertain = Verdict::on(
        SubIndication::Custom(Custom::TimeUncertain),
        Basis::TimestampDelay,
    );
    let table = facts.utc.ok_or(uncertain)?;
    let nanos = i128::from(delay.as_secs()) * 1_000_000_000 + i128::from(delay.subsec_nanos());
    // Reuse the shared elapsed-time arithmetic; POSIX addition would erase
    // an inserted second. Missing coverage cannot become a constraint pass.
    let limit = table.shift(claimed, nanos).map_err(|_| uncertain)?;
    // Also establish that the compared timestamp lies in the supplied UTC
    // coverage (including whether a leap label actually exists).
    table.shift(best, 0).map_err(|_| uncertain)?;
    if limit > best { Ok(()) } else { Err(failure) }
}

/// The cryptographic verification building block (5.2.7.4): signed data
/// first, then the hashes, then the signature value.
fn verify(facts: &Facts<'_>) -> Result<(), Verdict> {
    if let Some(index) = facts
        .references
        .iter()
        .position(|reference| *reference == Reference::Missing)
    {
        return Err(Verdict::on(
            SubIndication::SignedDataNotFound,
            Basis::Reference(index),
        ));
    }
    if let Some(index) = facts
        .references
        .iter()
        .position(|reference| *reference == Reference::Mismatch)
    {
        return Err(Verdict::on(
            SubIndication::HashFailure,
            Basis::Reference(index),
        ));
    }
    match facts.value {
        Value::Verified => Ok(()),
        Value::Mismatch => Err(Verdict::on(
            SubIndication::SigCryptoFailure,
            Basis::SignatureValue,
        )),
        // The value was never computed: not a failure of the signature, and
        // not a fact Table 6 names.
        Value::Unsupported => Err(Verdict::on(
            SubIndication::Custom(Custom::UnsupportedAlgorithm),
            Basis::SignatureValue,
        )),
    }
}

/// 5.2.6.4 over the built paths: the first path that passes or returns a
/// terminal signer finding is
/// used, and if none does, the status of the last one tried is reported
/// (step 2a).
fn select(facts: &Facts<'_>, constraints: &Constraints<'_>) -> Result<usize, Verdict> {
    let mut status = Verdict::on(SubIndication::NoCertificateChainFound, Basis::Paths);
    for (index, path) in facts.paths.iter().enumerate() {
        match judge(index, path, facts.signer, facts.now, constraints) {
            Ok(()) => return Ok(index),
            Err(verdict) => status = verdict,
        }
    }
    Err(status)
}

fn judge(
    index: usize,
    path: &Path<'_>,
    signer: Option<Signer>,
    now: Instant,
    constraints: &Constraints<'_>,
) -> Result<(), Verdict> {
    // Steps 2 and 3 decide whether the chain reaches an anchor trusted at the
    // validation time before step 4 validates it.
    anchor(path.anchor.current).map_err(|sub| Verdict::on(sub, Basis::Path(index)))?;
    if path.chain == Chain::GeneralFailure {
        return Err(Verdict::on(
            SubIndication::CertificateChainGeneralFailure,
            Basis::Path(index),
        ));
    }
    for (position, status) in path.authorities.iter().enumerate() {
        authority(*status).map_err(|sub| {
            Verdict::on(
                sub,
                Basis::Authority {
                    path: index,
                    index: position,
                },
            )
        })?;
    }
    // EN 319 102-1 V1.4.1 5.2.6.4 step 4b/c returns this chain for a
    // revoked or held signer, before steps 5-8. Select it for certificate()
    // to report that terminal finding; this does not accept its later limits.
    if let Some(signer) = signer
        && matches!(
            signer.revocation,
            Status::Revoked { .. } | Status::OnHold { .. } | Status::NotIssued { .. }
        )
    {
        return Ok(());
    }
    if path.chain == Chain::ConstraintsFailure {
        return Err(Verdict::on(
            SubIndication::ChainConstraintsFailure,
            Basis::Path(index),
        ));
    }
    // 5.2.6.4 step 6 and 5.5.4 step 10, at the current time. Both clauses
    // name CRYPTO_CONSTRAINTS_FAILURE_NO_POE for this material, whatever the
    // shortfall: nothing here proves when it was made.
    for (position, material) in path.materials.iter().enumerate() {
        constraints
            .assess(*material, now, None)
            .map_err(|unmet| Verdict {
                sub: SubIndication::CryptoConstraintsFailureNoPoe,
                basis: Basis::PathMaterial {
                    path: index,
                    index: position,
                },
                unmet: Some(unmet),
            })?;
    }
    // EN 319 102-1 V1.4.1 5.2.6.4 step 7 returns this chain before
    // inspecting the revocation-data issuers. Apply the final indication
    // in certificate(), where 5.5.4 can reconsider it using a time proof.
    if let Some(signer) = signer
        && (now < signer.not_before || now > signer.not_after)
    {
        return Ok(());
    }
    // EN 319 102-1 V1.4.1 5.2.6.4 step 8: the revocation-data issuer's
    // certificate must be valid at validation time, including both endpoints.
    for (position, issuer) in path.revocation_issuers.iter().enumerate() {
        if now < issuer.not_before || now > issuer.not_after {
            return Err(Verdict::on(
                SubIndication::RevocationOutOfBoundsNoPoe,
                Basis::RevocationIssuer {
                    path: index,
                    index: position,
                },
            ));
        }
    }
    Ok(())
}

/// A shortfall of the signature's own material as its sub-indication: the
/// outright failure where a content timestamp proves it made when the
/// mechanism was not reliable (5.3.4 step 6), the `_NO_POE` form otherwise
/// (5.2.8.4.1).
fn crypto(unmet: Unmet, basis: Basis) -> Verdict {
    Verdict {
        sub: if unmet.proven_after {
            SubIndication::CryptoConstraintsFailure
        } else {
            SubIndication::CryptoConstraintsFailureNoPoe
        },
        basis,
        unmet: Some(unmet),
    }
}

/// Whether the anchor counts as trusted at the current time.
///
/// A path reaches an anchor the trusted list binds; one that reached no
/// listed anchor is not a candidate path at all and is not supplied.
fn anchor(conclusion: Conclusion) -> Result<(), SubIndication> {
    match conclusion {
        Conclusion::Recognized => Ok(()),
        // Listed, with no rule that makes it a trust anchor.
        Conclusion::NoRule => Err(SubIndication::NoCertificateChainFound),
        // Listed and not trusted now, which this process cannot place the
        // signing time against (5.2.6.4 steps 1a and 3).
        Conclusion::NotRecognized
        | Conclusion::OutsideValidity
        | Conclusion::Mixed
        | Conclusion::UnknownTime
        | Conclusion::ClaimedTime
        | Conclusion::UpperBoundOnly
        | Conclusion::LowerBoundOnly => Err(SubIndication::NoCertificateChainFoundNoPoe),
        Conclusion::IncompleteHistory => Err(SubIndication::Custom(Custom::TrustHistoryIncomplete)),
        Conclusion::ConflictingHistory => {
            Err(SubIndication::Custom(Custom::TrustHistoryConflicting))
        }
        Conclusion::UnsupportedConditions => {
            Err(SubIndication::Custom(Custom::TrustConditionsUnsupported))
        }
    }
}

/// An authority's revocation (5.2.6.4 steps 4a and 4d, 5.5.4 step 4a). The
/// evidence already compared any revocation with the interval, so one that
/// is still reported revoked was not provably after the signature.
fn authority(status: Status) -> Result<(), SubIndication> {
    match status {
        Status::NotRevoked { .. } => Ok(()),
        Status::Revoked { .. } => Err(SubIndication::RevokedCaNoPoe),
        other => pending(other),
    }
}

/// A revocation status that neither clears nor revokes.
fn pending(status: Status) -> Result<(), SubIndication> {
    match status {
        // RFC 6960 2.2 requires rejection, not a retry after certificateHold.
        // Table 6 CUSTOM retains this cause without inventing a revocation date.
        Status::NotIssued { .. } => Err(SubIndication::Custom(Custom::CertificateNotIssued)),
        Status::NotRevoked { .. } => Ok(()),
        // 5.2.6.4 steps 4a and 4c, 5.5.4 steps 6 and 7.
        Status::OnHold { .. } | Status::NotFresh { .. } | Status::NoEvidence => {
            Err(SubIndication::TryLater)
        }
        Status::Revoked { .. } => Err(SubIndication::RevokedNoPoe),
        Status::Unknown { .. } => Err(SubIndication::Custom(Custom::RevocationUnknown)),
        Status::Conflict { .. } => Err(SubIndication::Custom(Custom::RevocationConflict)),
        Status::PartialReasons { .. } => {
            Err(SubIndication::Custom(Custom::RevocationReasonsUncovered))
        }
        Status::HeldOrRevoked { .. } => Err(SubIndication::Custom(Custom::RevocationHeldOrRevoked)),
        Status::Uncertain(_) => Err(SubIndication::Custom(Custom::TimeUncertain)),
    }
}

/// The signing certificate at best-signature-time (5.2.6.4 steps 4b and 7,
/// 5.3.4 step 4, 5.5.4 steps 4a, 4b and 4d).
fn certificate(facts: &Facts<'_>, signer: Signer, best: Instant) -> Result<(), Verdict> {
    let revocation = |sub| Verdict::on(sub, Basis::SignerRevocation);
    let validity = |sub| Verdict::on(sub, Basis::SignerValidity);
    match signer.revocation {
        Status::NotIssued { .. } => {
            return Err(revocation(SubIndication::Custom(
                Custom::CertificateNotIssued,
            )));
        }
        // Revoked before the signature is proven made: the content timestamp
        // is after the revocation (5.3.4 step 4).
        Status::Revoked {
            when: When::Before, ..
        } => return Err(revocation(SubIndication::Revoked)),
        // Revoked, and not provably after best-signature-time (5.5.4 step
        // 4a.b).
        Status::Revoked { .. } => return Err(revocation(SubIndication::RevokedNoPoe)),
        // EN 319 102-1 V1.4.1 5.2.6.4 step 4c precedes the validity
        // comparison of step 7, just as signer revocation does.
        Status::OnHold { .. } => return Err(revocation(SubIndication::TryLater)),
        _ => {}
    }
    // EN 319 102-1 V1.4.1 5.5.4 step 4b/d requires proof the signature
    // already existed before issuance. The current time is not that proof.
    if best < signer.not_before && facts.time.before.is_some() {
        return Err(validity(SubIndication::NotYetValid));
    }
    // A content timestamp at or after notAfter proves the signature made
    // after the certificate expired (5.3.4 step 4).
    if facts
        .time
        .after
        .is_some_and(|after| after >= signer.not_after)
    {
        return Err(validity(SubIndication::Expired));
    }
    let not_revoked = matches!(signer.revocation, Status::NotRevoked { .. });
    let outside_now = facts.now < signer.not_before || facts.now > signer.not_after;
    // Step 4d recovers a step-7 result only when revocation is clear and the
    // proof predates expiration. Step 4b leaves OUT_OF_BOUNDS_NO_POE intact
    // unless the proof places the signature before issuance.
    if best < signer.not_before
        || best > signer.not_after
        || (outside_now && (!not_revoked || best == signer.not_after))
    {
        return Err(validity(if not_revoked {
            SubIndication::OutOfBoundsNotRevoked
        } else {
            SubIndication::OutOfBoundsNoPoe
        }));
    }
    pending(signer.revocation).map_err(revocation)
}

fn integrity(facts: &Facts<'_>) -> Integrity {
    if facts.value == Value::Mismatch || facts.references.contains(&Reference::Mismatch) {
        Integrity::Broken
    } else if facts.references.contains(&Reference::Missing) {
        Integrity::Incomplete
    } else if facts.value == Value::Unsupported {
        Integrity::Unsupported
    } else {
        Integrity::Intact
    }
}

/// The interval against the certificate's validity, closed at both ends.
fn coverage(time: Time, signer: Signer) -> Coverage {
    let (from, until) = (signer.not_before, signer.not_after);
    // Ends that cross prove no interval at all.
    if let (Some(after), Some(before)) = (time.after, time.before)
        && after >= before
    {
        return Coverage::Undecided;
    }
    if time.before.is_some_and(|before| before < from)
        || time.after.is_some_and(|after| after >= until)
    {
        return Coverage::Outside;
    }
    match (time.after, time.before) {
        // Made strictly after `after`, so `after` itself may equal `from`.
        (Some(after), Some(before)) if from <= after && before <= until => Coverage::Whole,
        _ => Coverage::Undecided,
    }
}

#[cfg(test)]
mod tests;
