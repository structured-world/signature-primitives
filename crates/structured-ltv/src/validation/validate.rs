//! The validation process of ETSI EN 319 102-1 V1.4.1, clauses 5.3.4 and
//! 5.5.4, over facts that other stages established.
//!
//! The clauses are followed in their order, which decides which of several
//! findings is reported. Basic validation assesses the chain and signature
//! at current time. The with-time process keeps that decision until a clause
//! 5.5.4 recovery rule applies at the earliest proven signature time. Path
//! material is assessed at current time. [`Axes`] separately describes the
//! evidence across the whole interval.

use super::Recognition as Conclusion;
use super::crypto::{Constraints, Material, Unmet};
use super::indication::{Custom, Indication, SubIndication};
use super::policy::{Element, Elements, Requirements};
use crate::pki::status::{ExpiryEvidence, Status};
use structured_asn1::memory::{MemoryError, Work};
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
    /// Verification needs inherited key parameters from a certification chain.
    NeedsChain,
}

/// Format-established outcome for one original signature timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureTimestamp {
    /// The imprint did not bind this signature, and the token is discarded.
    ImprintMismatch,
    /// The token validated and proves signature existence by this instant.
    Passed(Instant),
    /// The bound token failed its validation.
    Finding {
        /// The token's validation finding.
        sub: SubIndication,
        /// Whether the selected constraints mandate its validity.
        required: bool,
    },
}

/// Status evidence to re-evaluate at best-signature-time (5.5.4 steps 6 and 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationRetry {
    /// The status was stale at the original check time.
    Freshness {
        /// Exclusive upper bound supplied by the selected freshness rule.
        fresh_before: Option<Instant>,
        /// Next update or equivalent retry suggestion.
        retry_at: Option<Instant>,
    },
    /// The signer was suspended at the original check time.
    Suspension {
        /// Beginning of the authenticated suspension.
        from: Instant,
        /// Next update or equivalent retry suggestion.
        retry_at: Option<Instant>,
    },
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
    /// Separate support for non-revocation once the signer has expired.
    pub expiry_evidence: ExpiryEvidence,
}

/// What path validation (RFC 5280 6.1) established about one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// The signer itself is the selected anchor, and local policy permits
    /// direct signer trust. Recognition at the validation time is still required.
    DirectTrust,
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
    /// Evidence belonging to this path's current `TRY_LATER` result.
    pub revocation_retry: Option<RevocationRetry>,
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
    /// current time during basic validation and best-signature-time later.
    /// This slice holds the signature value's own mechanisms.
    pub materials: &'a [Material],
    /// Independent cryptography used by signed attributes.
    pub signed_attribute_materials: &'a [Material],
    /// The signature elements it carries in a form that passed their own
    /// checks, for the policy's element constraints (5.2.8.4).
    pub elements: Elements,
    /// What is proven about when it was made.
    pub time: Time,
    /// Authenticated lower generation bound of a content timestamp
    /// for EN 319 102-1 §5.3.4 steps 4 and 6.
    pub content_timestamp: Option<Instant>,
    /// Every path built, in the order they were built.
    pub paths: &'a [Path<'a>],
    /// Whether the path builder stopped before trying every candidate.
    pub truncated: bool,
    /// Whether the timestamps are ordered.
    pub order: Order,
    /// Whether a signature time-stamp token is present. A proof supplied by
    /// the application or another kind of token does not imply this.
    pub signature_timestamp: bool,
    /// Individual signature timestamp results, in source order.
    pub signature_timestamps: &'a [SignatureTimestamp],
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

impl Facts<'_> {
    pub(super) fn has_signature_timestamp(&self) -> bool {
        self.signature_timestamp || !self.signature_timestamps.is_empty()
    }
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
    /// Material index into the signature value slice followed by the
    /// signed-attribute slice.
    Material(usize),
    /// A signature element the policy requires and the signature lacks.
    Element(Element),
    /// The timestamps.
    Timestamps,
    /// Original signature timestamp by index.
    SignatureTimestamp(usize),
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
    /// Evaluation time of that constraint.
    pub crypto_at: Option<Instant>,
    /// All unmet element constraints when signature elements decided the result.
    pub missing_elements: Elements,
    /// The path the decision was taken on, where one was.
    pub path: Option<usize>,
    /// The time the status was determined for (5.1.3).
    pub best_signature_time: Instant,
    /// The process used (5.1.3).
    pub process: Process,
    /// Whether the path builder stopped before trying every candidate.
    pub truncated: bool,
    /// An evidence-supplied time to retry the deciding revocation check.
    pub retry_at: Option<Instant>,
    /// Each property's own answer.
    pub axes: Axes,
}

/// A finding that ends the process, with what it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) sub: SubIndication,
    basis: Basis,
    unmet: Option<Unmet>,
    crypto_at: Option<Instant>,
    retry_at: Option<Instant>,
}

impl Verdict {
    const fn on(sub: SubIndication, basis: Basis) -> Self {
        Self {
            sub,
            basis,
            unmet: None,
            crypto_at: None,
            retry_at: None,
        }
    }

    const fn path(self) -> Option<usize> {
        match self.basis {
            Basis::Path(path)
            | Basis::Authority { path, .. }
            | Basis::PathMaterial { path, .. }
            | Basis::RevocationIssuer { path, .. } => Some(path),
            _ => None,
        }
    }

    fn bind_revocation_retry(
        &mut self,
        paths: &[Path<'_>],
        selected: Option<usize>,
    ) -> Option<RevocationRetry> {
        if self.sub != SubIndication::TryLater {
            return None;
        }
        let retry = paths[self.path().or(selected)?].revocation_retry?;
        self.retry_at = match retry {
            RevocationRetry::Freshness { retry_at, .. }
            | RevocationRetry::Suspension { retry_at, .. } => retry_at,
        };
        Some(retry)
    }
}

/// Validates one signature under `policy`.
#[must_use]
pub(super) fn compute(facts: &Facts<'_>, policy: &Requirements<'_>) -> Outcome {
    // 5.5.4 step 1: best-signature-time starts as the current time and moves
    // to the earliest proven existence.
    let mut best = facts.time.before.map_or(facts.now, |at| at.min(facts.now));
    let constraints = policy.crypto;
    let initialized = initialize(facts.context);
    let selected = initialized.and_then(|()| select(facts, &constraints));
    let decided = decide(facts, &mut best, selected, policy, initialized);
    let own = if initialized.is_ok() && decided.is_err() {
        own_failure(facts, best, &constraints).map(|(index, unmet)| (Basis::Material(index), unmet))
    } else {
        None
    };
    let path = decided
        .err()
        .and_then(Verdict::path)
        .or_else(|| match selected {
            Ok(path) => Some(path),
            Err(verdict) => verdict.path(),
        });
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
    let (indication, sub, basis, unmet, crypto_at, retry_at) = match decided {
        Ok(()) => (Indication::TotalPassed, None, None, None, None, None),
        Err(verdict) => (
            verdict.sub.indication(),
            Some(verdict.sub),
            Some(verdict.basis),
            verdict.unmet,
            verdict.crypto_at,
            verdict.retry_at,
        ),
    };
    Outcome {
        indication,
        sub,
        basis,
        unmet,
        crypto_at,
        // EN 319 102-1 Table 6 requests the set of unsatisfied elements.
        missing_elements: if matches!(basis, Some(Basis::Element(_))) {
            policy.elements.missing_from(facts.elements)
        } else {
            Elements::NONE
        },
        path,
        best_signature_time: best,
        process: if with_time(facts) {
            Process::WithTime
        } else {
            Process::Basic
        },
        truncated: facts.truncated,
        retry_at,
        axes,
    }
}

pub(super) fn visit_findings(
    facts: &Facts<'_>,
    policy: &Requirements<'_>,
    result: &Outcome,
    execution: &impl Work,
    mut visit: impl FnMut(Basis, Unmet),
) -> Result<(), MemoryError> {
    let (Some(at), Some(basis)) = (result.crypto_at, result.basis) else {
        return Ok(());
    };
    let (value, attributes) = match basis {
        Basis::Material(_) => (facts.materials, facts.signed_attribute_materials),
        Basis::PathMaterial { path, .. } => (facts.paths[path].materials, &[][..]),
        _ => return Ok(()),
    };
    let count = (value.len() as u64)
        .checked_add(attributes.len() as u64)
        .ok_or(MemoryError::WorkExceeded)?;
    let cost = super::admission::material_cost(&policy.crypto, execution)?;
    execution.charge_work(count.checked_mul(cost).ok_or(MemoryError::WorkExceeded)?)?;
    for (index, &material) in value.iter().chain(attributes).enumerate() {
        let (source, lower) = match basis {
            Basis::PathMaterial { path, .. } => (Basis::PathMaterial { path, index }, None),
            _ => (Basis::Material(index), content_bound(facts, index)),
        };
        policy
            .crypto
            .inspect(material, at, lower, |unmet| visit(source, unmet));
    }
    Ok(())
}

fn decide(
    facts: &Facts<'_>,
    best: &mut Instant,
    selected: Result<usize, Verdict>,
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
    // EN 319 102-1 V1.4.1 §5.3.4 step 4 returns before cryptography
    // when key extraction needs the missing chain (e.g. inherited DSA).
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf#page=58
    if facts.value == Value::NeedsChain
        && let Err(verdict) = selected
        && verdict.sub == SubIndication::NoCertificateChainFound
    {
        return Err(verdict);
    }
    // §5.3.4 step 5 gives all other verification failures precedence.
    verify(facts)?;
    let mut basic = selected
        .and_then(|index| {
            if facts.paths[index].chain == Chain::DirectTrust {
                return Ok(());
            }
            basic_certificate(facts, signer)
        })
        .and_then(|()| acceptance(facts, facts.now, policy))
        .and_then(|()| elements(facts, policy));
    // EN 319 102-1 V1.4.1 §5.2.6.4 step 4 and §5.5.4 steps 6–7:
    // retry facts belong to the original revocation finding of this path.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf#page=63
    let basic_retry = basic
        .as_mut()
        .err()
        .and_then(|verdict| verdict.bind_revocation_retry(facts.paths, selected.ok()));
    if !with_time(facts) {
        return basic;
    }
    // EN 319 102-1 V1.4.1 §5.5.4 steps 2 to 4 preserve the basic
    // finding until the corresponding temporal rule explicitly recovers it.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf#page=62
    if let Err(verdict) = basic
        && !matches!(
            verdict.sub,
            SubIndication::CryptoConstraintsFailureNoPoe
                | SubIndication::RevokedNoPoe
                | SubIndication::RevokedCaNoPoe
                | SubIndication::TryLater
                | SubIndication::OutOfBoundsNoPoe
                | SubIndication::OutOfBoundsNotRevoked
        )
    {
        return Err(verdict);
    }
    let mut proved = facts.time.before.is_some_and(|bound| bound <= facts.now);
    for (index, token) in facts.signature_timestamps.iter().enumerate() {
        // §5.5.4 step 3(a) discards imprint mismatches before step 3(b)
        // enforces validity of the remaining required timestamps.
        match *token {
            SignatureTimestamp::Passed(bound) => {
                *best = (*best).min(bound);
                proved = true;
            }
            SignatureTimestamp::Finding {
                sub,
                required: true,
            } => {
                return Err(Verdict::on(sub, Basis::SignatureTimestamp(index)));
            }
            SignatureTimestamp::ImprintMismatch
            | SignatureTimestamp::Finding {
                required: false, ..
            } => {}
        }
    }
    let path = compare_times(facts, signer, *best, proved, selected, basic, policy)?;
    timestamp_order(facts.order)?;
    timestamp_delay(facts, *best, policy)?;
    if let Err(verdict) = basic
        && verdict.sub == SubIndication::TryLater
    {
        // §5.5.4 steps 6 and 7 use the exact freshness or suspension facts.
        let recovered = match basic_retry {
            Some(RevocationRetry::Freshness { fresh_before, .. }) => {
                fresh_before.is_some_and(|end| *best < end)
            }
            Some(RevocationRetry::Suspension { from, .. }) => *best < from,
            None => false,
        };
        if !recovered {
            return Err(verdict);
        }
    }
    let recovered = matches!(basic, Err(verdict) if matches!(verdict.sub,
        SubIndication::TryLater | SubIndication::RevokedCaNoPoe | SubIndication::RevokedNoPoe
    ));
    if let Err(verdict) = basic
        && recovered
    {
        // §5.5.4 steps 4(a), 6 and 7 recover the named temporal finding.
        // They do not establish status for any other path member.
        recovered_path(path, facts, signer, *best, verdict)?;
    }
    // §§5.5.4 steps 8 to 10 reapply own crypto at best time and path
    // crypto at current time, including a path recovered from revocation.
    if *best != facts.now || basic.is_err() {
        acceptance(facts, *best, policy)?;
        elements(facts, policy)?;
    }
    if recovered {
        path_crypto(path, &facts.paths[path], facts.now, &policy.crypto)?;
        issuer_validity(path, &facts.paths[path], facts.now)?;
    }
    Ok(())
}

fn recovered_path(
    path: usize,
    facts: &Facts<'_>,
    signer: Signer,
    best: Instant,
    original: Verdict,
) -> Result<(), Verdict> {
    let selected = &facts.paths[path];
    for (index, &status) in selected.authorities.iter().enumerate() {
        let basis = Basis::Authority { path, index };
        if original.sub == SubIndication::TryLater && original.basis == basis {
            continue;
        }
        authority(status, best).map_err(|sub| Verdict::on(sub, basis))?;
    }
    // EN 319 102-1 V1.4.1 §5.2.6.4 steps 4(b) to 5 still apply
    // after clearing the particular failure under §5.5.4.
    let resumed_signer_status = original.sub == SubIndication::TryLater
        && matches!(original.basis, Basis::SignerRevocation | Basis::Path(_));
    if !resumed_signer_status {
        signer_status_at(signer.revocation, best, facts.content_timestamp)?;
    }
    if best < signer.not_before || best > signer.not_after {
        return Err(Verdict::on(
            if best < signer.not_before && best < facts.now {
                SubIndication::NotYetValid
            } else {
                outside_validity(signer, best)
            },
            Basis::SignerValidity,
        ));
    }
    chain_constraints(path, selected)
}

fn with_time(facts: &Facts<'_>) -> bool {
    facts.time.before.is_some() || facts.has_signature_timestamp()
}

fn own_failure(
    facts: &Facts<'_>,
    at: Instant,
    constraints: &Constraints<'_>,
) -> Option<(usize, Unmet)> {
    facts
        .materials
        .iter()
        .chain(facts.signed_attribute_materials)
        .enumerate()
        .find_map(|(index, material)| {
            // §5.3.4 step 6 upgrades only the signature value's own failure.
            let lower = content_bound(facts, index);
            constraints
                .assess(*material, at, lower)
                .err()
                .map(|unmet| (index, unmet))
        })
}

fn content_bound(facts: &Facts<'_>, index: usize) -> Option<Instant> {
    if index < facts.materials.len() {
        facts.content_timestamp
    } else {
        None
    }
}

fn acceptance(facts: &Facts<'_>, at: Instant, policy: &Requirements<'_>) -> Result<(), Verdict> {
    if let Some((index, unmet)) = own_failure(facts, at, &policy.crypto) {
        return Err(crypto(unmet, Basis::Material(index), at));
    }
    Ok(())
}

fn elements(facts: &Facts<'_>, policy: &Requirements<'_>) -> Result<(), Verdict> {
    if let Some(element) = policy.elements.first_missing(facts.elements) {
        return Err(Verdict::on(
            SubIndication::SigConstraintsFailure,
            Basis::Element(element),
        ));
    }
    Ok(())
}

fn compare_times(
    facts: &Facts<'_>,
    signer: Signer,
    best: Instant,
    proved: bool,
    selected: Result<usize, Verdict>,
    basic: Result<(), Verdict>,
    policy: &Requirements<'_>,
) -> Result<usize, Verdict> {
    use SubIndication as Sub;
    let not_yet = Verdict::on(Sub::NotYetValid, Basis::SignerValidity);
    let out_of_bounds = Verdict::on(outside_validity(signer, best), Basis::SignerValidity);
    let direct_trust = selected.is_ok_and(|index| facts.paths[index].chain == Chain::DirectTrust);
    match basic {
        Ok(()) => {
            if !direct_trust && best < signer.not_before {
                return Err(not_yet);
            }
        }
        Err(verdict) => match verdict.sub {
            Sub::RevokedNoPoe | Sub::RevokedCaNoPoe => {
                let revoked = match verdict.basis {
                    Basis::Authority { path, index } => {
                        revocation(facts.paths[path].authorities[index])
                    }
                    _ => revocation(signer.revocation),
                };
                if revoked.is_none_or(|at| at <= best) {
                    return Err(verdict);
                }
                if best < signer.not_before {
                    return Err(not_yet);
                }
                if best >= signer.not_after {
                    return Err(out_of_bounds);
                }
                if let Basis::Authority { path, .. } | Basis::Path(path) = verdict.basis {
                    return Ok(path);
                }
            }
            Sub::OutOfBoundsNoPoe | Sub::OutOfBoundsNotRevoked => {
                // EN 319 102-1 §5.5.4 steps 4(b) and 4(d): a failed
                // optional token does not prove existence before issuance.
                if best < signer.not_before {
                    return Err(if proved { not_yet } else { verdict });
                }
                if verdict.sub == Sub::OutOfBoundsNoPoe || best >= signer.not_after {
                    return Err(verdict);
                }
            }
            Sub::CryptoConstraintsFailureNoPoe if matches!(verdict.basis, Basis::Material(_)) => {
                acceptance(facts, best, policy)?;
                // §5.5.4 step 4(c) recovers algorithm acceptance. The
                // earlier proof still has to satisfy the issuance boundary
                // from step 4(b) before it can support the signature.
                if !direct_trust && best < signer.not_before {
                    return Err(not_yet);
                }
            }
            Sub::TryLater => {
                if let Basis::Authority { path, .. } | Basis::Path(path) = verdict.basis {
                    return Ok(path);
                }
            }
            _ => return Err(verdict),
        },
    }
    selected
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
    if !facts.has_signature_timestamp() {
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
        Value::Unsupported | Value::NeedsChain => Err(Verdict::on(
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
    // EN 319 102-1 §5.2.6.4 step 1: direct trust precedes ordinary
    // path processing. Sunset falls through to alternate candidates.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf#page=52
    for (index, path) in facts.paths.iter().enumerate() {
        if path.chain == Chain::DirectTrust {
            match anchor(path.anchor.current) {
                Ok(()) => return Ok(index),
                Err(sub) => status = Verdict::on(sub, Basis::Path(index)),
            }
        }
    }
    for (index, path) in facts.paths.iter().enumerate() {
        if path.chain == Chain::DirectTrust {
            continue;
        }
        match judge(index, path, facts.signer, facts.now, constraints) {
            Ok(()) => return Ok(index),
            // §5.2.6.4 step 8 returns the validated chain and this status.
            Err(verdict) if verdict.sub == SubIndication::RevocationOutOfBoundsNoPoe => {
                return Err(verdict);
            }
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
        authority(*status, now).map_err(|sub| {
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
        && (revocation(signer.revocation).is_some_and(|at| at <= now)
            || matches!(
                signer.revocation,
                Status::OnHold { .. } | Status::NotIssued { .. }
            ))
    {
        return Ok(());
    }
    if let Some(signer) = signer {
        match signer.revocation {
            Status::NotFresh { .. } | Status::NoEvidence => {
                return pending(signer.revocation)
                    .map_err(|sub| Verdict::on(sub, Basis::Path(index)));
            }
            _ => {}
        }
    }
    chain_constraints(index, path)?;
    // 5.2.6.4 step 6 and 5.5.4 step 10, at the current time. Both clauses
    // name CRYPTO_CONSTRAINTS_FAILURE_NO_POE for this material, whatever the
    // shortfall: nothing here proves when it was made.
    path_crypto(index, path, now, constraints)?;
    // EN 319 102-1 V1.4.1 5.2.6.4 step 7 returns this chain before
    // inspecting the revocation-data issuers. Apply the final indication
    // in certificate(), where 5.5.4 can reconsider it using a time proof.
    if let Some(signer) = signer
        && (now < signer.not_before || now > signer.not_after)
    {
        return Ok(());
    }
    issuer_validity(index, path, now)
}

fn chain_constraints(index: usize, path: &Path<'_>) -> Result<(), Verdict> {
    if path.chain == Chain::ConstraintsFailure {
        return Err(Verdict::on(
            SubIndication::ChainConstraintsFailure,
            Basis::Path(index),
        ));
    }
    Ok(())
}

fn issuer_validity(index: usize, path: &Path<'_>, now: Instant) -> Result<(), Verdict> {
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

fn path_crypto(
    index: usize,
    path: &Path<'_>,
    now: Instant,
    constraints: &Constraints<'_>,
) -> Result<(), Verdict> {
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
                crypto_at: Some(now),
                retry_at: None,
            })?;
    }
    Ok(())
}

/// A shortfall of the signature's own material as its sub-indication: the
/// outright failure where a content timestamp proves it made when the
/// mechanism was not reliable (5.3.4 step 6), the `_NO_POE` form otherwise
/// (5.2.8.4.1).
fn crypto(unmet: Unmet, basis: Basis, at: Instant) -> Verdict {
    Verdict {
        sub: if unmet.proven_after {
            SubIndication::CryptoConstraintsFailure
        } else {
            SubIndication::CryptoConstraintsFailureNoPoe
        },
        basis,
        unmet: Some(unmet),
        crypto_at: Some(at),
        retry_at: None,
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
fn authority(status: Status, now: Instant) -> Result<(), SubIndication> {
    if revocation(status).is_some_and(|at| at <= now) {
        return Err(SubIndication::RevokedCaNoPoe);
    }
    match status {
        Status::NotRevoked { .. } | Status::Revoked { .. } => Ok(()),
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
        Status::OnHold { .. } | Status::NotFresh { .. } => Err(SubIndication::TryLater),
        // EN 319 102-1 §5.2.6.4 step 4(e): no usable status is a general
        // chain failure. Step 4(a) needs an available, insufficiently fresh source.
        Status::NoEvidence => Err(SubIndication::CertificateChainGeneralFailure),
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

fn revocation(status: Status) -> Option<Instant> {
    match status {
        Status::Revoked { revoked, .. }
        | Status::NotRevoked {
            later: Some(revoked),
            ..
        } => Some(revoked.at.instant()),
        _ => None,
    }
}

/// Basic X.509 result and content-timestamp upgrades (§5.3.4 step 4).
fn basic_certificate(facts: &Facts<'_>, signer: Signer) -> Result<(), Verdict> {
    let validity = |sub| Verdict::on(sub, Basis::SignerValidity);
    let status = signer_status_at(signer.revocation, facts.now, facts.content_timestamp);
    if matches!(
        status,
        Err(Verdict {
            sub: SubIndication::Revoked | SubIndication::RevokedNoPoe,
            ..
        })
    ) || matches!(
        signer.revocation,
        Status::NotIssued { .. } | Status::OnHold { .. }
    ) {
        return status;
    }
    if facts.now < signer.not_before || facts.now > signer.not_after {
        return Err(validity(
            if facts
                .content_timestamp
                .is_some_and(|at| at > signer.not_after)
            {
                SubIndication::Expired
            } else if status.is_ok() {
                outside_validity(signer, facts.now)
            } else {
                SubIndication::OutOfBoundsNoPoe
            },
        ));
    }
    status
}

fn outside_validity(signer: Signer, at: Instant) -> SubIndication {
    // EN 319 102-1 §5.2.6.4 step 7 and NOTE 8: ordinary positive
    // revocation status does not establish non-revocation after expiry.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf#page=53
    if at > signer.not_after && signer.expiry_evidence == ExpiryEvidence::Unestablished {
        return SubIndication::OutOfBoundsNoPoe;
    }
    SubIndication::OutOfBoundsNotRevoked
}

fn signer_status_at(status: Status, at: Instant, content: Option<Instant>) -> Result<(), Verdict> {
    if let Some(revoked) = revocation(status) {
        if revoked <= at {
            let sub = if content.is_some_and(|bound| bound > revoked) {
                SubIndication::Revoked
            } else {
                SubIndication::RevokedNoPoe
            };
            return Err(Verdict::on(sub, Basis::SignerRevocation));
        }
        return Ok(());
    }
    pending(status).map_err(|sub| Verdict::on(sub, Basis::SignerRevocation))
}

fn integrity(facts: &Facts<'_>) -> Integrity {
    if facts.value == Value::Mismatch || facts.references.contains(&Reference::Mismatch) {
        Integrity::Broken
    } else if facts.references.contains(&Reference::Missing) {
        Integrity::Incomplete
    } else if matches!(facts.value, Value::Unsupported | Value::NeedsChain) {
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
