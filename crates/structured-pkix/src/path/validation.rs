//! Static certificate-path processing shared by construction and supplied paths.
//! RFC5280 §6.1 and RFC9618 govern the common core. Revocation, application
//! purpose, algorithm permissions and trust-anchor selection remain external.

use super::{
    Anchor, BuildError, BuildResult, Interval, Meter, Policy, Truncation, Verified, Verify, Watch,
    WorkingKey, cost, sorting_rounds,
};
use crate::constraints::BasicConstraints;
use crate::extension::{Extension, Recognizer};
use crate::{Certificate, ErrorCode, Name, oid};
use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec};

mod processing;

/// Explicit local trust anchor with an effective, possibly inherited key.
/// Binding proves original SPKI identity, not trust or a continuation of an
/// earlier path's accumulated constraints. The caller selects this boundary.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveAnchor<'a> {
    anchor: Anchor<'a>,
    key: WorkingKey<'a>,
}

impl<'a> EffectiveAnchor<'a> {
    /// Bind a previously projected effective key to this anchor's original
    /// SPKI. `None` denotes completed source mismatch; resource errors remain
    /// errors. Inherited parameter bytes continue borrowing their source.
    pub fn bind(
        anchor: Anchor<'a>,
        key: WorkingKey<'a>,
        execution: &Memory,
    ) -> crate::Result<Option<Self>> {
        let left = anchor.key().as_bytes();
        let right = key.key().as_bytes();
        let work = u64::try_from(left.len().max(right.len()))
            .ok()
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| anchor.name().resource(MemoryError::WorkExceeded))?;
        execution
            .charge_work(work)
            .map_err(|reason| anchor.name().resource(reason))?;
        if left != right {
            return Ok(None);
        }
        Ok(Some(Self { anchor, key }))
    }

    /// Caller-selected local anchor, retaining its certificate constraints.
    #[must_use]
    pub fn anchor(self) -> Anchor<'a> {
        self.anchor
    }

    /// Effective key bound to the anchor's original SPKI.
    #[must_use]
    pub fn key(self) -> WorkingKey<'a> {
        self.key
    }

    fn standing(anchor: Anchor<'a>) -> Self {
        Self {
            anchor,
            key: WorkingKey::standing(anchor.key()),
        }
    }
}

/// The source of a path fact; certificate positions are leaf-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintSource {
    /// The explicitly supplied trust anchor.
    Anchor,
    /// A certificate at this position in the supplied path.
    Certificate(usize),
}

/// How a presented name fails an accumulated name constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameConstraintFailure {
    /// An authority explicitly excluded the name.
    Excluded,
    /// No permitted subtree of the relevant authority contains the name.
    NotPermitted,
    /// A relevant constraint cannot be enforced by this implementation/provider.
    Unenforceable,
}

/// A completed semantic rejection, distinct from inability to execute a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason<'a> {
    /// A certification path must contain at least one certificate.
    EmptyPath,
    /// The same encoded certificate already occurs at the named position.
    DuplicateCertificate {
        /// The earlier leaf-first position.
        earlier: usize,
    },
    /// The trust anchor's own certificate is not part of a prospective path.
    AnchorIncluded,
    /// The certificate does not cover the requested validation interval.
    Validity,
    /// The certificate's issuer name differs from the expected issuer.
    Issuer,
    /// An intermediate does not assert certificate-authority status.
    NotAuthority,
    /// An intermediate's `KeyUsage` forbids signing certificates.
    KeyCertSign,
    /// An asserted authority has an empty subject name.
    EmptyAuthorityName,
    /// The path exceeds an authority's pathLenConstraint.
    PathLength {
        /// The authority whose retained limit was exhausted.
        source: ConstraintSource,
        /// The original pathLenConstraint, before counter decrements.
        limit: u32,
    },
    /// The provider completed the signature check with a negative answer.
    Signature,
    /// The provider cannot verify this algorithm/key/parameter combination.
    UnsupportedSignature,
    /// A critical extension is not understood.
    CriticalExtension(Oid<'a>),
    /// A relevant extension could not be decoded semantically.
    MalformedExtension {
        /// The extension's type identifier.
        extension: Oid<'a>,
        /// The original decoding code.
        code: ErrorCode,
        /// The original schema field.
        field: &'static str,
        /// The original document offset.
        offset: u64,
    },
    /// A name constraint is carried by a certificate that is not a CA.
    NameConstraintsOnNonAuthority,
    /// A name violates a constraint originating above this certificate.
    NameConstraints {
        /// The authority or anchor that supplied the decisive constraint.
        source: ConstraintSource,
        /// The completed constraint result.
        failure: NameConstraintFailure,
    },
    /// The path does not satisfy the requested/required certificate policies.
    Policies,
}

/// A semantic failure at its source; `None` denotes the whole supplied input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection<'a> {
    /// Leaf-first certificate position, anchor, or whole-input failure.
    pub at: Option<ConstraintSource>,
    /// The completed rejection reason.
    pub reason: RejectionReason<'a>,
}

/// Accepted static path facts, not a complete application trust verdict.
/// The policy container owns and accounts its allocation; its OID values and
/// the effective key still borrow the original certificate/anchor input.
#[derive(Debug)]
pub struct ValidationFacts<'a> {
    /// The target's effective key, including inherited algorithm parameters.
    pub key: WorkingKey<'a>,
    /// Intermediate CAs that are not self-issued, excluding target and anchor.
    /// This scalar lets caller anchor-policy checks reuse the completed census.
    pub non_self_issued_intermediates: u32,
    policies: OwnedVec<Oid<'a>>,
}

impl<'a> ValidationFacts<'a> {
    /// Accepted authority/user policy identifiers in deterministic encoded order.
    #[must_use]
    pub fn policies(&self) -> &[Oid<'a>] {
        &self.policies
    }

    /// Transfers owned policy-set storage with its retained capacity charge.
    #[must_use]
    pub fn into_policies(self) -> OwnedVec<Oid<'a>> {
        self.policies
    }
}

/// The completed outcome of checking exactly one supplied path.
#[derive(Debug)]
pub enum Validation<'a> {
    /// Static certificate-path checks completed successfully.
    Accepted(ValidationFacts<'a>),
    /// Static checks completed with a semantic rejection.
    Rejected(Rejection<'a>),
    /// A local processing limit stopped the operation; no accepted facts exist.
    Incomplete(Truncation),
}

/// Local limits for checking a supplied path, with no alternative-path search.
#[derive(Debug, Clone, Copy)]
pub struct ValidationBounds {
    /// Maximum number of supplied certificates, excluding the anchor.
    pub depth: usize,
    /// Maximum cumulative work units for this check.
    pub work: u64,
    /// Retained policy graph nodes, parent edges and expected OIDs together.
    pub policies: usize,
}

impl Default for ValidationBounds {
    fn default() -> Self {
        let bounds = super::Bounds::default();
        Self {
            depth: bounds.depth,
            work: bounds.work,
            policies: bounds.policies,
        }
    }
}

/// Explicit execution inputs for static checking of a borrowed supplied path.
/// Callers supply trusted anchors, cryptographic capability and application
/// policy separately; no clock, network or trust discovery is performed here.
pub struct ValidationContext<'a, 'p, V: Verify, W: Watch, R: Recognizer> {
    /// The current operation's shared work and storage account.
    pub execution: &'p Memory,
    /// The interval every certificate must cover.
    pub interval: Interval,
    /// Certificate-policy processing inputs.
    pub policy: Policy<'a>,
    /// Local bounds that only tighten the shared execution budget.
    pub bounds: ValidationBounds,
    /// Injected signature verifier; it accounts its own internal work/storage.
    pub verifier: &'p V,
    /// Caller-provided deadline check; `()` means no clock, with work still bounded.
    pub watch: &'p W,
    /// Injected recognition of scheme-specific critical extensions/names.
    pub recognizer: &'p R,
}

pub(super) struct Settings<'a, 'p, R: Recognizer> {
    pub(super) execution: &'p Memory,
    pub(super) interval: Interval,
    pub(super) policy: Policy<'a>,
    pub(super) policies: usize,
    pub(super) recognizer: &'p R,
}

/// Cached by search, computed directly for a supplied path without cache storage.
#[derive(Debug, Clone, Copy)]
pub(super) struct CertificateFacts<'a> {
    pub(super) self_issued: bool,
    pub(super) basic: Option<BasicConstraints>,
    pub(super) issuing: Option<RejectionReason<'a>>,
    pub(super) rejected: Option<RejectionReason<'a>>,
}

pub(super) trait Driver<'a, R: Recognizer>: Meter {
    type VerificationError;
    fn verified(
        &mut self,
        certificate: &'a Certificate<'a>,
        key: WorkingKey<'a>,
    ) -> BuildResult<Option<Verified>, Self::VerificationError, R::Error>;
    fn facts(
        &mut self,
        certificate: &'a Certificate<'a>,
        settings: &Settings<'a, '_, R>,
    ) -> BuildResult<Option<CertificateFacts<'a>>, Self::VerificationError, R::Error>;
}

/// Search constructs this witness only after all selected issuer-name bindings
/// and the terminal anchor binding were checked. The supplied variant performs
/// those same Name comparisons here, without repeating search's proven work.
#[derive(Clone, Copy)]
pub(super) enum Chain<'a, 'p> {
    Supplied(&'p [&'a Certificate<'a>]),
    Constructed(&'p [&'a Certificate<'a>]),
}

enum Decoded<T> {
    Value(Option<T>),
    Rejected(RejectionReason<'static>),
    Incomplete,
}

fn decode<T>(
    meter: &mut impl Meter,
    kind: Oid<'static>,
    action: impl FnOnce() -> crate::Result<Option<T>>,
) -> crate::Result<Decoded<T>> {
    if !meter.spend(cost::EXTENSION)? {
        return Ok(Decoded::Incomplete);
    }
    Ok(match decoded(kind, action())? {
        Ok(value) => Decoded::Value(value),
        Err(reason) => Decoded::Rejected(reason),
    })
}

fn decoded<T>(
    kind: Oid<'static>,
    result: crate::Result<T>,
) -> crate::Result<core::result::Result<T, RejectionReason<'static>>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error) if error.is_resource() => Err(error),
        Err(error) => Ok(Err(RejectionReason::MalformedExtension {
            extension: kind,
            code: error.code(),
            field: error.field(),
            offset: error.offset(),
        })),
    }
}

pub(super) fn spend_names(
    meter: &mut impl Meter,
    left: &Name<'_>,
    right: &Name<'_>,
) -> crate::Result<bool> {
    let parts = left.parts().len() as u64 + right.parts().len() as u64;
    if !meter.spend(parts)? {
        return Ok(false);
    }
    let bytes = left.as_bytes().len() as u64 + right.as_bytes().len() as u64;
    let rounds = sorting_rounds(left).max(sorting_rounds(right));
    let work = rounds
        .checked_mul(bytes / cost::COMPARED)
        .and_then(|work| work.checked_add(cost::NAME))
        .ok_or_else(|| left.resource(MemoryError::WorkExceeded))?;
    meter.spend(work)
}

fn critical_policy(
    item: &Extension<'_>,
    execution: &Memory,
) -> Option<(Oid<'static>, crate::Result<bool>)> {
    // Known path extensions retain decoder failures even when critical.
    let kind = item.kind();
    if kind == oid::CERTIFICATE_POLICIES {
        Some((
            oid::CERTIFICATE_POLICIES,
            // RFC5280 §4.2.1.4 requires interpretation of all qualifiers
            // when critical. Reuse the ordinary qualifier semantic core on
            // this decoded value rather than treating shape as understanding.
            crate::policy::CertificatePolicies::read(item, execution)
                .and_then(|policies| policies.understood(item.parser(), execution)),
        ))
    } else if kind == oid::POLICY_CONSTRAINTS {
        Some((
            oid::POLICY_CONSTRAINTS,
            crate::constraints::PolicyConstraints::read(item, execution).map(|_| true),
        ))
    } else if kind == oid::POLICY_MAPPINGS {
        Some((
            oid::POLICY_MAPPINGS,
            crate::policy::PolicyMappings::read(item, execution).map(|_| true),
        ))
    } else if kind == oid::INHIBIT_ANY_POLICY {
        Some((
            oid::INHIBIT_ANY_POLICY,
            crate::constraints::InhibitAnyPolicy::read(item, execution).map(|_| true),
        ))
    } else {
        None
    }
}

pub(super) fn certificate_facts<'a, E, R: Recognizer, M: Meter>(
    certificate: &'a Certificate<'a>,
    settings: &Settings<'a, '_, R>,
    meter: &mut M,
) -> BuildResult<Option<CertificateFacts<'a>>, E, R::Error> {
    let execution = settings.execution;
    let extensions = certificate.tbs().extensions();
    if !meter.spend(cost::CHECK)? {
        return Ok(None);
    }
    let mut facts = CertificateFacts {
        self_issued: false,
        basic: None,
        issuing: Some(RejectionReason::NotAuthority),
        rejected: None,
    };
    if !settings.interval.inside(certificate.tbs().validity()) {
        facts.rejected = Some(RejectionReason::Validity);
        return Ok(Some(facts));
    }
    if !spend_names(
        meter,
        certificate.tbs().subject(),
        certificate.tbs().issuer(),
    )? {
        return Ok(None);
    }
    facts.self_issued = certificate
        .tbs()
        .subject()
        .matches(certificate.tbs().issuer(), execution)?;
    match decode(meter, oid::BASIC_CONSTRAINTS, || {
        extensions.basic_constraints(execution)
    })? {
        Decoded::Value(basic) => facts.basic = basic,
        Decoded::Rejected(reason) => {
            facts.rejected = Some(reason);
            return Ok(Some(facts));
        }
        Decoded::Incomplete => return Ok(None),
    }
    if facts.basic.is_some_and(BasicConstraints::is_authority) {
        facts.issuing = None;
        if certificate.tbs().subject().is_empty() {
            facts.rejected = Some(RejectionReason::EmptyAuthorityName);
            return Ok(Some(facts));
        }
        match decode(meter, oid::KEY_USAGE, || extensions.key_usage(execution))? {
            Decoded::Value(Some(usage)) if !usage.key_cert_sign() => {
                facts.issuing = Some(RejectionReason::KeyCertSign);
            }
            Decoded::Rejected(reason) => facts.issuing = Some(reason),
            Decoded::Incomplete => return Ok(None),
            Decoded::Value(_) => {}
        }
    }
    for demand in extensions.criticals(execution) {
        let demand = demand?;
        if !meter.spend(cost::EXTENSION)? {
            return Ok(None);
        }
        // The common processor decodes and retains nameConstraints before
        // verification, then enforces it on subordinate names. Decoding here
        // as well would allocate the same constraint payload twice.
        if demand.kind() == oid::NAME_CONSTRAINTS || demand.kind() == oid::BASIC_CONSTRAINTS {
            continue;
        }
        if demand.kind() == oid::KEY_USAGE
            && facts.basic.is_some_and(BasicConstraints::is_authority)
        {
            if matches!(
                facts.issuing,
                Some(RejectionReason::MalformedExtension { .. })
            ) {
                facts.rejected = facts.issuing;
                return Ok(Some(facts));
            }
            continue;
        }
        // RFC5280 §6.1.3/§6.1.4/§6.1.5: these are known path-processing
        // extensions. A malformed value keeps its decoder details even if
        // critical; it is not an unrecognized extension. Critical mappings
        // and inhibitAnyPolicy must decode even on the final certificate,
        // where their intermediate-only state transitions do not apply.
        if let Some((kind, result)) = critical_policy(demand, execution) {
            let reason = match decoded(kind, result)? {
                Ok(true) => continue,
                Ok(false) => RejectionReason::CriticalExtension(kind),
                Err(reason) => reason,
            };
            facts.rejected = Some(reason);
            return Ok(Some(facts));
        }
        if extensions.understands(demand, settings.recognizer, execution)? {
            continue;
        }
        facts.rejected = Some(RejectionReason::CriticalExtension(demand.kind()));
        return Ok(Some(facts));
    }
    Ok(Some(facts))
}

fn rejection(at: ConstraintSource, reason: RejectionReason<'_>) -> Validation<'_> {
    Validation::Rejected(Rejection {
        at: Some(at),
        reason,
    })
}

pub(super) fn process<'a, R: Recognizer, D: Driver<'a, R>>(
    input: Chain<'a, '_>,
    anchor: Anchor<'a>,
    settings: &Settings<'a, '_, R>,
    driver: &mut D,
) -> BuildResult<Validation<'a>, D::VerificationError, R::Error> {
    processing::process(input, EffectiveAnchor::standing(anchor), settings, driver)
}

struct Supplied<'a, 'p, V: Verify, W: Watch, R: Recognizer> {
    context: &'p ValidationContext<'a, 'p, V, W, R>,
    origin: &'a Certificate<'a>,
    spent: u64,
    halted: Option<Truncation>,
}

impl<V: Verify, W: Watch, R: Recognizer> Supplied<'_, '_, V, W, R> {
    fn admit(&mut self, work: u64) -> crate::Result<Option<Truncation>> {
        if work > self.context.bounds.work - self.spent {
            return Ok(Some(Truncation::Work));
        }
        if self.context.watch.out_of_time() {
            return Ok(Some(Truncation::Time));
        }
        self.context
            .execution
            .charge_work(work)
            .map_err(|reason| self.origin.tbs().subject().resource(reason))?;
        self.spent += work;
        Ok(None)
    }
}

impl<V: Verify, W: Watch, R: Recognizer> Meter for Supplied<'_, '_, V, W, R> {
    fn spend(&mut self, work: u64) -> crate::Result<bool> {
        if let Some(halted) = self.admit(work)? {
            self.halted = Some(halted);
            return Ok(false);
        }
        Ok(true)
    }
}

impl<'a, V: Verify, W: Watch, R: Recognizer> Driver<'a, R> for Supplied<'a, '_, V, W, R> {
    type VerificationError = V::Error;
    fn verified(
        &mut self,
        certificate: &'a Certificate<'a>,
        key: WorkingKey<'a>,
    ) -> BuildResult<Option<Verified>, V::Error, R::Error> {
        if !self.spend(cost::SIGNATURE)? {
            return Ok(None);
        }
        self.context
            .verifier
            .verify(
                &certificate.signature_algorithm(),
                key,
                certificate.signed_bytes(),
                certificate.signature(),
                self.context.execution,
            )
            .map(Some)
            .map_err(BuildError::Verification)
    }
    fn facts(
        &mut self,
        certificate: &'a Certificate<'a>,
        settings: &Settings<'a, '_, R>,
    ) -> BuildResult<Option<CertificateFacts<'a>>, V::Error, R::Error> {
        certificate_facts(certificate, settings, self)
    }
}

/// Checks exactly the supplied leaf-first path to one explicit anchor.
///
/// The anchor is excluded from `chain`. This returns static path facts only;
/// revocation, purpose, key strength and application permissions remain caller
/// decisions. It neither searches alternative issuers nor re-encodes signed data.
///
/// A completed rejection is a value. Processing/resource and injected callback
/// errors remain `BuildError`, while local bounds yield `Validation::Incomplete`.
///
/// ```
/// use structured_asn1::memory::Memory;
/// use structured_pkix::{Certificate, path};
///
/// fn check<'a, V: path::Verify>(
///     chain: &[&'a Certificate<'a>],
///     anchor: path::Anchor<'a>,
///     execution: &Memory,
///     interval: path::Interval,
///     verifier: &V,
/// ) -> path::BuildResult<path::Validation<'a>, V::Error, core::convert::Infallible> {
///     let context = path::ValidationContext {
///         execution,
///         interval,
///         policy: path::Policy::default(),
///         bounds: path::ValidationBounds::default(),
///         verifier,
///         watch: &(),
///         recognizer: &(),
///     };
///     path::validate(chain, anchor, &context)
/// }
/// ```
pub fn validate<'a, V: Verify, W: Watch, R: Recognizer>(
    chain: &[&'a Certificate<'a>],
    anchor: Anchor<'a>,
    context: &ValidationContext<'a, '_, V, W, R>,
) -> BuildResult<Validation<'a>, V::Error, R::Error> {
    validate_effective(chain, EffectiveAnchor::standing(anchor), context)
}

/// Check the supplied local path with an explicitly bound effective anchor key.
/// This shares every static check with [`validate`], including the local anchor
/// certificate's name constraints. It does not resume constraints or policy
/// state inherited from a previously validated ancestor path. For original-root
/// validation, pass that complete path and its original anchor instead.
pub fn validate_effective<'a, V: Verify, W: Watch, R: Recognizer>(
    chain: &[&'a Certificate<'a>],
    effective: EffectiveAnchor<'a>,
    context: &ValidationContext<'a, '_, V, W, R>,
) -> BuildResult<Validation<'a>, V::Error, R::Error> {
    let anchor = effective.anchor;
    let Some(target) = chain.first() else {
        return Ok(Validation::Rejected(Rejection {
            at: None,
            reason: RejectionReason::EmptyPath,
        }));
    };
    if chain.len() > context.bounds.depth {
        return Ok(Validation::Incomplete(Truncation::Depth));
    }
    let length = u32::try_from(chain.len()).map_err(|_| {
        target
            .tbs()
            .subject()
            .resource(MemoryError::CapacityOverflow)
    })?;
    length.checked_add(1).ok_or_else(|| {
        target
            .tbs()
            .subject()
            .resource(MemoryError::CapacityOverflow)
    })?;
    let mut driver = Supplied {
        context,
        origin: target,
        spent: 0,
        halted: None,
    };
    let mut seen = context.execution.map();
    for (index, certificate) in chain.iter().enumerate() {
        if let Some(halted) =
            driver.admit(cost::ENTRY + certificate.as_bytes().len() as u64 / cost::HASHED)?
        {
            return Ok(Validation::Incomplete(halted));
        }
        if let Some(earlier) = seen
            .try_insert(certificate.as_bytes(), index)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?
        {
            return Ok(rejection(
                ConstraintSource::Certificate(index),
                RejectionReason::DuplicateCertificate { earlier },
            ));
        }
        if let Some(published) = anchor.certificate() {
            let bytes = certificate.as_bytes().len().min(published.as_bytes().len()) as u64;
            if let Some(halted) = driver.admit(bytes / cost::COMPARED)? {
                return Ok(Validation::Incomplete(halted));
            }
            context
                .execution
                .charge_work(bytes)
                .map_err(|reason| certificate.tbs().subject().resource(reason))?;
            if super::same(certificate, published) {
                return Ok(rejection(
                    ConstraintSource::Certificate(index),
                    RejectionReason::AnchorIncluded,
                ));
            }
        }
    }
    drop(seen);
    let settings = Settings {
        execution: context.execution,
        interval: context.interval,
        policy: context.policy,
        policies: context.bounds.policies,
        recognizer: context.recognizer,
    };
    let outcome = processing::process(Chain::Supplied(chain), effective, &settings, &mut driver)?;
    if let Some(halted) = driver.halted {
        return Ok(Validation::Incomplete(halted));
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{CertificateParts, oid as encoded_oid, printable, seq, set};
    use core::cell::Cell;
    use structured_asn1::{BitString, Parser};

    struct Answer {
        result: Verified,
        calls: Cell<usize>,
    }
    impl Verify for Answer {
        type Error = core::convert::Infallible;
        fn verify(
            &self,
            _algorithm: &crate::AlgorithmIdentifier<'_>,
            _key: WorkingKey<'_>,
            _signed: &[u8],
            _signature: BitString<'_>,
            _execution: &Memory,
        ) -> core::result::Result<Verified, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.result)
        }
    }

    fn target() -> alloc::vec::Vec<u8> {
        CertificateParts {
            subject: seq(&[set(&[seq(&[
                encoded_oid(oid::COMMON_NAME),
                printable("target"),
            ])])]),
            ..CertificateParts::default()
        }
        .build()
    }

    fn root() -> alloc::vec::Vec<u8> {
        let parts = CertificateParts::default();
        CertificateParts {
            subject: parts.issuer.clone(),
            ..parts
        }
        .build()
    }

    #[test]
    fn supplied_path_separates_success_no_and_unsupported() {
        // The same public operation preserves all three completed provider answers.
        let root_der = root();
        let leaf_der = target();
        let parser = Parser::der(crate::fixtures::memory());
        let root = Certificate::read(&parser, &root_der, 0).unwrap();
        let leaf = Certificate::read(&parser, &leaf_der, 100).unwrap();
        let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
        for result in [Verified::Yes, Verified::No, Verified::Unsupported] {
            let execution = crate::fixtures::memory();
            let verifier = Answer {
                result,
                calls: Cell::new(0),
            };
            let context = ValidationContext {
                execution: &execution,
                interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
                policy: Policy::default(),
                bounds: ValidationBounds::default(),
                verifier: &verifier,
                watch: &(),
                recognizer: &(),
            };
            let outcome = crate::path::validate(&[&leaf], anchor, &context).unwrap();
            match (result, outcome) {
                (Verified::Yes, Validation::Accepted(facts)) => {
                    assert_eq!(
                        facts.key.key().as_bytes(),
                        leaf.tbs().public_key().as_bytes()
                    );
                    assert_eq!(facts.policies(), []);
                }
                (Verified::No, Validation::Rejected(rejection)) => {
                    assert_eq!(rejection.at, Some(ConstraintSource::Certificate(0)));
                    assert_eq!(rejection.reason, RejectionReason::Signature);
                }
                (Verified::Unsupported, Validation::Rejected(rejection)) => {
                    assert_eq!(rejection.at, Some(ConstraintSource::Certificate(0)));
                    assert_eq!(rejection.reason, RejectionReason::UnsupportedSignature);
                }
                other => panic!("unexpected public path result: {other:?}"),
            }
            assert_eq!(verifier.calls.get(), 1);
            assert_eq!(execution.used(), 0);
        }
    }

    #[test]
    fn supplied_local_work_refusal_never_calls_the_provider() {
        // Local work exhaustion is incomplete; it is not a signature rejection.
        let root_der = root();
        let leaf_der = target();
        let parser = Parser::der(crate::fixtures::memory());
        let root = Certificate::read(&parser, &root_der, 0).unwrap();
        let leaf = Certificate::read(&parser, &leaf_der, 100).unwrap();
        let execution = crate::fixtures::memory();
        let verifier = Answer {
            result: Verified::Yes,
            calls: Cell::new(0),
        };
        let context = ValidationContext {
            execution: &execution,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds {
                work: 0,
                ..ValidationBounds::default()
            },
            verifier: &verifier,
            watch: &(),
            recognizer: &(),
        };
        assert!(matches!(
            crate::path::validate(
                &[&leaf],
                Anchor::new(root.tbs().subject(), root.tbs().public_key()),
                &context
            )
            .unwrap(),
            Validation::Incomplete(Truncation::Work)
        ));
        assert_eq!(verifier.calls.get(), 0);
        assert_eq!(execution.used(), 0);
        assert_eq!(execution.work_used(), 0);
    }
}
