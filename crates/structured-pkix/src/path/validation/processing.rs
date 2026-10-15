//! One processing state machine; drivers supply cached or direct facts.

use super::super::name_space::{Admission, NameSpace};
use super::super::{
    BuildError, BuildResult, Meter, Truncation, Verified, WorkingKey, cost, policy,
};
use super::{
    CertificateFacts, Chain, ConstraintSource, Decoded, Driver, EffectiveAnchor,
    NameConstraintFailure, Rejection, RejectionReason, Settings, Validation, ValidationFacts,
    decode, spend_names,
};
use crate::constraints::{BasicConstraints, CertificateCount, PolicyConstraints};
use crate::error::CallbackError;
use crate::extension::Recognizer;
use crate::{Certificate, Name, oid};
use structured_asn1::Oid;
use structured_asn1::memory::{MemoryError, Work};

enum Stop<'a, V, R> {
    Error(BuildError<V, R>),
    Rejected(Rejection<'a>),
    Incomplete(Truncation),
}

type Result<'a, T, V, R> = core::result::Result<T, Stop<'a, V, R>>;

impl<V, R> From<crate::Error> for Stop<'_, V, R> {
    fn from(error: crate::Error) -> Self {
        Self::Error(BuildError::Processing(error))
    }
}

impl<V, R> From<BuildError<V, R>> for Stop<'_, V, R> {
    fn from(error: BuildError<V, R>) -> Self {
        Self::Error(error)
    }
}

impl<V, R> From<CallbackError<R>> for Stop<'_, V, R> {
    fn from(error: CallbackError<R>) -> Self {
        Self::Error(error.into())
    }
}

fn reject<V, R>(at: ConstraintSource, reason: RejectionReason<'_>) -> Stop<'_, V, R> {
    Stop::Rejected(Rejection {
        at: Some(at),
        reason,
    })
}

fn graph<T, V, R>(result: core::result::Result<T, policy::Overflow>) -> Result<'static, T, V, R> {
    match result {
        Ok(value) => Ok(value),
        Err(policy::Overflow::Limit) => Err(Stop::Incomplete(Truncation::Policies)),
        Err(policy::Overflow::Resource(error)) => Err(error.into()),
    }
}

fn read<T, V, R>(
    meter: &mut impl Meter,
    at: ConstraintSource,
    kind: Oid<'static>,
    action: impl FnOnce() -> crate::Result<Option<T>>,
) -> Result<'static, Option<T>, V, R> {
    match decode(meter, kind, action)? {
        Decoded::Value(value) => Ok(value),
        Decoded::Rejected(reason) => Err(reject(at, reason)),
        Decoded::Incomplete => Err(Stop::Incomplete(Truncation::Work)),
    }
}

struct Processing<'a, E: Work> {
    policies: policy::Processing<'a, E>,
    space: NameSpace<'a, ConstraintSource, E>,
    working: WorkingKey<'a>,
    issuer: &'a Name<'a>,
    allowed: u32,
    path_length_source: Option<(ConstraintSource, u32)>,
    last_constraints: Option<PolicyConstraints>,
    top: usize,
    non_self_issued_intermediates: u32,
}

impl<'a, E: Work> Processing<'a, E> {
    fn new<R: Recognizer<E>, D: Driver<'a, R, E>>(
        chain: &[&'a Certificate<'a>],
        effective: &EffectiveAnchor<'a>,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, Self, D::VerificationError, R::Error> {
        let anchor = effective.anchor();
        let Some(target) = chain.first() else {
            return Err(Stop::Rejected(Rejection {
                at: None,
                reason: RejectionReason::EmptyPath,
            }));
        };
        let length = u32::try_from(chain.len()).map_err(|_| {
            target
                .tbs()
                .subject()
                .resource(MemoryError::CapacityOverflow)
        })?;
        let origin = target
            .tbs()
            .subject()
            .resource(MemoryError::CapacityOverflow)
            .offset();
        let policies = graph(policy::Processing::new(
            length,
            policy::Initial {
                explicit_policy: settings.policy.explicit,
                policy_mapping: settings.policy.mapping,
                any_policy: settings.policy.any,
            },
            settings.policies,
            settings.execution,
            origin,
        ))?;
        let mut space = NameSpace::with_sources(settings.execution);
        if let Some(certificate) = anchor.certificate()
            && let Some(constraints) = read(
                driver,
                ConstraintSource::Anchor,
                oid::NAME_CONSTRAINTS,
                || {
                    certificate
                        .tbs()
                        .extensions()
                        .name_constraints(settings.execution)
                },
            )?
        {
            space
                .narrow_from(constraints, ConstraintSource::Anchor)
                .map_err(|reason| certificate.tbs().subject().resource(reason))?;
        }
        Ok(Self {
            policies,
            space,
            working: effective.key(),
            issuer: anchor.name(),
            allowed: length,
            path_length_source: None,
            last_constraints: None,
            top: chain.len() - 1,
            non_self_issued_intermediates: 0,
        })
    }

    fn certificate<R: Recognizer<E>, D: Driver<'a, R, E>>(
        &mut self,
        certificate: &'a Certificate<'a>,
        index: usize,
        proven: bool,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, (), D::VerificationError, R::Error> {
        let at = ConstraintSource::Certificate(index);
        let execution = settings.execution;
        if !driver.spend(cost::CHECK)? {
            return Err(Stop::Incomplete(Truncation::Work));
        }
        if !proven {
            if !spend_names(driver, certificate.tbs().issuer(), self.issuer)? {
                return Err(Stop::Incomplete(Truncation::Work));
            }
            if !certificate.tbs().issuer().matches(self.issuer, execution)? {
                return Err(reject(at, RejectionReason::Issuer));
            }
        }
        let Some(facts) = driver.facts(certificate, settings)? else {
            return Err(Stop::Incomplete(Truncation::Work));
        };
        if let Some(reason) = facts.rejected {
            return Err(reject(at, reason));
        }
        if index != 0
            && let Some(reason) = facts.issuing
        {
            return Err(reject(at, reason));
        }
        let extensions = certificate.tbs().extensions();
        let current_constraints = read(driver, at, oid::NAME_CONSTRAINTS, || {
            extensions.name_constraints(execution)
        })?;
        if current_constraints.is_some() && !facts.basic.is_some_and(BasicConstraints::is_authority)
        {
            return Err(reject(at, RejectionReason::NameConstraintsOnNonAuthority));
        }
        let Some(verified) = driver.verified(certificate, self.working)? else {
            return Err(Stop::Incomplete(Truncation::Work));
        };
        match verified {
            Verified::Yes => {}
            Verified::No => return Err(reject(at, RejectionReason::Signature)),
            Verified::Unsupported => return Err(reject(at, RejectionReason::UnsupportedSignature)),
        }
        // RFC5280 §6: the anchor certificate is outside the path even when
        // trust was supplied as name/key. The constructed witness already
        // excludes self-published anchors; supplied input must establish it.
        if !proven
            && index == self.top
            && facts.self_issued
            && self.same_anchor_key(certificate, settings, driver)?
        {
            return Err(reject(at, RejectionReason::AnchorIncluded));
        }
        let Some(working) = self.working.below(certificate, execution, driver)? else {
            return Err(Stop::Incomplete(Truncation::Work));
        };
        self.working = working;
        self.issuer = certificate.tbs().subject();
        if !self.space.is_open() && (index == 0 || !facts.self_issued) {
            self.names(certificate, at, settings, driver)?;
        }
        self.policy(certificate, index, facts, settings, driver)?;
        if let Some(constraints) = current_constraints {
            self.space
                .narrow_from(constraints, at)
                .map_err(|reason| certificate.tbs().subject().resource(reason))?;
        }
        if index != 0 {
            self.path_length(at, facts)?;
        }
        Ok(())
    }

    fn same_anchor_key<R: Recognizer<E>, D: Driver<'a, R, E>>(
        &self,
        certificate: &Certificate<'_>,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, bool, D::VerificationError, R::Error> {
        let key = certificate.tbs().public_key().as_bytes();
        let anchor = self.working.key().as_bytes();
        if key.len() != anchor.len() {
            return Ok(false);
        }
        if core::ptr::eq(key, anchor) {
            return Ok(true);
        }
        let reads = (key.len() as u64).checked_mul(2).ok_or_else(|| {
            certificate
                .tbs()
                .subject()
                .resource(MemoryError::WorkExceeded)
        })?;
        if !driver.spend(reads / cost::COMPARED)? {
            return Err(Stop::Incomplete(Truncation::Work));
        }
        settings
            .execution
            .charge_work(reads)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?;
        Ok(key == anchor)
    }

    fn names<R: Recognizer<E>, D: Driver<'a, R, E>>(
        &self,
        certificate: &'a Certificate<'a>,
        at: ConstraintSource,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, (), D::VerificationError, R::Error> {
        let alternatives = read(driver, at, oid::SUBJECT_ALT_NAME, || {
            certificate
                .tbs()
                .extensions()
                .subject_alt_name(settings.execution)
        })?;
        // RFC5280 §4.2.1.6: absent SAN contributes no additional names.
        let alternatives = match &alternatives {
            Some(names) => &**names,
            None => &[],
        };
        if !self.space.charge(
            certificate.tbs().subject(),
            alternatives,
            driver,
            settings.execution,
        )? {
            return Err(Stop::Incomplete(Truncation::Work));
        }
        let (admission, source) = self.space.admits_located(
            certificate.tbs().subject(),
            alternatives,
            settings.recognizer,
            settings.execution,
        )?;
        let failure = match admission {
            Admission::Admitted => return Ok(()),
            Admission::Excluded => NameConstraintFailure::Excluded,
            Admission::NotPermitted => NameConstraintFailure::NotPermitted,
            Admission::Unenforceable => NameConstraintFailure::Unenforceable,
        };
        Err(reject(
            at,
            RejectionReason::NameConstraints {
                source: source.expect("a rejected constraint names its retained source"),
                failure,
            },
        ))
    }

    fn policy<R: Recognizer<E>, D: Driver<'a, R, E>>(
        &mut self,
        certificate: &'a Certificate<'a>,
        index: usize,
        facts: CertificateFacts<'a>,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, (), D::VerificationError, R::Error> {
        let at = ConstraintSource::Certificate(index);
        let extensions = certificate.tbs().extensions();
        let execution = settings.execution;
        let named = read(driver, at, oid::CERTIFICATE_POLICIES, || {
            extensions.certificate_policies(execution)
        })?;
        if !graph(
            self.policies
                .present(named.as_ref(), facts.self_issued, index == 0, driver),
        )? {
            return Err(reject(at, RejectionReason::Policies));
        }
        let constraints = read(driver, at, oid::POLICY_CONSTRAINTS, || {
            extensions.policy_constraints(execution)
        })?;
        if index == 0 {
            self.last_constraints = constraints;
            return Ok(());
        }
        // RFC5280 §6.1.4/§6.1.5: mappings are processed only for intermediates.
        let mappings = read(driver, at, oid::POLICY_MAPPINGS, || {
            extensions.policy_mappings(execution)
        })?;
        let inhibit = read(driver, at, oid::INHIBIT_ANY_POLICY, || {
            extensions.inhibit_any_policy(execution)
        })?;
        graph(self.policies.carry(
            mappings.as_ref(),
            constraints,
            inhibit,
            facts.self_issued,
            driver,
        ))
    }

    fn path_length<V, R>(
        &mut self,
        at: ConstraintSource,
        facts: CertificateFacts<'a>,
    ) -> Result<'a, (), V, R> {
        // RFC5280 §6.1.4(l,m): self-issued intermediates do not spend the
        // counter; the target is never included in this intermediate step.
        if !facts.self_issued {
            if self.allowed == 0 {
                let (source, limit) = self
                    .path_length_source
                    .expect("only an authority constraint can exhaust before the target");
                return Err(reject(at, RejectionReason::PathLength { source, limit }));
            }
            self.allowed -= 1;
            // Constructor bounds the total path length below u32::MAX.
            debug_assert!(self.non_self_issued_intermediates < u32::MAX);
            self.non_self_issued_intermediates += 1;
        }
        if let Some(limit) = facts
            .basic
            .and_then(BasicConstraints::path_length)
            .and_then(CertificateCount::certificates)
            && limit < self.allowed
        {
            self.allowed = limit;
            self.path_length_source = Some((at, limit));
        }
        Ok(())
    }

    fn finish<R: Recognizer<E>, D: Driver<'a, R, E>>(
        self,
        settings: &Settings<'a, '_, R, E>,
        driver: &mut D,
    ) -> Result<'a, ValidationFacts<'a>, D::VerificationError, R::Error> {
        let settled = graph(self.policies.settle(
            self.last_constraints,
            settings.policy.wanted,
            driver,
        ))?;
        if !settled.is_satisfied() {
            return Err(reject(
                ConstraintSource::Certificate(0),
                RejectionReason::Policies,
            ));
        }
        Ok(ValidationFacts {
            key: self.working,
            policies: settled.into_policies(),
            non_self_issued_intermediates: self.non_self_issued_intermediates,
        })
    }
}

fn inner<'a, R: Recognizer<E>, D: Driver<'a, R, E>, E: Work>(
    input: Chain<'a, '_>,
    anchor: &EffectiveAnchor<'a>,
    settings: &Settings<'a, '_, R, E>,
    driver: &mut D,
) -> Result<'a, ValidationFacts<'a>, D::VerificationError, R::Error> {
    let (chain, proven) = match input {
        Chain::Supplied(chain) => (chain, false),
        Chain::Constructed(chain) => (chain, true),
    };
    let mut state = Processing::new(chain, anchor, settings, driver)?;
    for index in (0..chain.len()).rev() {
        state.certificate(chain[index], index, proven, settings, driver)?;
    }
    state.finish(settings, driver)
}

pub(super) fn process<'a, R: Recognizer<E>, D: Driver<'a, R, E>, E: Work>(
    input: Chain<'a, '_>,
    anchor: &EffectiveAnchor<'a>,
    settings: &Settings<'a, '_, R, E>,
    driver: &mut D,
) -> BuildResult<Validation<'a>, D::VerificationError, R::Error> {
    match inner(input, anchor, settings, driver) {
        Ok(facts) => Ok(Validation::Accepted(facts)),
        Err(Stop::Rejected(reason)) => Ok(Validation::Rejected(reason)),
        Err(Stop::Incomplete(reason)) => Ok(Validation::Incomplete(reason)),
        Err(Stop::Error(error)) => Err(error),
    }
}
