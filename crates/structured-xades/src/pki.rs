//! Original certificate-path facts for validation-material accounting.
//!
//! Caller trust selection and signature/credential association stay explicit.
//! This module executes the common PKIX processor, rather than accepting a
//! caller-written assertion that unrelated certificates formed a valid path.

use crate::timestamp::{CheckedActor, Interval as GenerationInterval, TemporalError};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::Certificate;
use structured_pkix::extension::Recognizer;
use structured_pkix::path::{
    self, Anchor, BuildResult, Interval, Rejection, Truncation, Validation, ValidationContext,
    ValidationFacts, Verify, Watch, WorkingKey,
};
use structured_pkix::temporal::LeapTable;

mod authority;
mod census;
mod counter;
pub use counter::{
    CounterActor, CounterBinding, CounterPath, CounterPathResult, CounterPaths, CounterPathsResult,
    CounterSelectionError, bind_counters,
};
mod closure;
mod root_visits;
pub use closure::{
    AuthorityClosure, AuthorityClosureError, AuthorityNode, AuthorityOrigin, close_authorities,
};
pub use root_visits::AuthorityVisitError;
mod crl;
pub use census::{MemberStatus, PathStatuses, StatusCensusError};
mod origin;
mod participants;
mod purpose;
pub use purpose::{AuthorityUse, AuthorityUses, Uses, UsesError, UsesResult, authority_uses};
mod reading;
pub use participants::{
    Participant, ParticipantAuthority, ParticipantClosure, ParticipantClosureError,
    ParticipantClosureResult, ParticipantError, ParticipantRequirement, ParticipantRequirements,
    ParticipantResult, participants,
};
mod responder;
pub use reading::{CrlReading, CrlReadingBinding, CrlReadingTarget};
mod status;
pub use crl::{
    CrlAuthorities, CrlAuthority, CrlBinding, CrlBindingError, CrlBindingFailure, CrlCoverage,
    CrlCoverageBinding, CrlCoverageError, CrlTarget,
};
pub use responder::{ResponderBinding, ResponderError, ResponderFailure, ResponderPath};
pub use status::{OcspBinding, OcspBindingError, OcspBindingFailure, OcspTarget};

/// One original non-anchor certificate and its projected effective key.
#[derive(Debug, Clone, Copy)]
pub struct Member<'a> {
    certificate: &'a Certificate<'a>,
    key: WorkingKey<'a>,
}

impl<'a> Member<'a> {
    /// Original certificate, without a rendered or re-encoded identity.
    #[must_use]
    pub fn certificate(self) -> &'a Certificate<'a> {
        self.certificate
    }

    /// Effective key at this certificate, including inherited parameters.
    #[must_use]
    pub fn key(self) -> WorkingKey<'a> {
        self.key
    }
}

/// Static checked chain used by the common material census.
///
/// This does not authenticate its association with an XML signature, credential
/// or timestamp. Nor does it establish revocation, purpose, historical trust or
/// application algorithm permission. The root operation must establish those
/// separate facts against the actual selected source.
#[derive(Debug)]
pub struct CheckedPath<'a> {
    anchor: Anchor<'a>,
    interval: Interval,
    members: OwnedVec<Member<'a>>,
    facts: ValidationFacts<'a>,
}

impl<'a> CheckedPath<'a> {
    /// Caller-selected anchor, outside the prospective certification path.
    /// An anchor certificate, when supplied, is available for material census
    /// but never becomes a non-anchor revocation obligation.
    #[must_use]
    pub fn anchor(&self) -> Anchor<'a> {
        self.anchor
    }

    /// Exact lossless interval checked by the shared path processor.
    #[must_use]
    pub fn interval(&self) -> Interval {
        self.interval
    }

    /// Original non-anchor members in issuer-to-subject order. The final entry
    /// is the supplied target. Each needs its own status-processing outcome;
    /// the path's existence alone never supplies a Good assertion.
    #[must_use]
    pub fn members(&self) -> &[Member<'a>] {
        &self.members
    }

    /// Accepted static policies/effective target key from the same invocation.
    #[must_use]
    pub fn facts(&self) -> &ValidationFacts<'a> {
        &self.facts
    }

    /// Binds this actual path to the signer/key used by the complete token check.
    /// The checked path interval must contain the entire timestamp-generation
    /// interval, not just its bare genTime. This is static TSA path binding;
    /// unresolved revocation and application trust acceptance remain separate.
    ///
    /// # Panics
    /// Only if the private construction invariant is violated: an accepted
    /// common path always has its original nonempty target chain.
    pub fn bind_timestamp<'view, 'certificate, N: Copy, D: Copy, G: Copy, W: Work>(
        &'view self,
        actor: &'view CheckedActor<'certificate, 'a, N, D, G>,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<TimestampBinding<'view, 'certificate, 'a, N, D, G>, TimestampBindingError> {
        execution
            .charge_work(1)
            .map_err(TimestampBindingError::Resource)?;
        // Construction follows a successful common path with a nonempty chain.
        let target = self.members.last().expect("a checked path has a target");
        if !exact(
            target.certificate.as_bytes(),
            actor.certificate().as_bytes(),
            execution,
        )
        .map_err(TimestampBindingError::Resource)?
        {
            return Ok(TimestampBinding::Rejected(
                TimestampBindingFailure::Certificate,
            ));
        }
        // The common token checker already bound the original SPKI. Inherited
        // parameter state must additionally equal the state actually projected
        // by this validated path; never replace it after checking a signature.
        let key = match (self.facts.key.parameters(), actor.key().parameters()) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                exact(left, right, execution).map_err(TimestampBindingError::Resource)?
            }
            _ => false,
        };
        if !key {
            return Ok(TimestampBinding::Rejected(
                TimestampBindingFailure::EffectiveKey,
            ));
        }
        let generation = actor
            .verified()
            .interval(utc, execution)
            .map_err(TimestampBindingError::Temporal)?;
        if self.interval.from_instant() > generation.earliest
            || self.interval.to_instant() < generation.latest
        {
            return Ok(TimestampBinding::Rejected(
                TimestampBindingFailure::Interval,
            ));
        }
        Ok(TimestampBinding::Bound(TimestampPath {
            path: self,
            actor,
            generation,
        }))
    }
}

fn exact(left: &[u8], right: &[u8], execution: &impl Work) -> Result<bool, MemoryError> {
    execution.charge_work(1)?;
    if core::ptr::eq(left, right) {
        return Ok(true);
    }
    if left.len() != right.len() {
        return Ok(false);
    }
    let work = u64::try_from(left.len())
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(work)?;
    Ok(left == right)
}

/// Completed mismatch between an actual token actor and a checked static path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampBindingFailure {
    /// Target is a different original certificate, even if a DN/key hint agrees.
    Certificate,
    /// Signature was checked under a different inherited parameter state.
    EffectiveKey,
    /// The path was not checked over the complete generation interval.
    Interval,
}

/// Inability to bind, separately from a completed source/key/interval mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampBindingError {
    /// Current work refusal before source comparison or metadata traversal.
    Resource(MemoryError),
    /// Existing accuracy/UTC kernel could not establish the generation interval.
    Temporal(TemporalError),
}

/// Privately bound mathematical timestamp and static path for its actual signer.
/// Revocation, required material and application trust still need completion.
pub struct TimestampPath<'view, 'certificate, 'document, N, D, G> {
    path: &'view CheckedPath<'document>,
    actor: &'view CheckedActor<'certificate, 'document, N, D, G>,
    generation: GenerationInterval,
}

impl<'view, 'certificate, 'document, N, D, G>
    TimestampPath<'view, 'certificate, 'document, N, D, G>
{
    /// Same static path that was bound to this token's actual selected signer.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Same complete mathematical token/input receipt and selected key.
    #[must_use]
    pub fn actor(&self) -> &'view CheckedActor<'certificate, 'document, N, D, G> {
        self.actor
    }
    /// Complete generation interval covered by this static path's check.
    #[must_use]
    pub fn generation(&self) -> GenerationInterval {
        self.generation
    }
}

/// Completed binding or explicit mismatch; errors never become a false match.
pub enum TimestampBinding<'view, 'certificate, 'document, N, D, G> {
    /// Same original signer and parameters, with full generation-time coverage.
    Bound(TimestampPath<'view, 'certificate, 'document, N, D, G>),
    /// Completed source/key/interval mismatch.
    Rejected(TimestampBindingFailure),
}

/// Completed static processing, without converting incomplete work to rejection.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "return the checked path and its existing accounted storage without a second heap allocation for enum layout"
)]
pub enum PathOutcome<'a> {
    /// Original chain passed the common static checks.
    Accepted(CheckedPath<'a>),
    /// Common processor completed with its original semantic rejection.
    Rejected(Rejection<'a>),
    /// Explicit local path bounds or deadline stopped processing.
    Incomplete(Truncation),
}

/// Checks an original leaf-first chain and records precisely its member keys.
///
/// The caller selects the trusted anchor, interval, policy and backend through
/// the shared context. Original certificate bytes are neither copied nor
/// reparsed. The common RFC5280/RFC9618 validator runs once; effective-key
/// projection then reuses its ordinary transition kernel, without verifying a
/// signature again. All metadata growth and transitions retain current Work.
///
/// EN319132-1 V1.3.1 §§5.4.2–5.4.5/6.3(aa) make incorporated material depend
/// on the actual validated actors and paths, not the number of carried values.
/// The resulting path supplies original inputs for that census, not a B level.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_path<'a, V: Verify<E>, T: Watch, R: Recognizer<E>, E: Work>(
    chain: &[&'a Certificate<'a>],
    anchor: Anchor<'a>,
    context: &ValidationContext<'a, '_, V, T, R, E>,
) -> BuildResult<PathOutcome<'a>, V::Error, R::Error> {
    let facts = match path::validate(chain, anchor, context)? {
        Validation::Accepted(facts) => facts,
        Validation::Rejected(reason) => return Ok(PathOutcome::Rejected(reason)),
        Validation::Incomplete(reason) => return Ok(PathOutcome::Incomplete(reason)),
    };
    let execution = context.execution;
    let mut members = execution.vector();
    let fail = |reason| {
        structured_pkix::Error::resource(reason, "xades.validationPath", chain[0].span().start)
    };
    members.try_reserve_exact(chain.len()).map_err(fail)?;
    let mut key = WorkingKey::standing(anchor.key());
    for certificate in chain.iter().rev() {
        key = key.subject(certificate, execution)?;
        members
            .try_push(Member { certificate, key })
            .map_err(fail)?;
    }
    Ok(PathOutcome::Accepted(CheckedPath {
        anchor,
        interval: context.interval,
        members: members.into_owned(),
        facts,
    }))
}
