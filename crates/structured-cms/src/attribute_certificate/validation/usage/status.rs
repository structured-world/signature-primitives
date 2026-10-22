//! Closed adapters for original, already evaluated common status evidence.
use super::super::{Profile, Revocation, charge};
use crate::Result;
use structured_asn1::memory::Work;
use structured_pkix::crl::{Coverage, EvidenceSource};
use structured_pkix::ocsp::{BoundEvidence, NonceBinding, UpdateWindow};
use structured_pkix::revocation::{RevocationTarget, TargetKind};
use structured_pkix::temporal::Reading;

/// Status facts for this exact AC and evaluation label. This enum does not
/// accept a caller-created Good assertion as input; Evidence is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Complete common non-revocation evidence for the exact target and time.
    Good,
    /// The authenticated profile explicitly elects RFC5755 §6's never-revoke scheme.
    NoRevAvailable,
    /// No original evidence was supplied for a profile requiring status.
    Missing,
    /// Original evidence belongs to a different target.
    Target,
    /// Evidence was evaluated at another precise label.
    Time,
    /// Evidence contradicts the profile's written never-revoke scheme.
    Scheme,
    /// CRL absence coverage omits at least one required reason.
    Reasons,
    /// OCSP update window does not establish current status.
    Window(UpdateWindow),
    /// The actual request's nonce was not returned or differs.
    Nonce(NonceBinding),
    /// Original adverse OCSP status, retaining Unknown/Revoked/NotIssued.
    Ocsp(structured_pkix::ocsp::Status),
}

/// No external status source. This only completes the never-revoke scheme when
/// that extension was actually accepted in the authenticated original profile.
#[derive(Debug, Clone, Copy)]
pub struct NoStatus;

mod sealed {
    pub trait Sealed {}
}

/// Original status capability implemented only by existing shared evidence and
/// `NoStatus`. It performs association/summary checks, never repeats a signature,
/// `CertID` hash, CRL entry census or temporal evaluation. Caller-selected maximum
/// age, unsolicited-nonce policy and configured responder trust remain external.
pub trait Evidence: sealed::Sealed {
    /// Check actual original target, exact label and established status facts
    /// under the current operation and all sources' producing ceilings.
    fn check<W: Work>(&self, profile: &Profile<'_, '_>, now: Reading, work: &W) -> Result<Status>;
}
impl sealed::Sealed for NoStatus {}
impl Evidence for NoStatus {
    fn check<W: Work>(&self, profile: &Profile<'_, '_>, _: Reading, work: &W) -> Result<Status> {
        charge(
            &work.execution_for(profile.certificate().parser),
            1,
            profile.certificate().element().span().start,
        )?;
        Ok(if profile.revocation() == Revocation::NoRevAvailable {
            Status::NoRevAvailable
        } else {
            Status::Missing
        })
    }
}

fn target<'a, T: RevocationTarget<'a>, W: Work>(
    target: &T,
    profile: &Profile<'_, '_>,
    work: &W,
) -> Result<bool> {
    let left = target.execution_in(work);
    let ac = profile.certificate();
    let right = work.execution_for(ac.parser);
    charge(&left, 1, target.span().start)?;
    charge(&right, 1, ac.element().span().start)?;
    let original = target.encoded();
    let actual = ac.element().as_bytes();
    if target.kind() != TargetKind::Attribute || original.len() != actual.len() {
        return Ok(false);
    }
    if core::ptr::eq(original, actual) {
        return Ok(true);
    }
    charge(&left, original.len() as u64, target.span().start)?;
    charge(&right, actual.len() as u64, ac.element().span().start)?;
    Ok(original == actual)
}

impl<'a, T: RevocationTarget<'a>> sealed::Sealed for Coverage<'_, 'a, T> {}
impl<'a, T: RevocationTarget<'a>> Evidence for Coverage<'_, 'a, T> {
    fn check<W: Work>(&self, profile: &Profile<'_, '_>, now: Reading, work: &W) -> Result<Status> {
        if !target(self.target(), profile, work)? {
            return Ok(Status::Target);
        }
        let execution = work.execution_for(profile.certificate().parser);
        charge(&execution, 3, profile.certificate().element().span().start)?;
        if profile.revocation() != Revocation::Required {
            return Ok(Status::Scheme);
        }
        if self.evaluated_at() != now {
            return Ok(Status::Time);
        }
        // Every contributing source is already scoped/time-qualified and
        // conflict-free. A retained union is not credit for this query's scan.
        charge(
            &execution,
            self.sources().len() as u64,
            profile.certificate().element().span().start,
        )?;
        for absence in self.sources() {
            let admit = |source: structured_pkix::crl::Authenticated<'_, '_>| {
                let signature = source.crl().signature_value();
                charge(
                    &signature.execution_in(&execution),
                    1,
                    signature.span().start,
                )
            };
            match absence.source() {
                EvidenceSource::Complete(source) => admit(source)?,
                EvidenceSource::Delta { base, delta } => {
                    admit(base)?;
                    admit(delta)?;
                }
            }
        }
        Ok(if self.reasons().is_complete() {
            Status::Good
        } else {
            Status::Reasons
        })
    }
}

impl<'a, T: RevocationTarget<'a>> sealed::Sealed for BoundEvidence<'_, 'a, '_, '_, T> {}
impl<'a, T: RevocationTarget<'a>> Evidence for BoundEvidence<'_, 'a, '_, '_, T> {
    fn check<W: Work>(&self, profile: &Profile<'_, '_>, now: Reading, work: &W) -> Result<Status> {
        if !target(self.target(), profile, work)? {
            return Ok(Status::Target);
        }
        let evidence = self.evidence();
        let signature = evidence.source().signed().response().signature_value();
        let execution = signature.execution_in(work);
        charge(&execution, 5, signature.span().start)?;
        if profile.revocation() != Revocation::Required {
            return Ok(Status::Scheme);
        }
        if self.evaluated_at() != now {
            return Ok(Status::Time);
        }
        if evidence.window() != UpdateWindow::Within {
            return Ok(Status::Window(evidence.window()));
        }
        if matches!(
            evidence.nonce(),
            NonceBinding::Missing | NonceBinding::Differs
        ) {
            return Ok(Status::Nonce(evidence.nonce()));
        }
        Ok(
            if matches!(evidence.status(), structured_pkix::ocsp::Status::Good) {
                Status::Good
            } else {
                Status::Ocsp(evidence.status())
            },
        )
    }
}
