//! Compose signature/issuer scope with requested target, extension and time facts.

use super::{
    ExtensionProcessing, Lookup, NonceBinding, RequestNonce, ScopedResponse, SingleResponse,
    UpdateWindow,
};
use crate::algorithm::digest::AsnDigest;
use crate::error::{CallbackResult, Result};
use crate::temporal::{LeapTable, Reading};
use crate::{Certificate, Error};
use structured_asn1::memory::{Memory, MemoryError, Work};
use structured_asn1::{Oid, Span};

/// Actual caller request facts, never inferred from the received response.
pub struct Request<'p, 'a> {
    /// Certificate identified by the actual request and authenticated issuer path.
    pub target: &'p Certificate<'a>,
    /// Actual sent nonce, not a newly generated replacement.
    pub nonce: Option<RequestNonce<'p>>,
    /// Optional expected exact signer certificate chosen by the caller. Absent
    /// binding is reported explicitly rather than counted as a match.
    pub intended_signer: Option<&'p Certificate<'a>>,
}

/// Current temporal/resource facts; maximum age and clock-skew policy stay outside.
pub struct Evaluation<'p, E: Work = Memory> {
    /// Actual caller-supplied current label, retaining subnanosecond precision.
    pub now: Reading,
    /// Caller-authenticated UTC correction evidence and explicit coverage.
    pub utc: &'p LeapTable<'p>,
    /// Current operation's shared work and storage domain.
    pub execution: &'p E,
}

/// Whether this evidence is bound to the caller's exact intended signer input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientBinding {
    /// Caller did not supply an exact signer; no such claim is made.
    NotSpecified,
    /// Authenticated actual signer matches the supplied exact certificate.
    Matches,
}

/// Composed original evidence, still not final application acceptance. Read its
/// authority source for pending delegate revocation, and apply nonce, maximum
/// age, recipient and time-uncertainty policy before interpreting status.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'r, 'a> {
    source: ScopedResponse<'r, 'a>,
    assertion: &'r SingleResponse<'a>,
    window: UpdateWindow,
    nonce: NonceBinding,
    recipient: RecipientBinding,
    revocation_time: Option<crate::time::Relation>,
    status: super::Status,
    archive_cutoff: Option<Reading>,
}

impl<'r, 'a> Evidence<'r, 'a> {
    /// Signature and explicit issuer-scope provenance.
    #[must_use]
    pub fn source(self) -> ScopedResponse<'r, 'a> {
        self.source
    }
    /// Selected original assertion, with every uninterpreted noncritical value.
    #[must_use]
    pub fn assertion(self) -> &'r SingleResponse<'a> {
        self.assertion
    }
    /// Update-window relation, not a maximum-age decision.
    #[must_use]
    pub fn window(self) -> UpdateWindow {
        self.window
    }
    /// Actual request/response nonce relation.
    #[must_use]
    pub fn nonce(self) -> NonceBinding {
        self.nonce
    }
    /// Exact intended signer binding, when requested.
    #[must_use]
    pub fn recipient(self) -> RecipientBinding {
        self.recipient
    }

    /// UTC-qualified recorded revocation time when this assertion is revoked.
    #[must_use]
    pub fn revocation_time(self) -> Option<crate::time::Relation> {
        self.revocation_time
    }

    /// Assertion status under the response's extended revoked definition,
    /// including [`super::Status::NotIssued`].
    #[must_use]
    pub fn status(self) -> super::Status {
        self.status
    }

    /// The assertion's archive cutoff, retaining decimal subnanosecond precision.
    #[must_use]
    pub fn archive_cutoff(self) -> Option<Reading> {
        self.archive_cutoff
    }
}

/// Target processing outcome, without turning missing/unsupported into Good.
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::large_enum_variant,
    reason = "retain source/key/time facts by value rather than allocate a box per target merely to discriminate the result"
)]
pub enum TargetEvidence<'r, 'a> {
    /// Identity and supported extension semantics completed; policy facts remain.
    Evidence(Evidence<'r, 'a>),
    /// Actual signer differs from the caller's intended exact signer.
    UnexpectedSigner,
    /// Identity lookup did not yield one usable assertion.
    Lookup(Lookup<'r, 'a>),
    /// Response-wide or selected-assertion critical demand cannot be processed.
    UnsupportedCritical {
        /// Original unsupported demand identifier.
        kind: Oid<'a>,
        /// Original location.
        span: Span,
    },
}

/// Complete target processing together with the original requested certificate.
/// Target and response lifetimes are independent; no temporary request,
/// evaluation context, provider or execution wrapper is retained.
#[derive(Debug)]
pub struct TargetReading<'target, 'request, 'response, 'source> {
    target: &'target Certificate<'request>,
    evaluated_at: Reading,
    outcome: TargetEvidence<'response, 'source>,
}

impl<'target, 'request, 'response, 'source> TargetReading<'target, 'request, 'response, 'source> {
    /// Original actual target, not another certificate with a matching hint.
    #[must_use]
    pub fn target(&self) -> &'target Certificate<'request> {
        self.target
    }
    /// Exact label used by the same update-window/revocation-time processing.
    #[must_use]
    pub fn evaluated_at(&self) -> Reading {
        self.evaluated_at
    }
    /// Original complete result, including lookup and critical-demand failures.
    #[must_use]
    pub fn outcome(&self) -> &TargetEvidence<'response, 'source> {
        &self.outcome
    }
    /// Bind established mechanism facts to the target used by this invocation.
    /// Status, temporal uncertainty, nonce and delegated-responder requirements
    /// remain exactly as reported; this does not mean the status is Good.
    #[must_use]
    pub fn evidence(&self) -> Option<BoundEvidence<'target, 'request, 'response, 'source>> {
        match self.outcome {
            TargetEvidence::Evidence(evidence) => Some(BoundEvidence {
                target: self.target,
                evaluated_at: self.evaluated_at,
                evidence,
            }),
            _ => None,
        }
    }
    /// Move the original outcome when the caller does not retain target binding.
    #[must_use]
    pub fn into_outcome(self) -> TargetEvidence<'response, 'source> {
        self.outcome
    }
}

/// Privately bound target and facts from the same completed common evaluation.
/// This association cannot be created from an unrelated certificate and result.
#[derive(Debug, Clone, Copy)]
pub struct BoundEvidence<'target, 'request, 'response, 'source> {
    target: &'target Certificate<'request>,
    evaluated_at: Reading,
    evidence: Evidence<'response, 'source>,
}

impl<'target, 'request, 'response, 'source> BoundEvidence<'target, 'request, 'response, 'source> {
    /// Original requested certificate whose identity the common kernel matched.
    #[must_use]
    pub fn target(self) -> &'target Certificate<'request> {
        self.target
    }
    /// Original evaluation label; the caller cannot relabel status in time.
    #[must_use]
    pub fn evaluated_at(self) -> Reading {
        self.evaluated_at
    }
    /// Same original mechanism facts, without repeating identity hashes.
    #[must_use]
    pub fn evidence(self) -> Evidence<'response, 'source> {
        self.evidence
    }
}

fn exact_signer<E: Work>(
    left: &Certificate<'_>,
    right: &Certificate<'_>,
    execution: &E,
    at: u64,
) -> Result<bool> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let work = u64::try_from(left.len().max(right.len()))
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, "ocspResponse.recipient", at))?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, "ocspResponse.recipient", at))?;
    Ok(left == right)
}

impl<'r, 'a> ScopedResponse<'r, 'a> {
    /// Run the same complete target-processing kernel once while retaining its
    /// original requested certificate. No hashing, parsing or allocation is
    /// repeated to recover provenance later. Failures retain their original
    /// result/cause; no positive target binding is returned for a lookup failure.
    pub fn evaluate_with_target<'target, 'request, 'd, D: AsnDigest<'d> + ?Sized, E: Work>(
        self,
        request: &Request<'target, 'request>,
        time: &Evaluation<'_, E>,
        digest: &'d D,
    ) -> CallbackResult<TargetReading<'target, 'request, 'r, 'a>, D::Error> {
        let outcome = self.evaluate(request, time, digest)?;
        Ok(TargetReading {
            target: request.target,
            evaluated_at: time.now,
            outcome,
        })
    }

    /// Evaluate the actual request against this issuer-scoped signed response.
    /// RFC6960 §3.2 requires identity, signer, authorization and temporal checks;
    /// this operation composes mechanism facts without choosing caller policy.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-3.2>
    pub fn evaluate<'d, D: AsnDigest<'d> + ?Sized, E: Work>(
        self,
        request: &Request<'_, '_>,
        time: &Evaluation<'_, E>,
        digest: &'d D,
    ) -> CallbackResult<TargetEvidence<'r, 'a>, D::Error> {
        let execution = time.execution;
        let response = self.signed().response();
        let recipient = match request.intended_signer {
            None => RecipientBinding::NotSpecified,
            Some(expected) => {
                if !exact_signer(
                    self.signed().signer(),
                    expected,
                    execution,
                    response.span().start,
                )? {
                    return Ok(TargetEvidence::UnexpectedSigner);
                }
                RecipientBinding::Matches
            }
        };
        let processed = response.process_extensions(execution)?;
        if let ExtensionProcessing::Unsupported { kind, span } = processed.processing {
            return Ok(TargetEvidence::UnsupportedCritical { kind, span });
        }
        let assertion = match self.find(request.target, digest, execution)? {
            Lookup::Found(assertion) => assertion,
            outcome => return Ok(TargetEvidence::Lookup(outcome)),
        };
        let single = assertion.process_extensions(execution)?;
        if let ExtensionProcessing::Unsupported { kind, span } = single.processing {
            return Ok(TargetEvidence::UnsupportedCritical { kind, span });
        }
        let status = super::retention::status(assertion, processed.extended_revoke, execution)?;
        let nonce = super::nonce::bind(
            request.nonce,
            processed.nonce,
            execution,
            response.span().start,
        )?;
        let window = assertion.update_window(time.now, time.utc, execution)?;
        let revocation_time = assertion.revocation_relation(time.now, time.utc, execution)?;
        Ok(TargetEvidence::Evidence(Evidence {
            source: self,
            assertion,
            nonce,
            window,
            recipient,
            revocation_time,
            status,
            archive_cutoff: single.archive_cutoff,
        }))
    }
}

#[cfg(test)]
mod tests;
