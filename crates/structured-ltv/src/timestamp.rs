//! Retained mathematical timestamp evidence with its original source identity.

use crate::source::Location;
use core::marker::PhantomData;
use structured_asn1::memory::{MemoryError, Work};
use structured_cms::timestamp::{BoundUncertainty, Evidence};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_pkix::{Certificate, path::WorkingKey};

mod obligation;
pub use obligation::{
    ObligationError, PathBindingResult, RequiredToken, TimestampPathBinding, TimestampPathFailure,
    TimestampPaths, TimestampRequirements, TimestampScope,
};
mod signature;
pub use signature::{
    SignatureTime, SignatureTimeBinding, SignatureTimeError, SignatureTimeFailure,
    SignatureTimeResult, existence_time_path, signature_time, signature_time_path,
};

/// What a timestamp proves the existence of.
///
/// Every `AdES` format writes these four kinds under its own names (`XAdES`
/// properties, `CAdES` attributes, `PAdES` document timestamps); the format layer
/// maps its own input role onto one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Signed data objects, before the signature was produced.
    Content,
    /// The signature value.
    Signature,
    /// The signature and its validation-data references.
    ValidationData,
    /// The signature, its validation material and earlier timestamps.
    Archive,
}

/// Successfully checked token covering the input its format layer selected.
///
/// Only the holder of issuer `I` constructs it, from its own complete token
/// check over that input (see [`crate`] on issuers); this is not a TSA trust
/// decision or a level.
#[derive(Debug)]
pub struct Verified<N, D, G, I> {
    token: Location<N, D, G>,
    signature: N,
    property: N,
    purpose: Purpose,
    evidence: Evidence,
    issuer: PhantomData<I>,
}

/// Successful mathematical timestamp check with its actual selected signer.
///
/// The certificate and effective key come from the same complete-check context,
/// not a later caller-supplied association; only the holder of issuer `I`
/// constructs it. This still establishes no TSA path, status or trust.
/// Certificate/key borrows need not retain the provider or temporary context.
pub struct CheckedActor<'certificate, 'document, N, D, G, I> {
    verified: Verified<N, D, G, I>,
    certificate: &'certificate Certificate<'document>,
    key: WorkingKey<'document>,
}

impl<'certificate, 'document, N, D, G, I> CheckedActor<'certificate, 'document, N, D, G, I> {
    /// Binds evidence to the certificate and effective key its check used.
    /// Requiring the issuer value keeps a caller of the format from
    /// associating the evidence with another certificate.
    #[must_use]
    pub fn new(
        _issuer: I,
        verified: Verified<N, D, G, I>,
        certificate: &'certificate Certificate<'document>,
        key: WorkingKey<'document>,
    ) -> Self {
        Self {
            verified,
            certificate,
            key,
        }
    }

    /// Actual candidate used for the successful token signature/ESS checks.
    #[must_use]
    pub fn certificate(&self) -> &'certificate Certificate<'document> {
        self.certificate
    }

    /// Actual effective parameters supplied to that same selected provider.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'document> {
        self.key
    }

    /// Independently retained mathematical evidence with original identity.
    #[must_use]
    pub fn verified(&self) -> &Verified<N, D, G, I> {
        &self.verified
    }

    /// Ends the borrowed signer association while moving independent evidence.
    /// This performs no copy/allocation and makes no subsequent TSA claim.
    #[must_use]
    pub fn into_verified(self) -> Verified<N, D, G, I> {
        self.verified
    }
}

/// Factual generation-time interval, not the document's signing-time interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// Earliest generation consistent with the authority's stated accuracy.
    pub earliest: Instant,
    /// Latest generation, including any subnanosecond rounding.
    pub latest: Instant,
}

/// Complete timestamp-generation interval relative to an explicit event label.
/// This temporal fact does not authenticate that event or associate a
/// certificate/status response with the timestamp's actual signing actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryRelation {
    /// Every possible generation instant is strictly before the event.
    Before,
    /// The authority stated an exact generation instant equal to the event.
    At,
    /// Every possible generation instant is strictly after the event.
    After,
    /// The complete interval touches or straddles the event; strict ordering
    /// cannot be established. Equality of just one endpoint is insufficient.
    Overlaps,
}

/// Current execution refusal is distinct from incomplete authenticated UTC facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalError {
    /// Admission failed before UTC table lookup or arithmetic.
    Resource(MemoryError),
    /// Existing RFC3161/UTC kernel could not establish a complete interval.
    Uncertain(BoundUncertainty),
}

impl<N, D, G, I> Verified<N, D, G, I> {
    /// Retains a complete token check with the original identity of its input.
    ///
    /// `token` is the original token enclosure, `signature` the signature whose
    /// input was covered, `property` the timestamp property or attribute and
    /// `purpose` the kind of input selected for the check. Requiring the
    /// issuer value keeps a caller of the format from relabeling evidence.
    #[must_use]
    pub fn new(
        _issuer: I,
        token: Location<N, D, G>,
        signature: N,
        property: N,
        purpose: Purpose,
        evidence: Evidence,
    ) -> Self {
        Self {
            token,
            signature,
            property,
            purpose,
            evidence,
            issuer: PhantomData,
        }
    }
}

impl<N: Copy, D: Copy, G: Copy, I> Verified<N, D, G, I> {
    /// Original token enclosure, not an offset in its decoded ASN.1 source.
    #[must_use]
    pub fn token(&self) -> Location<N, D, G> {
        self.token
    }
    /// Actual selected signature whose original input was covered.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original timestamp property, independently of its encapsulated token.
    #[must_use]
    pub fn property(&self) -> N {
        self.property
    }
    /// Kind of input selected during checking.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Independently retained token facts and original ASN.1 source projection.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Moves retained evidence without a second allocation or deep copy.
    #[must_use]
    pub fn into_evidence(self) -> Evidence {
        self.evidence
    }

    /// Derives the complete authority generation interval using the existing
    /// RFC3161/UTC arithmetic, funded by the current operation. The effective
    /// deviation includes explicit TSA-policy accuracy retained by the checker;
    /// absence from both sources remains uncertainty. Caller policy is
    /// responsible for authenticating the supplied leap table.
    ///
    /// EN319132-1 §6.3(o) requires the signature timestamp to precede signer
    /// revocation/expiry; its bare genTime is insufficient when accuracy is
    /// stated. This helper supplies endpoints, not path/status acceptance.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn interval<W: Work>(
        &self,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<Interval, TemporalError> {
        interval(
            self.evidence.facts().gen_time(),
            self.evidence
                .facts()
                .effective_accuracy()
                .map(structured_cms::timestamp::EffectiveAccuracy::accuracy),
            utc,
            execution,
        )
    }

    /// Compares the complete generation interval to an explicit event label.
    ///
    /// This never substitutes the bare genTime or a claimed signing time for
    /// the interval, nor decides certificate/status/trust policy. Missing
    /// accuracy, invalid leap labels and absent UTC coverage remain
    /// uncertainty; all table work is admitted through current execution.
    pub fn relation<W: Work>(
        &self,
        boundary: Instant,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<BoundaryRelation, TemporalError> {
        relation(self.interval(utc, execution)?, boundary, utc, execution)
    }
}

fn relation<W: Work>(
    interval: Interval,
    boundary: Instant,
    utc: &LeapTable<'_>,
    execution: &W,
) -> Result<BoundaryRelation, TemporalError> {
    let bits = usize::BITS - utc.transitions().len().leading_zeros();
    execution
        .charge_work(16 + 3 * (u64::from(bits) + 1))
        .map_err(TemporalError::Resource)?;
    utc.shift(boundary, 0)
        .map_err(|cause| TemporalError::Uncertain(BoundUncertainty::Utc(cause)))?;
    Ok(if interval.latest < boundary {
        BoundaryRelation::Before
    } else if interval.earliest > boundary {
        BoundaryRelation::After
    } else if interval.earliest == boundary && interval.latest == boundary {
        BoundaryRelation::At
    } else {
        BoundaryRelation::Overlaps
    })
}

fn interval<W: Work>(
    reading: structured_pkix::temporal::Reading,
    accuracy: Option<structured_cms::timestamp::Accuracy>,
    utc: &LeapTable<'_>,
    execution: &W,
) -> Result<Interval, TemporalError> {
    let interval = structured_cms::timestamp::interval_in(reading, accuracy, utc, execution)
        .map_err(|cause| match cause {
            structured_cms::timestamp::IntervalError::Resource(cause) => {
                TemporalError::Resource(cause)
            }
            structured_cms::timestamp::IntervalError::Uncertain(cause) => {
                TemporalError::Uncertain(cause)
            }
        })?;
    Ok(Interval {
        earliest: interval.earliest,
        latest: interval.latest,
    })
}

#[cfg(test)]
mod tests;
