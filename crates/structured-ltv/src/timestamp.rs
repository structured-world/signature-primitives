//! Retained mathematical timestamp evidence with its original source identity.

use crate::source::Location;
use structured_asn1::memory::{MemoryError, Work};
use structured_cms::timestamp::{BoundUncertainty, Evidence, earliest, latest};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_pkix::{Certificate, path::WorkingKey};

mod obligation;
pub use obligation::{
    ObligationError, RequiredToken, TimestampPathBinding, TimestampPathFailure, TimestampPaths,
    TimestampRequirements, TimestampScope,
};
mod signature;
pub use signature::{
    SignatureTime, SignatureTimeBinding, SignatureTimeError, SignatureTimeFailure,
    SignatureTimeResult, signature_time, signature_time_path,
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
/// The format layer constructs it only from its own complete token check over
/// that input; this is not a TSA trust decision or a level.
#[derive(Debug)]
pub struct Verified<N, D, G> {
    token: Location<N, D, G>,
    signature: N,
    property: N,
    purpose: Purpose,
    evidence: Evidence,
}

/// Successful mathematical timestamp check with its actual selected signer.
///
/// The certificate and effective key come from the same complete-check context,
/// not a later caller-supplied association. This still establishes no TSA path,
/// status or trust. Certificate/key borrows need not retain the provider or
/// temporary context.
pub struct CheckedActor<'certificate, 'document, N, D, G> {
    verified: Verified<N, D, G>,
    certificate: &'certificate Certificate<'document>,
    key: WorkingKey<'document>,
}

impl<'certificate, 'document, N, D, G> CheckedActor<'certificate, 'document, N, D, G> {
    /// Binds evidence to the certificate and effective key its check used.
    #[must_use]
    pub fn new(
        verified: Verified<N, D, G>,
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
    pub fn verified(&self) -> &Verified<N, D, G> {
        &self.verified
    }

    /// Ends the borrowed signer association while moving independent evidence.
    /// This performs no copy/allocation and makes no subsequent TSA claim.
    #[must_use]
    pub fn into_verified(self) -> Verified<N, D, G> {
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

impl<N, D, G> Verified<N, D, G> {
    /// Retains a complete token check with the original identity of its input.
    ///
    /// `token` is the original token enclosure, `signature` the signature whose
    /// input was covered, `property` the timestamp property or attribute and
    /// `purpose` the kind of input selected for the check.
    #[must_use]
    pub fn new(
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
        }
    }
}

impl<N: Copy, D: Copy, G: Copy> Verified<N, D, G> {
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
    /// RFC3161/UTC arithmetic, funded by the current operation. Missing accuracy
    /// remains uncertainty, never an implicitly exact time. Caller policy is
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
            self.evidence.facts().accuracy(),
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
    // earliest uses one shift; latest uses upper_bound + one shift. Each
    // shift has three binary partition searches, with at most bit_length(n)+1
    // predicate calls apiece. 48 also admits fixed per-shift/scalar inspections.
    // Table construction/validation belongs to its caller, not this lookup.
    let count = utc.transitions().len();
    let bits = usize::BITS - count.leading_zeros();
    let cost = 48 + 9 * (u64::from(bits) + 1);
    execution
        .charge_work(cost)
        .map_err(TemporalError::Resource)?;
    let earliest = earliest(reading, accuracy, utc).map_err(TemporalError::Uncertain)?;
    let latest = latest(reading, accuracy, utc).map_err(TemporalError::Uncertain)?;
    Ok(Interval { earliest, latest })
}

#[cfg(test)]
mod tests;
