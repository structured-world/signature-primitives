//! RFC3161 timestamp facts, independent of application timelines and trust.

use structured_pkix::temporal::{Instant, LeapTable, Reading, Uncertainty};

mod accuracy;
pub use accuracy::{AccuracyReading, Component, ComponentReading, DeviationError, DeviationReason};
mod imprint;
pub use imprint::{HashAlgorithmReading, MessageImprint};
mod imprint_check;
pub use imprint_check::{ImprintAgreement, ImprintError};
mod requested;
pub use requested::{ImprintOperand, RequestAgreement, RequestImprintError, RequestedContentError};
mod extension;
pub use extension::{RecognitionError, TokenExtension, TokenExtensions};
mod info;
pub use info::{IntegerField, TokenInfo};
mod tsa;
pub use tsa::TsaReading;
mod token;
pub use token::{InfoError, Token};
mod timeliness;
pub use timeliness::{RequestWindow, Timeliness, timeliness};
mod request;
pub use request::Request;
mod request_extensions;
mod request_fields;
pub use request_fields::{RequestFieldError, RequestFields};
mod authority;
mod carried;
mod signature;
pub use authority::{AuthorityError, AuthorityFacts, AuthoritySource, TsaIdentity, TsaUsage};
pub use signature::{SignatureError, TokenSignature};
mod check;
pub use check::{
    CheckContext, CheckError, CheckedTimestamp, Evidence, EvidenceCopyError, InfoCheckError,
    MappedCheckError, Requested,
};
mod retained;
pub use retained::{RetainedFacts, RetainedImprint};

pub(crate) fn record<W: structured_asn1::memory::Work>(
    faults: &mut structured_asn1::memory::OwnedVec<crate::Error, W>,
    error: crate::Error,
) -> crate::Result<()> {
    if error.is_terminal() {
        return Err(error);
    }
    let at = error.offset();
    let field = error.field();
    faults
        .try_push(error)
        .map_err(|reason| crate::Error::resource(reason, field, at))
}

/// Accuracy components as read, with zero for an omitted component.
///
/// The scalar model preserves readable malformed components for inspection;
/// constructing it does not establish ASN.1 conformance or a successful proof.
/// A missing entire Accuracy is represented separately by None. RFC3161
/// §2.4.2 allows external policy to supply accuracy, but absence in a token
/// alone never establishes a zero deviation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accuracy {
    seconds: u64,
    millis: u64,
    micros: u64,
}

impl Accuracy {
    /// Original scalar components, without narrowing or syntax repair.
    #[must_use]
    pub const fn new(seconds: u64, millis: u64, micros: u64) -> Self {
        Self {
            seconds,
            millis,
            micros,
        }
    }
    /// Whole seconds as read.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.seconds
    }
    /// Milliseconds as read, zero when omitted.
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.millis
    }
    /// Microseconds as read, zero when omitted.
    #[must_use]
    pub const fn micros(self) -> u64 {
        self.micros
    }
    /// Exact total deviation, including retained malformed scalar components.
    #[must_use]
    pub fn nanos(self) -> u128 {
        // All three parts are below 2^64; this sum is below 2^95.
        u128::from(self.seconds) * 1_000_000_000
            + u128::from(self.millis) * 1_000_000
            + u128::from(self.micros) * 1_000
    }
}

/// Why the timestamp facts cannot establish a temporal endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundUncertainty {
    /// No accuracy was stated by the token or supplied as authenticated policy.
    AccuracyUnstated,
    /// Existing UTC arithmetic cannot place the source or destination.
    Utc(Uncertainty),
}

/// Lower endpoint of the authority's generation-time accuracy interval.
/// This says nothing about when the imprinted document was signed.
pub fn earliest(
    reading: Reading,
    accuracy: Option<Accuracy>,
    utc: &LeapTable<'_>,
) -> Result<Instant, BoundUncertainty> {
    let accuracy = accuracy.ok_or(BoundUncertainty::AccuracyUnstated)?;
    shift(reading.start(), accuracy, true, utc)
}

/// Upper endpoint, retaining subnanosecond rounding and supplied leap facts.
/// This is a factual interval calculation, not signature or trust validation.
pub fn latest(
    reading: Reading,
    accuracy: Option<Accuracy>,
    utc: &LeapTable<'_>,
) -> Result<Instant, BoundUncertainty> {
    // RFC3161 §2.4.2 allows a policy to state omitted accuracy, but the
    // absent token field alone supplies none. Prioritize this API limitation
    // before attempting rounding with independently incomplete UTC facts.
    // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
    let accuracy = accuracy.ok_or(BoundUncertainty::AccuracyUnstated)?;
    let upper = reading.upper_bound(utc).map_err(BoundUncertainty::Utc)?;
    shift(upper, accuracy, false, utc)
}

fn shift(
    at: Instant,
    accuracy: Accuracy,
    earlier: bool,
    utc: &LeapTable<'_>,
) -> Result<Instant, BoundUncertainty> {
    let nanos = i128::try_from(accuracy.nanos())
        .map_err(|_| BoundUncertainty::Utc(Uncertainty::OutOfRange))?;
    utc.shift(at, if earlier { -nanos } else { nanos })
        .map_err(BoundUncertainty::Utc)
}
