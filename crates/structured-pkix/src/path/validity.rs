//! Explicit certificate path validity selection and original issuance dates.

use crate::crl::Reason;
use crate::error::Located;
use crate::temporal::{Instant, LeapTable, Reading, Uncertainty};
use crate::{Certificate, Error, ErrorCode, Result, Time, oid};
use structured_asn1::{
    Tag,
    memory::{MemoryError, Work},
    universal,
};

/// Whether a recorded CA revocation permits the Chain issuance exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceEffect {
    /// This revocation leaves the earlier issuance intact.
    Preserved,
    /// The revocation does not qualify for the issuance exception.
    NoException,
    /// The supplied UTC facts cannot establish the required date ordering.
    Uncertain(Uncertainty),
}

/// Assess the Chain exception for an already applicable CA revocation.
///
/// Common PKI v2.0 Part 9 §6, applied by EN 319 102-1 V1.4.1 §5.2.6.4 step 4,
/// permits the exception only for a known reason that preserves the reliability
/// of previously issued certificates. The recorded revocation must be strictly
/// after issuance. Only a potential exception needs UTC qualification.
/// Authentication, freshness and applicability at the validation date remain
/// obligations of the caller.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
/// <https://www.bundesnetzagentur.de/EVD/SharedDocuments/Downloads/QES/Common_PKI_v2.0_02.pdf?__blob=publicationFile&v=1>
///
/// # Errors
///
/// Returns a resource error if the work budget cannot qualify the dates.
pub fn chain_issuance_effect<W: Work>(
    revoked_at: Instant,
    reason: Option<Reason>,
    issued: Reading,
    utc: &LeapTable<'_>,
    work: &W,
) -> core::result::Result<IssuanceEffect, MemoryError> {
    // The recorded date has nanosecond precision. When its label exceeds
    // the issuance label, it also exceeds any subnanosecond remainder.
    if revoked_at <= issued.start()
        || !matches!(
            reason,
            Some(
                Reason::AffiliationChanged
                    | Reason::Superseded
                    | Reason::CessationOfOperation
                    | Reason::PrivilegeWithdrawn
            )
        )
    {
        return Ok(IssuanceEffect::NoException);
    }
    let bits = usize::BITS - utc.transitions().len().leading_zeros();
    work.charge_work(2 * (8 + 3 * (u64::from(bits) + 1)))?;
    for label in [revoked_at, issued.start()] {
        if let Err(cause) = utc.shift(label, 0) {
            return Ok(IssuanceEffect::Uncertain(cause));
        }
    }
    Ok(IssuanceEffect::Preserved)
}

/// Time at which each issuer in the prospective path must be valid.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ValidityModel {
    /// Each issuer must cover the entire validation interval.
    #[default]
    Shell,
    /// Each issuer must have been valid when it issued its immediate subordinate.
    Chain,
}

/// When to enforce validity of the path target itself.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TargetValidity {
    /// Require the target to cover the entire validation interval.
    #[default]
    Required,
    /// Leave the signing-certificate time check to EN 319 102-1 §5.2.6.4 step 7.
    /// The returned path is only static evidence for that later check.
    Deferred,
}

/// Explicit time rules for a path check. The default is RFC 5280 shell validity,
/// including the target. An explicit trust anchor is outside the path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ValidityPolicy {
    /// Issuing-certificate rule.
    pub model: ValidityModel,
    /// Target-certificate rule.
    pub target: TargetValidity,
}

impl ValidityPolicy {
    /// Select the validity model for `AdES` signing-certificate validation.
    /// EN 319 102-1 V1.4.1 §5.2.6.4 separates steps 4 and 7.
    #[must_use]
    pub const fn ades(model: ValidityModel) -> Self {
        Self {
            model,
            target: TargetValidity::Deferred,
        }
    }
}

/// Issuance time of the original, signed certificate for chain validity.
///
/// Common PKI v2.0 Part 9 §6 uses `DateOfCertGen` when present and the
/// certificate's `notBefore` otherwise. An unreadable written extension has
/// a located error. It never selects the absent-extension rule.
pub fn issuance_time<W: Work>(certificate: &Certificate<'_>, execution: &W) -> Result<Time> {
    // Common PKI v2.0 Part 9 Tables 1 and 3 specify a noncritical
    // GeneralizedTime with seconds and Z, without fractional seconds.
    // https://www.bundesnetzagentur.de/EVD/SharedDocuments/Downloads/QES/Common_PKI_v2.0_02.pdf?__blob=publicationFile&v=1
    const FIELD: &str = "certificate.extensions.dateOfCertGen";
    let work = certificate.execution_in(execution);
    work.charge_work(1)
        .map_err(|cause| Error::resource(cause, FIELD, certificate.span().start))?;
    let Some(extension) = certificate
        .tbs()
        .extensions()
        .get(oid::DATE_OF_CERT_GEN, &work)?
    else {
        return Ok(certificate.tbs().validity().not_before());
    };
    if extension.is_critical() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            extension.span().start,
        ));
    }
    let mut reader = extension.reader_scoped(execution).field(FIELD)?;
    let value = reader
        .expect(Tag::primitive(universal::GENERALIZED_TIME))
        .field(FIELD)?;
    if !reader.is_empty() {
        return Err(Error::new(ErrorCode::TrailingData, FIELD, reader.offset()));
    }
    Time::read(&reader, &value, FIELD)
}
