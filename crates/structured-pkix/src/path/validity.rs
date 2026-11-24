//! Explicit certificate path validity selection and original issuance dates.

use crate::error::Located;
use crate::{Certificate, Error, ErrorCode, Result, Time, oid};
use structured_asn1::{Tag, memory::Work, universal};

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
