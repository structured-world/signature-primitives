//! Original root field preflight before certificate/provider side effects.

use super::{Prepared, UriError, check_uris};
use crate::attributes::{self, AttributeXml};
use crate::binary::BinaryXml;
use crate::properties::{self, ClaimedTime, ClaimedTimeBinding, DateTimeXml};
use crate::scalar::{ScalarXml, UriXml};
use crate::xml::{Access, Xml};
use structured_asn1::memory::Work;

/// Completed root declared-attribute, URI/OID, optional validation-reference
/// syntax and claimed-time checks against exactly this prepared source.
/// The borrow prevents substituting another
/// preparation when composing subsequent certificate/provider checks.
///
/// This is deliberately not whole-schema validity or a baseline level. Open
/// property semantics, binary values, counters, certificate/path/status binding,
/// policy acceptance and timestamp/material completeness remain obligations.
pub struct Fields<'prepared, N, D, G> {
    prepared: &'prepared super::Preparation<N, D, G>,
    claimed_time: ClaimedTime<N, D, G>,
}

impl<N, D, G> Fields<'_, N, D, G> {
    /// Same preparation whose original fields were checked, without reparsing.
    #[must_use]
    pub fn prepared(&self) -> &super::Preparation<N, D, G> {
        self.prepared
    }

    /// Actual schema-qualified zoned claim, not a verified generation instant.
    #[must_use]
    pub fn claimed_time(&self) -> &ClaimedTime<N, D, G> {
        &self.claimed_time
    }
}

/// A failed/incomplete field never creates a successful preflight receipt.
#[derive(Debug)]
pub enum FieldError<E, N, D, G> {
    /// Original root attribute declaration/scalar/source refusal.
    Attributes(attributes::Error<E, N>),
    /// Original URI/OID/policy-qualifier refusal.
    Uri(UriError<E, N>),
    /// Original optional validation-reference scalar/base64/method refusal.
    ValidationReference(crate::validation::ReferenceFieldError<E, N, D, G>),
    /// Original claimed-time source/current-operation refusal.
    Time(properties::ClaimedTimeError<E, N>),
    /// Completed claimed-time interpretation did not establish a zoned claim.
    UnprovenTime {
        /// Original protected `SigningTime`.
        node: N,
        /// Unsupported, malformed and genuinely absent timezone stay distinct.
        cause: properties::ClaimedTimeFailure,
    },
}

/// Root preflight in the XML owner's original identity/error domain.
pub type FieldResult<'prepared, X> = Result<
    Fields<'prepared, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    FieldError<<X as Xml>::Error, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

/// Execute root field preflight in one ordered path, BEFORE certificate hashes,
/// key association, path building or timestamp/provider work. Optional original
/// reference fields use their retained structural model and XML-owned scalar/
/// base64 kernels; this does not compare references against actual artifacts.
/// It invokes the
/// existing field kernels once; no successful caller-supplied flags or copied
/// normalized values can stand in for the original protected source.
///
/// All operations use this current Access/Work, even when preparation survives
/// its earlier parsing operation. Refusal drops temporary OID/attribute scratch;
/// the prepared source and its retained storage account remain unchanged.
pub fn check_fields<'prepared, X, W>(
    prepared: &'prepared Prepared<X>,
    access: &Access<'_, X, W>,
) -> FieldResult<'prepared, X>
where
    X: AttributeXml + ScalarXml + UriXml + DateTimeXml + BinaryXml,
    W: Work,
{
    attributes::check_prepared(prepared, access).map_err(FieldError::Attributes)?;
    check_uris(prepared, access).map_err(FieldError::Uri)?;
    for index in 0..prepared.validation_references().len() {
        access.execution().charge_work(1).map_err(|cause| {
            FieldError::ValidationReference(crate::validation::ReferenceFieldError::Resource {
                node: prepared.bound().containers().signature(),
                cause,
            })
        })?;
        crate::validation::check_reference_fields(&prepared.validation_references()[index], access)
            .map_err(FieldError::ValidationReference)?;
    }
    let claimed_time =
        match properties::check_time(prepared.signed(), access).map_err(FieldError::Time)? {
            ClaimedTimeBinding::Bound(claimed_time) => claimed_time,
            ClaimedTimeBinding::Unproven { node, cause } => {
                return Err(FieldError::UnprovenTime { node, cause });
            }
        };
    Ok(Fields {
        prepared,
        claimed_time,
    })
}
