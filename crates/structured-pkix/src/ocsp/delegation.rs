//! Direct responder delegation uses the common supplied-path processor.

use crate::error::{Located, Result};
use crate::extension::{Extension, Recognizer};
use crate::path::{
    self, Anchor, BuildResult, EffectiveAnchor, Validation, ValidationContext, Verify, Watch,
    WorkingKey,
};
use crate::{Certificate, oid};
use structured_asn1::memory::Memory;
use structured_asn1::{Tag, universal};

/// The responder certificate's revocation-checking fact, not a trust decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderRevocation {
    /// A valid NULL-valued id-pkix-ocsp-nocheck exemption covers this certificate.
    NoCheck,
    /// No exemption; checking/acceptance remains the caller's explicit policy.
    Unresolved,
}

pub(crate) fn read_no_check(extension: &Extension<'_>, execution: &Memory) -> Result<()> {
    const FIELD: &str = "extensions.ocspNoCheck";
    let mut reader = extension.reader(execution).field(FIELD)?;
    let element = reader
        .expect(Tag::primitive(universal::NULL))
        .field(FIELD)?;
    reader.null(&element).field(FIELD)?;
    // DER primitive NULL must have empty contents; the producing Reader
    // enforces that value rule. NoCheck is not any arbitrary one-value schema.
    super::end(&reader, FIELD)
}

/// Completed OCSP-specific purpose/source refusal, separate from path rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationFailure {
    /// Effective issuing key does not belong to the supplied issuer certificate.
    IssuerKeyBinding,
    /// The delegate lacks explicit id-kp-OCSPSigning; anyExtendedKeyUsage is not it.
    SigningPurpose,
    /// Present keyUsage allows neither applicable object-signing use.
    KeyUsage,
}

/// Accepted local delegation facts. Neither the issuer's original-root trust
/// nor the responder's unresolved revocation is silently established here.
#[derive(Debug, Clone, Copy)]
pub struct DelegateFacts<'a> {
    responder: &'a Certificate<'a>,
    issuer: &'a Certificate<'a>,
    key: WorkingKey<'a>,
    revocation: ResponderRevocation,
}

impl<'a> DelegateFacts<'a> {
    /// Actual directly issued responder certificate.
    #[must_use]
    pub fn responder(self) -> &'a Certificate<'a> {
        self.responder
    }
    /// Caller-selected, already authenticated target issuer.
    #[must_use]
    pub fn issuer(self) -> &'a Certificate<'a> {
        self.issuer
    }
    /// Responder effective key projected by the common path processor.
    #[must_use]
    pub fn key(self) -> WorkingKey<'a> {
        self.key
    }
    /// Revocation exemption or unresolved checking requirement.
    #[must_use]
    pub fn revocation(self) -> ResponderRevocation {
        self.revocation
    }
}

/// Completed local delegation result; resource/provider failures stay Result.
#[derive(Debug)]
pub enum Delegation<'a> {
    /// Direct local path, explicit OCSP purpose and keyUsage established.
    Accepted(DelegateFacts<'a>),
    /// Completed purpose/source rejection.
    Rejected(DelegationFailure),
    /// Common static path processor rejected this responder.
    PathRejected(path::Rejection<'a>),
    /// Local path bounds prevented a completed check.
    Incomplete(path::Truncation),
}

/// Check direct delegation from the *actual*, already authenticated target
/// issuing key. RFC6960 §4.2.2.2 requires the same issuing key, not merely the
/// same CA name; the caller binds this issuer to its authenticated target path.
/// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
///
/// The one-link local path uses every common static check and the issuer's own
/// name constraints. It does not resume original-root ancestor constraints;
/// callers requiring those must validate the complete responder path as well.
/// `context.interval` is the caller's response-acceptance interval, not an
/// untrusted producedAt clock. A noCheck exemption never skips this validity.
pub fn check_delegate<'a, V: Verify, W: Watch, R: Recognizer>(
    responder: &'a Certificate<'a>,
    issuer: &'a Certificate<'a>,
    issuing_key: WorkingKey<'a>,
    context: &ValidationContext<'a, '_, V, W, R>,
) -> BuildResult<Delegation<'a>, V::Error, R::Error> {
    let execution = context.execution;
    let Some(anchor) =
        EffectiveAnchor::bind(Anchor::from_certificate(issuer), issuing_key, execution)?
    else {
        return Ok(Delegation::Rejected(DelegationFailure::IssuerKeyBinding));
    };
    let extensions = responder.tbs().extensions();
    let Some(purposes) = extensions.extended_key_usage(execution)? else {
        return Ok(Delegation::Rejected(DelegationFailure::SigningPurpose));
    };
    if !purposes.has(oid::OCSP_SIGNING, execution)? {
        return Ok(Delegation::Rejected(DelegationFailure::SigningPurpose));
    }
    if !super::authority::signing_usage(responder, execution)? {
        return Ok(Delegation::Rejected(DelegationFailure::KeyUsage));
    }
    let revocation = match extensions.get(oid::OCSP_NO_CHECK, execution)? {
        Some(extension) => {
            read_no_check(extension, execution)?;
            ResponderRevocation::NoCheck
        }
        None => ResponderRevocation::Unresolved,
    };
    Ok(
        match path::validate_effective(&[responder], anchor, context)? {
            Validation::Accepted(facts) => Delegation::Accepted(DelegateFacts {
                responder,
                issuer,
                key: facts.key,
                revocation,
            }),
            Validation::Rejected(reason) => Delegation::PathRejected(reason),
            Validation::Incomplete(reason) => Delegation::Incomplete(reason),
        },
    )
}

#[cfg(test)]
mod tests;
