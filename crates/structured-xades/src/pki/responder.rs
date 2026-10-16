//! Original-root association for an actually authenticated delegated responder.

use super::{CheckedPath, OcspTarget, authority};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::{
    ocsp::{AuthoritySource, ResponderRevocation},
    temporal::{LeapTable, Uncertainty},
};

/// Completed mismatch in a delegated responder's original-root path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderFailure {
    /// The full responder path uses a different original root name/key.
    Anchor,
    /// Its target is not the original certificate/key that signed the response.
    Signer,
    /// The signature used different inherited key parameters.
    EffectiveKey,
    /// The path does not cover the full original status-evaluation reading.
    Interval,
}

/// Inability to bind a delegated path, never an OCSP status or trust decision.
#[derive(Debug)]
pub enum ResponderError {
    /// The response was authenticated by its issuer or configured trust rather
    /// than by direct certificate delegation. Those branches have no delegate
    /// path to substitute and remain explicit in `OcspTarget::authority`.
    SourceKind,
    /// Current operation refused before comparison or temporal processing.
    Resource(MemoryError),
    /// Original shared Name comparison failed.
    Name(structured_pkix::Error),
    /// Shared UTC facts cannot establish the full original reading.
    Time(Uncertainty),
}

impl From<authority::Error> for ResponderError {
    fn from(value: authority::Error) -> Self {
        match value {
            authority::Error::Resource(cause) => Self::Resource(cause),
            authority::Error::Name(cause) => Self::Name(cause),
            authority::Error::Time(cause) => Self::Time(cause),
        }
    }
}

impl From<authority::Failure> for ResponderFailure {
    fn from(value: authority::Failure) -> Self {
        match value {
            authority::Failure::Anchor => Self::Anchor,
            authority::Failure::Signer => Self::Signer,
            authority::Failure::EffectiveKey => Self::EffectiveKey,
            authority::Failure::Interval => Self::Interval,
        }
    }
}

/// A delegated response bound to its original target and full responder path.
/// This preserves the shared noCheck/unresolved fact; it does not establish
/// responder revocation, status freshness or application trust acceptance.
pub struct ResponderPath<'receipt, 'view, 'certificate, 'document> {
    target: &'receipt OcspTarget<'view, 'certificate, 'document>,
    path: &'receipt CheckedPath<'document>,
    revocation: ResponderRevocation,
}

impl<'receipt, 'view, 'certificate, 'document>
    ResponderPath<'receipt, 'view, 'certificate, 'document>
{
    /// Original target, issuing-key and authenticated response association.
    #[must_use]
    pub fn target(&self) -> &'receipt OcspTarget<'view, 'certificate, 'document> {
        self.target
    }

    /// Full original-root responder path, including ancestor constraints.
    #[must_use]
    pub fn path(&self) -> &'receipt CheckedPath<'document> {
        self.path
    }

    /// Actual common delegation fact; absence of noCheck is not success.
    #[must_use]
    pub fn revocation(&self) -> ResponderRevocation {
        self.revocation
    }
}

/// Completed association or original source/key/time mismatch.
pub enum ResponderBinding<'receipt, 'view, 'certificate, 'document> {
    /// Original delegated signer and complete status-reading interval agree.
    Bound(ResponderPath<'receipt, 'view, 'certificate, 'document>),
    /// No partial association is returned for a different root/source/time.
    Rejected(ResponderFailure),
}

impl<'view, 'certificate, 'document> OcspTarget<'view, 'certificate, 'document> {
    /// Bind an actual delegated response to a full path under the target's root.
    /// The shared RFC6960 §4.2.2.2 delegation check establishes the direct
    /// issuing-key relation and OCSP purpose; it does not resume the original
    /// root's ancestor constraints. This separate binding requires those full
    /// path facts, the original signer/effective key and complete evaluation
    /// reading. It reuses the CRL association kernel without signature replay.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
    pub fn bind_responder_path<'receipt, W: Work>(
        &'receipt self,
        path: &'receipt CheckedPath<'document>,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<ResponderBinding<'receipt, 'view, 'certificate, 'document>, ResponderError> {
        execution.charge_work(1).map_err(ResponderError::Resource)?;
        let AuthoritySource::Delegate { revocation } = self.authority() else {
            return Err(ResponderError::SourceKind);
        };
        let evidence = self.evidence().evidence();
        let signed = evidence.source().signed();
        if let Some(cause) = self.path().path_authority(
            path,
            signed.signer(),
            signed.key(),
            self.evidence().evaluated_at(),
            utc,
            execution,
        )? {
            return Ok(ResponderBinding::Rejected(cause.into()));
        }
        Ok(ResponderBinding::Bound(ResponderPath {
            target: self,
            path,
            revocation,
        }))
    }
}
