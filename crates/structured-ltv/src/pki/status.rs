//! Request/issuer-key association with an actually checked path member.

use super::{CheckedPath, exact};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::{
    ocsp::{AuthoritySource, BoundEvidence},
    path::WorkingKey,
};

/// Completed source mismatch, not malformed XML or an unsuccessful OCSP lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspBindingFailure {
    /// Common evaluation processed another original target certificate.
    Target,
    /// Its selected issuer has a different original SPKI from this path issuer.
    Issuer,
    /// Its authenticated issuing key used a different effective parameter state.
    EffectiveKey,
}

/// Processing/resource refusal is separate from a completed source mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspBindingError {
    /// Caller selected no such original path member; not a document fault.
    MemberIndex {
        /// Invalid issuer-to-subject ordinal.
        index: usize,
    },
    /// Current execution refused before source/parameter comparison.
    Resource(MemoryError),
    /// Internal authenticated-source provenance is incomplete. This cannot be
    /// treated as a malformed document, mismatch or configured trust.
    IssuerKeyUnstated,
}

/// Actual target and issuing-key association. This does not bless the status,
/// nonce, update window or configured responder policy. Delegation still needs
/// original-root path constraints and any unresolved responder revocation.
pub struct OcspTarget<'view, 'certificate, 'document> {
    path: &'view CheckedPath<'document>,
    member: usize,
    evidence: &'view BoundEvidence<'certificate, 'document, 'certificate, 'document>,
}

impl<'view, 'certificate, 'document> OcspTarget<'view, 'certificate, 'document> {
    /// Same actual common-validator path, without a substituted issuer key.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Exact original target's issuer-to-subject path ordinal.
    #[must_use]
    pub fn member(&self) -> usize {
        self.member
    }
    /// Same original target/request/status source and temporal facts.
    #[must_use]
    pub fn evidence(
        &self,
    ) -> &'view BoundEvidence<'certificate, 'document, 'certificate, 'document> {
        self.evidence
    }
    /// Original authorization branch. Configured trust remains explicit and
    /// does not fabricate an issuer-signature/delegation-key proof.
    #[must_use]
    pub fn authority(&self) -> AuthoritySource {
        self.evidence.evidence().source().source()
    }
}

/// Completed association or source mismatch, never a partial Good assertion.
pub enum OcspBinding<'view, 'certificate, 'document> {
    /// Target and original issuing key are bound to this path member.
    Bound(OcspTarget<'view, 'certificate, 'document>),
    /// A complete original-source comparison found a mismatch.
    Rejected(OcspBindingFailure),
}

impl<'document> CheckedPath<'document> {
    /// Attach a common OCSP target result to the actual path member and issuing
    /// key. A successful `CertID` match alone cannot establish that the caller
    /// supplied the issuer that actually certified this target.
    ///
    /// RFC6960 §4.2.2.2 requires the same issuing key for direct delegation.
    /// Match that original SPKI and authenticated inherited parameter state,
    /// rather than reconstructing a standing key from a certificate or accepting
    /// a matching issuer DN. Both the common `CertID` evaluation and this common
    /// path already checked Name equality against the SAME original target.
    /// Explicit configured-responder trust used no issuing-key authentication;
    /// its separate branch is retained, with the same issuer SPKI check.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
    ///
    /// # Panics
    /// Only if the private vector/index invariant is violated: a validated
    /// nonzero member index always has its immediately preceding issuer.
    pub fn bind_ocsp<'view, 'certificate, W: Work>(
        &'view self,
        member: usize,
        evidence: &'view BoundEvidence<'certificate, 'document, 'certificate, 'document>,
        execution: &W,
    ) -> Result<OcspBinding<'view, 'certificate, 'document>, OcspBindingError> {
        let resource = OcspBindingError::Resource;
        execution.charge_work(1).map_err(resource)?;
        let Some(target) = self.members.get(member) else {
            return Err(OcspBindingError::MemberIndex { index: member });
        };
        if !exact(
            target.certificate().as_bytes(),
            evidence.target().as_bytes(),
            execution,
        )
        .map_err(resource)?
        {
            return Ok(OcspBinding::Rejected(OcspBindingFailure::Target));
        }
        execution.charge_work(1).map_err(resource)?;
        let expected = if member == 0 {
            WorkingKey::standing(self.anchor.key())
        } else {
            self.members[member - 1].key()
        };
        let source = evidence.evidence().source();
        if !exact(
            expected.key().as_bytes(),
            source.issuer().tbs().public_key().as_bytes(),
            execution,
        )
        .map_err(resource)?
        {
            return Ok(OcspBinding::Rejected(OcspBindingFailure::Issuer));
        }
        if let Some(actual) = source.issuing_key() {
            let same = match (expected.parameters(), actual.parameters()) {
                (None, None) => true,
                (Some(left), Some(right)) => exact(left, right, execution).map_err(resource)?,
                _ => false,
            };
            if !same {
                return Ok(OcspBinding::Rejected(OcspBindingFailure::EffectiveKey));
            }
        } else if !matches!(source.source(), AuthoritySource::Configured) {
            return Err(OcspBindingError::IssuerKeyUnstated);
        }
        Ok(OcspBinding::Bound(OcspTarget {
            path: self,
            member,
            evidence,
        }))
    }
}
