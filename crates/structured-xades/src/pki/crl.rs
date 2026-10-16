//! CRL authority paths bound to an actual certificate path and original source.

use super::{CheckedPath, exact};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::{
    crl::{AbsenceEvidence, Authenticated, EvidenceSource},
    path::WorkingKey,
    temporal::{LeapTable, Reading, Uncertainty},
};

/// Authority path already checked by the common PKIX processor.
#[derive(Clone, Copy)]
pub enum CrlAuthority<'view, 'document> {
    /// The target path's explicit trust anchor signs directly. This does not
    /// turn the anchor certificate into a prospective path member.
    Anchor,
    /// Original checked path whose target is the actual CRL signing certificate.
    Path(&'view CheckedPath<'document>),
}

/// Each original list needs its actual signing authority, including both lists
/// in a complete/delta pair. A delta never substitutes for its base's path.
#[derive(Clone, Copy)]
pub enum CrlAuthorities<'view, 'document> {
    /// One original complete CRL.
    Complete(CrlAuthority<'view, 'document>),
    /// Original complete and updating delta CRLs.
    Delta {
        /// Authority of the complete list.
        base: CrlAuthority<'view, 'document>,
        /// Authority of the updating list.
        delta: CrlAuthority<'view, 'document>,
    },
}

/// Every contributing reason source bound to one actual checked path member.
/// This retains the original union and authority inputs without copying their
/// catalogues. Partial reason coverage remains partial; signer revocation and
/// application trust are separate obligations.
pub struct CrlCoverage<'view, 'certificate, 'document> {
    path: &'view CheckedPath<'document>,
    member: usize,
    coverage: &'view structured_pkix::crl::Coverage<'certificate, 'document>,
    authorities: &'view [CrlAuthorities<'view, 'document>],
}

impl<'view, 'certificate, 'document> CrlCoverage<'view, 'certificate, 'document> {
    /// Same original target path.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Original non-anchor member ordinal.
    #[must_use]
    pub fn member(&self) -> usize {
        self.member
    }
    /// All original contributing complete/delta sources and their reason union.
    #[must_use]
    pub fn coverage(&self) -> &'view structured_pkix::crl::Coverage<'certificate, 'document> {
        self.coverage
    }
    /// Actual authority inputs, in the original contributing-source order.
    #[must_use]
    pub fn authorities(&self) -> &'view [CrlAuthorities<'view, 'document>] {
        self.authorities
    }
}

/// Complete association, or the exact contributing source that mismatched.
pub enum CrlCoverageBinding<'view, 'certificate, 'document> {
    /// Every contributor is associated; reason completeness is still explicit.
    Bound(CrlCoverage<'view, 'certificate, 'document>),
    /// No successful partial receipt is returned for earlier contributors.
    Rejected {
        /// Original source ordinal in the coverage union.
        source: usize,
        /// Actual completed mismatch.
        cause: CrlBindingFailure,
    },
}

/// Inability to associate all contributors, never an absent/Good status.
#[derive(Debug)]
pub enum CrlCoverageError {
    /// One authority input is required for every original reason contributor.
    AuthorityCount,
    /// Original source ordinal and processing/resource cause.
    Source {
        /// Original ordinal in the reason-union catalogue.
        source: usize,
        /// Original processing refusal; not a semantic absence.
        cause: CrlBindingError,
    },
}

/// Completed mismatch, separately from a resource or processing refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlBindingFailure {
    /// The absence was established for another original certificate.
    Target,
    /// The CRL signer path ends at a different trusted name/key.
    Anchor,
    /// The checked authority is not the actual CRL signer.
    Signer,
    /// Actual signature verification used different inherited parameters.
    EffectiveKey,
    /// Authority path does not cover the full status-evaluation reading.
    Interval,
}

/// Inability to complete association; these causes are never a status result.
#[derive(Debug)]
pub enum CrlBindingError {
    /// There is no such non-anchor target member.
    MemberIndex {
        /// Caller-supplied issuer-to-subject ordinal.
        index: usize,
    },
    /// Complete/delta authority inputs do not match the original evidence kind.
    SourceKind,
    /// Current execution refused before traversal, comparison or UTC lookup.
    Resource(MemoryError),
    /// Original shared Name comparison cause.
    Name(structured_pkix::Error),
    /// Shared UTC facts cannot establish the evaluation label.
    Time(Uncertainty),
}

impl From<super::authority::Error> for CrlBindingError {
    fn from(cause: super::authority::Error) -> Self {
        match cause {
            super::authority::Error::Resource(cause) => Self::Resource(cause),
            super::authority::Error::Name(cause) => Self::Name(cause),
            super::authority::Error::Time(cause) => Self::Time(cause),
        }
    }
}

impl From<super::authority::Failure> for CrlBindingFailure {
    fn from(cause: super::authority::Failure) -> Self {
        match cause {
            super::authority::Failure::Anchor => Self::Anchor,
            super::authority::Failure::Signer => Self::Signer,
            super::authority::Failure::EffectiveKey => Self::EffectiveKey,
            super::authority::Failure::Interval => Self::Interval,
        }
    }
}

/// Target and signing-authority association, still not complete revocation
/// coverage, CRL signer non-revocation or application trust/policy acceptance.
pub struct CrlTarget<'view, 'certificate, 'document> {
    path: &'view CheckedPath<'document>,
    member: usize,
    evidence: &'view AbsenceEvidence<'certificate, 'document>,
    authorities: CrlAuthorities<'view, 'document>,
}

impl<'view, 'certificate, 'document> CrlTarget<'view, 'certificate, 'document> {
    /// Actual target path, not another certificate sharing its serial.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Original target's issuer-to-subject ordinal.
    #[must_use]
    pub fn member(&self) -> usize {
        self.member
    }
    /// Same original qualified absence and source pair; no verification repeats.
    #[must_use]
    pub fn evidence(&self) -> &'view AbsenceEvidence<'certificate, 'document> {
        self.evidence
    }
    /// Actual checked authority for each retained original list.
    #[must_use]
    pub fn authorities(&self) -> &CrlAuthorities<'view, 'document> {
        &self.authorities
    }
}

/// Complete association or a completed original-source mismatch.
pub enum CrlBinding<'view, 'certificate, 'document> {
    /// Actual target and each original signing authority are associated.
    Bound(CrlTarget<'view, 'certificate, 'document>),
    /// A required original target/path/key/time association does not hold.
    Rejected(CrlBindingFailure),
}

#[derive(Clone, Copy)]
pub(super) enum CrlSource<'view, 'certificate, 'document> {
    Absence(&'view AbsenceEvidence<'certificate, 'document>),
    Reading(super::CrlReading<'view, 'certificate, 'document>),
}

impl<'certificate, 'document> CrlSource<'_, 'certificate, 'document> {
    fn target(self) -> &'certificate structured_pkix::Certificate<'document> {
        match self {
            Self::Absence(value) => value.target(),
            Self::Reading(value) => value.target(),
        }
    }
    fn at(self) -> Reading {
        match self {
            Self::Absence(value) => value.evaluated_at(),
            Self::Reading(value) => value.evaluated_at(),
        }
    }
    fn source(self) -> EvidenceSource<'certificate, 'document> {
        match self {
            Self::Absence(value) => value.source(),
            Self::Reading(value) => value.source(),
        }
    }
}

impl<'document> CheckedPath<'document> {
    pub(super) fn bind_crl_source<W: Work>(
        &self,
        member: usize,
        facts: CrlSource<'_, '_, 'document>,
        authorities: CrlAuthorities<'_, 'document>,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<Option<CrlBindingFailure>, CrlBindingError> {
        execution
            .charge_work(1)
            .map_err(CrlBindingError::Resource)?;
        let Some(expected) = self.members.get(member) else {
            return Err(CrlBindingError::MemberIndex { index: member });
        };
        if !exact(
            expected.certificate().as_bytes(),
            facts.target().as_bytes(),
            execution,
        )
        .map_err(CrlBindingError::Resource)?
        {
            return Ok(Some(CrlBindingFailure::Target));
        }
        // Normalize only after the current metadata admission above. Both
        // variants originate in private common processing facts, not a caller
        // supplied certificate/time tuple or a synthesized absence claim.
        match (facts.source(), authorities) {
            (EvidenceSource::Complete(source), CrlAuthorities::Complete(authority)) => {
                self.crl_authority(source, authority, facts.at(), utc, execution)
            }
            (
                EvidenceSource::Delta { base, delta },
                CrlAuthorities::Delta {
                    base: first,
                    delta: second,
                },
            ) => {
                if let Some(failure) =
                    self.crl_authority(base, first, facts.at(), utc, execution)?
                {
                    return Ok(Some(failure));
                }
                self.crl_authority(delta, second, facts.at(), utc, execution)
            }
            _ => Err(CrlBindingError::SourceKind),
        }
    }

    /// Bind every original reason contributor using the same target/key/time
    /// kernel as a single source. RFC5280 §6.3.3's `reasons_mask` union cannot
    /// inherit authenticated-path provenance from only its first contributor.
    /// This traversal adds no catalogue allocation or signature verification;
    /// shared Name comparison retains its ordinary scoped scratch admission.
    /// <https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3.3>
    pub fn bind_crl_coverage<'view, 'certificate, W: Work>(
        &'view self,
        member: usize,
        coverage: &'view structured_pkix::crl::Coverage<'certificate, 'document>,
        authorities: &'view [CrlAuthorities<'view, 'document>],
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<CrlCoverageBinding<'view, 'certificate, 'document>, CrlCoverageError> {
        execution
            .charge_work(1)
            .map_err(|cause| CrlCoverageError::Source {
                source: 0,
                cause: CrlBindingError::Resource(cause),
            })?;
        if authorities.len() != coverage.sources().len() {
            return Err(CrlCoverageError::AuthorityCount);
        }
        for (source, authority) in authorities.iter().enumerate() {
            execution
                .charge_work(1)
                .map_err(|cause| CrlCoverageError::Source {
                    source,
                    cause: CrlBindingError::Resource(cause),
                })?;
            match self
                .bind_crl(
                    member,
                    &coverage.sources()[source],
                    *authority,
                    utc,
                    execution,
                )
                .map_err(|cause| CrlCoverageError::Source { source, cause })?
            {
                CrlBinding::Bound(_) => {}
                CrlBinding::Rejected(cause) => {
                    return Ok(CrlCoverageBinding::Rejected { source, cause });
                }
            }
        }
        Ok(CrlCoverageBinding::Bound(CrlCoverage {
            path: self,
            member,
            coverage,
            authorities,
        }))
    }

    /// Bind one original qualified CRL source to this actual path member.
    /// RFC5280 §6.3.3(f) requires the CRL issuer's path to use the same trust
    /// anchor as the target path. Shared CRL authentication already checks the
    /// actual signature and cRLSign; this operation binds its original signer
    /// and effective key to the supplied checked authority, without repeating
    /// math. An indirect CRL authority may differ from the target's issuer.
    /// <https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3.3>
    ///
    /// # Panics
    /// Only if the private nonempty checked-path invariant is violated.
    pub fn bind_crl<'view, 'certificate, W: Work>(
        &'view self,
        member: usize,
        evidence: &'view AbsenceEvidence<'certificate, 'document>,
        authorities: CrlAuthorities<'view, 'document>,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<CrlBinding<'view, 'certificate, 'document>, CrlBindingError> {
        if let Some(failure) = self.bind_crl_source(
            member,
            CrlSource::Absence(evidence),
            authorities,
            utc,
            execution,
        )? {
            return Ok(CrlBinding::Rejected(failure));
        }
        Ok(CrlBinding::Bound(CrlTarget {
            path: self,
            member,
            evidence,
            authorities,
        }))
    }

    fn crl_authority<W: Work>(
        &self,
        source: Authenticated<'_, 'document>,
        authority: CrlAuthority<'_, 'document>,
        at: Reading,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<Option<CrlBindingFailure>, CrlBindingError> {
        let resource = CrlBindingError::Resource;
        execution.charge_work(1).map_err(resource)?;
        let expected = match authority {
            CrlAuthority::Anchor => {
                if !self
                    .anchor
                    .name()
                    .matches(source.issuer().tbs().subject(), execution)
                    .map_err(CrlBindingError::Name)?
                {
                    return Ok(Some(CrlBindingFailure::Signer));
                }
                WorkingKey::standing(self.anchor.key())
            }
            CrlAuthority::Path(path) => {
                return Ok(self
                    .path_authority(path, source.issuer(), source.key(), at, utc, execution)?
                    .map(Into::into));
            }
        };
        if !exact(
            expected.key().as_bytes(),
            source.key().key().as_bytes(),
            execution,
        )
        .map_err(resource)?
        {
            return Ok(Some(CrlBindingFailure::Signer));
        }
        let same = match (expected.parameters(), source.key().parameters()) {
            (None, None) => true,
            (Some(left), Some(right)) => exact(left, right, execution).map_err(resource)?,
            _ => false,
        };
        if same {
            return Ok(None);
        }
        Ok(Some(CrlBindingFailure::EffectiveKey))
    }
}
