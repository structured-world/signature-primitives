//! Original CRL processing facts, including outcomes that cannot mint absence.

use super::{CheckedPath, CrlAuthorities, CrlBindingError, CrlBindingFailure};
use structured_asn1::memory::Work;
use structured_pkix::{
    Certificate,
    crl::{CompleteFacts, DeltaFacts, EvidenceSource},
    temporal::{LeapTable, Reading},
};

/// Actual common processing output, without substituting a qualified absence
/// for an unsuitable window, revoked entry or conflicting source demands.
#[derive(Clone, Copy)]
pub enum CrlReading<'view, 'certificate, 'document> {
    /// Original applicable complete-list facts.
    Complete(&'view CompleteFacts<'view, 'certificate, 'document>),
    /// Original applicable metadata-bound complete/delta facts.
    Delta(&'view DeltaFacts<'view, 'certificate, 'document>),
}

impl<'certificate, 'document> CrlReading<'_, 'certificate, 'document> {
    /// Same actual evaluated target; the caller cannot relabel the result.
    #[must_use]
    pub fn target(self) -> &'certificate Certificate<'document> {
        match self {
            Self::Complete(value) => value.target(),
            Self::Delta(value) => value.target(),
        }
    }
    /// Exact original evaluation label, including fractional precision.
    #[must_use]
    pub fn evaluated_at(self) -> Reading {
        match self {
            Self::Complete(value) => value.evaluated_at(),
            Self::Delta(value) => value.evaluated_at(),
        }
    }
    /// Original authenticated sources. This does not establish usable absence;
    /// the actual entry, freshness and reason facts remain in this reading.
    #[must_use]
    pub fn source(self) -> EvidenceSource<'certificate, 'document> {
        match self {
            Self::Complete(value) => EvidenceSource::Complete(*value.source()),
            Self::Delta(value) => EvidenceSource::Delta {
                base: *value.pair().base(),
                delta: *value.pair().delta(),
            },
        }
    }
}

/// Same original CRL result and each actual signing authority bound to a
/// checked path member. No absence/Good/status acceptance is manufactured.
pub struct CrlReadingTarget<'view, 'certificate, 'document> {
    path: &'view CheckedPath<'document>,
    member: usize,
    reading: CrlReading<'view, 'certificate, 'document>,
    authorities: CrlAuthorities<'view, 'document>,
}

impl<'view, 'certificate, 'document> CrlReadingTarget<'view, 'certificate, 'document> {
    /// Same original checked target path.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Exact non-anchor target ordinal.
    #[must_use]
    pub fn member(&self) -> usize {
        self.member
    }
    /// Original complete/delta facts, including every negative outcome.
    #[must_use]
    pub fn reading(&self) -> CrlReading<'view, 'certificate, 'document> {
        self.reading
    }
    /// Actual authority for every original complete/delta source.
    #[must_use]
    pub fn authorities(&self) -> CrlAuthorities<'view, 'document> {
        self.authorities
    }
}

/// Completed source association or original target/key/root/time mismatch.
pub enum CrlReadingBinding<'view, 'certificate, 'document> {
    /// All source authorities and the original target are associated.
    Bound(CrlReadingTarget<'view, 'certificate, 'document>),
    /// No partial or relabelled result is returned.
    Rejected(CrlBindingFailure),
}

impl<'document> CheckedPath<'document> {
    /// Bind actual CRL facts using the same authority kernel as qualified
    /// absence. Unsuitable freshness/entries remain readable negative facts;
    /// only the common facts' separate `absence` method can qualify absence.
    pub fn bind_crl_reading<'view, 'certificate, W: Work>(
        &'view self,
        member: usize,
        reading: CrlReading<'view, 'certificate, 'document>,
        authorities: CrlAuthorities<'view, 'document>,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<CrlReadingBinding<'view, 'certificate, 'document>, CrlBindingError> {
        if let Some(cause) = self.bind_crl_source(
            member,
            super::crl::CrlSource::Reading(reading),
            authorities,
            utc,
            execution,
        )? {
            return Ok(CrlReadingBinding::Rejected(cause));
        }
        Ok(CrlReadingBinding::Bound(CrlReadingTarget {
            path: self,
            member,
            reading,
            authorities,
        }))
    }
}
