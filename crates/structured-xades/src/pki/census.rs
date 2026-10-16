//! Complete original per-member status inputs, without application acceptance.

use super::{CheckedPath, CrlCoverage, CrlReadingTarget, OcspTarget, ResponderPath};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::temporal::Reading;

/// An actual status-source association produced by this module's shared
/// target/authority kernels. Neither variant is a caller-written Good flag.
pub enum MemberStatus<'view, 'certificate, 'document> {
    /// Every complete/delta reason contributor has its actual authority bound.
    Crl(&'view CrlCoverage<'view, 'certificate, 'document>),
    /// Actual complete/delta facts, including stale/revoked/conflicting results
    /// which cannot mint qualified absence. No negative fact is discarded.
    CrlReading(&'view CrlReadingTarget<'view, 'certificate, 'document>),
    /// Original OCSP target/issuing-key association; its actual status, update
    /// window, nonce and configured/delegated authority remain explicit.
    Ocsp(&'view OcspTarget<'view, 'certificate, 'document>),
    /// The final member is the actual delegated responder with a valid shared
    /// noCheck fact. This exempts only its revocation lookup, not its path or
    /// any non-anchor ancestor. An unresolved delegation cannot use this arm.
    ResponderNoCheck(&'view ResponderPath<'view, 'view, 'certificate, 'document>),
}

impl<'view, 'document> MemberStatus<'view, '_, 'document> {
    fn identity(&self) -> (&'view CheckedPath<'document>, usize, Reading) {
        match self {
            Self::Crl(value) => (
                value.path(),
                value.member(),
                value.coverage().evaluated_at(),
            ),
            Self::CrlReading(value) => {
                (value.path(), value.member(), value.reading().evaluated_at())
            }
            Self::Ocsp(value) => (
                value.path(),
                value.member(),
                value.evidence().evaluated_at(),
            ),
            Self::ResponderNoCheck(value) => (
                value.path(),
                value.path().members().len() - 1,
                value.target().evidence().evaluated_at(),
            ),
        }
    }
}

/// Complete status-input census for one original checked path and evaluation
/// label. The anchor is deliberately outside this non-anchor member census.
/// No allocation, signature verification, hash or copied evidence is required.
/// This does not approve partial reasons, OCSP Unknown/Revoked/stale assertions,
/// responder revocation, or application trust: original facts remain accessible.
pub struct PathStatuses<'view, 'certificate, 'document> {
    path: &'view CheckedPath<'document>,
    at: Reading,
    entries: &'view [MemberStatus<'view, 'certificate, 'document>],
}

impl<'view, 'certificate, 'document> PathStatuses<'view, 'certificate, 'document> {
    /// Same original static path, not an independently counted certificate set.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Exact shared evaluation label, including its precision/remainder.
    #[must_use]
    pub fn evaluated_at(&self) -> Reading {
        self.at
    }
    /// Every non-anchor member's actual input, in issuer-to-subject order.
    #[must_use]
    pub fn entries(&self) -> &'view [MemberStatus<'view, 'certificate, 'document>] {
        self.entries
    }
}

/// Incomplete/foreign input is not a certificate status or successful subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCensusError {
    /// Exactly one input is required for each actual non-anchor member.
    Count,
    /// This input belongs to a different checked path receipt or member.
    Member {
        /// Expected issuer-to-subject member ordinal.
        index: usize,
    },
    /// Input was evaluated at a different exact label.
    Time {
        /// Original member ordinal.
        index: usize,
    },
    /// The original delegation has no noCheck exemption. It cannot be used
    /// instead of an actual status input for this member.
    Exemption {
        /// Original non-anchor member ordinal.
        index: usize,
    },
    /// Current work refused before a metadata access/comparison.
    Resource(MemoryError),
}

impl<'document> CheckedPath<'document> {
    /// Establish complete original status-input association for the actual
    /// path, before deriving conditional validation-material obligations.
    /// EN319132-1 V1.3.1 §6.3(aa) refers to the validation data actually needed
    /// for the signer, counters, credentials and earlier timestamps, rather
    /// than accepting a nonempty bag of statuses as the complete path set.
    /// Status/freshness acceptance and historical trust remain separate.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn status_census<'view, 'certificate, W: Work>(
        &'view self,
        at: Reading,
        entries: &'view [MemberStatus<'view, 'certificate, 'document>],
        execution: &W,
    ) -> Result<PathStatuses<'view, 'certificate, 'document>, StatusCensusError> {
        execution
            .charge_work(1)
            .map_err(StatusCensusError::Resource)?;
        if self.members().len() != entries.len() {
            return Err(StatusCensusError::Count);
        }
        for (index, entry) in entries.iter().enumerate() {
            execution
                .charge_work(1)
                .map_err(StatusCensusError::Resource)?;
            if let MemberStatus::ResponderNoCheck(value) = entry
                && value.revocation() != structured_pkix::ocsp::ResponderRevocation::NoCheck
            {
                return Err(StatusCensusError::Exemption { index });
            }
            let (path, member, evaluated_at) = entry.identity();
            if !core::ptr::eq(self, path) || member != index {
                return Err(StatusCensusError::Member { index });
            }
            if evaluated_at != at {
                return Err(StatusCensusError::Time { index });
            }
        }
        Ok(PathStatuses {
            path: self,
            at,
            entries,
        })
    }
}
