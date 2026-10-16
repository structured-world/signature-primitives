//! Signature-value timestamp association and static certificate interval.

use super::CheckedPathCertificate;
use crate::timestamp::{Interval, Role, TemporalError, Verified};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::Work;
use structured_pkix::temporal::LeapTable;

/// A completed mathematical/static association, still requiring authenticated
/// TSA path/status and signer revocation/algorithm/policy processing.
pub struct SignatureTime<'receipt, 'view, 'document, N, D, G> {
    certificate: &'receipt CheckedPathCertificate<'view, 'document, N, D, G>,
    timestamp: &'receipt Verified<N, D, G>,
    generation: Interval,
}

impl<'receipt, 'view, 'document, N, D, G> SignatureTime<'receipt, 'view, 'document, N, D, G> {
    /// Same original selected signature/certificate and checked static path.
    #[must_use]
    pub fn certificate(&self) -> &'receipt CheckedPathCertificate<'view, 'document, N, D, G> {
        self.certificate
    }
    /// Same complete token check over the selected original `SignatureValue`.
    #[must_use]
    pub fn timestamp(&self) -> &'receipt Verified<N, D, G> {
        self.timestamp
    }
    /// Entire stated generation interval, never a bare claimed `SigningTime`.
    #[must_use]
    pub fn generation(&self) -> Interval {
        self.generation
    }
}

/// Missing association facts do not assert that a certificate has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureTimeFailure {
    /// Selected key/certificate or an original path digest is not established.
    Certificate,
    /// Static path was not checked over the complete generation interval.
    Interval,
}

/// Original execution/context error, not a completed negative time claim.
#[derive(Debug)]
pub enum SignatureTimeError<E, N> {
    /// Original current-source/generation/resource refusal.
    Access(AccessError<E, N>),
    /// The receipt belongs to another selected signature or XML generation.
    Foreign {
        /// Original timestamp property.
        property: N,
    },
    /// Caller supplied a different timestamp role; it cannot replace a required
    /// `SignatureTimeStamp` simply because it also covers some signature bytes.
    Role {
        /// Original timestamp property.
        property: N,
    },
    /// Full stated accuracy/UTC interval cannot be established.
    Time {
        /// Original timestamp property.
        property: N,
        /// Original UTC uncertainty or execution refusal.
        cause: TemporalError,
    },
}

/// Mathematical/static binding or explicit insufficient facts, not a B-T grade.
pub enum SignatureTimeBinding<'receipt, 'view, 'document, N, D, G> {
    /// Same selected signature, with full generation-time static path coverage.
    Bound(SignatureTime<'receipt, 'view, 'document, N, D, G>),
    /// Required certificate/interval facts have not been established.
    Unproven(SignatureTimeFailure),
}

impl<'view, 'document, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq>
    CheckedPathCertificate<'view, 'document, N, D, G>
{
    /// Associate a complete original `SignatureTimeStamp` with this actual signing
    /// certificate/path, preserving source generation and its full accuracy.
    ///
    /// EN319132-1 V1.3.1 §§5.3/6.3(o) timestamp the original `SignatureValue` and
    /// require creation before signing-certificate expiry/revocation. A checked
    /// path interval containing the entire generation interval supplies static
    /// validity; revocation and TSA authority remain separate necessary facts.
    /// Neither an archive role nor claimed `SigningTime` can substitute here.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn bind_signature_time<'receipt, X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &'receipt self,
        timestamp: &'receipt Verified<N, D, G>,
        utc: &LeapTable<'_>,
        access: &Access<'_, X, W>,
    ) -> Result<
        SignatureTimeBinding<'receipt, 'view, 'document, N, D, G>,
        SignatureTimeError<X::Error, N>,
    > {
        self.bind_generation(timestamp, access, || {
            timestamp.interval(utc, access.execution())
        })
    }

    /// Reuse the complete generation interval already established by the actual
    /// checked TSA path for this SAME private mathematical token receipt. This
    /// has the same source/role/certificate/static interval semantics as
    /// `bind_signature_time`, without repeating UTC lookup or arithmetic.
    pub fn bind_signature_time_path<
        'receipt,
        X: Xml<Id = N, Document = D, Generation = G>,
        W: Work,
    >(
        &'receipt self,
        path: &'receipt crate::pki::TimestampPath<'_, '_, '_, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> Result<
        SignatureTimeBinding<'receipt, 'view, 'document, N, D, G>,
        SignatureTimeError<X::Error, N>,
    > {
        self.bind_generation(path.actor().verified(), access, || Ok(path.generation()))
    }

    fn bind_generation<'receipt, X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &'receipt self,
        timestamp: &'receipt Verified<N, D, G>,
        access: &Access<'_, X, W>,
        interval: impl FnOnce() -> Result<Interval, TemporalError>,
    ) -> Result<
        SignatureTimeBinding<'receipt, 'view, 'document, N, D, G>,
        SignatureTimeError<X::Error, N>,
    > {
        let references = self.selected().reference();
        if references.snapshot() != access.snapshot()
            || timestamp.token().snapshot != references.snapshot()
        {
            return Err(SignatureTimeError::Foreign {
                property: timestamp.property(),
            });
        }
        if !access
            .equal_id(timestamp.signature(), references.signature())
            .map_err(|cause| {
                SignatureTimeError::Access(AccessError::Resource {
                    node: timestamp.property(),
                    cause,
                })
            })?
        {
            return Err(SignatureTimeError::Foreign {
                property: timestamp.property(),
            });
        }
        access
            .query(references.signature(), |_, _, _| Ok(()))
            .map_err(SignatureTimeError::Access)?;
        if timestamp.role() != Role::Signature {
            return Err(SignatureTimeError::Role {
                property: timestamp.property(),
            });
        }
        if !self.is_bound() {
            return Ok(SignatureTimeBinding::Unproven(
                SignatureTimeFailure::Certificate,
            ));
        }
        let generation = interval().map_err(|cause| SignatureTimeError::Time {
            property: timestamp.property(),
            cause,
        })?;
        access
            .query(references.signature(), |_, _, _| Ok(()))
            .map_err(SignatureTimeError::Access)?;
        let checked = self.digests().path().interval();
        if checked.from_instant() > generation.earliest || checked.to_instant() < generation.latest
        {
            return Ok(SignatureTimeBinding::Unproven(
                SignatureTimeFailure::Interval,
            ));
        }
        Ok(SignatureTimeBinding::Bound(SignatureTime {
            certificate: self,
            timestamp,
            generation,
        }))
    }
}
