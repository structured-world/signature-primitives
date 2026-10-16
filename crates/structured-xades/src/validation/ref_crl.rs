//! Original CRL identifier facts over the shared name/time kernels.

use super::{
    ReferenceIdentifier, ReferenceNameError, ReferenceProperty, ReferenceTime, ReferenceTimeError,
    matches_reference_name, matches_reference_time,
};
use crate::{
    binary::{self, Location},
    properties::CalendarXml,
    scalar::TextXml,
    xml::{Access, AccessError, Xml},
};
use structured_asn1::ScopedReader;
use structured_pkix::crl::CertificateList;

/// Completed mandatory fields. Optional original Number is only an acquisition
/// hint; it is never narrowed to u64 or used as a digest identity.
pub struct CrlReferenceIdentity<N> {
    issuer: bool,
    issued_at: ReferenceTime,
    number_hint: Option<N>,
}

impl<N: Copy> CrlReferenceIdentity<N> {
    /// Shared issuer equality, not CRL signature authentication.
    #[must_use]
    pub fn issuer_matches(&self) -> bool {
        self.issuer
    }
    /// Full issue-time fact without defaulting an absent timezone to UTC.
    #[must_use]
    pub fn issued_at(&self) -> ReferenceTime {
        self.issued_at
    }
    /// Original optional Number element; its integer lexical check belongs to
    /// field preflight and remains independent of artifact agreement.
    #[must_use]
    pub fn number_hint(&self) -> Option<N> {
        self.number_hint
    }
}

/// Terminal causes never become missing identity or completed disagreement.
#[derive(Debug)]
pub enum CrlReferenceError<E, N> {
    /// Original source/generation/current-operation refusal.
    Access(AccessError<E, N>),
    /// No original reference exists at this ordinal.
    Index {
        /// Requested ordinal, not an XML byte offset.
        index: usize,
    },
    /// Original name syntax/source/shared comparison refusal.
    Name(ReferenceNameError<E, N>),
    /// Original time-source/current comparison refusal.
    Time(ReferenceTimeError<E, N>),
}

/// Original XML enclosure and both fields, or the exact terminal cause.
pub type CrlReferenceResult<X> = Result<
    Option<binary::LocatedValue<CrlReferenceIdentity<<X as Xml>::Id>, X>>,
    CrlReferenceError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Compare every mandatory field of a written `CRLIdentifier` with the actual
/// list through original name/XSD1.0 time semantics under the current query.
/// EN319132-1 Annex A.1.2 requires issuer and issue time; Note3 expressly makes
/// Number an optional retrieval hint. It cannot replace the whole-list digest
/// or impose a finite-width requirement. None means no written CRL identifier,
/// including another reference kind, never successful agreement.
/// Signature/issuer authorization, complete/delta applicability, freshness,
/// actual use and incorporation remain independent. No CRL parse is repeated.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only if an immutable privately constructed reference changes its selector
/// kind between original field selection and the same field kernel.
pub fn check_crl_reference<X: TextXml + CalendarXml>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    actual: &CertificateList<'_>,
    operation: &ScopedReader<'_, '_>,
) -> CrlReferenceResult<X> {
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(CrlReferenceError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(CrlReferenceError::Index { index });
    };
    let ReferenceIdentifier::Crl { node, number, .. } = entry.identifier() else {
        return Ok(None);
    };
    let issuer = matches_reference_name(xml, references, index, actual.tbs().issuer(), operation)
        .map_err(CrlReferenceError::Name)?
        .expect("original CRL issuer entry");
    let issued_at = matches_reference_time(
        xml,
        references,
        index,
        actual.tbs().this_update(),
        operation,
    )
    .map_err(CrlReferenceError::Time)?
    .expect("original CRL time entry");
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(CrlReferenceError::Access)?;
    Ok(Some(binary::Located {
        location: Location {
            snapshot: references.snapshot(),
            node,
        },
        value: CrlReferenceIdentity {
            issuer,
            issued_at,
            number_hint: number,
        },
    }))
}
