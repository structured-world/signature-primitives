//! Bind optional CRL identifier fields and mandatory digest to one original list.

use super::{
    CrlReferenceError, CrlReferenceIdentity, ReferenceDigest, ReferenceDigestError, ReferenceKind,
    ReferenceProperty, ReferenceTarget, ReferenceTime, check_crl_reference,
    compare_reference_target,
};
use crate::{
    binary::{self, BinaryXml, Located},
    certificate::{Agreement, DigestProvider},
    properties::CalendarXml,
    scalar::TextXml,
    xml::{Access, AccessError, Xml},
};
use structured_asn1::ScopedReader;
use structured_pkix::crl::CertificateList;

/// One original row's identifier and digest against the SAME actual CRL.
/// Private construction retains the source pair for subsequent composition;
/// a caller cannot substitute another list after the checks have completed.
pub struct CrlValueReference<'references, 'actual, 'document, N, D, G> {
    references: &'references ReferenceProperty<N, D, G>,
    entry: usize,
    actual: &'actual CertificateList<'document>,
    identity: Option<Located<CrlReferenceIdentity<N>, N, D, G>>,
    digest: Option<ReferenceDigest>,
}

impl<'r, 'a, 'd, N: Copy, D: Copy, G: Copy> CrlValueReference<'r, 'a, 'd, N, D, G> {
    /// Original reference property, including its actual role and generation.
    #[must_use]
    pub fn references(&self) -> &'r ReferenceProperty<N, D, G> {
        self.references
    }

    /// Original row ordinal within that property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// Same complete/delta CRL whose original DER supplied the digest input.
    #[must_use]
    pub fn actual(&self) -> &'a CertificateList<'d> {
        self.actual
    }

    /// Written original identifier and all field facts, or legitimate absence.
    #[must_use]
    pub fn identity(&self) -> Option<&Located<CrlReferenceIdentity<N>, N, D, G>> {
        self.identity.as_ref()
    }

    /// Whole-list comparison. None means malformed/unsupported mandatory time
    /// syntax prevented provider dispatch, not a successful absent digest.
    #[must_use]
    pub fn digest(&self) -> Option<ReferenceDigest> {
        self.digest
    }

    /// Only agreement with this one CRL: mandatory digest plus every written
    /// issuer/time field. An absent optional identifier may be inferred from
    /// the digest; an unstated timezone does not prove time equality.
    /// This is not signature authentication, status applicability, actual path
    /// use, complete/delta coverage, incorporation or a baseline grade.
    #[must_use]
    pub fn agrees(&self) -> bool {
        if self.digest != Some(ReferenceDigest::Compared(Agreement::Matches)) {
            return false;
        }
        if let Some(identity) = &self.identity {
            return identity.value.issuer_matches()
                && identity.value.issued_at() == ReferenceTime::Matches;
        }
        true
    }
}

/// Exact original processing stage; resource/source refusals never disagree.
#[derive(Debug)]
pub enum CrlValueError<E, PE, N, D, G> {
    /// Original source/generation/current-query refusal.
    Access(AccessError<E, N>),
    /// Caller selected an ordinal outside the original property.
    Index {
        /// Requested row ordinal, not a document byte offset.
        index: usize,
    },
    /// Existing original issuer/time interpreter refused.
    Identity(CrlReferenceError<E, N>),
    /// Existing whole-list digest/source/provider interpreter refused.
    Digest(binary::Error<E, ReferenceDigestError<PE>, N, D, G>),
}

/// Complete source-paired CRL facts or the unchanged terminal cause.
pub type CrlValueResult<'r, 'a, 'd, X, PE> = Result<
    Option<
        CrlValueReference<'r, 'a, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    >,
    CrlValueError<
        <X as Xml>::Error,
        PE,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
>;

/// Compose Annex A.1.2's mandatory DER-list digest and optional `CRLIdentifier`
/// through the SAME existing digest/name/calendar kernels and current query.
/// No parse, serialization, signature verification or acquisition repeats.
/// A different reference kind returns None, never successful agreement.
///
/// EN319132-1 A.1.2 permits omission of `CRLIdentifier` if other information
/// identifies the list. A written identifier still requires issuer/issue time;
/// its Number and URI remain hints. Readable mismatch retains the independent
/// digest fact; malformed/unsupported time prevents provider side effects.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_crl_value_reference<'r, 'a, 'd, 'q, X, P>(
    xml: &X,
    references: &'r ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    actual: &'a CertificateList<'d>,
    provider: &'q P,
    operation: &ScopedReader<'_, '_>,
) -> CrlValueResult<'r, 'a, 'd, X, P::Error>
where
    X: BinaryXml + CalendarXml + TextXml,
    P: DigestProvider<'q, X>,
{
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(CrlValueError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(CrlValueError::Index { index });
    };
    if entry.kind() != ReferenceKind::Crl {
        return Ok(None);
    }
    let identity = check_crl_reference(xml, references, index, actual, operation)
        .map_err(CrlValueError::Identity)?;
    let digest = match identity.as_ref() {
        Some(identity)
            if matches!(
                identity.value.issued_at(),
                ReferenceTime::Malformed | ReferenceTime::Unsupported
            ) =>
        {
            None
        }
        _ => Some(
            compare_reference_target(
                xml,
                references,
                index,
                ReferenceTarget::Crl(actual),
                provider,
                &work,
            )
            .map_err(CrlValueError::Digest)?,
        ),
    };
    access
        .query(entry.node(), |_, _, _| Ok(()))
        .map_err(CrlValueError::Access)?;
    Ok(Some(CrlValueReference {
        references,
        entry: index,
        actual,
        identity,
        digest,
    }))
}
