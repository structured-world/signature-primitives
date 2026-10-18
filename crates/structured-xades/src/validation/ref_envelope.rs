//! Bind one OCSP reference's digest and identifier to the same signed response.

use super::{
    OcspReferenceError, OcspReferenceIdentity, ReferenceDigest, ReferenceDigestError,
    ReferenceIdentifier, ReferenceProperty, ReferenceTarget, ReferenceTime, check_ocsp_reference,
    compare_reference_target,
};
use crate::{
    binary::{self, BinaryXml},
    certificate::{Agreement, DigestProvider},
    properties::CalendarXml,
    scalar::TextXml,
    xml::{Access, AccessError, Xml},
};
use structured_asn1::{
    Reader,
    memory::{MemoryError, Work},
};
use structured_pkix::{
    algorithm::digest::AsnDigest,
    ocsp::{ResponderMatch, ResponseBytes, SignedResponse},
    oid,
};

/// Original whole envelope and an actual signature receipt. This is an INPUT,
/// not a trusted binding: [`check_ocsp_envelope_reference`] checks the relation.
#[derive(Clone, Copy)]
pub struct OcspReferenceInput<'envelope, 'signed, 'document> {
    /// Whole original successful `OCSPResponse`; a basic-only value is insufficient.
    pub envelope: &'envelope ResponseBytes<'document>,
    /// Already authenticated original basic response and its actual signer.
    pub signed: SignedResponse<'signed, 'document>,
}

/// Identifier and optional digest checked against the SAME signed envelope.
/// This does not prove authorization, target status, actual use or trust.
pub struct OcspEnvelopeReference<'r, 'e, 's, 'd, N, D, G> {
    references: &'r ReferenceProperty<N, D, G>,
    entry: usize,
    actual: OcspReferenceInput<'e, 's, 'd>,
    identity: binary::Located<OcspReferenceIdentity, N, D, G>,
    digest: Option<ReferenceDigest>,
}
impl<'r, 'e, 's, 'd, N, D, G> OcspEnvelopeReference<'r, 'e, 's, 'd, N, D, G> {
    /// Original property and its immutable source/generation.
    #[must_use]
    pub fn references(&self) -> &'r ReferenceProperty<N, D, G> {
        self.references
    }
    /// Original reference ordinal within that property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Same whole envelope, authenticated body and signer used by both checks.
    #[must_use]
    pub fn actual(&self) -> OcspReferenceInput<'e, 's, 'd> {
        self.actual
    }
    /// Original identifier location and all readable responder/time facts.
    #[must_use]
    pub fn identity(&self) -> &binary::Located<OcspReferenceIdentity, N, D, G> {
        &self.identity
    }
    /// None means mandatory identifier syntax was malformed/unsupported, so
    /// digest processing was not attempted. `IdentifierOnly` means no digest was
    /// written; neither is a successful whole-envelope digest agreement.
    #[must_use]
    pub fn digest(&self) -> Option<ReferenceDigest> {
        self.digest
    }

    /// Mandatory responder/time agree with this response, and its digest
    /// agrees if written. Annex A.1.2 makes the digest optional (SHOULD): an
    /// identifier-only reference can identify this response but does not bind
    /// its whole contents against substitution. Inspect [`Self::digest`] to
    /// retain that distinction; this proves no authority, status, trust or grade.
    #[must_use]
    pub fn identifies_response(&self) -> bool {
        if self.identity.value.responder() != Some(ResponderMatch::Matches)
            || self.identity.value.produced_at() != ReferenceTime::Matches
        {
            return false;
        }
        matches!(
            self.digest,
            Some(ReferenceDigest::Compared(Agreement::Matches) | ReferenceDigest::IdentifierOnly)
        )
    }
}

/// Input/source and execution failures never become an OCSP identity mismatch.
#[derive(Debug)]
pub enum OcspEnvelopeError<E, KP, DP, N, D, G> {
    /// Current original XML/source query refused.
    Access(AccessError<E, N>),
    /// No original reference exists at this ordinal.
    Index {
        /// Requested ordinal, not a physical document offset.
        index: usize,
    },
    /// The supplied envelope does not contain this receipt's exact basic
    /// response under the known basic-response syntax. Caller input association
    /// failed; the original document is not thereby declared malformed.
    InputMismatch {
        /// Original reference node whose input pair was supplied incorrectly.
        node: N,
    },
    /// Current relation comparison was not admitted before scanning.
    Resource {
        /// Original reference node; no invented binary offset.
        node: N,
        /// Exact admission cause.
        cause: MemoryError,
    },
    /// Existing original identifier/source/provider cause.
    Identity(OcspReferenceError<E, KP, N, D, G>),
    /// Existing original whole-response digest/source/provider cause.
    Digest(binary::Error<E, ReferenceDigestError<DP>, N, D, G>),
}

/// Complete paired facts or the unchanged stage-specific terminal cause.
pub type OcspEnvelopeResult<'r, 'e, 's, 'd, X, KP, DP> = Result<
    Option<
        OcspEnvelopeReference<
            'r,
            'e,
            's,
            'd,
            <X as Xml>::Id,
            <X as Xml>::Document,
            <X as Xml>::Generation,
        >,
    >,
    OcspEnvelopeError<
        <X as Xml>::Error,
        KP,
        DP,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
>;

pub(super) fn basic_payload<'a, W: Work>(
    envelope: &ResponseBytes<'a>,
    work: &W,
) -> Result<Option<&'a [u8]>, MemoryError> {
    work.charge_work(1)?;
    let kind = envelope.kind().as_bytes();
    let expected_kind = oid::OCSP_BASIC.as_bytes();
    if kind.len() != expected_kind.len() {
        return Ok(None);
    }
    work.charge_work(u64::try_from(kind.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
    if kind != expected_kind {
        return Ok(None);
    }
    Ok(Some(envelope.payload()))
}

pub(super) fn envelope_contains<W: Work>(
    envelope: &ResponseBytes<'_>,
    authenticated: &[u8],
    work: &W,
) -> Result<bool, MemoryError> {
    let Some(payload) = basic_payload(envelope, work)? else {
        return Ok(false);
    };
    if payload.len() != authenticated.len() {
        return Ok(false);
    }
    work.charge_work(u64::try_from(payload.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
    Ok(payload == authenticated)
}

/// Compose Annex A.1.2's mandatory responder/time fields and optional whole
/// `OCSPResponse` digest WITHOUT allowing a valid identifier from response A to
/// be joined to a digest of envelope B. The known syntax and exact original
/// payload relation are paid and checked before any provider callback; neither
/// signature verification nor parsing repeats. Two different encodings of the
/// same signed body are not normalized or silently substituted.
/// Malformed/unavailable mandatory time syntax prevents both key and envelope
/// digest callbacks. A readable time mismatch retains both independent facts.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
/// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1>
///
/// This is not issuer authorization, freshness, status applicability, presence,
/// actor membership, substitution-resistant acquisition policy or a grade.
/// None means the original reference has a different kind, never agreement.
pub fn check_ocsp_envelope_reference<'r, 'e, 's, 'd, 'k, 'q, X, K, P, KP>(
    xml: &X,
    references: &'r ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    actual: OcspReferenceInput<'e, 's, 'd>,
    key_digest: &'k K,
    provider: &'q P,
    operation: &Reader<'_>,
) -> OcspEnvelopeResult<'r, 'e, 's, 'd, X, KP, P::Error>
where
    X: BinaryXml + CalendarXml + TextXml,
    K: AsnDigest<'k, Error = KP>,
    P: DigestProvider<'q, X>,
{
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(OcspEnvelopeError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(OcspEnvelopeError::Index { index });
    };
    let ReferenceIdentifier::Ocsp { node, .. } = entry.identifier() else {
        return Ok(None);
    };
    let resource = |cause| OcspEnvelopeError::Resource { node, cause };
    if !envelope_contains(actual.envelope, actual.signed.response().as_bytes(), &work)
        .map_err(resource)?
    {
        return Err(OcspEnvelopeError::InputMismatch { node });
    }
    let identity =
        check_ocsp_reference(xml, references, index, actual.signed, key_digest, operation)
            .map_err(OcspEnvelopeError::Identity)?;
    let Some(identity) = identity else {
        return Err(OcspEnvelopeError::InputMismatch { node });
    };
    let digest = if identity.value.responder().is_some() {
        Some(
            compare_reference_target(
                xml,
                references,
                index,
                ReferenceTarget::Ocsp(actual.envelope),
                provider,
                &work,
            )
            .map_err(OcspEnvelopeError::Digest)?,
        )
    } else {
        None
    };
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(OcspEnvelopeError::Access)?;
    Ok(Some(OcspEnvelopeReference {
        references,
        entry: index,
        actual,
        identity,
        digest,
    }))
}
