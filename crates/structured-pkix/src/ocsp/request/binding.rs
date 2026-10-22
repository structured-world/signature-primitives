//! Batch identity and nonce relations retain each actual sent request entry.

use super::super::digest::CertDigest;
use super::{FIELD, OcspRequest, RequestEntry};
use crate::algorithm::digest::AsnDigest;
use crate::error::{CallbackError, CallbackResult, Error, Result};
use crate::ocsp::{
    CertId, CertMatch, ExtensionProcessing, Lookup, NonceBinding, RequestNonce, SignedResponse,
};
use structured_asn1::memory::{OwnedVec, Work};

pub(super) fn equal<L: Work, R: Work>(
    left: &[u8],
    l: &L,
    right: &[u8],
    r: &R,
    field: &'static str,
    left_at: u64,
    right_at: u64,
) -> Result<bool> {
    l.charge_work(1)
        .map_err(|e| Error::resource(e, field, left_at))?;
    r.charge_work(1)
        .map_err(|e| Error::resource(e, field, right_at))?;
    if left.len() != right.len() {
        return Ok(false);
    }
    l.charge_work(left.len() as u64)
        .map_err(|e| Error::resource(e, field, left_at))?;
    r.charge_work(right.len() as u64)
        .map_err(|e| Error::resource(e, field, right_at))?;
    Ok(left == right)
}

impl CertId<'_> {
    /// Compare two actual wire `CertIDs` under their own source ceilings and the
    /// current operation, resolving complete digest identities before hash-byte
    /// comparison. This does not hash certificates or establish issuer trust.
    /// Unknown/malformed algorithms and widths never become positive matches.
    pub fn matches_id<'d, D: AsnDigest<'d> + ?Sized, W: Work>(
        &self,
        other: &CertId<'_>,
        digest: &'d D,
        execution: &W,
    ) -> CallbackResult<CertMatch, D::Error> {
        const FIELD: &str = "ocsp.certID";
        let left_work = self.algorithm.query_in(execution);
        let right_work = other.algorithm.query_in(execution);
        if !equal(
            self.serial.as_bytes(),
            &left_work,
            other.serial.as_bytes(),
            &right_work,
            FIELD,
            self.span.start,
            other.span.start,
        )? {
            return Ok(CertMatch::Differs);
        }
        let left = match self.digest_identity(digest, execution)? {
            CertDigest::Ready(id) => id,
            CertDigest::Rejected(reason) => return Ok(reason),
        };
        let right = match other.digest_identity(digest, execution)? {
            CertDigest::Ready(id) => id,
            CertDigest::Rejected(reason) => return Ok(reason),
        };
        execution
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, self.span.start))?;
        if !digest
            .compare(&left, &right, execution)
            .map_err(CallbackError::Callback)?
            .is_eq()
        {
            return Ok(CertMatch::Differs);
        }
        for (left, right) in [
            (self.issuer_name_hash, other.issuer_name_hash),
            (self.issuer_key_hash, other.issuer_key_hash),
        ] {
            if !equal(
                left,
                &left_work,
                right,
                &right_work,
                FIELD,
                self.span.start,
                other.span.start,
            )? {
                return Ok(CertMatch::Differs);
            }
        }
        Ok(CertMatch::Matches)
    }
}

/// One original sent entry and its duplicate-preserving authenticated lookup.
#[derive(Debug)]
pub struct RequestLookup<'q, 'a, 'r, 'response> {
    request: &'q RequestEntry<'a>,
    lookup: Lookup<'r, 'response>,
    extensions: ExtensionProcessing<'a>,
}
impl<'q, 'a, 'r, 'response> RequestLookup<'q, 'a, 'r, 'response> {
    /// Original sent entry, not a reconstructed certificate identity.
    #[must_use]
    pub fn request(&self) -> &'q RequestEntry<'a> {
        self.request
    }
    /// Original response match; ambiguity is never reduced to the first entry.
    #[must_use]
    pub fn lookup(&self) -> Lookup<'r, 'response> {
        self.lookup
    }
    /// Unknown per-entry critical demands remain separate from identity.
    #[must_use]
    pub fn extensions(&self) -> ExtensionProcessing<'a> {
        self.extensions
    }
}

/// Complete request/response relation, not freshness, responder authority or
/// request acceptance. Inspect every lookup, critical demand and nonce fact.
#[derive(Debug)]
pub struct BoundResponse<'q, 'a, 'r, 'response> {
    request: &'q OcspRequest<'a>,
    response: SignedResponse<'r, 'response>,
    nonce: NonceBinding,
    extensions: ExtensionProcessing<'a>,
    lookups: OwnedVec<RequestLookup<'q, 'a, 'r, 'response>>,
}
impl<'q, 'a, 'r, 'response> BoundResponse<'q, 'a, 'r, 'response> {
    /// Original request whose complete batch and nonce were examined.
    #[must_use]
    pub fn request(&self) -> &'q OcspRequest<'a> {
        self.request
    }
    /// Actual authenticated response; issuer authority remains a separate check.
    #[must_use]
    pub fn response(&self) -> SignedResponse<'r, 'response> {
        self.response
    }
    /// Actual sent/received nonce relation, preserving missing and unsolicited.
    #[must_use]
    pub fn nonce(&self) -> NonceBinding {
        self.nonce
    }
    /// Request-wide critical processing, not application acceptance.
    #[must_use]
    pub fn extensions(&self) -> ExtensionProcessing<'a> {
        self.extensions
    }
    /// Every original request in order, including repeated `CertIDs`.
    #[must_use]
    pub fn lookups(&self) -> &[RequestLookup<'q, 'a, 'r, 'response>] {
        &self.lookups
    }
}

impl<'a> OcspRequest<'a> {
    /// Decode the original request-wide nonce with the same RFC9654 kernel as
    /// responses. Received legacy sizes 1..128 are readable; generation of new
    /// requests must still supply at least 32 strong random octets.
    pub fn nonce<W: Work>(&self, execution: &W) -> Result<Option<RequestNonce<'a>>> {
        let source = self.execution_in(execution);
        let Some(extension) = self.extensions.get(crate::oid::OCSP_NONCE, &source)? else {
            return Ok(None);
        };
        let bytes = super::super::nonce::read(extension, &source, "ocspRequest.nonce")?;
        RequestNonce::from_sent(bytes).map(Some).map_err(|_| {
            Error::new(
                crate::ErrorCode::MalformedValue,
                "ocspRequest.nonce",
                extension.span().start,
            )
        })
    }

    /// Process known request-wide nonce syntax and preserve unknown critical
    /// demands. RFC6960 §4.1.2 makes all specific extensions optional; unknown
    /// noncritical values remain in the original model, never silently dropped.
    pub fn check_extensions<W: Work>(&self, execution: &W) -> Result<ExtensionProcessing<'a>> {
        process_extensions(&self.extensions, true, &self.execution_in(execution))
            .map(|processed| processed.processing)
    }

    /// Bind the complete original batch to an already authenticated response.
    /// RFC6960 §3.2 requires actual requested-certificate binding. This query
    /// proves neither responder authority nor that a found status is Good.
    /// On any execution/provider refusal all partial lookup storage is dropped.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-3.2>
    pub fn bind_response<'q, 'r, 'response, 'd, D: AsnDigest<'d> + ?Sized, W: Work>(
        &'q self,
        response: SignedResponse<'r, 'response>,
        digest: &'d D,
        execution: &W,
    ) -> CallbackResult<BoundResponse<'q, 'a, 'r, 'response>, D::Error> {
        let source = self.execution_in(execution);
        let processed = process_extensions(&self.extensions, true, &source)?;
        let response_nonce = response.response().nonce(execution)?;
        let response_work = response
            .response()
            .signature_algorithm()
            .query_in(execution);
        let nonce = super::super::nonce::bind(
            processed.nonce,
            response_nonce,
            (&source, "ocspRequest.nonce", self.span.start),
            (
                &response_work,
                "ocspResponse.nonce",
                response.response().span().start,
            ),
        )?;
        let mut lookups = source.vector();
        // The complete output must be retainable before selected-provider
        // comparison callbacks run. Refusal returns no successful partial batch.
        lookups
            .try_reserve_exact(self.entries.len())
            .map_err(|e| Error::resource(e, FIELD, self.span.start))?;
        for request in &self.entries {
            source
                .charge_work(1)
                .map_err(|e| Error::resource(e, FIELD, request.span.start))?;
            let extensions = process_extensions(&request.extensions, false, &source)?.processing;
            let lookup = response.find_id(&request.id, digest, execution)?;
            lookups
                .try_push(RequestLookup {
                    request,
                    lookup,
                    extensions,
                })
                .map_err(|e| Error::resource(e, FIELD, request.span.start))?;
        }
        Ok(BoundResponse {
            request: self,
            response,
            nonce,
            extensions: processed.processing,
            lookups: lookups.into_owned(),
        })
    }
}

struct Processed<'a> {
    processing: ExtensionProcessing<'a>,
    nonce: Option<RequestNonce<'a>>,
}

fn process_extensions<'a, W: Work>(
    extensions: &crate::Extensions<'a>,
    wide: bool,
    execution: &W,
) -> Result<Processed<'a>> {
    let mut processing = ExtensionProcessing::Understood;
    let mut nonce = None;
    for extension in extensions.iter(execution) {
        let extension = extension?;
        execution
            .charge_work(10)
            .map_err(|e| Error::resource(e, FIELD, extension.span().start))?;
        if wide && extension.kind() == crate::oid::OCSP_NONCE {
            let bytes = super::super::nonce::read(extension, execution, "ocspRequest.nonce")?;
            nonce = Some(RequestNonce::from_sent(bytes).map_err(|_| {
                Error::new(
                    crate::ErrorCode::MalformedValue,
                    "ocspRequest.nonce",
                    extension.span().start,
                )
            })?);
        } else if extension.is_critical() && matches!(processing, ExtensionProcessing::Understood) {
            processing = ExtensionProcessing::Unsupported {
                kind: extension.kind(),
                span: extension.span(),
            };
        }
    }
    Ok(Processed { processing, nonce })
}
