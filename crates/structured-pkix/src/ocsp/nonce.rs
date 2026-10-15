//! Request nonce binding; randomness and request transport belong to the caller.

use super::{BasicResponse, end};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::oid;
use structured_asn1::memory::{MemoryError, Work};

/// Caller-generated nonce for a new RFC9654 request. Construction validates
/// size only; the caller must use a cryptographically strong random generator.
#[derive(Debug, Clone, Copy)]
pub struct RequestNonce<'a>(&'a [u8]);

/// The actual sent nonce has a size outside the received wire schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceSizeError {
    /// Actual octet count; no input bytes are copied into diagnostics.
    pub length: usize,
}
impl core::fmt::Display for NonceSizeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "nonce length {} is outside 1..128", self.length)
    }
}
#[cfg(feature = "std")]
impl std::error::Error for NonceSizeError {}

impl<'a> RequestNonce<'a> {
    /// Retain an actual sent wire nonce for comparison, including legacy short
    /// requests. RFC9654 §2.1 permits received sizes 1..128; generation of a
    /// new compliant request must still use at least 32 strong random octets.
    /// Invalid input is an error, not an absent request nonce.
    /// <https://www.rfc-editor.org/rfc/rfc9654#section-2.1>
    pub fn from_sent(bytes: &'a [u8]) -> core::result::Result<Self, NonceSizeError> {
        if bytes.is_empty() || bytes.len() > 128 {
            return Err(NonceSizeError {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }
    /// Validate a newly generated request value. RFC9654 §2.1 requires new
    /// requesters to use at least 32 octets; the
    /// schema maximum is 128. This is not a check of the bytes' randomness.
    /// <https://www.rfc-editor.org/rfc/rfc9654#section-2.1>
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes.len() > 128 {
            return None;
        }
        Some(Self(bytes))
    }

    /// Original request bytes; no copy or encoding bridge.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Completed request-binding fact, not response authenticity or time validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceBinding {
    /// Neither request nor response carries a nonce.
    NotRequested,
    /// Responder supplied a nonce without a nonce-bearing request.
    Unsolicited,
    /// A nonce-bearing request received a response without one.
    Missing,
    /// The original request and response nonce bytes agree.
    Matches,
    /// The original request and response nonce bytes differ.
    Differs,
}

pub(super) fn read<'a, W: Work + 'a>(
    extension: &crate::Extension<'a>,
    execution: &W,
) -> Result<&'a [u8]> {
    const FIELD: &str = "ocspResponse.nonce";
    let mut reader = extension.reader(execution).field(FIELD)?;
    let value = reader
        .expect(structured_asn1::Tag::primitive(
            structured_asn1::universal::OCTET_STRING,
        ))
        .field(FIELD)?;
    end(&reader, FIELD)?;
    let bytes = value.contents();
    // RFC9654 §2.1: encoded inner OCTET STRING, not raw extnValue bytes.
    // https://www.rfc-editor.org/rfc/rfc9654#section-2.1
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            extension.span().start,
        ));
    }
    Ok(bytes)
}

pub(super) fn bind<W: Work>(
    request: Option<RequestNonce<'_>>,
    response: Option<&[u8]>,
    execution: &W,
    at: u64,
) -> Result<NonceBinding> {
    let (request, response) = match (request, response) {
        (None, None) => return Ok(NonceBinding::NotRequested),
        (None, Some(_)) => return Ok(NonceBinding::Unsolicited),
        (Some(_), None) => return Ok(NonceBinding::Missing),
        (Some(request), Some(response)) => (request.as_bytes(), response),
    };
    let work = u64::try_from(request.len().max(response.len()))
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, "ocspResponse.nonce", at))?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, "ocspResponse.nonce", at))?;
    Ok(if request == response {
        NonceBinding::Matches
    } else {
        NonceBinding::Differs
    })
}

impl<'a> BasicResponse<'a> {
    /// Decode a response nonce, retaining the producing parser's local work and
    /// depth ceilings. Received nonce syntax accepts 1..128 octets, including
    /// legacy short nonces; this does not relax new-request construction.
    pub fn nonce<W: Work + 'a>(&self, execution: &W) -> Result<Option<&'a [u8]>> {
        match self.extensions.get(oid::OCSP_NONCE, execution)? {
            Some(extension) => read(extension, execution).map(Some),
            None => Ok(None),
        }
    }

    /// Compare the actual request nonce only after authenticating this response.
    /// Missing/unsolicited values are preserved for the caller's replay policy;
    /// they are never replaced by a generated or default nonce.
    pub fn bind_nonce<W: Work + 'a>(
        &self,
        request: Option<RequestNonce<'_>>,
        execution: &W,
    ) -> Result<NonceBinding> {
        bind(request, self.nonce(execution)?, execution, self.span.start)
    }
}
