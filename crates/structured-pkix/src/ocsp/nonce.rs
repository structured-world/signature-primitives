//! Request nonce binding; randomness and request transport belong to the caller.

use super::{BasicResponse, end};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::oid;
use structured_asn1::memory::Work;

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
impl core::error::Error for NonceSizeError {}

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
    /// The requested nonce could not be decoded from a noncritical extension.
    Malformed {
        /// Original decoding failure.
        code: ErrorCode,
        /// Original byte offset of the failure.
        offset: u64,
    },
}

impl NonceBinding {
    /// Whether an actual requested nonce failed to bind the response.
    #[must_use]
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Missing | Self::Differs | Self::Malformed { .. })
    }
}

pub(super) fn read<'a, W: Work>(
    extension: &crate::Extension<'a>,
    execution: &W,
    field: &'static str,
) -> Result<&'a [u8]> {
    let mut reader = extension.reader_scoped(execution).field(field)?;
    let value = reader
        .expect(structured_asn1::Tag::primitive(
            structured_asn1::universal::OCTET_STRING,
        ))
        .field(field)?;
    end(&reader, field)?;
    let bytes = value.contents();
    // RFC9654 §2.1: encoded inner OCTET STRING, not raw extnValue bytes.
    // https://www.rfc-editor.org/rfc/rfc9654#section-2.1
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            extension.span().start,
        ));
    }
    Ok(bytes)
}

pub(super) fn bind<L: Work, R: Work>(
    request: Option<RequestNonce<'_>>,
    response: Option<&crate::Extension<'_>>,
    left: (&L, &'static str, u64),
    right: (&R, &'static str, u64),
) -> Result<NonceBinding> {
    let Some(response) = response else {
        return Ok(if request.is_some() {
            NonceBinding::Missing
        } else {
            NonceBinding::NotRequested
        });
    };
    // RFC 9654 §2.1 gives nonce its request-response binding role.
    // An unsolicited noncritical value is irrelevant to that binding.
    // https://www.rfc-editor.org/rfc/rfc9654#section-2.1
    if request.is_none() && !response.is_critical() {
        return Ok(NonceBinding::Unsolicited);
    }
    let value = match read(response, right.0, right.1) {
        Ok(value) => value,
        Err(error) if error.is_resource() || response.is_critical() => return Err(error),
        Err(error) => {
            return Ok(NonceBinding::Malformed {
                code: error.code(),
                offset: error.offset(),
            });
        }
    };
    let Some(request) = request else {
        return Ok(NonceBinding::Unsolicited);
    };
    let request = request.as_bytes();
    left.0
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, left.1, left.2))?;
    right
        .0
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, right.1, right.2))?;
    if request.len() != value.len() {
        return Ok(NonceBinding::Differs);
    }
    left.0
        .charge_work(request.len() as u64)
        .map_err(|reason| Error::resource(reason, left.1, left.2))?;
    right
        .0
        .charge_work(value.len() as u64)
        .map_err(|reason| Error::resource(reason, right.1, right.2))?;
    Ok(if request == value {
        NonceBinding::Matches
    } else {
        NonceBinding::Differs
    })
}

impl<'a> BasicResponse<'a> {
    /// Decode a response nonce, retaining the producing parser's local work and
    /// depth ceilings. Received nonce syntax accepts 1..128 octets, including
    /// legacy short nonces; this does not relax new-request construction.
    pub fn nonce<W: Work>(&self, execution: &W) -> Result<Option<&'a [u8]>> {
        match self.extensions.get(oid::OCSP_NONCE, execution)? {
            Some(extension) => read(extension, execution, "ocspResponse.nonce").map(Some),
            None => Ok(None),
        }
    }

    /// Compare the actual request nonce only after authenticating this response.
    /// Unsolicited noncritical values are reported without decoding. A malformed
    /// requested noncritical value preserves its original decoding failure.
    /// Resource failures and malformed critical values return errors.
    pub fn bind_nonce<W: Work>(
        &self,
        request: Option<RequestNonce<'_>>,
        execution: &W,
    ) -> Result<NonceBinding> {
        let source = self.algorithm.query_in(execution);
        bind(
            request,
            self.extensions.get(oid::OCSP_NONCE, execution)?,
            (execution, "ocspResponse.nonce", self.span.start),
            (&source, "ocspResponse.nonce", self.span.start),
        )
    }
}
