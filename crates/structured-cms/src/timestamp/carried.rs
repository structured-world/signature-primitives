//! Exact selected-certificate carriage, distinct from SID or trust matching.

use super::{ImprintOperand, Request, RequestFieldError, Token};
use crate::{Error, ErrorCode};
use structured_asn1::{Reader, memory::Work};
use structured_pkix::Certificate;

impl Token<'_> {
    /// Checks the parsed request's certReq against this original `SignedData`.
    ///
    /// RFC3161 §2.4.1 requires the signing certificate when TRUE, and absence
    /// of the certificates field when FALSE (including the schema default).
    /// A present empty field fails FALSE; a different certificate with the same
    /// SID fails TRUE. `selected` must independently be signature/ESS-bound;
    /// exact carriage alone establishes neither binding nor certificate trust.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1>
    pub fn matches_cert_req(
        &self,
        requested: &Request<'_>,
        selected: Option<&Certificate<'_>>,
        token_parent: &Reader<'_>,
        request_parent: &Reader<'_>,
    ) -> Result<bool, RequestFieldError> {
        self.signer()
            .require_session(token_parent, "signedData.certificates")
            .map_err(|source| RequestFieldError {
                operand: ImprintOperand::Token,
                source,
            })?;
        if !requested.same_session(request_parent) {
            return Err(RequestFieldError {
                operand: ImprintOperand::Requested,
                source: Error::pkix(structured_pkix::Error::new(
                    structured_pkix::ErrorCode::ForeignReader,
                    "timeStampReq.certReq",
                    requested.span().start,
                )),
            });
        }
        let work = token_parent.execution();
        let at = self
            .message()
            .certificate_field()
            .map_or(self.message().span().start, |span| span.start);
        let failure = |reason| RequestFieldError {
            operand: ImprintOperand::Token,
            source: Error::resource(reason, "signedData.certificates", at),
        };
        work.charge_work(1).map_err(failure)?;
        if !requested.cert_req() {
            return Ok(self.message().certificate_field().is_none());
        }
        let Some(selected) = selected else {
            return Ok(false);
        };
        for carried in self.message().certificates() {
            work.charge_work(1).map_err(failure)?;
            let original = selected.as_bytes();
            let written = carried.as_bytes();
            if original.len() != written.len() {
                continue;
            }
            let length = u64::try_from(original.len()).map_err(|_| RequestFieldError {
                operand: ImprintOperand::Token,
                source: Error::schema(ErrorCode::LengthOverflow, "signedData.certificates", at),
            })?;
            work.charge_work(length).map_err(failure)?;
            if original == written {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
