//! Response execution delegates all timestamp semantics to the existing core.

use super::{Response, Status};
use crate::timestamp::{
    CheckContext, CheckError, CheckedTimestamp, ImprintOperand, ProfileCheckError, ProfileFailure,
    ProfileInput, RequestFieldError, TokenExtension,
};
use crate::{Error, ErrorCode, provider::SignatureProvider, stream::Source};
use core::convert::Infallible;
use structured_asn1::{Reader, memory::Execution};

/// Completed response facts. A rejection/waiting/notification has no timestamp
/// evidence; a granted status still does not override negative token facts.
pub struct CheckedResponse<'a> {
    status: Status,
    timestamp: Option<CheckedTimestamp<'a>>,
}
impl<'a> CheckedResponse<'a> {
    /// Original unauthenticated response status, not a cryptographic assertion.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }
    /// Original complete token checks, when a token was present.
    #[must_use]
    pub fn timestamp(&self) -> Option<&CheckedTimestamp<'a>> {
        self.timestamp.as_ref()
    }
    /// Move the token result without copying retained evidence or diagnostics.
    pub fn into_timestamp(self) -> Option<CheckedTimestamp<'a>> {
        self.timestamp
    }
}
impl<'doc> Response<'doc> {
    /// Check a response against its actual live parsed request. `context.requested`
    /// is required; its absence is a caller-context `InvalidLocation` refusal, not
    /// a malformed response or a downgrade to archival checking. Negative status
    /// responses start no provider, profile, recognizer or covered-content work.
    /// All token, request, source, callback and resource causes remain unchanged.
    #[expect(
        clippy::result_large_err,
        reason = "preserve the existing original token/source refusal without allocating an error box on resource exhaustion"
    )]
    pub fn check<'a, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        query: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<CheckedResponse<'a>, CheckError<S::Error, PE, RE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_with_profile(provider, query, context, covered, recognizes, |_| {
            Ok::<(), ProfileFailure<Infallible>>(())
        })
        .map_err(ProfileCheckError::into_common)
    }
    /// Same shared token kernel with its original pre-crypto profile hook. No
    /// response status, nonce or certificate hint bypasses the selected profile.
    #[expect(
        clippy::result_large_err,
        reason = "retain the existing typed token/profile/source cause without another fallible allocation"
    )]
    pub fn check_with_profile<'a, P, S: Source, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        query: &Reader<'a>,
        context: &CheckContext<'a, '_>,
        covered: &mut S,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        profile: impl for<'view, 'scope> FnOnce(
            ProfileInput<'view, 'doc, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<CheckedResponse<'a>, ProfileCheckError<S::Error, PE, RE, FE>>
    where
        'doc: 'a,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let Some(requested) = &context.requested else {
            return Err(CheckError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                "timeStampResp.requestContext",
                self.element().span().start,
            ))
            .into());
        };
        requested
            .request
            .imprint()
            .require_session(requested.parent)
            .map_err(|source| {
                CheckError::RequestField(RequestFieldError {
                    operand: ImprintOperand::Requested,
                    source,
                })
            })?;
        let timestamp = match self.token_in(query).map_err(CheckError::Processing)? {
            Some((token, reader)) => Some(
                token
                    .check_with_profile(provider, &reader, context, covered, recognizes, profile)?,
            ),
            None => None,
        };
        Ok(CheckedResponse {
            status: self.status().status(),
            timestamp,
        })
    }
}
