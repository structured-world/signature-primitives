//! The original request signature, independently of requester authorization.

use super::{FIELD, OcspRequest};
use crate::error::{CallbackError, Error};
use crate::general_name::{self, GeneralName};
use crate::path::{Verified, Verify, WorkingKey};
use crate::{Certificate, revocation::RevocationTarget};
use core::fmt;
use structured_asn1::memory::Work;

/// A processing refusal or the original selected verifier's error.
pub type RequestSignatureError<E> = CallbackError<E>;

/// Completed negative signature/key result, distinct from an execution error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSignatureFailure {
    /// The supplied effective key belongs to a different original SPKI.
    KeyBinding,
    /// Signature arithmetic completed and rejected the signature.
    Signature,
}

/// Relation of the declared requester name to the actual signing certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestorBinding {
    /// Directory subject or one subjectAltName matches the original requestor.
    /// Opaque name forms use the shared `GeneralName` encoded-identity contract.
    Matches,
    /// No subject/subjectAltName matches. The signature can still be valid;
    /// this result must not be presented as an authenticated requester name.
    Differs,
}

/// Original key-bound signature and independently reported requester-name fact.
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'q, 'a, 'c, 'cert> {
    request: &'q OcspRequest<'a>,
    signer: &'c Certificate<'cert>,
    key: WorkingKey<'cert>,
    name: RequestorBinding,
}
impl<'q, 'a, 'c, 'cert> SignedRequest<'q, 'a, 'c, 'cert> {
    /// The exact original request whose TBS was verified.
    #[must_use]
    pub fn request(self) -> &'q OcspRequest<'a> {
        self.request
    }
    /// The actual certificate whose SPKI was bound before verification.
    #[must_use]
    pub fn signer(self) -> &'c Certificate<'cert> {
        self.signer
    }
    /// Same effective key passed to the selected verifier.
    #[must_use]
    pub fn key(self) -> WorkingKey<'cert> {
        self.key
    }
    /// Separate declared-name binding, not certificate path/server permission.
    #[must_use]
    pub fn requestor(self) -> RequestorBinding {
        self.name
    }
}

/// Mathematical authentication does not decide request acceptance or trust.
#[derive(Debug)]
pub enum RequestAuthentication<'q, 'a, 'c, 'cert> {
    /// No signature was present; the verifier was not invoked.
    Unsigned,
    /// Original TBS verified with the actual certificate-bound effective key.
    Signed(SignedRequest<'q, 'a, 'c, 'cert>),
    /// Completed negative key binding or signature result.
    Rejected(RequestSignatureFailure),
    /// Selected verifier cannot process this algorithm/key combination.
    UnsupportedSignature,
}

impl fmt::Display for RequestSignatureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KeyBinding => "request key differs from signer SPKI",
            Self::Signature => "request signature rejected",
        })
    }
}

impl<'a> OcspRequest<'a> {
    /// Verify the exact original `TBSRequest` and bind the actual signer SPKI.
    /// RFC6960 §4.1.2 makes signing optional and names mandatory when signed.
    /// Requestor-name binding is reported separately: certificate path, key
    /// usage, name interpretation and server authorization remain with callers.
    /// Included certificates are never automatically selected or trusted.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.1.2>
    pub fn authenticate_signature<'q, 'c, 'cert, V: Verify<E>, E: Work>(
        &'q self,
        signer: &'c Certificate<'cert>,
        key: WorkingKey<'cert>,
        verifier: &V,
        execution: &E,
    ) -> core::result::Result<
        RequestAuthentication<'q, 'a, 'c, 'cert>,
        RequestSignatureError<V::Error>,
    > {
        let current = self.execution_in(execution);
        current
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, self.span.start))?;
        let Some(signature) = &self.signature else {
            return Ok(RequestAuthentication::Unsigned);
        };
        let actual_work = signer.execution_in(execution);
        let key_work = key.key().execution_in(execution);
        if !super::binding::equal(
            key.key().as_bytes(),
            &key_work,
            signer.tbs().public_key().as_bytes(),
            &actual_work,
            "ocspRequest.signerKey",
            key.key().key_offset(),
            signer.span().start,
        )? {
            return Ok(RequestAuthentication::Rejected(
                RequestSignatureFailure::KeyBinding,
            ));
        }
        // The parser enforces presence before constructing a signed request.
        let Some(requestor) = self.requestor.as_ref() else {
            return Err(Error::new(
                crate::ErrorCode::MissingField,
                "ocspRequest.requestorName",
                self.signed.span().start,
            )
            .into());
        };
        let mut name = RequestorBinding::Differs;
        if let GeneralName::Directory(requestor) = requestor
            && requestor.matches_between(
                signer.tbs().subject(),
                (&current, self.parser),
                (&actual_work, signer.source_parser()),
            )?
        {
            name = RequestorBinding::Matches;
        }
        if name == RequestorBinding::Differs
            && let Some(names) = signer.tbs().extensions().subject_alt_name(execution)?
        {
            for candidate in &*names {
                actual_work.charge_work(1).map_err(|reason| {
                    Error::resource(reason, "ocspRequest.requestorName", signer.span().start)
                })?;
                if general_name::matches_between(
                    requestor,
                    candidate,
                    (&current, self.parser),
                    (&actual_work, signer.source_parser()),
                    self.signed.span().start,
                    "ocspRequest.requestorName",
                )? {
                    name = RequestorBinding::Matches;
                    break;
                }
            }
        }
        current
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, self.span.start))?;
        match verifier
            .verify(
                &signature.algorithm,
                key,
                self.signed_bytes(),
                signature.value,
                execution,
            )
            .map_err(CallbackError::Callback)?
        {
            Verified::Yes => Ok(RequestAuthentication::Signed(SignedRequest {
                request: self,
                signer,
                key,
                name,
            })),
            Verified::No => Ok(RequestAuthentication::Rejected(
                RequestSignatureFailure::Signature,
            )),
            Verified::Unsupported => Ok(RequestAuthentication::UnsupportedSignature),
        }
    }
}
