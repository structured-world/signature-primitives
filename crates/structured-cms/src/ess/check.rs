//! Selected-provider certificate hash and issuer facts, without trust claims.

use super::{CertificateId, IssuerAgreement, SigningAttributes};
use crate::digest::{DigestBatch, DigestError, PassError};
use crate::provider::{DigestProvider, Resolution};
use crate::stream::RangesError;
use crate::{Error, Octets};
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_asn1::{Reader, Span};
use structured_pkix::Certificate;

/// Agreement of one ESS first identifier with a caller-selected certificate.
/// None of these answers independently establishes signature/path trust or
/// erases the parsed attribute's conformance/restriction diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Whole-certificate hash and the optional readable issuer/serial agree.
    Matches,
    /// Computed whole-certificate hash does not agree.
    HashDiffers,
    /// Hash agrees but readable issuer/serial identifies something else.
    IssuerDiffers,
    /// Written issuer/serial is unreadable; hash agreement is insufficient.
    IssuerUnreadable,
    /// Known digest width cannot produce the declared certificate hash.
    MalformedHash,
    /// Selected provider rejects the written algorithm's parameter syntax.
    MalformedAlgorithm,
    /// The selected provider cannot compute this explicit mechanism.
    Unsupported,
}

/// Both independent answers; absence does not imply a successful binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bindings {
    /// V1 answer when that signed attribute existed.
    pub v1: Option<Binding>,
    /// V2 answer when that signed attribute existed.
    pub v2: Option<Binding>,
}

/// Resource, source-pass and provider failures remain outside semantic answers.
#[derive(Debug)]
pub enum BindingError<E> {
    /// Original common processing/resource refusal and its source location.
    Processing(Error),
    /// Original resolver/comparison failure, including backend resources.
    Callback {
        /// Original enclosing ESS field whose callback refused.
        field: &'static str,
        /// Real original identifier span; no offset is synthesized.
        span: Span,
        /// Original selected-provider cause.
        source: E,
    },
    /// Digest preparation/refusal or provider output contract failure.
    Digest {
        /// Original whole-certificate range being processed.
        span: Span,
        /// Common digest/provider cause, independently of document conformance.
        source: DigestError<E>,
    },
    /// Incomplete/failed certificate pass; no successful partial output.
    Pass {
        /// Original whole-certificate range supplied to the failed pass.
        span: Span,
        /// Original source/common/provider cause.
        source: PassError<RangesError, E>,
    },
    /// An accepted request is absent from a completed common digest memo.
    /// This is an internal processing contract failure, not document syntax
    /// or a provider's negative cryptographic answer.
    LostRequest(usize),
}

enum Expected<'a, W: Work> {
    Borrowed(&'a [u8]),
    Joined(OwnedVec<u8, W>),
}

impl<W: Work> Expected<'_, W> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Joined(bytes) => bytes,
        }
    }
}

struct Queued<'s, 'a, W: Work> {
    identifier: &'s CertificateId<'a>,
    expected: Expected<'a, W>,
    ordinal: usize,
}

enum Request<I, H> {
    Answer(Binding),
    Compute { identity: I, expected: H },
}

type PreparedRequest<'a, 'p, P> = Result<
    Request<<P as DigestProvider<'a>>::Identity, Expected<'a, Execution<'p>>>,
    BindingError<<P as DigestProvider<'a>>::Error>,
>;

impl<'a> SigningAttributes<'a> {
    /// Checks both first identifiers over one complete original DER certificate.
    ///
    /// Resolution and known-width checks precede every state/input side effect.
    /// Semantic digest identities are deduplicated through the selected provider;
    /// neither digest states nor output identities are cloned. Each version keeps
    /// its own outcome, while the target issuer is prepared at most once. Later
    /// identifiers and policy terms remain signed validation-set restrictions in
    /// this object; the caller must enforce them and signature/path/time policy.
    pub fn bind_certificate<P: DigestProvider<'a>>(
        &self,
        provider: &'a P,
        certificate: &Certificate<'_>,
        parent: &Reader<'a>,
    ) -> Result<Bindings, BindingError<P::Error>> {
        let execution = parent.execution();
        let identifiers = [
            self.v1().map(super::SigningCertificate::signer),
            self.v2().map(super::SigningCertificate::signer),
        ];
        let mut answers = [None, None];
        let mut queued = [None, None];
        let mut identities = None;
        for (index, identifier) in identifiers.iter().enumerate() {
            let Some(identifier) = identifier else {
                continue;
            };
            let at = identifier.element().span().start;
            let field = identifier.field;
            match prepare_request(provider, identifier, parent)? {
                Request::Answer(answer) => answers[index] = Some(answer),
                Request::Compute { identity, expected } => {
                    let identities = match identities.as_mut() {
                        Some(identities) => identities,
                        None => identities.insert(execution.vector()),
                    };
                    let ordinal = identities.len();
                    identities.try_push(identity).map_err(|reason| {
                        BindingError::Processing(Error::resource(reason, field, at))
                    })?;
                    queued[index] = Some(Queued {
                        identifier,
                        expected,
                        ordinal,
                    });
                }
            }
        }
        let Some(identities) = identities else {
            return Ok(Bindings {
                v1: answers[0],
                v2: answers[1],
            });
        };
        let source_at = certificate.span().start;
        let batch = DigestBatch::prepare(
            provider,
            identities.into_owned(),
            &execution,
            "ess.certificate",
            source_at,
        )
        .map_err(|source| BindingError::Digest {
            span: certificate.span(),
            source,
        })?;
        let mut ranges = [certificate.as_bytes()];
        let memo = batch
            .run(&mut ranges, &execution)
            .map_err(|source| BindingError::Pass {
                span: certificate.span(),
                source,
            })?;
        let mut issuer = None;
        for (index, request) in queued.into_iter().enumerate() {
            let Some(request) = request else {
                continue;
            };
            let Some(digest) = memo
                .for_request(request.ordinal, &execution)
                .map_err(|source| BindingError::Digest {
                    span: certificate.span(),
                    source,
                })?
            else {
                return Err(BindingError::LostRequest(request.ordinal));
            };
            answers[index] = Some(compare_binding(
                provider,
                request.identifier,
                request.expected.as_bytes(),
                digest.prehash(),
                certificate,
                parent,
                &mut issuer,
            )?);
        }
        Ok(Bindings {
            v1: answers[0],
            v2: answers[1],
        })
    }
}

fn prepare_request<'a, 'p, P: DigestProvider<'a>>(
    provider: &'a P,
    identifier: &CertificateId<'a>,
    parent: &'p Reader<'a>,
) -> PreparedRequest<'a, 'p, P> {
    crate::provider::require_instance(
        provider,
        identifier.field,
        identifier.element().span().start,
    )
    .map_err(BindingError::Processing)?;
    let execution = parent.execution();
    let at = identifier.element().span().start;
    let field = identifier.field;
    execution
        .charge_work(1)
        .map_err(|reason| BindingError::Processing(Error::resource(reason, field, at)))?;
    let resolved = provider
        .resolve_digest(identifier.digest_algorithm(), parent.encoding(), parent)
        .map_err(|source| BindingError::Callback {
            field,
            span: identifier.element().span(),
            source,
        })?;
    match resolved {
        Resolution::Unsupported => Ok(Request::Answer(Binding::Unsupported)),
        Resolution::Malformed => Ok(Request::Answer(Binding::MalformedAlgorithm)),
        Resolution::Supported(identity) => {
            if let Some(width) = provider.digest_width(&identity)
                && width != identifier.hashed().len()
            {
                return Ok(Request::Answer(Binding::MalformedHash));
            }
            // Only a constructed logical hash needs a joined buffer. Every
            // declaration's admission finishes before any hash state starts.
            let expected = prepare_expected(identifier.hashed(), &execution, field, at)?;
            Ok(Request::Compute { identity, expected })
        }
    }
}

fn prepare_expected<'a, W: Work, E>(
    octets: &Octets<'a>,
    execution: &W,
    field: &'static str,
    at: u64,
) -> Result<Expected<'a, W>, BindingError<E>> {
    if let Some(bytes) = octets.as_one() {
        return Ok(Expected::Borrowed(bytes));
    }
    let mut joined = execution.vector();
    joined
        .try_reserve_exact(octets.len())
        .map_err(|reason| BindingError::Processing(Error::resource(reason, field, at)))?;
    for piece in octets.pieces() {
        execution.charge_work(1).map_err(|reason| {
            BindingError::Processing(Error::resource(reason, field, piece.span().start))
        })?;
        joined
            .try_extend_from_slice(piece.as_bytes())
            .map_err(|reason| {
                BindingError::Processing(Error::resource(reason, field, piece.span().start))
            })?;
    }
    Ok(Expected::Joined(joined))
}

fn compare_binding<'a, 'c, 'p, P: DigestProvider<'a>>(
    provider: &P,
    identifier: &CertificateId<'a>,
    expected: &[u8],
    digest: crate::provider::Prehash<'_, '_, P, P::Identity>,
    certificate: &Certificate<'c>,
    parent: &'p Reader<'_>,
    issuer: &mut Option<structured_pkix::Ordered<'c, Execution<'p>>>,
) -> Result<Binding, BindingError<P::Error>> {
    // Variable-width identities still require complete declared/actual output
    // agreement. A width mismatch is malformed, never an ordinary hash mismatch.
    if expected.len() != digest.as_bytes().len() {
        return Ok(Binding::MalformedHash);
    }
    let matches = provider
        .matches_digest(digest, expected, &parent.execution())
        .map_err(|source| BindingError::Callback {
            field: identifier.field,
            span: identifier.element().span(),
            source,
        })?;
    if !matches {
        return Ok(Binding::HashDiffers);
    }
    match identifier
        .matches_issuer_with(certificate, parent, issuer)
        .map_err(BindingError::Processing)?
    {
        IssuerAgreement::Unstated | IssuerAgreement::Matches => Ok(Binding::Matches),
        IssuerAgreement::Differs => Ok(Binding::IssuerDiffers),
        IssuerAgreement::Unreadable => Ok(Binding::IssuerUnreadable),
    }
}
