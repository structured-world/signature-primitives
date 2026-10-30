//! Schema and selected-provider preflight before state initialization or I/O.

use crate::binding::{self, Binding, Protection, Scope};
use crate::provider::{SignatureDigestError, SignatureMode, SignatureProvider};
use crate::signer::SignerInfo;
use crate::{Error, ErrorCode};
use core::cmp::Ordering;
use structured_asn1::Reader;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_pkix::path::WorkingKey;

/// Which selected-provider operation could not answer the challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Outer digest algorithm.
    Digest,
    /// Outer signature algorithm and effective key compatibility.
    Signature,
    /// Protected digest algorithm.
    ProtectedDigest,
    /// Protected signature algorithm.
    ProtectedSignature,
    /// Full resolved digest identity comparison.
    DigestComparison,
    /// Full resolved signature identity comparison.
    SignatureComparison,
}

/// Processing refusal, independently of unsupported or malformed mechanisms.
#[derive(Debug)]
pub enum PrepareError<E> {
    /// Shared processing/resource failure with original source location.
    Processing(Error),
    /// Original selected-provider failure, including its resource refusal.
    Callback {
        /// Callback that failed.
        part: Part,
        /// Original error; never mapped to mismatch or unsupported.
        source: E,
    },
}

/// Preflight facts, without a signature or trust verdict.
pub enum Preparation<'a, P: SignatureProvider<'a>> {
    /// The complete schema and selected algorithm input contract are resolved.
    Ready(ResolvedSigner<'a, P>),
    /// The selected provider cannot process this explicit mechanism.
    Unsupported(Part),
    /// The schema/algorithm binding is malformed, independently of resources.
    Malformed(Error),
}

/// Resolved content binding, after any protected algorithms have been checked.
/// The temporary protection identifiers are not copied into every ready plan.
#[derive(Debug)]
pub enum ResolvedBinding<'a> {
    /// Original logical content is the signature input.
    Direct,
    /// Original payload digest declaration; signature input is signedAttrs.
    Attributes {
        /// Expected payload digest, borrowed from the original DER value.
        digest: &'a [u8],
        /// That value's original source span.
        digest_span: structured_asn1::Span,
    },
}

/// Movable resolved identities bound to original signer/key/provider inputs.
pub struct ResolvedSigner<'a, P: SignatureProvider<'a>> {
    provider: &'a P,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    binding: ResolvedBinding<'a>,
    digest: P::Identity,
    signature: SignatureMode<P::SignatureIdentity>,
}

impl<'a, P: SignatureProvider<'a>> ResolvedSigner<'a, P> {
    pub(crate) fn into_parts(self) -> ResolvedParts<'a, P> {
        ResolvedParts {
            signer: self.signer,
            key: self.key,
            binding: self.binding,
            digest: self.digest,
            signature: self.signature,
        }
    }
    /// Exact selected provider instance that resolved this challenge.
    #[must_use]
    pub fn provider(&self) -> &'a P {
        self.provider
    }
    /// Original signer, including any independently retained conformance faults.
    #[must_use]
    pub fn signer(&self) -> &'a SignerInfo<'a> {
        self.signer
    }
    /// Original effective key descriptor; no new standing key is synthesized.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'a> {
        self.key
    }
    /// Original direct/attribute content binding.
    #[must_use]
    pub fn binding(&self) -> &ResolvedBinding<'a> {
        &self.binding
    }
    /// Full resolved digest identity.
    #[must_use]
    pub fn digest(&self) -> &P::Identity {
        &self.digest
    }
    /// Distinct raw/prehashed signature input contract.
    #[must_use]
    pub fn signature(&self) -> &SignatureMode<P::SignatureIdentity> {
        &self.signature
    }

    /// Compares prepared signer values under this selected provider's full
    /// algorithm/default semantics, without new resolution, state or hashing.
    ///
    /// Both plans must belong to the same provider instance. Non-algorithm
    /// document fields use the same original-range kernel as the narrow
    /// encoded comparison, especially exact signedAttrs octets. This is a
    /// duplicate-document identity query, not equality of caller trust/key
    /// selections and not signature verification or a conformance verdict.
    pub fn same_signer_value(
        &self,
        other: &Self,
        parent: &Reader<'_>,
    ) -> Result<bool, PrepareError<P::Error>> {
        if !core::ptr::eq(self.provider, other.provider) {
            return Err(PrepareError::Processing(Error::schema(
                ErrorCode::ProviderMismatch,
                "signedData.signerInfos",
                other.signer.span().start,
            )));
        }
        if !self
            .signer
            .same_fields(other.signer, parent)
            .map_err(PrepareError::Processing)?
        {
            return Ok(false);
        }
        let execution = parent.execution();
        let digest = self
            .provider
            .compare(&self.digest, &other.digest, &execution)
            .map_err(|source| PrepareError::Callback {
                part: Part::DigestComparison,
                source,
            })?;
        if digest != Ordering::Equal {
            return Ok(false);
        }
        let ((SignatureMode::Raw(left), SignatureMode::Raw(right))
        | (SignatureMode::Prehashed(left), SignatureMode::Prehashed(right))) =
            (&self.signature, &other.signature)
        else {
            return Ok(false);
        };
        self.provider
            .compare_signature(left, right, &execution)
            .map(|order| order == Ordering::Equal)
            .map_err(|source| PrepareError::Callback {
                part: Part::SignatureComparison,
                source,
            })
    }
}

pub(crate) struct ResolvedParts<'a, P: SignatureProvider<'a>> {
    pub signer: &'a SignerInfo<'a>,
    pub key: WorkingKey<'a>,
    pub binding: ResolvedBinding<'a>,
    pub digest: P::Identity,
    pub signature: SignatureMode<P::SignatureIdentity>,
}

/// Resolves a selected signer only after its complete binding syntax is checked.
///
/// This does not select a certificate, assert SID binding/trust, or discard
/// retained conformance faults. The caller supplies an effective key selected
/// through those independent facts. Unknown/invalid algorithms and provider
/// failures remain distinct. Impossible fixed message-digest widths refuse
/// before signature initialization or payload acquisition. RFC6211 §3 protected
/// algorithms are resolved and compared through the same selected provider,
/// including defaults; generic `AlgorithmIdentifier::matches` is not used.
/// <https://www.rfc-editor.org/rfc/rfc6211#section-3>
pub fn resolve<'a, P: SignatureProvider<'a>>(
    provider: &'a P,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    parent: &Reader<'a>,
    scope: Scope<'a>,
) -> Result<Preparation<'a, P>, PrepareError<P::Error>> {
    crate::provider::require_instance(provider, "signerInfo", signer.span().start)
        .map_err(PrepareError::Processing)?;
    signer
        .require_session(parent, "signerInfo")
        .map_err(PrepareError::Processing)?;
    // Both inspection gates precede binding work and all provider callbacks.
    // A valid digest cannot authorize observable resolution when the later
    // signature declaration already contains a retained syntax fault.
    let identifiers = match algorithms(signer) {
        Ok(identifiers) => identifiers,
        Err(error) => return Ok(Preparation::Malformed(error)),
    };
    let binding = match binding::inspect(signer, parent, scope) {
        Ok(binding) => binding,
        Err(error) if error.is_terminal() => return Err(PrepareError::Processing(error)),
        Err(error) => return Ok(Preparation::Malformed(error)),
    };
    let identifier = identifiers.0;
    let digest = match provider
        .resolve_signature_digest(identifier, key, parent)
        .map_err(|error| digest_error(error, Part::Digest))?
    {
        Resolution::Supported(digest) => digest,
        Resolution::Unsupported => return Ok(Preparation::Unsupported(Part::Digest)),
        Resolution::Malformed => {
            return Ok(Preparation::Malformed(Error::schema(
                ErrorCode::AlgorithmSyntax,
                "signerInfo.digestAlgorithm",
                identifier.offset(),
            )));
        }
    };
    if let Binding::Attributes {
        digest: expected,
        digest_span,
        ..
    } = &binding
        && let Some(width) = provider.width(&digest)
        && expected.len() != width
    {
        return Ok(Preparation::Malformed(Error::schema(
            ErrorCode::DigestWidth,
            "signerInfo.signedAttrs.messageDigest",
            digest_span.start,
        )));
    }
    let identifier = identifiers.1;
    let signature = match provider
        .resolve_signature(identifier, &digest, key, identifier.encoding(), parent)
        .map_err(|source| PrepareError::Callback {
            part: Part::Signature,
            source,
        })? {
        Resolution::Supported(signature) => signature,
        Resolution::Unsupported => return Ok(Preparation::Unsupported(Part::Signature)),
        Resolution::Malformed => {
            return Ok(Preparation::Malformed(Error::schema(
                ErrorCode::AlgorithmSyntax,
                "signerInfo.signatureAlgorithm",
                identifier.offset(),
            )));
        }
    };
    if let Binding::Attributes {
        protection: Some(protection),
        ..
    } = &binding
    {
        match protected(provider, *protection, &digest, &signature, key, parent)? {
            ProtectionStatus::Matching => {}
            ProtectionStatus::Unsupported(part) => return Ok(Preparation::Unsupported(part)),
            ProtectionStatus::Malformed(error) => return Ok(Preparation::Malformed(error)),
        }
    }
    let binding = match binding {
        Binding::Direct => ResolvedBinding::Direct,
        Binding::Attributes {
            digest,
            digest_span,
            ..
        } => ResolvedBinding::Attributes {
            digest,
            digest_span,
        },
    };
    Ok(Preparation::Ready(ResolvedSigner {
        provider,
        signer,
        key,
        binding,
        digest,
        signature,
    }))
}

enum ProtectionStatus {
    Matching,
    Unsupported(Part),
    Malformed(Error),
}

fn algorithms<'a>(
    signer: &SignerInfo<'a>,
) -> Result<
    (
        structured_pkix::AlgorithmIdentifier<'a>,
        structured_pkix::AlgorithmIdentifier<'a>,
    ),
    Error,
> {
    let digest = signer
        .digest_algorithm()
        .require_identifier()
        .map_err(Error::pkix)?;
    let signature = signer
        .signature_algorithm()
        .require_identifier()
        .map_err(Error::pkix)?;
    Ok((digest, signature))
}

fn protected<'a, P: SignatureProvider<'a>>(
    provider: &'a P,
    protection: Protection<'a>,
    digest: &P::Identity,
    signature: &SignatureMode<P::SignatureIdentity>,
    key: WorkingKey<'a>,
    parent: &Reader<'a>,
) -> Result<ProtectionStatus, PrepareError<P::Error>> {
    const FIELD: &str = "signerInfo.signedAttrs.cmsAlgorithmProtection";
    let identifier = protection.digest();
    let protected_digest = match provider
        .resolve_signature_digest(identifier, key, parent)
        .map_err(|error| digest_error(error, Part::ProtectedDigest))?
    {
        Resolution::Supported(digest) => digest,
        Resolution::Unsupported => {
            return Ok(ProtectionStatus::Unsupported(Part::ProtectedDigest));
        }
        Resolution::Malformed => {
            return Ok(ProtectionStatus::Malformed(Error::schema(
                ErrorCode::AlgorithmSyntax,
                FIELD,
                identifier.offset(),
            )));
        }
    };
    if provider
        .compare(digest, &protected_digest, &parent.execution())
        .map_err(|source| PrepareError::Callback {
            part: Part::DigestComparison,
            source,
        })?
        != Ordering::Equal
    {
        return Ok(ProtectionStatus::Malformed(Error::schema(
            ErrorCode::AlgorithmProtection,
            FIELD,
            identifier.offset(),
        )));
    }
    let identifier = protection.signature();
    let protected_signature = match provider
        .resolve_signature(
            identifier,
            &protected_digest,
            key,
            identifier.encoding(),
            parent,
        )
        .map_err(|source| PrepareError::Callback {
            part: Part::ProtectedSignature,
            source,
        })? {
        Resolution::Supported(signature) => signature,
        Resolution::Unsupported => {
            return Ok(ProtectionStatus::Unsupported(Part::ProtectedSignature));
        }
        Resolution::Malformed => {
            return Ok(ProtectionStatus::Malformed(Error::schema(
                ErrorCode::AlgorithmSyntax,
                FIELD,
                identifier.offset(),
            )));
        }
    };
    parent.execution().charge_work(1).map_err(|reason| {
        PrepareError::Processing(Error::resource(reason, FIELD, identifier.offset()))
    })?;
    let same = match (signature, &protected_signature) {
        (SignatureMode::Raw(left), SignatureMode::Raw(right))
        | (SignatureMode::Prehashed(left), SignatureMode::Prehashed(right)) => {
            provider
                .compare_signature(left, right, &parent.execution())
                .map_err(|source| PrepareError::Callback {
                    part: Part::SignatureComparison,
                    source,
                })?
                == Ordering::Equal
        }
        _ => false,
    };
    if !same {
        return Ok(ProtectionStatus::Malformed(Error::schema(
            ErrorCode::AlgorithmProtection,
            FIELD,
            identifier.offset(),
        )));
    }
    Ok(ProtectionStatus::Matching)
}

fn digest_error<E>(error: SignatureDigestError<E>, part: Part) -> PrepareError<E> {
    match error {
        SignatureDigestError::Encoding(error) => PrepareError::Processing(Error::pkix(error)),
        SignatureDigestError::Callback(source) => PrepareError::Callback { part, source },
    }
}
