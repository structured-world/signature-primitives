//! Explicit object-digest Holder binding (RFC5755 §7.3), not authorization.
//!
//! A key assertion covers DER effective `SubjectPublicKeyInfo`, not just key bits
//! or the subject's parameter-less SPKI. A certificate assertion covers the
//! entire original DER Certificate, including its signature. Input selection is
//! explicit; other Holder alternatives are never tried as a fallback.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-7.3>

use super::super::{AttributeCertificate, DigestedObject};
use crate::Error;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_pkix::Certificate;
use structured_pkix::algorithm::digest::{self as algorithms, AsnDigest};
use structured_pkix::key::effective::{EffectiveSpki, VisitError};
use structured_pkix::path::WorkingKey;

const FIELD: &str = "attributeCertificate.holder.objectDigestInfo";

/// The selected digest provider's representation check, before key hashing.
///
/// It must validate the original key and effective parameters against its
/// algorithm's encoding rules (RFC3279 §2.3 and applicable updates, e.g.
/// RFC5480), using the existing shared key readers. DER framing alone does not
/// validate RSA/DSA/EC/DH/KEA payloads or repair invalid written parameters.
/// Unsupported algorithms/policy remain Unsupported, never a digest mismatch.
/// This is the same provider's narrow capability, not an implicit engine.
/// All transitive work/storage is admitted in the supplied execution; key
/// mathematics, strength and authenticated proof-of-possession remain separate.
pub trait ObjectDigestProvider<'p>: AsnDigest<'p> {
    /// Check algorithm-specific wire representation and effective parameters.
    fn validate_public_key<W: Work>(
        &self,
        key: WorkingKey<'_>,
        work: &W,
    ) -> Result<Resolution<()>, Self::Error>;
}

/// The caller's explicit object. A key need not have a public-key certificate.
#[derive(Debug, Clone, Copy)]
pub enum Object<'c, 'a> {
    /// Entire original DER certificate, including its signature.
    Certificate(&'c Certificate<'a>),
    /// Effective public key, including any inherited parameter source.
    PublicKey(WorkingKey<'a>),
}

/// A hash comparison bound to this original AC and this explicitly supplied object.
/// No certificate trust, key possession or authorization follows from it.
#[derive(Debug)]
pub struct BoundObject<'r, 'a, 's> {
    certificate: &'r AttributeCertificate<'a>,
    object: Object<'r, 's>,
}
impl<'r, 'a, 's> BoundObject<'r, 'a, 's> {
    /// Original AC whose Holder assertion was checked.
    #[must_use]
    pub fn certificate(&self) -> &'r AttributeCertificate<'a> {
        self.certificate
    }
    /// Actual caller-selected object covered by the completed comparison.
    #[must_use]
    pub fn object(&self) -> Object<'r, 's> {
        self.object
    }
}

/// A completed semantic refusal; processing and callback failures use Result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// No objectDigestInfo Holder alternative was written.
    Absent,
    /// Written object choice differs from the caller's explicit object.
    ObjectType,
    /// otherObjectTypes or otherObjectTypeID is forbidden by this profile.
    OtherObject,
    /// Known digest algorithm has invalid parameters.
    Algorithm,
    /// Digest bits have padding or the wrong fixed algorithm width.
    Hash,
    /// Provider rejected the key's algorithm-specific representation.
    KeyEncoding,
    /// Completed digest comparison found different bytes.
    Differs,
}

/// A capability the selected provider cannot supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Written hash is unsupported or refused by selected policy.
    Digest,
    /// Key representation cannot be supplied by this provider/policy.
    Key,
}

/// Bound facts, semantic refusal and unavailable capability remain distinct.
#[derive(Debug)]
pub enum Binding<'r, 'a, 's> {
    /// Complete successful comparison of the chosen object.
    Bound(BoundObject<'r, 'a, 's>),
    /// Complete profile/comparison refusal, without fallback.
    Rejected(Failure),
    /// An operation was not supported; no comparison is asserted.
    Unsupported(Capability),
}

/// Where a selected-provider operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Algorithm-specific key representation gate.
    KeyEncoding,
    /// Digest state initialization.
    Start,
    /// Whole original certificate input.
    CertificateInput,
    /// Digest state finalization.
    Finish,
    /// Finished output versus written digest.
    Comparison,
}

/// Original execution failures and provider contract failures, never mismatch.
#[derive(Debug)]
pub enum BindingError<E> {
    /// Located source/current processing failure.
    Processing(Error),
    /// Original provider cause and the operation that failed.
    Callback {
        /// Operation that failed.
        phase: Phase,
        /// Original provider cause.
        source: E,
    },
    /// Effective key traversal or its original callback cause/part.
    KeyInput(VisitError<E>),
    /// Provider identity/output contradicts the standard's fixed output width.
    OutputWidth {
        /// Width imposed by the written digest algorithm.
        expected: usize,
        /// Width the provider advertised or produced.
        actual: usize,
    },
}
impl<E> From<Error> for BindingError<E> {
    fn from(error: Error) -> Self {
        Self::Processing(error)
    }
}

impl<'a> AttributeCertificate<'a> {
    /// Bind the written objectDigestInfo to one explicit object with one provider.
    ///
    /// Profile/object/algorithm/width gates precede hash state creation. The
    /// public-key branch checks representation with the selected provider before
    /// hashing canonical effective SPKI chunks. Certificate hashing includes its
    /// signature. Every input callback receives its own source/current execution;
    /// comparison receives the assertion's execution. States/output are consumed
    /// once and dropped on any failure; no successful partial fact escapes.
    pub fn bind_holder_digest<'r, 's, 'p, P: ObjectDigestProvider<'p>, W: Work>(
        &'r self,
        object: Object<'r, 's>,
        provider: &'p P,
        work: &W,
    ) -> Result<Binding<'r, 'a, 's>, BindingError<P::Error>> {
        let execution = work.execution_for(self.parser);
        let at = self.signed_element().span().start;
        execution
            .charge_work(4)
            .map_err(|e| Error::resource(e, FIELD, at))?;
        let Some(assertion) = &self.information.holder.object_digest else {
            return Ok(Binding::Rejected(Failure::Absent));
        };
        if assertion.object_type == DigestedObject::Other || assertion.other_type.is_some() {
            return Ok(Binding::Rejected(Failure::OtherObject));
        }
        if !matches!(
            (&assertion.object_type, object),
            (DigestedObject::PublicKey, Object::PublicKey(_))
                | (DigestedObject::PublicKeyCertificate, Object::Certificate(_))
        ) {
            return Ok(Binding::Rejected(Failure::ObjectType));
        }
        let algorithm =
            match algorithms::algorithm(&assertion.algorithm, &execution).map_err(Error::pkix)? {
                Resolution::Supported(value) => value,
                Resolution::Unsupported => return Ok(Binding::Unsupported(Capability::Digest)),
                Resolution::Malformed => return Ok(Binding::Rejected(Failure::Algorithm)),
            };
        let Some(expected) = assertion
            .digest
            .octets()
            .filter(|bytes| bytes.len() == algorithm.width())
        else {
            return Ok(Binding::Rejected(Failure::Hash));
        };
        let Some(identity) = provider.identity(algorithm) else {
            return Ok(Binding::Unsupported(Capability::Digest));
        };
        check_width(provider.width(&identity), algorithm.width())?;
        let calculation = match prepare(object, provider, &execution, |input| {
            hash(
                input,
                provider,
                &identity,
                algorithm.width(),
                expected,
                &execution,
            )
        })? {
            Resolution::Supported(calculation) => calculation,
            Resolution::Unsupported => return Ok(Binding::Unsupported(Capability::Key)),
            Resolution::Malformed => return Ok(Binding::Rejected(Failure::KeyEncoding)),
        };
        let matches = match calculation {
            Resolution::Supported(matches) => matches,
            Resolution::Unsupported => return Ok(Binding::Unsupported(Capability::Digest)),
            Resolution::Malformed => return Ok(Binding::Rejected(Failure::Algorithm)),
        };
        Ok(if matches {
            Binding::Bound(BoundObject {
                certificate: self,
                object,
            })
        } else {
            Binding::Rejected(Failure::Differs)
        })
    }
}

fn check_width<E>(actual: Option<usize>, expected: usize) -> Result<(), BindingError<E>> {
    if let Some(actual) = actual
        && actual != expected
    {
        return Err(BindingError::OutputWidth { expected, actual });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Input<'v, 's> {
    Certificate(&'v Certificate<'s>),
    Key(&'v EffectiveSpki<'s>),
}

fn prepare<'s, 'p, P: ObjectDigestProvider<'p>, W: Work, T>(
    object: Object<'_, 's>,
    provider: &'p P,
    work: &W,
    visit: impl FnOnce(Input<'_, 's>) -> Result<T, BindingError<P::Error>>,
) -> Result<Resolution<T>, BindingError<P::Error>> {
    let key = match object {
        Object::Certificate(certificate) => {
            return visit(Input::Certificate(certificate)).map(Resolution::Supported);
        }
        Object::PublicKey(key) => key,
    };
    let encoded = EffectiveSpki::read(key, work).map_err(Error::pkix)?;
    Ok(
        match provider
            .validate_public_key(key, &encoded.execution_in(work))
            .map_err(|source| BindingError::Callback {
                phase: Phase::KeyEncoding,
                source,
            })? {
            Resolution::Supported(()) => {
                return visit(Input::Key(&encoded)).map(Resolution::Supported);
            }
            Resolution::Unsupported => Resolution::Unsupported,
            Resolution::Malformed => Resolution::Malformed,
        },
    )
}

fn hash<'p, P: ObjectDigestProvider<'p>, W: Work>(
    input: Input<'_, '_>,
    provider: &'p P,
    identity: &P::Identity,
    width: usize,
    expected: &[u8],
    work: &W,
) -> Result<Resolution<bool>, BindingError<P::Error>> {
    let mut state =
        match provider
            .start(identity, work)
            .map_err(|source| BindingError::Callback {
                phase: Phase::Start,
                source,
            })? {
            Resolution::Supported(state) => state,
            Resolution::Unsupported => return Ok(Resolution::Unsupported),
            Resolution::Malformed => return Ok(Resolution::Malformed),
        };
    match input {
        Input::Certificate(certificate) => {
            let execution = certificate.execution_in(work);
            execution.charge_work(1).map_err(|e| {
                Error::resource(
                    e,
                    "attributeCertificate.objectDigestInfo.certificateInput",
                    certificate.span().start,
                )
            })?;
            provider
                .update(&mut state, certificate.as_bytes(), &execution)
                .map_err(|source| BindingError::Callback {
                    phase: Phase::CertificateInput,
                    source,
                })?;
        }
        Input::Key(encoded) => encoded
            .visit(work, |_, bytes, source| {
                provider.update(&mut state, bytes, source)
            })
            .map_err(BindingError::KeyInput)?,
    }
    let output = provider
        .finish(state, work)
        .map_err(|source| BindingError::Callback {
            phase: Phase::Finish,
            source,
        })?;
    check_width(Some(output.as_ref().len()), width)?;
    provider
        .matches(identity, &output, expected, work)
        .map(Resolution::Supported)
        .map_err(|source| BindingError::Callback {
            phase: Phase::Comparison,
            source,
        })
}
