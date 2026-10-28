//! X.509 alternative signatures, independent of native mathematics and trust.
//!
//! ITU-T X.509 (2019) §§7.2.2, 7.10.3 and 9.8 define certificate/CRL
//! extensions. PKCS#10 uses the single-valued attribute convention implemented
//! by Bouncy Castle, not an extension to RFC2986's normative grammar.
//! Native verification remains unchanged unless a caller selects this API.
//! <https://www.itu.int/rec/T-REC-X.509-201910-I/en>

use crate::algorithm::{AlgorithmIdentifier, ml_dsa};
use crate::error::{CallbackError, CallbackResult, Located};
use crate::path::{Verified, Verify, WorkingKey};
use crate::signature::SignatureValue;
use crate::{Error, ErrorCode, PublicKeyInfo, Result};
use structured_asn1::memory::Work;
use structured_asn1::{Oid, ScopedReader, Tag};

mod components;
mod preimage;
pub mod request;
pub use components::{Component, Components};
pub use preimage::Preimage;

/// X.509 §9.8.2, the subject's alternative SPKI.
pub const SUBJECT_ALT_PUBLIC_KEY_INFO: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 72]);
/// X.509 §9.8.3, the issuer's alternative signature algorithm.
pub const ALT_SIGNATURE_ALGORITHM: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 73]);
/// X.509 §9.8.4, the issuer's alternative signature value.
pub const ALT_SIGNATURE_VALUE: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 74]);
const FIELD: &str = "hybrid";

/// Allocation-free, located conformance diagnostic. Resource errors never enter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    code: ErrorCode,
    field: &'static str,
    offset: u64,
}
impl Fault {
    /// Recover the original located error without allocating.
    #[must_use]
    pub fn error(self) -> Error {
        Error::new(self.code, self.field, self.offset)
    }
    pub(crate) fn of(error: &Error) -> Self {
        Self {
            code: error.code(),
            field: error.field(),
            offset: error.offset(),
        }
    }
}

/// Alternative outcome, without conflating bad mathematics and bad encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alternative {
    /// The selected verifier completed its mathematical check.
    Verified(Verified),
    /// Required source facts are missing or malformed; no alternative callback ran.
    Nonconforming(Fault),
}

/// Independent completed signature facts, not a trust or enrollment decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signatures {
    /// Native signature result, even when the alternative is missing or invalid.
    pub native: Verified,
    /// Alternative signature or located conformance result.
    pub alternative: Alternative,
}

/// Caller-selected requirement, fixed before checking any mathematical result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Require the alternative signature independently of native mathematics.
    Alternative,
    /// Require both signatures, for example for two-key enrollment.
    Both,
}
impl Requirement {
    /// Completed mathematical acceptance only; path/usage/trust remain separate.
    #[must_use]
    pub fn accepts(self, result: Signatures) -> bool {
        result.alternative == Alternative::Verified(Verified::Yes)
            && (self == Self::Alternative || result.native == Verified::Yes)
    }
    pub(crate) fn answer(self, result: Signatures) -> Verified {
        if self.accepts(result) {
            return Verified::Yes;
        }
        if result.alternative == Alternative::Verified(Verified::Unsupported)
            || (self == Self::Both && result.native == Verified::Unsupported)
        {
            Verified::Unsupported
        } else {
            Verified::No
        }
    }
}

/// An injected alternative-signature verifier. No algorithm engine is included.
pub trait AlternativeVerifier<W: Work> {
    /// Original provider/resource cause, never a boolean mismatch.
    type Error;
    /// Verify the exact raw stream. For RFC9881 ML-DSA this is pure mode with
    /// empty context, not HashML-DSA or a digest passed as the message. Admit
    /// key work through `key.execution_in(work)` and input through `visit`;
    /// the provider owns transitive backend allocation/work qualification.
    fn verify(
        &self,
        algorithm: AlgorithmIdentifier<'_>,
        key: PublicKeyInfo<'_>,
        preimage: &Preimage<'_>,
        signature: SignatureValue<'_>,
        work: &W,
    ) -> core::result::Result<Verified, Self::Error>;
}

/// Processing and independent callback errors keep their original causes.
#[derive(Debug)]
pub enum CheckError<N, A> {
    /// Located processing/resource refusal.
    Processing(Error),
    /// Native verifier failed to execute.
    Native(N),
    /// Alternative verifier failed to execute.
    Alternative(A),
}
impl<N, A> From<Error> for CheckError<N, A> {
    fn from(error: Error) -> Self {
        Self::Processing(error)
    }
}

impl<N: core::fmt::Display, A: core::fmt::Display> core::fmt::Display for CheckError<N, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Processing(error) => error.fmt(f),
            Self::Native(error) => write!(f, "native verifier: {error}"),
            Self::Alternative(error) => write!(f, "alternative verifier: {error}"),
        }
    }
}
impl<N: core::error::Error + 'static, A: core::error::Error + 'static> core::error::Error
    for CheckError<N, A>
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Processing(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Alternative(error) => Some(error),
        }
    }
}

/// Strict alternative signature fields and exact preimage, still not mathematics.
#[derive(Debug)]
pub struct Prepared<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    signature: SignatureValue<'a>,
    preimage: Preimage<'a>,
}
impl<'a> Prepared<'a> {
    /// Algorithm protected by the alternative signature.
    #[must_use]
    pub fn algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }
    /// Original alternative signature and producing source.
    #[must_use]
    pub fn signature(&self) -> SignatureValue<'a> {
        self.signature
    }
    /// DER stream with original payload ranges and synthetic framing.
    #[must_use]
    pub fn preimage(&self) -> &Preimage<'a> {
        &self.preimage
    }

    /// Verify with the issuer's authenticated alternative key, not the subject key.
    pub fn verify<W: Work, V: AlternativeVerifier<W>>(
        &self,
        issuer_key: PublicKeyInfo<'_>,
        verifier: &V,
        work: &W,
    ) -> CallbackResult<Verified, V::Error> {
        // All ML-DSA profile/framing decisions precede the callback. The
        // provider checks coefficients, key validity and the actual signature.
        issuer_key
            .execution_in(work)
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, issuer_key.key_offset()))?;
        if let Some(set) = ml_dsa::resolve(self.algorithm, work)? {
            let key = crate::key::ml_dsa::read(issuer_key, work)?;
            if key.parameter_set() != set {
                return Err(Error::new(
                    ErrorCode::AlgorithmMismatch,
                    FIELD,
                    issuer_key.key_offset(),
                )
                .into());
            }
            self.signature.ml_dsa_in(set, work)?;
        }
        verifier
            .verify(
                self.algorithm,
                issuer_key,
                &self.preimage,
                self.signature,
                work,
            )
            .map_err(CallbackError::Callback)
    }
}

/// Inspect the original alternative certificate extensions, including absences.
pub fn inspect_certificate<'a, W: Work>(
    certificate: &crate::Certificate<'a>,
    work: &W,
) -> Result<Components<'a>> {
    components::extensions(
        certificate.tbs().extensions(),
        &certificate.execution_in(work),
        certificate.span().start,
    )
}

/// Prepare the X.509 §7.2.2 preTBSCertificate, requiring all three components.
pub fn prepare_certificate<'a, W: Work>(
    certificate: &crate::Certificate<'a>,
    work: &W,
) -> Result<Prepared<'a>> {
    prepare_certificate_key(certificate, work).map(|(prepared, _)| prepared)
}
pub(crate) fn prepare_certificate_key<'a, W: Work>(
    certificate: &crate::Certificate<'a>,
    work: &W,
) -> Result<(Prepared<'a>, PublicKeyInfo<'a>)> {
    let components = components::extensions(
        certificate.tbs().extensions(),
        &certificate.execution_in(work),
        certificate.span().start,
    )?;
    prepare_certificate_components(certificate, &components, work)
}

pub(crate) fn prepare_certificate_components<'a, W: Work>(
    certificate: &crate::Certificate<'a>,
    components: &Components<'a>,
    work: &W,
) -> Result<(Prepared<'a>, PublicKeyInfo<'a>)> {
    let key = components.key.require()?;
    validate_key(key, work)?;
    let (algorithm, signature, remove) = components.signature_fields()?;
    let reader = certificate.tbs().reader_scoped(work)?;
    let preimage = preimage::extensions(reader, certificate.tbs().signature(), 3, remove)?;
    Ok((
        Prepared {
            algorithm,
            signature,
            preimage,
        },
        key,
    ))
}

pub(crate) fn critical_key_understood<W: Work, R: crate::Recognizer<W>>(
    components: &Components<'_>,
    recognizer: &R,
    work: &W,
) -> CallbackResult<bool, R::Error> {
    if components.key.critical() != Some(true) {
        return Ok(true);
    }
    let key = components.key.require()?;
    // X.509(2019)§9.8.2: critical alternative SPKI requires understanding
    // its public-key algorithm too, not merely the extension's OID.
    // https://www.itu.int/rec/T-REC-X.509-201910-I/en
    if ml_dsa::resolve(key.algorithm(), work)?.is_some() {
        crate::key::ml_dsa::read(key, work)?;
        return Ok(true);
    }
    key.execution_in(work)
        .charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, key.key_offset()))?;
    recognizer
        .recognizes(SUBJECT_ALT_PUBLIC_KEY_INFO, work)
        .map_err(CallbackError::Callback)
}

/// Inspect CRL alternative algorithm/value; CRLs do not carry a subject key.
pub fn inspect_crl<'a, W: Work>(
    crl: &crate::crl::CertificateList<'a>,
    work: &W,
) -> Result<Components<'a>> {
    components::extensions(
        crl.tbs().extensions(),
        &crl.execution_in(work),
        crl.span().start,
    )
}

/// Prepare the X.509 §7.10.3 preTBSCertList, excluding its native algorithm.
pub fn prepare_crl<'a, W: Work>(
    crl: &crate::crl::CertificateList<'a>,
    work: &W,
) -> Result<Prepared<'a>> {
    let components = inspect_crl(crl, work)?;
    let (algorithm, signature, remove) = components.signature_fields()?;
    let reader = crl.tbs().reader_scoped(work)?;
    let preimage = preimage::extensions(reader, crl.tbs().signature(), 0, remove)?;
    Ok(Prepared {
        algorithm,
        signature,
        preimage,
    })
}

fn alternative<W: Work, V: AlternativeVerifier<W>>(
    prepared: Result<Prepared<'_>>,
    key: PublicKeyInfo<'_>,
    verifier: &V,
    work: &W,
) -> CallbackResult<Alternative, V::Error> {
    let result = match prepared {
        Ok(prepared) => prepared
            .verify(key, verifier, work)
            .map(Alternative::Verified),
        Err(error) => Err(CallbackError::Processing(error)),
    };
    match result {
        Err(CallbackError::Processing(error)) if !terminal(&error) => {
            Ok(Alternative::Nonconforming(Fault::of(&error)))
        }
        other => other,
    }
}

pub(super) fn validate_key<W: Work>(key: PublicKeyInfo<'_>, work: &W) -> Result<()> {
    if ml_dsa::resolve(key.algorithm(), work)?.is_some() {
        crate::key::ml_dsa::read(key, work)?;
    }
    Ok(())
}
pub(crate) fn terminal(error: &Error) -> bool {
    error.is_resource() || error.code() == ErrorCode::ForeignReader
}

/// Check both mathematical signatures without short-circuiting on native No or Unsupported.
pub fn check_certificate<W: Work, N: Verify<W>, A: AlternativeVerifier<W>>(
    certificate: &crate::Certificate<'_>,
    native_key: WorkingKey<'_>,
    alternative_key: PublicKeyInfo<'_>,
    native: &N,
    verifier: &A,
    work: &W,
) -> core::result::Result<Signatures, CheckError<N::Error, A::Error>> {
    certificate
        .execution_in(work)
        .charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, certificate.span().start))?;
    native_key
        .key()
        .execution_in(work)
        .charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, native_key.key().key_offset()))?;
    let result = native
        .verify(
            &certificate.signature_algorithm(),
            native_key,
            certificate.signed_bytes(),
            certificate.signature_value(),
            work,
        )
        .map_err(CheckError::Native)?;
    let alternative = alternative(
        prepare_certificate(certificate, work),
        alternative_key,
        verifier,
        work,
    )
    .map_err(|e| match e {
        CallbackError::Processing(e) => CheckError::Processing(e),
        CallbackError::Callback(e) => CheckError::Alternative(e),
    })?;
    Ok(Signatures {
        native: result,
        alternative,
    })
}

/// Check both CRL signatures with caller-authenticated issuer keys. This does
/// not replace issuer-name, cRLSign, freshness, scope or revocation processing.
pub fn check_crl<W: Work, N: Verify<W>, A: AlternativeVerifier<W>>(
    crl: &crate::crl::CertificateList<'_>,
    native_key: WorkingKey<'_>,
    alternative_key: PublicKeyInfo<'_>,
    native: &N,
    verifier: &A,
    work: &W,
) -> core::result::Result<Signatures, CheckError<N::Error, A::Error>> {
    crl.execution_in(work)
        .charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, crl.span().start))?;
    native_key
        .key()
        .execution_in(work)
        .charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, native_key.key().key_offset()))?;
    let result = native
        .verify(
            &crl.signature_algorithm(),
            native_key,
            crl.signed_bytes(),
            crl.signature_value(),
            work,
        )
        .map_err(CheckError::Native)?;
    let alternative = alternative(prepare_crl(crl, work), alternative_key, verifier, work)
        .map_err(|e| match e {
            CallbackError::Processing(e) => CheckError::Processing(e),
            CallbackError::Callback(e) => CheckError::Alternative(e),
        })?;
    Ok(Signatures {
        native: result,
        alternative,
    })
}

fn required<'a>(
    reader: &mut ScopedReader<'a, '_>,
    tag: Tag,
) -> Result<structured_asn1::Element<'a>> {
    reader.expect(tag).field(FIELD)
}

fn identifier_work<W: Work>(kind: Oid<'_>, work: &W, at: u64) -> Result<()> {
    let units = (kind.as_bytes().len() as u64)
        .checked_mul(3)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                FIELD,
                at,
            )
        })?;
    work.charge_work(units)
        .map_err(|e| Error::resource(e, FIELD, at))
}
