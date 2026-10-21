//! Authenticated issuance and evaluation-window facts, not AC authorization.
//!
//! RFC5755 §5 separates signature/purpose/time from holder authentication,
//! certification paths, direct AA trust and targeting. The latter obligations,
//! proxy effects and revocation remain with the caller. A successfully parsed
//! critical extension is not an enforced effect. Returned profile facts retain
//! these obligations rather than silently satisfying them.
//! <https://www.rfc-editor.org/rfc/rfc5755.html#section-5>

use super::{Check, Profile, Rejection as ProfileRejection, charge};
use crate::attribute_certificate::AttributeCertificate;
use crate::{Error, Result};
use structured_asn1::Span;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Execution, Work};
use structured_pkix::path::{Interval, Verified, Verify, WorkingKey};
use structured_pkix::{AlgorithmIdentifier, Certificate};

/// Semantic agreement supplied by the same selected signature verifier.
///
/// Resolve both original identifiers, including algorithm-specific defaults
/// and parameter validity, before comparing. Equal malformed parameters do not
/// agree; generic absent/NULL equality is not this operation. Unsupported and
/// malformed inputs remain distinct from a completed different identity.
/// Original algorithm readers preserve their own source/depth and current work.
/// No second registry or cryptographic engine is selected by this trait.
pub trait AlgorithmAgreement {
    /// Original provider, policy or resource cause.
    type Error;
    /// Compare fully resolved identities; no signature arithmetic yet.
    fn algorithms<W: Work>(
        &self,
        signed: AlgorithmIdentifier<'_>,
        outer: AlgorithmIdentifier<'_>,
        work: &W,
    ) -> core::result::Result<Resolution<bool>, Self::Error>;
}

/// Callback capability or source of a provider failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Original inner/outer algorithm resolution and agreement.
    Algorithms,
    /// Exact original signature input and effective key.
    Signature,
}

/// Completed semantic refusal, never a resource or callback error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Static AC profile rejected, retaining its original reason and source.
    Profile(ProfileRejection),
    /// Supplied AA identity or purpose rejected by the common authority check.
    Authority(ProfileRejection),
    /// Effective key's original SPKI differs from the supplied AA certificate.
    KeyBinding,
    /// The entire evaluation interval is not inside the AC's inclusive validity.
    AcValidity,
    /// The entire interval is not inside the AA PKC's inclusive validity.
    AuthorityValidity,
    /// At least one known algorithm has malformed parameters.
    AlgorithmSyntax,
    /// Resolved inner and outer signature identities disagree.
    AlgorithmMismatch,
    /// Signature is not a whole number of octets.
    SignatureEncoding,
    /// Completed signature verification returned No.
    Signature,
}

/// A refusal and an honest original enclosure, not an invented field range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// Which fact failed.
    pub reason: Failure,
    /// Original AC or authority context.
    pub source: Span,
}

/// Completed operation, with unsupported capability separate from rejection.
#[derive(Debug)]
pub enum Outcome<T> {
    /// Issuance, static profile and explicit interval checks completed.
    Authenticated(T),
    /// A completed negative check.
    Rejected(Rejection),
    /// The selected provider/policy cannot execute this capability.
    Unsupported(Stage),
}

/// Original shared processing failure or selected-provider failure.
#[derive(Debug)]
pub enum AuthenticationError<E> {
    /// Original located encoding/resource cause.
    Processing(Error),
    /// A newer verifier answer has no interpretation in this implementation.
    UnknownAnswer,
    /// Original opaque provider cause; it is not rewritten as a document fault.
    Callback {
        /// Callback being executed.
        stage: Stage,
        /// Real enclosing AC context, not a replacement for the cause's source.
        context: Span,
        /// Original callback cause, including resource or policy failures.
        source: E,
    },
}
impl<E> From<Error> for AuthenticationError<E> {
    fn from(value: Error) -> Self {
        Self::Processing(value)
    }
}

/// Original authenticated issuance facts with independently owned profile storage.
///
/// This is not full RFC5755 acceptance: holder authentication, both PKIX paths,
/// direct AA trust, targeting/proxy effects, revocation and product permission
/// remain separate. AKI is retained as a hint, not a mandatory matching policy
/// (RFC5755 §4.3.3). UTC correction provenance belongs to the caller, as for the
/// shared PKIX interval; comparisons retain fractional and inserted-second labels.
#[derive(Debug)]
pub struct Authenticated<'r, 'a, 's> {
    profile: Profile<'r, 'a>,
    authority: &'r Certificate<'s>,
    key: WorkingKey<'s>,
    interval: Interval,
}
impl<'r, 'a, 's> Authenticated<'r, 'a, 's> {
    /// Original AC, without normalization or removal of its attributes.
    #[must_use]
    pub fn certificate(&self) -> &AttributeCertificate<'a> {
        self.profile.certificate()
    }
    /// Checked static facts and still-pending targeting/proxy/status obligations.
    #[must_use]
    pub fn profile(&self) -> &Profile<'r, 'a> {
        &self.profile
    }
    /// Actual supplied authority; this operation does not establish its path/trust.
    #[must_use]
    pub fn authority(&self) -> &'r Certificate<'s> {
        self.authority
    }
    /// Actual supplied effective key, preserving its inherited parameter source.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'s> {
        self.key
    }
    /// Complete explicit interval checked against both AC and authority validity.
    #[must_use]
    pub fn interval(&self) -> Interval {
        self.interval
    }
}

fn rejected<T>(reason: Failure, source: Span) -> Outcome<T> {
    Outcome::Rejected(Rejection { reason, source })
}

fn key_matches<W: Work>(
    authority: &Certificate<'_>,
    key: WorkingKey<'_>,
    work: &W,
) -> Result<bool> {
    let original = key.key().algorithm();
    let key_work = key.key().execution_in(work);
    let authority_work = authority.execution_in(work);
    charge(&key_work, 1, original.offset())?;
    charge(&authority_work, 1, authority.span().start)?;
    let supplied = key.key().as_bytes();
    let actual = authority.tbs().public_key().as_bytes();
    if supplied.len() != actual.len() {
        return Ok(false);
    }
    // The common case is the very same immutable SPKI. Identity needs no scan;
    // metadata still pays each source/current ceiling before this shortcut.
    if core::ptr::eq(supplied, actual) {
        return Ok(true);
    }
    charge(&key_work, supplied.len() as u64, original.offset())?;
    charge(&authority_work, actual.len() as u64, authority.span().start)?;
    Ok(supplied == actual)
}

impl<'a> AttributeCertificate<'a> {
    /// Authenticate the selected authority/key and complete evaluation interval.
    ///
    /// All static profile, authority, key, time and signature-padding gates run
    /// before provider resolution or signature math. The selected verifier also
    /// implements the existing PKIX signature contract for scoped execution.
    /// It must account backend work/storage and use original key/signature
    /// readers for deferred decoding; passing Work does not qualify a backend.
    /// No PKIX path or direct AA trust is inferred from successful arithmetic.
    pub fn authenticate<'r, 's, V, W: Work>(
        &'r self,
        authority: &'r Certificate<'s>,
        key: WorkingKey<'s>,
        interval: Interval,
        verifier: &V,
        work: &W,
    ) -> core::result::Result<
        Outcome<Authenticated<'r, 'a, 's>>,
        AuthenticationError<<V as AlgorithmAgreement>::Error>,
    >
    where
        V: AlgorithmAgreement,
        for<'op> V: Verify<Execution<'op>, Error = <V as AlgorithmAgreement>::Error>,
    {
        let execution = work.execution_for(self.parser);
        let at = self.signed_element().span();
        let profile = match self.profile(&execution)? {
            Check::Accepted(profile) => profile,
            Check::Rejected(cause) => return Ok(rejected(Failure::Profile(cause), at)),
        };
        if let Check::Rejected(cause) = self.bind_authority(authority, &execution)? {
            return Ok(rejected(Failure::Authority(cause), authority.span()));
        }
        if !key_matches(authority, key, &execution)? {
            return Ok(rejected(Failure::KeyBinding, authority.span()));
        }
        charge(&execution, 4, at.start)?;
        let info = self.information();
        if interval.from_instant() < info.not_before.instant()
            || interval.to_instant() > info.not_after.instant()
        {
            return Ok(rejected(Failure::AcValidity, at));
        }
        let authority_work = authority.execution_in(&execution);
        charge(&authority_work, 4, authority.span().start)?;
        let validity = authority.tbs().validity();
        if interval.from_instant() < validity.not_before().instant()
            || interval.to_instant() > validity.not_after().instant()
        {
            return Ok(rejected(Failure::AuthorityValidity, authority.span()));
        }
        charge(&execution, 1, at.start)?;
        if self.signature_value().octets().is_none() {
            return Ok(rejected(
                Failure::SignatureEncoding,
                self.signature_value().span(),
            ));
        }
        // RFC5755 §4.1 carries two original algorithm fields. Their resolved
        // equality is algorithm-specific, not generic absent/NULL normalization.
        // https://www.rfc-editor.org/rfc/rfc5755.html#section-4.1
        match verifier
            .algorithms(info.signature, self.signature_algorithm(), &execution)
            .map_err(|source| AuthenticationError::Callback {
                stage: Stage::Algorithms,
                context: at,
                source,
            })? {
            Resolution::Supported(true) => {}
            Resolution::Supported(false) => return Ok(rejected(Failure::AlgorithmMismatch, at)),
            Resolution::Malformed => return Ok(rejected(Failure::AlgorithmSyntax, at)),
            Resolution::Unsupported => return Ok(Outcome::Unsupported(Stage::Algorithms)),
        }
        charge(&execution, 1, at.start)?;
        match verifier
            .verify(
                &info.signature,
                key,
                self.signed_bytes(),
                self.signature_value(),
                &execution,
            )
            .map_err(|source| AuthenticationError::Callback {
                stage: Stage::Signature,
                context: at,
                source,
            })? {
            Verified::Yes => Ok(Outcome::Authenticated(Authenticated {
                profile,
                authority,
                key,
                interval,
            })),
            Verified::No => Ok(rejected(Failure::Signature, self.signature_value().span())),
            Verified::Unsupported => Ok(Outcome::Unsupported(Stage::Signature)),
            _ => Err(AuthenticationError::UnknownAnswer),
        }
    }
}
