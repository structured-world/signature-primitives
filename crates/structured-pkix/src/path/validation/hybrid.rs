//! Alternative-signature driver over the ordinary RFC5280/RFC9618 processor.
//! Native No/Unsupported is recorded independently; the caller's requirement
//! decides which mathematical result is required before processing continues.

use super::{
    CertificateFacts, Chain, Driver, Settings, Supplied, Validation, ValidationContext,
    certificate_facts,
};
use crate::extension::Recognizer;
use crate::hybrid::{Alternative, AlternativeVerifier, CheckError, Fault, Requirement, Signatures};
use crate::path::{
    Anchor, BuildError, BuildResult, Meter, Truncation, Verified, Verify, Watch, WorkingKey, cost,
};
use crate::{Certificate, Error, PublicKeyInfo};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Oid, Span};

/// Explicit native and alternative trust-anchor information. Neither a
/// self-signature nor a key supplied by a child establishes anchor trust.
#[derive(Debug, Clone, Copy)]
pub struct HybridAnchor<'a> {
    /// Caller-selected ordinary anchor, including its name and constraints.
    pub native: Anchor<'a>,
    /// Independently trusted alternative key of that same authority.
    pub alternative: PublicKeyInfo<'a>,
}

/// One original path certificate's completed mathematical facts.
#[derive(Debug, Clone, Copy)]
pub struct CertificateSignatures {
    /// Leaf-first position, excluding the trust anchor.
    pub position: usize,
    /// Exact source certificate range.
    pub source: Span,
    /// None if an earlier constraint/signature/local bound stopped this path.
    pub signatures: Option<Signatures>,
}

/// Ordinary path outcome plus independent signature facts, not application trust.
#[derive(Debug)]
pub struct HybridValidation<'a> {
    /// Shared static path validation under the selected signature requirement.
    pub outcome: Validation<'a>,
    signatures: OwnedVec<CertificateSignatures>,
}
impl HybridValidation<'_> {
    /// Source positions admitted after preflight, including unchecked signatures.
    #[must_use]
    pub fn signatures(&self) -> &[CertificateSignatures] {
        &self.signatures
    }
}

struct Known<'r, R>(&'r R);
impl<R: Recognizer<E>, E: Work> Recognizer<E> for Known<'_, R> {
    type Error = R::Error;
    fn recognizes(&self, oid: Oid<'_>, work: &E) -> core::result::Result<bool, Self::Error> {
        // The driver semantically decodes these before acceptance; the ordinary
        // extension kernel still checks their DER, including critical payloads.
        if oid == crate::hybrid::SUBJECT_ALT_PUBLIC_KEY_INFO
            || oid == crate::hybrid::ALT_SIGNATURE_ALGORITHM
            || oid == crate::hybrid::ALT_SIGNATURE_VALUE
        {
            return Ok(true);
        }
        self.0.recognizes(oid, work)
    }
    fn recognizes_other_name(
        &self,
        oid: Oid<'_>,
        work: &E,
    ) -> core::result::Result<bool, Self::Error> {
        self.0.recognizes_other_name(oid, work)
    }
    fn recognizes_name_constraint(
        &self,
        oid: Oid<'_>,
        work: &E,
    ) -> core::result::Result<bool, Self::Error> {
        self.0.recognizes_name_constraint(oid, work)
    }
    fn recognizes_access_method(
        &self,
        oid: Oid<'_>,
        work: &E,
    ) -> core::result::Result<bool, Self::Error> {
        self.0.recognizes_access_method(oid, work)
    }
    fn recognizes_statement(
        &self,
        oid: Oid<'_>,
        work: &E,
    ) -> core::result::Result<bool, Self::Error> {
        self.0.recognizes_statement(oid, work)
    }
}

struct HybridDriver<
    'a,
    'p,
    N: Verify<E>,
    W: Watch,
    R: Recognizer<E>,
    A: AlternativeVerifier<E>,
    E: Work,
> {
    native: Supplied<'a, 'p, N, W, R, E>,
    verifier: &'p A,
    working: PublicKeyInfo<'a>,
    signatures: OwnedVec<CertificateSignatures>,
    next: usize,
    requirement: Requirement,
    components: Option<crate::hybrid::Components<'a>>,
}
impl<N: Verify<E>, W: Watch, R: Recognizer<E>, A: AlternativeVerifier<E>, E: Work> Meter
    for HybridDriver<'_, '_, N, W, R, A, E>
{
    fn spend(&mut self, amount: u64) -> crate::Result<bool> {
        self.native.spend(amount)
    }
}
impl<'a, N: Verify<E>, W: Watch, R: Recognizer<E>, A: AlternativeVerifier<E>, E: Work>
    Driver<'a, Known<'_, R>, E> for HybridDriver<'a, '_, N, W, R, A, E>
{
    type VerificationError = CheckError<N::Error, A::Error>;
    fn verified(
        &mut self,
        certificate: &'a Certificate<'a>,
        key: WorkingKey<'a>,
    ) -> BuildResult<Option<Verified>, Self::VerificationError, R::Error> {
        if !self.spend(cost::SIGNATURE)? || !self.spend(cost::SIGNATURE)? {
            return Ok(None);
        }
        // The shared supplied-path processor visits each certificate once,
        // in anchor-to-leaf order. No per-certificate search/cache is needed.
        debug_assert!(self.next > 0);
        self.next -= 1;
        debug_assert_eq!(self.signatures[self.next].source, certificate.span());
        let work = self.native.context.execution;
        let native = self
            .native
            .context
            .verifier
            .verify(
                &certificate.signature_algorithm(),
                key,
                certificate.signed_bytes(),
                certificate.signature_value(),
                work,
            )
            .map_err(|e| BuildError::Verification(CheckError::Native(e)))?;
        let components = self
            .components
            .take()
            .expect("shared facts precede signature verification");
        let alternative =
            match crate::hybrid::prepare_certificate_components(certificate, &components, work) {
                Ok((prepared, child_key)) => {
                    let verified = match prepared.verify(self.working, self.verifier, work) {
                        Ok(answer) => Alternative::Verified(answer),
                        Err(crate::error::CallbackError::Processing(error))
                            if !crate::hybrid::terminal(&error) =>
                        {
                            Alternative::Nonconforming(Fault::of(&error))
                        }
                        Err(crate::error::CallbackError::Processing(error)) => {
                            return Err(BuildError::Processing(error));
                        }
                        Err(crate::error::CallbackError::Callback(error)) => {
                            return Err(BuildError::Verification(CheckError::Alternative(error)));
                        }
                    };
                    self.working = child_key;
                    verified
                }
                Err(error) if crate::hybrid::terminal(&error) => {
                    return Err(BuildError::Processing(error));
                }
                Err(error) => Alternative::Nonconforming(Fault::of(&error)),
            };
        let signatures = Signatures {
            native,
            alternative,
        };
        self.signatures[self.next].signatures = Some(signatures);
        Ok(Some(self.requirement.answer(signatures)))
    }
    fn facts(
        &mut self,
        certificate: &'a Certificate<'a>,
        settings: &Settings<'a, '_, Known<'_, R>, E>,
    ) -> BuildResult<Option<CertificateFacts<'a>>, Self::VerificationError, R::Error> {
        let Some(mut facts) = certificate_facts(certificate, settings, self)? else {
            return Ok(None);
        };
        if facts.rejected.is_some() {
            return Ok(Some(facts));
        }
        let components = crate::hybrid::inspect_certificate(certificate, settings.execution)?;
        let understood = crate::hybrid::critical_key_understood(
            &components,
            self.native.context.recognizer,
            settings.execution,
        );
        match understood {
            Ok(true) => {}
            Ok(false) => {
                facts.rejected = Some(super::RejectionReason::CriticalExtension(
                    crate::hybrid::SUBJECT_ALT_PUBLIC_KEY_INFO,
                ));
            }
            Err(crate::error::CallbackError::Processing(error))
                if crate::hybrid::terminal(&error) =>
            {
                return Err(BuildError::Processing(error));
            }
            Err(crate::error::CallbackError::Processing(error)) => {
                facts.rejected = Some(super::RejectionReason::MalformedExtension {
                    extension: crate::hybrid::SUBJECT_ALT_PUBLIC_KEY_INFO,
                    code: error.code(),
                    field: error.field(),
                    offset: error.offset(),
                });
            }
            Err(crate::error::CallbackError::Callback(error)) => {
                return Err(BuildError::Recognition(error));
            }
        }
        self.components = Some(components);
        Ok(Some(facts))
    }
}

/// Check one supplied path with independent signatures and an explicit trusted
/// alternative anchor. Required missing/stripped/unsupported/invalid alternative
/// signatures never fall back to native success. All ordinary validity, CA/KU,
/// name, critical-extension, policy and resource checks share the native core.
/// Native mathematics still runs and remains visible when only PQ is required.
pub fn validate<
    'a,
    N: Verify<E>,
    W: Watch,
    R: Recognizer<E>,
    A: AlternativeVerifier<E>,
    E: Work,
>(
    chain: &[&'a Certificate<'a>],
    anchor: HybridAnchor<'a>,
    context: &ValidationContext<'a, '_, N, W, R, E>,
    requirement: Requirement,
    verifier: &A,
) -> BuildResult<HybridValidation<'a>, CheckError<N::Error, A::Error>, R::Error> {
    let mut signatures = context.execution.vector();
    if chain.is_empty() || chain.len() > context.bounds.depth {
        let outcome = if chain.is_empty() {
            Validation::Rejected(super::Rejection {
                at: None,
                reason: super::RejectionReason::EmptyPath,
            })
        } else {
            Validation::Incomplete(Truncation::Depth)
        };
        return Ok(HybridValidation {
            outcome,
            signatures: signatures.into_owned(),
        });
    }
    let native = Supplied {
        context,
        origin: chain[0],
        spent: 0,
        halted: None,
    };
    let mut driver = HybridDriver {
        native,
        verifier,
        working: anchor.alternative,
        signatures: context.execution.vector().into_owned(),
        next: chain.len(),
        requirement,
        components: None,
    };
    if let Some(outcome) = super::supplied_inputs(chain, anchor.native, &mut driver.native)? {
        return Ok(HybridValidation {
            outcome,
            signatures: signatures.into_owned(),
        });
    }
    signatures
        .try_reserve_exact(chain.len())
        .map_err(|e| Error::resource(e, "hybrid.path", chain[0].span().start))?;
    for (position, certificate) in chain.iter().enumerate() {
        certificate
            .execution_in(context.execution)
            .charge_work(1)
            .map_err(|e| Error::resource(e, "hybrid.path", certificate.span().start))?;
        signatures
            .try_push(CertificateSignatures {
                position,
                source: certificate.span(),
                signatures: None,
            })
            .map_err(|e| Error::resource(e, "hybrid.path", certificate.span().start))?;
    }
    driver.signatures = signatures.into_owned();
    let known = Known(context.recognizer);
    let settings = Settings {
        execution: context.execution,
        interval: context.interval,
        policy: context.policy,
        policies: context.bounds.policies,
        recognizer: &known,
    };
    let outcome = super::process(
        Chain::Supplied(chain),
        anchor.native,
        &settings,
        &mut driver,
    )?;
    let outcome = match driver.native.halted {
        Some(halted) => Validation::Incomplete(halted),
        None => outcome,
    };
    Ok(HybridValidation {
        outcome,
        signatures: driver.signatures,
    })
}
