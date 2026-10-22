//! Authenticated AA-CA paths and their constrained AC issuance facts.
use super::{AaPath, Permission};
use crate::attribute_certificate::AttributeCertificate;
use crate::attribute_certificate::controls;
use crate::attribute_certificate::validation::authentication::{self, AlgorithmAgreement};
use crate::attribute_certificate::validation::{Check, Rejection, charge};
use crate::{Error, Result};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Oid, Span};
use structured_pkix::Certificate;
use structured_pkix::extension::Recognizer;
use structured_pkix::path::{self, Anchor, EffectiveAnchor, Interval, Verify, Watch, WorkingKey};

/// Completed AA path result. No rejected or incomplete path carries a usable key.
#[derive(Debug)]
pub enum PathCheck<T, P> {
    /// Static PKIX validation and the complete `AAControls` census/distance
    /// checks completed. Attribute use still requires the retained intersection.
    Accepted(T),
    /// The caller supplied no AA issuer followed by a distinct AA CA position.
    /// Direct-AA trust uses the separate AC authentication API.
    MissingAaCa,
    /// The final path position is not the explicitly selected trusted AA CA
    /// object. Equal encodings from an untrusted pool are not substituted.
    TrustBoundary,
    /// The supplied effective anchor key does not belong to the selected AA CA.
    AnchorKey,
    /// A control was absent or its distance was exceeded.
    Controls(Rejection),
    /// Completed common PKIX path refusal, preserving its source position.
    Path(P),
    /// A caller-selected PKIX processing bound prevented a complete path check.
    Incomplete(path::Truncation),
}

/// Execution failures keep their original processing or callback cause.
#[derive(Debug)]
pub enum PathError<V, R> {
    /// Original AC/PKIX decoding or resource failure.
    Processing(Error),
    /// Original path-verifier error; not an invalid-signature answer.
    Verification(V),
    /// Original caller recognizer error; not an unknown-extension answer.
    Recognition(R),
}
impl<V, R> From<Error> for PathError<V, R> {
    fn from(error: Error) -> Self {
        Self::Processing(error)
    }
}

/// Complete AA-path operation result with independent verifier/recognizer errors.
pub type PathResult<'p, 'a, V, R> =
    core::result::Result<PathCheck<ValidatedPath<'p, 'a>, path::Rejection<'a>>, PathError<V, R>>;

/// A caller-selected AA CA, its authenticated path, effective AA key and controls.
///
/// The last supplied certificate is explicitly trusted as the AA CA and is not
/// part of the RFC5280 prospective path. This capability establishes neither
/// revocation status nor application authorization, holder proof, or targeting.
/// Policy storage and control catalogues retain their accounts after the query.
#[derive(Debug)]
pub struct ValidatedPath<'p, 'a> {
    controls: AaPath<'p, 'a>,
    facts: path::ValidationFacts<'a>,
    anchor: EffectiveAnchor<'a>,
    interval: Interval,
}

impl<'p, 'a> ValidatedPath<'p, 'a> {
    /// Original leaf-first certificates, including the explicitly trusted AA CA.
    #[must_use]
    pub fn certificates(&self) -> &[&Certificate<'a>] {
        self.controls.certificates()
    }
    /// Selected AA CA and its bound effective key, without root re-verification.
    #[must_use]
    pub fn anchor(&self) -> EffectiveAnchor<'a> {
        self.anchor
    }
    /// Completed static PKIX facts, including the actual AA effective key.
    #[must_use]
    pub fn facts(&self) -> &path::ValidationFacts<'a> {
        &self.facts
    }
    /// The same complete interval used by path and later AC authentication.
    #[must_use]
    pub fn interval(&self) -> Interval {
        self.interval
    }
    /// Intersect every control, including for decrypted types and encAttrs.
    /// The caller owns attribute decryption and application permission decisions.
    pub fn allows<W: Work>(&self, kind: Oid<'_>, work: &W) -> Result<Permission> {
        self.controls.allows(kind, work)
    }
    /// Authenticate an AC with this path's AA key and interval, without repeating
    /// any path signature. The supplied verifier enforces its selected algorithm
    /// policy and accounts its backend; no engine is selected by this module.
    /// Holder proof, status, target/proxy effects and authorization remain separate.
    pub fn authenticate<'r, 'c, V, W: Work>(
        &'r self,
        certificate: &'r AttributeCertificate<'c>,
        verifier: &V,
        work: &W,
    ) -> core::result::Result<
        authentication::Outcome<Issued<'r, 'p, 'c, 'a>>,
        authentication::AuthenticationError<<V as AlgorithmAgreement>::Error>,
    >
    where
        V: AlgorithmAgreement,
        for<'op> V: Verify<Execution<'op>, Error = <V as AlgorithmAgreement>::Error>,
    {
        Ok(
            match certificate.authenticate(
                self.controls.certificates[0],
                self.facts.key,
                self.interval,
                verifier,
                work,
            )? {
                authentication::Outcome::Authenticated(facts) => {
                    authentication::Outcome::Authenticated(Issued { path: self, facts })
                }
                authentication::Outcome::Rejected(error) => {
                    authentication::Outcome::Rejected(error)
                }
                authentication::Outcome::Unsupported(stage) => {
                    authentication::Outcome::Unsupported(stage)
                }
            },
        )
    }
}

/// Original AC issuance authenticated under one checked AA-CA path.
/// This is not an authorization grant or proof that other AC obligations passed.
#[derive(Debug)]
pub struct Issued<'r, 'p, 'c, 'a> {
    path: &'r ValidatedPath<'p, 'a>,
    facts: authentication::Authenticated<'r, 'c, 'a>,
}
impl<'r, 'p, 'c, 'a> Issued<'r, 'p, 'c, 'a> {
    /// Actual checked path and selected trust boundary.
    #[must_use]
    pub fn path(&self) -> &'r ValidatedPath<'p, 'a> {
        self.path
    }
    /// Exact AC, AA, effective key, interval and profile obligations.
    #[must_use]
    pub fn facts(&self) -> &authentication::Authenticated<'r, 'c, 'a> {
        &self.facts
    }
    /// Attribute eligibility under this authenticated issuance's complete path.
    /// Excluded types must be ignored for authorization (RFC5755 §7.4), rather
    /// than causing other permitted attributes to disappear. This also applies
    /// to caller-decrypted types and to id-aca-encAttrs itself.
    pub fn allows<W: Work>(&self, kind: Oid<'_>, work: &W) -> Result<Permission> {
        self.path.allows(kind, work)
    }
}

/// Validate one full AA path ending in a caller-selected, directly trusted AA CA.
///
/// Input includes the AA issuer first and the selected AA CA last. The final
/// position must be the exact `trusted_aa_ca` object supplied separately from
/// the path; trust is never inferred from the final element of an input pool.
/// Equal encodings can be represented by using that trusted object in the
/// final position, without copying or re-parsing its contents. All lower
/// certificates must have `AAControls`; the AA CA's optional control also applies.
/// One position alone is not an AA-CA path: use explicit direct-AA authentication
/// instead. No self-signed certificate discovered in a pool becomes trusted.
///
/// The existing PKIX context controls policy, interval and path processing bounds.
/// Its Work bounds the entire operation, including the control census. Only the
/// PKIX phase consumes ValidationBounds.work; no new policy settings are added.
/// All control syntax/distance checks run before provider callbacks. Critical
/// `AAControls` is understood only because this operation enforces its complete
/// census; the caller's remaining recognizer capabilities are forwarded unchanged.
/// No successful prefix or key is returned on processing/callback refusal.
/// RFC5755 §7.4: <https://www.rfc-editor.org/rfc/rfc5755#section-7.4>
pub fn validate<'p, 'a, V, T, R, W>(
    certificates: &'p [&'a Certificate<'a>],
    trusted_aa_ca: &'a Certificate<'a>,
    context: &path::ValidationContext<'a, '_, V, T, R, W>,
) -> PathResult<'p, 'a, <V as Verify<W>>::Error, R::Error>
where
    W: Work,
    V: Verify<W>,
    for<'op> V: Verify<Execution<'op>, Error = <V as Verify<W>>::Error>,
    T: Watch,
    R: Recognizer<W>,
{
    validate_inner(certificates, trusted_aa_ca, None, context)
}

/// The same complete operation with an effective key supplied for the selected
/// AA CA. Original inherited parameters are retained; a key from another SPKI
/// refuses before control decoding or any verification callback.
pub fn validate_with_key<'p, 'a, V, T, R, W>(
    certificates: &'p [&'a Certificate<'a>],
    trusted_aa_ca: &'a Certificate<'a>,
    anchor_key: WorkingKey<'a>,
    context: &path::ValidationContext<'a, '_, V, T, R, W>,
) -> PathResult<'p, 'a, <V as Verify<W>>::Error, R::Error>
where
    W: Work,
    V: Verify<W>,
    for<'op> V: Verify<Execution<'op>, Error = <V as Verify<W>>::Error>,
    T: Watch,
    R: Recognizer<W>,
{
    validate_inner(certificates, trusted_aa_ca, Some(anchor_key), context)
}

enum RecognitionError<E> {
    Processing(Error),
    Callback(E),
}

enum VerificationError<E> {
    Processing(Error),
    Callback(E),
}
struct ScopedVerifier<'r, V>(&'r V);
impl<W: Work, V> Verify<W> for ScopedVerifier<'_, V>
where
    V: Verify<W>,
    for<'op> V: Verify<Execution<'op>, Error = <V as Verify<W>>::Error>,
{
    type Error = VerificationError<<V as Verify<W>>::Error>;
    fn verify(
        &self,
        algorithm: &structured_pkix::AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        input: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        work: &W,
    ) -> core::result::Result<path::Verified, Self::Error> {
        let execution = signature.execution_in(work);
        charge(&execution, 1, signature.span().start).map_err(VerificationError::Processing)?;
        self.0
            .verify(algorithm, key, input, signature, &execution)
            .map_err(VerificationError::Callback)
    }
}
struct Recognized<'r, R> {
    inner: &'r R,
    source: Span,
}
impl<W: Work, R: Recognizer<W>> Recognizer<W> for Recognized<'_, R> {
    type Error = RecognitionError<R::Error>;
    fn recognizes(&self, kind: Oid<'_>, work: &W) -> core::result::Result<bool, Self::Error> {
        charge(work, 10, self.source.start).map_err(RecognitionError::Processing)?;
        if kind == controls::IDENTIFIER {
            Ok(true)
        } else {
            self.inner
                .recognizes(kind, work)
                .map_err(RecognitionError::Callback)
        }
    }
    fn recognizes_other_name(
        &self,
        kind: Oid<'_>,
        work: &W,
    ) -> core::result::Result<bool, Self::Error> {
        self.inner
            .recognizes_other_name(kind, work)
            .map_err(RecognitionError::Callback)
    }
    fn recognizes_name_constraint(
        &self,
        kind: Oid<'_>,
        work: &W,
    ) -> core::result::Result<bool, Self::Error> {
        self.inner
            .recognizes_name_constraint(kind, work)
            .map_err(RecognitionError::Callback)
    }
    fn recognizes_access_method(
        &self,
        kind: Oid<'_>,
        work: &W,
    ) -> core::result::Result<bool, Self::Error> {
        self.inner
            .recognizes_access_method(kind, work)
            .map_err(RecognitionError::Callback)
    }
    fn recognizes_statement(
        &self,
        kind: Oid<'_>,
        work: &W,
    ) -> core::result::Result<bool, Self::Error> {
        self.inner
            .recognizes_statement(kind, work)
            .map_err(RecognitionError::Callback)
    }
}

fn validate_inner<'p, 'a, V, T, R, W>(
    certificates: &'p [&'a Certificate<'a>],
    trusted_aa_ca: &'a Certificate<'a>,
    key: Option<WorkingKey<'a>>,
    context: &path::ValidationContext<'a, '_, V, T, R, W>,
) -> PathResult<'p, 'a, <V as Verify<W>>::Error, R::Error>
where
    W: Work,
    V: Verify<W>,
    for<'op> V: Verify<Execution<'op>, Error = <V as Verify<W>>::Error>,
    T: Watch,
    R: Recognizer<W>,
{
    let Some((aa_ca, chain)) = certificates.split_last() else {
        return Ok(PathCheck::MissingAaCa);
    };
    if chain.is_empty() {
        return Ok(PathCheck::MissingAaCa);
    }
    if !core::ptr::eq(*aa_ca, trusted_aa_ca) {
        return Ok(PathCheck::TrustBoundary);
    }
    if chain.len() > context.bounds.depth {
        return Ok(PathCheck::Incomplete(path::Truncation::Depth));
    }
    let anchor = Anchor::from_certificate(aa_ca);
    let key = key.unwrap_or_else(|| WorkingKey::standing(anchor.key()));
    let Some(anchor) = EffectiveAnchor::bind(anchor, key, context.execution)
        .map_err(|e| PathError::Processing(Error::pkix(e)))?
    else {
        return Ok(PathCheck::AnchorKey);
    };
    let controls = match AaPath::read(certificates, context.execution)? {
        Check::Accepted(value) => value,
        Check::Rejected(error) => return Ok(PathCheck::Controls(error)),
    };
    let recognizer = Recognized {
        inner: context.recognizer,
        source: chain[0].span(),
    };
    // Every path callback must carry the original signed certificate's
    // ceiling, even when the PKIX processor uses an independent current Work.
    let verifier = ScopedVerifier(context.verifier);
    let scoped = path::ValidationContext {
        execution: context.execution,
        interval: context.interval,
        policy: context.policy,
        bounds: context.bounds,
        verifier: &verifier,
        watch: context.watch,
        recognizer: &recognizer,
    };
    let facts = path::validate_effective(chain, anchor, &scoped).map_err(|error| match error {
        path::BuildError::Processing(e) => PathError::Processing(Error::pkix(e)),
        path::BuildError::Verification(VerificationError::Callback(e)) => {
            PathError::Verification(e)
        }
        path::BuildError::Verification(VerificationError::Processing(e)) => {
            PathError::Processing(e)
        }
        path::BuildError::Recognition(RecognitionError::Callback(e)) => PathError::Recognition(e),
        path::BuildError::Recognition(RecognitionError::Processing(e)) => PathError::Processing(e),
    })?;
    Ok(match facts {
        path::Validation::Accepted(facts) => PathCheck::Accepted(ValidatedPath {
            controls,
            facts,
            anchor,
            interval: context.interval,
        }),
        path::Validation::Rejected(error) => PathCheck::Path(error),
        path::Validation::Incomplete(reason) => PathCheck::Incomplete(reason),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::cell::Cell;
    use structured_asn1::memory::{Memory, MemoryAccount};

    struct Spy {
        calls: [Cell<u32>; 5],
        fail: bool,
    }
    impl Spy {
        fn observe(&self, role: usize) -> core::result::Result<bool, usize> {
            self.calls[role].set(self.calls[role].get() + 1);
            if self.fail { Err(role) } else { Ok(true) }
        }
    }
    impl Recognizer for Spy {
        type Error = usize;
        fn recognizes(&self, _: Oid<'_>, _: &Memory) -> core::result::Result<bool, usize> {
            self.observe(0)
        }
        fn recognizes_other_name(
            &self,
            _: Oid<'_>,
            _: &Memory,
        ) -> core::result::Result<bool, usize> {
            self.observe(1)
        }
        fn recognizes_name_constraint(
            &self,
            _: Oid<'_>,
            _: &Memory,
        ) -> core::result::Result<bool, usize> {
            self.observe(2)
        }
        fn recognizes_access_method(
            &self,
            _: Oid<'_>,
            _: &Memory,
        ) -> core::result::Result<bool, usize> {
            self.observe(3)
        }
        fn recognizes_statement(
            &self,
            _: Oid<'_>,
            _: &Memory,
        ) -> core::result::Result<bool, usize> {
            self.observe(4)
        }
    }
    #[test]
    fn control_recognition_preserves_all_other_scheme_roles_and_causes() {
        // A composition adapter must not silently replace any of the caller's five capabilities.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 100)));
        let kind = Oid::from_bytes(&[42]);
        for fail in [false, true] {
            let spy = Spy {
                calls: core::array::from_fn(|_| Cell::new(0)),
                fail,
            };
            let adapter = Recognized {
                inner: &spy,
                source: Span {
                    start: 10,
                    length: 10,
                },
            };
            assert!(matches!(
                adapter.recognizes(controls::IDENTIFIER, &work),
                Ok(true)
            ));
            let outcomes = [
                adapter.recognizes(kind, &work),
                adapter.recognizes_other_name(kind, &work),
                adapter.recognizes_name_constraint(kind, &work),
                adapter.recognizes_access_method(kind, &work),
                adapter.recognizes_statement(kind, &work),
            ];
            for (role, result) in outcomes.into_iter().enumerate() {
                if fail {
                    assert!(
                        matches!(result, Err(RecognitionError::Callback(cause)) if cause == role)
                    );
                } else {
                    assert!(matches!(result, Ok(true)));
                }
                assert_eq!(spy.calls[role].get(), 1);
            }
        }
    }
    #[test]
    fn control_recognition_refuses_current_work_before_comparison_or_delegate() {
        // A known identifier is not an unaccounted success shortcut.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let spy = Spy {
            calls: core::array::from_fn(|_| Cell::new(0)),
            fail: false,
        };
        let adapter = Recognized {
            inner: &spy,
            source: Span {
                start: 10,
                length: 10,
            },
        };
        assert!(
            matches!(adapter.recognizes(controls::IDENTIFIER, &work), Err(RecognitionError::Processing(error)) if error.is_resource() && error.offset() == 10)
        );
        assert_eq!(spy.calls[0].get(), 0);
    }
}
