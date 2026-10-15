use super::*;
use crate::fixtures::{
    CertificateParts, bits, context, extension, generalized_time, octets, seq, tlv,
};
use crate::ocsp::{
    AuthorityBinding, AuthoritySource, DigestAlgorithm, ResolvedDigest, SignatureAuthentication,
};
use crate::path::{Verified, Verify, WorkingKey};
use core::{cell::Cell, num::NonZeroUsize};
use structured_asn1::{BitString, Parser};

struct Provider<'a> {
    key: &'a [u8],
    name: &'a [u8],
    signed: &'a [u8],
    calls: Cell<usize>,
    hashes: Cell<usize>,
    fail: Cell<bool>,
}
impl<E: Work> Digest<E> for Provider<'_> {
    type Handle = ();
    type Error = &'static str;
    fn resolve(
        &self,
        _: DigestAlgorithm<'_>,
        _: &E,
    ) -> core::result::Result<Option<ResolvedDigest<()>>, Self::Error> {
        if self.fail.get() {
            return Err("hash refusal");
        }
        Ok(Some(ResolvedDigest {
            handle: (),
            width: NonZeroUsize::new(20).unwrap(),
        }))
    }
    fn matches(
        &self,
        (): (),
        input: &[u8],
        expected: &[u8],
        _: &E,
    ) -> core::result::Result<bool, Self::Error> {
        self.hashes.set(self.hashes.get() + 1);
        let original = if expected == [0x11; 20] {
            self.name
        } else {
            self.key
        };
        assert_eq!(input.as_ptr(), original.as_ptr());
        assert_eq!(input, original);
        Ok(true)
    }
}
impl Verify for Provider<'_> {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        _: &crate::AlgorithmIdentifier<'_>,
        _: WorkingKey<'_>,
        signed: &[u8],
        _: BitString<'_>,
        _: &Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        assert_eq!(signed.as_ptr(), self.signed.as_ptr());
        assert_eq!(signed, self.signed);
        self.calls.set(self.calls.get() + 1);
        Ok(Verified::Yes)
    }
}

fn inspect(
    repeat: bool,
    check: impl FnOnce(ScopedResponse<'_, '_>, &Certificate<'_>, &Provider<'_>, Evaluation<'_>),
) {
    let target_parts = CertificateParts::default();
    let issuer_bytes = CertificateParts {
        subject: target_parts.issuer.clone(),
        ..CertificateParts::default()
    }
    .build();
    let id = seq(&[
        target_parts.outer_algorithm.clone(),
        octets(&[0x11; 20]),
        octets(&[0x22; 20]),
        target_parts.serial.clone(),
    ]);
    let timestamp = generalized_time("20250101000000Z");
    let single = seq(&[
        id,
        tlv(0x80, &[]),
        timestamp.clone(),
        context(0, &[generalized_time("20250102000000Z")]),
    ]);
    let assertions = if repeat {
        seq(&[single.clone(), single])
    } else {
        seq(&[single])
    };
    let data = seq(&[
        context(2, &[octets(&[0x33; 20])]),
        timestamp,
        assertions,
        context(
            1,
            &[seq(&[extension(
                crate::oid::OCSP_NONCE,
                false,
                &octets(&[0x61; 32]),
            )])],
        ),
    ]);
    let bytes = seq(&[data, target_parts.outer_algorithm.clone(), bits(&[0xab])]);
    let target_bytes = target_parts.build();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let target = Certificate::read(&parser, &target_bytes, 100).unwrap();
    let issuer = Certificate::read(&parser, &issuer_bytes, 300).unwrap();
    let mut reader = parser.read(&bytes, 700).unwrap();
    let root = reader.next_element().unwrap().unwrap();
    let response = crate::ocsp::read_basic(&reader, &root).unwrap();
    let provider = Provider {
        key: issuer.tbs().public_key().key().as_bytes(),
        name: target.tbs().issuer().as_bytes(),
        signed: response.signed_bytes(),
        calls: Cell::new(0),
        hashes: Cell::new(0),
        fail: Cell::new(false),
    };
    let key = WorkingKey::standing(issuer.tbs().public_key());
    let SignatureAuthentication::Signed(signed) = response
        .authenticate_signature(&issuer, key, &provider, &provider, &execution)
        .unwrap()
    else {
        panic!("signature fixture refused");
    };
    let AuthorityBinding::Bound(scoped) = signed.bind_issuer(&issuer, key, &execution).unwrap()
    else {
        panic!("issuer fixture refused");
    };
    let start = response.responses()[0].this_update().instant();
    let utc = LeapTable::new(start.seconds() - 10, start.seconds() + 100_000, &[]).unwrap();
    check(
        scoped,
        &target,
        &provider,
        Evaluation {
            now: start.into(),
            utc: &utc,
            execution: &execution,
        },
    );
}

#[test]
fn issuer_key_origin_is_retained_and_configured_trust_does_not_invent_it() {
    // A source wrapper must retain the actual parameter/source state; the
    // separately configured trust branch never authenticated an issuing key.
    inspect(false, |source, _, _, _| {
        let key = source.issuing_key().expect("actual issuer binding");
        assert!(core::ptr::eq(
            key.key().as_bytes(),
            source.signed().key().key().as_bytes()
        ));
        assert_eq!(key.parameters(), source.signed().key().parameters());
        let configured = source.signed().trust_for_issuer(source.issuer());
        assert_eq!(configured.source(), AuthoritySource::Configured);
        assert!(configured.issuing_key().is_none());
    });
}

#[test]
fn target_reading_retains_actual_binding_without_request_or_rehashing() {
    // A temporary Request/TargetReading must not be pinned by the returned
    // binding. Its target is the actual operand and two CertID hashes run once.
    inspect(false, |source, target, provider, time| {
        let before = provider.hashes.get();
        let held = time.execution.used();
        let bound = {
            // Even the current operation's parser/cursor can end here. The
            // returned target result retains original sources, not its budget.
            let operation = Parser::der(time.execution.clone());
            let query = operation.read(&[], 1200).unwrap();
            let work = query.execution();
            let scoped = Evaluation {
                now: time.now,
                utc: time.utc,
                execution: &work,
            };
            let request = Request {
                target,
                nonce: None,
                intended_signer: None,
            };
            let reading = source
                .evaluate_with_target(&request, &scoped, provider)
                .unwrap();
            assert!(core::ptr::eq(reading.target(), target));
            assert_eq!(reading.evaluated_at(), time.now);
            assert!(matches!(reading.outcome(), TargetEvidence::Evidence(_)));
            reading.evidence().unwrap()
        };
        assert!(core::ptr::eq(bound.target(), target));
        assert_eq!(bound.evaluated_at(), time.now);
        assert!(core::ptr::eq(
            bound.evidence().assertion(),
            &raw const source.signed().response().responses()[0]
        ));
        assert_eq!(provider.hashes.get() - before, 2);
        assert_eq!(provider.calls.get(), 1);
        assert_eq!(time.execution.used(), held);
    });
    inspect(true, |source, target, provider, time| {
        let request = Request {
            target,
            nonce: None,
            intended_signer: None,
        };
        let reading = source
            .evaluate_with_target(&request, &time, provider)
            .unwrap();
        assert!(reading.evidence().is_none());
        assert!(matches!(
            reading.into_outcome(),
            TargetEvidence::Lookup(Lookup::Ambiguous { .. })
        ));
        provider.fail.set(true);
        assert!(matches!(
            source.evaluate_with_target(&request, &time, provider),
            Err(crate::error::CallbackError::Callback("hash refusal"))
        ));
        provider.fail.set(false);
        let unfunded = Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 0),
        ));
        let time = Evaluation {
            execution: &unfunded,
            ..time
        };
        assert!(
            matches!(source.evaluate_with_target(&request,&time,provider),Err(crate::error::CallbackError::Processing(error)) if error.is_resource() && error.offset()==700)
        );
    });
}

#[test]
fn composed_evidence_retains_policy_facts_and_original_ranges_without_reverification() {
    // Provider observation qualifies dispatch/provenance, not crypto accuracy.
    // Evaluation must keep nonce/recipient/time facts rather than bless Good.
    inspect(false, |source, target, provider, time| {
        let retained = time.execution.used();
        let request = Request {
            target,
            nonce: RequestNonce::new(&[0x61; 32]),
            intended_signer: Some(source.signed().signer()),
        };
        let TargetEvidence::Evidence(evidence) =
            source.evaluate(&request, &time, provider).unwrap()
        else {
            panic!("target evidence refused");
        };
        assert_eq!(evidence.nonce(), NonceBinding::Matches);
        assert_eq!(evidence.recipient(), RecipientBinding::Matches);
        assert_eq!(evidence.window(), UpdateWindow::Within);
        assert_eq!(evidence.source().source(), AuthoritySource::Issuer);
        assert!(core::ptr::eq(
            evidence.assertion(),
            &raw const source.signed().response().responses()[0]
        ));
        assert_eq!(provider.calls.get(), 1);
        assert_eq!(time.execution.used(), retained);
        let request = Request {
            nonce: None,
            intended_signer: None,
            ..request
        };
        let TargetEvidence::Evidence(evidence) =
            source.evaluate(&request, &time, provider).unwrap()
        else {
            panic!("missing recipient became implicit rejection");
        };
        assert_eq!(evidence.recipient(), RecipientBinding::NotSpecified);
        assert_eq!(evidence.nonce(), NonceBinding::Unsolicited);
        let request = Request {
            intended_signer: Some(target),
            ..request
        };
        assert!(matches!(
            source.evaluate(&request, &time, provider).unwrap(),
            TargetEvidence::UnexpectedSigner
        ));
        assert_eq!(provider.calls.get(), 1);
    });
}

#[test]
fn duplicate_identity_provider_and_resource_refusals_never_become_missing_or_good() {
    // Duplicate identity stays ambiguous, and callback/resource failures must
    // retain their origin instead of becoming absent/mismatch certificates.
    inspect(true, |source, target, provider, time| {
        let request = Request {
            target,
            nonce: None,
            intended_signer: None,
        };
        assert!(matches!(
            source.evaluate(&request, &time, provider).unwrap(),
            TargetEvidence::Lookup(Lookup::Ambiguous { .. })
        ));
        provider.fail.set(true);
        assert!(matches!(
            source.evaluate(&request, &time, provider),
            Err(crate::error::CallbackError::Callback("hash refusal"))
        ));
        provider.fail.set(false);
        let unfunded = Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 0),
        ));
        let time = Evaluation {
            execution: &unfunded,
            ..time
        };
        assert!(
            matches!(source.evaluate(&request, &time, provider), Err(crate::error::CallbackError::Processing(error)) if error.is_resource() && error.offset() == 700)
        );
    });
}

#[test]
fn scoped_ocsp_evaluation_funds_lazy_nonce_lookup_callbacks_and_utc() {
    // Authentication was established from the original source. A subsequent
    // query must preserve its own operation ceilings through every deferred
    // component, without charging the earlier source's aggregate domain.
    struct ScopedDigest<'a, 'b> {
        original: &'a Provider<'b>,
        resolve_cost: u64,
    }
    impl<E: Work> Digest<E> for ScopedDigest<'_, '_> {
        type Handle = ();
        type Error = structured_asn1::memory::MemoryError;
        fn resolve(
            &self,
            _: DigestAlgorithm<'_>,
            execution: &E,
        ) -> core::result::Result<Option<ResolvedDigest<()>>, Self::Error> {
            execution.charge_work(self.resolve_cost)?;
            Ok(Some(ResolvedDigest {
                handle: (),
                width: NonZeroUsize::new(20).unwrap(),
            }))
        }
        fn matches(
            &self,
            (): (),
            input: &[u8],
            expected: &[u8],
            execution: &E,
        ) -> core::result::Result<bool, Self::Error> {
            execution.charge_work(input.len() as u64)?;
            let original = if expected == [0x11; 20] {
                self.original.name
            } else {
                self.original.key
            };
            assert_eq!(input.as_ptr(), original.as_ptr());
            Ok(input == original)
        }
    }
    inspect(false, |source, target, provider, original| {
        let retained = original.execution.used();
        let old_work = original.execution.work_used();
        let request = Request {
            target,
            nonce: RequestNonce::new(&[0x61; 32]),
            intended_signer: None,
        };
        for (work, depth, resolve_cost, accepted) in [
            (1_000_000, 32, 1, true),
            (0, 32, 1, false),
            (1_000_000, 0, 1, false),
            (1_000_000, 32, 1_000_000, false),
        ] {
            let current = crate::fixtures::memory();
            let operation = Parser::new(
                structured_asn1::Encoding::Der,
                structured_asn1::Limits {
                    max_work: work,
                    max_depth: depth,
                    ..structured_asn1::Limits::default()
                },
                current.clone(),
            );
            let query = operation.read(&[], 1200).unwrap();
            let execution = query.execution();
            let time = Evaluation {
                now: original.now,
                utc: original.utc,
                execution: &execution,
            };
            let digest = ScopedDigest {
                original: provider,
                resolve_cost,
            };
            let result = source.evaluate(&request, &time, &digest);
            if accepted {
                let TargetEvidence::Evidence(evidence) = result.unwrap() else {
                    panic!("same semantic evidence required")
                };
                assert_eq!(evidence.nonce(), NonceBinding::Matches);
                assert_eq!(evidence.window(), UpdateWindow::Within);
            } else if resolve_cost == 1_000_000 {
                assert!(matches!(
                    result,
                    Err(crate::error::CallbackError::Callback(
                        structured_asn1::memory::MemoryError::WorkExceeded
                    ))
                ));
            } else {
                assert!(
                    matches!(result,Err(crate::error::CallbackError::Processing(error)) if error.is_resource())
                );
            }
            assert_eq!(current.used(), 0);
            assert_eq!(original.execution.used(), retained);
            assert_eq!(original.execution.work_used(), old_work);
            assert_eq!(provider.calls.get(), 1);
        }
    });
}
