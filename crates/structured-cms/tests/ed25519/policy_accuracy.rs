//! Real token checks preserve external accuracy without rewriting signed facts.

use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_cms::timestamp::{
    Accuracy, CheckContext, CheckError, EffectiveAccuracy, Evidence, InfoCheckError, InfoError,
    PolicyAccuracy, ProfileCheckError, ProfileFailure, Timeliness, Token,
};
use structured_cms::{
    content_source::ContentError,
    stream::{AsyncSource, Receiver, Refused, Source},
};
use structured_pkix::{
    Certificate,
    temporal::{Instant, LeapTable},
};

struct Input {
    calls: usize,
}
impl Source for Input {
    type Error = Refused;
    fn stream<W: Work>(&mut self, receiver: &mut impl Receiver, _work: &W) -> Result<(), Refused> {
        self.calls += 1;
        receiver.write(b"document")
    }
}
impl AsyncSource for Input {
    type Error = Refused;
    async fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        work: &'q W,
    ) -> Result<(), Refused> {
        let mut suspended = false;
        core::future::poll_fn(|cx| {
            if suspended {
                Poll::Ready(())
            } else {
                suspended = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        Source::stream(self, receiver, work)
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..4 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("bounded test source must complete after one suspension")
}
#[derive(Clone, Copy)]
enum Mode {
    Sync,
    Async,
    Historical,
    HistoricalAsync,
}
#[derive(Clone, Copy)]
enum Expected {
    Evidence(Option<EffectiveAccuracy>),
    Uncertain,
    PolicyMismatch,
    Malformed,
}

fn check(
    accuracy: Option<&[u8]>,
    offered: Option<(&[u8], Accuracy)>,
    mode: Mode,
    expected: Expected,
) -> Option<Evidence> {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let (bytes, certificate_bytes) =
        timestamp_fixture_accuracy(&signing, accuracy, false, FixtureCatalogue::Signer);
    let memory = Memory::new(Arc::new(MemoryAccount::new(2_000_000, 100_000_000)));
    let parser = Parser::ber(memory.clone());
    let certificates = Parser::der(memory.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let parent = parser.read(&[], 400).unwrap();
    let certificate = Certificate::read(&certificates, &certificate_bytes, 900).unwrap();
    let certificate_parent = certificates.read(&[], 900).unwrap();
    let provider = Oracle {
        key: signing.verifying_key(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: if matches!(mode, Mode::Historical | Mode::HistoricalAsync) {
            None
        } else {
            Some(Instant::new(1_800_000_000, 0).unwrap())
        },
        window: None,
        policy_accuracy: offered.map(|(oid, value)| {
            PolicyAccuracy::new(structured_asn1::Oid::from_bytes(oid), value).unwrap()
        }),
    };
    let mut input = Input { calls: 0 };
    let profile_calls = Cell::new(0);
    let profile = |_: structured_cms::timestamp::ProfileInput<'_, '_, '_, '_>| {
        profile_calls.set(profile_calls.get() + 1);
        Ok::<(), ProfileFailure<core::convert::Infallible>>(())
    };
    let checked = match mode {
        Mode::Sync => token.check_input_with_profile(
            &provider,
            &parent,
            &context,
            &mut structured_cms::timestamp::RawInput::new(&mut input),
            |_, _| Ok::<_, ()>(false),
            profile,
        ),
        Mode::Async => ready(token.check_async_with_profile(
            &provider,
            &parent,
            &context,
            &mut structured_cms::timestamp::AsyncRawInput::new(&mut input),
            |_, _| Ok::<_, ()>(false),
            profile,
        )),
        Mode::Historical => token.check_historical_input_with_profile(
            &provider,
            &parent,
            &context,
            &mut structured_cms::timestamp::RawInput::new(&mut input),
            |_, _| Ok::<_, ()>(false),
            profile,
        ),
        Mode::HistoricalAsync => ready(token.check_historical_async_with_profile(
            &provider,
            &parent,
            &context,
            &mut structured_cms::timestamp::AsyncRawInput::new(&mut input),
            |_, _| Ok::<_, ()>(false),
            profile,
        )),
    }
    .map_err(|error| match error {
        ProfileCheckError::Common(source) => source,
        other @ ProfileCheckError::Profile { .. } => {
            panic!("unexpected profile refusal: {other:?}")
        }
    });
    assert_checked(
        checked,
        expected,
        accuracy.is_some(),
        &provider,
        (input.calls, profile_calls.get()),
        &memory,
    )
}

fn assert_checked(
    checked: Result<
        structured_cms::timestamp::CheckedTimestamp<'_>,
        CheckError<Refused, Failure, ()>,
    >,
    expected: Expected,
    written_accuracy: bool,
    provider: &Oracle,
    calls: (usize, usize),
    memory: &Memory,
) -> Option<Evidence> {
    match expected {
        Expected::PolicyMismatch | Expected::Malformed => {
            let error = checked.err().expect("context or syntax must refuse");
            match error {
                CheckError::Information(ContentError::Callback {
                    source: InfoError::Callback(InfoCheckError::PolicyAccuracy { span }),
                    context,
                }) if matches!(expected, Expected::PolicyMismatch) => {
                    // This fixture carries two OCTET STRING fragments, so the
                    // inner TSTInfo starts at logical zero, not physical 400.
                    assert_eq!(span.start, 0);
                    assert_eq!(
                        context.coordinates(),
                        structured_cms::content_source::Coordinates::Logical
                    );
                    let ranges = context.project_span(span, memory).unwrap();
                    assert_eq!(ranges.len(), 2);
                    assert_eq!(ranges[0].length, 7);
                }
                CheckError::Information(ContentError::Callback {
                    source: InfoError::Callback(InfoCheckError::Nonconforming { .. }),
                    ..
                }) if matches!(expected, Expected::Malformed) => (),
                other => panic!("wrong refusal: {other:?}"),
            }
            assert_eq!(provider.digest_starts.get(), 0);
            assert_eq!(provider.raw_starts.get(), 0);
            assert_eq!(calls, (0, 0));
            None
        }
        Expected::Evidence(effective) => {
            let checked = checked.unwrap();
            assert_eq!(provider.raw_finishes.get(), 1);
            assert_eq!(calls, (1, 1));
            let evidence = checked.into_evidence().expect("all checks hold");
            assert_eq!(evidence.facts().effective_accuracy(), effective);
            assert_eq!(
                evidence.facts().accuracy(),
                if written_accuracy {
                    Some(Accuracy::new(0, 0, 0))
                } else {
                    None
                }
            );
            Some(evidence)
        }
        Expected::Uncertain => {
            let checked = checked.unwrap();
            assert_eq!(
                checked.timeliness,
                Timeliness::Uncertain(
                    structured_cms::timestamp::BoundUncertainty::AccuracyUnstated
                )
            );
            assert!(checked.evidence().is_none());
            None
        }
    }
}

#[test]
fn policy_accuracy_reaches_real_sync_async_and_historical_evidence() {
    // The same real signature and asynchronous suspension exercise every driver;
    // no implicit accuracy is introduced in the archived ordinary path.
    let value = Accuracy::new(2, 3, 4);
    for mode in [
        Mode::Sync,
        Mode::Async,
        Mode::Historical,
        Mode::HistoricalAsync,
    ] {
        check(
            None,
            Some((&[43], value)),
            mode,
            Expected::Evidence(Some(EffectiveAccuracy::CallerPolicy(value))),
        );
        check(
            Some(&[0x30, 0]),
            Some((&[43], value)),
            mode,
            Expected::Evidence(Some(EffectiveAccuracy::Token(Accuracy::new(0, 0, 0)))),
        );
        check(None, Some((&[42], value)), mode, Expected::PolicyMismatch);
        check(
            Some(&[0x30, 0]),
            Some((&[42], value)),
            mode,
            Expected::PolicyMismatch,
        );
        check(
            Some(&[0x30, 3, 0x80, 1, 0]),
            Some((&[43], value)),
            mode,
            Expected::Malformed,
        );
    }
    for mode in [Mode::Sync, Mode::Async] {
        check(None, None, mode, Expected::Uncertain);
    }
    for mode in [Mode::Historical, Mode::HistoricalAsync] {
        check(None, None, mode, Expected::Evidence(None));
    }
}

#[test]
fn policy_accuracy_provenance_survives_independent_copy_and_zero_is_explicit() {
    // Source token/parser are gone. Both origin and signed policy survive the
    // accounted copy, while token-declared accuracy remains genuinely absent.
    let zero = Accuracy::new(0, 0, 0);
    let evidence = check(
        None,
        Some((&[43], zero)),
        Mode::Sync,
        Expected::Evidence(Some(EffectiveAccuracy::CallerPolicy(zero))),
    )
    .unwrap();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let copy = evidence.try_copy_in(&memory).unwrap();
    drop(evidence);
    assert_eq!(copy.facts().policy().as_bytes(), &[43]);
    assert_eq!(copy.facts().accuracy(), None);
    assert_eq!(
        copy.facts().effective_accuracy(),
        Some(EffectiveAccuracy::CallerPolicy(zero))
    );
    assert!(memory.used() > 0);
    drop(copy);
    assert_eq!(memory.used(), 0);
}

#[test]
fn policy_accuracy_rejects_invalid_fractional_components_without_clamping() {
    // This explicit caller input must be validated independently of token ASN.1.
    let oid = structured_asn1::Oid::from_bytes(&[43]);
    for value in [Accuracy::new(0, 1000, 0), Accuracy::new(0, 0, 1000)] {
        assert_eq!(
            PolicyAccuracy::new(oid, value).err(),
            Some(structured_cms::timestamp::InvalidPolicyAccuracy)
        );
    }
    assert!(PolicyAccuracy::new(oid, Accuracy::new(u64::MAX, 999, 999)).is_ok());
}

#[test]
fn ers_chronology_uses_effective_accuracy_and_keeps_uncertainty_separate() {
    // Identical source times are ordered only with explicit zero deviation;
    // a policy interval overlaps, while genuinely unstated bounds stay unknown.
    use structured_cms::evidence::verify::{OrderCause, order_evidence};
    let zero = Accuracy::new(0, 0, 0);
    let stated = check(
        None,
        Some((&[43], zero)),
        Mode::Historical,
        Expected::Evidence(Some(EffectiveAccuracy::CallerPolicy(zero))),
    )
    .unwrap();
    let range = Accuracy::new(2, 0, 0);
    let bounded = check(
        None,
        Some((&[43], range)),
        Mode::Historical,
        Expected::Evidence(Some(EffectiveAccuracy::CallerPolicy(range))),
    )
    .unwrap();
    let unknown = check(None, None, Mode::Historical, Expected::Evidence(None)).unwrap();
    let signing = SigningKey::from_bytes(&[7; 32]);
    let (_, bytes) = timestamp_fixture(&signing, false, false);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let parser = Parser::der(memory.clone());
    let certificate = Certificate::read(&parser, &bytes, 900).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    assert_eq!(
        order_evidence(&stated, &certificate, &stated, &certificate, &utc, &memory).unwrap(),
        None
    );
    assert_eq!(
        order_evidence(
            &bounded,
            &certificate,
            &bounded,
            &certificate,
            &utc,
            &memory
        )
        .unwrap(),
        Some(OrderCause::Overlap)
    );
    assert_eq!(
        order_evidence(
            &unknown,
            &certificate,
            &unknown,
            &certificate,
            &utc,
            &memory
        )
        .unwrap(),
        Some(OrderCause::Bounds {
            earlier: Some(structured_cms::timestamp::BoundUncertainty::AccuracyUnstated),
            later: Some(structured_cms::timestamp::BoundUncertainty::AccuracyUnstated)
        })
    );
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(
        order_evidence(&stated, &certificate, &stated, &certificate, &utc, &empty)
            .unwrap_err()
            .is_resource()
    );
}
