//! Actual pending acquisition exercises the shared resident/async ERS model.

use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_cms::{
    content_source::ContentError,
    evidence::{AsyncStreams, InputError, verify::VerificationError},
    stream::{AsyncSource, StreamError},
    timestamp::{
        CheckError, ImprintError, InfoCheckError, InfoError, ProfileCheckError, ProfileFailure,
        ProfileSource,
    },
};

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Offline,
    Refused,
}
struct PendingObject<'a> {
    bytes: &'a [u8],
    passes: Cell<usize>,
    offline: bool,
}
impl AsyncSource for PendingObject<'_> {
    type Error = Failure;
    async fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        work: &'q W,
    ) -> Result<(), Failure> {
        work.charge_work(1).map_err(|_| Failure::Refused)?;
        self.passes.set(self.passes.get() + 1);
        let mut yielded = false;
        core::future::poll_fn(|context| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        receiver.write(self.bytes).map_err(|_| Failure::Refused)?;
        if self.offline {
            return Err(Failure::Offline);
        }
        Ok(())
    }
}
fn finish<F: Future>(future: F) -> (F::Output, usize) {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for polls in 0..32 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return (output, polls);
        }
    }
    panic!("the deterministic source only suspends once per object");
}
fn fixture() -> (Vec<u8>, Vec<u8>) {
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &key, &root_key, true);
    let first = token(b"data", &tsa, &root, &key, 0);
    let renewed = token(&first, &tsa, &root, &key, 10);
    let chain = tlv(0x30, &[stamp(&first), stamp(&renewed)].concat());
    let input = [
        Sha256::digest(b"data").as_slice(),
        Sha256::digest(tlv(0x30, &chain)).as_slice(),
    ]
    .concat();
    let last = token(&input, &tsa, &root, &key, 20);
    (record(&[chain, tlv(0x30, &stamp(&last))]), tsa)
}

#[test]
fn pending_objects_share_one_pass_across_both_renewals_and_match_resident_facts() {
    // An actual Pending must preserve all three signed tokens and both renewal
    // recipes. Async acquisition adds no replay, hash state or success subset.
    let (encoded, tsa) = fixture();
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let plan = parsed.input_plan(&parent).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
    let cert_parent = cert_parser.read(&[], 100).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let now = Instant::new(1_767_312_000, 0).unwrap();
    for answer in [Decision::Valid, Decision::Unknown, Decision::Invalid] {
        let provider = Oracle::new();
        let mut resident = [Object {
            bytes: b"data",
            passes: Cell::new(0),
        }];
        let checked = plan
            .verify_with_profile(
                &provider,
                &parent,
                &authority,
                &utc,
                now,
                &mut resident,
                Membership::Object,
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(answer),
                |_, _| Ok::<_, ProfileFailure<Infallible>>(()),
            )
            .unwrap();
        let starts = provider.starts.get();
        let signatures = provider.signatures.get();
        let mut objects = [PendingObject {
            bytes: b"data",
            passes: Cell::new(0),
            offline: false,
        }];
        let history = Cell::new(0);
        let (asynchronous, pending) = finish(plan.verify_async_with_profile(
            &provider,
            &parent,
            &authority,
            &utc,
            now,
            AsyncStreams(&mut objects),
            Membership::Object,
            |_, _, _| Ok::<_, Infallible>(true),
            |facts, _| {
                assert_eq!(facts.index, 2 - history.get());
                assert!(facts.current.evidence().is_some());
                assert_eq!(facts.following.is_some(), facts.index != 2);
                assert_eq!(facts.following_chain.is_some(), facts.index != 2);
                history.set(history.get() + 1);
                Ok::<_, Infallible>(answer)
            },
            |_, _| Ok::<_, ProfileFailure<Infallible>>(()),
        ));
        let asynchronous = asynchronous.unwrap();
        assert_eq!(pending, 1);
        assert_eq!(objects[0].passes.get(), 1);
        assert_eq!(resident[0].passes.get(), 1);
        assert_eq!(history.get(), 3);
        assert_eq!(provider.starts.get() - starts, starts);
        assert_eq!(provider.signatures.get() - signatures, 3);
        assert_eq!(
            asynchronous.verified().is_some(),
            checked.verified().is_some()
        );
        assert_eq!(asynchronous.verified().is_some(), answer == Decision::Valid);
        assert_eq!(asynchronous.ordering(), checked.ordering());
        assert_eq!(
            asynchronous
                .checks()
                .map(structured_cms::evidence::verify::Checked::index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        for (left, right) in asynchronous.checks().zip(checked.checks()) {
            assert_eq!(left.timestamp().imprint, right.timestamp().imprint);
            assert_eq!(left.historical(), right.historical());
        }
    }
}

#[test]
fn async_profile_refusal_precedes_acquisition_and_preserves_original_cause() {
    // Profile admission still precedes provider signature math and external
    // bytes. A generic async wrapper must not eagerly warm the object cache.
    let (encoded, tsa) = fixture();
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let plan = parsed.input_plan(&parent).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
    let cert_parent = cert_parser.read(&[], 100).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let provider = Oracle::new();
    let mut objects = [PendingObject {
        bytes: b"data",
        passes: Cell::new(0),
        offline: false,
    }];
    let (result, pending) = finish(plan.verify_async_with_profile(
        &provider,
        &parent,
        &authority,
        &utc,
        Instant::new(1_767_312_000, 0).unwrap(),
        AsyncStreams(&mut objects),
        Membership::Object,
        |_, _, _| Ok::<_, Infallible>(true),
        |_, _| panic!("history follows profile admission"),
        |index, _| {
            assert_eq!(index, 2);
            Err(ProfileFailure {
                source: ProfileSource::Information,
                cause: "profile",
            })
        },
    ));
    let error = result.err().expect("the selected profile refuses");
    assert!(matches!(
        error,
        VerificationError::<_, _, _, _, Infallible, _>::Timestamp {
            index: 2,
            cause: ProfileCheckError::Profile {
                source: ProfileFailure {
                    cause: "profile",
                    ..
                },
                ..
            },
        }
    ));
    assert_eq!(pending, 0);
    assert_eq!(objects[0].passes.get(), 0);
    assert_eq!(provider.signatures.get(), 0);
}

#[test]
fn failed_and_cancelled_acquisition_release_the_whole_async_cache() {
    // Input failure retains its exact typed cause. Cancellation drops all
    // admitted temporary storage, without manufacturing a partial record.
    let (encoded, tsa) = fixture();
    let mem = memory();
    let parser = Parser::ber(mem.clone());
    let mut parent = parser.read(&encoded, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let plan = parsed.input_plan(&parent).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
    let cert_parent = cert_parser.read(&[], 100).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let provider = Oracle::new();
    let baseline = mem.used();
    for cancelled in [false, true] {
        let mut objects = [PendingObject {
            bytes: b"data",
            passes: Cell::new(0),
            offline: true,
        }];
        {
            let future = plan.verify_async_with_profile(
                &provider,
                &parent,
                &authority,
                &utc,
                Instant::new(1_767_312_000, 0).unwrap(),
                AsyncStreams(&mut objects),
                Membership::Object,
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| panic!("failed input cannot reach historical acceptance"),
                |_, _| Ok::<_, ProfileFailure<Infallible>>(()),
            );
            if cancelled {
                let mut future = pin!(future);
                let mut context = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut context).is_pending());
                assert!(mem.used() > baseline);
            } else {
                let (result, pending) = finish(future);
                assert_eq!(pending, 1);
                let error = result.err().expect("failed EOF has no completed report");
                assert!(matches!(
                    error,
                    VerificationError::<_, _, _, _, Infallible, _>::Timestamp {
                        index: 2,
                        cause: ProfileCheckError::Common(CheckError::Information(
                            ContentError::Callback {
                                source: InfoError::Callback(InfoCheckError::Imprint(
                                    ImprintError::Pass(StreamError::Source(InputError::Source(
                                        Failure::Offline
                                    )))
                                )),
                                ..
                            }
                        )),
                    }
                ));
            }
        }
        assert_eq!(objects[0].passes.get(), 1);
        assert_eq!(mem.used(), baseline);
    }
}
