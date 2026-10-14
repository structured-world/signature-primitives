//! Provider lifecycle/cost-model tests; the synthetic digest is not cryptography.

use core::cell::Cell;
use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::digest::{DigestBatch, DigestError, DigestMemo};
use structured_cms::provider::{DigestAlgorithm, DigestProvider, Prehash, Resolution};

#[test]
fn finalized_binding_refuses_a_different_provider_instance_before_callback() {
    // Equal associated identity/output types do not prove instance provenance.
    // A digest completed by one provider cannot be rebound through another.
    let original = Provider::default();
    let other = Provider::default();
    let memory = memory();
    let batch = DigestBatch::prepare(
        &original,
        identities(&memory, &[(1, 0)]),
        &memory,
        "payload",
        400,
    )
    .unwrap();
    let mut source = Feed {
        chunks: &[b"ab"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    let memo = batch.run(&mut source, &memory).unwrap();
    let digest = memo.for_request(0, &memory).unwrap().unwrap();
    let error = structured_cms::binding::matches_digest(
        &other,
        digest.prehash(),
        &[1, 195],
        &memory,
        "imprint",
        structured_asn1::Span {
            start: 700,
            length: 4,
        },
    )
    .unwrap_err();
    let structured_cms::binding::BindError::Processing(error) = error else {
        panic!("instance misuse must be processing failure")
    };
    assert_eq!(error.code(), structured_cms::ErrorCode::ProviderMismatch);
    assert_eq!(error.offset(), 700);
    assert_eq!(other.matches.get(), 0);
    assert_eq!(other.starts.get(), 0);
}
use structured_cms::stream::{Receiver, Source, StreamError};

#[derive(Debug)]
enum CallbackError {
    Resource(MemoryError),
    Injected,
}

impl From<MemoryError> for CallbackError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

// Neither resolved identities nor states implement Clone.
struct Identity {
    algorithm: u8,
    parameters: u8,
}
struct State {
    sum: u8,
    hold: OwnedVec<u8>,
}
struct Output(OwnedVec<u8>);
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    updates: Cell<usize>,
    finishes: Cell<usize>,
    comparisons: Cell<usize>,
    truncate_output: Cell<bool>,
    matches: Cell<usize>,
}

impl<'a> DigestProvider<'a> for Provider {
    type Error = CallbackError;
    type Identity = Identity;
    type State = State;
    type Output = Output;

    fn resolve_digest(
        &'a self,
        _identifier: DigestAlgorithm<'a>,
        _encoding: Encoding,
        _parent: &Reader<'a>,
    ) -> Result<Resolution<Identity>, CallbackError> {
        Ok(Resolution::Unsupported)
    }
    fn compare_digest<W: Work>(
        &self,
        left: &Identity,
        right: &Identity,
        execution: &W,
    ) -> Result<Ordering, CallbackError> {
        execution.charge_work(1)?;
        self.comparisons.set(self.comparisons.get() + 1);
        Ok((left.algorithm, left.parameters).cmp(&(right.algorithm, right.parameters)))
    }
    fn digest_width(&self, identity: &Identity) -> Option<usize> {
        if identity.algorithm == 9 {
            None
        } else {
            Some(2)
        }
    }
    fn start_digest<W: Work>(
        &'a self,
        identity: &Identity,
        execution: &W,
    ) -> Result<State, CallbackError> {
        execution.charge_work(1)?;
        let mut hold = execution.vector();
        hold.try_reserve_exact(1)?;
        hold.try_push(identity.algorithm)?;
        self.starts.set(self.starts.get() + 1);
        Ok(State {
            sum: identity.parameters,
            hold: hold.into_owned(),
        })
    }
    fn update_digest<W: Work>(
        &self,
        state: &mut State,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), CallbackError> {
        execution.charge_work(bytes.len() as u64)?;
        self.updates.set(self.updates.get() + 1);
        if bytes == b"stop" {
            return Err(CallbackError::Injected);
        }
        for byte in bytes {
            state.sum = state.sum.wrapping_add(*byte);
        }
        Ok(())
    }
    fn finish_digest<W: Work>(&self, state: State, execution: &W) -> Result<Output, CallbackError> {
        execution.charge_work(1)?;
        let mut output = execution.vector();
        output.try_reserve_exact(2)?;
        output.try_push(state.hold[0])?;
        output.try_push(state.sum)?;
        if self.truncate_output.get() {
            output.pop();
        }
        self.finishes.set(self.finishes.get() + 1);
        Ok(Output(output.into_owned()))
    }

    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, Identity>,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, CallbackError> {
        execution.charge_work(1)?;
        let bytes = digest.as_bytes();
        if bytes.len() != expected.len() {
            return Ok(false);
        }
        execution.charge_work(bytes.len() as u64)?;
        self.matches.set(self.matches.get() + 1);
        Ok(bytes == expected)
    }
}

struct Feed<'a> {
    chunks: &'a [&'a [u8]],
    calls: usize,
    incomplete: bool,
    ignore_refusal: bool,
}
impl Source for Feed<'_> {
    type Error = &'static str;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        for chunk in self.chunks {
            execution.charge_work(1).map_err(|_| "source resources")?;
            if receiver.write(chunk).is_err() && !self.ignore_refusal {
                return Err("receiver refused");
            }
        }
        if self.incomplete {
            Err("incomplete")
        } else {
            Ok(())
        }
    }
}

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, 1_048_576)))
}
fn identities(execution: &Memory, pairs: &[(u8, u8)]) -> OwnedVec<Identity> {
    let mut values = execution.vector();
    for (algorithm, parameters) in pairs {
        values
            .try_push(Identity {
                algorithm: *algorithm,
                parameters: *parameters,
            })
            .unwrap();
    }
    values
}

#[test]
fn wrong_fixed_provider_output_never_becomes_a_completed_digest() {
    // A selected identity promises a fixed width. An adapter violating that
    // contract must not publish a malformed digest or report a document mismatch.
    let provider = Provider::default();
    provider.truncate_output.set(true);
    let memory = memory();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&memory, &[(1, 0)]),
        &memory,
        "digest",
        400,
    )
    .unwrap();
    let mut source = Feed {
        chunks: &[b"a"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    assert!(matches!(
        batch.run(&mut source, &memory),
        Err(StreamError::Callback(DigestError::OutputWidth {
            expected: 2,
            actual: 1
        }))
    ));
    assert_eq!(source.calls, 1);
    assert_eq!(provider.finishes.get(), 1);
    assert_eq!(memory.used(), 0);
}

#[test]
fn original_signed_ranges_get_a_distinct_output_with_the_same_mapped_identity() {
    // signedAttrs and payload use the same selected identity but different
    // inputs. Only the signed implicit tag is replaced; no state/identity clone
    // or new resolution is needed after payload sort/dedup.
    let provider = Provider::default();
    let memory = memory();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&memory, &[(2, 3), (1, 2), (1, 2)]),
        &memory,
        "payload",
        400,
    )
    .unwrap();
    let mut payload = Feed {
        chunks: &[b"a"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    let memo = batch.run(&mut payload, &memory).unwrap();
    let encoded = [0xa0, 7, 0x30, 5, 6, 1, 42, 0x31, 0];
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = structured_cms::attribute::Attributes::read(
        &reader,
        &element,
        structured_cms::attribute::Placement::Signed,
    )
    .unwrap();
    let mut ranges = attributes.signed_bytes().unwrap();
    assert_eq!(ranges[0], &[0x31]);
    assert_eq!(ranges[1].as_ptr(), encoded[1..].as_ptr());
    let held = memory.used();
    let related = memo
        .digest_related(
            1,
            &mut ranges,
            &reader.execution(),
            "signerInfo.signedAttrs",
            900,
        )
        .unwrap()
        .unwrap();
    let payload_digest = memo.for_request(1, &reader.execution()).unwrap().unwrap();
    let duplicate = memo.for_request(2, &reader.execution()).unwrap().unwrap();
    let prehash = related.prehash();
    assert!(core::ptr::eq(prehash.identity(), payload_digest.identity()));
    assert!(core::ptr::eq(payload_digest, duplicate));
    let expected = ranges
        .iter()
        .flat_map(|range| range.iter())
        .fold(2_u8, |sum, byte| sum.wrapping_add(*byte));
    assert_eq!(prehash.as_bytes(), &[1, expected]);
    assert_eq!(payload_digest.as_bytes(), &[1, 99]);
    assert_ne!(prehash.as_bytes(), payload_digest.as_bytes());
    assert!(
        provider
            .matches_digest(related.prehash(), &[1, expected], &reader.execution())
            .unwrap()
    );
    assert!(
        !provider
            .matches_digest(
                payload_digest.prehash(),
                &[1, expected],
                &reader.execution()
            )
            .unwrap()
    );
    assert_eq!(payload.calls, 1);
    assert_eq!(provider.starts.get(), 3);
    assert_eq!(provider.updates.get(), 4);
    assert_eq!(provider.finishes.get(), 3);
    drop(related);
    assert_eq!(memory.used(), held);
    assert_incomplete_related_keeps_memo(&memo, &provider, &reader.execution());
    drop(attributes);
    drop(memo);
    assert_eq!(memory.used(), 0);
}

fn assert_incomplete_related_keeps_memo<W: Work>(
    memo: &DigestMemo<'_, Provider>,
    provider: &Provider,
    execution: &W,
) {
    let starts = provider.starts.get();
    let finishes = provider.finishes.get();
    let held = execution.memory().used();
    let mut absent = Feed {
        chunks: &[b"unused"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    assert!(
        memo.digest_related(99, &mut absent, execution, "attrs", 900)
            .unwrap()
            .is_none()
    );
    assert_eq!(absent.calls, 0);
    assert_eq!(provider.starts.get(), starts);
    let mut partial = Feed {
        chunks: &[b"prefix"],
        calls: 0,
        incomplete: true,
        ignore_refusal: false,
    };
    assert!(matches!(
        memo.digest_related(1, &mut partial, execution, "attrs", 900),
        Err(StreamError::Source("incomplete"))
    ));
    assert_eq!(provider.finishes.get(), finishes);
    assert_eq!(execution.memory().used(), held);
}

#[test]
fn imprint_binding_admits_current_work_and_checks_actual_width_without_rehashing() {
    // Both fixed and nonfixed metadata paths must distinguish malformed width,
    // admitted byte mismatch and current-domain resource refusal.
    use structured_cms::binding::{self, BindError, DigestBinding};
    let span = structured_asn1::Span {
        start: 700,
        length: 4,
    };
    for algorithm in [1, 9] {
        let provider = Provider::default();
        let memory = memory();
        let batch = DigestBatch::prepare(
            &provider,
            identities(&memory, &[(algorithm, 0)]),
            &memory,
            "payload",
            400,
        )
        .unwrap();
        let mut source = Feed {
            chunks: &[b"ab"],
            calls: 0,
            incomplete: false,
            ignore_refusal: false,
        };
        let memo = batch.run(&mut source, &memory).unwrap();
        let digest = memo.for_request(0, &memory).unwrap().unwrap();
        let compare = |expected: &[u8]| {
            binding::matches_digest(
                &provider,
                digest.prehash(),
                expected,
                &memory,
                "imprint",
                span,
            )
        };
        assert!(matches!(
            compare(&[algorithm, 195]).unwrap(),
            DigestBinding::Matches
        ));
        assert!(matches!(
            compare(&[algorithm + 1, 195]).unwrap(),
            DigestBinding::Differs
        ));
        assert!(matches!(
            compare(&[algorithm, 194]).unwrap(),
            DigestBinding::Differs
        ));
        let DigestBinding::Malformed(error) = compare(&[algorithm]).unwrap() else {
            panic!("width mismatch is malformed");
        };
        assert_eq!(error.code(), structured_cms::ErrorCode::DigestWidth);
        assert_eq!(error.offset(), 700);
        assert_eq!(provider.matches.get(), 3);
        let exhausted = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let Err(BindError::Processing(error)) = binding::matches_digest(
            &provider,
            digest.prehash(),
            &[algorithm, 195],
            &exhausted,
            "imprint",
            span,
        ) else {
            panic!("dispatch must refuse");
        };
        assert!(error.is_resource());
        assert_eq!(error.offset(), 700);
        let exhausted = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
        assert!(matches!(
            binding::matches_digest(
                &provider,
                digest.prehash(),
                &[algorithm, 195],
                &exhausted,
                "imprint",
                span
            ),
            Err(BindError::Callback(CallbackError::Resource(
                MemoryError::WorkExceeded
            )))
        ));
        assert_eq!(provider.matches.get(), 3);
        assert_eq!(provider.starts.get(), 1);
        assert_eq!(provider.updates.get(), 1);
        assert_eq!(provider.finishes.get(), 1);
        assert_eq!(source.calls, 1);
    }
}

#[test]
fn one_source_pass_and_one_finish_per_full_identity_without_state_clone() {
    // Equal OIDs/widths with different parameters must remain different hashes.
    let provider = Provider::default();
    let old = memory();
    let mut source = Feed {
        chunks: &[b"a", b"b"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    let memo;
    {
        let parser = Parser::ber(old.clone());
        let reader = parser.read(&[], 900).unwrap();
        let requested = identities(&old, &[(2, 0), (1, 1), (1, 0), (1, 1)]);
        let batch = DigestBatch::prepare(&provider, requested, &reader.execution(), "content", 900)
            .unwrap();
        assert_eq!(batch.len(), 3);
        memo = batch.run(&mut source, &reader.execution()).unwrap();
    }
    assert_eq!(source.calls, 1);
    assert_eq!(provider.starts.get(), 3);
    assert_eq!(provider.updates.get(), 6);
    assert_eq!(provider.finishes.get(), 3);
    assert_eq!(memo.len(), 3);
    assert_eq!(memo.request_count(), 4);
    let current = memory();
    let old_work = old.work_used();
    assert!(core::ptr::eq(
        memo.for_request(1, &current).unwrap().unwrap(),
        memo.for_request(3, &current).unwrap().unwrap()
    ));
    assert_eq!(
        memo.for_request(0, &current)
            .unwrap()
            .unwrap()
            .identity()
            .algorithm,
        2
    );
    assert_eq!(
        memo.for_request(2, &current)
            .unwrap()
            .unwrap()
            .identity()
            .parameters,
        0
    );
    assert!(memo.for_request(4, &current).unwrap().is_none());
    assert_eq!(
        memo.find(
            &Identity {
                algorithm: 1,
                parameters: 0
            },
            &current
        )
        .unwrap()
        .unwrap()
        .as_bytes(),
        [1, 195]
    );
    assert_eq!(
        memo.find(
            &Identity {
                algorithm: 1,
                parameters: 1
            },
            &current
        )
        .unwrap()
        .unwrap()
        .as_bytes(),
        [1, 196]
    );
    assert!(
        memo.find(
            &Identity {
                algorithm: 7,
                parameters: 0
            },
            &current
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(provider.finishes.get(), 3);
    assert_eq!(old.work_used(), old_work);
    assert!(old.used() > 0);
    drop(memo);
    assert_eq!(old.used(), 0);
    assert_eq!(current.used(), 0);
}

#[test]
fn incomplete_source_returns_no_partial_digest_and_never_finishes_states() {
    // A readable prefix cannot authenticate a truncated payload.
    let provider = Provider::default();
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 900).unwrap();
    let requested = identities(&memory, &[(1, 0)]);
    let batch =
        DigestBatch::prepare(&provider, requested, &reader.execution(), "content", 900).unwrap();
    let mut source = Feed {
        chunks: &[b"prefix"],
        calls: 0,
        incomplete: true,
        ignore_refusal: false,
    };
    assert!(matches!(
        batch.run(&mut source, &reader.execution()),
        Err(StreamError::Source("incomplete"))
    ));
    assert_eq!(provider.updates.get(), 1);
    assert_eq!(provider.finishes.get(), 0);
    assert_eq!(memory.used(), 0);
}

#[test]
fn provider_refusal_is_sticky_even_when_source_ignores_it() {
    // Source success after a failed write cannot erase the original callback error.
    let provider = Provider::default();
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 900).unwrap();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&memory, &[(1, 0)]),
        &reader.execution(),
        "content",
        900,
    )
    .unwrap();
    let mut source = Feed {
        chunks: &[b"prefix", b"stop", b"ignored"],
        calls: 0,
        incomplete: false,
        ignore_refusal: true,
    };
    assert!(matches!(
        batch.run(&mut source, &reader.execution()),
        Err(StreamError::Callback(DigestError::Callback(
            CallbackError::Injected
        )))
    ));
    assert_eq!(provider.updates.get(), 2);
    assert_eq!(provider.finishes.get(), 0);
    assert_eq!(memory.used(), 0);
}

#[test]
fn preparation_refuses_before_any_provider_state_allocation() {
    // Current-operation metadata admission precedes opaque callback effects.
    let provider = Provider::default();
    let original = memory();
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let result = DigestBatch::prepare(
        &provider,
        identities(&original, &[(1, 0)]),
        &current,
        "content",
        900,
    );
    let Err(DigestError::Processing(error)) = result else {
        panic!("metadata must refuse");
    };
    assert!(error.is_resource());
    assert_eq!(error.offset(), 900);
    assert_eq!(provider.starts.get(), 0);
    assert_eq!(original.used(), 0);
    assert_eq!(current.used(), 0);
}

#[test]
fn memo_lookup_refusal_never_becomes_missing_identity() {
    // Retained output has its old charge, but a new lookup needs current work.
    let provider = Provider::default();
    let original = memory();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&original, &[(1, 0)]),
        &original,
        "content",
        900,
    )
    .unwrap();
    let mut source = Feed {
        chunks: &[],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    let memo = batch.run(&mut source, &original).unwrap();
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let Err(DigestError::Processing(error)) = memo.find(
        &Identity {
            algorithm: 9,
            parameters: 0,
        },
        &current,
    ) else {
        panic!("absence requires an admitted lookup");
    };
    assert!(error.is_resource());
    assert_eq!(error.offset(), 900);
}

#[test]
fn wide_duplicate_requests_use_sorting_rather_than_pairwise_search() {
    // Bound the actual comparator count to guard against quadratic deduplication.
    let provider = Provider::default();
    let memory = memory();
    let mut pairs = Vec::new();
    for index in (0..128_u8).rev() {
        pairs.push((index % 8, index % 2));
    }
    let batch = DigestBatch::prepare(
        &provider,
        identities(&memory, &pairs),
        &memory,
        "content",
        900,
    )
    .unwrap();
    assert_eq!(batch.len(), 8);
    assert_eq!(provider.starts.get(), 8);
    assert!(provider.comparisons.get() <= 4 * pairs.len() * 8);
    drop(batch);
    assert_eq!(memory.used(), 0);
}

#[test]
fn provider_owned_output_allocation_refusal_keeps_callback_cause() {
    // A backend's charge refusal remains Callback(Resource), not invalid data.
    let provider = Provider::default();
    let memory = memory();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&memory, &[(1, 0)]),
        &memory,
        "content",
        900,
    )
    .unwrap();
    let output_slot =
        core::mem::size_of::<structured_cms::provider::Finalized<'_, Provider, Identity, Output>>();
    let unfunded = Memory::new(Arc::new(MemoryAccount::new(output_slot, 65536)));
    let mut source = Feed {
        chunks: &[],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    // Fund the exact core output slot. The provider's additional output bytes
    // must then refuse before allocation, preserving that original callback cause.
    assert!(matches!(
        batch.run(&mut source, &unfunded),
        Err(StreamError::Callback(DigestError::Callback(
            CallbackError::Resource(MemoryError::LimitExceeded)
        )))
    ));
    assert_eq!(memory.used(), 0);
    assert_eq!(unfunded.used(), 0);
    assert_eq!(source.calls, 1);
    assert_eq!(provider.finishes.get(), 0);
}

#[test]
fn output_catalogue_is_admitted_before_observable_source_work() {
    // Its required size is known during preparation: refuse before reading a
    // payload that could never produce an accounted complete result catalogue.
    let provider = Provider::default();
    let original = memory();
    let batch = DigestBatch::prepare(
        &provider,
        identities(&original, &[(1, 0)]),
        &original,
        "content",
        900,
    )
    .unwrap();
    let unfunded = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let mut source = Feed {
        chunks: &[b"payload"],
        calls: 0,
        incomplete: false,
        ignore_refusal: false,
    };
    let Err(StreamError::Processing(error)) = batch.run(&mut source, &unfunded) else {
        panic!("output slots must be funded before source dispatch");
    };
    assert!(error.is_resource());
    assert_eq!(source.calls, 0);
    assert_eq!(provider.updates.get(), 0);
    assert_eq!(provider.finishes.get(), 0);
    assert_eq!(original.used(), 0);
}
