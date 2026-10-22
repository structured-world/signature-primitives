//! Computed alternatives and tree inputs use actual SHA256, not digest-shaped bytes.

use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use structured_asn1::{
    Parser, Reader,
    digest::Resolution,
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_cms::{
    digest::DigestError,
    stream::{Receiver, Source, StreamError},
    timestamp::{
        ComputedInput, ImprintAgreement, ImprintContext, ImprintError, ImprintProof, InputFailure,
        MessageImprint,
    },
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Resource(MemoryError),
    Update,
    Comparison,
    Unread,
    Receiver,
}
struct Identity;
struct State(Sha256);
struct Output {
    bytes: [u8; 32],
    short: bool,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        if self.short {
            &self.bytes[..31]
        } else {
            &self.bytes
        }
    }
}
#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    finishes: Cell<usize>,
    comparisons: Cell<usize>,
    fail_update: bool,
    fail_comparison: bool,
    short: bool,
}
impl structured_asn1::digest::Digest<'_> for Provider {
    type Identity = Identity;
    type State = State;
    type Output = Output;
    type Error = Failure;
    fn width(&self, _: &Identity) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, _: &Identity, _: &Identity, work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, _: &Identity, work: &W) -> Result<Resolution<State>, Failure> {
        // Explicit test allowances; not a qualified production crypto cost model.
        work.charge_work(1).map_err(Failure::Resource)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(State(Sha256::new())))
    }
    fn update<W: Work>(&self, state: &mut State, bytes: &[u8], work: &W) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64)
            .map_err(Failure::Resource)?;
        if self.fail_update {
            return Err(Failure::Update);
        }
        state.0.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: State, work: &W) -> Result<Output, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        self.finishes.set(self.finishes.get() + 1);
        Ok(Output {
            bytes: state.0.finalize().into(),
            short: self.short,
        })
    }
    fn matches<W: Work>(
        &self,
        _: &Identity,
        output: &Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(expected.len() as u64)
            .map_err(Failure::Resource)?;
        self.comparisons.set(self.comparisons.get() + 1);
        if self.fail_comparison {
            return Err(Failure::Comparison);
        }
        Ok(output.as_ref() == expected)
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Identity> {
        if algorithm == Algorithm::Sha256 {
            Some(Identity)
        } else {
            None
        }
    }
}
struct Chunks<'a> {
    bytes: &'a [u8],
    passes: usize,
    unread: bool,
    ignore_refusal: bool,
}
impl Source for Chunks<'_> {
    type Error = Failure;
    fn stream<W: Work>(&mut self, sink: &mut impl Receiver, _: &W) -> Result<(), Failure> {
        self.passes += 1;
        for bytes in self.bytes.chunks(2) {
            if sink.write(bytes).is_err() && !self.ignore_refusal {
                return Err(Failure::Receiver);
            }
        }
        if self.unread {
            Err(Failure::Unread)
        } else {
            Ok(())
        }
    }
}
fn bytes(value: &[u8]) -> Chunks<'_> {
    Chunks {
        bytes: value,
        passes: 0,
        unread: false,
        ignore_refusal: false,
    }
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)))
}
fn encoded(hash: &[u8], segmented: bool) -> Vec<u8> {
    let mut body = vec![0x30, 11, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
    if segmented {
        body.extend_from_slice(&[0x24, 36, 4, 16]);
        body.extend_from_slice(&hash[..16]);
        body.extend_from_slice(&[4, 16]);
        body.extend_from_slice(&hash[16..]);
    } else {
        body.extend_from_slice(&[4, u8::try_from(hash.len()).unwrap()]);
        body.extend_from_slice(hash);
    }
    let mut result = vec![0x30, u8::try_from(body.len()).unwrap()];
    result.extend(body);
    result
}
fn read<'a>(reader: &mut Reader<'a>) -> MessageImprint<'a> {
    let element = reader.next_element().unwrap().unwrap();
    MessageImprint::read(reader, &element).unwrap()
}

struct Alternatives<'source, 'payload>(&'source mut Chunks<'payload>);
impl<P, PE> ComputedInput<P, PE> for Alternatives<'_, '_> {
    type Error = Failure;
    fn compute<'c, 'r, 'd>(
        &mut self,
        context: &'c ImprintContext<'r, 'd, P, Failure>,
    ) -> Result<ImprintProof<'c>, InputFailure<Failure>>
    where
        P: AsnDigest<'d, Error = PE>,
    {
        let mut first = context.start()?;
        let mut second = context.start()?;
        first.write(b"first")?;
        second.write(b"second")?;
        context.stream(self.0, &mut [&mut first, &mut second])?;
        let first = first.finish()?;
        let second = second.finish()?;
        let left = context.compare(&first)?;
        let right = context.compare(&second)?;
        if left.agreement() == ImprintAgreement::Matches {
            Ok(left)
        } else {
            Ok(right)
        }
    }
}

#[test]
fn alternatives_share_one_pass_and_complete_every_candidate() {
    // Both possible normative inputs hash together; choosing the second must
    // neither replay acquisition nor require Clone on identity/state/output.
    for (prefix, segmented) in [(b"first".as_slice(), false), (b"second", true)] {
        let work = memory();
        let parser = Parser::ber(work.clone());
        let mut hash = Sha256::new();
        hash.update(prefix);
        hash.update(b"payload");
        let raw = encoded(&hash.finalize(), segmented);
        let mut reader = parser.read(&raw, 700).unwrap();
        let imprint = read(&mut reader);
        let held = work.used();
        let provider = Provider::default();
        let mut source = bytes(b"payload");
        let result = imprint.check_input(&provider, &reader, &mut Alternatives(&mut source));
        assert_eq!(result.unwrap(), ImprintAgreement::Matches);
        assert_eq!(source.passes, 1);
        assert_eq!(
            (
                provider.starts.get(),
                provider.finishes.get(),
                provider.comparisons.get()
            ),
            (2, 2, 2)
        );
        assert_eq!(work.used(), held);
    }
}

struct Tree<'source, 'payload>(&'source mut Chunks<'payload>);
impl<P, PE> ComputedInput<P, PE> for Tree<'_, '_> {
    type Error = Failure;
    fn compute<'c, 'r, 'd>(
        &mut self,
        context: &'c ImprintContext<'r, 'd, P, Failure>,
    ) -> Result<ImprintProof<'c>, InputFailure<Failure>>
    where
        P: AsnDigest<'d, Error = PE>,
    {
        let mut leaf = context.start()?;
        context.stream(self.0, &mut [&mut leaf])?;
        let leaf = leaf.finish()?;
        let mut root = context.start()?;
        root.write(leaf.as_bytes())?;
        root.write(b"sibling")?;
        context
            .compare(&root.finish()?)
            .map_err(InputFailure::Refused)
    }
}
#[test]
fn a_completed_tree_root_is_compared_without_hashing_it_again() {
    // Hash(data) is an intermediate, Hash(leaf||sibling) the imprint itself.
    // Hashing that root a third time is not the specified tree computation.
    let parser = Parser::ber(memory());
    let mut expected = Sha256::new();
    expected.update(Sha256::digest(b"object"));
    expected.update(b"sibling");
    let raw = encoded(&expected.finalize(), false);
    let mut reader = parser.read(&raw, 700).unwrap();
    let imprint = read(&mut reader);
    let provider = Provider::default();
    let mut source = bytes(b"object");
    assert_eq!(
        imprint
            .check_input(&provider, &reader, &mut Tree(&mut source))
            .unwrap(),
        ImprintAgreement::Matches
    );
    assert_eq!(source.passes, 1);
    assert_eq!(
        (
            provider.starts.get(),
            provider.finishes.get(),
            provider.comparisons.get()
        ),
        (2, 2, 1)
    );
}

struct Abandoned(bool);
impl<P, PE> ComputedInput<P, PE> for Abandoned {
    type Error = Failure;
    fn compute<'c, 'r, 'd>(
        &mut self,
        context: &'c ImprintContext<'r, 'd, P, Failure>,
    ) -> Result<ImprintProof<'c>, InputFailure<Failure>>
    where
        P: AsnDigest<'d, Error = PE>,
    {
        let unfinished = context.start()?;
        if self.0 {
            core::mem::forget(unfinished);
        } else {
            drop(unfinished);
        }
        let mut actual = context.start()?;
        actual.write(b"object")?;
        context
            .compare(&actual.finish()?)
            .map_err(InputFailure::Refused)
    }
}
#[test]
fn abandoned_or_forgotten_states_cannot_return_a_successful_prefix() {
    // Dropping OR forgetting an unfinished alternative must prevent a positive
    // final result even when another completed hash matches the declaration.
    let parser = Parser::ber(memory());
    let raw = encoded(&Sha256::digest(b"object"), false);
    let mut reader = parser.read(&raw, 700).unwrap();
    let imprint = read(&mut reader);
    for forget in [false, true] {
        assert!(matches!(
            imprint.check_input(&Provider::default(), &reader, &mut Abandoned(forget)),
            Err(ImprintError::IncompleteInput)
        ));
    }
}

struct Ignored<'source, 'payload>(&'source mut Chunks<'payload>);
impl<P, PE> ComputedInput<P, PE> for Ignored<'_, '_> {
    type Error = Failure;
    fn compute<'c, 'r, 'd>(
        &mut self,
        context: &'c ImprintContext<'r, 'd, P, Failure>,
    ) -> Result<ImprintProof<'c>, InputFailure<Failure>>
    where
        P: AsnDigest<'d, Error = PE>,
    {
        let mut state = context.start()?;
        let _ = context.stream(self.0, &mut [&mut state]);
        if let Ok(output) = state.finish() {
            let _ = context.compare(&output);
        }
        // A later source error cannot replace an earlier original refusal.
        Err(InputFailure::Source(Failure::Receiver))
    }
}
#[test]
fn ignored_acquisition_provider_comparison_and_width_refusals_stay_terminal() {
    // Each underlying failure must survive a deliberately uncooperative
    // source/recipe; no later marker or matching prefix can erase its cause.
    let work = memory();
    let parser = Parser::ber(work.clone());
    let raw = encoded(&Sha256::digest(b"object"), false);
    let mut reader = parser.read(&raw, 700).unwrap();
    let imprint = read(&mut reader);
    let held = work.used();
    let mut source = bytes(b"object");
    source.unread = true;
    assert!(matches!(
        imprint.check_input(&Provider::default(), &reader, &mut Ignored(&mut source)),
        Err(ImprintError::Pass(StreamError::Source(Failure::Unread)))
    ));
    let provider = Provider {
        fail_update: true,
        ..Provider::default()
    };
    let mut source = bytes(b"object");
    source.ignore_refusal = true;
    assert!(matches!(
        imprint.check_input(&provider, &reader, &mut Ignored(&mut source)),
        Err(ImprintError::Pass(StreamError::Callback(
            DigestError::Callback(Failure::Update)
        )))
    ));
    assert_eq!(provider.finishes.get(), 0);
    let provider = Provider {
        fail_comparison: true,
        ..Provider::default()
    };
    let mut source = bytes(b"object");
    assert!(matches!(
        imprint.check_input(&provider, &reader, &mut Ignored(&mut source)),
        Err(ImprintError::Comparison(
            structured_cms::binding::BindError::Callback(Failure::Comparison)
        ))
    ));
    let provider = Provider {
        short: true,
        ..Provider::default()
    };
    let mut source = bytes(b"object");
    assert!(matches!(
        imprint.check_input(&provider, &reader, &mut Ignored(&mut source)),
        Err(ImprintError::Pass(StreamError::Callback(
            DigestError::OutputWidth {
                expected: 32,
                actual: 31
            }
        )))
    ));
    assert_eq!(provider.comparisons.get(), 0);
    assert_eq!(work.used(), held);
}

struct EmptyOrigin<'reader, 'document>(&'reader Reader<'document>);
impl<P, PE> ComputedInput<P, PE> for EmptyOrigin<'_, '_> {
    type Error = Failure;
    fn compute<'c, 'r, 'd>(
        &mut self,
        context: &'c ImprintContext<'r, 'd, P, Failure>,
    ) -> Result<ImprintProof<'c>, InputFailure<Failure>>
    where
        P: AsnDigest<'d, Error = PE>,
    {
        let mut state = context.start()?;
        state.write_from(&[], self.0)?;
        context
            .compare(&state.finish()?)
            .map_err(InputFailure::Refused)
    }
}

#[test]
fn empty_origin_chunk_pays_origin_metadata_before_provider() {
    // An attacker can supply arbitrarily many EMPTY fragments. The engine
    // legitimately charges zero byte work, so the shared fanout must admit
    // the producing-source visit before entering that callback.
    let parser = Parser::ber(memory());
    let raw = encoded(&Sha256::digest([]), false);
    let mut reader = parser.read(&raw, 700).unwrap();
    let imprint = read(&mut reader);
    for allowance in [0, 1] {
        let origin = Parser::new(
            structured_asn1::Encoding::Ber,
            structured_asn1::Limits {
                max_work: allowance,
                ..structured_asn1::Limits::default()
            },
            memory(),
        );
        let origin = origin.read(&[], 9000).unwrap();
        let provider = Provider::default();
        let result = imprint.check_input(&provider, &reader, &mut EmptyOrigin(&origin));
        if allowance == 0 {
            assert!(
                matches!(result, Err(ImprintError::Pass(StreamError::Processing(_)))),
                "exhausted origin returned {result:?}"
            );
            assert_eq!(provider.finishes.get(), 0);
        } else {
            assert_eq!(result.unwrap(), ImprintAgreement::Matches);
            assert_eq!(provider.finishes.get(), 1);
        }
    }
}
