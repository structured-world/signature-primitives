//! Actual SHA-256 imprint computation and pre-input refusal boundaries.

use core::cell::Cell;
use core::cmp::Ordering;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::provider::{DigestAlgorithm, DigestProvider, Prehash, Resolution};
use structured_cms::stream::{Receiver, Refused, Source};
use structured_cms::timestamp::{ImprintAgreement, ImprintError, MessageImprint};

const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];

#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    finishes: Cell<usize>,
    comparisons: Cell<usize>,
    unsupported: bool,
    truncate: bool,
}

struct Output(OwnedVec<u8>);
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> DigestProvider<'a> for Provider {
    type Error = MemoryError;
    type Identity = ();
    type State = Sha256;
    type Output = Output;

    fn resolve_digest(
        &'a self,
        written: DigestAlgorithm<'a>,
        _: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<()>, MemoryError> {
        let DigestAlgorithm::Written(written) = written else {
            return Ok(Resolution::Unsupported);
        };
        parent
            .execution()
            .charge_work(written.algorithm().as_bytes().len() as u64)?;
        if self.unsupported || written.algorithm().as_bytes() != SHA256 {
            return Ok(Resolution::Unsupported);
        }
        // This test adapter deliberately supports only the absent-parameters
        // SHA-256 profile, not a production algorithm dispatcher.
        if written.parameters().is_some() {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(()))
    }
    fn compare_digest<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn digest_width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn start_digest<W: Work>(&'a self, (): &(), work: &W) -> Result<Sha256, MemoryError> {
        // Explicit test allowance, not a qualified production cost model.
        work.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Sha256::new())
    }
    fn update_digest<W: Work>(
        &self,
        state: &mut Sha256,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish_digest<W: Work>(&self, state: Sha256, work: &W) -> Result<Output, MemoryError> {
        work.charge_work(1)?;
        let value = state.finalize();
        let mut output = work.vector();
        output.try_extend_from_slice(&value)?;
        if self.truncate {
            output.pop();
        }
        self.finishes.set(self.finishes.get() + 1);
        Ok(Output(output.into_owned()))
    }
    fn matches_digest<W: Work>(
        &self,
        output: Prehash<'_, '_, Self, ()>,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(expected.len() as u64)?;
        self.comparisons.set(self.comparisons.get() + 1);
        Ok(output.as_bytes() == expected)
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    passes: usize,
    fail: bool,
}
#[derive(Debug)]
enum InputError {
    Receiver(Refused),
    Unread,
}
impl Source for Input<'_> {
    type Error = InputError;
    fn stream<W: Work>(&mut self, receiver: &mut impl Receiver, _: &W) -> Result<(), InputError> {
        self.passes += 1;
        if self.fail {
            return Err(InputError::Unread);
        }
        for chunk in self.bytes.chunks(2) {
            receiver.write(chunk).map_err(InputError::Receiver)?;
        }
        Ok(())
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag, u8::try_from(value.len()).unwrap()];
    bytes.extend_from_slice(value);
    bytes
}
fn imprint(hash: &[u8], constructed: bool, bare_oid: bool) -> Vec<u8> {
    let oid = tlv(6, SHA256);
    let mut fields = if bare_oid { oid } else { tlv(0x30, &oid) };
    let hash = if constructed {
        let middle = hash.len() / 2;
        let mut fragments = tlv(4, &hash[..middle]);
        fragments.extend(tlv(4, &hash[middle..]));
        tlv(0x24, &fragments)
    } else {
        tlv(4, hash)
    };
    fields.extend(hash);
    tlv(0x30, &fields)
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)))
}

#[test]
fn complete_content_matches_once_without_rehash_or_replay() {
    // Actual SHA-256 over chunked input must agree with both primitive and
    // segmented declarations, preserving one start/pass/finish/comparison.
    for constructed in [false, true] {
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let provider = Provider::default();
        let bytes = imprint(&Sha256::digest(b"abc"), constructed, false);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let imprint = MessageImprint::read(&reader, &element).unwrap();
        let held = memory.used();
        let mut input = Input {
            bytes: b"abc",
            passes: 0,
            fail: false,
        };
        assert_eq!(
            imprint
                .check_content(&provider, &reader, &mut input)
                .unwrap(),
            ImprintAgreement::Matches
        );
        assert_eq!(
            (
                input.passes,
                provider.starts.get(),
                provider.finishes.get(),
                provider.comparisons.get()
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(memory.used(), held);
        let mut different = Input {
            bytes: b"abd",
            passes: 0,
            fail: false,
        };
        assert_eq!(
            imprint
                .check_content(&provider, &reader, &mut different)
                .unwrap(),
            ImprintAgreement::Differs
        );
        assert_eq!(different.passes, 1);
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn impossible_width_malformed_algorithm_and_unsupported_do_not_read_content() {
    // Known malformed width is not mismatch; malformed bare OID is not sent
    // to the resolver and neither condition can initialize a hash state.
    for (hash, bare, unsupported, expected) in [
        (&[0; 31][..], false, false, ImprintAgreement::MalformedHash),
        (
            &[0; 32][..],
            true,
            false,
            ImprintAgreement::MalformedImprint,
        ),
        (&[0; 32][..], false, true, ImprintAgreement::Unsupported),
    ] {
        let memory = memory();
        let parser = Parser::ber(memory);
        let provider = Provider {
            unsupported,
            ..Provider::default()
        };
        let bytes = imprint(hash, false, bare);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let imprint = MessageImprint::read(&reader, &element).unwrap();
        let mut input = Input {
            bytes: b"abc",
            passes: 0,
            fail: true,
        };
        assert_eq!(
            imprint
                .check_content(&provider, &reader, &mut input)
                .unwrap(),
            expected
        );
        assert_eq!(
            (
                input.passes,
                provider.starts.get(),
                provider.finishes.get(),
                provider.comparisons.get()
            ),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn unread_source_and_inconsistent_provider_output_never_become_mismatch() {
    // A failure to complete the pass or a lying output width is an execution
    // failure, independent of valid document syntax and expected hash bytes.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let provider = Provider::default();
    let bad_provider = Provider {
        truncate: true,
        ..Provider::default()
    };
    let bytes = imprint(&Sha256::digest(b"abc"), false, false);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&reader, &element).unwrap();
    let held = memory.used();
    let mut input = Input {
        bytes: b"abc",
        passes: 0,
        fail: true,
    };
    assert!(matches!(
        imprint.check_content(&provider, &reader, &mut input),
        Err(ImprintError::Pass(_))
    ));
    assert_eq!(provider.finishes.get(), 0);
    input.fail = false;
    assert!(matches!(
        imprint.check_content(&bad_provider, &reader, &mut input),
        Err(ImprintError::Pass(_))
    ));
    assert_eq!(bad_provider.comparisons.get(), 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn aggregate_refusal_and_foreign_session_abort_before_input() {
    // Shared storage identity does not grant authority to restart local work.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let provider = Provider::default();
    let bytes = imprint(&Sha256::digest(b"abc"), true, false);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&reader, &element).unwrap();
    let mut input = Input {
        bytes: b"abc",
        passes: 0,
        fail: false,
    };
    let work = memory.work_used();
    assert!(
        matches!(imprint.check_content(&provider, &other, &mut input), Err(ImprintError::Processing(error)) if error.is_terminal())
    );
    assert_eq!(memory.work_used(), work);
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    assert!(matches!(
        imprint.check_content(&provider, &reader, &mut input),
        Err(ImprintError::Callback(_))
    ));
    assert_eq!(input.passes, 0);
    assert_eq!(provider.starts.get(), 0);
}
