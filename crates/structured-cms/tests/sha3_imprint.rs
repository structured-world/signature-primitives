//! SHA3 through the public timestamp boundary, with a test-only crypto oracle.

use core::{cell::Cell, cmp::Ordering};
use sha3::{Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_cms::stream::{Receiver, Refused, Source};
use structured_cms::timestamp::{ImprintAgreement, ImprintError, MessageImprint};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

const CASES: [(Algorithm, u8); 4] = [
    (Algorithm::Sha3_224, 7),
    (Algorithm::Sha3_256, 8),
    (Algorithm::Sha3_384, 9),
    (Algorithm::Sha3_512, 10),
];

enum State {
    S224(Sha3_224),
    S256(Sha3_256),
    S384(Sha3_384),
    S512(Sha3_512),
}

struct Output {
    bytes: [u8; 64],
    width: usize,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.width]
    }
}

#[derive(Default)]
struct Provider {
    identities: Cell<usize>,
    starts: Cell<usize>,
    finishes: Cell<usize>,
    unsupported: bool,
}

impl structured_asn1::digest::Digest<'_> for Provider {
    type Identity = Algorithm;
    type State = State;
    type Output = Output;
    type Error = MemoryError;

    fn width(&self, identity: &Algorithm) -> Option<usize> {
        Some(identity.width())
    }
    fn compare<W: Work>(
        &self,
        a: &Algorithm,
        b: &Algorithm,
        work: &W,
    ) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok(a.cmp(b))
    }
    fn start<W: Work>(
        &self,
        identity: &Algorithm,
        work: &W,
    ) -> Result<Resolution<State>, MemoryError> {
        // Inline fixed-size states; these charges are a test allowance, not
        // a qualified production backend cost model.
        work.charge_work(1)?;
        let state = match identity {
            Algorithm::Sha3_224 => State::S224(Sha3_224::new()),
            Algorithm::Sha3_256 => State::S256(Sha3_256::new()),
            Algorithm::Sha3_384 => State::S384(Sha3_384::new()),
            Algorithm::Sha3_512 => State::S512(Sha3_512::new()),
            _ => return Ok(Resolution::Unsupported),
        };
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(state))
    }
    fn update<W: Work>(
        &self,
        state: &mut State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(bytes.len() as u64)?;
        match state {
            State::S224(s) => s.update(bytes),
            State::S256(s) => s.update(bytes),
            State::S384(s) => s.update(bytes),
            State::S512(s) => s.update(bytes),
        }
        Ok(())
    }
    fn finish<W: Work>(&self, state: State, work: &W) -> Result<Output, MemoryError> {
        work.charge_work(65)?;
        let mut output = Output {
            bytes: [0; 64],
            width: 0,
        };
        match state {
            State::S224(s) => {
                output.width = 28;
                output.bytes[..28].copy_from_slice(&s.finalize());
            }
            State::S256(s) => {
                output.width = 32;
                output.bytes[..32].copy_from_slice(&s.finalize());
            }
            State::S384(s) => {
                output.width = 48;
                output.bytes[..48].copy_from_slice(&s.finalize());
            }
            State::S512(s) => {
                output.width = 64;
                output.bytes.copy_from_slice(&s.finalize());
            }
        }
        self.finishes.set(self.finishes.get() + 1);
        Ok(output)
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        output: &Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(expected.len() as u64)?;
        Ok(output.as_ref() == expected)
    }
}

impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        self.identities.set(self.identities.get() + 1);
        if self.unsupported {
            return None;
        }
        match algorithm {
            Algorithm::Sha3_224
            | Algorithm::Sha3_256
            | Algorithm::Sha3_384
            | Algorithm::Sha3_512 => Some(algorithm),
            _ => None,
        }
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    passes: usize,
}
impl Source for Input<'_> {
    type Error = Refused;
    fn stream<W: Work>(&mut self, receiver: &mut impl Receiver, work: &W) -> Result<(), Refused> {
        self.passes += 1;
        for chunk in self.bytes.chunks(2) {
            // Funding for source traversal is separate from provider hashing.
            work.charge_work(1).map_err(|_| Refused)?;
            receiver.write(chunk)?;
        }
        Ok(())
    }
}

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag, u8::try_from(bytes.len()).unwrap()];
    result.extend_from_slice(bytes);
    result
}
fn imprint(tail: u8, hash: &[u8], segmented: bool, parameters: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, tail]);
    algorithm.extend_from_slice(parameters);
    let mut fields = tlv(0x30, &algorithm);
    if segmented {
        let middle = hash.len() / 2;
        let mut fragments = tlv(4, &hash[..middle]);
        fragments.extend(tlv(4, &hash[middle..]));
        fields.extend(tlv(0x24, &fragments));
    } else {
        fields.extend(tlv(4, hash));
    }
    tlv(0x30, &fields)
}
fn hash(algorithm: Algorithm, input: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::Sha3_224 => Sha3_224::digest(input).to_vec(),
        Algorithm::Sha3_256 => Sha3_256::digest(input).to_vec(),
        Algorithm::Sha3_384 => Sha3_384::digest(input).to_vec(),
        Algorithm::Sha3_512 => Sha3_512::digest(input).to_vec(),
        _ => unreachable!(),
    }
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)))
}

#[test]
fn all_sha3_imprints_stream_once_and_release_temporary_storage() {
    // All four wire OIDs route to their distinct provider identity. Fragmented
    // declarations and chunked content agree without replay; changed content
    // produces a complete mismatch rather than an unsupported algorithm.
    for (algorithm, tail) in CASES {
        for segmented in [false, true] {
            let memory = memory();
            let parser = Parser::ber(memory.clone());
            let provider = Provider::default();
            let bytes = imprint(tail, &hash(algorithm, b"abc"), segmented, &[]);
            let mut reader = parser.read(&bytes, 400).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let reading = MessageImprint::read(&reader, &element).unwrap();
            let held = memory.used();
            for (content, expected) in [
                (b"abc", ImprintAgreement::Matches),
                (b"abd", ImprintAgreement::Differs),
            ] {
                let mut source = Input {
                    bytes: content,
                    passes: 0,
                };
                assert_eq!(
                    reading
                        .check_content(&provider, &reader, &mut source)
                        .unwrap(),
                    expected
                );
                assert_eq!(source.passes, 1);
                assert_eq!(memory.used(), held);
            }
            assert_eq!(
                (
                    provider.identities.get(),
                    provider.starts.get(),
                    provider.finishes.get()
                ),
                (2, 2, 2)
            );
        }
    }
}

#[test]
fn malformed_sha3_and_provider_refusal_precede_content() {
    // Valid NULL is forbidden here even with a BER length spelling. Width
    // refusal occurs before state creation, and provider refusal is distinct.
    for (algorithm, tail) in CASES {
        for (parameters, width, unsupported, expected, identities) in [
            (
                &[5, 0][..],
                algorithm.width(),
                false,
                ImprintAgreement::MalformedAlgorithm,
                0,
            ),
            (
                &[5, 0x81, 0][..],
                algorithm.width(),
                false,
                ImprintAgreement::MalformedAlgorithm,
                0,
            ),
            (
                &[2, 1, 0][..],
                algorithm.width(),
                false,
                ImprintAgreement::MalformedAlgorithm,
                0,
            ),
            (
                &[][..],
                algorithm.width() - 1,
                false,
                ImprintAgreement::MalformedHash,
                1,
            ),
            (
                &[][..],
                algorithm.width(),
                true,
                ImprintAgreement::Unsupported,
                1,
            ),
        ] {
            let parser = Parser::ber(memory());
            let provider = Provider {
                unsupported,
                ..Provider::default()
            };
            let bytes = imprint(tail, &vec![0; width], false, parameters);
            let mut reader = parser.read(&bytes, 400).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let reading = MessageImprint::read(&reader, &element).unwrap();
            let mut source = Input {
                bytes: b"abc",
                passes: 0,
            };
            assert_eq!(
                reading
                    .check_content(&provider, &reader, &mut source)
                    .unwrap(),
                expected
            );
            assert_eq!(
                (
                    source.passes,
                    provider.starts.get(),
                    provider.finishes.get(),
                    provider.identities.get()
                ),
                (0, 0, 0, identities)
            );
        }
    }
}

#[test]
fn exhausted_sha3_query_remains_a_located_resource_error() {
    // A valid algorithm cannot turn budget exhaustion into Unsupported or a
    // digest mismatch, and must not trigger provider or source side effects.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let provider = Provider::default();
    let bytes = imprint(8, &[0; 32], false, &[]);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = MessageImprint::read(&reader, &element).unwrap();
    let held = memory.used();
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    let mut source = Input {
        bytes: b"abc",
        passes: 0,
    };
    assert!(
        matches!(reading.check_content(&provider, &reader, &mut source), Err(ImprintError::Processing(error)) if error.is_resource() && error.offset() == 402)
    );
    assert_eq!(
        (
            source.passes,
            provider.identities.get(),
            provider.starts.get()
        ),
        (0, 0, 0)
    );
    assert_eq!(memory.used(), held);
}
