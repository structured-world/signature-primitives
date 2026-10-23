//! Tree and TSA identities can differ without losing finalized-output identity.

use super::{algorithm, memory, record, stamp, tlv};
use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest as _, Sha256, Sha512_256};
use structured_asn1::{
    Parser,
    digest::{Digest, Resolution},
    memory::{MemoryError, Work},
};
use structured_cms::{
    evidence::{EvidenceRecord, Membership, ObjectInput},
    timestamp::{ImprintAgreement, MessageImprint},
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

#[derive(Default)]
struct Provider(Cell<usize>);
enum State {
    Sha256(Sha256),
    Sha512_256(Sha512_256),
}
struct Output {
    algorithm: Algorithm,
    bytes: [u8; 32],
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Digest<'_> for Provider {
    type Identity = Algorithm;
    type State = State;
    type Output = Output;
    type Error = MemoryError;
    fn width(&self, _: &Algorithm) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(
        &self,
        a: &Algorithm,
        b: &Algorithm,
        w: &W,
    ) -> Result<Ordering, MemoryError> {
        w.charge_work(1)?;
        Ok(a.cmp(b))
    }
    fn start<W: Work>(
        &self,
        algorithm: &Algorithm,
        w: &W,
    ) -> Result<Resolution<State>, MemoryError> {
        w.charge_work(1)?;
        self.0.set(self.0.get() + 1);
        Ok(match algorithm {
            Algorithm::Sha256 => Resolution::Supported(State::Sha256(Sha256::new())),
            Algorithm::Sha512_256 => Resolution::Supported(State::Sha512_256(Sha512_256::new())),
            _ => Resolution::Unsupported,
        })
    }
    fn update<W: Work>(&self, state: &mut State, bytes: &[u8], w: &W) -> Result<(), MemoryError> {
        w.charge_work(1 + bytes.len() as u64)?;
        match state {
            State::Sha256(hash) => hash.update(bytes),
            State::Sha512_256(hash) => hash.update(bytes),
        }
        Ok(())
    }
    fn finish<W: Work>(&self, state: State, w: &W) -> Result<Output, MemoryError> {
        w.charge_work(128)?;
        Ok(match state {
            State::Sha256(hash) => Output {
                algorithm: Algorithm::Sha256,
                bytes: hash.finalize().into(),
            },
            State::Sha512_256(hash) => Output {
                algorithm: Algorithm::Sha512_256,
                bytes: hash.finalize().into(),
            },
        })
    }
    fn matches<W: Work>(
        &self,
        algorithm: &Algorithm,
        output: &Output,
        expected: &[u8],
        w: &W,
    ) -> Result<bool, MemoryError> {
        w.charge_work(33)?;
        assert_eq!(
            *algorithm, output.algorithm,
            "a finalized tree output retains its actual tree identity"
        );
        Ok(output.bytes == expected)
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        if matches!(algorithm, Algorithm::Sha256 | Algorithm::Sha512_256) {
            Some(algorithm)
        } else {
            None
        }
    }
}

#[test]
fn written_tree_algorithm_is_not_replaced_with_the_timestamp_algorithm() {
    // RFC4998 §4.2(5) permits explicit tree identity differing from the TSA's
    // identity. Both widths are 32: length is not algorithm provenance.
    let hash = Sha256::digest(b"object");
    let parser = Parser::ber(memory(1_000_000));
    let encoded = record(1, &algorithm(0x30), &tlv(0x30, &stamp(None)));
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let imprint_bytes = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 6])),
            tlv(4, &hash),
        ]
        .concat(),
    );
    let mut query = parser.read(&imprint_bytes, 900).unwrap();
    let element = query.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&query, &element).unwrap();
    let provider = Provider::default();
    let mut sources = [[b"object".as_slice()]];
    let mut input = ObjectInput::new(&parsed.timestamps()[0], &mut sources, Membership::Object);
    assert_eq!(
        imprint.check_input(&provider, &query, &mut input).unwrap(),
        ImprintAgreement::Matches
    );
    assert_eq!(provider.0.get(), 1);
}
