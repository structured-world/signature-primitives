//! Independent SHA256 computations exercise the complete reduced-tree recipe.

use super::{algorithm, memory, record, stamp, tlv};
use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest as _, Sha256};
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
struct Provider {
    starts: Cell<usize>,
    short: bool,
}
impl Digest<'_> for Provider {
    type Identity = Algorithm;
    type State = Sha256;
    type Output = Vec<u8>;
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
    fn start<W: Work>(&self, _: &Algorithm, w: &W) -> Result<Resolution<Sha256>, MemoryError> {
        w.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], w: &W) -> Result<(), MemoryError> {
        w.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, w: &W) -> Result<Vec<u8>, MemoryError> {
        // Test oracle only, not a production allocation-accounting claim.
        w.charge_work(32)?;
        let mut bytes = state.finalize().to_vec();
        if self.short {
            bytes.pop();
        }
        Ok(bytes)
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        output: &Vec<u8>,
        expected: &[u8],
        w: &W,
    ) -> Result<bool, MemoryError> {
        w.charge_work(expected.len() as u64)?;
        Ok(output == expected)
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        if algorithm == Algorithm::Sha256 {
            Some(algorithm)
        } else {
            None
        }
    }
}
fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn branch(mut hashes: Vec<Vec<u8>>) -> Vec<u8> {
    hashes.sort();
    digest(&hashes.concat())
}

#[test]
fn real_sha256_tree_inserts_computed_child_and_keeps_source_single_pass() {
    // The higher list omits its computed child. Requiring it in the encoding
    // or double-hashing the object/leaf rejects this independent RFC4.2 vector.
    let a = digest(b"A");
    let b = digest(b"B");
    let c = digest(b"C");
    let root = branch(vec![branch(vec![a.clone(), b.clone()]), c.clone()]);
    for group in [false, true] {
        let first = tlv(0x30, &[tlv(4, &b), tlv(4, &a)].concat());
        let second = tlv(0x30, &tlv(4, &c));
        let encoded = record(
            1,
            &algorithm(0x30),
            &tlv(0x30, &stamp(Some(&[first, second].concat()))),
        );
        let imprint = tlv(0x30, &[algorithm(0x30), tlv(4, &root)].concat());
        let parser = Parser::ber(memory(1_000_000));
        let mut parent = parser.read(&encoded, 900).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parsed = EvidenceRecord::read(&parent, &element).unwrap();
        let mut query = parser.read(&imprint, 1500).unwrap();
        let element = query.next_element().unwrap().unwrap();
        let imprint = MessageImprint::read(&query, &element).unwrap();
        let mut sources = vec![[b"A".as_slice()]];
        if group {
            sources.push([b"B".as_slice()]);
        }
        let mut input = ObjectInput::new(
            &parsed.timestamps()[0],
            &mut sources,
            if group {
                Membership::Group
            } else {
                Membership::Object
            },
        );
        assert_eq!(
            imprint
                .check_input(&Provider::default(), &query, &mut input)
                .unwrap(),
            ImprintAgreement::Matches
        );
    }
}

#[test]
fn singleton_tree_preserves_finished_leaf_without_second_hash() {
    // A one-leaf tree has the object hash as root, not H(H(object)).
    let hash = digest(b"one");
    let encoded = record(
        1,
        &algorithm(0x30),
        &tlv(0x30, &stamp(Some(&tlv(0x30, &tlv(4, &hash))))),
    );
    let imprint = tlv(0x30, &[algorithm(0x30), tlv(4, &hash)].concat());
    let parser = Parser::ber(memory(1_000_000));
    let mut parent = parser.read(&encoded, 0).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let mut query = parser.read(&imprint, 2000).unwrap();
    let element = query.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&query, &element).unwrap();
    let provider = Provider::default();
    let mut sources = [[b"one".as_slice()]];
    let mut input = ObjectInput::new(&parsed.timestamps()[0], &mut sources, Membership::Object);
    assert_eq!(
        imprint.check_input(&provider, &query, &mut input).unwrap(),
        ImprintAgreement::Matches
    );
    assert_eq!(provider.starts.get(), 1);
}

#[test]
fn missing_member_extra_group_member_and_wrong_width_never_match() {
    // A matching root is insufficient without first-list membership; exact
    // group matching must not silently accept a subset or collapse duplicates.
    for mode in 0..4 {
        let a = digest(b"A");
        let b = if mode == 3 { vec![1; 31] } else { digest(b"B") };
        let root = branch(vec![a.clone(), b.clone()]);
        let encoded = record(
            1,
            &algorithm(0x30),
            &tlv(
                0x30,
                &stamp(Some(&tlv(0x30, &[tlv(4, &a), tlv(4, &b)].concat()))),
            ),
        );
        let imprint = tlv(0x30, &[algorithm(0x30), tlv(4, &root)].concat());
        let parser = Parser::ber(memory(1_000_000));
        let mut parent = parser.read(&encoded, 0).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parsed = EvidenceRecord::read(&parent, &element).unwrap();
        let mut query = parser.read(&imprint, 2000).unwrap();
        let element = query.next_element().unwrap().unwrap();
        let imprint = MessageImprint::read(&query, &element).unwrap();
        let provider = Provider::default();
        let mut sources = vec![[if mode == 0 {
            b"absent".as_slice()
        } else {
            b"A".as_slice()
        }]];
        if mode == 2 {
            sources.push([b"A".as_slice()]);
        }
        let mut input = ObjectInput::new(
            &parsed.timestamps()[0],
            &mut sources,
            if mode == 0 || mode == 3 {
                Membership::Object
            } else {
                Membership::Group
            },
        );
        assert!(imprint.check_input(&provider, &query, &mut input).is_err());
        if mode == 3 {
            assert_eq!(provider.starts.get(), 0);
        }
    }
}
