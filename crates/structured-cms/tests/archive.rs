//! EN 319 122-1 §5.5 `ats-hash-index-v3` coverage and `archive-time-stamp-v3`
//! imprint input over original encodings.

use core::cmp::Ordering;
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::sync::Arc;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Parser, Reader};
use structured_cms::archive::{
    self, AttributeValue, HashIndex, IndexList, Unmatched, check_index, imprint_input,
};
use structured_cms::digest::DigestError;
use structured_cms::{ErrorCode, SignedData, oid};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    let length = contents.len();
    if length < 0x80 {
        encoded.push(u8::try_from(length).unwrap());
    } else if length < 0x100 {
        encoded.extend([0x81, u8::try_from(length).unwrap()]);
    } else {
        encoded.extend([0x82, u8::try_from(length >> 8).unwrap()]);
        encoded.push(u8::try_from(length & 0xff).unwrap());
    }
    encoded.extend_from_slice(contents);
    encoded
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut state = Sha256::new();
    for part in parts {
        state.update(part);
    }
    state.finalize().to_vec()
}

/// SHA-256 only, charging its work like a provider must, and counting hashes
/// and comparisons. `refuse` fails every comparison; `deny` answers each one
/// as differing, as a backend's own comparison strategy may.
#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    comparisons: Cell<usize>,
    refuse: bool,
    deny: bool,
}

impl Digest<'_> for Provider {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Sha256>, MemoryError> {
        work.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut Sha256,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<[u8; 32], MemoryError> {
        work.charge_work(1)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(32)?;
        self.comparisons.set(self.comparisons.get() + 1);
        if self.refuse {
            return Err(MemoryError::WorkExceeded);
        }
        Ok(!self.deny && output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}

/// Original elements of one synthetic signature, in their written encodings.
struct Fixture {
    certificates: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
    /// Each unsigned attribute's `attrType` encoding and its values.
    attributes: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    signer_fields: Vec<u8>,
    encoded: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_empty_attributes(0)
    }

    /// Adds `empty` unsigned attributes whose value sets are empty.
    fn with_empty_attributes(empty: usize) -> Self {
        let certificates = vec![
            // Version-1 attribute certificate and an other-format choice,
            // preserved as encoded without X.509 parsing.
            tlv(0xa1, &tlv(0x30, &[2, 1, 1])),
            tlv(0xa3, &[tlv(6, &[0x2a, 5]), vec![5, 0]].concat()),
        ];
        let revocations = vec![
            tlv(0xa1, &[tlv(6, &[0x2a, 6]), tlv(4, &[9])].concat()),
            tlv(0xa1, &[tlv(6, &[0x2a, 7]), tlv(4, &[10, 11])].concat()),
        ];
        let mut attributes = vec![
            (tlv(6, &[0x2a, 3]), vec![tlv(2, &[1]), tlv(2, &[2])]),
            (tlv(6, &[0x2a, 4]), vec![tlv(12, b"x")]),
        ];
        attributes.extend((0..empty).map(|_| (tlv(6, &[0x2a, 9]), Vec::new())));
        let signer_fields = [
            vec![2, 1, 3],
            vec![0x80, 1, 7],
            tlv(0x30, &tlv(6, &[0x2a])),
            tlv(0x30, &tlv(6, &[0x2b])),
            tlv(4, &[8]),
        ]
        .concat();
        let unsigned = attributes
            .iter()
            .map(|(kind, values)| tlv(0x30, &[kind.clone(), tlv(0x31, &values.concat())].concat()))
            .collect::<Vec<_>>()
            .concat();
        let signer = tlv(
            0x30,
            &[signer_fields.clone(), tlv(0xa1, &unsigned)].concat(),
        );
        let mut inside = vec![2, 1, 5, 0x31, 0];
        inside.extend(tlv(0x30, &tlv(6, oid::DATA.as_bytes())));
        inside.extend(tlv(0xa0, &certificates.concat()));
        inside.extend(tlv(0xa1, &revocations.concat()));
        inside.extend(tlv(0x31, &signer));
        let envelope = [
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &inside)),
        ]
        .concat();
        Self {
            certificates,
            revocations,
            attributes,
            signer_fields,
            encoded: tlv(0x30, &envelope),
        }
    }

    fn certificate_hashes(&self) -> Vec<Vec<u8>> {
        self.certificates
            .iter()
            .map(|element| sha256(&[element]))
            .collect()
    }
    fn revocation_hashes(&self) -> Vec<Vec<u8>> {
        self.revocations
            .iter()
            .map(|element| sha256(&[element]))
            .collect()
    }
    fn value_hashes(&self) -> Vec<Vec<u8>> {
        self.attributes
            .iter()
            .flat_map(|(kind, values)| values.iter().map(move |value| sha256(&[kind, value])))
            .collect()
    }
}

fn index(algorithm: &[u8], lists: [&[Vec<u8>]; 3]) -> Vec<u8> {
    let mut fields = tlv(0x30, &tlv(6, algorithm));
    for list in lists {
        let entries = list
            .iter()
            .map(|hash| tlv(4, hash))
            .collect::<Vec<_>>()
            .concat();
        fields.extend(tlv(0x30, &entries));
    }
    tlv(0x30, &fields)
}

fn read_index<'a>(parser: &'a Parser, encoded: &'a [u8]) -> structured_cms::Result<HashIndex<'a>> {
    let mut reader = parser.read(encoded, 900).unwrap();
    let value = reader.next_element().unwrap().unwrap();
    HashIndex::read(&reader, &value)
}

type Coverage = Result<Resolution<archive::IndexCoverage>, DigestError<MemoryError>>;

/// Parses with one parser, then leaves exactly `work` units for the check, so
/// a ceiling measures the check alone. Returns the result and the work used.
fn coverage_measured(fixture: &Fixture, encoded_index: &[u8], work: usize) -> (Coverage, usize) {
    // Parsing is paid from the margin above `work`.
    let account = memory(work + 100_000);
    let parser = Parser::ber(account.clone());
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let index = read_index(&parser, encoded_index).unwrap();
    let query: Reader<'_> = parser.read(&[], 0).unwrap();
    account
        .charge_work((account.work_remaining() - work) as u64)
        .unwrap();
    let before = account.work_used();
    let provider = Provider::default();
    let result = check_index(&index, &message, &message.signers()[0], &provider, &query);
    // A completed check hashes each original element exactly once, however
    // many entries name it; an unresolved algorithm hashes nothing.
    match &result {
        Ok(Resolution::Supported(_)) => assert_eq!(provider.starts.get(), 7),
        Ok(_) => assert_eq!(provider.starts.get(), 0),
        Err(_) => {}
    }
    (result, account.work_used() - before)
}

fn coverage(fixture: &Fixture, encoded_index: &[u8], work: usize) -> Coverage {
    coverage_measured(fixture, encoded_index, work).0
}

fn supported(result: Resolution<archive::IndexCoverage>) -> archive::IndexCoverage {
    match result {
        Resolution::Supported(coverage) => coverage,
        other => panic!("index algorithm not answered as supported: {other:?}"),
    }
}

#[test]
fn a_complete_index_protects_every_original_element() {
    // §5.5.2: every certificate, revocation and unsigned attribute value present
    // when the time-stamp was requested has its hash in the index.
    let fixture = Fixture::new();
    let encoded = index(
        SHA256_OID,
        [
            &fixture.certificate_hashes(),
            &fixture.revocation_hashes(),
            &fixture.value_hashes(),
        ],
    );
    let coverage = supported(coverage(&fixture, &encoded, 1_000_000).unwrap());
    assert!(coverage.is_valid());
    assert_eq!(coverage.certificates(), &[true, true]);
    assert_eq!(coverage.revocations(), &[true, true]);
    let values = coverage.attribute_values();
    assert_eq!(values.len(), 3);
    assert!(values.iter().all(|(_, covered)| *covered));
    assert_eq!(
        values[2].0,
        AttributeValue {
            attribute: 1,
            value: 0
        }
    );
}

#[test]
fn an_element_added_after_the_timestamp_is_unprotected_not_invalid() {
    // §5.5.2 NOTE 5: certificates, revocation values and unsigned attributes
    // may be added after an archive time-stamp without invalidating it; they
    // are simply not covered by that time-stamp.
    let fixture = Fixture::new();
    let values = fixture.value_hashes();
    let encoded = index(
        SHA256_OID,
        [&fixture.certificate_hashes()[..1], &[], &values[..2]],
    );
    let coverage = supported(coverage(&fixture, &encoded, 1_000_000).unwrap());
    assert!(coverage.is_valid());
    assert_eq!(coverage.certificates(), &[true, false]);
    assert_eq!(coverage.revocations(), &[false, false]);
    let covered: Vec<bool> = coverage
        .attribute_values()
        .iter()
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(covered, [true, true, false]);
}

#[test]
fn an_entry_without_its_element_invalidates_the_index() {
    // §5.5.2: an entry that corresponds to no original element makes the
    // ats-hash-index-v3 invalid, whichever list holds it.
    let fixture = Fixture::new();
    let foreign = sha256(&[b"not in this signature"]);
    let mut certificates = fixture.certificate_hashes();
    certificates.push(foreign.clone());
    let mut values = fixture.value_hashes();
    values.insert(1, foreign);
    let encoded = index(
        SHA256_OID,
        [&certificates, &fixture.revocation_hashes(), &values],
    );
    let coverage = supported(coverage(&fixture, &encoded, 1_000_000).unwrap());
    assert!(!coverage.is_valid());
    assert_eq!(
        coverage.unmatched(),
        &[
            Unmatched {
                list: IndexList::Certificates,
                ordinal: 2
            },
            Unmatched {
                list: IndexList::AttributeValues,
                ordinal: 1
            },
        ]
    );
    // The real elements are still reported as covered.
    assert_eq!(coverage.certificates(), &[true, true]);
}

#[test]
fn entries_match_in_any_written_order() {
    // §5.5.2 lists the hashes per element without requiring the element order.
    let fixture = Fixture::new();
    let mut certificates = fixture.certificate_hashes();
    certificates.reverse();
    let mut values = fixture.value_hashes();
    values.rotate_left(1);
    let encoded = index(
        SHA256_OID,
        [&certificates, &fixture.revocation_hashes(), &values],
    );
    let coverage = supported(coverage(&fixture, &encoded, 1_000_000).unwrap());
    assert!(coverage.is_valid());
    assert!(
        coverage
            .attribute_values()
            .iter()
            .all(|(_, covered)| *covered)
    );
}

#[test]
fn a_hash_over_another_encoding_of_the_same_value_does_not_match() {
    // §5.5.2: hashes cover the entire encoded component; a BER long-form
    // length of the same certificate choice is another octet string.
    let fixture = Fixture::new();
    let mut certificates = fixture.certificate_hashes();
    let original = &fixture.certificates[0];
    let mut respelled = vec![original[0], 0x81];
    respelled.extend_from_slice(&original[1..]);
    certificates[0] = sha256(&[&respelled]);
    // The value alone, without its attrType, is not the §5.5.2 octet stream.
    let mut values = fixture.value_hashes();
    values[0] = sha256(&[&fixture.attributes[0].1[0]]);
    let encoded = index(
        SHA256_OID,
        [&certificates, &fixture.revocation_hashes(), &values],
    );
    let coverage = supported(coverage(&fixture, &encoded, 1_000_000).unwrap());
    assert_eq!(
        coverage.unmatched(),
        &[
            Unmatched {
                list: IndexList::Certificates,
                ordinal: 0
            },
            Unmatched {
                list: IndexList::AttributeValues,
                ordinal: 0
            },
        ]
    );
    assert_eq!(coverage.certificates(), &[false, true]);
}

#[test]
fn an_unknown_index_algorithm_is_answered_not_guessed() {
    // The provider cannot hash with SHA-384 here; nothing is hashed or matched.
    let fixture = Fixture::new();
    let encoded = index(SHA384_OID, [&[], &[], &[]]);
    assert!(matches!(
        coverage(&fixture, &encoded, 1_000_000).unwrap(),
        Resolution::Unsupported
    ));
    // Parameters other than NULL make a known identifier malformed.
    let mut malformed = tlv(0x30, &[tlv(6, SHA256_OID), tlv(2, &[1])].concat());
    for _ in 0..3 {
        malformed.extend(tlv(0x30, &[]));
    }
    let encoded = tlv(0x30, &malformed);
    assert!(matches!(
        coverage(&fixture, &encoded, 1_000_000).unwrap(),
        Resolution::Malformed
    ));
}

#[test]
fn a_foreign_reader_is_refused_before_hashing() {
    // The producing parser's ceilings fund every hash and comparison; another
    // parser's account cannot stand in for them.
    let fixture = Fixture::new();
    let parser = Parser::ber(memory(1_000_000));
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let encoded = index(SHA256_OID, [&fixture.certificate_hashes(), &[], &[]]);
    let index = read_index(&parser, &encoded).unwrap();
    let foreign = Parser::ber(memory(1_000_000));
    let other = foreign.read(&[], 0).unwrap();
    let provider = Provider::default();
    match check_index(&index, &message, &message.signers()[0], &provider, &other) {
        Err(DigestError::Processing(error)) => assert_eq!(
            error.code(),
            ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
        ),
        other => panic!("foreign reader was not refused: {other:?}"),
    }
    assert_eq!(provider.starts.get(), 0);
}

#[test]
fn the_signer_must_belong_to_the_checked_message() {
    // Coverage and imprint input name one SignerInfo of one root SignedData
    // (§5.5.1); a message from another parser, or another document of the
    // same parser, would yield a result about neither.
    let fixture = Fixture::new();
    let parser = Parser::ber(memory(1_000_000));
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let copy = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let encoded = index(SHA256_OID, [&fixture.certificate_hashes(), &[], &[]]);
    let index = read_index(&parser, &encoded).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let foreign = Parser::ber(memory(1_000_000));
    let elsewhere = SignedData::read(&foreign, &fixture.encoded, 0).unwrap();
    let signer = &message.signers()[0];
    for (other, code) in [
        (
            &elsewhere,
            ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader),
        ),
        (&copy, ErrorCode::InvalidLocation),
    ] {
        let provider = Provider::default();
        match check_index(&index, other, signer, &provider, &query) {
            Err(DigestError::Processing(error)) => assert_eq!(error.code(), code),
            result => panic!("a mismatched message was not refused: {result:?}"),
        }
        assert_eq!(provider.starts.get(), 0);
        // Without a reader, both mismatches are a signer outside the message.
        assert_eq!(
            imprint_input(other, signer, &index, &[])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidLocation
        );
    }
    assert!(imprint_input(&message, signer, &index, &[]).is_ok());
}

#[test]
fn every_entry_is_judged_by_the_provider_comparison() {
    // Digest::matches applies the backend's comparison strategy and may fail;
    // each entry gets exactly one comparison, and its answer and failure stand.
    let fixture = Fixture::new();
    let encoded = index(
        SHA256_OID,
        [
            &fixture.certificate_hashes(),
            &fixture.revocation_hashes(),
            &fixture.value_hashes(),
        ],
    );
    let parser = Parser::ber(memory(1_000_000));
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let index = read_index(&parser, &encoded).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let signer = &message.signers()[0];

    let provider = Provider::default();
    assert!(
        supported(check_index(&index, &message, signer, &provider, &query).unwrap()).is_valid()
    );
    assert_eq!(provider.comparisons.get(), 7);

    let denying = Provider {
        deny: true,
        ..Provider::default()
    };
    let coverage = supported(check_index(&index, &message, signer, &denying, &query).unwrap());
    assert_eq!(coverage.unmatched().len(), 7);
    assert_eq!(coverage.certificates(), &[false, false]);

    let refusing = Provider {
        refuse: true,
        ..Provider::default()
    };
    assert!(matches!(
        check_index(&index, &message, signer, &refusing, &query),
        Err(DigestError::Callback(MemoryError::WorkExceeded))
    ));
}

#[test]
fn every_unsigned_attribute_scanned_is_paid_for() {
    // Attributes with empty value sets are never hashed, yet scanning them is
    // work: a signer with many of them must cost more than one without.
    let used = |fixture: &Fixture| {
        let account = memory(1_000_000);
        let parser = Parser::ber(account.clone());
        let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
        let encoded = index(SHA256_OID, [&[], &[], &[]]);
        let index = read_index(&parser, &encoded).unwrap();
        let query = parser.read(&[], 0).unwrap();
        let before = account.work_used();
        let provider = Provider::default();
        check_index(&index, &message, &message.signers()[0], &provider, &query).unwrap();
        account.work_used() - before
    };
    let plain = used(&Fixture::new());
    let padded = used(&Fixture::with_empty_attributes(50));
    assert!(
        padded >= plain + 50,
        "{padded} work for 50 more attributes, {plain} without"
    );
}

#[test]
fn an_entry_after_every_hash_still_reaches_the_provider() {
    // Ordered after every computed hash, the entry is judged against the last
    // one, so the provider's answer or failure stands instead of `false`.
    let fixture = Fixture::new();
    let encoded = index(SHA256_OID, [&[vec![0xff; 32]], &[], &[]]);
    let parser = Parser::ber(memory(1_000_000));
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let after = read_index(&parser, &encoded).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let signer = &message.signers()[0];
    let refusing = Provider {
        refuse: true,
        ..Provider::default()
    };
    assert!(matches!(
        check_index(&after, &message, signer, &refusing, &query),
        Err(DigestError::Callback(MemoryError::WorkExceeded))
    ));
    let provider = Provider::default();
    let coverage = supported(check_index(&after, &message, signer, &provider, &query).unwrap());
    assert_eq!(coverage.unmatched().len(), 1);
    assert_eq!(provider.comparisons.get(), 1);
}

#[test]
fn a_zero_sized_provider_is_refused_before_hashing() {
    // Distinct zero-sized providers may share an address, so like every other
    // provider-driven check this one refuses them before any work.
    struct Unit;
    impl Digest<'_> for Unit {
        type Identity = ();
        type State = Sha256;
        type Output = [u8; 32];
        type Error = MemoryError;
        fn width(&self, (): &()) -> Option<usize> {
            Some(32)
        }
        fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
            Ok(Ordering::Equal)
        }
        fn start<W: Work>(&self, (): &(), _: &W) -> Result<Resolution<Sha256>, MemoryError> {
            panic!("a refused provider must not be started")
        }
        fn update<W: Work>(&self, _: &mut Sha256, _: &[u8], _: &W) -> Result<(), MemoryError> {
            unreachable!()
        }
        fn finish<W: Work>(&self, _: Sha256, _: &W) -> Result<[u8; 32], MemoryError> {
            unreachable!()
        }
        fn matches<W: Work>(
            &self,
            (): &(),
            _: &[u8; 32],
            _: &[u8],
            _: &W,
        ) -> Result<bool, MemoryError> {
            unreachable!()
        }
    }
    impl AsnDigest<'_> for Unit {
        fn identity(&self, _: Algorithm) -> Option<()> {
            Some(())
        }
    }
    let fixture = Fixture::new();
    let parser = Parser::ber(memory(1_000_000));
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let encoded = index(SHA256_OID, [&fixture.certificate_hashes(), &[], &[]]);
    let index = read_index(&parser, &encoded).unwrap();
    let query = parser.read(&[], 0).unwrap();
    match check_index(&index, &message, &message.signers()[0], &Unit, &query) {
        Err(DigestError::Processing(error)) => {
            assert_eq!(error.code(), ErrorCode::ProviderMismatch);
        }
        other => panic!("zero-sized provider was not refused: {other:?}"),
    }
}

#[test]
fn a_malformed_index_value_is_refused() {
    // Annex D: four fields, hashIndAlgorithm without DEFAULT, OCTET STRING
    // entries, DER encoding (§5.5.2).
    let parser = Parser::der(memory(1_000_000));
    let three = tlv(
        0x30,
        &[tlv(0x30, &[]), tlv(0x30, &[]), tlv(0x30, &[])].concat(),
    );
    assert!(read_index(&parser, &three).is_err());
    let integer_entry = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, SHA256_OID)),
            tlv(0x30, &tlv(2, &[1])),
            tlv(0x30, &[]),
            tlv(0x30, &[]),
        ]
        .concat(),
    );
    assert_eq!(
        read_index(&parser, &integer_entry).unwrap_err().code(),
        ErrorCode::UnexpectedTag
    );
    let mut trailing = vec![tlv(0x30, &tlv(6, SHA256_OID))];
    trailing.extend([
        tlv(0x30, &[]),
        tlv(0x30, &[]),
        tlv(0x30, &[]),
        tlv(0x30, &[]),
    ]);
    let trailing = tlv(0x30, &trailing.concat());
    assert_eq!(
        read_index(&parser, &trailing).unwrap_err().code(),
        ErrorCode::TrailingData
    );
    // The same index with a non-minimal length is not DER.
    let good = index(SHA256_OID, [&[], &[], &[]]);
    let mut long = vec![0x30, 0x81];
    long.extend_from_slice(&good[1..]);
    let ber = Parser::ber(memory(1_000_000));
    let mut reader = ber.read(&long, 0).unwrap();
    let value = reader.next_element().unwrap().unwrap();
    assert!(HashIndex::read(&reader, &value).is_err());
}

#[test]
fn a_spent_work_ceiling_refuses_the_whole_check() {
    // Every hash and comparison is paid before it runs; a ceiling below the
    // whole check is a resource refusal, never a partial coverage.
    let fixture = Fixture::new();
    let encoded = index(
        SHA256_OID,
        [
            &fixture.certificate_hashes(),
            &fixture.revocation_hashes(),
            &fixture.value_hashes(),
        ],
    );
    let (result, total) = coverage_measured(&fixture, &encoded, 500_000);
    assert!(supported(result.unwrap()).is_valid());
    // Exactly the measured work completes the same check again.
    assert!(coverage(&fixture, &encoded, total).is_ok());
    match coverage(&fixture, &encoded, total - 1) {
        Err(DigestError::Processing(error)) => assert!(error.is_resource()),
        Err(DigestError::Callback(MemoryError::WorkExceeded)) => {}
        other => panic!("one unit below the whole check was not refused: {other:?}"),
    }
}

#[test]
fn the_imprint_input_is_the_four_original_ranges_in_order() {
    // §5.5.3 steps 1-4: eContentType, the content hash, version through
    // signature of the archived signer, and the ATSHashIndexV3 value.
    let fixture = Fixture::new();
    let account = memory(1_000_000);
    let parser = Parser::ber(account.clone());
    let message = SignedData::read(&parser, &fixture.encoded, 0).unwrap();
    let signer = &message.signers()[0];
    assert_eq!(signer.signed_fields(), fixture.signer_fields.as_slice());
    let encoded = index(SHA256_OID, [&[], &[], &[]]);
    let index_parser = Parser::der(account.clone());
    let index = read_index(&index_parser, &encoded).unwrap();
    let content = sha256(&[b"content"]);
    let input = imprint_input(&message, signer, &index, &content).unwrap();
    assert_eq!(input[0], tlv(6, oid::DATA.as_bytes()).as_slice());
    assert_eq!(input[1], content.as_slice());
    assert_eq!(input[2], fixture.signer_fields.as_slice());
    assert_eq!(input[3], encoded.as_slice());
    // The attribute type encoding keeps its tag and length.
    let attributes = signer.unsigned_attributes().unwrap().items();
    assert_eq!(
        attributes[1].kind_encoding(),
        fixture.attributes[1].0.as_slice()
    );
}

#[test]
fn the_index_algorithm_must_be_the_imprint_algorithm() {
    // §5.5.2: hashIndAlgorithm is the algorithm of the time-stamp's imprint.
    let account = memory(1_000_000);
    let parser = Parser::der(account.clone());
    let encoded = index(SHA256_OID, [&[], &[], &[]]);
    let index = read_index(&parser, &encoded).unwrap();
    for (imprint, expected) in [(SHA256_OID, true), (SHA384_OID, false)] {
        let identifier = tlv(0x30, &tlv(6, imprint));
        let mut reader = parser.read(&identifier, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let algorithm =
            structured_pkix::algorithm::read(&reader, &element, "messageImprint").unwrap();
        assert_eq!(
            archive::same_algorithm(&index, &algorithm, &account).unwrap(),
            Resolution::Supported(expected)
        );
    }
}

#[test]
fn archive_algorithm_comparison_keeps_both_original_source_limits() {
    // Each retained operand owns a different parser. A fresh current account
    // must not repair either spent source or turn refusal into a mismatch.
    for (exhaust_index, exhaust_imprint) in [(false, false), (true, false), (false, true)] {
        let limits = structured_asn1::Limits {
            max_work: 100_000,
            ..structured_asn1::Limits::default()
        };
        let source = Parser::new(structured_asn1::Encoding::Der, limits, memory(1_000_000));
        let imprint_source = Parser::new(structured_asn1::Encoding::Der, limits, memory(1_000_000));
        let encoded = index(SHA256_OID, [&[], &[], &[]]);
        let index = read_index(&source, &encoded).unwrap();
        let encoded_imprint = tlv(0x30, &tlv(6, SHA256_OID));
        let mut reader = imprint_source.read(&encoded_imprint, 1700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let algorithm = structured_pkix::algorithm::read(&reader, &element, "imprint").unwrap();
        for (parser, exhaust) in [(&source, exhaust_index), (&imprint_source, exhaust_imprint)] {
            if exhaust {
                let work = parser.execution_in(parser.memory());
                work.charge_work(work.work_remaining() as u64).unwrap();
            }
        }
        let current = memory(100);
        let result = archive::same_algorithm(&index, &algorithm, &current);
        if !exhaust_index && !exhaust_imprint {
            assert_eq!(result.unwrap(), Resolution::Supported(true));
            assert_eq!(current.work_used(), 20);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            if exhaust_index {
                assert_eq!(
                    (error.field(), error.offset()),
                    ("atsHashIndexV3.hashIndAlgorithm", 902)
                );
                assert_eq!(current.work_used(), 0);
            } else {
                assert_eq!((error.field(), error.offset()), ("imprint", 1700));
                assert_eq!(current.work_used(), 10);
            }
        }
        assert_eq!(current.used(), 0);
    }
}
