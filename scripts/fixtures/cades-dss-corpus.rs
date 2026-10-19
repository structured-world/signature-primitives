//! Public DSS CAdES corpus: archive-time-stamp-v3 coverage and imprint input,
//! decoded by structured-cms and compared with an independent DER walker.
//! No signature, trust or level verdict is made here.

use sha2::{Digest as _, Sha256, Sha512};
use std::{cell::Cell, cmp::Ordering, path::PathBuf, sync::Arc};
use structured_asn1::Parser;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_cms::archive::{
    self, HashIndex, IndexList, check_index, imprint_input, token_reader,
};
use structured_cms::timestamp::{HashAlgorithmReading, ImprintAgreement, Token};
use structured_cms::{ErrorCode, SignedData, oid};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("CADES_DSS_CORPUS").unwrap()).join(name)
}

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28)))
}

enum State {
    Sha256(Sha256),
    Sha512(Sha512),
}

/// SHA-256 and SHA-512, the algorithms these fixtures index with, counting hashes.
#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
}

impl Digest<'_> for Provider {
    type Identity = Algorithm;
    type State = State;
    type Output = Vec<u8>;
    type Error = MemoryError;

    fn width(&self, algorithm: &Algorithm) -> Option<usize> {
        Some(if *algorithm == Algorithm::Sha256 {
            32
        } else {
            64
        })
    }
    fn compare<W: Work>(
        &self,
        a: &Algorithm,
        b: &Algorithm,
        work: &W,
    ) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok((*a as u8).cmp(&(*b as u8)))
    }
    fn start<W: Work>(
        &self,
        algorithm: &Algorithm,
        work: &W,
    ) -> Result<Resolution<State>, MemoryError> {
        work.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(if *algorithm == Algorithm::Sha256 {
            State::Sha256(Sha256::new())
        } else {
            State::Sha512(Sha512::new())
        }))
    }
    fn update<W: Work>(
        &self,
        state: &mut State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(bytes.len() as u64)?;
        match state {
            State::Sha256(inner) => inner.update(bytes),
            State::Sha512(inner) => inner.update(bytes),
        }
        Ok(())
    }
    fn finish<W: Work>(&self, state: State, work: &W) -> Result<Vec<u8>, MemoryError> {
        work.charge_work(1)?;
        Ok(match state {
            State::Sha256(inner) => inner.finalize().to_vec(),
            State::Sha512(inner) => inner.finalize().to_vec(),
        })
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        output: &Vec<u8>,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(output.len() as u64)?;
        Ok(output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        matches!(algorithm, Algorithm::Sha256 | Algorithm::Sha512).then_some(algorithm)
    }
}

fn hash(algorithm: Algorithm, bytes: &[u8]) -> Vec<u8> {
    if algorithm == Algorithm::Sha256 {
        Sha256::digest(bytes).to_vec()
    } else {
        Sha512::digest(bytes).to_vec()
    }
}

fn list_name(list: IndexList) -> &'static str {
    match list {
        IndexList::Certificates => "certificates",
        IndexList::Revocations => "revocations",
        IndexList::AttributeValues => "values",
    }
}

/// Checks every archive-time-stamp-v3 of one fixture against the oracle files:
/// `ats-N-index.txt` lists the entries without an element, `ats-N-input.bin`
/// (attached content only) is the §5.5.3 imprint input.
fn check(name: &str, file: &str, tokens: usize, superseded: bool) {
    let directory = corpus(name);
    let original = std::fs::read(directory.join(file)).unwrap();
    let parser = Parser::ber(memory());
    let signed = SignedData::read(&parser, &original, 0).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let signer = &signed.signers()[0];
    let unsigned = signer.unsigned_attributes().unwrap();
    let mut seen = 0;
    for (ordinal, attribute) in unsigned
        .all_in(oid::ARCHIVE_TIMESTAMP_V3, &query)
        .enumerate()
    {
        seen = ordinal + 1;
        let mut reader = token_reader(attribute.unwrap(), &query).unwrap();
        let token = Token::read_from(&mut reader).unwrap();
        let index = HashIndex::of_token(&token, &reader);
        if superseded {
            // Only the TS 101 733 index is present: it is not read as v3.
            assert_eq!(index.unwrap_err().code(), ErrorCode::MissingField);
            continue;
        }
        let index = index.unwrap();
        let provider = Provider::default();
        let coverage = match check_index(&index, &signed, signer, &provider, &query).unwrap() {
            Resolution::Supported(coverage) => coverage,
            other => panic!("{name}: index algorithm not supported: {other:?}"),
        };
        // Each original element is hashed exactly once.
        let elements = coverage.certificates().len()
            + coverage.revocations().len()
            + coverage.attribute_values().len();
        assert_eq!(provider.starts.get(), elements, "{name}: element hashes");
        let found: Vec<String> = coverage
            .unmatched()
            .iter()
            .map(|entry| format!("{} {}", list_name(entry.list), entry.ordinal))
            .collect();
        let listed =
            std::fs::read_to_string(directory.join(format!("ats-{ordinal}-index.txt"))).unwrap();
        let expected: Vec<&str> = listed.lines().collect();
        assert_eq!(found, expected, "{name}: unmatched index entries");
        assert_eq!(coverage.is_valid(), expected.is_empty());

        let oracle_input = std::fs::read(directory.join(format!("ats-{ordinal}-input.bin")));
        let Some(content) = signed.content().content() else {
            assert!(
                oracle_input.is_err(),
                "{name}: detached content has no oracle input"
            );
            continue;
        };
        let algorithm = match structured_pkix::algorithm::digest::algorithm(
            index.algorithm(),
            &query.execution(),
        )
        .unwrap()
        {
            Resolution::Supported(algorithm) => algorithm,
            other => panic!("{name}: index algorithm unresolved: {other:?}"),
        };
        let attached = content.copy_in(&query, "eContent", 0).unwrap();
        let content_hash = hash(algorithm, &attached);
        let mut input = imprint_input(&signed, signer, &index, &content_hash);
        assert_eq!(
            input.concat(),
            oracle_input.unwrap(),
            "{name}: imprint input"
        );
        token
            .with_info(&reader, |info, scope, _| {
                let HashAlgorithmReading::Identifier(imprint) = info.imprint().algorithm() else {
                    panic!("{name}: malformed imprint algorithm");
                };
                assert_eq!(
                    archive::same_algorithm(&index, imprint, &scope.execution()).unwrap(),
                    Resolution::Supported(true)
                );
                let agreement = info
                    .imprint()
                    .check_content(&provider, scope, &mut input)
                    .unwrap();
                assert_eq!(agreement, ImprintAgreement::Matches, "{name}: imprint");
                Ok::<_, ()>(())
            })
            .unwrap();
    }
    assert_eq!(seen, tokens, "{name}: archive time-stamp census");
}

#[test]
fn a_conforming_index_and_imprint_match_the_independent_walker() {
    // Attached content: every index entry has its element and the token's
    // imprint is over exactly the §5.5.3 input the walker built.
    check("single", "cades-lta-en319122.cms", 1, false);
}

#[test]
fn an_extra_certificate_entry_invalidates_the_index() {
    // certificatesHashIndex[5] names no certificate of the root SignedData;
    // the imprint itself still matches, so only the index is at fault.
    check("wrong-certificate", "cades-ats-v3-wrong-cert.p7m", 1, false);
}

#[test]
fn an_extra_revocation_entry_invalidates_the_index() {
    // crlsHashIndex[0] names no revocation choice of the root SignedData.
    check("wrong-crl", "cades-ats-v3-wrong-crl.p7s", 1, false);
    check("wrong-ocsp", "cades-ats-v3-wrong-ocsp.p7s", 1, false);
}

#[test]
fn a_revocation_value_attribute_crl_is_not_a_crls_choice() {
    // §5.5.2 indexes the crls field of the root SignedData only; an entry over
    // a CertificateList inside revocation-values has no element there.
    check("rev-val-crl", "cades-ats-v3-rev-val-crl.p7s", 1, false);
}

#[test]
fn the_superseded_ts_101_733_index_is_not_read_as_v3() {
    // Both archive time-stamps carry only 0.4.0.1733.2.5, whose attribute
    // hashing differs from §5.5.2; reading it as v3 would misjudge coverage.
    check("superseded-double", "CAdESDoubleLTA.p7m", 2, true);
}
