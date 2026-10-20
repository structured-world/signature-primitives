//! One ASN.1 digest resolver for OCSP and CMS: parameters read under their
//! document's encoding, known identifiers kept apart from unknown ones, and a
//! spent ceiling kept apart from both.

use std::sync::Arc;
use std::{cell::Cell, cmp::Ordering};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Parser, Tag, universal};
use structured_pkix::algorithm::digest::{self, Algorithm, AsnDigest};
use structured_pkix::algorithm::{self, AlgorithmIdentifier};

const SHA256_OID: [u8; 11] = [6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 16, work)))
}

fn identifier(parameters: &[u8]) -> Vec<u8> {
    let mut contents = SHA256_OID.to_vec();
    contents.extend_from_slice(parameters);
    let mut der = vec![0x30, u8::try_from(contents.len()).unwrap()];
    der.extend(contents);
    der
}

fn read<'a>(parser: &'a Parser, bytes: &'a [u8]) -> AlgorithmIdentifier<'a> {
    let mut reader = parser.read(bytes, 0).unwrap();
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    algorithm::read(&reader, &element, "digestAlgorithm").unwrap()
}

fn ber() -> Parser {
    Parser::new(Encoding::Ber, Limits::default(), memory(1 << 20))
}

fn resolved(parser: &Parser, bytes: &[u8]) -> Resolution<Algorithm> {
    digest::algorithm(&read(parser, bytes), &memory(64)).unwrap()
}

#[test]
fn absent_and_null_parameters_both_mean_none() {
    // RFC 8017 Appendix B.1 / RFC 5754 §2: absent or NULL.
    let der = Parser::der(memory(1 << 20));
    for bytes in [identifier(&[]), identifier(&[5, 0])] {
        assert_eq!(
            resolved(&der, &bytes),
            Resolution::Supported(Algorithm::Sha256)
        );
    }
}

#[test]
fn a_ber_null_with_a_long_form_length_is_null_not_malformed() {
    // A signed message is BER (RFC 5652 §1). Its NULL may spell the zero
    // length in long form; comparing against the DER bytes `05 00` would
    // report a conforming SHA-256 identifier as malformed.
    let ber = ber();
    assert_eq!(
        resolved(&ber, &identifier(&[5, 0x81, 0])),
        Resolution::Supported(Algorithm::Sha256)
    );
}

#[test]
fn any_other_parameter_of_a_known_identifier_is_malformed() {
    // An INTEGER where SHA-256 takes nothing says something the identifier
    // does not mean; it is neither SHA-256 nor an unknown algorithm.
    let der = Parser::der(memory(1 << 20));
    assert_eq!(
        resolved(&der, &identifier(&[2, 1, 0])),
        Resolution::Malformed
    );
}

#[test]
fn an_unknown_identifier_is_unsupported_whatever_its_parameters() {
    // Parameters of an identifier the table does not know are not judged.
    let der = Parser::der(memory(1 << 20));
    let bytes = [0x30, 0x06, 6, 1, 0x2a, 2, 1, 0];
    assert_eq!(resolved(&der, &bytes), Resolution::Unsupported);
}

#[test]
fn sha3_identifiers_require_absent_parameters_even_in_ber() {
    // RFC 9688 §2 forbids NULL for these digest identifiers. This is an
    // algorithm rule, so accepting BER does not relax it to the SHA-2 rule.
    for encoding in [Encoding::Der, Encoding::Ber] {
        let parser = Parser::new(encoding, Limits::default(), memory(1 << 20));
        for tail in 7..=10 {
            for parameters in [&[][..], &[5, 0][..], &[2, 1, 0][..]] {
                let mut bytes = identifier(parameters);
                bytes[12] = tail;
                let reading = read(&parser, &bytes);
                let work = Memory::new(Arc::new(MemoryAccount::new(0, 10)));
                let outcome = digest::algorithm(&reading, &work).unwrap();
                if parameters.is_empty() {
                    assert!(matches!(outcome, Resolution::Supported(_)), "tail {tail}");
                } else {
                    assert_eq!(outcome, Resolution::Malformed);
                }
                assert_eq!(work.work_used(), 10);
                assert_eq!(work.used(), 0);
            }
            if encoding == Encoding::Ber {
                let mut bytes = identifier(&[5, 0x81, 0]);
                bytes[12] = tail;
                assert_eq!(resolved(&parser, &bytes), Resolution::Malformed);
            }
        }
    }
}

#[test]
fn sha3_resolution_honors_the_producing_local_ceiling_and_location() {
    // Once parsing has finished, the same execution still owns query work.
    // Exhausting its local ceiling must refuse before comparison even when
    // aggregate work and storage remain available.
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1000,
            ..Limits::default()
        },
        memory(1 << 20),
    );
    let mut bytes = identifier(&[]);
    bytes[12] = 8;
    let mut reader = parser.read(&bytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = algorithm::read(&reader, &element, "sha3").unwrap();
    let execution = reader.execution();
    assert_eq!(
        digest::algorithm(&reading, &execution).unwrap(),
        Resolution::Supported(Algorithm::Sha3_256)
    );
    // Consume only the remaining local allowance; the final failed unit must
    // not be charged, nor turned into a semantic resolution.
    while execution.charge_work(1).is_ok() {}
    let error = digest::algorithm(&reading, &execution).unwrap_err();
    assert!(error.is_resource());
    assert_eq!((error.field(), error.offset()), ("sha3", 700));
    assert!(parser.memory().work_remaining() > 0);
}

#[test]
fn every_algorithm_resolves_from_its_own_identifier() {
    // The table is the identifiers' own bytes; each resolves to itself and
    // carries its FIPS 180-4 output width.
    let der = Parser::der(memory(1 << 20));
    for (algorithm, width) in [
        (Algorithm::Sha1, 20),
        (Algorithm::Sha224, 28),
        (Algorithm::Sha256, 32),
        (Algorithm::Sha384, 48),
        (Algorithm::Sha512, 64),
        (Algorithm::Sha512_224, 28),
        (Algorithm::Sha512_256, 32),
        (Algorithm::Sha3_224, 28),
        (Algorithm::Sha3_256, 32),
        (Algorithm::Sha3_384, 48),
        (Algorithm::Sha3_512, 64),
    ] {
        let oid = algorithm.identifier();
        let mut contents = vec![6, u8::try_from(oid.as_bytes().len()).unwrap()];
        contents.extend_from_slice(oid.as_bytes());
        let mut bytes = vec![0x30, u8::try_from(contents.len()).unwrap()];
        bytes.extend(contents);
        assert_eq!(resolved(&der, &bytes), Resolution::Supported(algorithm));
        assert_eq!(algorithm.width(), width);
    }
}

#[test]
fn resolution_costs_one_pass_over_the_written_identifier() {
    // An unknown OID sharing the SHA-2 prefix is the costliest input: it is
    // decided in one pass, paid as its length plus one, and one unit less is
    // refused before any comparison.
    let der = Parser::der(memory(1 << 20));
    let bytes = [0x30, 11, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 0x7f];
    let unknown = read(&der, &bytes);
    let exact = memory(10);
    assert_eq!(
        digest::algorithm(&unknown, &exact).unwrap(),
        Resolution::Unsupported
    );
    assert_eq!(exact.work_used(), 10);
    assert!(
        digest::algorithm(&unknown, &memory(9))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn a_spent_ceiling_is_an_error_never_a_resolution() {
    // Running out of work is a refusal to finish, located at the identifier.
    let der = Parser::der(memory(1 << 20));
    let bytes = identifier(&[]);
    let error = digest::algorithm(&read(&der, &bytes), &memory(0)).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "digestAlgorithm");
    assert_eq!(error.offset(), 0);
}

/// Implements only SHA-256, to show the provider's own refusal.
#[derive(Default)]
struct OnlySha256 {
    identities: Cell<usize>,
}

impl Digest<'_> for OnlySha256 {
    type Identity = Algorithm;
    type State = ();
    type Output = [u8; 0];
    type Error = MemoryError;
    fn width(&self, identity: &Algorithm) -> Option<usize> {
        Some(identity.width())
    }
    fn compare<W: Work>(
        &self,
        l: &Algorithm,
        r: &Algorithm,
        _: &W,
    ) -> Result<Ordering, MemoryError> {
        Ok(l.cmp(r))
    }
    fn start<W: Work>(&self, _: &Algorithm, _: &W) -> Result<Resolution<()>, MemoryError> {
        Ok(Resolution::Unsupported)
    }
    fn update<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), MemoryError> {
        Ok(())
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 0], MemoryError> {
        Ok([])
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        _: &[u8; 0],
        _: &[u8],
        _: &W,
    ) -> Result<bool, MemoryError> {
        Ok(false)
    }
}

impl AsnDigest<'_> for OnlySha256 {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        self.identities.set(self.identities.get() + 1);
        (algorithm == Algorithm::Sha256).then_some(algorithm)
    }
}

#[test]
fn the_provider_decides_which_known_algorithms_it_implements() {
    // A known identifier the provider refuses is unsupported; a malformed one
    // stays malformed before the provider is asked.
    let der = Parser::der(memory(1 << 20));
    let execution = memory(64);
    let provider = OnlySha256::default();
    let sha256 = identifier(&[]);
    let malformed = identifier(&[2, 1, 0]);
    assert_eq!(
        digest::resolve(&provider, &read(&der, &sha256), &execution).unwrap(),
        Resolution::Supported(Algorithm::Sha256)
    );
    assert_eq!(
        digest::resolve(&provider, &read(&der, &malformed), &execution).unwrap(),
        Resolution::Malformed
    );
    assert_eq!(
        digest::supported(&provider, Algorithm::Sha1),
        Resolution::Unsupported
    );
}

#[test]
fn identifier_equality_treats_a_ber_null_as_absent_parameters() {
    // `has_no_parameters` and `matches` follow the same rule as resolution:
    // a long-form BER NULL is still NULL.
    let ber = ber();
    let long_null = identifier(&[5, 0x81, 0]);
    let absent = identifier(&[]);
    let long_null = read(&ber, &long_null);
    let absent = read(&ber, &absent);
    assert!(long_null.has_no_parameters());
    assert!(long_null.matches(&absent, &memory(64)).unwrap());
}

#[test]
fn fresh_account_cannot_reset_a_retained_identifiers_source_ceiling() {
    // A retained query must pay the original parser too, even when the new
    // caller supplies an independently funded account and no former Reader.
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1000,
            ..Limits::default()
        },
        memory(1 << 20),
    );
    let bytes = identifier(&[]);
    let mut reader = source.read(&bytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = algorithm::read(&reader, &element, "retained.digest").unwrap();
    let source_work = reader.execution();
    source_work
        .charge_work(source_work.work_remaining() as u64)
        .unwrap();
    drop(reader);
    let current = memory(64);
    let error = digest::algorithm(&reading, &current).unwrap_err();
    assert!(error.is_resource());
    assert_eq!((error.field(), error.offset()), ("retained.digest", 700));
    assert_eq!(current.work_used(), 0);
    assert_eq!(current.used(), 0);
}

fn leave_work(work: &impl Work, remaining: usize) {
    let available = work.work_remaining();
    assert!(available >= remaining);
    work.charge_work((available - remaining) as u64).unwrap();
}

#[test]
fn retained_resolution_admits_source_current_and_aggregate_before_callbacks() {
    // Exact cost is unchanged: source and operation ceilings constrain one
    // ten-unit bill. Refusal cannot spend it partially or ask the provider.
    for (source_left, current_left, aggregate, success) in [
        (10, 10, 10, true),
        (9, 10, 10, false),
        (10, 9, 10, false),
        (10, 10, 9, false),
    ] {
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1000,
                ..Limits::default()
            },
            memory(1 << 20),
        );
        let bytes = identifier(&[]);
        let reading = read(&source, &bytes);
        let old = source.execution_in(source.memory());
        leave_work(&old, source_left);
        let source_aggregate = source.memory().work_used();
        let current = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: current_left,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 900).unwrap();
        let provider = OnlySha256::default();
        let result = digest::resolve(&provider, &reading, &query.execution());
        if success {
            assert_eq!(result.unwrap(), Resolution::Supported(Algorithm::Sha256));
            assert_eq!(provider.identities.get(), 1);
            assert_eq!(current.work_used(), 10);
            assert_eq!(old.work_remaining(), source_left - 10);
            assert_eq!(query.execution().work_remaining(), 0);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!((error.field(), error.offset()), ("digestAlgorithm", 0));
            assert_eq!(provider.identities.get(), 0);
            assert_eq!(current.work_used(), 0);
            assert_eq!(old.work_remaining(), source_left);
        }
        assert_eq!(source.memory().work_used(), source_aggregate);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn retained_resolution_preserves_root_operation_across_another_source() {
    // Switching from a root operation through an unrelated source must keep
    // that root's tight limit, without inheriting the intermediate ceiling.
    for (remaining, success) in [(9, false), (10, true)] {
        let source = Parser::der(memory(1 << 20));
        let bytes = identifier(&[]);
        let reading = read(&source, &bytes);
        let current = memory(1000);
        let root = Parser::new(
            Encoding::Der,
            Limits {
                max_work: remaining,
                ..Limits::default()
            },
            current.clone(),
        );
        let intermediate = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 0,
                ..Limits::default()
            },
            memory(1000),
        );
        let root_work = root.execution_in(&current);
        let intermediate_work = root_work.execution_for(&intermediate);
        let result = digest::algorithm(&reading, &intermediate_work);
        if success {
            assert_eq!(result.unwrap(), Resolution::Supported(Algorithm::Sha256));
            assert_eq!(root_work.work_remaining(), 0);
            assert_eq!(current.work_used(), 10);
        } else {
            assert!(result.unwrap_err().is_resource());
            assert_eq!(
                root_work.work_remaining(),
                usize::try_from(remaining).unwrap()
            );
            assert_eq!(current.work_used(), 0);
        }
        assert_eq!(intermediate.memory().work_used(), 0);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn same_session_resolution_has_one_bill_and_no_retained_storage() {
    // The common origin/operation session must be deduplicated. Both the
    // local and aggregate remainder fall by ten, not twenty, with no clone.
    let account = Arc::new(MemoryAccount::new(4096, 1 << 20));
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1000,
            ..Limits::default()
        },
        Memory::new(account.clone()),
    );
    let bytes = identifier(&[5, 0]);
    let reading = read(&source, &bytes);
    let work = source.execution_in(source.memory());
    leave_work(&work, 10);
    let local = work.work_remaining();
    let aggregate = source.memory().work_used();
    let owners = Arc::strong_count(&account);
    assert_eq!(
        digest::algorithm(&reading, &work).unwrap(),
        Resolution::Supported(Algorithm::Sha256)
    );
    assert_eq!(work.work_remaining(), local - 10);
    assert_eq!(source.memory().work_used(), aggregate + 10);
    assert_eq!(source.memory().used(), 0);
    assert_eq!(Arc::strong_count(&account), owners);
}

#[test]
fn source_refusal_precedes_supported_malformed_and_unknown_answers() {
    // Even a negative classification examines untrusted metadata. It cannot
    // bypass a spent source, nor invoke an identity callback on the way out.
    for bytes in [
        identifier(&[]),
        identifier(&[2, 1, 0]),
        vec![48, 3, 6, 1, 42],
    ] {
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1000,
                ..Limits::default()
            },
            memory(1 << 20),
        );
        let reading = read(&source, &bytes);
        leave_work(&source.execution_in(source.memory()), 0);
        let current = memory(1000);
        let provider = OnlySha256::default();
        let error = digest::resolve(&provider, &reading, &current).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(provider.identities.get(), 0);
        assert_eq!(current.work_used(), 0);
        assert_eq!(current.used(), 0);
    }
}
