//! One ASN.1 digest resolver for OCSP and CMS: parameters read under their
//! document's encoding, known identifiers kept apart from unknown ones, and a
//! spent ceiling kept apart from both.

use std::cmp::Ordering;
use std::sync::Arc;
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
    let bytes = [0x30, 11, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 7];
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
struct OnlySha256;

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
        (algorithm == Algorithm::Sha256).then_some(algorithm)
    }
}

#[test]
fn the_provider_decides_which_known_algorithms_it_implements() {
    // A known identifier the provider refuses is unsupported; a malformed one
    // stays malformed before the provider is asked.
    let der = Parser::der(memory(1 << 20));
    let execution = memory(64);
    let sha256 = identifier(&[]);
    let malformed = identifier(&[2, 1, 0]);
    assert_eq!(
        digest::resolve(&OnlySha256, &read(&der, &sha256), &execution).unwrap(),
        Resolution::Supported(Algorithm::Sha256)
    );
    assert_eq!(
        digest::resolve(&OnlySha256, &read(&der, &malformed), &execution).unwrap(),
        Resolution::Malformed
    );
    assert_eq!(
        digest::supported(&OnlySha256, Algorithm::Sha1),
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
