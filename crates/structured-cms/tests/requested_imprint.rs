//! Selected-provider request identity/source contracts; no cryptographic engine.

use core::cell::Cell;
use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_cms::timestamp::{
    ImprintAgreement, ImprintOperand, MessageImprint, RequestAgreement, RequestImprintError,
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];
const UNKNOWN: &[u8] = &[42];

#[derive(Default)]
struct Provider {
    resolves: Cell<usize>,
    compares: Cell<usize>,
}
impl Digest<'_> for Provider {
    type Identity = Algorithm;
    type State = ();
    type Output = [u8; 1];
    type Error = MemoryError;
    fn compare<W: Work>(
        &self,
        left: &Algorithm,
        right: &Algorithm,
        work: &W,
    ) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        self.compares.set(self.compares.get() + 1);
        Ok(left.cmp(right))
    }
    // A synthetic one-octet width, so short test hashes are well formed.
    fn width(&self, _: &Algorithm) -> Option<usize> {
        Some(1)
    }
    fn start<W: Work>(&self, _: &Algorithm, _: &W) -> Result<Resolution<()>, MemoryError> {
        panic!("request comparison must not start hashing")
    }
    fn update<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), MemoryError> {
        panic!("request comparison must not read content")
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 1], MemoryError> {
        panic!("request comparison must not finalize hashing")
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        _: &[u8; 1],
        _: &[u8],
        _: &W,
    ) -> Result<bool, MemoryError> {
        panic!("request declarations are not finished digests")
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        self.resolves.set(self.resolves.get() + 1);
        Some(algorithm)
    }
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag, u8::try_from(value.len()).unwrap()];
    bytes.extend_from_slice(value);
    bytes
}
fn imprint(oid: &[u8], parameter: Option<&[u8]>, hash: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, oid);
    if let Some(parameter) = parameter {
        algorithm.extend_from_slice(parameter);
    }
    let mut body = tlv(0x30, &algorithm);
    body.extend(tlv(4, hash));
    tlv(0x30, &body)
}

#[test]
fn full_identity_includes_parameters_and_kind_beyond_equal_hash_width() {
    // Two independent source sessions are valid; NULL parameters equal their
    // omission (RFC 5754 §2), while a different algorithm or a malformed
    // parameter never matches by width alone.
    let provider = Provider::default();
    let token_parser = Parser::ber(memory());
    let requested_parser = Parser::ber(memory());
    let token_bytes = imprint(SHA256, None, &[7]);
    let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let token = MessageImprint::read(&token_parent, &element).unwrap();
    for (kind, parameter, hash, expected) in [
        (SHA256, Some(&[5, 0][..]), 7, RequestAgreement::Matches),
        (
            SHA256,
            Some(&[2, 1, 1][..]),
            7,
            RequestAgreement::Unusable {
                operand: ImprintOperand::Requested,
                reason: ImprintAgreement::MalformedAlgorithm,
            },
        ),
        (SHA384, None, 7, RequestAgreement::AlgorithmDiffers),
        (SHA256, None, 8, RequestAgreement::HashDiffers),
    ] {
        let requested_bytes = imprint(kind, parameter, &[hash]);
        let mut asked_parent = requested_parser.read(&requested_bytes, 800).unwrap();
        let element = asked_parent.next_element().unwrap().unwrap();
        let asked = MessageImprint::read(&asked_parent, &element).unwrap();
        assert_eq!(
            token
                .matches_request(&asked, &provider, &token_parent, &asked_parent)
                .unwrap(),
            expected
        );
    }
    // The malformed request never reaches the provider or a comparison.
    assert_eq!(provider.compares.get(), 3);
    assert_eq!(provider.resolves.get(), 7);
}

#[test]
fn matching_malformed_widths_and_unsupported_operands_never_succeed() {
    // Shared semantic preflight rejects impossible widths even when bytes agree;
    // the caller can tell whether the token or the request supplied that fact.
    let provider = Provider::default();
    let parser = Parser::ber(memory());
    for (token_kind, token_hash, asked_kind, asked_hash, operand, reason) in [
        (
            SHA256,
            &[7, 8][..],
            SHA256,
            &[7, 8][..],
            ImprintOperand::Token,
            ImprintAgreement::MalformedHash,
        ),
        (
            SHA256,
            &[7][..],
            SHA256,
            &[7, 8][..],
            ImprintOperand::Requested,
            ImprintAgreement::MalformedHash,
        ),
        (
            UNKNOWN,
            &[7][..],
            SHA256,
            &[7][..],
            ImprintOperand::Token,
            ImprintAgreement::Unsupported,
        ),
        (
            SHA256,
            &[7][..],
            UNKNOWN,
            &[7][..],
            ImprintOperand::Requested,
            ImprintAgreement::Unsupported,
        ),
    ] {
        let token_bytes = imprint(token_kind, None, token_hash);
        let asked_bytes = imprint(asked_kind, None, asked_hash);
        let mut token_parent = parser.read(&token_bytes, 400).unwrap();
        let mut asked_parent = parser.read(&asked_bytes, 800).unwrap();
        let element = token_parent.next_element().unwrap().unwrap();
        let token = MessageImprint::read(&token_parent, &element).unwrap();
        let element = asked_parent.next_element().unwrap().unwrap();
        let asked = MessageImprint::read(&asked_parent, &element).unwrap();
        assert_eq!(
            token
                .matches_request(&asked, &provider, &token_parent, &asked_parent)
                .unwrap(),
            RequestAgreement::Unusable { operand, reason }
        );
    }
    assert_eq!(provider.compares.get(), 0);
}

#[test]
fn wrong_requested_reader_preflights_before_resolving_either_operand() {
    // Sharing an account cannot substitute the token session for the original
    // request session. Both provenance guards run before any resolver side effect.
    let memory = memory();
    let provider = Provider::default();
    let token_parser = Parser::ber(memory.clone());
    let asked_parser = Parser::ber(memory.clone());
    let bytes = imprint(SHA256, None, &[7]);
    let mut token_parent = token_parser.read(&bytes, 400).unwrap();
    let mut asked_parent = asked_parser.read(&bytes, 800).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let token = MessageImprint::read(&token_parent, &element).unwrap();
    let element = asked_parent.next_element().unwrap().unwrap();
    let asked = MessageImprint::read(&asked_parent, &element).unwrap();
    let work = memory.work_used();
    let error = token
        .matches_request(&asked, &provider, &token_parent, &token_parent)
        .unwrap_err();
    assert!(
        matches!(error, RequestImprintError::Processing { operand: ImprintOperand::Requested, source } if source.is_terminal())
    );
    assert_eq!(provider.resolves.get(), 0);
    assert_eq!(memory.work_used(), work);
}

#[test]
fn requested_resource_refusal_keeps_its_source_role() {
    // A refusal in the request's own aggregate domain is not token mismatch and
    // is reported against the request, located in its own coordinates.
    let requested_memory = memory();
    let provider = Provider::default();
    let token_parser = Parser::ber(memory());
    let asked_parser = Parser::ber(requested_memory.clone());
    let bytes = imprint(SHA256, None, &[7]);
    let mut token_parent = token_parser.read(&bytes, 400).unwrap();
    let mut asked_parent = asked_parser.read(&bytes, 800).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let token = MessageImprint::read(&token_parent, &element).unwrap();
    let element = asked_parent.next_element().unwrap().unwrap();
    let asked = MessageImprint::read(&asked_parent, &element).unwrap();
    requested_memory
        .charge_work(requested_memory.work_remaining() as u64)
        .unwrap();
    let error = token
        .matches_request(&asked, &provider, &token_parent, &asked_parent)
        .unwrap_err();
    let RequestImprintError::Processing { operand, source } = error else {
        panic!("requested resource cause lost")
    };
    assert_eq!(operand, ImprintOperand::Requested);
    assert!(source.is_resource());
    assert!(source.offset() >= 800);
    assert_eq!(provider.resolves.get(), 1);
    assert_eq!(provider.compares.get(), 0);
}
