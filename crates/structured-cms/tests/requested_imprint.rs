//! Selected-provider request identity/source contracts; no cryptographic engine.

use core::cell::Cell;
use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Parser, Reader, Tag, universal};
use structured_cms::provider::{DigestAlgorithm, DigestProvider, Prehash, Resolution};
use structured_cms::timestamp::{
    ImprintAgreement, ImprintOperand, MessageImprint, RequestAgreement, RequestImprintError,
};

#[derive(Debug)]
enum CallbackError {
    Resource(MemoryError),
    Encoding(structured_asn1::Error),
    Processing(structured_pkix::Error),
}
impl CallbackError {
    fn is_resource(&self) -> bool {
        match self {
            Self::Resource(_) => true,
            Self::Encoding(error) => error.is_resource(),
            Self::Processing(error) => error.is_resource(),
        }
    }
}
impl From<MemoryError> for CallbackError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}
struct Identity<'a> {
    oid: &'a [u8],
    parameter: u64,
}
#[derive(Default)]
struct Provider {
    resolves: Cell<usize>,
    compares: Cell<usize>,
}
impl<'a> DigestProvider<'a> for Provider {
    type Error = CallbackError;
    type Identity = Identity<'a>;
    type State = ();
    type Output = [u8; 1];
    fn resolve_digest(
        &'a self,
        written: DigestAlgorithm<'a>,
        _: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<Identity<'a>>, CallbackError> {
        let DigestAlgorithm::Written(written) = written else {
            return Ok(Resolution::Unsupported);
        };
        let oid = written.algorithm().as_bytes();
        parent.execution().charge_work(oid.len() as u64)?;
        self.resolves.set(self.resolves.get() + 1);
        if oid != [42] && oid != [43] {
            return Ok(Resolution::Unsupported);
        }
        // Explicit TEST profile: these private test identifiers carry an
        // optional INTEGER parameter, whose absent/default identity is zero.
        // This is not a SHA/RSA parameter policy or a production dispatcher.
        let mut parameter = 0;
        if let Some(mut reader) = written
            .parameters_reader_in(parent, "algorithm.parameters")
            .map_err(CallbackError::Processing)?
        {
            let element = reader
                .next_element()
                .map_err(CallbackError::Encoding)?
                .unwrap();
            if element.tag() != Tag::primitive(universal::INTEGER) {
                return Ok(Resolution::Malformed);
            }
            let value = reader.integer(&element).map_err(CallbackError::Encoding)?;
            reader.execution().charge_work(9)?;
            let Some(value) = value.as_u64() else {
                return Ok(Resolution::Malformed);
            };
            parameter = value;
        }
        Ok(Resolution::Supported(Identity { oid, parameter }))
    }
    fn compare_digest<W: Work>(
        &self,
        left: &Identity<'a>,
        right: &Identity<'a>,
        work: &W,
    ) -> Result<Ordering, CallbackError> {
        work.charge_work(1 + left.oid.len() as u64 + right.oid.len() as u64)?;
        self.compares.set(self.compares.get() + 1);
        Ok(left
            .oid
            .cmp(right.oid)
            .then_with(|| left.parameter.cmp(&right.parameter)))
    }
    fn digest_width(&self, _: &Identity<'a>) -> Option<usize> {
        Some(1)
    }
    fn start_digest<W: Work>(&'a self, _: &Identity<'a>, _: &W) -> Result<(), CallbackError> {
        panic!("request comparison must not start hashing")
    }
    fn update_digest<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), CallbackError> {
        panic!("request comparison must not read content")
    }
    fn finish_digest<W: Work>(&self, (): (), _: &W) -> Result<[u8; 1], CallbackError> {
        panic!("request comparison must not finalize hashing")
    }
    fn matches_digest<W: Work>(
        &self,
        _: Prehash<'_, '_, Self, Identity<'a>>,
        _: &[u8],
        _: &W,
    ) -> Result<bool, CallbackError> {
        panic!("request declarations are not finalized prehashes")
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
fn imprint(oid: u8, parameter: Option<u8>, hash: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, &[oid]);
    if let Some(parameter) = parameter {
        algorithm.extend([2, 1, parameter]);
    }
    let mut body = tlv(0x30, &algorithm);
    body.extend(tlv(4, hash));
    tlv(0x30, &body)
}

#[test]
fn full_identity_includes_parameters_and_kind_beyond_equal_hash_width() {
    // Two independent source sessions are valid; a written test-profile default
    // equals omission, but different parameters/OIDs never match by width alone.
    let provider = Provider::default();
    let token_parser = Parser::ber(memory());
    let requested_parser = Parser::ber(memory());
    let token_bytes = imprint(42, None, &[7]);
    let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let token = MessageImprint::read(&token_parent, &element).unwrap();
    for (kind, parameter, hash, expected) in [
        (42, Some(0), 7, RequestAgreement::Matches),
        (42, Some(1), 7, RequestAgreement::AlgorithmDiffers),
        (43, None, 7, RequestAgreement::AlgorithmDiffers),
        (42, None, 8, RequestAgreement::HashDiffers),
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
    assert_eq!(provider.compares.get(), 4);
    assert_eq!(provider.resolves.get(), 8);
}

#[test]
fn matching_malformed_widths_and_unsupported_operands_never_succeed() {
    // Shared semantic preflight rejects impossible widths even when bytes agree;
    // the caller can tell whether the token or the request supplied that fact.
    let provider = Provider::default();
    let parser = Parser::ber(memory());
    for (token_kind, token_hash, asked_kind, asked_hash, operand, reason) in [
        (
            42,
            &[7, 8][..],
            42,
            &[7, 8][..],
            ImprintOperand::Token,
            ImprintAgreement::MalformedHash,
        ),
        (
            42,
            &[7][..],
            42,
            &[7, 8][..],
            ImprintOperand::Requested,
            ImprintAgreement::MalformedHash,
        ),
        (
            44,
            &[7][..],
            42,
            &[7][..],
            ImprintOperand::Token,
            ImprintAgreement::Unsupported,
        ),
        (
            42,
            &[7][..],
            44,
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
    let bytes = imprint(42, None, &[7]);
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
fn requested_resource_cause_keeps_requested_span_and_source_role() {
    // A refusal in the request's own aggregate domain is not token mismatch and
    // is not projected through the token's possibly joined SourceMap.
    let requested_memory = memory();
    let provider = Provider::default();
    let token_parser = Parser::ber(memory());
    let asked_parser = Parser::ber(requested_memory.clone());
    let bytes = imprint(42, None, &[7]);
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
    let RequestImprintError::Callback {
        operand,
        span,
        source,
    } = error
    else {
        panic!("requested callback cause lost")
    };
    assert_eq!(operand, ImprintOperand::Requested);
    assert_eq!(span.start, 800);
    assert!(source.is_resource());
    assert!(matches!(
        source,
        CallbackError::Resource(MemoryError::WorkExceeded)
    ));
    assert_eq!(provider.resolves.get(), 1);
    assert_eq!(provider.compares.get(), 0);
}
