//! Operation-local catalogues and non-Send provider frames; not a crypto oracle.

use core::{cell::Cell, cmp::Ordering, marker::PhantomData};
use std::{rc::Rc, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::Octets;
use structured_cms::provider::{
    DigestAlgorithm, DigestProvider, Prehash, Resolution, SignatureAnswer, SignatureMode,
    SignatureProvider,
};
use structured_cms::signer::SignerInfo;
use structured_pkix::path::WorkingKey;
use structured_pkix::{AlgorithmIdentifier, PublicKeyInfo};

#[derive(Default)]
struct Provider {
    raw_updates: Cell<usize>,
    digest_updates: Cell<usize>,
    raw_finishes: Cell<usize>,
    digest_finishes: Cell<usize>,
    refuse_raw: Cell<bool>,
    digest_resolutions: Cell<usize>,
    signature_resolutions: Cell<usize>,
    unsupported_digest: Cell<bool>,
    refuse_resolution: Cell<bool>,
    digest_starts: Cell<usize>,
    raw_starts: Cell<usize>,
    refuse_comparison: Cell<bool>,
}
struct Digest(u8, PhantomData<Rc<()>>);
struct Frame<'a> {
    provider: &'a Provider,
    signature: &'a Octets<'a>,
    key: WorkingKey<'a>,
    sum: u8,
    marker: PhantomData<Rc<()>>,
}

impl<'a> DigestProvider<'a> for Provider {
    type Error = MemoryError;
    type Identity = ();
    type State = Digest;
    type Output = [u8; 1];
    fn resolve_digest(
        &'a self,
        identifier: DigestAlgorithm<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<()>, MemoryError> {
        parent.execution().charge_work(2)?;
        if self.refuse_resolution.get() {
            return Err(MemoryError::WorkExceeded);
        }
        self.digest_resolutions
            .set(self.digest_resolutions.get() + 1);
        let DigestAlgorithm::Written(identifier) = identifier else {
            // This selected synthetic backend does not implement ESS defaults;
            // schema identity never grants support by changing the mechanism.
            return Ok(Resolution::Unsupported);
        };
        if self.unsupported_digest.get() || identifier.algorithm().as_bytes() != [42] {
            return Ok(Resolution::Unsupported);
        }
        Ok(Resolution::Supported(()))
    }
    fn compare_digest<W: Work>(
        &self,
        _left: &(),
        _right: &(),
        execution: &W,
    ) -> Result<Ordering, MemoryError> {
        execution.charge_work(1)?;
        if self.refuse_comparison.get() {
            return Err(MemoryError::WorkExceeded);
        }
        Ok(Ordering::Equal)
    }
    fn digest_width(&self, _identity: &()) -> Option<usize> {
        Some(1)
    }
    fn start_digest<W: Work>(
        &'a self,
        _identity: &(),
        execution: &W,
    ) -> Result<Digest, MemoryError> {
        execution.charge_work(1)?;
        self.digest_starts.set(self.digest_starts.get() + 1);
        Ok(Digest(0, PhantomData))
    }
    fn update_digest<W: Work>(
        &self,
        state: &mut Digest,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), MemoryError> {
        execution.charge_work(bytes.len() as u64)?;
        self.digest_updates.set(self.digest_updates.get() + 1);
        for byte in bytes {
            state.0 = state.0.wrapping_add(*byte);
        }
        Ok(())
    }
    fn finish_digest<W: Work>(&self, state: Digest, execution: &W) -> Result<[u8; 1], MemoryError> {
        execution.charge_work(1)?;
        self.digest_finishes.set(self.digest_finishes.get() + 1);
        Ok([state.0])
    }

    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, ()>,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, MemoryError> {
        execution.charge_work(1)?;
        let bytes = digest.as_bytes();
        if bytes.len() != expected.len() {
            return Ok(false);
        }
        execution.charge_work(bytes.len() as u64)?;
        Ok(bytes == expected)
    }
}

impl<'a> SignatureProvider<'a> for Provider {
    type SignatureIdentity = ();
    type RawState = Frame<'a>;
    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        _digest: &(),
        _key: WorkingKey<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, MemoryError> {
        parent.execution().charge_work(2)?;
        self.signature_resolutions
            .set(self.signature_resolutions.get() + 1);
        // These synthetic signature mechanisms deliberately differ by input mode.
        Ok(match identifier.algorithm().as_bytes() {
            [43] => Resolution::Supported(SignatureMode::Raw(())),
            [44] => Resolution::Supported(SignatureMode::Prehashed(())),
            _ => Resolution::Unsupported,
        })
    }
    fn compare_signature<W: Work>(
        &self,
        _left: &(),
        _right: &(),
        execution: &W,
    ) -> Result<Ordering, MemoryError> {
        execution.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start_raw<W: Work>(
        &'a self,
        _identity: &(),
        key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        execution: &W,
    ) -> Result<Frame<'a>, MemoryError> {
        execution.charge_work(1)?;
        self.raw_starts.set(self.raw_starts.get() + 1);
        Ok(Frame {
            provider: self,
            signature,
            key,
            sum: 0,
            marker: PhantomData,
        })
    }
    fn update_raw<W: Work>(
        &self,
        state: &mut Frame<'a>,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), MemoryError> {
        execution.charge_work(bytes.len() as u64)?;
        if self.refuse_raw.get() {
            return Err(MemoryError::WorkExceeded);
        }
        state
            .provider
            .raw_updates
            .set(state.provider.raw_updates.get() + 1);
        for byte in bytes {
            state.sum = state.sum.wrapping_add(*byte);
        }
        Ok(())
    }
    fn finish_raw<W: Work>(
        &self,
        state: Frame<'a>,
        execution: &W,
    ) -> Result<SignatureAnswer, MemoryError> {
        execution.charge_work(2)?;
        self.raw_finishes.set(self.raw_finishes.get() + 1);
        Ok(
            if state.signature.as_one() == Some(&[state.sum][..])
                && state.key.key().key_octets() == Some(&[7][..])
            {
                SignatureAnswer::Valid
            } else {
                SignatureAnswer::Invalid
            },
        )
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        _identity: &(),
        key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, ()>,
        execution: &W,
    ) -> Result<SignatureAnswer, MemoryError> {
        execution.charge_work(2)?;
        Ok(
            if signature.as_one() == Some(digest.as_bytes())
                && key.key().key_octets() == Some(&[7][..])
            {
                SignatureAnswer::Valid
            } else {
                SignatureAnswer::Invalid
            },
        )
    }
}

fn operation<'a>(
    provider: &'a Provider,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    parent: &Reader<'a>,
) -> SignatureAnswer {
    // The descriptor is passed by value. The native-like frame borrows the
    // stable operation-local signature catalogue/provider, never Reader/Work.
    let Resolution::Supported(identity) = provider
        .resolve_digest(
            DigestAlgorithm::Written(signer.digest_algorithm().identifier().unwrap()),
            signer.encoding(),
            parent,
        )
        .unwrap()
    else {
        panic!("fixture digest is supported");
    };
    let Resolution::Supported(SignatureMode::Raw(signature)) = provider
        .resolve_signature(
            signer.signature_algorithm().identifier().unwrap(),
            &identity,
            key,
            signer.encoding(),
            parent,
        )
        .unwrap()
    else {
        panic!("fixture selects raw");
    };
    let mut frame = provider
        .start_raw(&signature, key, signer.signature(), &parent.execution())
        .unwrap();
    provider
        .update_raw(&mut frame, b"a", &parent.execution())
        .unwrap();
    provider
        .update_raw(&mut frame, b"b", &parent.execution())
        .unwrap();
    provider.finish_raw(frame, &parent.execution()).unwrap()
}

#[test]
fn raw_frame_borrows_stack_local_decoded_signer_without_self_reference_or_copy() {
    // A lifetime tied to source bytes must not force a heap-pinned SignerInfo,
    // cloned signature catalogue, Send/Sync provider or escaped parser borrow.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let encoded = [
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 195,
    ];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let provider = Provider::default();
    let held = memory.used();
    assert_eq!(
        operation(&provider, &signer, WorkingKey::standing(key), &reader),
        SignatureAnswer::Valid
    );
    assert_eq!(provider.raw_updates.get(), 2);
    assert_eq!(provider.digest_updates.get(), 0);
    assert_eq!(memory.used(), held);
    assert_eq!(
        signer.signature().as_one().unwrap().as_ptr(),
        encoded[encoded.len() - 1..].as_ptr()
    );
}

struct Chunks {
    calls: usize,
    incomplete: bool,
}

struct IgnoringSource;

impl structured_cms::stream::Source for IgnoringSource {
    type Error = &'static str;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl structured_cms::stream::Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        execution.charge_work(1).map_err(|_| "source resource")?;
        assert!(receiver.write(b"a").is_err());
        assert!(receiver.write(b"b").is_err());
        Ok(())
    }
}

impl structured_cms::stream::Source for Chunks {
    type Error = &'static str;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl structured_cms::stream::Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        execution.charge_work(1).map_err(|_| "source resource")?;
        self.calls += 1;
        receiver.write(b"a").map_err(|_| "refused")?;
        if self.incomplete {
            return Err("incomplete");
        }
        receiver.write(b"b").map_err(|_| "refused")
    }
}

fn prepare_payload<'a>(
    provider: &'a Provider,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    parent: &Reader<'a>,
) -> structured_cms::payload::PayloadBatch<'a, Provider> {
    use structured_cms::digest::DigestBatch;
    use structured_cms::payload::{PayloadBatch, RawRequest};
    let mut digests = parent.execution().vector();
    let mut raw = parent.execution().vector();
    for _ in 0..2 {
        let Resolution::Supported(digest) = provider
            .resolve_digest(
                DigestAlgorithm::Written(signer.digest_algorithm().identifier().unwrap()),
                signer.encoding(),
                parent,
            )
            .unwrap()
        else {
            panic!("fixture digest is supported");
        };
        let Resolution::Supported(SignatureMode::Raw(identity)) = provider
            .resolve_signature(
                signer.signature_algorithm().identifier().unwrap(),
                &digest,
                key,
                signer.encoding(),
                parent,
            )
            .unwrap()
        else {
            panic!("fixture signature is raw");
        };
        digests.try_push(digest).unwrap();
        raw.try_push(RawRequest {
            identity,
            key,
            signature: signer.signature(),
        })
        .unwrap();
    }
    let digests = DigestBatch::prepare(
        provider,
        digests.into_owned(),
        &parent.execution(),
        "payload",
        400,
    )
    .unwrap();
    PayloadBatch::prepare(digests, raw.into_owned(), &parent.execution()).unwrap()
}

#[test]
fn malformed_signer_algorithms_refuse_before_any_provider_callback() {
    // A valid digest followed by a malformed signature must not resolve even
    // the digest: both syntax gates precede every provider side effect.
    let malformed = [0x30, 6, 6, 2, 42, 3, 0x25, 0];
    let digest = [0x30, 3, 6, 1, 42];
    let signature = [0x30, 3, 6, 1, 43];
    for (digest, signature, fault_field) in [
        (
            malformed.as_slice(),
            signature.as_slice(),
            "signerInfo.digestAlgorithm",
        ),
        (
            digest.as_slice(),
            malformed.as_slice(),
            "signerInfo.signatureAlgorithm",
        ),
        (
            malformed.as_slice(),
            malformed.as_slice(),
            "signerInfo.digestAlgorithm",
        ),
    ] {
        let mut fields = vec![2, 1, 3, 0x80, 1, 7];
        fields.extend_from_slice(digest);
        fields.extend_from_slice(signature);
        fields.extend_from_slice(&[4, 1, 8]);
        let mut encoded = vec![0x30, u8::try_from(fields.len()).unwrap()];
        encoded.extend_from_slice(&fields);
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let parser = Parser::ber(memory);
        let mut parent = parser.read(&encoded, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&parent, &element).expect("readable inspection");
        let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
        let mut key_reader = parser.read(&spki, 900).unwrap();
        let element = key_reader.next_element().unwrap().unwrap();
        let key = WorkingKey::standing(
            PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap(),
        );
        let provider = Provider::default();
        let answer = structured_cms::prepare::resolve(
            &provider,
            &signer,
            key,
            &parent,
            structured_cms::binding::Scope::Content(structured_cms::oid::DATA),
        )
        .unwrap();
        let structured_cms::prepare::Preparation::Malformed(fault) = answer else {
            panic!("malformed inspection cannot produce a ready or unsupported plan");
        };
        assert_eq!(fault.field(), fault_field);
        assert_eq!(
            encoded[usize::try_from(fault.offset() - 700).unwrap()],
            0x25
        );
        assert_eq!(provider.digest_resolutions.get(), 0);
        assert_eq!(provider.signature_resolutions.get(), 0);
        assert_eq!(provider.digest_starts.get(), 0);
        assert_eq!(provider.raw_starts.get(), 0);
        // Retained syntax faults do not hide caller misuse: a different parser
        // on the same account must still fail as processing, before callbacks.
        let foreign = Parser::ber(parser.memory().clone());
        let query = foreign.read(&[], 700).unwrap();
        let Err(structured_cms::prepare::PrepareError::Processing(error)) =
            structured_cms::prepare::resolve(
                &provider,
                &signer,
                key,
                &query,
                structured_cms::binding::Scope::Content(structured_cms::oid::DATA),
            )
        else {
            panic!("foreign producer must not become malformed document evidence");
        };
        assert_eq!(
            error.code(),
            structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader,)
        );
        assert_eq!(provider.digest_resolutions.get(), 0);
        assert_eq!(provider.signature_resolutions.get(), 0);
    }
}

#[test]
fn shared_pass_finishes_raw_and_digest_once_only_after_complete_eof() {
    // This exercises the real common fan-out with non-Send borrowed raw
    // frames. The synthetic checksum only checks routing, not cryptography.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let encoded = [
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 195,
    ];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key =
        WorkingKey::standing(PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap());
    let provider = Provider::default();
    let held = memory.used();
    let batch = prepare_payload(&provider, &signer, key, &reader);
    let mut source = Chunks {
        calls: 0,
        incomplete: false,
    };
    let completed = batch.run(&mut source, &reader.execution()).unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(provider.digest_updates.get(), 2);
    assert_eq!(provider.raw_updates.get(), 4);
    assert_eq!(provider.digest_finishes.get(), 1);
    assert_eq!(provider.raw_finishes.get(), 2);
    assert_eq!(
        completed.raw(),
        &[SignatureAnswer::Valid, SignatureAnswer::Valid]
    );
    let left = completed
        .digests()
        .for_request(0, &reader.execution())
        .unwrap()
        .unwrap();
    let right = completed
        .digests()
        .for_request(1, &reader.execution())
        .unwrap()
        .unwrap();
    assert!(core::ptr::eq(left, right));
    assert_eq!(left.as_bytes(), &[195]);
    assert_eq!(
        provider
            .verify_prehashed(
                &(),
                key,
                signer.signature(),
                left.prehash(),
                &reader.execution()
            )
            .unwrap(),
        SignatureAnswer::Valid
    );
    assert_eq!(
        provider.digest_updates.get(),
        2,
        "prehashed verification never rehashes"
    );
    drop(completed);
    assert_eq!(memory.used(), held);
    assert_refusals_release_every_unfinished_state(&provider, &signer, key, &reader, &memory);
}

fn assert_refusals_release_every_unfinished_state<'a>(
    provider: &'a Provider,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    reader: &Reader<'a>,
    memory: &Memory,
) {
    let held = memory.used();
    let batch = prepare_payload(provider, signer, key, reader);
    let mut incomplete = Chunks {
        calls: 0,
        incomplete: true,
    };
    assert!(matches!(
        batch.run(&mut incomplete, &reader.execution()),
        Err(structured_cms::stream::StreamError::Source("incomplete"))
    ));
    assert_eq!(incomplete.calls, 1);
    assert_eq!(provider.digest_finishes.get(), 1);
    assert_eq!(provider.raw_finishes.get(), 2);
    assert_eq!(
        memory.used(),
        held,
        "unfinished states and catalogue capacity release"
    );
    let batch = prepare_payload(provider, signer, key, reader);
    provider.refuse_raw.set(true);
    assert!(matches!(
        batch.run(&mut IgnoringSource, &reader.execution()),
        Err(structured_cms::stream::StreamError::Callback(
            structured_cms::payload::PayloadError::Callback(MemoryError::WorkExceeded)
        ))
    ));
    assert_eq!(
        provider.digest_updates.get(),
        4,
        "a second ignored write cannot dispatch any state"
    );
    assert_eq!(provider.raw_updates.get(), 6);
    assert_eq!(provider.digest_finishes.get(), 1);
    assert_eq!(provider.raw_finishes.get(), 2);
    assert_eq!(memory.used(), held);
    provider.refuse_raw.set(false);
    let batch = prepare_payload(provider, signer, key, reader);
    let blocker = memory.reserve(memory.limit() - memory.used()).unwrap();
    let mut source = Chunks {
        calls: 0,
        incomplete: false,
    };
    assert!(matches!(
        batch.run(&mut source, &reader.execution()),
        Err(structured_cms::stream::StreamError::Processing(_))
    ));
    assert_eq!(
        source.calls, 0,
        "output catalogue capacity is admitted before payload I/O"
    );
    drop(blocker);
    assert_eq!(memory.used(), held);
}

#[test]
fn preflight_resolves_inputs_but_keeps_unsupported_and_resource_distinct() {
    // Resolving the input contract starts no raw/hash states or payload I/O.
    // Callback resource refusal cannot become semantic Unsupported.
    use structured_cms::binding::Scope;
    use structured_cms::prepare::{self, Part, Preparation, PrepareError};
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory);
    let encoded = [
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 195,
    ];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key =
        WorkingKey::standing(PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap());
    let provider = Provider::default();
    let Preparation::Ready(ready) = prepare::resolve(
        &provider,
        &signer,
        key,
        &reader,
        Scope::Content(structured_cms::oid::DATA),
    )
    .unwrap() else {
        panic!("fixture is ready");
    };
    assert!(core::ptr::eq(ready.provider(), &raw const provider));
    assert!(core::ptr::eq(ready.signer(), &raw const signer));
    assert!(matches!(ready.signature(), SignatureMode::Raw(())));
    assert_eq!(provider.digest_resolutions.get(), 1);
    assert_eq!(provider.signature_resolutions.get(), 1);
    assert_eq!(provider.raw_updates.get(), 0);
    assert_eq!(provider.digest_updates.get(), 0);
    assert_eq!(provider.raw_finishes.get(), 0);
    assert_eq!(provider.digest_starts.get(), 0);
    assert_eq!(provider.raw_starts.get(), 0);
    provider.unsupported_digest.set(true);
    assert!(matches!(
        prepare::resolve(
            &provider,
            &signer,
            key,
            &reader,
            Scope::Content(structured_cms::oid::DATA)
        )
        .unwrap(),
        Preparation::Unsupported(Part::Digest)
    ));
    assert_eq!(provider.signature_resolutions.get(), 1);
    provider.refuse_resolution.set(true);
    assert!(matches!(
        prepare::resolve(
            &provider,
            &signer,
            key,
            &reader,
            Scope::Content(structured_cms::oid::DATA)
        ),
        Err(PrepareError::Callback {
            part: Part::Digest,
            source: MemoryError::WorkExceeded
        })
    ));
    assert_eq!(provider.signature_resolutions.get(), 1);
}

fn bound_signer(include_digest: bool) -> Vec<u8> {
    if include_digest {
        binding_fixture(Some(&[1, 2]), None)
    } else {
        binding_fixture(None, None)
    }
}

fn binding_fixture(digest: Option<&[u8]>, protected_signature: Option<u8>) -> Vec<u8> {
    // Trusted synthetic fixture uses actual CMS singleton binding attributes.
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() < 128);
        let mut value = vec![tag, u8::try_from(bytes.len()).unwrap()];
        value.extend_from_slice(bytes);
        value
    }
    fn attribute(kind: structured_asn1::Oid<'_>, value: &[u8]) -> Vec<u8> {
        let mut contents = tlv(6, kind.as_bytes());
        contents.extend(tlv(0x31, value));
        tlv(0x30, &contents)
    }
    let mut attributes = vec![attribute(
        structured_cms::oid::CONTENT_TYPE,
        &tlv(6, structured_cms::oid::DATA.as_bytes()),
    )];
    if let Some(digest) = digest {
        attributes.push(attribute(
            structured_cms::oid::MESSAGE_DIGEST,
            &tlv(4, digest),
        ));
    }
    if let Some(signature) = protected_signature {
        attributes.push(attribute(
            structured_cms::oid::ALGORITHM_PROTECTION,
            &[0x30, 10, 0x30, 3, 6, 1, 42, 0xa1, 3, 6, 1, signature],
        ));
    }
    attributes.sort();
    let mut contents = vec![2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42];
    contents.extend(tlv(0xa0, &attributes.concat()));
    contents.extend_from_slice(&[0x30, 3, 6, 1, 43, 4, 1, 195]);
    tlv(0x30, &contents)
}

#[test]
fn syntax_and_fixed_impossible_imprint_width_refuse_before_states_or_payload() {
    // Binding syntax precedes every resolver. A readable fixed-width mismatch
    // needs digest resolution but cannot initialize a signature/hash state.
    use structured_cms::binding::Scope;
    use structured_cms::prepare::{self, Preparation};
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key =
        WorkingKey::standing(PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap());
    let provider = Provider::default();
    for (include_digest, code, resolutions) in [
        (false, structured_cms::ErrorCode::MissingField, 0),
        (true, structured_cms::ErrorCode::DigestWidth, 1),
    ] {
        let encoded = bound_signer(include_digest);
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&reader, &element).unwrap();
        let Preparation::Malformed(error) = prepare::resolve(
            &provider,
            &signer,
            key,
            &reader,
            Scope::Content(structured_cms::oid::DATA),
        )
        .unwrap() else {
            panic!("fixture must be refused");
        };
        assert_eq!(error.code(), code);
        assert_eq!(error.field(), "signerInfo.signedAttrs.messageDigest");
        assert!(error.offset() > 400);
        assert!(!error.is_resource());
        assert_eq!(provider.digest_resolutions.get(), resolutions);
        assert_eq!(provider.signature_resolutions.get(), 0);
        assert_eq!(provider.digest_starts.get(), 0);
        assert_eq!(provider.raw_starts.get(), 0);
    }
}

#[test]
fn protection_uses_selected_semantics_and_never_downgrades_raw_to_prehash() {
    // Same input mode/semantic identity can pass; a protected prehash mechanism
    // cannot stand in for the outer raw mechanism despite equal digest widths.
    use structured_cms::binding::Scope;
    use structured_cms::prepare::{self, Part, Preparation};
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key =
        WorkingKey::standing(PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap());
    for protected in [43, 44, 45] {
        let provider = Provider::default();
        let encoded = binding_fixture(Some(&[195]), Some(protected));
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&reader, &element).unwrap();
        let result = prepare::resolve(
            &provider,
            &signer,
            key,
            &reader,
            Scope::Content(structured_cms::oid::DATA),
        )
        .unwrap();
        match (protected, result) {
            (43, Preparation::Ready(ready)) => {
                assert!(matches!(ready.signature(), SignatureMode::Raw(())));
            }
            (44, Preparation::Malformed(error)) => {
                assert_eq!(error.code(), structured_cms::ErrorCode::AlgorithmProtection);
                assert_eq!(
                    error.field(),
                    "signerInfo.signedAttrs.cmsAlgorithmProtection"
                );
                assert!(error.offset() > signer.span().start);
            }
            (45, Preparation::Unsupported(Part::ProtectedSignature)) => {}
            _ => panic!("protected mechanism got the wrong classification"),
        }
        assert_eq!(provider.digest_resolutions.get(), 2);
        assert_eq!(provider.signature_resolutions.get(), 2);
        assert_eq!(provider.digest_starts.get(), 0);
        assert_eq!(provider.raw_starts.get(), 0);
    }
}

fn direct_case(signature: u8) -> Vec<u8> {
    vec![
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, signature, 4, 1, 195,
    ]
}

fn parameter_signer_case(parameter: &[u8], signature: u8, octet: u8) -> Vec<u8> {
    let mut inside = vec![
        2,
        1,
        3,
        0x80,
        1,
        7,
        0x30,
        u8::try_from(3 + parameter.len()).unwrap(),
        6,
        1,
        42,
    ];
    inside.extend_from_slice(parameter);
    inside.extend_from_slice(&[0x30, 3, 6, 1, signature, 4, 1, octet]);
    let mut bytes = vec![0x30, u8::try_from(inside.len()).unwrap()];
    bytes.extend_from_slice(&inside);
    bytes
}

#[test]
fn prepared_duplicate_comparison_uses_resolved_identities_without_resolution_or_hashing() {
    // The synthetic resolver deliberately maps its accepted parameter spellings
    // to one opaque identity. Common comparison must use that identity instead
    // of raw TLVs, while preserving mode/signature bytes and provider instance.
    use structured_cms::prepare::{Part, PrepareError};
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let parser = Parser::ber(memory.clone());
    let encodings = [
        parameter_signer_case(&[], 43, 195),
        parameter_signer_case(&[5, 0], 43, 195),
        parameter_signer_case(&[5, 0x81, 0], 43, 195),
        parameter_signer_case(&[], 44, 195),
        parameter_signer_case(&[], 43, 194),
    ];
    let signers: Vec<_> = encodings
        .iter()
        .enumerate()
        .map(|(index, encoded)| {
            let mut parent = parser
                .read(encoded, 400 + u64::try_from(index).unwrap() * 100)
                .unwrap();
            let element = parent.next_element().unwrap().unwrap();
            SignerInfo::read(&parent, &element).unwrap()
        })
        .collect();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut parent = parser.read(&spki, 1000).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let key = WorkingKey::standing(PublicKeyInfo::read_element(&parent, &element, "key").unwrap());
    let provider = Provider::default();
    let other = Provider::default();
    let ready = ready_requests(&provider, &signers, key, &parent);
    assert!(!signers[0].same_value(&signers[1], &parent).unwrap());
    let resolves = (
        provider.digest_resolutions.get(),
        provider.signature_resolutions.get(),
    );
    let held = memory.used();
    for (index, expected) in [(1, true), (2, true), (3, false), (4, false)] {
        assert_eq!(
            ready[0].same_signer_value(&ready[index], &parent).unwrap(),
            expected
        );
    }
    assert_eq!(
        (
            provider.digest_resolutions.get(),
            provider.signature_resolutions.get()
        ),
        resolves
    );
    assert_eq!(provider.digest_starts.get(), 0);
    assert_eq!(provider.raw_starts.get(), 0);
    assert_eq!(provider.digest_finishes.get(), 0);
    assert_eq!(provider.raw_finishes.get(), 0);
    assert_eq!(memory.used(), held);
    provider.refuse_comparison.set(true);
    assert!(matches!(
        ready[0].same_signer_value(&ready[1], &parent),
        Err(PrepareError::Callback {
            part: Part::DigestComparison,
            source: MemoryError::WorkExceeded
        })
    ));
    provider.refuse_comparison.set(false);
    let other_ready = ready_requests(&other, &signers, key, &parent);
    let Err(PrepareError::Processing(error)) = ready[0].same_signer_value(&other_ready[0], &parent)
    else {
        panic!("different provider instance accepted")
    };
    assert_eq!(error.code(), structured_cms::ErrorCode::ProviderMismatch);
    assert_eq!(error.offset(), signers[0].span().start);
    let current = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let limited = Parser::new(
        Encoding::Ber,
        structured_asn1::Limits {
            max_work: 1,
            ..structured_asn1::Limits::default()
        },
        current.clone(),
    );
    let query = limited.read(&[], 1500).unwrap();
    // Preserve the signers' origin session while narrowing the current query;
    // a new unrelated parser is caller misuse, not a local-budget test.
    let query = parser.read(&[], 1500).unwrap().with_query(&query).unwrap();
    let Err(PrepareError::Processing(error)) = ready[0].same_signer_value(&ready[1], &query) else {
        panic!("local refusal lost")
    };
    assert!(error.is_resource());
    assert_eq!(error.offset(), signers[1].span().start);
    assert_eq!(current.used(), 0);
}

fn attrs_case(signature: u8, expected: u8) -> Vec<u8> {
    // Synthetic checksum signature covers the original SET tag and the
    // original attrs length/content. It deliberately differs from payload195.
    let mut bytes = binding_fixture(Some(&[expected]), None);
    let start = bytes.iter().position(|byte| *byte == 0xa0).unwrap();
    let length = usize::from(bytes[start + 1]);
    let sum = bytes[start + 1..start + 2 + length]
        .iter()
        .fold(0x31_u8, |sum, byte| sum.wrapping_add(*byte));
    let last = bytes.len() - 1;
    bytes[last] = sum;
    bytes[last - 3] = signature;
    bytes
}

fn ready_requests<'a>(
    provider: &'a Provider,
    signers: &'a [SignerInfo<'a>],
    key: WorkingKey<'a>,
    parent: &Reader<'a>,
) -> structured_asn1::memory::OwnedVec<structured_cms::prepare::ResolvedSigner<'a, Provider>> {
    let mut requests = parent.execution().vector();
    for signer in signers {
        let prepared = structured_cms::prepare::resolve(
            provider,
            signer,
            key,
            parent,
            structured_cms::binding::Scope::Content(structured_cms::oid::DATA),
        )
        .unwrap();
        let structured_cms::prepare::Preparation::Ready(ready) = prepared else {
            panic!("synthetic valid challenge must resolve before state initialization");
        };
        requests.try_push(ready).unwrap();
    }
    requests.into_owned()
}

#[test]
fn selected_driver_separates_four_inputs_and_shares_only_the_payload_digest() {
    // Raw/prehash × direct/attrs must all accept their distinct exact input.
    // One payload pass and no identity/state clone are enough; attrs outputs
    // are not the payload memo and retained reports never assert trust.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let parser = Parser::ber(memory.clone());
    let encoded = [
        direct_case(43),
        direct_case(44),
        attrs_case(43, 195),
        attrs_case(44, 195),
    ];
    let signers: Vec<_> = encoded
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let mut reader = parser
                .read(bytes, 400 + u64::try_from(index).unwrap() * 1000)
                .unwrap();
            let element = reader.next_element().unwrap().unwrap();
            SignerInfo::read(&reader, &element).unwrap()
        })
        .collect();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut reader = parser.read(&spki, 9000).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&reader, &element, "key").unwrap();
    let provider = Provider::default();
    let held = memory.used();
    let requests = ready_requests(&provider, &signers, WorkingKey::standing(key), &reader);
    assert_eq!(provider.digest_starts.get(), 0);
    assert_eq!(provider.raw_starts.get(), 0);
    let batch = structured_cms::verify::Batch::prepare(
        &provider,
        requests,
        &reader.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    let mut source = Chunks {
        calls: 0,
        incomplete: false,
    };
    let results = batch.run(&mut source, &reader.execution()).unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(provider.digest_starts.get(), 2); // One payload + one attrs prehash.
    assert_eq!(provider.digest_finishes.get(), 2);
    assert_eq!(provider.raw_starts.get(), 2);
    assert_eq!(provider.raw_finishes.get(), 2);
    assert_eq!(provider.digest_resolutions.get(), 4);
    assert_eq!(provider.signature_resolutions.get(), 4);
    assert_eq!(results.len(), 4);
    for (index, result) in results.iter().enumerate() {
        assert!(core::ptr::eq(result.signer(), &raw const signers[index]));
        assert_eq!(result.signature(), Some(SignatureAnswer::Valid));
        assert!(result.signer().faults().is_empty());
    }
    assert!(matches!(
        results[0].content(),
        structured_cms::verify::ContentAgreement::Direct
    ));
    assert!(matches!(
        results[1].content(),
        structured_cms::verify::ContentAgreement::Direct
    ));
    assert!(matches!(
        results[2].content(),
        structured_cms::verify::ContentAgreement::Matches
    ));
    assert!(matches!(
        results[3].content(),
        structured_cms::verify::ContentAgreement::Matches
    ));
    assert!(memory.used() > held);
    drop(results);
    assert_eq!(memory.used(), held);
}

#[test]
fn selected_driver_refuses_partial_payload_without_finishing_any_state() {
    // Raw direct with no attrs resolves its required digestAlgorithm but starts
    // no unused hash. An incomplete source yields neither result nor finish.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = direct_case(43);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signers = [SignerInfo::read(&reader, &element).unwrap()];
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let provider = Provider::default();
    let held = memory.used();
    let requests = ready_requests(&provider, &signers, WorkingKey::standing(key), &reader);
    let batch = structured_cms::verify::Batch::prepare(
        &provider,
        requests,
        &reader.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    assert_eq!(provider.digest_resolutions.get(), 1);
    assert_eq!(provider.digest_starts.get(), 0);
    let mut source = Chunks {
        calls: 0,
        incomplete: true,
    };
    let Err(error) = batch.run(&mut source, &reader.execution()) else {
        panic!("partial input cannot produce completed per-signer facts");
    };
    assert!(matches!(
        error,
        structured_cms::stream::StreamError::Source("incomplete")
    ));
    assert_eq!(source.calls, 1);
    assert_eq!(provider.raw_finishes.get(), 0);
    assert_eq!(provider.digest_finishes.get(), 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn selected_driver_keeps_imprint_mismatch_and_refusal_out_of_signature_answers() {
    // Correct attrs signature bytes cannot override a payload imprint mismatch.
    // Before any payload I/O a foreign provider or output-storage refusal must
    // preserve its execution failure rather than becoming Invalid/Differs.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = attrs_case(43, 194);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signers = [SignerInfo::read(&reader, &element).unwrap()];
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key =
        WorkingKey::standing(PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap());
    let provider = Provider::default();
    let foreign = Provider::default();
    let held = memory.used();
    let requests = ready_requests(&provider, &signers, key, &reader);
    let Err(error) = structured_cms::verify::Batch::prepare(
        &foreign,
        requests,
        &reader.execution(),
        "signerInfos",
        400,
    ) else {
        panic!("another provider instance cannot initialize these requests");
    };
    let structured_cms::verify::CheckError::Processing(error) = error else {
        panic!("provider identity is common processing misuse");
    };
    assert_eq!(error.code(), structured_cms::ErrorCode::ProviderMismatch);
    assert_eq!(error.offset(), 400);
    assert_eq!(foreign.raw_starts.get(), 0);
    assert_eq!(provider.raw_starts.get(), 0);
    assert_eq!(memory.used(), held);
    let requests = ready_requests(&provider, &signers, key, &reader);
    let batch = structured_cms::verify::Batch::prepare(
        &provider,
        requests,
        &reader.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let mut source = Chunks {
        calls: 0,
        incomplete: false,
    };
    let Err(error) = batch.run(&mut source, &empty) else {
        panic!("report admission must precede source acquisition");
    };
    assert!(
        matches!(error, structured_cms::stream::StreamError::Processing(error) if error.is_resource())
    );
    assert_eq!(source.calls, 0);
    assert_eq!(provider.raw_finishes.get(), 0);
    assert_eq!(provider.digest_finishes.get(), 0);
    assert_eq!(memory.used(), held);
    let requests = ready_requests(&provider, &signers, key, &reader);
    let batch = structured_cms::verify::Batch::prepare(
        &provider,
        requests,
        &reader.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    let results = batch.run(&mut source, &reader.execution()).unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(results.len(), 1);
    assert!(matches!(
        results[0].content(),
        structured_cms::verify::ContentAgreement::Differs
    ));
    assert_eq!(results[0].signature(), None);
    assert_eq!(provider.digest_finishes.get(), 1);
    assert_eq!(provider.raw_finishes.get(), 0);
    drop(results);
    assert_eq!(memory.used(), held);
}

#[test]
fn counter_visitor_executes_operation_local_provider_without_escaping_child() {
    // The public walker must permit real prepare/verify use with short child
    // borrows and a non-Send raw frame. Only the owned answer leaves the call.
    use structured_cms::{binding::Scope, counter::Visit, prepare::Preparation};
    let child = direct_case(43);
    let mut attribute = vec![6, 9];
    attribute.extend_from_slice(structured_cms::oid::COUNTERSIGNATURE.as_bytes());
    attribute.extend_from_slice(&[0x31, u8::try_from(child.len()).unwrap()]);
    attribute.extend_from_slice(&child);
    let mut contents = direct_case(43)[2..].to_vec();
    contents.extend_from_slice(&[
        0xa1,
        u8::try_from(attribute.len() + 2).unwrap(),
        0x30,
        u8::try_from(attribute.len()).unwrap(),
    ]);
    contents.extend_from_slice(&attribute);
    let mut encoded = vec![0x30, u8::try_from(contents.len()).unwrap()];
    encoded.extend_from_slice(&contents);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 9000).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let provider = Provider::default();
    let results = structured_cms::counter::walk(&root, &reader, |event, producing| {
        let Visit::Signer {
            signer,
            mut signature,
            ..
        } = event
        else {
            panic!("readable fixture");
        };
        let Preparation::Ready(ready) = structured_cms::prepare::resolve(
            &provider,
            signer,
            WorkingKey::standing(key),
            producing,
            Scope::CounterSignature,
        )
        .unwrap() else {
            panic!("ready counter");
        };
        let mut requests = producing.execution().vector();
        requests.try_push(ready).unwrap();
        let batch = structured_cms::verify::Batch::prepare(
            &provider,
            requests.into_owned(),
            &producing.execution(),
            "counter",
            signer.span().start,
        )
        .unwrap();
        let checks = batch.run(&mut signature, &producing.execution()).unwrap();
        Ok::<_, ()>(checks[0].signature().unwrap())
    })
    .unwrap();
    assert_eq!(&*results, &[SignatureAnswer::Valid]);
    assert_eq!(provider.raw_starts.get(), 1);
    assert_eq!(provider.raw_finishes.get(), 1);
    assert_eq!(provider.digest_starts.get(), 0);
    drop(root);
    drop(reader);
    drop(key_reader);
    drop(parser);
    assert_eq!(&*results, &[SignatureAnswer::Valid]);
    drop(results);
    assert_eq!(memory.used(), 0);
}

#[test]
fn foreign_preparation_is_processing_before_any_provider_callback() {
    // Account equality does not establish producing session identity, even
    // when a bare signature needs no lazy attribute lookup to expose misuse.
    use structured_cms::prepare::{self, PrepareError};
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let encoded = direct_case(43);
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let spki = [0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7];
    let mut key_reader = parser.read(&spki, 9000).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let provider = Provider::default();
    let work = memory.work_used();
    assert!(
        structured_cms::binding::inspect(
            &signer,
            &other,
            structured_cms::binding::Scope::CounterSignature
        )
        .expect_err("foreign inspection")
        .is_terminal()
    );
    let error = prepare::resolve(
        &provider,
        &signer,
        WorkingKey::standing(key),
        &other,
        structured_cms::binding::Scope::CounterSignature,
    )
    .err()
    .expect("foreign session");
    assert!(
        matches!(error, PrepareError::Processing(ref error) if error.is_terminal() && !error.is_resource())
    );
    assert_eq!(provider.digest_resolutions.get(), 0);
    assert_eq!(provider.signature_resolutions.get(), 0);
    assert_eq!(memory.work_used(), work);
}
