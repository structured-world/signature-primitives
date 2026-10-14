//! Independent RFC8032 vectors through CMS's raw-input processing boundary.
//! This test adapter is not a production engine or a qualified crypto cost model.

use core::{cell::Cell, cmp::Ordering};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::provider::{
    DigestAlgorithm, DigestProvider, Prehash, Resolution, SignatureAnswer, SignatureMode,
    SignatureProvider,
};
use structured_cms::{Octets, binding, oid, prepare, signer::SignerInfo, verify};
use structured_pkix::{AlgorithmIdentifier, PublicKeyInfo, path::WorkingKey};

const SHA512: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];

#[derive(Debug)]
enum Failure {
    Resource(MemoryError),
    Encoding,
    Account,
    Prehash,
}

impl From<MemoryError> for Failure {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

struct Oracle {
    key: VerifyingKey,
    digest_resolutions: Cell<usize>,
    digest_starts: Cell<usize>,
    raw_starts: Cell<usize>,
    raw_finishes: Cell<usize>,
}

struct Raw<'a> {
    key: &'a VerifyingKey,
    signature: Signature,
    // Dalek's stable strict verifier needs contiguous input. Capacity is
    // retained until verification, and callback-local work is rebound each time.
    input: Option<OwnedVec<u8>>,
}

impl<'a> DigestProvider<'a> for Oracle {
    type Error = Failure;
    type Identity = ();
    type State = Sha512;
    type Output = [u8; 64];

    fn resolve_digest(
        &'a self,
        identifier: DigestAlgorithm<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<()>, Failure> {
        parent.execution().charge_work(SHA512.len() as u64 + 1)?;
        self.digest_resolutions
            .set(self.digest_resolutions.get() + 1);
        let DigestAlgorithm::Written(identifier) = identifier else {
            return Ok(Resolution::Unsupported);
        };
        if identifier.algorithm().as_bytes() != SHA512 {
            return Ok(Resolution::Unsupported);
        }
        // RFC8419 §2.3 requires absent SHA-512 parameters in this profile.
        if identifier.parameters().is_some() {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(()))
    }

    fn compare_digest<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }

    fn digest_width(&self, (): &()) -> Option<usize> {
        Some(64)
    }

    fn start_digest<W: Work>(&'a self, (): &(), work: &W) -> Result<Sha512, Failure> {
        work.charge_work(128)?;
        self.digest_starts.set(self.digest_starts.get() + 1);
        Ok(Sha512::new())
    }

    fn update_digest<W: Work>(
        &self,
        state: &mut Sha512,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64 + 128)?;
        state.update(bytes);
        Ok(())
    }

    fn finish_digest<W: Work>(&self, state: Sha512, work: &W) -> Result<[u8; 64], Failure> {
        work.charge_work(256)?;
        Ok(state.finalize().into())
    }

    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, ()>,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(64)?;
        Ok(digest.as_bytes() == expected)
    }
}

impl<'a> SignatureProvider<'a> for Oracle {
    type SignatureIdentity = ();
    type RawState = Raw<'a>;

    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        (): &(),
        key: WorkingKey<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, Failure> {
        parent.execution().charge_work(64)?;
        if identifier.algorithm().as_bytes() != ED25519
            || key.key().algorithm().algorithm().as_bytes() != ED25519
        {
            return Ok(Resolution::Unsupported);
        }
        // RFC8410 §3 and RFC8419 §3.1: absent parameters, PureEdDSA only.
        if identifier.parameters().is_some() || key.parameters().is_some() {
            return Ok(Resolution::Malformed);
        }
        if key.key().key_octets() != Some(self.key.as_bytes().as_slice()) {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(SignatureMode::Raw(())))
    }

    fn compare_signature<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }

    fn start_raw<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        work: &W,
    ) -> Result<Raw<'a>, Failure> {
        work.charge_work(64)?;
        let bytes = signature.as_one().ok_or(Failure::Encoding)?;
        let signature = Signature::from_slice(bytes).map_err(|_| Failure::Encoding)?;
        self.raw_starts.set(self.raw_starts.get() + 1);
        Ok(Raw {
            key: &self.key,
            signature,
            input: Some(work.vector().into_owned()),
        })
    }

    fn update_raw<W: Work>(
        &self,
        state: &mut Raw<'a>,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Failure> {
        let input = state.input.take().ok_or(Failure::Account)?;
        let mut scoped = match input.with_execution(work) {
            Ok(scoped) => scoped,
            Err(original) => {
                state.input = Some(original);
                return Err(Failure::Account);
            }
        };
        let result = scoped.try_extend_from_slice(bytes);
        state.input = Some(scoped.into_owned());
        result.map_err(Failure::Resource)
    }

    fn finish_raw<W: Work>(&self, state: Raw<'a>, work: &W) -> Result<SignatureAnswer, Failure> {
        let input = state.input.ok_or(Failure::Account)?;
        // A conservative test-only allowance precedes the fixed-curve oracle,
        // including its internal message hash. This is not a runtime cost claim.
        work.charge_work(100_000 + input.len() as u64)?;
        self.raw_finishes.set(self.raw_finishes.get() + 1);
        Ok(match state.key.verify_strict(&input, &state.signature) {
            Ok(()) => SignatureAnswer::Valid,
            Err(_) => SignatureAnswer::Invalid,
        })
    }

    fn verify_prehashed<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        _signature: &Octets<'a>,
        _digest: Prehash<'_, '_, Self, ()>,
        _work: &W,
    ) -> Result<SignatureAnswer, Failure> {
        Err(Failure::Prehash)
    }
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut result = [0; N];
    assert_eq!(text.len(), N * 2);
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid public vector"),
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    result
}

fn check(public: [u8; 32], signature: [u8; 64], message: &[u8]) -> SignatureAnswer {
    check_input(public, signature, message, None, ContentFact::Direct).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentFact {
    Direct,
    Matches,
    Differs,
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(u8::try_from(contents.len()).unwrap());
    } else if contents.len() < 256 {
        result.extend([0x81, u8::try_from(contents.len()).unwrap()]);
    } else {
        result.push(0x82);
        result.extend(u16::try_from(contents.len()).unwrap().to_be_bytes());
    }
    result.extend_from_slice(contents);
    result
}

fn check_input(
    public: [u8; 32],
    signature: [u8; 64],
    message: &[u8],
    attributes: Option<&[u8]>,
    expected_content: ContentFact,
) -> Option<SignatureAnswer> {
    // Fixture assembly precedes parsing, outside the untrusted execution domain.
    let mut contents = vec![2, 1, 3, 0x80, 1, 7, 0x30, 11, 6, 9];
    contents.extend_from_slice(SHA512);
    if let Some(attributes) = attributes {
        contents.extend_from_slice(attributes);
    }
    contents.extend_from_slice(&[0x30, 5, 6, 3]);
    contents.extend_from_slice(ED25519);
    contents.extend_from_slice(&[4, 64]);
    contents.extend_from_slice(&signature);
    let encoded = tlv(0x30, &contents);
    let mut spki = vec![0x30, 42, 0x30, 5, 6, 3];
    spki.extend_from_slice(ED25519);
    spki.extend_from_slice(&[3, 33, 0]);
    spki.extend_from_slice(&public);
    let memory = Memory::new(Arc::new(MemoryAccount::new(100_000, 1_000_000)));
    let parser = Parser::der(memory.clone());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&parent, &element).unwrap();
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let provider = Oracle {
        key: VerifyingKey::from_bytes(&public).unwrap(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    };
    let held = memory.used();
    let prepare::Preparation::Ready(ready) = prepare::resolve(
        &provider,
        &signer,
        WorkingKey::standing(key),
        &parent,
        binding::Scope::Content(oid::DATA),
    )
    .unwrap() else {
        panic!("RFC8419 profile must select PureEdDSA");
    };
    let mut requests = parent.execution().vector();
    requests.try_push(ready).unwrap();
    let batch = verify::Batch::prepare(
        &provider,
        requests.into_owned(),
        &parent.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    let mut source = [message];
    let report = batch.run(&mut source, &parent.execution()).unwrap();
    assert_eq!(provider.digest_resolutions.get(), 1);
    assert_eq!(
        provider.digest_starts.get(),
        usize::from(attributes.is_some())
    );
    assert_eq!(provider.raw_starts.get(), 1);
    assert_eq!(
        provider.raw_finishes.get(),
        usize::from(expected_content != ContentFact::Differs)
    );
    let actual_content = match report[0].content() {
        verify::ContentAgreement::Direct => ContentFact::Direct,
        verify::ContentAgreement::Matches => ContentFact::Matches,
        verify::ContentAgreement::Differs => ContentFact::Differs,
        verify::ContentAgreement::Malformed(error) => panic!("valid fixture: {error:?}"),
    };
    assert_eq!(actual_content, expected_content);
    assert!(report[0].signer().faults().is_empty());
    let answer = report[0].signature();
    drop(report);
    assert_eq!(
        memory.used(),
        held,
        "input and report capacity must be released"
    );
    answer
}

#[test]
fn pure_ed25519_public_vectors_use_raw_message_and_no_digest_state() {
    // RFC8032 §7.1 Tests1/2: independently published empty/one-byte messages.
    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(check(public, signature, b""), SignatureAnswer::Valid);
    let public = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let signature = hex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    assert_eq!(check(public, signature, &[0x72]), SignatureAnswer::Valid);
    assert_eq!(check(public, signature, &[0x73]), SignatureAnswer::Invalid);
    let mut damaged = signature;
    damaged[0] ^= 1;
    assert_eq!(check(public, damaged, &[0x72]), SignatureAnswer::Invalid);
}

#[test]
fn pure_ed25519_signed_attributes_cover_original_set_and_bind_payload_separately() {
    // RFC8419 §3.2 / RFC5652 §§5.4–5.5: the signature covers the original
    // signedAttrs with the SET identifier, while message-digest covers payload.
    // This is a PUBLIC RFC8032 §7.1 Test1 key, not a generated/private fixture.
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let public = signing.verifying_key().to_bytes();
    let message = b"CMS original payload";
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::DATA.as_bytes())));
    let mut message_digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    message_digest.extend(tlv(0x31, &tlv(4, &Sha512::digest(message))));
    let mut contents = tlv(0x30, &content_type);
    contents.extend(tlv(0x30, &message_digest));
    let mut signed = tlv(0x31, &contents);
    let signature = signing.sign(&signed).to_bytes();
    signed[0] = 0xa0;
    assert_eq!(
        check_input(
            public,
            signature,
            message,
            Some(&signed),
            ContentFact::Matches
        ),
        Some(SignatureAnswer::Valid)
    );
    assert_eq!(
        check_input(
            public,
            signature,
            b"different payload",
            Some(&signed),
            ContentFact::Differs
        ),
        None,
        "payload disagreement must stop the attrs signature challenge"
    );
    let wrong_tag_signature = signing.sign(&signed).to_bytes();
    assert_eq!(
        check_input(
            public,
            wrong_tag_signature,
            message,
            Some(&signed),
            ContentFact::Matches
        ),
        Some(SignatureAnswer::Invalid),
        "the context tag is not the signature input"
    );
}

#[test]
fn timestamp_signature_driver_covers_original_segmented_info_and_keeps_key() {
    // The timestamp driver must use the same CMS raw/attrs kernel: attached
    // BER fragments are the logical payload, never a repaired TSTInfo encoding.
    use structured_cms::timestamp::{Token, TokenSignature};
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let public = signing.verifying_key().to_bytes();
    let mut info_fields = vec![
        2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 7, 8, 2, 1, 7,
    ];
    info_fields.extend(tlv(0x18, b"20260101000000Z"));
    let original_info = tlv(0x30, &info_fields);
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::TST_INFO.as_bytes())));
    let mut message_digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    message_digest.extend(tlv(0x31, &tlv(4, &Sha512::digest(&original_info))));
    let mut attrs = tlv(0x30, &content_type);
    attrs.extend(tlv(0x30, &message_digest));
    let mut signed = tlv(0x31, &attrs);
    let signature = signing.sign(&signed).to_bytes();
    signed[0] = 0xa0;
    let digest_algorithm = tlv(0x30, &tlv(6, SHA512));
    let mut signer_fields = vec![2, 1, 3, 0x80, 1, 7];
    signer_fields.extend(&digest_algorithm);
    signer_fields.extend(signed);
    signer_fields.extend(tlv(0x30, &tlv(6, ED25519)));
    signer_fields.extend(tlv(4, &signature));
    let mut spki = tlv(0x30, &tlv(6, ED25519));
    let mut bits = vec![0];
    bits.extend(public);
    spki.extend(tlv(3, &bits));
    let spki = tlv(0x30, &spki);
    for corrupted in [false, true] {
        let mut payload = original_info.clone();
        if corrupted {
            *payload.last_mut().unwrap() ^= 1;
        }
        let mut fragments = tlv(4, &payload[..7]);
        fragments.extend(tlv(4, &payload[7..]));
        let mut content = tlv(6, oid::TST_INFO.as_bytes());
        content.extend(tlv(0xa0, &tlv(0x24, &fragments)));
        let mut fields = vec![2, 1, 3];
        fields.extend(tlv(0x31, &digest_algorithm));
        fields.extend(tlv(0x30, &content));
        fields.extend(tlv(0x31, &tlv(0x30, &signer_fields)));
        let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
        envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
        let bytes = tlv(0x30, &envelope);
        let memory = Memory::new(Arc::new(MemoryAccount::new(100_000, 1_000_000)));
        let parser = Parser::ber(memory.clone());
        let token = Token::read(&parser, &bytes, 400).unwrap();
        let parent = parser.read(&[], 400).unwrap();
        let mut key_reader = parser.read(&spki, 900).unwrap();
        let element = key_reader.next_element().unwrap().unwrap();
        let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
        let provider = Oracle {
            key: signing.verifying_key(),
            digest_resolutions: Cell::new(0),
            digest_starts: Cell::new(0),
            raw_starts: Cell::new(0),
            raw_finishes: Cell::new(0),
        };
        let held = memory.used();
        let TokenSignature::Checked(checked) = token
            .check_signature(&provider, WorkingKey::standing(key), &parent)
            .unwrap()
        else {
            panic!("supported profile");
        };
        assert_eq!(checked.key().key().as_bytes(), key.as_bytes());
        assert!(core::ptr::eq(checked.signer(), token.signer()));
        if corrupted {
            assert!(matches!(
                checked.content(),
                verify::ContentAgreement::Differs
            ));
            assert_eq!(checked.signature(), None);
        } else {
            assert!(matches!(
                checked.content(),
                verify::ContentAgreement::Matches
            ));
            assert_eq!(checked.signature(), Some(SignatureAnswer::Valid));
        }
        assert_eq!(provider.raw_finishes.get(), usize::from(!corrupted));
        drop(checked);
        assert_eq!(memory.used(), held);
    }
}

fn timestamp_fixture(
    signing: &SigningKey,
    stated_accuracy: bool,
    nonminimal_serial: bool,
) -> (Vec<u8>, Vec<u8>) {
    timestamp_fixture_catalogue(
        signing,
        stated_accuracy,
        nonminimal_serial,
        FixtureCatalogue::Signer,
    )
}

#[derive(Clone, Copy)]
enum FixtureCatalogue {
    Signer,
    Empty,
    Other,
}

fn timestamp_fixture_catalogue(
    signing: &SigningKey,
    stated_accuracy: bool,
    nonminimal_serial: bool,
    catalogue: FixtureCatalogue,
) -> (Vec<u8>, Vec<u8>) {
    // Entirely synthetic certificate/token from the public RFC8032 test key.
    let algorithm = tlv(0x30, &tlv(6, ED25519));
    let mut attribute = tlv(6, &[0x55, 4, 3]);
    attribute.extend(tlv(12, b"Test Authority"));
    let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)));
    let mut validity = tlv(0x17, b"250101000000Z");
    validity.extend(tlv(0x17, b"300101000000Z"));
    let mut bits = vec![0];
    bits.extend(signing.verifying_key().to_bytes());
    let mut spki = algorithm.clone();
    spki.extend(tlv(3, &bits));
    let spki = tlv(0x30, &spki);
    let mut key_identifier = tlv(6, structured_pkix::oid::SUBJECT_KEY_IDENTIFIER.as_bytes());
    key_identifier.extend(tlv(4, &tlv(4, &[7])));
    let mut eku = tlv(6, structured_pkix::oid::EXT_KEY_USAGE.as_bytes());
    eku.extend([1, 1, 0xff]);
    eku.extend(tlv(
        4,
        &tlv(
            0x30,
            &tlv(6, structured_pkix::oid::TIME_STAMPING.as_bytes()),
        ),
    ));
    let mut extensions = tlv(0x30, &key_identifier);
    extensions.extend(tlv(0x30, &eku));
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 1];
    tbs.extend(&algorithm);
    tbs.extend(&name);
    tbs.extend(tlv(0x30, &validity));
    tbs.extend(&name);
    tbs.extend(spki);
    tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
    let tbs = tlv(0x30, &tbs);
    let certificate_signature = signing.sign(&tbs).to_bytes();
    let mut certificate = tbs;
    certificate.extend(algorithm);
    let mut signature_bits = vec![0];
    signature_bits.extend(certificate_signature);
    certificate.extend(tlv(3, &signature_bits));
    let certificate = tlv(0x30, &certificate);
    let digest_algorithm = tlv(0x30, &tlv(6, SHA512));
    let mut imprint = digest_algorithm.clone();
    imprint.extend(tlv(4, &Sha512::digest(b"document")));
    let mut info = vec![2, 1, 1, 6, 1, 43];
    info.extend(tlv(0x30, &imprint));
    if nonminimal_serial {
        info.extend([2, 2, 0, 7]);
    } else {
        info.extend([2, 1, 7]);
    }
    info.extend(tlv(0x18, b"20260101000000Z"));
    if stated_accuracy {
        info.extend([0x30, 0]);
    }
    let info = tlv(0x30, &info);
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::TST_INFO.as_bytes())));
    let mut digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    digest.extend(tlv(0x31, &tlv(4, &Sha512::digest(&info))));
    let mut ess_identifier = digest_algorithm.clone();
    ess_identifier.extend(tlv(4, &Sha512::digest(&certificate)));
    let ess = tlv(0x30, &tlv(0x30, &tlv(0x30, &ess_identifier)));
    let mut signing_certificate = tlv(6, oid::SIGNING_CERTIFICATE_V2.as_bytes());
    signing_certificate.extend(tlv(0x31, &ess));
    let mut attributes = [
        tlv(0x30, &content_type),
        tlv(0x30, &digest),
        tlv(0x30, &signing_certificate),
    ];
    attributes.sort();
    let mut signed = tlv(0x31, &attributes.concat());
    let signature = signing.sign(&signed).to_bytes();
    signed[0] = 0xa0;
    let mut signer_fields = vec![2, 1, 3, 0x80, 1, 7];
    signer_fields.extend(&digest_algorithm);
    signer_fields.extend(signed);
    signer_fields.extend(tlv(0x30, &tlv(6, ED25519)));
    signer_fields.extend(tlv(4, &signature));
    let mut fragments = tlv(4, &info[..7]);
    fragments.extend(tlv(4, &info[7..]));
    let mut content = tlv(6, oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(0x24, &fragments)));
    let mut fields = vec![2, 1, 3];
    fields.extend(match catalogue {
        FixtureCatalogue::Signer => tlv(0x31, &digest_algorithm),
        FixtureCatalogue::Empty => tlv(0x31, &[]),
        FixtureCatalogue::Other => tlv(0x31, &tlv(0x30, &tlv(6, &[42]))),
    });
    fields.extend(tlv(0x30, &content));
    fields.extend(tlv(0x31, &tlv(0x30, &signer_fields)));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    (tlv(0x30, &envelope), certificate)
}

#[test]
fn complete_timestamp_checker_binds_signature_ess_content_time_and_retains_evidence() {
    // No caller-fabricated verdicts enter the evidence constructor. The real
    // selected provider performs CMS, ESS and document digests; absent accuracy
    // or wrong covered content must suppress evidence despite a valid signature.
    use structured_cms::timestamp::{CheckContext, ImprintAgreement, Token};
    use structured_pkix::{
        Certificate,
        temporal::{Instant, LeapTable},
    };
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    // RFC5652 §§5.1/5.3 explicitly permit an empty catalogue and optional
    // refusal of unlisted algorithms. No application rejection is asserted by
    // Evidence; real arithmetic still uses the original SHA512 signer input.
    for (accuracy, covered_bytes, positive, catalogue) in [
        (true, &b"document"[..], true, FixtureCatalogue::Signer),
        (true, &b"different"[..], false, FixtureCatalogue::Signer),
        (false, &b"document"[..], false, FixtureCatalogue::Signer),
        (true, &b"document"[..], true, FixtureCatalogue::Empty),
        (true, &b"document"[..], true, FixtureCatalogue::Other),
    ] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
        let evidence = {
            let (bytes, certificate_bytes) =
                timestamp_fixture_catalogue(&signing, accuracy, false, catalogue);
            let parser = Parser::ber(memory.clone());
            let cert_parser = Parser::der(memory.clone());
            let token = Token::read(&parser, &bytes, 400).unwrap();
            let parent = parser.read(&[], 400).unwrap();
            let certificate = Certificate::read(&cert_parser, &certificate_bytes, 900).unwrap();
            let certificate_parent = cert_parser.read(&[], 900).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let provider = Oracle {
                key: signing.verifying_key(),
                digest_resolutions: Cell::new(0),
                digest_starts: Cell::new(0),
                raw_starts: Cell::new(0),
                raw_finishes: Cell::new(0),
            };
            let context = CheckContext {
                certificate: &certificate,
                certificate_parent: &certificate_parent,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
            };
            let checked = token
                .check(
                    &provider,
                    &parent,
                    &context,
                    &mut [covered_bytes],
                    |_, _| Ok::<_, ()>(false),
                )
                .unwrap();
            assert_eq!(checked.evidence().is_some(), positive);
            assert_eq!(
                checked.bindings.v2,
                Some(structured_cms::ess::Binding::Matches)
            );
            assert_eq!(
                checked.imprint,
                if covered_bytes == b"document" {
                    ImprintAgreement::Matches
                } else {
                    ImprintAgreement::Differs
                }
            );
            checked.into_evidence()
        };
        if let Some(evidence) = evidence {
            assert_retained_evidence(evidence, &memory);
        }
        assert_eq!(memory.used(), 0);
    }
}

fn assert_retained_evidence(evidence: structured_cms::timestamp::Evidence, memory: &Memory) {
    // This runs after source/token/parser drop. Copy refusal must preserve
    // independent error provenance, not leak partial data or destroy the source.
    assert_eq!(evidence.facts().serial(), &[7]);
    assert_eq!(
        evidence.facts().imprint().hashed(),
        Sha512::digest(b"document").as_slice()
    );
    assert_eq!(
        evidence.source().coordinates(),
        structured_cms::content_source::Coordinates::Logical
    );
    assert_eq!(
        evidence
            .source()
            .project_span(evidence.facts().source_span(), memory)
            .unwrap()
            .len(),
        2
    );
    assert!(memory.used() > 0);
    let destination = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
    let independent = evidence.try_copy_in(&destination).unwrap();
    let partial = Memory::new(Arc::new(MemoryAccount::new(64, 10_000_000)));
    let refusal = evidence.try_copy_in(&partial).unwrap_err();
    drop(evidence);
    assert_eq!(memory.used(), 0);
    let structured_cms::timestamp::EvidenceCopyError::Facts { source, context } = refusal else {
        panic!("map admitted before partial fact refusal");
    };
    assert!(source.is_terminal());
    assert!(context.project_offset(source.offset(), &partial).unwrap() >= context.carrier().start);
    assert!(partial.used() > 0, "error context remains accounted");
    drop(context);
    assert_eq!(partial.used(), 0);
    assert_eq!(independent.facts().serial(), &[7]);
    assert!(destination.used() > 0);
    drop(independent);
    assert_eq!(destination.used(), 0);
}

#[test]
fn malformed_timestamp_info_is_refused_before_crypto_or_covered_source() {
    // A valid CMS signature does not license provider side effects over a
    // known nonconforming TSTInfo. The inspection reader retains the fault;
    // the complete checker must refuse before starting its crypto operations.
    use structured_cms::timestamp::{CheckContext, Token};
    use structured_pkix::{
        Certificate,
        temporal::{Instant, LeapTable},
    };
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let (bytes, certificate_bytes) = timestamp_fixture(&signing, true, true);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
    let parser = Parser::ber(memory.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let parent = parser.read(&[], 400).unwrap();
    let cert_parser = Parser::der(memory);
    let certificate = Certificate::read(&cert_parser, &certificate_bytes, 900).unwrap();
    let certificate_parent = cert_parser.read(&[], 900).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let provider = Oracle {
        key: signing.verifying_key(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    };
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
    };
    let answer = token.check(
        &provider,
        &parent,
        &context,
        &mut [&b"document"[..]],
        |_, _| Ok::<_, ()>(false),
    );
    assert!(
        answer.is_err(),
        "known schema fault entered complete execution"
    );
    assert_eq!(provider.digest_resolutions.get(), 0);
    assert_eq!(provider.digest_starts.get(), 0);
    assert_eq!(provider.raw_starts.get(), 0);
}

#[derive(Debug)]
enum NestedTimestampFailure {
    Syntax(structured_cms::Error),
    Check(
        structured_cms::timestamp::MappedCheckError<
            structured_cms::stream::RangesError,
            Failure,
            (),
        >,
    ),
}

impl core::fmt::Display for NestedTimestampFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax(source) => source.fmt(formatter),
            Self::Check(source) => write!(formatter, "{source:?}"),
        }
    }
}

#[test]
fn requested_timestamp_uses_one_resolved_token_imprint_for_comparison_and_hashing() {
    // Full request equality and covered-content hashing must share the token's
    // resolved identity, without resolving the same parameter-bearing occurrence
    // again or cloning/restoring a hash state.
    use structured_cms::timestamp::{
        CheckContext, Request, RequestAgreement, RequestWindow, Requested, Token,
    };
    use structured_pkix::{
        Certificate,
        temporal::{Instant, LeapTable},
    };
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let (bytes, certificate_bytes) = timestamp_fixture(&signing, true, false);
    let mut imprint = tlv(0x30, &tlv(6, SHA512));
    imprint.extend(tlv(4, &Sha512::digest(b"document")));
    let mut request = vec![2, 1, 1];
    request.extend(tlv(0x30, &imprint));
    let request_bytes = tlv(0x30, &request);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
    let parser = Parser::ber(memory.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let parent = parser.read(&[], 400).unwrap();
    let cert_parser = Parser::der(memory.clone());
    let certificate = Certificate::read(&cert_parser, &certificate_bytes, 900).unwrap();
    let certificate_parent = cert_parser.read(&[], 900).unwrap();
    let request_parser = Parser::der(memory);
    let mut request_parent = request_parser.read(&request_bytes, 1200).unwrap();
    let element = request_parent.next_element().unwrap().unwrap();
    let request = Request::read(&request_parent, &element).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let provider = Oracle {
        key: signing.verifying_key(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    };
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: Some(Requested {
            request: &request,
            parent: &request_parent,
        }),
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: RequestWindow::for_unique_imprint(
            Instant::new(1_767_225_500, 0).unwrap(),
            Instant::new(1_767_225_700, 0).unwrap(),
        ),
    };
    let checked = token
        .check(
            &provider,
            &parent,
            &context,
            &mut [&b"document"[..]],
            |_, _| Ok::<_, ()>(false),
        )
        .unwrap();
    assert_eq!(checked.requested_imprint, Some(RequestAgreement::Matches));
    assert!(checked.evidence().is_some());
    assert_eq!(provider.digest_resolutions.get(), 4);
    assert_eq!(provider.digest_starts.get(), 3);
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "exercise both independently owned source frames and opaque check failure without an unaccounted box"
)]
fn nested_timestamp_check_preserves_physical_evidence_and_error_frames() {
    // A CMS token can itself cross two outer fragments, while its TSTInfo
    // crosses two inner fragments. Neither proof nor failure may pin the joins
    // or mistake the CMS envelope's offsets for inner information offsets.
    use structured_cms::timestamp::{CheckContext, Token};
    use structured_cms::{ContentInfo, SignedData};
    use structured_pkix::{
        Certificate,
        temporal::{Instant, LeapTable},
    };
    let signing = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    for malformed in [false, true] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
        let result = {
            let (bytes, certificate_bytes) = timestamp_fixture(&signing, true, malformed);
            let date = bytes
                .windows(15)
                .position(|value| value == b"20260101000000Z")
                .unwrap();
            let split = date + 8;
            let mut fragments = tlv(4, &bytes[..split]);
            fragments.extend(tlv(4, &bytes[split..]));
            let wrapped = tlv(0x24, &fragments);
            let parser = Parser::ber(memory.clone());
            let mut parent = parser.read(&wrapped, 2000).unwrap();
            let element = parent.next_element().unwrap().unwrap();
            let outer_octets = Octets::read(&parent, &element, "outerToken").unwrap();
            let cert_parser = Parser::der(memory.clone());
            let certificate = Certificate::read(&cert_parser, &certificate_bytes, 900).unwrap();
            let certificate_parent = cert_parser.read(&[], 900).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let provider = Oracle {
                key: signing.verifying_key(),
                digest_resolutions: Cell::new(0),
                digest_starts: Cell::new(0),
                raw_starts: Cell::new(0),
                raw_finishes: Cell::new(0),
            };
            outer_octets.with_nested_reader(&parent, Encoding::Ber, "token", |reader, map| {
                let (envelope, producing) =
                    ContentInfo::read(reader).map_err(NestedTimestampFailure::Syntax)?;
                let message = SignedData::read_element(&producing, envelope.content())
                    .map_err(NestedTimestampFailure::Syntax)?;
                let token = Token::from_message(message, &producing)
                    .map_err(NestedTimestampFailure::Syntax)?;
                let context = CheckContext {
                    certificate: &certificate,
                    certificate_parent: &certificate_parent,
                    key: WorkingKey::standing(certificate.tbs().public_key()),
                    requested: None,
                    utc: &utc,
                    reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                    window: None,
                };
                assert_mapped_session_preflight(&token, &provider, map, &context);
                token
                    .check_mapped(
                        &provider,
                        (&producing, map),
                        &context,
                        &mut [&b"document"[..]],
                        |_, _| Ok::<_, ()>(false),
                    )
                    .map(structured_cms::timestamp::CheckedTimestamp::into_evidence)
                    .map_err(NestedTimestampFailure::Check)
            })
        };
        assert_nested_result(result, malformed, &memory);
        assert_eq!(memory.used(), 0);
    }
}

fn assert_mapped_session_preflight(
    token: &structured_cms::timestamp::Token<'_>,
    provider: &Oracle,
    map: &structured_cms::content_source::SourceMap,
    context: &structured_cms::timestamp::CheckContext<'_, '_>,
) {
    // Caller misuse must be rejected before copying fragment metadata, even
    // when the wrong reader has no storage allowance. No crypto/content runs.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000)));
    let parser = Parser::ber(memory.clone());
    let foreign = parser.read(&[], 0).unwrap();
    let before = memory.work_used();
    let result = token.check_mapped(
        provider,
        (&foreign, map),
        context,
        &mut [&b"document"[..]],
        |_, _| Ok::<_, ()>(false),
    );
    assert_eq!(memory.work_used(), before);
    let Err(structured_cms::timestamp::MappedCheckError::Preflight(
        structured_cms::timestamp::CheckError::Processing(error),
    )) = result
    else {
        panic!("foreign session was not refused before map admission");
    };
    assert_eq!(
        error.code(),
        structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(provider.digest_resolutions.get(), 0);
    assert_eq!(memory.used(), 0);
}

fn assert_nested_result(
    result: Result<
        Option<structured_cms::timestamp::Evidence>,
        structured_cms::content_source::ContentError<NestedTimestampFailure>,
    >,
    malformed: bool,
    memory: &Memory,
) {
    use structured_cms::content_source::ContentError;
    use structured_cms::timestamp::{CheckError, InfoCheckError, InfoError, MappedCheckError};
    // The frames and evidence must remain usable after both joins/parsers have
    // gone. Projections return original physical fragments, never joined spans.
    if malformed {
        let Err(ContentError::Callback {
            source:
                NestedTimestampFailure::Check(MappedCheckError::Execution {
                    envelope,
                    source:
                        CheckError::Information(ContentError::Callback {
                            source: InfoError::Callback(InfoCheckError::Nonconforming { span }),
                            context,
                        }),
                }),
            context: outer,
        }) = result
        else {
            panic!("failure frames lost");
        };
        assert_eq!(span.start, 0);
        assert_eq!(context.project_span(span, memory).unwrap().len(), 3);
        assert!(context.project_offset(span.start, memory).unwrap() >= 2000);
        assert!(envelope.project_offset(0, memory).unwrap() >= 2000);
        assert_eq!(envelope.carrier(), outer.carrier());
        assert!(memory.used() > 0);
        drop((context, envelope, outer));
    } else {
        let Ok(Some(evidence)) = result else {
            panic!("expected evidence");
        };
        assert_eq!(evidence.facts().serial(), &[7]);
        let original = evidence
            .source()
            .project_span(evidence.facts().source_span(), memory)
            .unwrap();
        assert_eq!(original.len(), 3);
        assert!(original.iter().all(|span| span.start >= 2000));
        drop((original, evidence));
    }
}

#[test]
fn raw_adapter_refuses_resources_before_copy_or_arithmetic() {
    // The contiguous oracle adapter must preserve refused input and expose
    // resource failure, rather than turning an incomplete verification into No.
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let oracle = Oracle {
        key: VerifyingKey::from_bytes(&public).unwrap(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000)));
    let mut state = Raw {
        key: &oracle.key,
        signature: Signature::from_bytes(&[0; 64]),
        input: Some(work.vector()),
    };
    assert!(matches!(
        oracle.update_raw(&mut state, b"must not be copied", &work),
        Err(Failure::Resource(MemoryError::LimitExceeded))
    ));
    assert!(state.input.as_ref().unwrap().is_empty());
    assert_eq!(work.used(), 0);
    drop(state);

    let work = Memory::new(Arc::new(MemoryAccount::new(128, 99_999)));
    let state = Raw {
        key: &oracle.key,
        signature: Signature::from_bytes(&[0; 64]),
        input: Some(work.vector()),
    };
    assert!(matches!(
        oracle.finish_raw(state, &work),
        Err(Failure::Resource(MemoryError::WorkExceeded))
    ));
    assert_eq!(oracle.raw_finishes.get(), 0);
    assert_eq!(work.used(), 0);
}
