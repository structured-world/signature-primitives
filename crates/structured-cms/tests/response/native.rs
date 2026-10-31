//! Native request/response checks share the existing independently tested oracle.

use super::*;
use structured_cms::timestamp::{
    CheckContext, CheckError, ProfileCheckError, ProfileFailure, Request, RequestWindow, Requested,
    Response, Timeliness, response::Status,
};
use structured_pkix::{
    Certificate,
    temporal::{Instant, LeapTable},
};

fn oracle(signing: &SigningKey) -> Oracle {
    Oracle {
        key: signing.verifying_key(),
        digest_resolutions: Cell::new(0),
        digest_starts: Cell::new(0),
        raw_starts: Cell::new(0),
        raw_finishes: Cell::new(0),
    }
}
fn signing() -> SigningKey {
    SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(4_000_000, 100_000_000)))
}

fn request(nonce: Option<u8>, policy: u8, hashed: &[u8], carry: bool) -> Vec<u8> {
    let mut imprint = tlv(0x30, &tlv(6, SHA512));
    imprint.extend(tlv(4, hashed));
    let mut fields = vec![2, 1, 1];
    fields.extend(tlv(0x30, &imprint));
    fields.extend([6, 1, policy]);
    if let Some(nonce) = nonce {
        fields.extend([2, 1, nonce]);
    }
    if carry {
        fields.extend([1, 1, 0xff]);
    }
    tlv(0x30, &fields)
}

fn token(
    signing: &SigningKey,
    nonce: Option<u8>,
    policy: u8,
    carry: bool,
    bad_signature: bool,
) -> (Vec<u8>, Vec<u8>) {
    // Reuse the existing real certificate and oracle, while making a DER
    // eContent (the older standalone BER token fixture deliberately fragments).
    let (_, certificate) = timestamp_fixture(signing, true, false);
    let digest_algorithm = tlv(0x30, &tlv(6, SHA512));
    let mut imprint = digest_algorithm.clone();
    imprint.extend(tlv(4, &Sha512::digest(b"document")));
    let mut info = vec![2, 1, 1, 6, 1, policy];
    info.extend(tlv(0x30, &imprint));
    info.extend([2, 1, 7]);
    info.extend(tlv(0x18, b"20260101000000Z"));
    info.extend([0x30, 0]);
    if let Some(nonce) = nonce {
        info.extend([2, 1, nonce]);
    }
    let info = tlv(0x30, &info);
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::TST_INFO.as_bytes())));
    let mut digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    digest.extend(tlv(0x31, &tlv(4, &Sha512::digest(&info))));
    let mut identifier = digest_algorithm.clone();
    identifier.extend(tlv(4, &Sha512::digest(&certificate)));
    let mut ess = tlv(6, oid::SIGNING_CERTIFICATE_V2.as_bytes());
    ess.extend(tlv(0x31, &tlv(0x30, &tlv(0x30, &tlv(0x30, &identifier)))));
    let mut attrs = [
        tlv(0x30, &content_type),
        tlv(0x30, &digest),
        tlv(0x30, &ess),
    ];
    attrs.sort();
    let mut covered_attrs = tlv(0x31, &attrs.concat());
    let mut signature = signing.sign(&covered_attrs).to_bytes();
    if bad_signature {
        signature[0] ^= 1;
    }
    covered_attrs[0] = 0xa0;
    let mut signer = vec![2, 1, 3, 0x80, 1, 7];
    signer.extend(&digest_algorithm);
    signer.extend(covered_attrs);
    signer.extend(tlv(0x30, &tlv(6, ED25519)));
    signer.extend(tlv(4, &signature));
    let mut content = tlv(6, oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &info)));
    let mut fields = vec![2, 1, 3];
    fields.extend(tlv(0x31, &digest_algorithm));
    fields.extend(tlv(0x30, &content));
    if carry {
        fields.extend(tlv(0xa0, &certificate));
    }
    fields.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    (tlv(0x30, &envelope), certificate)
}
fn response(status: u8, token: &[u8]) -> Vec<u8> {
    let mut fields = tlv(0x30, &[2, 1, status]);
    fields.extend(token);
    tlv(0x30, &fields)
}

#[test]
fn grants_check_real_signature_original_request_and_retained_evidence() {
    // The response grants no evidence by itself. The original live request,
    // selected certificate, ESS, content, nonce and policy are actually checked.
    for (status, nonce, windowed) in [(0, Some(9), false), (1, Some(9), false), (0, None, true)] {
        let memory = memory();
        let evidence = {
            let signing = signing();
            let (token, cert) = token(&signing, nonce, 43, true, false);
            let bytes = response(status, &token);
            let requested_bytes = request(nonce, 43, &Sha512::digest(b"document"), true);
            let parser = Parser::der(memory.clone());
            let cert_parser = Parser::der(memory.clone());
            let req_parser = Parser::der(memory.clone());
            let mut parent = parser.read(&bytes, 400).unwrap();
            let parsed = Response::read(&mut parent).unwrap();
            let certificate = Certificate::read(&cert_parser, &cert, 900).unwrap();
            let certificate_parent = cert_parser.read(&[], 900).unwrap();
            let mut req_parent = req_parser.read(&requested_bytes, 1200).unwrap();
            let req_element = req_parent.next_element().unwrap().unwrap();
            let req = Request::read(&req_parent, &req_element).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let window = if windowed {
                RequestWindow::for_unique_imprint(
                    Instant::new(1_767_225_599, 0).unwrap(),
                    Instant::new(1_767_225_602, 0).unwrap(),
                )
            } else {
                None
            };
            let context = CheckContext {
                certificate: &certificate,
                certificate_parent: &certificate_parent,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: Some(Requested {
                    request: &req,
                    parent: &req_parent,
                }),
                utc: &utc,
                reference: None,
                window,
                policy_accuracy: None,
            };
            let provider = oracle(&signing);
            let called = Cell::new(0);
            let result = parsed
                .check_with_profile(
                    &provider,
                    &parent,
                    &context,
                    &mut [&b"document"[..]],
                    |_, _| Ok::<_, ()>(false),
                    |_| {
                        called.set(called.get() + 1);
                        Ok::<_, ProfileFailure<()>>(())
                    },
                )
                .unwrap();
            assert_eq!(
                result.status(),
                if status == 0 {
                    Status::Granted
                } else {
                    Status::GrantedWithMods
                }
            );
            assert_eq!(called.get(), 1);
            let timestamp = result.into_timestamp().unwrap();
            assert_eq!(
                timestamp.timeliness,
                if windowed {
                    Timeliness::LocalWindow
                } else {
                    Timeliness::RequestNonce
                }
            );
            assert_eq!(provider.raw_finishes.get(), 1);
            timestamp
                .into_evidence()
                .expect("actual signature and every live-request fact match")
        };
        assert_eq!(evidence.facts().serial(), &[7]);
        assert_eq!(
            evidence.facts().imprint().hashed(),
            Sha512::digest(b"document").as_slice()
        );
        assert!(memory.used() > 0);
        drop(evidence);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn status_cannot_override_request_substitution_bad_signature_or_adverse_time() {
    // A grantedWithMods response still must match all explicit request fields.
    // A matching nonce must not turn a completed adverse window into success.
    let correct = Sha512::digest(b"document");
    let different = Sha512::digest(b"different");
    for (req_nonce, policy, hash, carry, bad_signature, adverse) in [
        (Some(8), 43, correct.as_slice(), true, false, false),
        (Some(9), 44, correct.as_slice(), true, false, false),
        (Some(9), 43, different.as_slice(), true, false, false),
        (Some(9), 43, correct.as_slice(), false, false, false),
        (Some(9), 43, correct.as_slice(), true, true, false),
        (Some(9), 43, correct.as_slice(), true, false, true),
        (None, 43, correct.as_slice(), true, false, false),
        (Some(9), 43, &correct[..63], true, false, false),
    ] {
        let memory = memory();
        let signing = signing();
        let (token, cert) = token(&signing, Some(9), 43, carry, bad_signature);
        let bytes = response(1, &token);
        let requested_bytes = request(req_nonce, policy, hash, true);
        let parser = Parser::der(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let parsed = Response::read(&mut parent).unwrap();
        let cert_parser = Parser::der(memory.clone());
        let certificate = Certificate::read(&cert_parser, &cert, 900).unwrap();
        let certificate_parent = cert_parser.read(&[], 900).unwrap();
        let req_parser = Parser::der(memory.clone());
        let mut req_parent = req_parser.read(&requested_bytes, 1200).unwrap();
        let req_element = req_parent.next_element().unwrap().unwrap();
        let req = Request::read(&req_parent, &req_element).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let window = if adverse {
            RequestWindow::for_unique_imprint(
                Instant::new(1_800_000_000, 0).unwrap(),
                Instant::new(1_800_000_010, 0).unwrap(),
            )
        } else {
            None
        };
        let context = CheckContext {
            certificate: &certificate,
            certificate_parent: &certificate_parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            requested: Some(Requested {
                request: &req,
                parent: &req_parent,
            }),
            utc: &utc,
            reference: None,
            window,
            policy_accuracy: None,
        };
        let provider = oracle(&signing);
        let checked = parsed
            .check(
                &provider,
                &parent,
                &context,
                &mut [&b"document"[..]],
                |_, _| Ok::<_, ()>(false),
            )
            .unwrap();
        assert!(checked.timestamp().unwrap().evidence().is_none());
        if adverse {
            assert_eq!(
                checked.timestamp().unwrap().timeliness,
                Timeliness::OutsideWindow
            );
        }
    }
}

#[test]
fn negative_status_has_no_provider_profile_recognizer_or_payload_side_effects() {
    // The actual request context remains mandatory. Negative status metadata
    // never enters a selected crypto provider or even reads supplied content.
    for status in 2..=5 {
        let signing = signing();
        let (_, cert) = token(&signing, Some(9), 43, true, false);
        let memory = memory();
        let bytes = response(status, &[]);
        let parser = Parser::der(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let parsed = Response::read(&mut parent).unwrap();
        let cert_parser = Parser::der(memory.clone());
        let certificate = Certificate::read(&cert_parser, &cert, 900).unwrap();
        let certificate_parent = cert_parser.read(&[], 900).unwrap();
        let req_bytes = request(Some(9), 43, &Sha512::digest(b"document"), true);
        let req_parser = Parser::der(memory.clone());
        let mut req_parent = req_parser.read(&req_bytes, 1200).unwrap();
        let req_element = req_parent.next_element().unwrap().unwrap();
        let req = Request::read(&req_parent, &req_element).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let mut context = CheckContext {
            certificate: &certificate,
            certificate_parent: &certificate_parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            requested: Some(Requested {
                request: &req,
                parent: &req_parent,
            }),
            utc: &utc,
            reference: None,
            window: None,
            policy_accuracy: None,
        };
        let provider = oracle(&signing);
        let mut covered = RefusingSource { calls: 0 };
        let checked = parsed
            .check_with_profile(
                &provider,
                &parent,
                &context,
                &mut covered,
                |_, _| -> Result<bool, ()> { panic!("negative response recognition") },
                |_| -> Result<(), ProfileFailure<()>> { panic!("negative response profile") },
            )
            .unwrap();
        assert!(checked.timestamp().is_none());
        assert_eq!(covered.calls, 0);
        assert_eq!(provider.digest_resolutions.get(), 0);
        assert_eq!(provider.raw_starts.get(), 0);
        context.requested = None;
        let error = parsed
            .check(&provider, &parent, &context, &mut covered, |_, _| {
                Ok::<_, ()>(false)
            })
            .err()
            .unwrap();
        assert!(
            matches!(error, CheckError::Processing(e) if e.code() == structured_cms::ErrorCode::InvalidLocation)
        );
        context.requested = Some(Requested {
            request: &req,
            parent: &parent,
        });
        let error = parsed
            .check(&provider, &parent, &context, &mut covered, |_, _| {
                Ok::<_, ()>(false)
            })
            .err()
            .unwrap();
        assert!(
            matches!(error, CheckError::RequestField(e) if e.operand == structured_cms::timestamp::ImprintOperand::Requested && e.source.is_terminal())
        );
        assert_eq!(covered.calls, 0);
    }
}

struct RefusingSource {
    calls: usize,
}
impl structured_cms::stream::Source for RefusingSource {
    type Error = &'static str;
    fn stream<W: Work>(
        &mut self,
        _: &mut impl structured_cms::stream::Receiver,
        _: &W,
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        Err("original covered source refusal")
    }
}

#[test]
fn profile_and_source_refusals_keep_original_causes_and_drop_partial_evidence() {
    // The profile runs before math/source effects; a later acquisition refusal
    // remains a Source error rather than a digest mismatch or partial evidence.
    let memory = memory();
    {
        let signing = signing();
        let (token, cert) = token(&signing, Some(9), 43, true, false);
        let bytes = response(0, &token);
        let requested_bytes = request(Some(9), 43, &Sha512::digest(b"document"), true);
        let parser = Parser::der(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let parsed = Response::read(&mut parent).unwrap();
        let cert_parser = Parser::der(memory.clone());
        let certificate = Certificate::read(&cert_parser, &cert, 900).unwrap();
        let certificate_parent = cert_parser.read(&[], 900).unwrap();
        let req_parser = Parser::der(memory.clone());
        let mut req_parent = req_parser.read(&requested_bytes, 1200).unwrap();
        let req_element = req_parent.next_element().unwrap().unwrap();
        let req = Request::read(&req_parent, &req_element).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = CheckContext {
            certificate: &certificate,
            certificate_parent: &certificate_parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            requested: Some(Requested {
                request: &req,
                parent: &req_parent,
            }),
            utc: &utc,
            reference: None,
            window: None,
            policy_accuracy: None,
        };
        let provider = oracle(&signing);
        let mut covered = RefusingSource { calls: 0 };
        let error = parsed
            .check_with_profile(
                &provider,
                &parent,
                &context,
                &mut covered,
                |_, _| Ok::<_, ()>(false),
                |_| {
                    Err(ProfileFailure {
                        source: structured_cms::timestamp::ProfileSource::Information,
                        cause: "original profile refusal",
                    })
                },
            )
            .err()
            .unwrap();
        assert!(
            matches!(error, ProfileCheckError::Profile { source, .. } if source.cause == "original profile refusal" && source.source == structured_cms::timestamp::ProfileSource::Information)
        );
        assert_eq!(provider.raw_starts.get(), 0);
        assert_eq!(provider.digest_resolutions.get(), 0);
        assert_eq!(covered.calls, 0);
        let error = parsed
            .check(&provider, &parent, &context, &mut covered, |_, _| {
                Ok::<_, ()>(false)
            })
            .err()
            .unwrap();
        assert!(matches!(
            error,
            CheckError::Information(structured_cms::content_source::ContentError::Callback {
                source: structured_cms::timestamp::InfoError::Callback(
                    structured_cms::timestamp::InfoCheckError::Imprint(
                        structured_cms::timestamp::ImprintError::Pass(
                            structured_cms::digest::PassError::Source(
                                "original covered source refusal"
                            )
                        )
                    )
                ),
                ..
            })
        ));
        assert_eq!(covered.calls, 1);
    }
    assert_eq!(memory.used(), 0);
}

#[test]
fn current_query_exact_work_capacity_and_depth_apply_to_every_nested_operation() {
    // A separately retained response cannot bill new ESS/crypto/content work
    // only to its old source. Both ceilings apply and failures release scratch.
    let attempt = |local, global, capacity, depth| {
        let original = memory();
        let current = Memory::new(Arc::new(MemoryAccount::new(capacity, global)));
        let succeeded = {
            let signing = signing();
            let (token, cert) = token(&signing, Some(9), 43, true, false);
            let bytes = response(0, &token);
            let req_bytes = request(Some(9), 43, &Sha512::digest(b"document"), true);
            let parser = Parser::der(original.clone());
            let mut parent = parser.read(&bytes, 400).unwrap();
            let parsed = Response::read(&mut parent).unwrap();
            let cert_parser = Parser::der(original.clone());
            let certificate = Certificate::read(&cert_parser, &cert, 900).unwrap();
            let certificate_parent = cert_parser.read(&[], 900).unwrap();
            let req_parser = Parser::der(original.clone());
            let mut req_parent = req_parser.read(&req_bytes, 1200).unwrap();
            let element = req_parent.next_element().unwrap().unwrap();
            let req = Request::read(&req_parent, &element).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let context = CheckContext {
                certificate: &certificate,
                certificate_parent: &certificate_parent,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: Some(Requested {
                    request: &req,
                    parent: &req_parent,
                }),
                utc: &utc,
                reference: None,
                window: None,
                policy_accuracy: None,
            };
            let provider = oracle(&signing);
            let query_parser = Parser::new(
                Encoding::Der,
                structured_asn1::Limits {
                    max_work: local,
                    max_depth: depth,
                    ..structured_asn1::Limits::default()
                },
                current.clone(),
            );
            let query = query_parser.read(&[], 0).unwrap();
            let mut covered = [&b"document"[..]];
            let result = parsed.check(&provider, &query, &context, &mut covered, |_, _| {
                Ok::<_, ()>(false)
            });
            let success = result
                .as_ref()
                .is_ok_and(|checked| checked.timestamp().unwrap().evidence().is_some());
            assert!(
                success || result.is_err(),
                "an enforced resource refusal must never become negative timestamp facts"
            );
            if local == 0 || depth == 0 {
                assert_eq!(provider.raw_starts.get(), 0);
            }
            drop(result);
            assert_eq!(current.used(), 0);
            success
        };
        assert_eq!(original.used(), 0);
        succeeded
    };
    let mut low = 0;
    let mut high = 3_000_000;
    assert!(attempt(high, 10_000_000, 4_000_000, 64));
    while low < high {
        let middle = u64::midpoint(low, high);
        if attempt(middle, 10_000_000, 4_000_000, 64) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert!(attempt(low, 10_000_000, 4_000_000, 64));
    assert!(!attempt(low - 1, 10_000_000, 4_000_000, 64));
    assert!(!attempt(0, 10_000_000, 4_000_000, 64));
    assert!(!attempt(3_000_000, 0, 4_000_000, 64));
    assert!(!attempt(3_000_000, 10_000_000, 1, 64));
    assert!(!attempt(3_000_000, 10_000_000, 4_000_000, 0));
}

#[test]
fn token_reopening_keeps_envelope_depth_and_original_physical_range() {
    // Embedding a response one level deeper must not let token_reader_in reset
    // it to a fresh root. Its bytes/start/depth are exactly the original range.
    let signing = signing();
    let (token, _) = token(&signing, Some(9), 43, false, false);
    let bytes = tlv(0x30, &response(0, &token));
    let memory = memory();
    let parser = Parser::der(memory.clone());
    let mut outer = parser.read(&bytes, 400).unwrap();
    let outer_element = outer.next_element().unwrap().unwrap();
    let mut inner = outer.enter(&outer_element).unwrap();
    let response_element = inner.next_element().unwrap().unwrap();
    let parsed = Response::read_element(&inner, &response_element).unwrap();
    let mut reopened = parsed.token_reader_in(&inner).unwrap().unwrap();
    assert_eq!(reopened.depth(), 2);
    let element = reopened.next_element().unwrap().unwrap();
    assert_eq!(element.as_bytes(), token);
    assert_eq!(
        element.span().start,
        response_element.contents_span().start + 5
    );
    let query_parser = Parser::new(
        Encoding::Der,
        structured_asn1::Limits {
            max_depth: 1,
            ..structured_asn1::Limits::default()
        },
        memory.clone(),
    );
    let query = query_parser.read(&[], 0).unwrap();
    assert!(parsed.token_reader_in(&query).unwrap_err().is_terminal());
    let remaining = structured_asn1::Limits::default().max_work - memory.work_used() as u64;
    inner.charge(remaining).unwrap();
    let fresh = Parser::der(memory);
    let generous = fresh.read(&[], 0).unwrap();
    assert!(parsed.token_reader_in(&generous).unwrap_err().is_resource());
}

#[test]
fn response_der_includes_the_carried_cms_without_reencoding_signed_input() {
    // RFC5652 standalone CMS supports BER, but RFC3161 §3 specifies DER wire
    // messages. The old fragmented OCTET STRING token remains valid standalone
    // inspection and must refuse as-is inside a DER response, never be rewritten.
    let signing = signing();
    let (token, _) = timestamp_fixture(&signing, true, false);
    let memory = memory();
    let parser = Parser::ber(memory);
    assert!(structured_cms::timestamp::Token::read(&parser, &token, 400).is_ok());
    let bytes = response(0, &token);
    let mut reader = parser.read(&bytes, 400).unwrap();
    assert!(Response::read(&mut reader).is_err());
}
