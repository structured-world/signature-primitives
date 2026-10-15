//! Public OCSP schema, original signed ranges and resource boundaries.

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::ErrorCode;
use structured_pkix::ocsp::{Failure, ResponderId, Response, Status};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(std::sync::Arc::new(MemoryAccount::new(storage, work)))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(u8::try_from(contents.len()).unwrap());
    } else if contents.len() < 256 {
        result.extend([0x81, u8::try_from(contents.len()).unwrap()]);
    } else {
        result.extend([
            0x82,
            u8::try_from(contents.len() >> 8).unwrap(),
            u8::try_from(contents.len() & 255).unwrap(),
        ]);
    }
    result.extend_from_slice(contents);
    result
}
fn date() -> Vec<u8> {
    tlv(24, b"20261012120000Z")
}
fn algorithm() -> Vec<u8> {
    tlv(48, &[6, 3, 0x2a, 3, 4])
}
fn assertion(status: &[u8]) -> Vec<u8> {
    let id = tlv(
        48,
        &[
            algorithm(),
            tlv(4, &[0x11; 20]),
            tlv(4, &[0x22; 20]),
            tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0]),
        ]
        .concat(),
    );
    tlv(48, &[id, status.to_vec(), date()].concat())
}
fn data(assertions: &[u8]) -> Vec<u8> {
    tlv(
        48,
        &[tlv(0xa2, &tlv(4, &[0x33; 20])), date(), tlv(48, assertions)].concat(),
    )
}
fn basic(data: &[u8]) -> Vec<u8> {
    tlv(48, &[data, &algorithm(), &[3, 2, 0, 0xab]].concat())
}
fn envelope(payload: &[u8], kind: &[u8]) -> Vec<u8> {
    let response_bytes = tlv(48, &[tlv(6, kind), tlv(4, payload)].concat());
    tlv(48, &[&[10, 1, 0][..], &tlv(0xa0, &response_bytes)].concat())
}
fn response(data: &[u8]) -> Vec<u8> {
    envelope(&basic(data), &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1])
}

fn decode_basic<'a>(
    parser: &'a Parser,
    bytes: &'a [u8],
    base: u64,
) -> structured_pkix::Result<structured_pkix::ocsp::BasicResponse<'a>> {
    let Response::Successful(payload) = Response::read(parser, bytes, base)? else {
        panic!("fixture needs a successful envelope")
    };
    Ok(payload
        .into_basic(parser.memory())?
        .expect("fixture uses basic response syntax"))
}

#[test]
fn borrowed_basic_query_preserves_original_bytes_and_uses_the_current_capacity_owner() {
    // A lazy query may belong to a different operation. Its results retain the
    // new storage charge, while original payload/offsets remain borrowed in place.
    let original = memory(100_000, 1_000_000);
    let source = Parser::der(original.clone());
    let bytes = response(&data(&assertion(&[0x80, 0])));
    let Response::Successful(envelope) = Response::read(&source, &bytes, 700).unwrap() else {
        panic!("success fixture");
    };
    let held = original.used();
    let execution = memory(100_000, 1_000_000);
    let operation = Parser::der(execution.clone());
    let query = operation.read(&[], 100).unwrap();
    let parsed = envelope.basic_in(&query).unwrap().unwrap();
    assert_eq!(parsed.as_bytes(), envelope.payload());
    assert_eq!(parsed.as_bytes().as_ptr(), envelope.payload().as_ptr());
    assert_eq!(parsed.span(), envelope.span());
    assert_eq!(parsed.responses().len(), 1);
    assert_eq!(original.used(), held);
    assert!(execution.used() > 0);
    drop(envelope);
    assert_eq!(parsed.responses()[0].status(), Status::Good);
    drop(parsed);
    assert_eq!(execution.used(), 0);
    assert_eq!(original.used(), 0);
}

#[test]
fn borrowed_basic_query_preserves_current_local_aggregate_and_capacity_refusals() {
    // Previously decoded envelope data is no credit for a new operation's lazy
    // basic-response parse. Refusal is resource failure, not unsupported syntax.
    let original = memory(100_000, 1_000_000);
    let source = Parser::der(original.clone());
    let bytes = response(&data(&assertion(&[0x80, 0])));
    let Response::Successful(envelope) = Response::read(&source, &bytes, 700).unwrap() else {
        panic!("success fixture");
    };
    let held = original.used();
    for (storage, work, local) in [
        (100_000, 1_000_000, 0),
        (100_000, 0, 1_000_000),
        (0, 1_000_000, 1_000_000),
    ] {
        let execution = memory(storage, work);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            execution.clone(),
        );
        let query = operation.read(&[], 100).unwrap();
        let error = envelope.basic_in(&query).unwrap_err();
        assert!(error.is_resource(), "{error:?}");
        assert!(error.offset() >= envelope.span().start);
        assert_eq!(execution.used(), 0);
        assert_eq!(original.used(), held);
    }
}

#[test]
fn borrowed_basic_query_does_not_turn_unknown_or_malformed_payloads_into_each_other() {
    // Unknown syntax is retained without interpreting opaque payload bytes.
    // The same bytes under id-pkix-ocsp-basic must produce the real schema error.
    let execution = memory(100_000, 1_000_000);
    let source = Parser::der(execution.clone());
    let query = source.read(&[], 0).unwrap();
    let unknown = envelope(&[0x25, 0], &[0x2a, 3, 4]);
    let Response::Successful(payload) = Response::read(&source, &unknown, 700).unwrap() else {
        panic!("success fixture");
    };
    assert!(payload.basic_in(&query).unwrap().is_none());
    let known = envelope(&[0x25, 0], structured_pkix::oid::OCSP_BASIC.as_bytes());
    let Response::Successful(payload) = Response::read(&source, &known, 900).unwrap() else {
        panic!("success fixture");
    };
    let error = payload.basic_in(&query).unwrap_err();
    assert!(!error.is_resource());
    assert_eq!(error.offset(), payload.span().start);
}

#[test]
fn unsupported_basic_query_pays_classification_without_entering_opaque_payload() {
    // Unknown response syntax has no BasicOCSPResponse nesting to inspect.
    // Exact envelope depth must still allow classification; current and source
    // work ceilings apply to the OID comparison without any payload allocation.
    let original = memory(100_000, 1_000_000);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        original.clone(),
    );
    let bytes = envelope(&[0x25, 0], &[0x2a, 3, 4]);
    let Response::Successful(payload) = Response::read(&source, &bytes, 700).unwrap() else {
        panic!("successful unknown response envelope")
    };
    let held = original.used();
    let before = original.work_used();
    let current = memory(0, 1_000_000);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 100).unwrap();
    assert!(payload.basic_in(&query).unwrap().is_none());
    assert_eq!(current.work_used(), 19);
    assert_eq!(original.work_used(), before);
    assert_eq!(original.used(), held);
    assert_eq!(current.used(), 0);
    let denied = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = denied.read(&[], 100).unwrap();
    let error = payload.basic_in(&query).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), payload.span().start);
    assert_eq!(current.work_used(), 19);
}

#[test]
fn borrowed_basic_query_inherits_exact_original_and_current_depth_without_a_new_root() {
    // The OCTET-carried BasicOCSPResponse remains nested under its actual
    // envelope depth. Neither a foreign operation nor a fresh root can reset it.
    let bytes = response(&data(&assertion(&[0x80, 0])));
    for origin_limited in [false, true] {
        let original = memory(100_000, 1_000_000);
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: if origin_limited { 3 } else { 100 },
                ..Limits::default()
            },
            original.clone(),
        );
        let Response::Successful(envelope) = Response::read(&source, &bytes, 700).unwrap() else {
            panic!("success fixture");
        };
        let execution = memory(100_000, 1_000_000);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: if origin_limited { 100 } else { 3 },
                ..Limits::default()
            },
            execution.clone(),
        );
        let query = operation.read(&[], 100).unwrap();
        let error = envelope.basic_in(&query).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
                structured_asn1::Limit::Depth
            ))
        );
        assert_eq!(error.offset(), envelope.span().start);
        assert_eq!(execution.used(), 0);
    }
    let source = Parser::der(memory(100_000, 1_000_000));
    let Response::Successful(envelope) = Response::read(&source, &bytes, 700).unwrap() else {
        panic!("success fixture");
    };
    for depth in [9, 10] {
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: depth,
                ..Limits::default()
            },
            memory(100_000, 1_000_000),
        );
        let query = operation.read(&[], 100).unwrap();
        let result = envelope.basic_in(&query);
        if depth == 9 {
            assert_eq!(
                result.unwrap_err().code(),
                ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
                    structured_asn1::Limit::Depth
                ))
            );
        } else {
            assert_eq!(result.unwrap().unwrap().as_bytes(), envelope.payload());
        }
    }
}

#[test]
fn nonce_binding_preserves_missing_unsolicited_and_exact_bytes() {
    // RFC9654 uses an encoded inner OCTET STRING, accepts legacy received
    // lengths, and requires new requester nonces to have at least 32 bytes.
    use structured_pkix::ocsp::{NonceBinding, RequestNonce};
    let request = [0x61; 32];
    assert!(RequestNonce::new(&request[..31]).is_none());
    assert!(RequestNonce::new(&[0; 129]).is_none());
    let extension = |value: &[u8]| {
        tlv(
            48,
            &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 2]), tlv(4, value)].concat(),
        )
    };
    let with_nonce = |value: &[u8]| {
        let fields = [
            tlv(0xa2, &tlv(4, &[0x33; 20])),
            date(),
            tlv(48, &assertion(&[0x80, 0])),
            tlv(0xa1, &tlv(48, &extension(value))),
        ]
        .concat();
        response(&tlv(48, &fields))
    };
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let bytes = with_nonce(&tlv(4, &request));
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    let retained = execution.used();
    assert_eq!(
        parsed
            .bind_nonce(Some(RequestNonce::new(&request).unwrap()), &execution)
            .unwrap(),
        NonceBinding::Matches
    );
    assert_eq!(
        parsed
            .bind_nonce(Some(RequestNonce::new(&[0x62; 32]).unwrap()), &execution)
            .unwrap(),
        NonceBinding::Differs
    );
    assert_eq!(
        parsed.bind_nonce(None, &execution).unwrap(),
        NonceBinding::Unsolicited
    );
    assert_eq!(execution.used(), retained);
    let original = parsed.nonce(&execution).unwrap().unwrap();
    assert_eq!(original, request);
    assert!(
        original.as_ptr() >= bytes.as_ptr() && original.as_ptr() < bytes[bytes.len()..].as_ptr()
    );
    let exhausted = memory(0, 0);
    assert!(
        parsed
            .bind_nonce(None, &exhausted)
            .unwrap_err()
            .is_resource()
    );
    let absent = response(&data(&assertion(&[0x80, 0])));
    let parsed = decode_basic(&parser, &absent, 401).unwrap();
    assert_eq!(
        parsed.bind_nonce(None, &execution).unwrap(),
        NonceBinding::NotRequested
    );
    assert_eq!(
        parsed
            .bind_nonce(Some(RequestNonce::new(&request).unwrap()), &execution)
            .unwrap(),
        NonceBinding::Missing
    );
    for length in [1, 16, 32, 128] {
        let nonce = vec![0x61; length];
        let bytes = with_nonce(&tlv(4, &nonce));
        assert_eq!(
            decode_basic(&parser, &bytes, 401)
                .unwrap()
                .nonce(&execution)
                .unwrap(),
            Some(nonce.as_slice())
        );
        assert_eq!(
            decode_basic(&parser, &bytes, 401)
                .unwrap()
                .bind_nonce(Some(RequestNonce::from_sent(&nonce).unwrap()), &execution)
                .unwrap(),
            NonceBinding::Matches
        );
    }
    assert_eq!(RequestNonce::from_sent(&[]).unwrap_err().length, 0);
    assert_eq!(RequestNonce::from_sent(&[0; 129]).unwrap_err().length, 129);
    for value in [
        tlv(4, &[]),
        tlv(4, &[0; 129]),
        tlv(2, &[1]),
        [tlv(4, &request), tlv(4, &request)].concat(),
        request.to_vec(),
    ] {
        let bytes = with_nonce(&value);
        let parsed = decode_basic(&parser, &bytes, 401).unwrap();
        assert!(parsed.nonce(&execution).is_err());
        assert!(parsed.check_extensions(&execution).is_err());
    }
}

#[test]
fn update_windows_keep_ocsp_strict_deadline_and_no_invented_ttl() {
    // RFC6960 §3.2(6) requires nextUpdate > now. Exact equality is stale,
    // unlike the separately reported CRL cached-source endpoint fact.
    use structured_pkix::ocsp::UpdateWindow;
    use structured_pkix::temporal::{Instant, LeapTable};
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let encoded = assertion(&[0x80, 0]);
    let contents = if encoded[1] < 128 {
        &encoded[2..]
    } else {
        panic!("short fixture assertion")
    };
    let bytes = response(&data(&tlv(
        48,
        &[contents, &tlv(0xa0, &tlv(24, b"20261013120000Z"))].concat(),
    )));
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    let single = &parsed.responses()[0];
    let this = single.this_update().instant();
    let next = single.next_update().unwrap().instant();
    let utc = LeapTable::new(this.seconds() - 10, next.seconds() + 10, &[]).unwrap();
    for (now, expected) in [
        (
            Instant::new(this.seconds() - 1, 0).unwrap(),
            UpdateWindow::NotYetCurrent,
        ),
        (this, UpdateWindow::Within),
        (
            Instant::new(next.seconds() - 1, 999_999_999).unwrap(),
            UpdateWindow::Within,
        ),
        (next, UpdateWindow::Stale),
        (
            Instant::new(next.seconds() + 1, 0).unwrap(),
            UpdateWindow::Stale,
        ),
    ] {
        assert_eq!(
            single.update_window(now.into(), &utc, &execution).unwrap(),
            expected
        );
    }
    assert!(
        single
            .update_window(this.into(), &utc, &memory(0, 0))
            .unwrap_err()
            .is_resource()
    );
    let unknown = LeapTable::new(this.seconds() + 1, next.seconds() + 10, &[]).unwrap();
    assert!(matches!(
        single
            .update_window(this.into(), &unknown, &execution)
            .unwrap(),
        UpdateWindow::Uncertain(_)
    ));
    let bytes = response(&data(&assertion(&[0x80, 0])));
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    assert_eq!(
        parsed.responses()[0]
            .update_window(this.into(), &utc, &execution)
            .unwrap(),
        UpdateWindow::NoNextUpdate
    );
    assert_eq!(
        parsed.responses()[0]
            .update_window(
                Instant::new(this.seconds() - 1, 0).unwrap().into(),
                &utc,
                &execution
            )
            .unwrap(),
        UpdateWindow::NotYetCurrent
    );
    assert!(matches!(
        parsed.responses()[0]
            .update_window(this.into(), &unknown, &execution)
            .unwrap(),
        UpdateWindow::Uncertain(_)
    ));
}

#[test]
fn critical_demands_have_response_wide_or_selected_assertion_scope() {
    // RFC6960 §4.4's extension model does not make an unrelated assertion's
    // demand invalidate the selected assertion. Global demands affect all.
    use structured_pkix::ocsp::ExtensionProcessing;
    let unknown = [0x2a, 3, 4];
    let extension = |critical: bool| {
        let mut contents = tlv(6, &unknown);
        if critical {
            contents.extend(tlv(1, &[0xff]));
        }
        contents.extend(tlv(4, &[5, 0]));
        tlv(48, &contents)
    };
    let single = assertion(&[0x80, 0]);
    assert!(single[1] < 128);
    let scoped_single = tlv(
        48,
        &[&single[2..], &tlv(0xa1, &tlv(48, &extension(true)))].concat(),
    );
    let bytes = response(&data(&[single.clone(), scoped_single].concat()));
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    assert!(matches!(
        parsed.check_extensions(&execution).unwrap(),
        ExtensionProcessing::Understood
    ));
    assert!(matches!(
        parsed.responses()[0].check_extensions(&execution).unwrap(),
        ExtensionProcessing::Understood
    ));
    assert!(
        matches!(parsed.responses()[1].check_extensions(&execution).unwrap(), ExtensionProcessing::Unsupported { kind, span } if kind.as_bytes() == unknown && span.start > 401)
    );
    for critical in [false, true] {
        let fields = [
            tlv(0xa2, &tlv(4, &[0x33; 20])),
            date(),
            tlv(48, &single),
            tlv(0xa1, &tlv(48, &extension(critical))),
        ]
        .concat();
        let bytes = response(&tlv(48, &fields));
        let parsed = decode_basic(&parser, &bytes, 401).unwrap();
        assert_eq!(
            matches!(
                parsed.check_extensions(&execution).unwrap(),
                ExtensionProcessing::Unsupported { .. }
            ),
            critical
        );
        assert!(
            parsed
                .check_extensions(&memory(0, 0))
                .unwrap_err()
                .is_resource()
        );
    }
}

#[test]
fn basic_response_retains_signed_der_hashes_dates_and_original_order() {
    // Decoding must never serialize ResponseData or collapse duplicate
    // assertions before the request-binding layer can detect ambiguity.
    let signed = data(&[assertion(&[0x80, 0]), assertion(&[0x82, 0])].concat());
    let bytes = response(&signed);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    assert_eq!(parsed.signed_bytes(), signed);
    let offset = usize::try_from(parsed.span().start - 401).unwrap();
    assert_eq!(parsed.as_bytes().as_ptr(), bytes[offset..].as_ptr());
    let signed_offset = bytes
        .windows(signed.len())
        .position(|window| window == signed)
        .unwrap();
    assert_eq!(
        parsed.signed_bytes().as_ptr(),
        bytes[signed_offset..].as_ptr()
    );
    assert_eq!(parsed.responses().len(), 2);
    assert_eq!(parsed.responses()[0].status(), Status::Good);
    assert_eq!(parsed.responses()[1].status(), Status::Unknown);
    assert_eq!(
        parsed.responses()[0].id().serial().as_bytes(),
        &[1, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(parsed.responses()[0].id().issuer_name_hash(), &[0x11; 20]);
    assert_eq!(parsed.responses()[0].id().issuer_key_hash(), &[0x22; 20]);
    assert_eq!(parsed.responses()[0].next_update(), None);
    let ResponderId::KeyHash(hash) = parsed.responder() else {
        panic!("missing key hash")
    };
    assert_eq!(*hash, &[0x33; 20]);
    assert!(execution.used() > 0);
    drop(parsed);
    assert_eq!(execution.used(), 0);
}

#[test]
fn unsigned_failures_and_unsupported_types_never_become_signed_statuses() {
    // RFC6960 §4.2.1 excludes responseBytes on error. Unsupported successful
    // response types preserve their original bytes without claiming a proof.
    let parser = Parser::der(memory(128 * 1024, 1_000_000));
    for (code, expected) in [
        (1, Failure::MalformedRequest),
        (2, Failure::InternalError),
        (3, Failure::TryLater),
        (5, Failure::SignatureRequired),
        (6, Failure::Unauthorized),
    ] {
        let bytes = tlv(48, &[10, 1, code]);
        let Response::Failure { failure, span } = Response::read(&parser, &bytes, 401).unwrap()
        else {
            panic!("signed failure")
        };
        assert_eq!(failure, expected);
        assert_eq!(span.start, 401);
    }
    let bytes = tlv(48, &[10, 1, 4]);
    assert_eq!(
        Response::read(&parser, &bytes, 401).unwrap_err().code(),
        ErrorCode::MalformedValue
    );
    let bytes = envelope(b"opaque", &[0x2a, 3, 4]);
    let Response::Successful(response_bytes) = Response::read(&parser, &bytes, 401).unwrap() else {
        panic!("unknown type was interpreted")
    };
    let (kind, payload, span) = (
        response_bytes.kind(),
        response_bytes.payload(),
        response_bytes.span(),
    );
    assert_eq!(kind.as_bytes(), &[0x2a, 3, 4]);
    assert_eq!(payload, b"opaque");
    assert_eq!(
        payload.as_ptr(),
        bytes[usize::try_from(span.start - 401).unwrap()..].as_ptr()
    );
    assert!(
        response_bytes
            .into_basic(parser.memory())
            .unwrap()
            .is_none()
    );
    let bytes = tlv(48, &[&[10, 1, 1][..], &tlv(0xa0, &[])].concat());
    assert_eq!(
        Response::read(&parser, &bytes, 401).unwrap_err().code(),
        ErrorCode::TrailingData
    );
}

#[test]
fn revoked_info_and_explicit_default_version_use_the_selected_schema() {
    // RevokedInfo is implicit SEQUENCE; responder identity/version wrappers
    // are explicit. DER omits DEFAULT v1 even when its integer value is zero.
    let revoked = tlv(0xa1, &[date(), tlv(0xa0, &[10, 1, 6])].concat());
    let bytes = response(&data(&assertion(&revoked)));
    let parser = Parser::der(memory(128 * 1024, 1_000_000));
    let parsed = decode_basic(&parser, &bytes, 401).unwrap();
    assert!(matches!(
        parsed.responses()[0].status(),
        Status::Revoked {
            reason: Some(structured_pkix::crl::Reason::CertificateHold),
            ..
        }
    ));
    let Status::Revoked { time, .. } = parsed.responses()[0].status() else {
        panic!("fixture must be revoked");
    };
    let instant = time.instant();
    let utc = structured_pkix::temporal::LeapTable::new(
        instant.seconds() - 10,
        instant.seconds() + 10,
        &[],
    )
    .unwrap();
    assert_eq!(
        parsed.responses()[0]
            .revocation_relation(instant.into(), &utc, parser.memory())
            .unwrap(),
        Some(structured_pkix::time::Relation::At)
    );
    let error = parsed.responses()[0]
        .revocation_relation(instant.into(), &utc, &memory(0, 0))
        .unwrap_err();
    assert!(error.is_resource());
    let date_offset = bytes
        .windows(date().len())
        .rposition(|window| window == date())
        .unwrap();
    // Last date is thisUpdate, so locate the earlier date inside the RevokedInfo.
    let earlier = bytes[..date_offset]
        .windows(date().len())
        .rposition(|window| window == date())
        .unwrap();
    assert_eq!(error.offset(), 401 + u64::try_from(earlier).unwrap());
    for (version, expected) in [
        (0, ErrorCode::MalformedValue),
        (1, ErrorCode::UnsupportedVersion),
    ] {
        let signed = tlv(
            48,
            &[
                tlv(0xa0, &[2, 1, version]),
                tlv(0xa2, &tlv(4, &[0x33; 20])),
                date(),
                tlv(48, &assertion(&[0x80, 0])),
            ]
            .concat(),
        );
        let bytes = response(&signed);
        assert_eq!(
            decode_basic(&parser, &bytes, 401).unwrap_err().code(),
            expected
        );
    }
}

#[test]
fn nested_payload_preserves_depth_work_storage_and_offset_boundaries() {
    // Basic payload decoding keeps the enclosing logical depth and budget;
    // neither allocation failure nor resource exhaustion becomes a status.
    let bytes = response(&data(&assertion(&[0x80, 0])));
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        execution.clone(),
    );
    let error = decode_basic(&parser, &bytes, 401).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 401);
    assert_eq!(execution.used(), 0);
    let parser = Parser::der(memory(128 * 1024, 1_000_000));
    let mut reader = parser.read(&bytes, 401).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    for (storage, work) in [(0, 1_000_000), (128 * 1024, 0)] {
        let current = memory(storage, work);
        let rebound = reader.try_clone().unwrap().with_execution(&current);
        let error = Response::read_element(&rebound, &element).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(current.used(), 0);
    }
}
