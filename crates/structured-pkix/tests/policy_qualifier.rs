//! Public selected-schema and execution-boundary qualification.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_pkix::{ErrorCode, oid, policy};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn check(parser: &Parser, kind: Oid<'_>, bytes: &[u8]) -> structured_pkix::Result<bool> {
    let mut reader = parser.read(bytes, 101).unwrap();
    let value = reader.next_element().unwrap().unwrap();
    policy::qualifier_understood(&reader, kind, &value)
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if contents.len() < 128 {
        output.push(u8::try_from(contents.len()).unwrap());
    } else if contents.len() < 256 {
        output.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    } else {
        output.push(0x82);
        output.extend_from_slice(&u16::try_from(contents.len()).unwrap().to_be_bytes());
    }
    output.extend_from_slice(contents);
    output
}

#[test]
fn display_text_counts_characters_and_notice_reference_keeps_integer_syntax() {
    // DisplayText SIZE counts characters, not UTF8/BMP octets. NoticeReference
    // numbers are INTEGER, including negatives, rather than unsigned serials.
    let parser = Parser::der(memory(64 * 1024, 1_000_000));
    for count in [0, 200, 201] {
        for (tag, contents) in [
            (12, "é".repeat(count).into_bytes()),
            (30, [0, b'A'].repeat(count)),
            (22, vec![b'A'; count]),
            (26, vec![b'A'; count]),
        ] {
            let value = tlv(48, &tlv(tag, &contents));
            assert_eq!(
                check(&parser, oid::USER_NOTICE_QUALIFIER, &value).unwrap(),
                count == 200
            );
        }
    }
    let numbers = tlv(48, &[2, 1, 0xff, 2, 1, 0]);
    let reference = tlv(48, &[tlv(12, b"A"), numbers].concat());
    assert!(check(&parser, oid::USER_NOTICE_QUALIFIER, &tlv(48, &reference)).unwrap());
    for reference in [
        tlv(48, &tlv(12, b"A")),
        tlv(48, &[tlv(12, b"A"), tlv(48, &[1, 1, 0xff])].concat()),
    ] {
        assert!(!check(&parser, oid::USER_NOTICE_QUALIFIER, &tlv(48, &reference)).unwrap());
    }
    assert!(
        !check(
            &parser,
            oid::USER_NOTICE_QUALIFIER,
            &[48, 6, 12, 1, b'A', 12, 1, b'B']
        )
        .unwrap()
    );
}

#[test]
fn cps_uri_validation_has_generic_uri_component_boundaries() {
    // CPS pointers need URI syntax, not a certificate-name or HTTP policy.
    // They remain data; neither a valid scheme nor an authority causes fetching.
    let parser = Parser::der(memory(0, 1_000_000));
    for uri in [
        "file:///tmp/cps",
        "https://local_host/cps",
        "https://%41.example/cps#part",
        "urn:a",
        "https://[::1]:443/cps",
    ] {
        assert!(
            check(&parser, oid::CPS_QUALIFIER, &tlv(22, uri.as_bytes())).unwrap(),
            "{uri}"
        );
    }
    for uri in [
        "relative/cps",
        "https://example.com/%GG",
        "https://example.com/cps#one#two",
        "https://user@bad@example.com/cps",
        "https://[bad]/cps",
        "https://example.com:port/cps",
    ] {
        assert!(
            !check(&parser, oid::CPS_QUALIFIER, &tlv(22, uri.as_bytes())).unwrap(),
            "{uri}"
        );
    }
    assert_eq!(parser.memory().used(), 0);
}

#[test]
fn known_qualifiers_validate_the_selected_schema() {
    // The OID selects the syntax. DER INTEGER is not CPSuri/DisplayText;
    // both optional UserNotice fields may be absent without malformation.
    let parser = Parser::der(memory(64 * 1024, 1_000_000));
    for (kind, bytes, understood) in [
        (oid::CPS_QUALIFIER, &[2, 1, 1][..], false),
        (oid::CPS_QUALIFIER, &[22, 1, 0xff][..], false),
        (
            oid::CPS_QUALIFIER,
            &[22, 5, b'u', b'r', b'n', b':', b'a'][..],
            true,
        ),
        (oid::USER_NOTICE_QUALIFIER, &[2, 1, 1][..], false),
        (oid::USER_NOTICE_QUALIFIER, &[48, 3, 2, 1, 1][..], false),
        (oid::USER_NOTICE_QUALIFIER, &[48, 0][..], true),
        (oid::USER_NOTICE_QUALIFIER, &[48, 3, 12, 1, b'A'][..], true),
        (oid::USER_NOTICE_QUALIFIER, &[48, 3, 22, 1, b'A'][..], true),
        (oid::USER_NOTICE_QUALIFIER, &[48, 3, 26, 1, b'A'][..], true),
        (
            oid::USER_NOTICE_QUALIFIER,
            &[48, 4, 30, 2, 0, b'A'][..],
            true,
        ),
        (
            oid::USER_NOTICE_QUALIFIER,
            &[48, 4, 30, 2, 0xd8, 0][..],
            false,
        ),
        (
            oid::USER_NOTICE_QUALIFIER,
            &[48, 7, 48, 5, 12, 1, b'A', 48, 0][..],
            true,
        ),
    ] {
        assert_eq!(
            check(&parser, kind, bytes).unwrap(),
            understood,
            "{bytes:?}"
        );
    }
    // An unknown kind is unhandled, not a decoding error or a mutation of
    // the caller's preserved value, even when that value is not a known schema.
    let unknown = Oid::from_bytes(&[42, 3]);
    assert!(!check(&parser, unknown, &[2, 1, 1]).unwrap());
}

#[test]
fn ber_envelope_does_not_weaken_known_qualifier_der() {
    // Reread the original bytes, not a regenerated value, under the selected
    // DER contract. Nonminimal headers and indefinite UserNotice stay false.
    let parser = Parser::ber(memory(64 * 1024, 1_000_000));
    assert!(
        check(
            &parser,
            oid::CPS_QUALIFIER,
            &[22, 5, b'u', b'r', b'n', b':', b'a']
        )
        .unwrap()
    );
    assert!(
        !check(
            &parser,
            oid::CPS_QUALIFIER,
            &[22, 0x81, 5, b'u', b'r', b'n', b':', b'a']
        )
        .unwrap()
    );
    assert!(!check(&parser, oid::USER_NOTICE_QUALIFIER, &[48, 0x80, 0, 0]).unwrap());
}

#[test]
fn resource_refusals_preserve_current_account_and_document_location() {
    // A retained producing Reader rebinds execution without transferring its
    // old storage charge. Work/storage refusal must never become false.
    let storage = memory(64 * 1024, 1_000_000);
    let parser = Parser::ber(storage.clone());
    let bytes = [48, 0];
    let mut reader = parser.read(&bytes, 101).unwrap();
    let value = reader.next_element().unwrap().unwrap();
    let before = storage.work_used();
    let refused = memory(64 * 1024, 0);
    let current = reader.with_execution(&refused);
    let error =
        policy::qualifier_understood(&current, oid::USER_NOTICE_QUALIFIER, &value).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 101);
    assert_eq!(refused.work_used(), 0);
    assert_eq!(storage.work_used(), before);

    let refused = memory(0, 100_000);
    let current = current.with_execution(&refused);
    let error =
        policy::qualifier_understood(&current, oid::USER_NOTICE_QUALIFIER, &value).unwrap_err();
    assert!(error.is_resource());
    // Enter reports the original content boundary, after the two-byte header.
    assert_eq!(error.offset(), 103);
    assert_eq!(refused.used(), 0);
}

#[test]
fn parser_local_depth_and_work_cannot_be_reset_by_validation() {
    // The shared account has plenty of work; the producing parser's smaller
    // local ceilings still apply, including a reread from a BER envelope.
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(64 * 1024, 1_000_000),
    );
    let error = check(&parser, oid::USER_NOTICE_QUALIFIER, &[48, 0]).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Depth
        ))
    );
    assert_eq!(error.offset(), 103);

    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 100,
            ..Limits::default()
        },
        memory(64 * 1024, 1_000_000),
    );
    let mut bytes = vec![22, 120];
    bytes.extend_from_slice(b"https://example.com/");
    bytes.resize(122, b'x');
    let error = check(&parser, oid::CPS_QUALIFIER, &bytes).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
    assert_eq!(error.offset(), 101);
    assert_eq!(parser.memory().used(), 0);
}
