//! TSA restrictions reuse original certificates without claiming their trust.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::timestamp::{TokenInfo, TsaIdentity, TsaUsage};
use structured_pkix::{Certificate, oid};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if bytes.len() < 128 {
        output.push(u8::try_from(bytes.len()).unwrap());
    } else if bytes.len() <= 255 {
        output.extend([0x81, u8::try_from(bytes.len()).unwrap()]);
    } else {
        output.push(0x82);
        output.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
    }
    output.extend(bytes);
    output
}
fn name() -> Vec<u8> {
    let mut attribute = tlv(6, oid::COMMON_NAME.as_bytes());
    attribute.extend(tlv(12, b"Authority"));
    tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)))
}
fn extension(kind: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut fields = tlv(6, kind);
    if critical {
        fields.extend([1, 1, 0xff]);
    }
    fields.extend(tlv(4, value));
    tlv(0x30, &fields)
}
fn certificate(critical: bool, purpose: &[u8], malformed_tail: bool) -> Vec<u8> {
    certificate_with_purposes(critical, &tlv(6, purpose), malformed_tail)
}
fn certificate_with_purposes(critical: bool, purposes: &[u8], malformed_tail: bool) -> Vec<u8> {
    // Synthetic syntax-only key/signature: the authority helper must not
    // pretend these establish arithmetic validity or a trusted certificate.
    let algorithm = [0x30, 3, 6, 1, 42];
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 1];
    tbs.extend(algorithm);
    tbs.extend(name());
    let mut validity = tlv(0x17, b"260101000000Z");
    validity.extend(tlv(0x17, b"270101000000Z"));
    tbs.extend(tlv(0x30, &validity));
    tbs.extend(name());
    let mut key = algorithm.to_vec();
    key.extend([3, 2, 0, 1]);
    tbs.extend(tlv(0x30, &key));
    let mut extensions = extension(
        oid::EXT_KEY_USAGE.as_bytes(),
        critical,
        &tlv(0x30, purposes),
    );
    let mut san = tlv(0x82, b"EXAMPLE.COM");
    if malformed_tail {
        san.extend([2, 1, 7]);
    }
    extensions.extend(extension(
        oid::SUBJECT_ALT_NAME.as_bytes(),
        false,
        &tlv(0x30, &san),
    ));
    tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
    let mut fields = tlv(0x30, &tbs);
    fields.extend(algorithm);
    fields.extend([3, 2, 0, 8]);
    tlv(0x30, &fields)
}
fn info() -> Vec<u8> {
    let mut fields = vec![
        2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 7, 8, 2, 1, 7,
    ];
    fields.extend(tlv(0x18, b"20260101000000Z"));
    fields.extend(tlv(0xa0, &tlv(0x82, b"example.com")));
    tlv(0x30, &fields)
}

fn token_with_certificates(certificates: Option<&[u8]>) -> Vec<u8> {
    let mut content = tlv(6, structured_cms::oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &info())));
    let mut fields = vec![2, 1, 3, 0x31, 0];
    fields.extend(tlv(0x30, &content));
    if let Some(certificates) = certificates {
        fields.extend(tlv(0xa0, certificates));
    }
    let signer = [
        2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8,
    ];
    fields.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut envelope = tlv(6, structured_cms::oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    tlv(0x30, &envelope)
}

#[test]
fn certificate_request_checks_presence_and_exact_selected_certificate() {
    // FALSE forbids the field itself, including an empty catalogue. TRUE
    // requires the exact selected DER certificate, not merely its SID/key.
    use structured_cms::timestamp::{Request, Token};
    let cert_bytes = certificate(true, oid::TIME_STAMPING.as_bytes(), false);
    let mut other_bytes = cert_bytes.clone();
    *other_bytes.last_mut().unwrap() ^= 1;
    let cert_parser = Parser::der(memory());
    let selected = Certificate::read(&cert_parser, &cert_bytes, 700).unwrap();
    for (requested, carried, expected) in [
        (false, None, true),
        (false, Some(&[][..]), false),
        (false, Some(cert_bytes.as_slice()), false),
        (true, None, false),
        (true, Some(other_bytes.as_slice()), false),
        (true, Some(cert_bytes.as_slice()), true),
    ] {
        let mut request_fields = vec![2, 1, 1, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 7, 8];
        if requested {
            request_fields.extend([1, 1, 0xff]);
        }
        let request_bytes = tlv(0x30, &request_fields);
        let request_parser = Parser::der(memory());
        let mut request_parent = request_parser.read(&request_bytes, 900).unwrap();
        let request_element = request_parent.next_element().unwrap().unwrap();
        let request = Request::read(&request_parent, &request_element).unwrap();
        let token_bytes = token_with_certificates(carried);
        let token_parser = Parser::ber(memory());
        let token = Token::read(&token_parser, &token_bytes, 400).unwrap();
        let token_parent = token_parser.read(&[], 400).unwrap();
        assert_eq!(
            token
                .matches_cert_req(&request, Some(&selected), &token_parent, &request_parent)
                .unwrap(),
            expected
        );
        if requested {
            assert!(
                !token
                    .matches_cert_req(&request, None, &token_parent, &request_parent)
                    .unwrap()
            );
        }
        let foreign = cert_parser.read(&[], 700).unwrap();
        assert!(
            token
                .matches_cert_req(&request, Some(&selected), &token_parent, &foreign)
                .unwrap_err()
                .source
                .is_terminal()
        );
    }
}

#[test]
fn exclusive_critical_usage_and_shared_dns_binding_do_not_claim_trust() {
    // Different source sessions/accounts are legitimate. Lazy decoding and
    // comparison spend the current token account while source storage stays put.
    for (critical, purpose, expected) in [
        (true, oid::TIME_STAMPING, 0),
        (false, oid::TIME_STAMPING, 1),
        (true, oid::OCSP_SIGNING, 2),
    ] {
        let current = memory();
        let storage = memory();
        let token_parser = Parser::ber(current.clone());
        let cert_parser = Parser::der(storage.clone());
        let token_bytes = info();
        let cert_bytes = certificate(critical, purpose.as_bytes(), false);
        let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
        let element = token_parent.next_element().unwrap().unwrap();
        let info = TokenInfo::read(&token_parent, &element).unwrap();
        let mut cert_parent = cert_parser.read(&cert_bytes, 900).unwrap();
        let element = cert_parent.next_element().unwrap().unwrap();
        let cert = Certificate::read_element(&cert_parent, &element).unwrap();
        let old_work = storage.work_used();
        let old_storage = storage.used();
        let old_current = current.work_used();
        let facts = info.authority(&cert, &token_parent, &cert_parent).unwrap();
        assert!(matches!(facts.identity, TsaIdentity::Matches));
        assert!(match expected {
            0 => matches!(facts.usage, TsaUsage::TimeStampingOnly),
            1 => matches!(facts.usage, TsaUsage::NotCritical),
            2 => matches!(facts.usage, TsaUsage::OtherPurposes),
            _ => unreachable!(),
        });
        assert_eq!(storage.work_used(), old_work);
        assert_eq!(storage.used(), old_storage);
        assert!(current.work_used() > old_current);
    }
}

#[test]
fn malformed_san_tail_cannot_hide_behind_an_earlier_match() {
    // Early matching DNS does not validate the remainder. Preserve the original
    // certificate-located syntax cause instead of returning a positive identity.
    let token_parser = Parser::ber(memory());
    let cert_parser = Parser::der(memory());
    let token_bytes = info();
    let cert_bytes = certificate(true, oid::TIME_STAMPING.as_bytes(), true);
    let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&token_parent, &element).unwrap();
    let mut cert_parent = cert_parser.read(&cert_bytes, 900).unwrap();
    let element = cert_parent.next_element().unwrap().unwrap();
    let cert = Certificate::read_element(&cert_parent, &element).unwrap();
    let facts = info.authority(&cert, &token_parent, &cert_parent).unwrap();
    let TsaIdentity::CertificateUnreadable(error) = facts.identity else {
        panic!("malformed remainder must remain unreadable")
    };
    assert_eq!(
        cert_bytes[usize::try_from(error.offset() - 900).unwrap()],
        2
    );
    assert_eq!(error.field(), "extensions.subjectAltName");
    assert!(!error.is_terminal());
}

#[test]
fn already_parsed_certificate_cannot_bypass_current_query_local_work() {
    // Both source documents were read under ample budgets. A later operation
    // has only its cursor-admission unit; lookup/lazy work cannot use that old
    // parse or the ample aggregate account as a credit or report a mismatch.
    use structured_asn1::{Encoding, Limits};
    use structured_cms::timestamp::AuthoritySource;
    let token_parser = Parser::ber(memory());
    let cert_parser = Parser::der(memory());
    let token_bytes = info();
    let cert_bytes = certificate(true, oid::TIME_STAMPING.as_bytes(), false);
    let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&token_parent, &element).unwrap();
    let mut cert_parent = cert_parser.read(&cert_bytes, 900).unwrap();
    let element = cert_parent.next_element().unwrap().unwrap();
    let cert = Certificate::read_element(&cert_parent, &element).unwrap();
    let current = memory();
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 0).unwrap();
    let token_parent = token_parent.with_query(&query).unwrap();
    let error = info
        .authority(&cert, &token_parent, &cert_parent)
        .unwrap_err();
    assert_eq!(error.source, AuthoritySource::Certificate);
    assert!(error.cause.is_resource());
    assert!(error.cause.offset() >= 900);
    assert_eq!(current.work_used(), 1);
    assert_eq!(current.used(), 0);
}

#[test]
fn lazy_eku_catalogue_cannot_spend_outside_current_query_work() {
    // Borrowed original extnValue is not credit for lazy catalogue allocation.
    // Headers and repeated-purpose map/vector costs must fit one current local
    // ceiling; aggregate spend exceeding that ceiling reveals a dropped bridge.
    use structured_asn1::{Encoding, Limits};
    use structured_cms::timestamp::AuthoritySource;
    let token_parser = Parser::ber(memory());
    let storage = memory();
    let cert_parser = Parser::der(storage.clone());
    let token_bytes = info();
    let mut purposes = Vec::new();
    for _ in 0..64 {
        purposes.extend(tlv(6, oid::TIME_STAMPING.as_bytes()));
    }
    let cert_bytes = certificate_with_purposes(true, &purposes, false);
    let mut token_parent = token_parser.read(&token_bytes, 400).unwrap();
    let element = token_parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&token_parent, &element).unwrap();
    let mut cert_parent = cert_parser.read(&cert_bytes, 900).unwrap();
    let element = cert_parent.next_element().unwrap().unwrap();
    let cert = Certificate::read_element(&cert_parent, &element).unwrap();
    let old_work = storage.work_used();
    let old_storage = storage.used();
    let current = memory();
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 100,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 0).unwrap();
    let token_parent = token_parent.with_query(&query).unwrap();
    let error = info
        .authority(&cert, &token_parent, &cert_parent)
        .unwrap_err();
    assert_eq!(error.source, AuthoritySource::Certificate);
    assert_eq!(error.cause.field(), "extensions.extKeyUsage");
    assert!(error.cause.is_resource());
    assert!(current.work_used() <= 100);
    assert_eq!(current.used(), 0);
    assert_eq!(storage.work_used(), old_work);
    assert_eq!(storage.used(), old_storage);
}
