//! Request syntax retains its own producing source and never creates fake IDs.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{ErrorCode, timestamp::Request};

fn request(optional: &[u8]) -> Vec<u8> {
    let mut fields = vec![2, 1, 1, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 7, 8];
    fields.extend(optional);
    let mut bytes = vec![0x30, u8::try_from(fields.len()).unwrap()];
    bytes.extend(fields);
    bytes
}

#[test]
fn ordered_optional_fields_and_default_keep_original_views() {
    // certReq absence is its normative false default, not an implicit product
    // policy. Nonce and policy continue to borrow the original request source.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    for (optional, cert_req) in [
        (&[][..], false),
        (&[6, 1, 43, 2, 1, 9, 1, 1, 0xff][..], true),
    ] {
        let bytes = request(optional);
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parsed = Request::read(&parent, &element).unwrap();
        assert_eq!(parsed.cert_req(), cert_req);
        assert_eq!(
            parsed.nonce().map(|n| n.as_u64().unwrap()),
            if cert_req { Some(9) } else { None }
        );
        assert_eq!(
            parsed.policy().map(structured_asn1::Oid::as_bytes),
            if cert_req { Some(&[43][..]) } else { None }
        );
        assert!(parsed.same_session(&parent));
        assert_eq!(parsed.imprint().hashed().as_one(), Some(&[7, 8][..]));
        drop(parsed);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn duplicate_and_out_of_order_request_fields_are_not_recovered() {
    // Requests have no token-inspection recovery contract. Repeated nonce or
    // reordered policy must refuse rather than selecting one caller context.
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    for (optional, code) in [
        (&[2, 1, 9, 2, 1, 9][..], ErrorCode::DuplicateField),
        (&[2, 1, 9, 6, 1, 43][..], ErrorCode::FieldOrder),
    ] {
        let bytes = request(optional);
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        assert_eq!(Request::read(&parent, &element).unwrap_err().code(), code);
    }
}

#[test]
fn request_version_requires_integer_tag_before_numeric_interpretation() {
    // Reader::integer is a value decoder, not a schema tag dispatcher. An OID
    // with contents 01 must not be treated as protocol version INTEGER 1.
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    let mut bytes = request(&[]);
    bytes[2] = 6;
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = Request::read(&parent, &element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedTag);
    assert_eq!(error.offset(), 402);
}

#[test]
fn written_cert_req_false_is_ber_only_not_a_der_default() {
    // X.690 §11.5 requires DEFAULT-valued fields to be absent in DER. BER may
    // carry the same explicit value; no permissive mode can change that rule.
    let bytes = request(&[1, 1, 0]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let ber = Parser::ber(memory.clone());
    let der = Parser::der(memory);
    let mut parent = ber.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    assert!(!Request::read(&parent, &element).unwrap().cert_req());
    let mut parent = der.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = Request::read(&parent, &element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::DefaultWritten);
    assert_eq!(error.offset(), 416);
}

#[test]
fn nonce_policy_facts_use_original_sessions_and_current_token_work() {
    // Legitimate request/token sessions differ. Nonminimal token INTEGER can
    // still be inspected numerically, while its fault prevents proof acceptance.
    // Resource refusal and caller session misuse must not become false/None.
    use structured_cms::timestamp::{ImprintOperand, RequestFields, TokenInfo};
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let token_parser = Parser::ber(memory.clone());
    let request_parser = Parser::ber(memory);
    let asked = request(&[6, 1, 43, 2, 1, 9]);
    let mut request_parent = request_parser.read(&asked, 900).unwrap();
    let element = request_parent.next_element().unwrap().unwrap();
    let requested = Request::read(&request_parent, &element).unwrap();
    let mut fields = vec![
        2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 7, 8, 2, 1, 7, 0x18, 15,
    ];
    fields.extend(b"20260101000000Z");
    fields.extend([2, 2, 0, 9]);
    let mut bytes = vec![0x30, u8::try_from(fields.len()).unwrap()];
    bytes.extend(fields);
    let mut parent = token_parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    assert!(info.has_faults());
    assert_eq!(
        info.matches_request_fields(&requested, &parent, &request_parent)
            .unwrap(),
        RequestFields {
            nonce: Some(true),
            policy: Some(true)
        }
    );
    let wrong = info
        .matches_request_fields(&requested, &parent, &parent)
        .unwrap_err();
    assert_eq!(wrong.operand, ImprintOperand::Requested);
    assert!(wrong.source.is_terminal());
    let exhausted = Memory::new(Arc::new(MemoryAccount::new(65536, 0)));
    let query = parent.with_execution(&exhausted);
    let error = info
        .matches_request_fields(&requested, &query, &request_parent)
        .unwrap_err();
    assert_eq!(error.operand, ImprintOperand::Token);
    assert!(error.source.is_resource());
    assert_eq!(error.source.offset(), 400);
}
#[test]
fn request_recognition_visits_noncritical_extensions_and_preserves_refusal() {
    // RFC3161 request recognition includes both critical and noncritical
    // extensions. Reusing the token critical-only route would lose the first.
    let members = [
        0x30, 8, 6, 1, 42, 4, 3, 2, 1, 7, 0x30, 11, 6, 1, 43, 1, 1, 0xff, 4, 3, 2, 1, 8,
    ];
    let mut extensions = vec![0xa0, u8::try_from(members.len()).unwrap()];
    extensions.extend(members);
    let bytes = request(&extensions);
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = Request::read(&parent, &element).unwrap();
    let mut calls = Vec::new();
    let unknown = parsed
        .unrecognized_extensions(&parent, |entry, _| {
            calls.push(entry.kind().as_bytes()[0]);
            Ok::<_, ()>(entry.is_critical())
        })
        .unwrap();
    assert_eq!(calls, [42, 43]);
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].as_bytes(), &[42]);
    let error = parsed
        .unrecognized_extensions(&parent, |_, _| Err::<bool, _>("capacity"))
        .unwrap_err();
    let structured_cms::timestamp::RecognitionError::Callback { source, span } = error else {
        panic!("handler failure became unrecognized");
    };
    assert_eq!(source, "capacity");
    assert!(span.start > parsed.span().start);
}
