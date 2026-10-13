//! Public identity queries and producing-reader budget boundaries.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::general_name::{self, GeneralName};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn dns_and_mailbox_identity_keep_distinct_case_rules() {
    // RFC9549 §§2.3/2.5: DNS is whole-name case-insensitive; mailbox local
    // parts are exact. Equality must not become wildcard or subtree matching.
    let execution = memory(0, 4096);
    assert!(
        GeneralName::Dns("EXAMPLE.COM")
            .matches(&GeneralName::Dns("example.com"), &execution)
            .unwrap()
    );
    assert!(
        !GeneralName::Dns("example.com")
            .matches(&GeneralName::Dns("sub.example.com"), &execution)
            .unwrap()
    );
    assert!(
        GeneralName::Email("Alice@EXAMPLE.COM")
            .matches(&GeneralName::Email("Alice@example.com"), &execution)
            .unwrap()
    );
    assert!(
        !GeneralName::Email("Alice@example.com")
            .matches(&GeneralName::Email("alice@example.com"), &execution)
            .unwrap()
    );
    assert!(
        GeneralName::Email("\"a@b\"@EXAMPLE.COM")
            .matches(&GeneralName::Email("\"a@b\"@example.com"), &execution)
            .unwrap()
    );
    assert_eq!(execution.used(), 0);
}

#[test]
fn equivalent_mailbox_quoting_preserves_local_case_and_literal_octets() {
    // RFC5321 §4.1.2 requires equivalent quoted forms when comparing a
    // local-part. Quoting changes spelling, never its case-sensitive identity.
    let execution = memory(0, 4096);
    for (left, right, expected) in [
        ("\"Alice\"@example.com", "Alice@EXAMPLE.COM", true),
        ("\"Al\\ice\"@example.com", "Alice@example.com", true),
        ("\"a\\@b\"@example.com", "\"a@b\"@example.com", true),
        ("\"Alice\"@example.com", "alice@example.com", false),
        ("\"a\\\\b\"@example.com", "\"a\\b\"@example.com", false),
    ] {
        assert_eq!(
            GeneralName::Email(left)
                .matches(&GeneralName::Email(right), &execution)
                .unwrap(),
            expected
        );
    }
    assert_eq!(execution.used(), 0);
}

#[test]
fn producing_queries_keep_both_ceilings_and_explicit_location() {
    // Neither a spare aggregate domain nor a spare parser ceiling authorizes
    // comparison when the other is exhausted; refusal is never false.
    for (local, aggregate) in [(0, 4096), (4096, 0)] {
        let execution = memory(4096, aggregate);
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            execution.clone(),
        );
        let reader = parser.read(&[], 400).unwrap();
        let error = general_name::matches(
            &reader,
            &GeneralName::Dns("EXAMPLE.COM"),
            &GeneralName::Dns("example.com"),
            777,
            "tstInfo.tsa",
        )
        .unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 777);
        assert_eq!(error.field(), "tstInfo.tsa");
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn decoded_repeated_tsa_dns_names_match_without_changing_the_first_encoding() {
    // The real adapter boundary is an explicit TSA wrapper with two readable
    // names. The common mechanism compares them but preserves the first bytes;
    // the consumer owns one DuplicateField fault and retention/recovery policy.
    let mut contents = tlv(0x82, b"EXAMPLE.COM");
    contents.extend_from_slice(&tlv(0x82, b"example.com"));
    let bytes = tlv(0xa0, &contents);
    let execution = memory(4096, 100_000);
    let parser = Parser::ber(execution.clone());
    let mut outer = parser.read(&bytes, 400).unwrap();
    let wrapper = outer.next_element().unwrap().unwrap();
    let mut inside = outer.enter(&wrapper).unwrap();
    let first = inside.next_element().unwrap().unwrap();
    let repeated = inside.next_element().unwrap().unwrap();
    let left = general_name::read(&inside, &first, "tstInfo.tsa").unwrap();
    let right = general_name::read(&inside, &repeated, "tstInfo.tsa").unwrap();
    assert!(
        general_name::matches(&inside, &left, &right, repeated.span().start, "tstInfo.tsa")
            .unwrap()
    );
    assert_eq!(first.contents(), b"EXAMPLE.COM");
    assert_eq!(repeated.span().start, 415);
    assert!(inside.is_empty());

    let unfunded = memory(4096, 0);
    let inside = inside.with_execution(&unfunded);
    let error = general_name::matches(&inside, &left, &right, repeated.span().start, "tstInfo.tsa")
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 415);
    assert_eq!(error.field(), "tstInfo.tsa");
    assert_eq!(unfunded.used(), 0);
    assert_eq!(first.contents(), b"EXAMPLE.COM");
}

#[test]
fn opaque_and_mask_identity_does_not_authorize_containment() {
    // A preserved unsupported syntax has encoded identity only. Likewise,
    // address/mask octets are values to compare, not a subnet membership test.
    let execution = memory(0, 4096);
    let mask = [192, 0, 2, 0, 255, 255, 255, 0];
    assert!(
        GeneralName::IpAddress(&mask)
            .matches(&GeneralName::IpAddress(&mask), &execution)
            .unwrap()
    );
    assert!(
        !GeneralName::IpAddress(&mask)
            .matches(&GeneralName::IpAddress(&[192, 0, 2, 1]), &execution)
            .unwrap()
    );
    assert!(
        GeneralName::EdiParty(b"encoded")
            .matches(&GeneralName::EdiParty(b"encoded"), &execution)
            .unwrap()
    );
    assert!(
        !GeneralName::X400(b"encoded")
            .matches(&GeneralName::EdiParty(b"encoded"), &execution)
            .unwrap()
    );
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if contents.len() < 128 {
        bytes.push(u8::try_from(contents.len()).unwrap());
    } else {
        let length = contents.len().to_be_bytes();
        let start = length.iter().position(|byte| *byte != 0).unwrap();
        bytes.push(0x80 | u8::try_from(length.len() - start).unwrap());
        bytes.extend_from_slice(&length[start..]);
    }
    bytes.extend_from_slice(contents);
    bytes
}

fn directory(value: &[u8]) -> Vec<u8> {
    let mut attribute = tlv(0x06, &[0x55, 0x04, 0x03]);
    attribute.extend_from_slice(value);
    tlv(0xa4, &tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute))))
}

#[test]
fn constructed_directory_strings_share_the_producing_semantic_core() {
    // X.690 §8.23 permits segmented restricted strings in BER. A valid
    // constructed UTF8String and a primitive spelling have one DN identity;
    // flattening must neither reset the parser budget nor change source bytes.
    let left = directory(&tlv(0x2c, &tlv(0x04, "\u{212a}".as_bytes())));
    let right = directory(&tlv(0x0c, b"k"));
    let execution = memory(65_536, 100_000);
    let parser = Parser::ber(execution.clone());
    let mut first = parser.read(&left, 400).unwrap();
    let first_element = first.next_element().unwrap().unwrap();
    let first_name = general_name::read(&first, &first_element, "tsa").unwrap();
    let mut second = parser.read(&right, 800).unwrap();
    let second_element = second.next_element().unwrap().unwrap();
    let second_name = general_name::read(&second, &second_element, "tsa").unwrap();
    let retained = execution.used();
    assert!(general_name::matches(&second, &first_name, &second_name, 800, "tsa").unwrap());
    assert!(first_name.matches(&second_name, &execution).unwrap());
    assert_eq!(execution.used(), retained);
    assert_eq!(first_element.as_bytes(), left);
    assert_eq!(second_element.as_bytes(), right);
}

#[test]
fn uri_queries_normalize_without_losing_reserved_component_identity() {
    // RFC5280 §7.4 requires syntax and recognized-scheme normalization,
    // while percent-encoded reserved delimiters and fragment presence differ.
    let execution = memory(65_536, 100_000);
    let parser = Parser::ber(execution.clone());
    let reader = parser.read(&[], 400).unwrap();
    for (left, right, expected) in [
        (
            "HTTP://EXAMPLE.COM:080/a/../%7e",
            "http://example.com/~",
            true,
        ),
        ("https://EXAMPLE.COM:443", "https://example.com/", true),
        (
            "ldap://EXAMPLE.COM:389/??BASE?(objectClass=*)",
            "ldap://example.com/",
            true,
        ),
        ("ftp://EXAMPLE.COM:21", "ftp://example.com/", true),
        ("http://example.com/a%2fb", "http://example.com/a/b", false),
        ("http://example.com/", "http://example.com/#", false),
        ("http://example.com/?", "http://example.com/", false),
    ] {
        let left = GeneralName::Uri(left);
        let right = GeneralName::Uri(right);
        assert_eq!(left.matches(&right, &execution).unwrap(), expected);
        assert_eq!(
            general_name::matches(&reader, &left, &right, 777, "tsa").unwrap(),
            expected
        );
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn directory_scratch_and_work_use_current_domain_without_resetting_the_session() {
    // Retained names belong to A; comparison scratch belongs to B. Unicode
    // allocation refusal must leave A's held capacity/work untouched, and a
    // new aggregate account must not refill the original parser ceiling.
    let left = directory(&tlv(0x0c, "\u{212a}".as_bytes()));
    let right = directory(&tlv(0x0c, b"k"));
    let original = memory(65_536, 100_000);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 20_000,
            ..Limits::default()
        },
        original.clone(),
    );
    let mut first = parser.read(&left, 400).unwrap();
    let element = first.next_element().unwrap().unwrap();
    let first_name = general_name::read(&first, &element, "tsa").unwrap();
    let mut second = parser.read(&right, 800).unwrap();
    let element = second.next_element().unwrap().unwrap();
    let second_name = general_name::read(&second, &element, "tsa").unwrap();
    let held = original.used();
    let spent = original.work_used();

    let no_storage = memory(0, 100_000);
    let rebound = second.with_execution(&no_storage);
    let error =
        general_name::matches(&rebound, &first_name, &second_name, 777, "tstInfo.tsa").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 777);
    assert_eq!(error.field(), "tstInfo.tsa");
    assert_eq!(no_storage.used(), 0);
    assert_eq!(original.used(), held);
    assert_eq!(original.work_used(), spent);

    let fresh = memory(65_536, 100_000);
    let rebound = rebound.with_execution(&fresh);
    while rebound.charge(256).is_ok() {}
    let error =
        general_name::matches(&rebound, &first_name, &second_name, 777, "tstInfo.tsa").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 777);
    assert_eq!(error.field(), "tstInfo.tsa");
    assert_eq!(fresh.used(), 0);
    assert_eq!(original.used(), held);
    assert_eq!(original.work_used(), spent);
}

#[test]
fn uri_partial_scratch_refusal_is_located_and_releases_every_allocation() {
    // Admit one normalization buffer but refuse its successor. Both local and
    // global refusal preserve source location and roll back temporary capacity.
    for (storage, local, aggregate) in [
        (24, 20_000, 100_000),
        (4096, 300, 100_000),
        (4096, 20_000, 300),
    ] {
        let execution = memory(storage, aggregate);
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            execution.clone(),
        );
        let reader = parser.read(&[], 400).unwrap();
        let error = general_name::matches(
            &reader,
            &GeneralName::Uri("http://EXAMPLE.com/a"),
            &GeneralName::Uri("http://example.com/a"),
            777,
            "tsa",
        )
        .unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 777);
        assert_eq!(error.field(), "tsa");
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn retained_directory_query_has_no_hidden_default_parser_depth_ceiling() {
    // A retained query pays the current Memory rather than a new default
    // parser profile. Valid BER nesting accepted by the producing parser must
    // remain comparable when the caller funds the iterative traversal.
    let mut value = tlv(0x04, b"k");
    for _ in 0..1002 {
        value = tlv(0x24, &value);
    }
    let left = directory(&tlv(0x2c, &value));
    let right = directory(&tlv(0x0c, b"k"));
    let execution = memory(16 * 1024 * 1024, 100_000_000);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 2000,
            max_work: 100_000_000,
            ..Limits::default()
        },
        execution.clone(),
    );
    let mut first = parser.read(&left, 400).unwrap();
    let element = first.next_element().unwrap().unwrap();
    let first_name = general_name::read(&first, &element, "tsa").unwrap();
    let mut second = parser.read(&right, 800).unwrap();
    let element = second.next_element().unwrap().unwrap();
    let second_name = general_name::read(&second, &element, "tsa").unwrap();
    let held = execution.used();
    assert!(first_name.matches(&second_name, &execution).unwrap());
    assert_eq!(execution.used(), held);
}
