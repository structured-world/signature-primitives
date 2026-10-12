//! Public codec qualification: identity, grammar, retained ownership and budgets.

use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::ErrorCode;
use structured_pkix::name::{self, Selector};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn singleton_comparisons_need_no_projection_allocation() {
    // Repeated certificate/selector matching must not materialize a borrowed
    // AVA catalogue. An ASCII singleton works with zero execution storage.
    let storage = memory(4096, 100_000);
    let left = Selector::parse("CN=ROOT", &storage).unwrap();
    let right = Selector::parse("2.5.4.3=root", &storage).unwrap();
    let bytes = [
        0x30, 15, 0x31, 13, 0x30, 11, 6, 3, 0x55, 4, 3, 0x0c, 4, b'r', b'o', b'o', b't',
    ];
    let parser = Parser::der(storage.clone());
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = name::read(&reader, &element, "name").unwrap();
    let execution = memory(0, 100_000);
    for _ in 0..10 {
        assert!(left.matches(&right, &execution).unwrap());
        assert!(left.matches_name(&name, &execution).unwrap());
    }
    assert_eq!(execution.used(), 0);
    assert!(execution.work_used() > 0);
}

#[test]
fn escaped_octets_are_decoded_once_and_rdn_order_is_preserved() {
    // Hex-escaped delimiters and a literal equals stay inside one value;
    // unordered AVAs compare equally but a reversed RDN sequence does not.
    let execution = memory(64 * 1024, 1_000_000);
    for (left, right) in [
        ("CN=A\\2CB\\+C=D", "cn=A\\,B\\2BC\\=D"),
        ("CN=\\C3\\A9", "CN=é"),
        ("CN=Straße", "CN=STRASSE"),
        ("SN=Doe", "surname=doe"),
        ("CN=A+OU=B,C=UA", "OU=b+CN=a,C=ua"),
        ("CN=\\\\2C", "CN=\\5C2C"),
        ("", ""),
    ] {
        let left = Selector::parse(left, &execution).unwrap();
        let right = Selector::parse(right, &execution).unwrap();
        assert!(left.matches(&right, &execution).unwrap());
    }
    let left = Selector::parse("CN=A,O=B", &execution).unwrap();
    let right = Selector::parse("O=B,CN=A", &execution).unwrap();
    assert!(!left.matches(&right, &execution).unwrap());
    let repeated = Selector::parse("CN=A+CN=A", &execution).unwrap();
    let singleton = Selector::parse("CN=A", &execution).unwrap();
    assert!(!repeated.matches(&singleton, &execution).unwrap());
}

#[test]
fn complete_ber_segments_reassemble_before_character_validation() {
    // BER segment boundaries are octet boundaries, not character boundaries.
    // UTF8/BMP/Universal may split a character; indefinite EOCs stay in raw BER.
    let execution = memory(64 * 1024, 1_000_000);
    for (encoded, plain) in [
        ("CN=#2C800401C30401A90000", "CN=é"),
        ("CN=#3E06040100040141", "CN=A"),
        ("CN=#3C080402000004020041", "CN=A"),
        ("CN=#2C080400240404024142", "CN=AB"),
    ] {
        let left = Selector::parse(encoded, &execution).unwrap();
        let right = Selector::parse(plain, &execution).unwrap();
        assert!(left.matches(&right, &execution).unwrap(), "{encoded}");
    }
    for text in [
        "CN=#2C030C0141",
        "CN=#2C80040141000000",
        "CN=#2C80040141",
        "CN=#2200",
    ] {
        assert!(Selector::parse(text, &execution).is_err(), "{text}");
    }
}

#[test]
fn reversible_ber_certificate_name_uses_the_same_segmented_identity() {
    // Reversible formatting of a BER Name must match that original Name,
    // including a UTF8String split mid-character across octet segments.
    let execution = memory(64 * 1024, 1_000_000);
    let bytes = [
        0x30, 19, 0x31, 17, 0x30, 15, 6, 3, 0x55, 4, 3, 0x2c, 0x80, 4, 1, 0xc3, 4, 1, 0xa9, 0, 0,
    ];
    let parser = Parser::ber(execution.clone());
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = name::read(&reader, &element, "name").unwrap();
    let text = name.rfc4514(&execution).unwrap();
    assert_eq!(text.as_str(&execution).unwrap(), "CN=#2C800401C30401A90000");
    let selected = Selector::parse(text.as_str(&execution).unwrap(), &execution).unwrap();
    assert!(selected.matches_name(&name, &execution).unwrap());
}

#[test]
fn reversible_codec_retains_malformed_string_octets() {
    // Name retains malformed string payloads for opaque wire identity. The
    // reversible codec must preserve those bytes without accepting them as text.
    let execution = memory(64 * 1024, 1_000_000);
    for value in [
        &[0x0c, 1, 0xff][..],
        &[0x2c, 3, 4, 1, 0xff][..],
        &[0x3e, 3, 4, 1, 0][..],
    ] {
        // Outer lengths include the OID TLV and the original value TLV.
        let mut bytes = vec![
            0x30,
            u8::try_from(9 + value.len()).unwrap(),
            0x31,
            u8::try_from(7 + value.len()).unwrap(),
            0x30,
            u8::try_from(5 + value.len()).unwrap(),
            6,
            3,
            0x55,
            4,
            3,
        ];
        bytes.extend_from_slice(value);
        let parser = Parser::ber(execution.clone());
        let mut reader = parser.read(&bytes, 41).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let name = name::read(&reader, &element, "name").unwrap();
        let text = name.rfc4514(&execution).unwrap();
        let selected = Selector::parse(text.as_str(&execution).unwrap(), &execution).unwrap();
        assert!(selected.matches_name(&name, &execution).unwrap());
    }
}

#[test]
fn unknown_assertion_semantics_are_distinct_from_opaque_identity() {
    // Numeric types are grammar-valid without a schema. String equality
    // cannot guess that schema, whereas identical retained BER has identity.
    let execution = memory(64 * 1024, 1_000_000);
    let assertion = Selector::parse("1.2.3=abc", &execution).unwrap();
    assert_eq!(
        assertion
            .matches(&assertion, &execution)
            .unwrap_err()
            .code(),
        ErrorCode::UnsupportedNameSyntax
    );
    let raw = Selector::parse("1.2.3=#0403616263", &execution).unwrap();
    let same = Selector::parse("1.2.3=#0403616263", &execution).unwrap();
    assert!(raw.matches(&same, &execution).unwrap());
    let wide = Selector::parse("2.18446744073709551616=#0500", &execution).unwrap();
    assert!(wide.matches(&wide, &execution).unwrap());
    assert_eq!(
        Selector::parse("unknown=abc", &execution)
            .unwrap_err()
            .code(),
        ErrorCode::UnsupportedNameSyntax
    );
    // Escaped octets are lexical assertions, but a known UTF8String value
    // with invalid UTF-8 is malformed, not an unknown equality rule.
    let malformed = Selector::parse("CN=\\FF", &execution).unwrap();
    assert_eq!(
        malformed
            .matches(&malformed, &execution)
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
}

#[test]
fn pseudonym_preparation_preserves_case() {
    // RFC2985 §5.2.9 assigns caseExactMatch to 2.5.4.65. Whitespace/NFKC
    // preparation still applies, but neither ASCII nor Unicode case may fold.
    let execution = memory(64 * 1024, 2_000_000);
    for (left, right, equal) in [
        ("pseudonym=Alice", "pseudonym=alice", false),
        ("pseudonym=Straße", "pseudonym=STRASSE", false),
        ("pseudonym=\\ Alice\\ ", "pseudonym=Alice", true),
        ("pseudonym=Ａlice", "pseudonym=Alice", true),
        ("pseudonym=É", "pseudonym=E\\CC\\81", true),
        ("pseudonym=É", "pseudonym=é", false),
    ] {
        let left = Selector::parse(left, &execution).unwrap();
        let right = Selector::parse(right, &execution).unwrap();
        assert_eq!(left.matches(&right, &execution).unwrap(), equal);
    }
    let bytes = [
        0x30, 16, 0x31, 14, 0x30, 12, 6, 3, 0x55, 4, 65, 12, 5, b'A', b'l', b'i', b'c', b'e',
    ];
    let parser = Parser::der(execution.clone());
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = name::read(&reader, &element, "name").unwrap();
    let same = Selector::parse("pseudonym=Alice", &execution).unwrap();
    let different = Selector::parse("pseudonym=alice", &execution).unwrap();
    let mut lower_bytes = bytes;
    lower_bytes[13] = b'a';
    let mut lower_reader = parser.read(&lower_bytes, 31).unwrap();
    let lower_element = lower_reader.next_element().unwrap().unwrap();
    let lower_name = name::read(&lower_reader, &lower_element, "name").unwrap();
    let comparison = memory(0, 100_000);
    assert!(same.matches_name(&name, &comparison).unwrap());
    assert!(!different.matches_name(&name, &comparison).unwrap());
    assert!(!name.matches(&lower_name, &comparison).unwrap());
    assert_eq!(
        name.order(&lower_name, &comparison).unwrap(),
        core::cmp::Ordering::Less
    );
    assert_eq!(comparison.used(), 0);
    assert!(
        same.matches_name(&name, &memory(0, 0))
            .unwrap_err()
            .is_resource()
    );
    let ordered = name.ordered(&execution).unwrap();
    let lower_ordered = lower_name.ordered(&execution).unwrap();
    assert_eq!(
        ordered.order(&lower_ordered, &comparison).unwrap(),
        core::cmp::Ordering::Less
    );
}

#[test]
fn malformed_grammar_refuses_before_storage_and_partial_ber_rolls_back() {
    // Lexical failures cannot allocate. BER failures release all temporary
    // and previously parsed AVAs rather than retaining a partial selector.
    for text in [
        "CN",
        "=x",
        "CN= x",
        "CN=x ",
        "CN=x,",
        "CN=x+",
        "CN=x;O=y",
        "CN=\\",
        "CN=\\0",
        "CN=\\0G",
        "CN=\\q",
        "CN=#0",
        "CN=#GG",
        "2.05.4.3=x",
    ] {
        let execution = memory(0, 100_000);
        let error = Selector::parse(text, &execution).unwrap_err();
        assert!(!error.is_resource(), "{text}: {error}");
        assert_eq!(execution.used(), 0);
    }
    let execution = memory(4096, 100_000);
    let error = Selector::parse("CN=A,O=#0C0241", &execution).unwrap_err();
    assert!(!error.is_resource());
    assert!(error.offset() >= 8);
    assert_eq!(execution.used(), 0);
}

#[test]
fn owned_selector_survives_source_account_handle_and_refusals() {
    // Source text and parser handle can disappear. New requests pay their
    // own work; storage stays charged until the independent selector drops.
    let account = Arc::new(MemoryAccount::new(4096, 100_000));
    let selector = {
        let storage = Memory::new(account.clone());
        let text = String::from("CN=ROOT");
        Selector::parse(&text, &storage).unwrap()
    };
    let execution = memory(0, 100_000);
    assert!(selector.matches(&selector, &execution).unwrap());
    let observer = Memory::new(account.clone());
    let before = observer.used();
    let refused = memory(0, 0);
    assert!(
        selector
            .matches(&selector, &refused)
            .unwrap_err()
            .is_resource()
    );
    assert_eq!(observer.used(), before);
    assert!(before > 0);
    drop(selector);
    assert_eq!(observer.used(), 0);
    let refused = memory(0, 100_000);
    assert!(Selector::parse("CN=A", &refused).unwrap_err().is_resource());
    assert_eq!(refused.used(), 0);
}

#[test]
fn wide_known_assertions_prepare_when_the_current_budget_funds_them() {
    // RFC5280 §7.1 mandates caseIgnoreMatch/StringPrep for DirectoryString.
    // A display-size bound must not turn a funded wide UID into unsupported
    // semantics or a binary mismatch; genuine budget refusal stays an error.
    let storage = memory(2 * 1024 * 1024, 20_000_000);
    let left = Selector::parse(&format!("UID={}", "A".repeat(40_000)), &storage).unwrap();
    let right = Selector::parse(&format!("UID={}", "a".repeat(40_000)), &storage).unwrap();
    let execution = memory(0, 10_000_000);
    assert!(left.matches(&right, &execution).unwrap());
    assert_eq!(execution.used(), 0);
    let refused = memory(0, 100);
    assert!(left.matches(&right, &refused).unwrap_err().is_resource());
}
