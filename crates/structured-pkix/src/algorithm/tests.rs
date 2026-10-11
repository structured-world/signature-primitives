use super::{AlgorithmIdentifier, read};
use crate::error::{ErrorCode, Result};
use crate::fixtures::{algorithm, int, null, oid as oid_of, printable, seq};
use crate::oid;
use structured_asn1::Parser;

fn parse<'a>(parser: &'a Parser, der: &'a [u8]) -> Result<AlgorithmIdentifier<'a>> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    read(&reader, &element, "test")
}

#[test]
fn retained_algorithm_comparison_refuses_unfunded_parameter_work() {
    // A retained opaque parameter may be large; its earlier parse must not
    // pay for a comparison in a new operation with no remaining work.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let parameters = crate::fixtures::tlv(0x04, &[0x55; 4096]);
    let der = seq(&[oid_of(oid::RSA_ENCRYPTION), parameters]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &der).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
    let result = left.matches(&left, &execution);
    let error = result.unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn algorithm_comparison_stops_before_unneeded_parameters_and_preserves_origin() {
    // A different OID or parameter length ends comparison without scanning
    // large opaque parameters. Equal-size parameters require their own charge.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let parameter = crate::fixtures::tlv(0x04, &[0x55; 4096]);
    let left_bytes = seq(&[oid_of(oid::RSA_ENCRYPTION), parameter.clone()]);
    let other_bytes = seq(&[oid_of(oid::EC_PUBLIC_KEY), parameter]);
    let shorter_bytes = seq(&[oid_of(oid::RSA_ENCRYPTION), int(7)]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &left_bytes).unwrap();
    let other = parse(&parser, &other_bytes).unwrap();
    let shorter = parse(&parser, &shorter_bytes).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 1)));
    assert!(!left.matches(&other, &execution).unwrap());
    assert_eq!(execution.work_used(), 1);
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(
        0,
        1 + left.algorithm().as_bytes().len(),
    )));
    assert!(!left.matches(&shorter, &execution).unwrap());
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(
        0,
        1 + left.algorithm().as_bytes().len(),
    )));
    let error = left.matches(&left, &execution).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "test");
    assert_eq!(error.offset(), 0);
    assert_eq!(execution.used(), 0);
    let exact = 1 + left.algorithm().as_bytes().len() + left.parameters().unwrap().len();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, exact)));
    assert!(left.matches(&left, &execution).unwrap());
    assert_eq!(execution.work_used(), exact);
}

#[test]
fn algorithm_comparison_through_a_reader_preserves_its_local_ceiling() {
    // A generous aggregate domain must not reset the producing parser's
    // cumulative limit for the certificate's signed/unsigned comparison.
    let der = algorithm(oid::RSA_ENCRYPTION);
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1024,
            ..structured_asn1::Limits::default()
        },
        crate::fixtures::memory(),
    );
    let mut reader = parser.read(&der, 73).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = read(&reader, &element, "signatureAlgorithm").unwrap();
    while reader.charge(1).is_ok() {}
    let before = parser.memory().work_used();
    let error = identifier.matches_in(&identifier, &reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "signatureAlgorithm");
    assert_eq!(error.offset(), 73);
    assert_eq!(parser.memory().work_used(), before);
}

#[test]
fn an_identifier_keeps_its_parameters_as_they_were_written() {
    // A curve, which is what the parameters are for a key on one. What they
    // mean is the registry's business; keeping them exactly is this layer's.
    let curve = oid_of(oid::EC_PUBLIC_KEY);
    let der = seq(&[oid_of(oid::EC_PUBLIC_KEY), curve.clone()]);
    let parser = Parser::der(crate::fixtures::memory());
    let identifier = parse(&parser, &der).unwrap();

    assert_eq!(identifier.algorithm(), oid::EC_PUBLIC_KEY);
    assert_eq!(identifier.parameters(), Some(&curve[..]));
    assert!(!identifier.has_no_parameters());
    assert_eq!(identifier.as_bytes(), &der[..]);
}

#[test]
fn an_absent_parameter_and_a_null_one_say_the_same_thing() {
    let absent = seq(&[oid_of(oid::RSA_ENCRYPTION)]);
    let explicit = algorithm(oid::RSA_ENCRYPTION);

    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &absent).unwrap();
    let right = parse(&other, &explicit).unwrap();

    assert!(left.has_no_parameters());
    assert!(right.has_no_parameters());
    assert!(left.matches(&right, one.memory()).unwrap());
    assert!(right.matches(&left, other.memory()).unwrap());
}

#[test]
fn anything_else_that_differs_is_a_different_algorithm() {
    let parsers = [
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
    ];
    let with_parameters = seq(&[oid_of(oid::RSA_ENCRYPTION), int(7)]);
    let base = parse(&parsers[0], &with_parameters).unwrap();

    // The same parameters under a different identifier.
    let elsewhere = seq(&[oid_of(oid::EC_PUBLIC_KEY), int(7)]);
    let elsewhere = parse(&parsers[1], &elsewhere).unwrap();
    assert!(!base.matches(&elsewhere, parsers[0].memory()).unwrap());

    // The same identifier with parameters that say something else. For an
    // algorithm that takes them, the parameters are half of what is being
    // verified.
    let different = seq(&[oid_of(oid::RSA_ENCRYPTION), int(8)]);
    let different = parse(&parsers[2], &different).unwrap();
    assert!(!base.matches(&different, parsers[0].memory()).unwrap());
}

#[test]
fn a_parameter_that_is_present_is_not_the_same_as_none_at_all() {
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let with_parameters = seq(&[oid_of(oid::RSA_ENCRYPTION), int(7)]);
    let without_parameters = seq(&[oid_of(oid::RSA_ENCRYPTION)]);
    let with = parse(&one, &with_parameters).unwrap();
    let without = parse(&other, &without_parameters).unwrap();

    assert!(!with.matches(&without, one.memory()).unwrap());
}

#[test]
fn a_parameter_that_is_not_der_is_refused_before_it_is_preserved() {
    // What the parameter says is the registry's business, and the registry
    // is handed the bytes: a curve, a hash, the salt length of a padding
    // scheme. It is handed them on the promise that they are the encoding
    // the document claims, so the whole value is held to that and not only
    // its outer header.
    use crate::fixtures::tlv;
    for parameter in [
        // An integer written a byte longer than it needs, inside a
        // container this layer does not interpret.
        seq(&[tlv(0x02, &[0x00, 0x01])]),
        // The same one level down.
        seq(&[seq(&[tlv(0x02, &[0x00, 0x01])])]),
        // A string written the way the distinguished rules do not write one.
        seq(&[tlv(0x2c, b"\x0c\x01x")]),
        // A set whose members descend.
        tlv(0x31, &[int(2), int(1)].concat()),
    ] {
        let der = seq(&[oid_of(oid::RSA_ENCRYPTION), parameter.clone()]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{parameter:02x?}");
    }

    // A parameter that is DER is preserved exactly as before.
    let parameter = seq(&[int(1), null()]);
    let der = seq(&[oid_of(oid::RSA_ENCRYPTION), parameter.clone()]);
    let parser = Parser::der(crate::fixtures::memory());
    let identifier = parse(&parser, &der).unwrap();
    assert_eq!(identifier.parameters(), Some(&parameter[..]));
}

#[test]
fn an_identifier_that_is_not_shaped_like_one_is_refused() {
    // Not a sequence.
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &printable("rsa")).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // No identifier.
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &seq(&[])).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedEnd)
    );

    // A second parameter, which would leave which one the algorithm takes
    // with no answer.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[oid_of(oid::RSA_ENCRYPTION), null(), int(1)]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
    assert_eq!(error.field(), "test");
}
