use super::{Extensions, Recognizer, is_known, read};
use crate::error::{ErrorCode, Result};
use crate::fixtures::{bits, boolean, extension, int, octets, oid as oid_of, seq, tlv};
use crate::oid;
use alloc::vec::Vec;
use structured_asn1::{Oid, Parser};

fn parse<'a>(parser: &'a Parser, der: &'a [u8]) -> Result<Extensions<'a>> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    read(&reader, &element, "test")
}

#[test]
fn critical_filter_refuses_unfunded_noncritical_scanning_and_then_stops() {
    // A critical-free answer still visits every metadata entry. Exhaustion
    // before the last noncritical element must not look like an empty result.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = seq(&[
        extension(oid::BASIC_CONSTRAINTS, false, &seq(&[])),
        extension(oid::KEY_USAGE, false, &bits(&[0x80])),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let items = parse(&parser, &der).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 1)));
    let mut criticals = items.criticals(&execution);
    let first = criticals.next();
    assert!(matches!(first, Some(Err(error)) if error.is_resource()));
    assert_eq!(execution.work_used(), 1);
    assert!(criticals.next().is_none());
    assert!(criticals.next().is_none());
    assert_eq!(execution.work_used(), 1);
}

#[test]
fn critical_filter_pays_for_the_visited_prefix_and_a_complete_miss() {
    // First-match admission stops at the critical entry; later metadata
    // needs new work. Empty/end states never scan or charge again.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = seq(&[
        extension(oid::BASIC_CONSTRAINTS, false, &seq(&[])),
        extension(oid::KEY_USAGE, true, &bits(&[0x80])),
        extension(oid::SUBJECT_KEY_IDENTIFIER, false, &octets(b"key")),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let items = parse(&parser, &der).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 2)));
    let mut entries = items.criticals(&execution);
    assert_eq!(entries.next().unwrap().unwrap().kind(), oid::KEY_USAGE);
    assert_eq!(execution.work_used(), 2);
    assert!(entries.next().unwrap().unwrap_err().is_resource());
    assert!(entries.next().is_none());
    assert_eq!(execution.work_used(), 2);
    let full = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 3)));
    let mut entries = items.criticals(&full);
    assert!(entries.next().unwrap().is_ok());
    assert!(entries.next().is_none());
    assert!(entries.next().is_none());
    assert_eq!(full.work_used(), 3);
    let empty = Extensions::empty(parser.memory());
    let denied = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
    assert!(empty.criticals(&denied).next().is_none());
    assert_eq!(denied.work_used(), 0);
}

#[test]
fn extension_reader_inherits_container_depth_and_offset() {
    // An attacker must not recover a fresh depth allowance inside extnValue.
    // The borrowed window must also retain its original document offset.
    let value = seq(&[boolean(true)]);
    let der = seq(&[extension(oid::BASIC_CONSTRAINTS, false, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    let item = extensions
        .get(oid::BASIC_CONSTRAINTS, extensions.memory())
        .unwrap()
        .unwrap();
    let mut reader = item.reader(item.parser().memory()).unwrap();
    assert_eq!(reader.depth(), 3);
    let element = reader.next_element().unwrap().unwrap();
    assert_eq!(element.span().start, item.value_span.start);
    assert_eq!(element.as_bytes().as_ptr(), item.value().as_ptr());
}

#[test]
fn extension_lookup_admits_each_oid_comparison_before_matching() {
    // Early matches pay only the visited prefix. A long query cannot obtain
    // a match or absence before its comparison has been admitted.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = seq(&[
        extension(oid::BASIC_CONSTRAINTS, false, &seq(&[])),
        extension(oid::KEY_USAGE, false, &bits(&[0x80])),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    let first_work = 1 + oid::BASIC_CONSTRAINTS.as_bytes().len();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, first_work)));
    assert!(
        extensions
            .get(oid::BASIC_CONSTRAINTS, &execution)
            .unwrap()
            .is_some()
    );
    assert_eq!(execution.work_used(), first_work);
    let error = extensions.get(oid::KEY_USAGE, &execution).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), extensions.items[0].span.start);
    assert_eq!(execution.work_used(), first_work);

    let mut encoded = [0x81; 80];
    encoded[79] = 1;
    let long = Oid::from_bytes(&encoded);
    let short = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 80)));
    assert!(extensions.get(long, &short).unwrap_err().is_resource());
    assert_eq!(short.work_used(), 0);
    let full = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 162)));
    assert!(extensions.get(long, &full).unwrap().is_none());
    assert_eq!(full.work_used(), 162);
    assert_eq!(full.used(), 0);
}

#[test]
fn lazy_extension_uses_current_work_and_storage_without_moving_old_charge() {
    // A retained extension collection in A must not finance B's decode.
    // Refusals remain located resource errors; successful nested vectors
    // are stored in B while the original collection remains charged to A.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let value = seq(&[crate::fixtures::implicit(2, b"example.ua")]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, false, &value)]);
    let original = crate::fixtures::memory();
    let parser = Parser::der(original.clone());
    let extensions = parse(&parser, &der).unwrap();
    let item = extensions
        .get(oid::SUBJECT_ALT_NAME, extensions.memory())
        .unwrap()
        .unwrap();
    let before = original.work_used();
    let held = original.used();
    let no_work = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
    let error = extensions.subject_alt_name(&no_work).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), item.span().start);
    let no_storage = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 10_000)));
    let error = extensions.subject_alt_name(&no_storage).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Memory
        ))
    );
    let execution = crate::fixtures::memory();
    let names = extensions.subject_alt_name(&execution).unwrap().unwrap();
    assert!(names.memory().same_account(&execution));
    assert!(matches!(
        &*names,
        [crate::general_name::GeneralName::Dns("example.ua")]
    ));
    assert_eq!(original.work_used(), before);
    assert_eq!(original.used(), held);
    assert!(execution.used() > 0);
    drop(names);
    assert_eq!(execution.used(), 0);
    drop(extensions);
    assert_eq!(original.used(), 0);
}

/// A scheme that knows one extension of its own.
struct Scheme(Oid<'static>);

impl Recognizer for Scheme {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        kind: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(kind == self.0)
    }
}

/// A scheme that can interpret one other-name type of its own.
struct NameScheme(Oid<'static>);

impl Recognizer for NameScheme {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        _kind: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    fn recognizes_other_name(
        &self,
        type_id: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(type_id == self.0)
    }
}

/// A scheme that states the containment rule for one other-name type, and
/// reads none.
struct ConstraintScheme(Oid<'static>);

impl Recognizer for ConstraintScheme {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        _kind: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    fn recognizes_name_constraint(
        &self,
        type_id: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(type_id == self.0)
    }
}

/// A scheme that understands one access method of its own, other-name
/// locations of the same identifier included.
struct AccessScheme(Oid<'static>);

impl Recognizer for AccessScheme {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        _kind: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    fn recognizes_other_name(
        &self,
        type_id: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(type_id == self.0)
    }

    fn recognizes_access_method(
        &self,
        method: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(method == self.0)
    }
}

#[test]
fn an_extension_keeps_its_value_encoded() {
    let value = seq(&[boolean(true), int(3)]);
    let der = seq(&[extension(oid::BASIC_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();

    let found = extensions
        .get(oid::BASIC_CONSTRAINTS, extensions.memory())
        .unwrap()
        .unwrap();
    assert!(found.is_critical());
    // The octet string is a wrapper: what it holds is a structure of its own,
    // and it is handed on as it arrived rather than decoded here.
    assert_eq!(found.value(), &value[..]);
    assert_eq!(found.span().start, 2);
}

#[test]
fn what_this_crate_reads_needs_no_scheme_to_recognize_it() {
    assert!(is_known(oid::BASIC_CONSTRAINTS));
    assert!(is_known(oid::QC_STATEMENTS));
    // Named here, and not read into a structure of its own, so a scheme that
    // needs it must say it knows it.
    assert!(!is_known(oid::PRIVATE_KEY_USAGE_PERIOD));
}

#[test]
fn a_scheme_says_which_of_its_own_extensions_it_knows() {
    let mine = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x02, 0x01]);
    let other = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x02, 0x02]);
    let der = seq(&[
        extension(mine, true, &octets(&[0x01])),
        extension(other, true, &octets(&[0x02])),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();

    let scheme = Scheme(mine);
    let blocked: Vec<_> = extensions
        .unhandled_critical(&scheme, parser.memory())
        .unwrap()
        .iter()
        .map(|extension| extension.kind())
        .collect();
    assert_eq!(blocked, [other]);

    // Both are still there to be reported, whether or not anything knows them.
    assert_eq!(extensions.len(), 2);
    assert!(extensions.iter().all(|extension| extension.is_critical()));
}

#[test]
fn extensions_that_say_nothing_or_say_it_twice_are_refused() {
    // Nothing at all, where the schema requires at least one.
    let parser = Parser::der(crate::fixtures::memory());
    let empty = seq(&[]);
    let error = parse(&parser, &empty).unwrap_err();
    assert_eq!(error.code(), ErrorCode::EmptySequence);

    // The same extension twice, with different values: which of them applies
    // would have no answer.
    let parser = Parser::der(crate::fixtures::memory());
    let twice = seq(&[
        extension(oid::KEY_USAGE, false, &bits(&[0x80])),
        extension(oid::KEY_USAGE, false, &bits(&[0x04])),
    ]);
    let error = parse(&parser, &twice).unwrap_err();
    assert_eq!(error.code(), ErrorCode::DuplicateExtension);
}

#[test]
fn an_extension_that_is_not_shaped_like_one_is_refused() {
    // A value that is not wrapped in an octet string.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[seq(&[oid_of(oid::KEY_USAGE), bits(&[0x80])])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // No value at all.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[seq(&[oid_of(oid::KEY_USAGE)])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);

    // Something after the value.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[seq(&[
        oid_of(oid::KEY_USAGE),
        octets(&bits(&[0x80])),
        int(1),
    ])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn a_default_written_out_is_refused_under_der_and_read_under_ber() {
    // DER requires a DEFAULT component to be omitted, so a flag written out
    // as FALSE is a second spelling of the absent flag and not DER at all.
    let der = seq(&[seq(&[
        oid_of(oid::SUBJECT_KEY_IDENTIFIER),
        boolean(false),
        octets(&octets(&[0x01, 0x02])),
    ])]);

    let strict = Parser::der(crate::fixtures::memory());
    let error = parse(&strict, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // BER has no such rule, and both spellings say the extension may be
    // ignored by a reader that does not know it.
    let lenient = Parser::ber(crate::fixtures::memory());
    let extensions = parse(&lenient, &der).unwrap();
    assert!(
        !extensions
            .get(oid::SUBJECT_KEY_IDENTIFIER, extensions.memory())
            .unwrap()
            .unwrap()
            .is_critical()
    );
}

#[test]
fn a_malformed_known_critical_extension_still_blocks() {
    // A critical key usage whose value is an integer: the identifier is
    // known, the value never parsed, and nothing here understood what the
    // certificate demanded be understood. Filtering it out by identifier
    // alone would leave a validator seeing no blocker.
    let der = seq(&[extension(oid::KEY_USAGE, true, &int(3))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();

    let blocked: Vec<_> = extensions
        .unhandled_critical(&(), parser.memory())
        .unwrap()
        .iter()
        .map(|item| item.kind())
        .collect();
    assert_eq!(blocked, [oid::KEY_USAGE]);

    // The same identifier with a value that parses blocks nothing:
    // digitalSignature in the minimal spelling, one data bit and seven of
    // padding.
    let der = seq(&[extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x07, 0x80]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn extension_values_decode_as_der_whatever_parser_is_passed() {
    // The lazy accessors take the caller's parser for its budget, and a
    // caller that read a CMS envelope naturally passes a BER one. The
    // extension value lives inside the DER certificate, so a spelled-out
    // default the BER leniency would accept must still be refused, and the
    // malformed critical extension must still block.
    let der = seq(&[extension(
        oid::BASIC_CONSTRAINTS,
        true,
        &seq(&[boolean(false)]),
    )]);
    let parser = Parser::ber(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();

    let error = extensions
        .basic_constraints(extensions.memory())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_unknown_other_name_type_in_a_critical_name_extension_blocks() {
    use crate::fixtures::{context, seq as fseq, utf8};

    // An otherName's value means what its type identifier says, and this
    // crate names no such types itself: a critical name extension carrying
    // one nobody claims was not understood, though it still reads for the
    // report.
    let other = fseq(&[context(
        0,
        &[oid_of(oid::USER_ID), context(0, &[utf8("uid")])],
    )]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, true, &other)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    // The names still read: the answer above is about understanding.
    assert!(
        extensions
            .subject_alt_name(extensions.memory())
            .unwrap()
            .is_some()
    );

    // A scheme that claims the type, in the other-name role, stops it
    // blocking.
    let scheme = NameScheme(oid::USER_ID);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_scheme_clears_a_critical_extension_only_where_its_value_is_der() {
    // "the corresponding ASN.1 DER encoded structure is the value of the
    // octet string extnValue" (RFC 5280 4.1.2.9), one structure and nothing
    // beside it. A scheme says which identifiers are its to decode, not that
    // any bytes under one are readable, and it never sees the value: a claim
    // over a payload that is not a value of any type would clear a critical
    // demand nobody decoded.
    let mine = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x02, 0x03]);
    let scheme = Scheme(mine);
    for value in [
        // Nothing at all.
        Vec::new(),
        // An integer written a byte longer than it needs, which is a second
        // spelling of the same value.
        tlv(0x02, &[0x00, 0x01]),
        // The same one level down, under a container the scheme would enter.
        seq(&[tlv(0x02, &[0x00, 0x01])]),
        // A complete value and then bytes after it.
        [int(1), int(2)].concat(),
        // A header whose length runs past the payload.
        tlv(0x02, &[0x01]).into_iter().take(2).collect(),
    ] {
        let der = seq(&[extension(mine, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&scheme, parser.memory())
                .unwrap()
                .len(),
            1,
            "{value:02x?}"
        );
    }

    // One complete value is the scheme's to read, and its claim clears it.
    let der = seq(&[extension(mine, true, &seq(&[int(1), octets(&[0x02])]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_unknown_access_method_in_a_critical_extension_blocks() {
    use crate::fixtures::{implicit, seq as fseq};

    // An access description's meaning is its method identifier: one nobody
    // claims is a critical access demand this run cannot interpret, though
    // it still reads for the report.
    let mine = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x06, 0x01]);
    let value = fseq(&[fseq(&[oid_of(mine), implicit(6, b"https://x.example.ua")])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    let scheme = AccessScheme(mine);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );

    // A method this crate names stays handled.
    let value = fseq(&[fseq(&[
        oid_of(oid::OCSP),
        implicit(6, b"https://ocsp.example.ua"),
    ])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_currency_code_that_is_not_alphabetic_blocks() {
    use crate::fixtures::{printable, seq as fseq};

    // The alphabetic ISO 4217 choice is three uppercase letters: a digit or
    // punctuation in the triple names no currency.
    for code in ["A1?", "uah", "U-H"] {
        let value = fseq(&[fseq(&[
            oid_of(oid::QC_LIMIT_VALUE),
            fseq(&[printable(code), int(1000), int(0)]),
        ])]);
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{code}"
        );
    }
}

#[test]
fn a_cps_pointer_that_is_not_a_uri_blocks() {
    use crate::fixtures::{ia5, seq as fseq};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // The pointer's type is a URI: non-empty IA5 text without a scheme, or
    // outside the URI alphabet, points at nothing.
    for pointer in [&b"not-a-uri"[..], b"/relative", b"https:%"] {
        let mut ia5_pointer = alloc::vec![0x16, u8::try_from(pointer.len()).unwrap()];
        ia5_pointer.extend_from_slice(pointer);
        let value = fseq(&[fseq(&[
            oid_of(policy),
            fseq(&[fseq(&[oid_of(oid::CPS_QUALIFIER), ia5_pointer])]),
        ])]);
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{pointer:02x?}"
        );
    }

    // A genuine pointer stays interpreted. The pointer is a URI, and that
    // production carries an optional fragment (RFC 3986 3), which is how a
    // statement points at the section that applies: reading it as the
    // fragment-free form would block a policy over the part of the pointer
    // that says which practice it means.
    for pointer in [
        "https://cps.example.ua",
        "https://cps.example.ua/text#signing",
        "https://cps.example.ua/text?v=2#signing",
        "https://cps.example.ua/text#",
    ] {
        let value = fseq(&[fseq(&[
            oid_of(policy),
            fseq(&[fseq(&[oid_of(oid::CPS_QUALIFIER), ia5(pointer)])]),
        ])]);
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            0,
            "{pointer}"
        );
    }

    // A second fragment delimiter is outside the production either way.
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(oid::CPS_QUALIFIER),
            ia5("https://cps.example.ua/text#a#b"),
        ])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn recognizing_an_extension_does_not_vouch_for_an_other_name_of_the_same_oid() {
    use crate::fixtures::{context, seq as fseq, utf8};

    // The recognizer answers by role: claiming an extension with an
    // identifier says nothing about interpreting an other-name whose type
    // reuses it.
    let mine = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let other = fseq(&[context(0, &[oid_of(mine), context(0, &[utf8("v")])])]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, true, &other)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    let scheme = Scheme(mine);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_mailbox_location_for_a_publication_method_blocks() {
    use crate::fixtures::{implicit, seq as fseq};

    // The issuing-certificate and repository methods publish over transfer
    // protocols or the directory (RFC 5280 4.2.2.1, 4.2.2.2): a mailbox
    // identifies no publication location for them.
    for method in [oid::CA_ISSUERS, oid::CA_REPOSITORY] {
        let value = fseq(&[fseq(&[oid_of(method), implicit(1, b"ca@example.ua")])]);
        let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{method:?}"
        );
    }
}

#[test]
fn an_attribute_outside_its_size_bounds_in_a_critical_name_blocks() {
    use crate::fixtures::{context, printable, seq as fseq, set as fset};

    // A country of three characters wears the type while naming no country:
    // the attribute is exactly two (RFC 5280 appendix A). The same appendix
    // bounds a common name at sixty-four.
    let long_country = fseq(&[context(
        4,
        &[fseq(&[fset(&[fseq(&[
            oid_of(oid::COUNTRY),
            printable("USA"),
        ])])])],
    )]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, true, &long_country)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    let oversized = "a".repeat(65);
    let long_common = fseq(&[context(
        4,
        &[fseq(&[fset(&[fseq(&[
            oid_of(oid::COMMON_NAME),
            crate::fixtures::utf8(&oversized),
        ])])])],
    )]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, true, &long_common)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_unknown_other_name_in_a_critical_authority_key_identifier_blocks() {
    use crate::fixtures::{context, implicit, seq as fseq, set as fset, utf8};
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x06, 0x03]);

    // The issuer names inside the identifier are the identity it points at:
    // an other-name nobody claims there was never interpreted. A directory
    // name rides beside it so the pair itself stays validly formed.
    let other = context(0, &[oid_of(unknown), context(0, &[int(1)])]);
    let root = fseq(&[fset(&[fseq(&[oid_of(oid::COMMON_NAME), utf8("Root")])])]);
    let value = fseq(&[
        implicit(0, &[0xab]),
        context(1, &[other, context(4, &[root])]),
        implicit(2, &[0x05]),
    ]);
    let der = seq(&[extension(oid::AUTHORITY_KEY_IDENTIFIER, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    let scheme = NameScheme(unknown);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_unknown_other_name_in_a_critical_distribution_point_blocks() {
    use crate::fixtures::{context, seq as fseq};
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x06, 0x04]);

    // The point's names say where the revocation evidence is: an other-name
    // nobody claims identifies nothing this run can use.
    let other = context(0, &[oid_of(unknown), context(0, &[int(1)])]);
    let point = fseq(&[context(0, &[context(0, &[other])])]);
    let der = seq(&[extension(
        oid::CRL_DISTRIBUTION_POINTS,
        true,
        &fseq(&[point]),
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    let scheme = NameScheme(unknown);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_pds_location_that_is_not_a_url_blocks() {
    use crate::fixtures::{printable, seq as fseq, tlv as ftlv};

    // The disclosure location is a URL: IA5 text without a scheme names no
    // place to disclose at.
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_PDS),
        fseq(&[fseq(&[ftlv(0x16, b"not-a-url"), printable("en")])]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_unknown_other_name_registration_authority_blocks() {
    use crate::fixtures::{context, seq as fseq};
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x06, 0x05]);

    // With no semantics identifier, the authorities are the statement's only
    // content: an other-name nobody claims there was never interpreted.
    let other = context(0, &[oid_of(unknown), context(0, &[int(1)])]);
    let information = fseq(&[fseq(&[other])]);
    let value = fseq(&[fseq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), information])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    let scheme = NameScheme(unknown);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_access_location_outside_its_methods_forms_blocks() {
    use crate::fixtures::{context, implicit, seq as fseq};

    // Each built-in method names the forms its location may take (RFC 5280
    // 4.2.2.1 and 4.2.2.2): the status responder is reached by a URI, and a
    // domain name there is an endpoint this run cannot use.
    let value = fseq(&[fseq(&[oid_of(oid::OCSP), implicit(2, b"ocsp.example.ua")])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    // The issuing-certificate method names the directory form among its own.
    let root = fseq(&[crate::fixtures::set(&[fseq(&[
        oid_of(oid::COMMON_NAME),
        crate::fixtures::utf8("Root"),
    ])])]);
    let value = fseq(&[fseq(&[oid_of(oid::CA_ISSUERS), context(4, &[root])])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_unknown_other_name_location_in_a_critical_access_extension_blocks() {
    use crate::fixtures::{context, seq as fseq, utf8};

    // A known method does not vouch for its location: an other-name whose
    // type nobody claims is a location this run never interpreted. Under a
    // named method the other-name blocks even when a scheme claims its
    // type, since the method's own forms do not include it; a method the
    // scheme claims keeps its own forms.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x06, 0x02]);
    let other = context(0, &[oid_of(unknown), context(0, &[utf8("loc")])]);
    let value = fseq(&[fseq(&[oid_of(oid::OCSP), other.clone()])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    let value = fseq(&[fseq(&[oid_of(unknown), other])]);
    let der = seq(&[extension(oid::AUTHORITY_INFO_ACCESS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    let scheme = AccessScheme(unknown);
    assert_eq!(
        extensions
            .unhandled_critical(&scheme, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_pds_language_that_is_not_a_language_code_blocks() {
    use crate::fixtures::{printable, seq as fseq};

    // The language beside a disclosure location is an ISO 639-1 code, two
    // lowercase letters: a digit or an uppercase pair names no language.
    for language in ["A1", "EN", "1a"] {
        let value = fseq(&[fseq(&[
            oid_of(oid::QC_PDS),
            fseq(&[fseq(&[
                crate::fixtures::ia5("https://pds.example.ua/en"),
                printable(language),
            ])]),
        ])]);
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{language}"
        );
    }
}

#[test]
fn a_legislation_code_that_is_not_a_country_blocks() {
    use crate::fixtures::{printable, seq as fseq};

    // The legislation entries are ISO 3166-1 alpha-2 codes, two uppercase
    // letters: a digit or punctuation in the pair names no country.
    for code in ["A1", "??", "ua"] {
        let value = fseq(&[fseq(&[
            oid_of(oid::QC_CC_LEGISLATION),
            fseq(&[printable(code)]),
        ])]);
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{code}"
        );
    }
}

#[test]
fn a_duplicate_key_purpose_reads_once() {
    use crate::fixtures::seq as fseq;

    // The list is a SEQUENCE OF with no uniqueness constraint, and a
    // repeated purpose permits exactly what one occurrence permits:
    // refusing it would block a valid certificate. The repeat is folded
    // away instead, so the list reads and holds each purpose once.
    let value = fseq(&[oid_of(oid::EMAIL_PROTECTION), oid_of(oid::EMAIL_PROTECTION)]);
    let der = seq(&[extension(oid::EXT_KEY_USAGE, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
    let purposes = extensions
        .extended_key_usage(extensions.memory())
        .unwrap()
        .unwrap();
    assert_eq!(purposes.purposes().len(), 1);
    assert!(
        purposes
            .has(oid::EMAIL_PROTECTION, extensions.memory())
            .unwrap()
    );
}

#[test]
fn encipher_bits_without_key_agreement_block() {
    // RFC 5280 4.2.1.3: the meaning of encipherOnly and decipherOnly is
    // undefined in the absence of the keyAgreement bit, and a critical bit
    // with no defined meaning was not understood. digitalSignature +
    // encipherOnly here; keyAgreement clear.
    let der = seq(&[extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x00, 0x81]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    // With keyAgreement set beside it, the bit means what it says.
    let der = seq(&[extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x00, 0x89]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_path_length_without_the_authority_flag_blocks() {
    // RFC 5280 4.2.1.9: the path length must not be present unless the
    // authority flag is asserted. Present without it, the value constrains a
    // path below a certificate that says it heads none.
    let der = seq(&[extension(oid::BASIC_CONSTRAINTS, true, &seq(&[int(2)]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_critical_statement_list_this_run_did_not_understand_blocks() {
    use crate::fixtures::null;
    // The outer list parses, but the kind statement's information is a NULL
    // where a sequence of types belongs: nothing here understood what the
    // certificate demanded be understood.
    let garbled_kind = seq(&[seq(&[oid_of(oid::QC_TYPE), null()])]);
    // And a statement identifier nobody here knows is exactly an unknown
    // critical demand, one level down.
    let unknown_kind = seq(&[seq(&[oid_of(structured_asn1::Oid::from_bytes(&[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x7e,
    ]))])]);

    for value in [garbled_kind, unknown_kind] {
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }

    // A list of statements this crate does read stays handled.
    let understood = seq(&[
        seq(&[oid_of(oid::QC_COMPLIANCE)]),
        seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESEAL)])]),
    ]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &understood)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_critical_policy_with_uninterpreted_qualifiers_blocks() {
    use crate::fixtures::{ia5, null, seq as fseq};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // A qualifier kind nobody here knows, and a practice-statement qualifier
    // whose payload is a NULL where a location belongs: either way the
    // critical qualifier was never interpreted.
    let unknown_kind = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(structured_asn1::Oid::from_bytes(&[
                0x2a, 0x86, 0x24, 0x03, 0x02,
            ])),
            ia5("x"),
        ])]),
    ])]);
    let garbled_cps = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[oid_of(oid::CPS_QUALIFIER), null()])]),
    ])]);
    for value in [unknown_kind, garbled_cps] {
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }

    // A policy without qualifiers, and one with a genuine practice statement,
    // both stay handled.
    let plain = fseq(&[fseq(&[oid_of(policy)])]);
    let with_cps = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(oid::CPS_QUALIFIER),
            ia5("https://cps.example.ua"),
        ])]),
    ])]);
    for value in [plain, with_cps] {
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            0
        );
    }
}

#[test]
fn a_critical_statement_payload_without_its_shape_blocks() {
    use crate::fixtures::{ia5, null, printable, seq as fseq};

    // The limit-value, disclosure-location and legislation statements carry
    // structured payloads; a NULL in any of them is a critical claim this
    // run never understood.
    for kind in [oid::QC_LIMIT_VALUE, oid::QC_PDS, oid::QC_CC_LEGISLATION] {
        let value = fseq(&[fseq(&[oid_of(kind), null()])]);
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1,
            "{kind:?}"
        );
    }

    // The genuine shapes stay handled: a monetary limit, one disclosure
    // location, one legislation country.
    let limit = fseq(&[fseq(&[
        oid_of(oid::QC_LIMIT_VALUE),
        fseq(&[printable("UAH"), int(1000), int(0)]),
    ])]);
    let locations = fseq(&[fseq(&[
        oid_of(oid::QC_PDS),
        fseq(&[fseq(&[ia5("https://pds.example.ua/en"), printable("en")])]),
    ])]);
    let legislation = fseq(&[fseq(&[
        oid_of(oid::QC_CC_LEGISLATION),
        fseq(&[printable("UA")]),
    ])]);
    for value in [limit, locations, legislation] {
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            0
        );
    }
}

/// Reads the list and asks what blocked under one element budget, or `None`
/// where the budget did not even let the list be read.
fn blocked_under_budget(der: &[u8], budget: u64) -> Option<Result<usize>> {
    let limits = structured_asn1::Limits {
        max_elements: budget,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let mut reader = parser.read(der, 0).ok()?;
    let element = reader.next_element().ok()??;
    let extensions = read(&reader, &element, "test").ok()?;
    Some(
        extensions
            .unhandled_critical(&(), parser.memory())
            .map(|blocked| blocked.len())
            .map_err(processing),
    )
}

#[test]
fn a_limit_error_inside_a_qualifier_points_into_the_document() {
    use crate::fixtures::{ia5, seq as fseq};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);
    let pointer = ia5("https://cps.example.ua");
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[oid_of(oid::CPS_QUALIFIER), pointer.clone()])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let qualifier_at = u64::try_from(
        der.windows(pointer.len())
            .position(|window| window == &pointer[..])
            .unwrap(),
    )
    .unwrap();

    // The last budget that still fails runs out at the deepest point of the
    // work, inside the qualifier re-parse. Its offset must be an offset in
    // the document, at or past the qualifier, never one counted from the
    // start of the re-read slice: the error type promises document offsets.
    let mut deepest = None;
    for budget in 1..512 {
        match blocked_under_budget(&der, budget) {
            Some(Ok(_)) => break,
            Some(Err(error)) => deepest = Some(error),
            None => {}
        }
    }
    let error = deepest.unwrap();
    assert!(error.is_limit());
    assert!(
        error.offset() >= qualifier_at,
        "offset {} points before the qualifier at {qualifier_at}",
        error.offset()
    );
}

#[test]
fn a_spent_budget_is_not_an_unhandled_extension() {
    // A well-formed critical key usage, and the smallest element budget that
    // lets the list be read. The gate's re-decode then runs out of budget,
    // which says the device gave up, not that the certificate demanded
    // something nobody understood: the answer is the spent budget itself,
    // never a blocker in the report.
    let der = seq(&[extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x07, 0x80]))]);
    let outcome = (1..64)
        .find_map(|budget| blocked_under_budget(&der, budget))
        .unwrap();
    assert!(outcome.unwrap_err().is_limit());
}

#[test]
fn a_notice_number_not_wearing_the_integer_tag_blocks() {
    use crate::fixtures::{ia5, seq as fseq};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // noticeNumbers is SEQUENCE OF INTEGER (RFC 5280 4.2.1.4): an OCTET
    // STRING whose contents happen to spell a minimal integer is not that,
    // and the reader's decoding helper is deliberately tag-agnostic for
    // implicitly tagged fields, so the schema layer must require the tag.
    let reference = fseq(&[ia5("org"), fseq(&[tlv(0x04, &[0x01])])]);
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(oid::USER_NOTICE_QUALIFIER),
            fseq(&[reference]),
        ])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_cps_pointer_outside_the_ia5_alphabet_blocks() {
    use crate::fixtures::seq as fseq;
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // The pointer is an IA5String, the 128-character IRV (X.680, 41.4): a
    // byte above 0x7f wears the tag but is not the type, and the critical
    // qualifier holding it was never interpreted.
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(oid::CPS_QUALIFIER),
            tlv(0x16, b"https://cps.example.ua/\xff"),
        ])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn display_text_that_does_not_decode_or_overruns_its_size_blocks() {
    use crate::fixtures::seq as fseq;
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);
    let notice = |text: Vec<u8>| {
        fseq(&[fseq(&[
            oid_of(policy),
            fseq(&[fseq(&[oid_of(oid::USER_NOTICE_QUALIFIER), fseq(&[text])])]),
        ])])
    };

    // Display text is a choice of four string types, each SIZE (1..200)
    // (RFC 5280 4.2.1.4): bytes that do not decode under the declared type,
    // or a decoded text longer than 200 characters, wear the tag without
    // being the type, and the critical qualifier was never interpreted.
    let undecodable_utf8 = notice(tlv(0x0c, b"\xff\xfe"));
    let odd_bmp = notice(tlv(0x1e, &[0x00, 0x04, 0x10]));
    // A surrogate pair is UTF-16, not the one-unit-a-character UCS-2 that
    // BMPString is (X.680, 41.16): a character outside the basic plane has
    // no spelling here, and combining the pair would accept one.
    let surrogate_bmp = notice(tlv(0x1e, &[0xd8, 0x01, 0xdc, 0x00]));
    let too_long = notice(tlv(0x0c, &[b'a'; 201]));
    for value in [undecodable_utf8, odd_bmp, surrogate_bmp, too_long] {
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }

    // Exactly two hundred characters is inside the size, and a two-byte
    // basic-plane character counts as one character rather than two bytes.
    let at_limit = notice(tlv(0x0c, &[b'a'; 200]));
    let cyrillic_bmp = notice(tlv(0x1e, &[0x04, 0x23, 0x04, 0x32]));
    for value in [at_limit, cyrillic_bmp] {
        let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            0
        );
    }
}

#[test]
fn a_numeric_currency_not_wearing_the_integer_tag_blocks() {
    use crate::fixtures::seq as fseq;

    // The numeric currency choice is an INTEGER; an OCTET STRING whose
    // contents spell a minimal integer wears a different type, and the
    // reader's decoding helper is deliberately tag-agnostic for implicitly
    // tagged fields, so the schema layer must require the tag.
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_LIMIT_VALUE),
        fseq(&[tlv(0x04, &[0x01]), int(1000), int(0)]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn qc_strings_outside_their_declared_alphabets_block() {
    use crate::fixtures::{printable, seq as fseq};

    // Each narrow string type declares an alphabet (X.680, 41.4): an
    // IA5String is the 128-character IRV, and PrintableString is a short
    // closed list. A byte outside the alphabet wears the tag but is not the
    // type, and a critical statement built on one was never understood.
    let bad_url = fseq(&[fseq(&[
        oid_of(oid::QC_PDS),
        fseq(&[fseq(&[
            tlv(0x16, b"https://pds.example.ua/\xff"),
            printable("en"),
        ])]),
    ])]);
    let bad_language = fseq(&[fseq(&[
        oid_of(oid::QC_PDS),
        fseq(&[fseq(&[
            tlv(0x16, b"https://pds.example.ua/en"),
            tlv(0x13, b"e@"),
        ])]),
    ])]);
    let bad_country = fseq(&[fseq(&[
        oid_of(oid::QC_CC_LEGISLATION),
        fseq(&[tlv(0x13, b"U@")]),
    ])]);
    let bad_currency = fseq(&[fseq(&[
        oid_of(oid::QC_LIMIT_VALUE),
        fseq(&[tlv(0x13, b"U@H"), int(1000), int(0)]),
    ])]);
    for value in [bad_url, bad_language, bad_country, bad_currency] {
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn an_empty_type_list_in_a_critical_statement_blocks() {
    use crate::fixtures::seq as fseq;

    // The type statement declares which purpose the certificate is issued
    // for (ETSI EN 319 412-5, clause 4.2.3); a list of zero purposes wears
    // the statement while declaring nothing, and a critical list carrying it
    // was never understood.
    let value = fseq(&[fseq(&[oid_of(oid::QC_TYPE), fseq(&[])])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_type_identifier_not_wearing_the_oid_tag_blocks() {
    use crate::fixtures::seq as fseq;

    // An OCTET STRING whose contents happen to be the bytes of a known
    // identifier is not an OBJECT IDENTIFIER: the schema says SEQUENCE OF
    // OBJECT IDENTIFIER, and the reader's decoding helpers are deliberately
    // tag-agnostic for implicitly tagged fields, so the schema layer is the
    // one that must require the universal tag.
    let full = oid_of(oid::QCT_ESIGN);
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_TYPE),
        fseq(&[tlv(0x04, &full[2..])]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_unknown_type_inside_a_critical_type_statement_blocks() {
    use crate::fixtures::seq as fseq;

    // The type statement's payload is what carries the meaning: a type
    // identifier nobody here knows is a certificate purpose this run cannot
    // name, and a critical list demanding it be understood blocks.
    let unknown = structured_asn1::Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x7d]);
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_TYPE),
        fseq(&[oid_of(oid::QCT_ESIGN), oid_of(unknown)]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_numeric_currency_outside_the_iso_4217_range_blocks() {
    use crate::fixtures::seq as fseq;

    // The numeric currency choice is INTEGER (1..999); zero, a negative
    // number and a four-digit number wear the type but name no currency, so
    // a critical limit carrying one was never understood.
    for code in [int(0), tlv(0x02, &[0xFF]), int(1000)] {
        let value = fseq(&[fseq(&[
            oid_of(oid::QC_LIMIT_VALUE),
            fseq(&[code, int(1000), int(0)]),
        ])]);
        let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }

    // A code inside the range stays handled.
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_LIMIT_VALUE),
        fseq(&[int(980), int(1000), int(0)]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn empty_semantics_information_blocks() {
    use crate::fixtures::seq as fseq;

    // The semantics structure requires at least one of its two optional
    // members (RFC 3739, 3.2.6.1): empty it says nothing while wearing the
    // statement, and a critical list carrying it was never understood.
    let value = fseq(&[fseq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), fseq(&[])])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_unknown_semantics_identifier_in_a_critical_statement_blocks() {
    use crate::fixtures::seq as fseq;

    // The identifier decides how the subject's identifiers are read, and
    // this crate names two ways of reading them. One it does not name is a
    // reading this run cannot perform, so a critical statement demanding it
    // was not understood. The accessor still hands the identifier back for
    // the report.
    let unknown = structured_asn1::Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x7c]);
    let value = fseq(&[fseq(&[
        oid_of(oid::PKIX_QC_SYNTAX_V2),
        fseq(&[oid_of(unknown)]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn every_semantics_statement_is_validated_not_just_the_preferred_one() {
    use crate::fixtures::{null, seq as fseq};

    // Both syntax statements may appear in one list. The accessor prefers
    // the newer one, but a well-formed preferred statement must not vouch
    // for the other: here the older statement's information is a NULL where
    // the semantics structure belongs, and that is a critical claim this run
    // never understood whichever statement stands beside it.
    let value = fseq(&[
        fseq(&[oid_of(oid::PKIX_QC_SYNTAX_V2)]),
        fseq(&[oid_of(oid::PKIX_QC_SYNTAX_V1), null()]),
    ]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    // Two genuine semantics statements side by side both parse and stay
    // handled. They say the same thing: two that disagree leave the
    // subject's identifiers with two readings, which blocks instead, and is
    // covered where the pair is compared.
    let value = fseq(&[
        fseq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V2),
            fseq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
        fseq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V1),
            fseq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
    ]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_access_method_in_the_wrong_extension_blocks() {
    use crate::fixtures::{implicit, seq as fseq};

    // Each extension defines its own methods: the authority side names OCSP
    // and the issuing certificates, the subject side names the repository
    // and the time-stamping service. A method carried by the other
    // extension has no defined meaning there, so a critical list holding
    // one was not understood.
    let crossed = [
        (oid::AUTHORITY_INFO_ACCESS, oid::TIME_STAMPING_ACCESS),
        (oid::AUTHORITY_INFO_ACCESS, oid::CA_REPOSITORY),
        (oid::SUBJECT_INFO_ACCESS, oid::OCSP),
        (oid::SUBJECT_INFO_ACCESS, oid::CA_ISSUERS),
    ];
    for (kind, method) in crossed {
        let value = fseq(&[fseq(&[
            oid_of(method),
            implicit(6, b"https://service.example.ua"),
        ])]);
        let der = seq(&[extension(kind, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            1
        );
    }

    // Each method in its own extension stays handled.
    let owned = [
        (oid::AUTHORITY_INFO_ACCESS, oid::CA_ISSUERS),
        (oid::SUBJECT_INFO_ACCESS, oid::TIME_STAMPING_ACCESS),
        (oid::SUBJECT_INFO_ACCESS, oid::CA_REPOSITORY),
    ];
    for (kind, method) in owned {
        let value = fseq(&[fseq(&[
            oid_of(method),
            implicit(6, b"https://service.example.ua"),
        ])]);
        let der = seq(&[extension(kind, true, &value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let extensions = parse(&parser, &der).unwrap();
        assert_eq!(
            extensions
                .unhandled_critical(&(), parser.memory())
                .unwrap()
                .len(),
            0
        );
    }
}

#[test]
fn an_opaque_name_form_in_a_constraint_blocks() {
    use crate::fixtures::{context, implicit, seq as fseq, set as fset};
    // A constraint is understood only where a certificate's names can be
    // matched against it. The X.400 form is kept as opaque encoded bytes
    // with no matching rule, so a critical constraint built on one was not
    // understood even though its structure parsed.
    let attribute = fseq(&[implicit(0, &[0x17]), context(1, &[int(1)])]);
    let x400 = context(3, &[fseq(&[]), fset(&[attribute])]);
    let value = fseq(&[context(0, &[fseq(&[x400])])]);
    let der = seq(&[extension(oid::NAME_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );

    // A form with a matching rule stays handled.
    let value = fseq(&[context(0, &[fseq(&[implicit(2, b"example.ua")])])]);
    let der = seq(&[extension(oid::NAME_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn decoding_an_other_name_does_not_vouch_for_a_constraint_on_it() {
    use crate::fixtures::{context, seq as fseq, utf8};

    // The two are different questions about the same identifier. Decoding
    // asks what a name of this type says; a constraint asks whether a
    // certificate's names fall inside a subtree of it, and answering that
    // needs a containment rule the decoding side never states. A scheme
    // that reads the name and has no such rule would leave a critical
    // constraint enforced by nobody.
    let mine = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let base = context(0, &[oid_of(mine), context(0, &[utf8("branch")])]);
    let value = fseq(&[context(0, &[fseq(&[base])])]);
    let der = seq(&[extension(oid::NAME_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();

    // Nobody at all, and a scheme that only reads the name, both leave it
    // blocking.
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
    let reader = NameScheme(mine);
    assert_eq!(
        extensions
            .unhandled_critical(&reader, parser.memory())
            .unwrap()
            .len(),
        1
    );

    // A scheme that states the containment rule clears it.
    let matcher = ConstraintScheme(mine);
    assert_eq!(
        extensions
            .unhandled_critical(&matcher, parser.memory())
            .unwrap()
            .len(),
        0
    );

    // And the constraint role says nothing about reading the name itself:
    // the same scheme leaves a critical alternative name blocking.
    let value = fseq(&[context(0, &[oid_of(mine), context(0, &[utf8("branch")])])]);
    let der = seq(&[extension(oid::SUBJECT_ALT_NAME, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&matcher, parser.memory())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        extensions
            .unhandled_critical(&reader, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_empty_user_notice_is_understood() {
    use crate::fixtures::seq as fseq;
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // Both members of a user notice are optional (RFC 5280 4.2.1.4): the
    // empty sequence says nothing, but it is inside the schema, and
    // refusing it would block an otherwise valid critical policy.
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[oid_of(oid::USER_NOTICE_QUALIFIER), fseq(&[])])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn content_scans_are_charged_to_the_work_budget() {
    use crate::fixtures::{implicit, seq as fseq, tlv as ftlv};

    // The text and named-bit walks touch every content byte, so a caller
    // bounding work sees them on the meter: a value far past the budget
    // fails on the limit rather than costing an unmetered linear scan. The
    // list borrows the parser, so the accessor runs inside the helper.
    fn scan_error(
        der: &[u8],
        pick: impl FnOnce(&Extensions<'_>) -> crate::error::Error,
    ) -> ErrorCode {
        let limits = structured_asn1::Limits {
            max_work: 4096,
            ..structured_asn1::Limits::default()
        };
        let parser = Parser::new(
            structured_asn1::Encoding::Der,
            limits,
            crate::fixtures::memory(),
        );
        let mut reader = parser.read(der, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let extensions = read(&reader, &element, "test").unwrap();
        pick(&extensions).code()
    }

    let big = alloc::vec![b'a'; 100_000];
    let der = seq(&[extension(
        oid::SUBJECT_ALT_NAME,
        true,
        &fseq(&[implicit(2, &big)]),
    )]);
    assert_eq!(
        scan_error(&der, |list| list
            .subject_alt_name(list.memory())
            .unwrap_err()),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    let zeros = alloc::vec![0x00; 100_001];
    let der = seq(&[extension(oid::KEY_USAGE, true, &ftlv(0x03, &zeros))]);
    assert_eq!(
        scan_error(&der, |list| list.key_usage(list.memory()).unwrap_err()),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn a_registered_id_constraint_base_blocks() {
    use crate::fixtures::{context, seq as fseq, tlv as ftlv};
    // A registered identifier has no constraint-matching rule here either:
    // a critical constraint built on one was not understood.
    let base = ftlv(0x88, oid::OCSP.as_bytes());
    let value = fseq(&[context(0, &[fseq(&[base])])]);
    let der = seq(&[extension(oid::NAME_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn the_cps_uri_scan_is_charged_to_the_work_budget() {
    use crate::fixtures::{ia5, seq as fseq};
    // A CPS URI has no local size ceiling, and deciding whether a critical
    // policies extension is handled scans every byte of it for IA5, UTF-8
    // and URI shape, so the scan rides on the shared work meter.
    let mut url = alloc::string::String::from("https://cps.example.ua/");
    url.push_str(&"a".repeat(100_000));
    let policy = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x01, 0x02]);
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[oid_of(oid::CPS_QUALIFIER), ia5(&url)])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let extensions = parse(&parser, &der).unwrap();
    let error = processing(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap_err(),
    );
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn the_disclosure_url_scan_is_charged_to_the_work_budget() {
    use crate::fixtures::{ia5, printable, seq as fseq};
    // Same meter as the CPS URI: a PDS URL is certificate-controlled text
    // with no local bound, scanned to decide whether the critical statements
    // extension is handled.
    let mut url = alloc::string::String::from("https://pds.example.ua/");
    url.push_str(&"a".repeat(100_000));
    let value = fseq(&[fseq(&[
        oid_of(oid::QC_PDS),
        fseq(&[fseq(&[ia5(&url), printable("en")])]),
    ])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let extensions = parse(&parser, &der).unwrap();
    let error = processing(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap_err(),
    );
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn an_empty_notice_number_sequence_is_understood() {
    use crate::fixtures::{ia5, seq as fseq};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // noticeNumbers is SEQUENCE OF INTEGER with no minimum size
    // (RFC 5280 4.2.1.4): the empty sequence sits inside the schema, and a
    // critical policies extension carrying it was read entirely.
    let reference = fseq(&[ia5("org"), fseq(&[])]);
    let value = fseq(&[fseq(&[
        oid_of(policy),
        fseq(&[fseq(&[
            oid_of(oid::USER_NOTICE_QUALIFIER),
            fseq(&[reference]),
        ])]),
    ])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_scheme_recognized_qualified_statement_is_understood() {
    use crate::fixtures::{octets, seq as fseq};

    /// A scheme that knows one qualified statement of its own.
    struct Statements(Oid<'static>);
    impl Recognizer for Statements {
        type Error = core::convert::Infallible;
        fn recognizes(
            &self,
            _kind: Oid<'_>,
            _execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<bool, Self::Error> {
            Ok(false)
        }
        fn recognizes_statement(
            &self,
            kind: Oid<'_>,
            _execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<bool, Self::Error> {
            Ok(kind == self.0)
        }
    }

    // A national statement is knowledge a scheme carries: the built-in
    // identifiers cannot name it, but a caller whose recognizer claims it
    // has read the critical extension entirely.
    let national = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let value = fseq(&[fseq(&[oid_of(national), octets(&[0x01])])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());

    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&Statements(national), parser.memory())
            .unwrap()
            .len(),
        0
    );
    // Without that knowledge the same extension still blocks.
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_recognizer_reached_by_reference_answers_for_every_role() {
    use crate::fixtures::{octets, seq as fseq};

    /// A scheme that knows one statement and one other-name of its own.
    struct Scheme(Oid<'static>);
    impl Recognizer for Scheme {
        type Error = core::convert::Infallible;
        fn recognizes(
            &self,
            _kind: Oid<'_>,
            _execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<bool, Self::Error> {
            Ok(false)
        }
        fn recognizes_statement(
            &self,
            kind: Oid<'_>,
            _execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<bool, Self::Error> {
            Ok(kind == self.0)
        }
    }

    // A generic caller may hold its scheme behind a reference, and the
    // blanket implementation for one must forward every role: a role it
    // drops answers the default no, and the scheme's knowledge is lost
    // exactly where a certificate depends on it.
    let national = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let value = fseq(&[fseq(&[oid_of(national), octets(&[0x01])])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());

    let scheme = Scheme(national);
    let by_reference: &dyn Recognizer<Error = core::convert::Infallible> = &scheme;
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&by_reference, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn the_display_text_scan_is_charged_to_the_work_budget() {
    use crate::fixtures::{seq as fseq, utf8};
    let policy = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x03, 0x01]);

    // Each display text is bounded at 200 characters, but the number of
    // notices is not, so the aggregate scan is certificate-controlled: forty
    // maximum-sized notices walk far more content than a small budget
    // allows, and deciding whether the critical extension is handled must
    // see that walk on the meter.
    let text = utf8(&"a".repeat(200));
    let notice = fseq(&[
        oid_of(oid::USER_NOTICE_QUALIFIER),
        fseq(core::slice::from_ref(&text)),
    ]);
    let qualifiers: Vec<Vec<u8>> = core::iter::repeat_n(notice, 40).collect();
    let value = fseq(&[fseq(&[oid_of(policy), fseq(&qualifiers)])]);
    let der = seq(&[extension(oid::CERTIFICATE_POLICIES, true, &value)]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let extensions = parse(&parser, &der).unwrap();
    let error = processing(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap_err(),
    );
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn a_path_length_past_any_path_does_not_block() {
    use crate::fixtures::{boolean, seq as fseq};

    // pathLenConstraint is INTEGER (0..MAX) (RFC 5280 4.2.1.9), so a count
    // wider than any path that could be built is inside the schema: it is a
    // constraint nothing reaches, not a malformed one, and a critical
    // extension carrying it was read entirely.
    let huge = tlv(0x02, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let value = fseq(&[boolean(true), huge]);
    let der = seq(&[extension(oid::BASIC_CONSTRAINTS, true, &value)]);
    let parser = Parser::der(crate::fixtures::memory());
    let extensions = parse(&parser, &der).unwrap();
    assert_eq!(
        extensions
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
}

// An infallible test recognizer cannot create a callback failure; retain the
// exact processing error for the existing code/offset budget assertions.
fn processing(error: crate::error::CallbackError<core::convert::Infallible>) -> crate::Error {
    match error {
        crate::error::CallbackError::Processing(error) => error,
        crate::error::CallbackError::Callback(never) => match never {},
    }
}
