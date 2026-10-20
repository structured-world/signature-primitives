//! OCSP archive cutoff and the extended revoked definition (RFC6960 §§2.2, 4.4.4, 4.4.8).

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::ErrorCode;
use structured_pkix::crl::Reason;
use structured_pkix::ocsp::{BasicResponse, ExtensionProcessing, Response, Status};

const CUTOFF: [u8; 9] = [0x2b, 6, 1, 5, 5, 7, 0x30, 1, 6];
const EXTENDED: [u8; 9] = [0x2b, 6, 1, 5, 5, 7, 0x30, 1, 9];
const CRL_REFERENCES: [u8; 9] = [0x2b, 6, 1, 5, 5, 7, 0x30, 1, 3];
const INVALIDITY_DATE: [u8; 3] = [0x55, 0x1d, 0x18];
const UNKNOWN: [u8; 3] = [0x2a, 3, 4];

fn memory() -> Memory {
    Memory::new(std::sync::Arc::new(MemoryAccount::new(
        128 * 1024,
        1_000_000,
    )))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(u8::try_from(contents.len()).unwrap());
    } else {
        result.extend([0x81, u8::try_from(contents.len()).unwrap()]);
    }
    result.extend_from_slice(contents);
    result
}
fn date() -> Vec<u8> {
    tlv(24, b"20261012120000Z")
}
fn epoch() -> Vec<u8> {
    tlv(24, b"19700101000000Z")
}
fn algorithm() -> Vec<u8> {
    tlv(48, &[6, 3, 0x2a, 3, 4])
}
fn extension(kind: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let flag: &[u8] = if critical { &[1, 1, 0xff] } else { &[] };
    tlv(48, &[&tlv(6, kind)[..], flag, &tlv(4, value)].concat())
}
fn revoked(time: &[u8], reason: Option<u8>) -> Vec<u8> {
    let reason = reason
        .map(|code| tlv(0xa0, &[10, 1, code]))
        .unwrap_or_default();
    tlv(0xa1, &[time, &reason].concat())
}
fn assertion(status: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let id = tlv(
        48,
        &[
            algorithm(),
            tlv(4, &[0x11; 20]),
            tlv(4, &[0x22; 20]),
            tlv(2, &[1]),
        ]
        .concat(),
    );
    let extensions = if extensions.is_empty() {
        Vec::new()
    } else {
        tlv(0xa1, &tlv(48, &extensions.concat()))
    };
    tlv(48, &[id, status.to_vec(), date(), extensions].concat())
}
fn response(assertion: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let extensions = if extensions.is_empty() {
        Vec::new()
    } else {
        tlv(0xa1, &tlv(48, &extensions.concat()))
    };
    let data = tlv(
        48,
        &[
            tlv(0xa2, &tlv(4, &[0x33; 20])),
            date(),
            tlv(48, assertion),
            extensions,
        ]
        .concat(),
    );
    let basic = tlv(48, &[data, algorithm(), vec![3, 2, 0, 0xab]].concat());
    let bytes = tlv(
        48,
        &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]), tlv(4, &basic)].concat(),
    );
    tlv(48, &[&[10, 1, 0][..], &tlv(0xa0, &bytes)].concat())
}
fn decode<'a>(parser: &'a Parser, bytes: &'a [u8]) -> BasicResponse<'a> {
    let Response::Successful(payload) = Response::read(parser, bytes, 100).unwrap() else {
        panic!("fixture needs a successful envelope")
    };
    payload.into_basic(parser.memory()).unwrap().unwrap()
}
fn offset_of(bytes: &[u8], needle: &[u8]) -> u64 {
    100 + u64::try_from(
        bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn archive_cutoff_is_read_from_the_assertion_with_either_marking() {
    // RFC6960 §4.4.4 places the cutoff in singleExtensions and sets no
    // criticality, so a critical cutoff is understood, not an unknown demand.
    let parser = Parser::der(memory());
    for critical in [false, true] {
        let cutoff = extension(&CUTOFF, critical, &tlv(24, b"20190101000000Z"));
        let bytes = response(&assertion(&[0x80, 0], &[cutoff]), &[]);
        let basic = decode(&parser, &bytes);
        let single = &basic.responses()[0];
        let time = single.archive_cutoff(parser.memory()).unwrap().unwrap();
        assert_eq!(time.start().seconds(), 1_546_300_800);
        assert!(matches!(
            single.check_extensions(parser.memory()).unwrap(),
            ExtensionProcessing::Understood
        ));
    }
}

#[test]
fn archive_cutoff_accepts_der_fractional_seconds() {
    // ArchiveCutoff is bare GeneralizedTime (RFC6960 §4.4.4), not the
    // certificate validity profile. DER fractions must retain their value.
    let parser = Parser::der(memory());
    for (label, nanos, remainder) in [
        (&b"20190101000000.5Z"[..], 500_000_000, false),
        (&b"20190101000000.123456789Z"[..], 123_456_789, false),
        (&b"20190101000000.0000000001Z"[..], 0, true),
        (&b"20190101000000.9999999999Z"[..], 999_999_999, true),
    ] {
        let cutoff = extension(&CUTOFF, false, &tlv(24, label));
        let bytes = response(&assertion(&[0x80, 0], &[cutoff]), &[]);
        let basic = decode(&parser, &bytes);
        let single = &basic.responses()[0];
        let time = single.archive_cutoff(parser.memory()).unwrap().unwrap();
        assert_eq!(time.start().seconds(), 1_546_300_800);
        assert_eq!(time.start().nanos(), nanos);
        assert_eq!(time.has_subnanosecond_remainder(), remainder);
        assert!(matches!(
            single.check_extensions(parser.memory()).unwrap(),
            ExtensionProcessing::Understood
        ));
    }
}

#[test]
fn fractional_cutoff_admits_the_whole_scan_under_current_work() {
    // A late nonzero digit must not be discarded or scanned on credit from
    // the producing parse. Exact current work succeeds; one unit less refuses
    // at the original time, with no current-account storage allocation.
    let parser = Parser::der(memory());
    let label = b"20190101000000.000000000000000000000000000000000000000000000000001Z";
    let value = tlv(24, label);
    let cutoff = extension(&CUTOFF, false, &value);
    let bytes = response(&assertion(&[0x80, 0], &[cutoff]), &[]);
    let basic = decode(&parser, &bytes);
    let single = &basic.responses()[0];
    let probe = memory();
    let expected = single.archive_cutoff(&probe).unwrap().unwrap();
    assert!(expected.has_subnanosecond_remainder());
    let cost = probe.work_used();
    for available in [cost - 1, cost] {
        let current = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, available)));
        let result = single.archive_cutoff(&current);
        if available == cost {
            assert_eq!(result.unwrap(), Some(expected));
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource(), "{error:?}");
            assert_eq!(error.offset(), offset_of(&bytes, &value));
        }
        assert_eq!(current.used(), 0);
    }
    let query = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(),
    );
    let reader = query.read(&[], 0).unwrap();
    let error = single.archive_cutoff(&reader.execution()).unwrap_err();
    assert!(error.is_resource(), "{error:?}");
}

#[test]
fn absent_cutoff_is_none_and_a_response_level_one_is_not_read_as_the_assertions() {
    // The cutoff belongs to one assertion; a responseExtensions copy is an
    // unrelated noncritical value and must not stand in for it.
    let parser = Parser::der(memory());
    let cutoff = extension(&CUTOFF, false, &tlv(24, b"20190101000000Z"));
    let bytes = response(&assertion(&[0x80, 0], &[]), &[cutoff]);
    let basic = decode(&parser, &bytes);
    assert!(
        basic.responses()[0]
            .archive_cutoff(parser.memory())
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_cutoff_is_a_located_fault_in_both_readings() {
    // UTCTime is not the GeneralizedTime syntax, and trailing bytes are not
    // one value; neither is silently absent or understood.
    let parser = Parser::der(memory());
    for value in [
        tlv(23, b"190101000000Z"),
        [tlv(24, b"20190101000000Z"), vec![5, 0]].concat(),
        tlv(24, b"2019010100Z"),
        tlv(24, b"20190101000000.0Z"),
        tlv(24, b"20190101000000.50Z"),
        tlv(24, b"20190101000000,5Z"),
        tlv(24, b"20190101000000.5+0000"),
    ] {
        let cutoff = extension(&CUTOFF, false, &value);
        let bytes = response(&assertion(&[0x80, 0], std::slice::from_ref(&cutoff)), &[]);
        let basic = decode(&parser, &bytes);
        let single = &basic.responses()[0];
        let error = single.archive_cutoff(parser.memory()).unwrap_err();
        assert!(!error.is_resource(), "{error:?}");
        assert!(error.offset() >= offset_of(&bytes, &cutoff), "{error:?}");
        let again = single.check_extensions(parser.memory()).unwrap_err();
        assert_eq!(again.code(), error.code());
    }
}

#[test]
fn unknown_critical_assertion_demands_stay_unsupported() {
    // Supporting the cutoff does not make every critical extension understood.
    let parser = Parser::der(memory());
    let unknown = extension(&UNKNOWN, true, &[5, 0]);
    let bytes = response(&assertion(&[0x80, 0], std::slice::from_ref(&unknown)), &[]);
    let basic = decode(&parser, &bytes);
    let ExtensionProcessing::Unsupported { kind, span } = basic.responses()[0]
        .check_extensions(parser.memory())
        .unwrap()
    else {
        panic!("unknown critical demand was understood")
    };
    assert_eq!(kind.as_bytes(), UNKNOWN);
    assert_eq!(span.start, offset_of(&bytes, &unknown));
}

#[test]
fn extended_revoke_is_read_only_from_a_noncritical_null_response_extension() {
    // RFC6960 §4.4.8: NULL value, never critical, responseExtensions only.
    let parser = Parser::der(memory());
    let present = response(
        &assertion(&[0x80, 0], &[]),
        &[extension(&EXTENDED, false, &[5, 0])],
    );
    let basic = decode(&parser, &present);
    assert!(basic.extended_revoke(parser.memory()).unwrap());
    assert!(matches!(
        basic.check_extensions(parser.memory()).unwrap(),
        ExtensionProcessing::Understood
    ));
    let absent = response(&assertion(&[0x80, 0], &[]), &[]);
    assert!(
        !decode(&parser, &absent)
            .extended_revoke(parser.memory())
            .unwrap()
    );
}

#[test]
fn critical_or_non_null_extended_revoke_is_a_fault_not_an_unknown_demand() {
    // A critical marking the clause forbids, or a value other than NULL, is
    // a malformed response rather than an unsupported critical extension.
    let parser = Parser::der(memory());
    for (critical, value) in [
        (true, vec![5, 0]),
        (false, vec![5, 1, 0]),
        (false, vec![4, 0]),
        (false, vec![5, 0, 5, 0]),
    ] {
        let flagged = extension(&EXTENDED, critical, &value);
        let bytes = response(&assertion(&[0x80, 0], &[]), std::slice::from_ref(&flagged));
        let basic = decode(&parser, &bytes);
        let error = basic.extended_revoke(parser.memory()).unwrap_err();
        assert!(!error.is_resource(), "{error:?}");
        assert!(error.offset() >= offset_of(&bytes, &flagged));
        if critical {
            assert_eq!(error.code(), ErrorCode::MalformedValue);
        }
        let again = basic.check_extensions(parser.memory()).unwrap_err();
        assert_eq!(again.code(), error.code());
    }
}

#[test]
fn extended_revoke_inside_an_assertion_is_a_fault() {
    // §4.4.8: it "MUST NOT appear in singleExtensions".
    let parser = Parser::der(memory());
    let misplaced = extension(&EXTENDED, false, &[5, 0]);
    let bytes = response(
        &assertion(&[0x80, 0], std::slice::from_ref(&misplaced)),
        &[],
    );
    let basic = decode(&parser, &bytes);
    let error = basic.responses()[0]
        .check_extensions(parser.memory())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.offset(), offset_of(&bytes, &misplaced));
}

#[test]
fn status_of_rejects_a_single_extension_marker_before_deriving_status() {
    // RFC6960 §4.4.8 forbids the marker in singleExtensions even when a
    // response-wide marker and the exact not-issued tuple are also present.
    // An unrelated critical demand must not hide this placement error.
    let parser = Parser::der(memory());
    let misplaced = extension(&EXTENDED, false, &[5, 0]);
    for extensions in [
        vec![misplaced.clone()],
        vec![extension(&UNKNOWN, true, &[5, 0]), misplaced.clone()],
    ] {
        let bytes = response(
            &assertion(&revoked(&epoch(), Some(6)), &extensions),
            &[extension(&EXTENDED, false, &[5, 0])],
        );
        let basic = decode(&parser, &bytes);
        let error = basic.status_of(0, parser.memory()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
        assert_eq!(error.field(), "ocspResponse.singleResponse.extendedRevoke");
        assert_eq!(error.offset(), offset_of(&bytes, &misplaced));
    }
}

#[test]
fn only_the_exact_tuple_under_extended_revoke_reads_as_not_issued() {
    // RFC6960 §2.2: certificateHold, revocationTime 1970-01-01T00:00:00Z, no
    // CRL references or CRL entry extensions, under the extended definition.
    // Every other combination, including that tuple without the extension,
    // keeps its ordinary revoked reading.
    let parser = Parser::der(memory());
    let extended = || vec![extension(&EXTENDED, false, &[5, 0])];
    let hold = revoked(&epoch(), Some(6));
    let not_issued = response(&assertion(&hold, &[]), &extended());
    let basic = decode(&parser, &not_issued);
    let single = &basic.responses()[0];
    assert_eq!(
        basic.status_of(0, parser.memory()).unwrap(),
        Some(Status::NotIssued)
    );
    assert!(matches!(
        single.status(),
        Status::Revoked {
            reason: Some(Reason::CertificateHold),
            ..
        }
    ));

    let crl_references = extension(&CRL_REFERENCES, false, &tlv(48, &[]));
    let invalidity = extension(&INVALIDITY_DATE, false, &epoch());
    for (status, extensions, carried) in [
        (hold.clone(), Vec::new(), Vec::new()),
        (revoked(&date(), Some(6)), Vec::new(), extended()),
        (
            revoked(&tlv(24, b"19700101000001Z"), Some(6)),
            Vec::new(),
            extended(),
        ),
        (revoked(&epoch(), Some(1)), Vec::new(), extended()),
        (revoked(&epoch(), None), Vec::new(), extended()),
        (hold.clone(), vec![crl_references], extended()),
        (hold.clone(), vec![invalidity], extended()),
    ] {
        let bytes = response(&assertion(&status, &extensions), &carried);
        let basic = decode(&parser, &bytes);
        let single = &basic.responses()[0];
        let reading = basic.status_of(0, parser.memory()).unwrap().unwrap();
        assert!(matches!(reading, Status::Revoked { .. }), "{reading:?}");
        assert_eq!(reading, single.status());
    }
    for status in [vec![0x80, 0], vec![0x82, 0]] {
        let bytes = response(&assertion(&status, &[]), &extended());
        let basic = decode(&parser, &bytes);
        let single = &basic.responses()[0];
        assert_eq!(
            basic.status_of(0, parser.memory()).unwrap(),
            Some(single.status())
        );
    }
}

#[test]
fn status_of_reads_only_this_responses_assertions_under_its_own_marker() {
    // RFC6960 §4.4.8 scopes the extended definition to the response carrying
    // it. Assertions are named by position in that response, so a hold from a
    // response without the marker cannot be read under another one's marker,
    // and a position past the last assertion names nothing.
    let parser = Parser::der(memory());
    let hold = revoked(&epoch(), Some(6));
    let marked = response(
        &assertion(&hold, &[]),
        &[extension(&EXTENDED, false, &[5, 0])],
    );
    let plain = response(&assertion(&hold, &[]), &[]);
    let marked = decode(&parser, &marked);
    let plain = decode(&parser, &plain);
    assert_eq!(
        marked.status_of(0, parser.memory()).unwrap(),
        Some(Status::NotIssued)
    );
    assert!(matches!(
        plain.status_of(0, parser.memory()).unwrap(),
        Some(Status::Revoked {
            reason: Some(Reason::CertificateHold),
            ..
        })
    ));
    assert_eq!(marked.status_of(1, parser.memory()).unwrap(), None);
}

#[test]
fn readings_charge_the_current_execution() {
    // Each reading is paid before it runs: a spent ceiling is a resource
    // refusal, not an absent extension or an ordinary hold.
    let parser = Parser::der(memory());
    let cutoff = extension(&CUTOFF, false, &tlv(24, b"20190101000000Z"));
    let hold = revoked(&epoch(), Some(6));
    let bytes = response(
        &assertion(&hold, &[cutoff]),
        &[extension(&EXTENDED, false, &[5, 0])],
    );
    let basic = decode(&parser, &bytes);
    let single = &basic.responses()[0];
    let spent = Parser::new(
        Encoding::Der,
        Limits::default(),
        Memory::new(std::sync::Arc::new(MemoryAccount::new(128 * 1024, 0))),
    );
    let none = spent.memory();
    assert!(single.archive_cutoff(none).unwrap_err().is_resource());
    assert!(basic.extended_revoke(none).unwrap_err().is_resource());
    assert!(basic.status_of(0, none).unwrap_err().is_resource());
    assert!(single.check_extensions(none).unwrap_err().is_resource());
}
