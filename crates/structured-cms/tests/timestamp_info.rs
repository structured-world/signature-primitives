//! Complete required timestamp fields retain uniquely readable schema faults.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{
    ErrorCode,
    timestamp::{HashAlgorithmReading, TokenInfo},
};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if bytes.len() < 128 {
        output.push(u8::try_from(bytes.len()).unwrap());
    } else {
        output.push(0x82);
        output.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
    }
    output.extend_from_slice(bytes);
    output
}
fn imprint(bare: bool) -> Vec<u8> {
    let mut body = if bare {
        vec![6, 1, 42]
    } else {
        vec![0x30, 3, 6, 1, 42]
    };
    body.extend_from_slice(&[4, 2, b'a', b'b']);
    tlv(0x30, &body)
}
fn fields(bare: bool, serial: &[u8], time: &[u8]) -> Vec<u8> {
    let mut fields = vec![2, 1, 1, 6, 1, 43];
    fields.extend(imprint(bare));
    fields.extend(tlv(2, serial));
    fields.extend_from_slice(time);
    fields
}
fn time() -> Vec<u8> {
    tlv(0x18, b"20260101000000Z")
}

#[test]
fn repeated_integer_must_match_nonce_not_an_unrelated_prior_field() {
    // Once nonce is populated, a version/serial match cannot rescue a
    // conflicting second nonce. Equal nonce recovery retains one fault.
    for repeated in [1, 7, 9] {
        let mut body = fields(false, &[7], &time());
        body.extend([2, 1, 9]);
        let offset = body.len();
        body.extend([2, 1, repeated]);
        let bytes = tlv(0x30, &body);
        let account = memory();
        let parser = Parser::ber(account.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let result = TokenInfo::read(&parent, &element);
        if repeated == 9 {
            let info = result.unwrap();
            assert_eq!(info.nonce().unwrap().value().as_u64(), Some(9));
            assert_eq!(info.faults().len(), 1);
            assert_eq!(info.faults()[0].code(), ErrorCode::DuplicateField);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::DuplicateField);
            assert_eq!(error.offset(), 402 + u64::try_from(offset).unwrap());
        }
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn displaced_version_does_not_choose_between_serial_and_nonce() {
    // After policy/imprint, INTEGER 1 could be displaced version or serial
    // with version missing. A second INTEGER cannot make that reading unique.
    let mut body = vec![6, 1, 43];
    body.extend(imprint(false));
    body.extend([2, 1, 1, 2, 1, 9]);
    body.extend(time());
    let bytes = tlv(0x30, &body);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let Err(error) = TokenInfo::read(&parent, &element) else {
        panic!("ambiguous version/serial/nonce was assigned a value");
    };
    assert_eq!(error.code(), ErrorCode::DuplicateField);
    drop(error);
    assert_eq!(memory.used(), 0);
}

#[test]
fn repeated_policy_ber_lengths_preserve_one_reading() {
    // Length spelling is encoding, not OID identity. Recovery is an inspection
    // contract: keep the original policy and a duplicate fault, never evidence.
    let mut body = fields(false, &[7], &time());
    body.extend([6, 0x81, 1, 43]);
    let bytes = tlv(0x30, &body);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    assert_eq!(info.policy().as_bytes(), &[43]);
    assert!(
        info.faults()
            .iter()
            .any(|fault| fault.code() == ErrorCode::DuplicateField)
    );
    drop(info);
    assert_eq!(memory.used(), 0);
}

#[test]
fn canonical_timestamp_has_required_views_without_invented_accuracy() {
    // Parsing is provider-independent. Absent complete Accuracy is not zero;
    // serial sign/size are not restricted beyond the actual reader ceilings.
    let bytes = tlv(0x30, &fields(false, &[0xff], &time()));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    assert!(!info.has_faults());
    assert_eq!(info.policy().as_bytes(), &[43]);
    assert!(matches!(
        info.imprint().algorithm(),
        HashAlgorithmReading::Identifier(_)
    ));
    assert_eq!(info.imprint().hashed().as_one(), Some(&b"ab"[..]));
    assert!(info.serial().value().is_negative());
    assert_eq!(info.serial().element().contents(), &[0xff]);
    assert_eq!(info.gen_time().start().seconds(), 1_767_225_600);
    assert!(info.accuracy().is_none());
    assert!(!info.ordering());
    assert!(info.nonce().is_none());
    assert!(info.tsa().is_none());
    assert!(info.extensions().is_none());
    drop(info);
    assert_eq!(memory.used(), 0);
}

#[test]
fn bare_oid_imprint_no_longer_erases_serial_or_generation_time() {
    // The old discriminator assigned this sequence to Accuracy and lost the
    // required imprint. Recover the one malformed algorithm reading instead.
    let bytes = tlv(0x30, &fields(true, &[7], &time()));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    assert!(info.has_faults());
    assert!(info.accuracy().is_none());
    assert!(matches!(
        info.imprint().algorithm(),
        HashAlgorithmReading::Malformed { kind: Some(_), .. }
    ));
    assert_eq!(info.imprint().faults()[0].code(), ErrorCode::MalformedValue);
    assert_eq!(info.serial().value().as_u64(), Some(7));
    assert_eq!(info.gen_time().start().seconds(), 1_767_225_600);
    drop(info);
    assert_eq!(memory.used(), 0);
}

#[test]
fn constructed_time_uses_shared_decoder_and_retains_der_fault() {
    // BER octet fragments retain a unique time label, but cannot silently become
    // conforming DER or a successful proof. No private calendar/collector runs.
    let mut segments = tlv(4, b"20260101");
    segments.extend(tlv(4, b"000000Z"));
    let bytes = tlv(0x30, &fields(false, &[7], &tlv(0x38, &segments)));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    assert_eq!(info.gen_time().start().seconds(), 1_767_225_600);
    assert!(info.has_faults());
    assert!(!info.faults().is_empty());
    drop(info);
    assert_eq!(memory.used(), 0);
}

#[test]
fn semantic_duplicate_tsa_keeps_first_encoding_and_a_fault() {
    // Common DNS identity, not a private byte comparer, governs different
    // spellings; the first original encoding remains the reporting source.
    let mut names = tlv(0x82, b"EXAMPLE.COM");
    names.extend(tlv(0x82, b"example.com"));
    let mut body = fields(false, &[7], &time());
    body.extend(tlv(0xa0, &names));
    let bytes = tlv(0x30, &body);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&parent, &element).unwrap();
    let tsa = info.tsa().unwrap();
    assert!(tsa.name().is_some());
    assert_eq!(tsa.element().unwrap().contents(), b"EXAMPLE.COM");
    assert!(info.has_faults());
    assert!(
        info.faults().iter().any(
            |fault| fault.field() == "tstInfo.tsa" && fault.code() == ErrorCode::DuplicateField
        )
    );
    drop(info);
    assert_eq!(memory.used(), 0);
}

#[test]
fn unreadable_optional_tsa_stays_present_and_does_not_erase_other_fields() {
    // Empty/malformed bounded wrappers occupy the optional slot. They are
    // faults, not absence or authority equality, while serial/time stay visible.
    for wrapper in [tlv(0xa0, &[]), tlv(0xa0, &[0x82, 0x82, 1])] {
        let mut body = fields(false, &[7], &time());
        body.extend(wrapper);
        let bytes = tlv(0x30, &body);
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let info = TokenInfo::read(&parent, &element).unwrap();
        assert!(info.tsa().unwrap().name().is_none());
        assert!(info.has_faults());
        assert_eq!(info.serial().value().as_u64(), Some(7));
        assert_eq!(info.gen_time().start().seconds(), 1_767_225_600);
        drop(info);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn competing_integer_roles_refuse_instead_of_assigning_by_encounter_order() {
    // An additional integer before genTime can exchange serial/nonce roles;
    // no complete reading may select one merely because its slot was free.
    let mut body = vec![2, 1, 1, 6, 1, 43];
    body.extend(imprint(false));
    body.extend_from_slice(&[2, 1, 7, 2, 1, 8]);
    body.extend(time());
    let bytes = tlv(0x30, &body);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = TokenInfo::read(&parent, &element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::DuplicateField);
    drop(error);
    assert_eq!(memory.used(), 0);
}
