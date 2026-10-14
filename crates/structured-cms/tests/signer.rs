//! Real schema choices, original signature ranges and duplicate recovery limits.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::ErrorCode;
use structured_cms::signer::{SignerIdentifier, SignerInfo};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(262_144, 262_144)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128);
    let mut encoded = vec![tag, u8::try_from(contents.len()).unwrap()];
    encoded.extend_from_slice(contents);
    encoded
}

fn signer(sid: &[u8], signature: &[u8], version: u8) -> Vec<u8> {
    let mut inside = vec![2, 1, version];
    inside.extend_from_slice(sid);
    inside.extend_from_slice(&[0x30, 3, 6, 1, 42]);
    inside.extend_from_slice(&[0x30, 3, 6, 1, 43]);
    inside.extend_from_slice(signature);
    tlv(0x30, &inside)
}

fn named_signer(text: &[u8], tag: u8, serial: u8) -> Vec<u8> {
    let mut attribute = vec![6, 3, 0x55, 4, 3];
    attribute.extend(tlv(tag, text));
    let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)));
    let mut identity = name;
    identity.extend([2, 1, serial]);
    signer(&tlv(0x30, &identity), &[4, 1, 8], 1)
}

#[test]
fn duplicate_issuer_identity_uses_shared_name_semantics() {
    // RFC5280 §7.1 issuer equality must survive case, space and DirectoryString
    // spelling changes without changing the original signer or serial bytes.
    let original = named_signer(b"Example CA", 0x0c, 7);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&original, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&parent, &element).unwrap();
    for (text, tag, serial, expected) in [
        (&b"  EXAMPLE   ca  "[..], 0x13, 7, true),
        (&b"example ca"[..], 0x0c, 7, true),
        (&b"Other CA"[..], 0x0c, 7, false),
        (&b"example ca"[..], 0x0c, 8, false),
    ] {
        let bytes = named_signer(text, tag, serial);
        let mut parent = parser.read(&bytes, 900).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let right = SignerInfo::read(&parent, &element).unwrap();
        assert_eq!(left.same_value(&right, &parent).unwrap(), expected);
        assert_eq!(left.as_bytes(), original);
        assert_eq!(left.signature().as_one(), Some(&[8][..]));
    }
}

#[test]
fn issuer_normalization_refusals_keep_duplicate_location_and_release_scratch() {
    // Normalization uses current query funding; partial preparation must release
    // scratch while retained issuer catalogues stay on their original account.
    // Non-ASCII composition exercises allocating preparation rather than the
    // allocation-free borrowed ASCII fast path.
    let first = named_signer("Éxample CA".as_bytes(), 0x0c, 7);
    let second = named_signer("  E\u{301}XAMPLE   ca  ".as_bytes(), 0x0c, 7);
    let retained = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 100_000,
            ..Limits::default()
        },
        retained.clone(),
    );
    let mut parent = parser.read(&first, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&parent, &element).unwrap();
    let mut parent = parser.read(&second, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let right = SignerInfo::read(&parent, &element).unwrap();
    let original_capacity = retained.used();
    let full = memory();
    let query = parent.try_clone().unwrap().with_execution(&full);
    assert!(left.same_value(&right, &query).unwrap());
    let cost = full.work_used();
    assert!(cost > 1);
    assert_eq!(full.used(), 0);
    for (capacity, work) in [(262_144, 0), (262_144, cost - 1), (0, cost)] {
        let current = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let query = parent.try_clone().unwrap().with_execution(&current);
        let error = left.same_value(&right, &query).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "signedData.signerInfos");
        assert_eq!(error.offset(), 900);
        assert_eq!(current.used(), 0);
        assert_eq!(retained.used(), original_capacity);
    }
    while parent.charge(1).is_ok() {}
    let current = memory();
    let query = parent.with_execution(&current);
    let error = left.same_value(&right, &query).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 900);
    assert_eq!(current.work_used(), 0);
}

#[test]
fn both_sid_forms_preserve_values_and_original_primitive_signature() {
    // Both RFC5652 CHOICE branches must reach the same borrowed signature path.
    for (sid, version) in [(vec![0x80, 1, 7], 3), (vec![0x30, 5, 0x30, 0, 2, 1, 1], 1)] {
        let encoded = signer(&sid, &[4, 2, 8, 9], version);
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let value = SignerInfo::read(&reader, &element).unwrap();
        assert_eq!(value.version(), u64::from(version));
        assert_eq!(value.sid().required_version(), u64::from(version));
        assert_eq!(value.signature().as_one(), Some(&[8, 9][..]));
        assert_eq!(
            value.signature().as_one().unwrap().as_ptr(),
            encoded[encoded.len() - 2..].as_ptr()
        );
        assert!(value.faults().is_empty());
        assert_eq!(value.as_bytes(), encoded);
        drop(value);
        drop(reader);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn constructed_identifier_and_signature_share_the_octet_walker() {
    // IMPLICIT changes only the root tag: every child still uses universal OCTET STRING.
    let encoded = signer(
        &[0xa0, 6, 4, 1, 7, 4, 1, 8],
        &[0x24, 6, 4, 1, 9, 4, 1, 10],
        3,
    );
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    let SignerIdentifier::SubjectKeyIdentifier(identifier) = value.sid() else {
        panic!("wrong choice");
    };
    assert_eq!(identifier.len(), 2);
    assert_eq!(identifier.pieces()[0].as_bytes(), [7]);
    assert_eq!(identifier.pieces()[1].as_bytes(), [8]);
    assert_eq!(value.signature().pieces()[0].as_bytes(), [9]);
    assert_eq!(value.signature().pieces()[1].as_bytes(), [10]);
    assert!(memory.used() > 0);
    drop(reader);
    assert!(memory.used() > 0);
    drop(value);
    assert_eq!(memory.used(), 0);
}

#[test]
fn uniquely_readable_version_mismatch_is_retained_with_capacity() {
    // Readability must not erase a normative fault or pretend the signer conforms.
    let encoded = signer(&[0x80, 1, 7], &[4, 1, 8], 1);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    assert_eq!(value.faults().len(), 1);
    assert_eq!(value.faults()[0].code(), ErrorCode::VersionMismatch);
    assert_eq!(value.faults()[0].offset(), 402);
    assert_eq!(value.faults()[0].field(), "signerInfo.version");
    drop(reader);
    assert!(memory.used() > 0);
    drop(value);
    assert_eq!(memory.used(), 0);
}

#[test]
fn duplicate_value_ignores_outer_ber_and_segmentation_but_not_changed_signature() {
    // BER envelope length spelling cannot create a different parsed signer.
    let canonical = signer(&[0x80, 2, 7, 8], &[4, 2, 9, 10], 3);
    let segmented = signer(
        &[0xa0, 6, 4, 1, 7, 4, 1, 8],
        &[0x24, 6, 4, 1, 9, 4, 1, 10],
        3,
    );
    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&segmented[2..]);
    indefinite.extend_from_slice(&[0, 0]);
    let changed = signer(&[0x80, 2, 7, 8], &[4, 2, 9, 11], 3);
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&canonical, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&reader, &element).unwrap();
    for (encoded, expected) in [(&indefinite, true), (&changed, false)] {
        let mut right_reader = parser.read(encoded, 900).unwrap();
        let right_element = right_reader.next_element().unwrap().unwrap();
        let right = SignerInfo::read(&right_reader, &right_element).unwrap();
        assert_eq!(left.same_value(&right, &right_reader).unwrap(), expected);
    }
}

#[test]
fn duplicate_query_refusal_preserves_current_domain_and_duplicate_offset() {
    // A new account does not reset the producing local ceiling, and refusal is not false.
    let encoded = signer(&[0x80, 1, 7], &[4, 1, 8], 3);
    let old = memory();
    let current = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 4096,
            ..Limits::default()
        },
        old.clone(),
    );
    let mut reader = parser.read(&encoded, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    while reader.charge(1).is_ok() {}
    let old_work = old.work_used();
    let reader = reader.with_execution(&current);
    let error = value.same_value(&value, &reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 900);
    assert_eq!(error.field(), "signedData.signerInfos");
    assert_eq!(old.work_used(), old_work);
    assert_eq!(current.work_used(), 0);
}

#[test]
fn trailing_component_and_wrong_implicit_children_are_not_recovered() {
    // Ambiguous/excess schema fields and non-octet SKI fragments remain refusal.
    let mut extra = signer(&[0x80, 1, 7], &[4, 1, 8], 3);
    extra.extend_from_slice(&[5, 0]);
    extra[1] += 2;
    let wrong_child = signer(&[0xa0, 2, 5, 0], &[4, 1, 8], 3);
    for encoded in [extra, wrong_child] {
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert!(SignerInfo::read(&reader, &element).is_err());
        drop(reader);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn duplicate_primitive_parameters_ignore_ber_length_but_do_not_invent_defaults() {
    // X.690 8.1.3.3 permits both definite length spellings. Present NULL
    // values agree; absence and other parameter tags retain their distinction.
    fn with_parameter(parameter: &[u8]) -> Vec<u8> {
        let mut inside = vec![2, 1, 3, 0x80, 1, 7];
        inside.extend_from_slice(&tlv(0x30, &[&[6, 1, 42][..], parameter].concat()));
        inside.extend_from_slice(&[0x30, 3, 6, 1, 43, 4, 1, 8]);
        tlv(0x30, &inside)
    }
    let canonical = with_parameter(&[5, 0]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&canonical, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&parent, &element).unwrap();
    for (parameter, expected) in [
        (&[5, 0x81, 0][..], true),
        (&[][..], false),
        (&[4, 0][..], false),
    ] {
        let encoded = with_parameter(parameter);
        let mut right_parent = parser.read(&encoded, 900).unwrap();
        let element = right_parent.next_element().unwrap().unwrap();
        let right = SignerInfo::read(&right_parent, &element).unwrap();
        assert_eq!(left.same_value(&right, &right_parent).unwrap(), expected);
        assert_eq!(left.digest_algorithm().parameters(), Some(&[5, 0][..]));
        assert_eq!(
            right.digest_algorithm().parameters(),
            if parameter.is_empty() {
                None
            } else {
                Some(parameter)
            }
        );
    }
}

fn sha2_signer(kind: u8, parameter: &[u8]) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7];
    let mut algorithm = vec![6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, kind];
    algorithm.extend_from_slice(parameter);
    fields.extend(tlv(0x30, &algorithm));
    fields.extend([0xa0, 8, 0x30, 6, 6, 2, 42, 9, 0x31, 0]);
    fields.extend([0x30, 3, 6, 1, 43, 4, 1, 8]);
    tlv(0x30, &fields)
}

#[test]
fn duplicate_sha2_defaults_preserve_original_signed_octets() {
    // RFC5754 §2 gives these four digest identifiers the same absent/NULL
    // meaning; duplicate recovery must retain the first exact signedAttrs.
    for kind in [4, 1, 2, 3] {
        let first = sha2_signer(kind, &[]);
        let parser = Parser::ber(memory());
        let mut parent = parser.read(&first, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let left = SignerInfo::read(&parent, &element).unwrap();
        for parameter in [&[5, 0][..], &[5, 0x81, 0][..]] {
            let encoded = sha2_signer(kind, parameter);
            let mut right_parent = parser.read(&encoded, 900).unwrap();
            let element = right_parent.next_element().unwrap().unwrap();
            let right = SignerInfo::read(&right_parent, &element).unwrap();
            assert!(left.same_value(&right, &right_parent).unwrap());
            assert_eq!(left.as_bytes(), first);
            assert_eq!(left.digest_algorithm().parameters(), None);
            assert_eq!(right.digest_algorithm().parameters(), Some(parameter));
        }
    }
}

#[test]
fn identical_opaque_invalid_digest_parameters_remain_inspectable() {
    // Identity inspection is not algorithm acceptance: identical malformed
    // known parameters must not erase the readable duplicate or become defaults.
    let encoded = sha2_signer(1, &[0x30, 0]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&parent, &element).unwrap();
    assert!(value.same_value(&value, &parent).unwrap());
    assert_eq!(value.digest_algorithm().parameters(), Some(&[0x30, 0][..]));
}

#[test]
fn duplicate_foreign_session_refuses_before_field_shortcuts_or_work() {
    // A version mismatch must not hide foreign-parser misuse or consume query
    // work before both original sessions have been checked.
    let left_bytes = signer(&[0x80, 1, 7], &[4, 1, 8], 3);
    let right_bytes = signer(&[0x80, 1, 7], &[4, 1, 8], 1);
    let memory = memory();
    let left_parser = Parser::ber(memory.clone());
    let right_parser = Parser::ber(memory.clone());
    let mut left_parent = left_parser.read(&left_bytes, 400).unwrap();
    let left_element = left_parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&left_parent, &left_element).unwrap();
    let mut right_parent = right_parser.read(&right_bytes, 900).unwrap();
    let right_element = right_parent.next_element().unwrap().unwrap();
    let right = SignerInfo::read(&right_parent, &right_element).unwrap();
    let before = (memory.used(), memory.work_used());
    let error = left.same_value(&right, &left_parent).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(error.offset(), 900);
    assert_eq!((memory.used(), memory.work_used()), before);
}

#[test]
fn duplicate_algorithm_budget_boundaries_keep_the_extra_signer_location() {
    // Exhaust each admission boundary, including left SHA-2 validation and
    // signature comparison: every resource refusal identifies the duplicate.
    let first = sha2_signer(1, &[]);
    let second = sha2_signer(1, &[5, 0x81, 0]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&first, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&parent, &element).unwrap();
    let mut parent = parser.read(&second, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let right = SignerInfo::read(&parent, &element).unwrap();
    let full = memory();
    assert!(
        left.same_value(&right, &parent.try_clone().unwrap().with_execution(&full))
            .unwrap()
    );
    let cost = full.work_used();
    assert!(cost > 10);
    for available in 0..cost {
        let current = Memory::new(Arc::new(MemoryAccount::new(262_144, available)));
        let query = parent.try_clone().unwrap().with_execution(&current);
        let error = left.same_value(&right, &query).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "signedData.signerInfos");
        assert_eq!(error.offset(), 900);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn duplicate_parameter_syntax_error_keeps_its_original_algorithm() {
    // Only resource refusals are relocated; a known bad parameter keeps the
    // original algorithm field/offset rather than becoming duplicate mismatch.
    let first = sha2_signer(1, &[0x30, 0]);
    let second = sha2_signer(1, &[]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&first, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let left = SignerInfo::read(&parent, &element).unwrap();
    let mut parent = parser.read(&second, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let right = SignerInfo::read(&parent, &element).unwrap();
    let error = left.same_value(&right, &parent).unwrap_err();
    assert!(!error.is_resource());
    assert_eq!(error.field(), "signerInfo.digestAlgorithm");
    assert_eq!(error.offset(), left.digest_algorithm().offset());
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::MalformedValue)
    );
}
