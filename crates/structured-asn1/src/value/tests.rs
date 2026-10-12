use super::{bit_string, boolean, integer, null, oid, real};
use crate::error::ErrorCode;
use crate::length::Encoding;
use alloc::string::String;

fn decimal(value: super::Oid<'_>) -> String {
    let execution = crate::test_memory();
    value
        .text(&execution)
        .unwrap()
        .as_str(&execution)
        .unwrap()
        .into()
}

#[test]
fn identifiers_render_as_the_dotted_form_they_encode() {
    // The first two arcs share a byte, and the second arc runs past 39 only
    // when the root is 2, which is where the three cases below differ.
    for (bytes, dotted) in [
        (&[0x55, 0x1d, 0x13][..], "2.5.29.19"),
        (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d][..], "1.2.840.113549"),
        (&[0x28, 0x03][..], "1.0.3"),
        (&[0x06][..], "0.6"),
        (&[0x88, 0x37][..], "2.999"),
    ] {
        let parsed = oid(bytes).unwrap();
        assert_eq!(decimal(parsed), dotted, "{bytes:02x?}");
        assert_eq!(parsed.as_bytes(), bytes);
    }
}

#[test]
fn identifiers_that_cannot_be_read_are_refused() {
    // Empty, ends asking for a byte that is not there, and an arc padded with a
    // leading zero group, which is a second spelling of a number.
    for bytes in [&[][..], &[0x2a, 0x86][..], &[0x2a, 0x80, 0x01][..]] {
        assert_eq!(
            oid(bytes).unwrap_err(),
            ErrorCode::MalformedOid,
            "{bytes:02x?}"
        );
    }
}

#[test]
fn an_arc_that_fits_sixty_four_bits_is_read_whatever_its_group_count() {
    // 2^63 takes ten base-128 groups, the first carrying a single significant
    // bit. Counting seven bits per group would refuse it although the value
    // fits the promised representation.
    let bytes = [
        0x2a, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    let parsed = oid(&bytes).unwrap();
    assert_eq!(parsed.arcs().nth(2).unwrap().as_u64(), Some(1u64 << 63));
    assert_eq!(decimal(parsed), "1.2.9223372036854775808");
}

#[test]
fn the_first_pair_carries_its_eighty_arc_offset() {
    // The first subidentifier joins two arcs as 40 * first + second, so
    // under root 2 the second arc reaches the sixty-four-bit ceiling with a
    // joint value eighty above it: one bit more than any single arc needs.
    // Refusing that pair would shrink the promised arc range at the top.
    let mut combined = u128::from(u64::MAX) + 80;
    let mut groups = alloc::vec::Vec::new();
    while combined > 0 {
        groups.push(u8::try_from(combined & 0x7f).unwrap());
        combined >>= 7;
    }
    groups.reverse();
    let last = groups.len() - 1;
    for group in &mut groups[..last] {
        *group |= 0x80;
    }
    let parsed = oid(&groups).unwrap();
    let arcs: alloc::vec::Vec<Option<u64>> = parsed.arcs().map(super::Arc::as_u64).collect();
    assert_eq!(arcs, [Some(2), Some(u64::MAX)]);

    // One past it no longer fits the second arc's integer, and the arc says
    // so while still printing the number the document names.
    let mut combined = u128::from(u64::MAX) + 81;
    let mut groups = alloc::vec::Vec::new();
    while combined > 0 {
        groups.push(u8::try_from(combined & 0x7f).unwrap());
        combined >>= 7;
    }
    groups.reverse();
    let last = groups.len() - 1;
    for group in &mut groups[..last] {
        *group |= 0x80;
    }
    let parsed = oid(&groups).unwrap();
    assert_eq!(parsed.arcs().nth(1).unwrap().as_u64(), None);
    assert_eq!(decimal(parsed), "2.18446744073709551616");
}

#[test]
fn an_arc_wider_than_this_reader_is_still_read() {
    // Ten continuation groups carry seventy bits. The identifier is written
    // correctly, and refusing it would blame the document for a width that
    // belongs to this reader.
    let bytes = [
        0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    let parsed = oid(&bytes).unwrap();
    assert_eq!(parsed.arcs().nth(2).unwrap().as_u64(), None);
    assert_eq!(decimal(parsed), "1.2.1180591620717411303423");
}

#[test]
fn integers_keep_their_bytes_and_convert_on_request() {
    let serial = integer(&[0x00, 0xd8, 0x1c, 0x4d]).unwrap();
    assert_eq!(serial.as_u64(), Some(0x00d8_1c4d));
    assert!(!serial.is_negative());
    // The leading zero is the sign byte, and it stays: a serial number is
    // compared as it was encoded.
    assert_eq!(serial.as_bytes(), &[0x00, 0xd8, 0x1c, 0x4d]);

    let negative = integer(&[0x80]).unwrap();
    assert!(negative.is_negative());
    assert_eq!(negative.as_i64(), Some(-128));
    assert_eq!(negative.as_u64(), None);

    assert_eq!(integer(&[0x00]).unwrap().as_u64(), Some(0));
    assert_eq!(integer(&[0x7f]).unwrap().as_i64(), Some(127));
    assert_eq!(integer(&[0xff]).unwrap().as_i64(), Some(-1));

    // Nine bytes hold more than sixty-four bits even when the first is a sign
    // byte carrying no magnitude, which the unsigned reading drops.
    let wide = integer(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(wide.as_u64(), Some(u64::MAX));
    assert_eq!(wide.as_i64(), None);
}

#[test]
fn integers_written_a_byte_longer_than_needed_are_refused() {
    assert_eq!(integer(&[]).unwrap_err(), ErrorCode::IntegerEmpty);
    assert_eq!(
        integer(&[0x00, 0x7f]).unwrap_err(),
        ErrorCode::IntegerNotMinimal
    );
    assert_eq!(
        integer(&[0xff, 0x80]).unwrap_err(),
        ErrorCode::IntegerNotMinimal
    );
    // Both bytes are needed here: without the leading zero the value reads as
    // negative, and without the leading 0xff it reads as positive.
    assert!(integer(&[0x00, 0x80]).is_ok());
    assert!(integer(&[0xff, 0x7f]).is_ok());
}

#[test]
fn a_bit_string_addresses_bits_rather_than_bytes() {
    // digitalSignature and keyCertSign, as a key usage extension writes them:
    // bits 0 and 5, so the two bits after them are padding.
    let usage = bit_string(&[0x02, 0x84], Encoding::Der).unwrap();
    assert_eq!(usage.len(), 6);
    assert!(usage.bit(0));
    assert!(!usage.bit(1));
    assert!(usage.bit(5));
    // Past the end reads as unset, which is what a usage shorter than the bit
    // asked about means rather than an error about a bit nobody encoded.
    assert!(!usage.bit(6));
    assert!(!usage.bit(64));
    assert_eq!(usage.octets(), None);

    let whole = bit_string(&[0x00, 0xde, 0xad], Encoding::Der).unwrap();
    assert_eq!(whole.octets(), Some(&[0xde, 0xad][..]));
    assert_eq!(whole.len(), 16);

    let empty = bit_string(&[0x00], Encoding::Der).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(!empty.bit(0));
}

#[test]
fn bit_strings_that_could_hide_bytes_in_the_padding_are_refused() {
    // No count of padding bits at all.
    assert_eq!(
        bit_string(&[], Encoding::Der).unwrap_err(),
        ErrorCode::MalformedBitString
    );
    // A padding count of eight would mean the last byte holds nothing.
    assert_eq!(
        bit_string(&[0x08, 0xff], Encoding::Der).unwrap_err(),
        ErrorCode::MalformedBitString
    );
    // Nothing to pad.
    assert_eq!(
        bit_string(&[0x01], Encoding::Der).unwrap_err(),
        ErrorCode::MalformedBitString
    );
    // Padding bits carrying data: a place to put a byte that a reader looking
    // only at the bits it was told about will never report.
    assert_eq!(
        bit_string(&[0x04, 0x8f], Encoding::Der).unwrap_err(),
        ErrorCode::MalformedBitString
    );
    // BER does not settle the padding, so the same bytes are readable there.
    assert!(bit_string(&[0x04, 0x8f], Encoding::Ber).is_ok());
}

#[test]
fn a_boolean_has_one_spelling_under_der_and_several_under_ber() {
    assert_eq!(boolean(&[0x00], Encoding::Der), Ok(false));
    assert_eq!(boolean(&[0xff], Encoding::Der), Ok(true));
    assert_eq!(
        boolean(&[0x01], Encoding::Der).unwrap_err(),
        ErrorCode::MalformedBoolean
    );
    assert_eq!(boolean(&[0x01], Encoding::Ber), Ok(true));
    // Length is not the encoding's business either way.
    for encoding in [Encoding::Der, Encoding::Ber] {
        assert_eq!(
            boolean(&[], encoding).unwrap_err(),
            ErrorCode::MalformedBoolean
        );
        assert_eq!(
            boolean(&[0x00, 0x00], encoding).unwrap_err(),
            ErrorCode::MalformedBoolean
        );
    }
}

#[test]
fn a_null_carries_nothing() {
    assert_eq!(null(&[]), Ok(()));
    assert_eq!(null(&[0x00]).unwrap_err(), ErrorCode::MalformedNull);
}

#[test]
#[should_panic(expected = "not a well formed object identifier")]
fn a_constant_with_a_padded_arc_is_refused_at_construction() {
    // The constant constructor holds the rules the document reader does, so
    // a mistyped table entry fails where it is written rather than naming an
    // identifier no document could carry. A padded arc is a second spelling
    // of a number that already has one.
    let _ = super::Oid::from_bytes(&[0x2a, 0x80, 0x01]);
}

#[test]
#[should_panic(expected = "not a well formed object identifier")]
fn a_constant_ending_mid_arc_is_refused_at_construction() {
    // The last byte asks for a continuation that never came.
    let _ = super::Oid::from_bytes(&[0x2a, 0x86]);
}

#[test]
fn a_constant_naming_a_wide_arc_is_built() {
    // Width is not a rule here either: an arc past any integer this crate
    // names is still an identifier, and a table may name one.
    let wide = super::Oid::from_bytes(&[
        0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ]);
    assert_eq!(decimal(wide), "1.2.1180591620717411303423");
}

#[test]
fn an_arc_wider_than_sixty_four_bits_is_read_and_printed() {
    // Eleven groups carrying 128^10, which is 2^70. The encoding bounds no
    // subidentifier (X.690 8.19.2), so an identifier naming one is valid and
    // a reader that refused it would abort a whole certificate over an arc
    // nobody has to interpret.
    let mut bytes = alloc::vec![0x2a, 0x81];
    bytes.extend(core::iter::repeat_n(0x80, 9));
    bytes.push(0x00);

    let parsed = oid(&bytes).unwrap();
    assert_eq!(decimal(parsed), "1.2.1180591620717411303424");
    // The value does not fit the integer this crate names, and the arc says
    // so rather than reporting some other number.
    assert_eq!(parsed.arcs().nth(2).unwrap().as_u64(), None);
    // The narrow arcs beside it still answer.
    assert_eq!(parsed.arcs().next().unwrap().as_u64(), Some(1));
}

#[test]
fn an_arc_past_the_accumulator_keeps_its_own_value() {
    // 2^133 + 1: twenty base-128 groups, the value one bit past what any
    // integer here holds. Shifting an accumulator by seven drops the high
    // bits silently, which would leave a small number in place of the real
    // one and print an identifier the document never named.
    let mut bytes = alloc::vec![0x2a, 0x81];
    bytes.extend(core::iter::repeat_n(0x80, 18));
    bytes.push(0x01);

    let parsed = oid(&bytes).unwrap();
    assert_eq!(parsed.arcs().nth(2).unwrap().as_u64(), None);
    assert_eq!(
        decimal(parsed),
        "1.2.10889035741470030830827987437816582766593"
    );
}

// Independent test oracle: accumulate base-128 groups by multiplication in
// base ten, rather than production's division into decimal blocks.
fn reference_decimal(groups: impl Iterator<Item = u8>, offset: u8) -> String {
    let mut digits = alloc::vec![0u8];
    for group in groups {
        let mut carry = u16::from(group & 0x7f);
        for digit in &mut digits {
            let value = u16::from(*digit) * 128 + carry;
            *digit = u8::try_from(value % 10).unwrap();
            carry = value / 10;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 10).unwrap());
            carry /= 10;
        }
    }
    let mut owed = offset;
    for digit in &mut digits {
        let next = owed / 10;
        let remainder = owed % 10;
        if *digit >= remainder {
            *digit -= remainder;
            owed = next;
        } else {
            *digit = *digit + 10 - remainder;
            owed = next + 1;
        }
        if owed == 0 {
            break;
        }
    }
    assert_eq!(owed, 0);
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    digits
        .into_iter()
        .rev()
        .map(|digit| char::from(b'0' + digit))
        .collect()
}

#[test]
fn a_wide_arc_takes_the_joint_offset_off_before_it_is_written() {
    // The packed first subidentifier is 2^4193; subtracting eighty must
    // borrow across its entire zero suffix and preserve every decimal digit.
    let mut bytes = alloc::vec![0x81];
    bytes.extend(core::iter::repeat_n(0x80, 598));
    bytes.push(0x00);
    let rendered = decimal(oid(&bytes).unwrap());
    let expected = reference_decimal(bytes.iter().copied(), 80);
    assert_eq!(rendered.strip_prefix("2."), Some(expected.as_str()));
}

#[test]
fn a_very_wide_arc_is_exact_or_returns_a_resource_error() {
    // Width alone cannot select another representation. Both the old
    // decimal boundary and old hex region must retain the exact value.
    for groups in [512, 4001] {
        let mut bytes = alloc::vec![0x2a];
        bytes.extend(core::iter::repeat_n(0xff, groups - 1));
        bytes.push(0x7f);
        let rendered = decimal(oid(&bytes).unwrap());
        let expected = reference_decimal(bytes[1..].iter().copied(), 0);
        assert_eq!(rendered.strip_prefix("1.2."), Some(expected.as_str()));
    }
    // Mixed groups just above the old cutoff detect repacking mistakes.
    let mut bytes = alloc::vec![0x2a];
    bytes.extend(core::iter::repeat_n(0x81, 512));
    bytes.push(0x02);
    let rendered = decimal(oid(&bytes).unwrap());
    let expected = reference_decimal(bytes[1..].iter().copied(), 0);
    assert_eq!(rendered.strip_prefix("1.2."), Some(expected.as_str()));

    // A hostile 40001-group value is refused before a conversion pass can
    // exceed the caller's work ceiling; no diagnostic fallback escapes it.
    let mut bytes = alloc::vec![0x2a];
    bytes.extend(core::iter::repeat_n(0xff, 40000));
    bytes.push(0x7f);
    let execution = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(100_000, 200_000),
    ));
    assert_eq!(
        oid(&bytes).unwrap().text(&execution).unwrap_err(),
        crate::memory::MemoryError::WorkExceeded,
    );
    assert_eq!(execution.used(), 0);
}

#[test]
fn a_real_exponent_is_written_in_the_shortest_form_that_holds_it() {
    // The first octet says how the exponent is written: in one, two or three
    // octets, or in a count and then that many (X.690 8.5.7.4). The long
    // form spends an octet saying a length the short forms carry in the
    // selector itself, so for one, two or three octets it is a second way to
    // write the same exponent, and the distinguished rules ask for the
    // fewest octets (11.3.1).
    for contents in [
        // A one-octet exponent written the long way.
        &[0x83, 0x01, 0x01, 0x01][..],
        // Two and three, the same.
        &[0x83, 0x02, 0x01, 0x00, 0x01],
        &[0x83, 0x03, 0x01, 0x00, 0x00, 0x01],
    ] {
        assert!(real(contents, Encoding::Ber).is_ok(), "{contents:02x?}");
        assert_eq!(
            real(contents, Encoding::Der).unwrap_err(),
            ErrorCode::MalformedReal,
            "{contents:02x?}"
        );
    }

    // Four octets is past what a selector can say, so the long form is the
    // only way to write it and both encodings take it.
    let long = [0x83, 0x04, 0x01, 0x00, 0x00, 0x00, 0x01];
    for encoding in [Encoding::Ber, Encoding::Der] {
        assert!(real(&long, encoding).is_ok());
    }

    // And the short forms stay what they were.
    for contents in [
        &[0x80, 0x01, 0x01][..],
        &[0x81, 0x01, 0x00, 0x01],
        &[0x82, 0x01, 0x00, 0x00, 0x01],
    ] {
        assert!(real(contents, Encoding::Der).is_ok(), "{contents:02x?}");
    }
}

#[test]
fn the_two_encodings_write_a_real_differently() {
    // The distinguished rules narrow what the basic ones permit (X.690 11.3
    // over 8.5), and reading a basic document by the narrow rules would
    // refuse values it is allowed to hold.

    // A base of eight, a scaling factor, and an even mantissa: written by a
    // sender the basic rules permit to choose, refused where the rules pick
    // one spelling (11.3.1).
    for contents in [
        &[0xa0, 0x01, 0x01][..],
        &[0x88, 0x01, 0x01],
        &[0x80, 0x01, 0x02],
    ] {
        assert!(real(contents, Encoding::Ber).is_ok(), "{contents:02x?}");
        assert_eq!(
            real(contents, Encoding::Der).unwrap_err(),
            ErrorCode::MalformedReal,
            "{contents:02x?}"
        );
    }

    // The first two number representations, where the distinguished rules
    // use the third alone (11.3.2.1). Their field is ISO 6093 as the sender
    // wrote it, which nothing here reads.
    for contents in [&b"\x011.0"[..], b"\x02 1.0"] {
        assert!(real(contents, Encoding::Ber).is_ok(), "{contents:02x?}");
        assert_eq!(
            real(contents, Encoding::Der).unwrap_err(),
            ErrorCode::MalformedReal,
            "{contents:02x?}"
        );
    }

    // What neither encoding writes: a reserved base, a reserved number
    // representation, and a reserved special value.
    for contents in [&[0xb0, 0x01, 0x01][..], &[0x00], &[0x44]] {
        for encoding in [Encoding::Ber, Encoding::Der] {
            assert_eq!(
                real(contents, encoding).unwrap_err(),
                ErrorCode::MalformedReal,
                "{contents:02x?}"
            );
        }
    }

    // And what both write: plus zero as nothing at all, the special values,
    // and a normalized binary value.
    for contents in [&[][..], &[0x40], &[0x43], &[0x80, 0x01, 0x01]] {
        for encoding in [Encoding::Ber, Encoding::Der] {
            assert!(real(contents, encoding).is_ok(), "{contents:02x?}");
        }
    }
}
