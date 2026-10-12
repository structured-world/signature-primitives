use super::{Encoding, Length, read};
use crate::error::ErrorCode;

fn der(input: &[u8]) -> Result<(Length, usize), ErrorCode> {
    read(input, Encoding::Der, 0).map_err(|(code, _)| code)
}

fn ber(input: &[u8]) -> Result<(Length, usize), ErrorCode> {
    read(input, Encoding::Ber, 0).map_err(|(code, _)| code)
}

#[test]
fn short_form_carries_its_own_value() {
    assert_eq!(der(&[0x00]).unwrap(), (Length::Definite(0), 1));
    assert_eq!(der(&[0x7f]).unwrap(), (Length::Definite(127), 1));
}

#[test]
fn long_form_is_read_big_endian() {
    assert_eq!(der(&[0x81, 0x80]).unwrap(), (Length::Definite(128), 2));
    assert_eq!(
        der(&[0x82, 0x01, 0x00]).unwrap(),
        (Length::Definite(256), 3)
    );
}

#[test]
fn der_refuses_a_long_form_that_would_fit_the_short_one() {
    // 127 belongs in one byte; writing it long is a second spelling of one
    // element, and a signature covers bytes rather than meanings.
    assert_eq!(der(&[0x81, 0x7f]).unwrap_err(), ErrorCode::LengthNotMinimal);
}

#[test]
fn der_refuses_leading_zero_bytes_in_the_long_form() {
    assert_eq!(
        der(&[0x82, 0x00, 0x80]).unwrap_err(),
        ErrorCode::LengthNotMinimal
    );
}

#[test]
fn ber_allows_what_der_refuses() {
    assert_eq!(ber(&[0x81, 0x7f]).unwrap(), (Length::Definite(127), 2));
    assert_eq!(
        ber(&[0x82, 0x00, 0x80]).unwrap(),
        (Length::Definite(128), 3)
    );
}

#[test]
fn indefinite_is_ber_only() {
    assert_eq!(ber(&[0x80]).unwrap(), (Length::Indefinite, 1));
    assert_eq!(
        der(&[0x80]).unwrap_err(),
        ErrorCode::IndefiniteLengthNotAllowed
    );
}

#[test]
fn reserved_initial_octet_is_refused() {
    // X.690 reserves 0xff; it is not a 127-byte length.
    assert_eq!(der(&[0xff]).unwrap_err(), ErrorCode::LengthTooLarge);
    assert_eq!(ber(&[0xff]).unwrap_err(), ErrorCode::LengthTooLarge);
}

#[test]
fn length_wider_than_an_offset_is_refused_rather_than_wrapping() {
    let input = [0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(der(&input).unwrap_err(), ErrorCode::LengthTooLarge);
}

#[test]
fn many_leading_zeroes_are_refused_by_der_before_the_width_check() {
    // BER tolerates the padding and reads the value; DER does not.
    let input = [0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    assert_eq!(der(&input).unwrap_err(), ErrorCode::LengthNotMinimal);
    assert_eq!(ber(&input).unwrap(), (Length::Definite(1), 10));
}

#[test]
fn truncated_length_is_refused() {
    assert_eq!(der(&[]).unwrap_err(), ErrorCode::UnexpectedEnd);
    assert_eq!(der(&[0x82, 0x01]).unwrap_err(), ErrorCode::UnexpectedEnd);
}
