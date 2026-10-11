use super::{Class, read, universal};
use crate::error::ErrorCode;

fn at(input: &[u8]) -> Result<(super::Tag, usize), ErrorCode> {
    read(input, 0).map_err(|(code, _)| code)
}

#[test]
fn low_tag_number_is_one_byte() {
    let (tag, taken) = at(&[0x02]).unwrap();
    assert_eq!(taken, 1);
    assert_eq!(tag.class(), Class::Universal);
    assert!(!tag.is_constructed());
    assert_eq!(tag.number(), Some(universal::INTEGER));
}

#[test]
fn constructed_bit_is_read() {
    let (tag, _) = at(&[0x30]).unwrap();
    assert!(tag.is_constructed());
    assert_eq!(tag.number(), Some(universal::SEQUENCE));
}

#[test]
fn context_specific_class_is_read() {
    let (tag, _) = at(&[0xa0]).unwrap();
    assert_eq!(tag.class(), Class::ContextSpecific);
    assert!(tag.is_constructed());
    assert_eq!(tag.number(), Some(0));
}

#[test]
fn end_of_contents_is_recognised() {
    let (tag, _) = at(&[0x00]).unwrap();
    assert!(tag.is_end_of_contents());
}

#[test]
fn high_tag_number_spans_continuation_bytes() {
    // 0x1f introduces the long form; 0x81 0x00 encodes 128.
    let (tag, taken) = at(&[0x1f, 0x81, 0x00]).unwrap();
    assert_eq!(taken, 3);
    assert_eq!(tag.number(), Some(128));
}

#[test]
fn high_tag_number_padded_with_a_leading_zero_group_is_refused() {
    // 0x80 as the first continuation byte is a zero seven-bit group, which
    // writes a number that already fits in fewer bytes.
    assert_eq!(
        at(&[0x1f, 0x80, 0x02]).unwrap_err(),
        ErrorCode::MalformedTag
    );
}

#[test]
fn high_tag_number_that_fits_the_low_form_is_refused() {
    // 2 is expressible as a single byte, so spelling it the long way is a
    // second encoding of one element.
    assert_eq!(at(&[0x1f, 0x02]).unwrap_err(), ErrorCode::MalformedTag);
}

#[test]
fn a_tag_number_wider_than_this_reader_names_is_read_rather_than_refused() {
    // The encoding bounds no tag number (X.690 8.1.2.4.2). A number past
    // what this reader names is not one any schema assigns, so it is kept
    // apart from every named tag; refusing it would block a document over an
    // element nothing was going to interpret.
    let input = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    let (tag, taken) = at(&input).unwrap();
    assert_eq!(taken, input.len());
    assert_eq!(tag.number(), None);
    assert_eq!(tag.class(), Class::Universal);
    assert!(!tag.is_constructed());

    // It is not the end-of-contents marker, and it is not a tag a schema
    // names, however wide the number.
    assert!(!tag.is_end_of_contents());
    assert_ne!(tag, super::Tag::primitive(universal::SEQUENCE));

    // Two wide numbers are the same tag here: what tells the two documents
    // apart is their bytes, which is what identity is compared on.
    let other = [0x1f, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x7f];
    assert_eq!(at(&other).unwrap().0, tag);
}

#[test]
fn continuation_that_never_ends_is_refused_without_reading_on() {
    // Every byte has the high bit set, so nothing here terminates the number.
    // The refusal is about the header's size and not the number's: without
    // it the rest of the document would be read looking for the last byte.
    let mut input = alloc::vec![0x1f];
    input.extend(core::iter::repeat_n(0xff, 32));
    assert_eq!(at(&input).unwrap_err(), ErrorCode::TagTooLarge);
}

#[test]
fn truncated_tag_is_refused() {
    assert_eq!(at(&[]).unwrap_err(), ErrorCode::UnexpectedEnd);
    assert_eq!(at(&[0x1f]).unwrap_err(), ErrorCode::UnexpectedEnd);
    assert_eq!(at(&[0x1f, 0x81]).unwrap_err(), ErrorCode::UnexpectedEnd);
}

#[test]
fn a_constructed_universal_zero_is_refused() {
    // Universal tag zero is reserved for the end-of-contents marker, which is
    // primitive. With the constructed bit set it is neither that marker nor a
    // tag anything may use, and letting it through hands the reader an element
    // no encoding defines.
    assert_eq!(at(&[0x20]).unwrap_err(), ErrorCode::MalformedTag);
    assert_eq!(at(&[0x20, 0x00]).unwrap_err(), ErrorCode::MalformedTag);
}

#[test]
fn a_primitive_universal_zero_is_still_the_marker() {
    let (tag, _) = at(&[0x00]).unwrap();
    assert!(tag.is_end_of_contents());
}
