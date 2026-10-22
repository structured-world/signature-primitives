//! Canonical scalar framing shares the parser's existing X.690 length grammar.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Parser,
    length::DerLength,
    memory::{Memory, MemoryAccount},
};

#[test]
fn canonical_lengths_cover_every_significant_width_without_allocation() {
    // Exact goldens prevent a matching encoder/decoder bug at the short/long
    // boundary; every u64 width also has a fixed nine-octet upper bound.
    for (length, expected) in [
        (0, &[0][..]),
        (127, &[127][..]),
        (128, &[0x81, 128][..]),
        (255, &[0x81, 255][..]),
        (256, &[0x82, 1, 0][..]),
        (
            u64::MAX,
            &[0x88, 255, 255, 255, 255, 255, 255, 255, 255][..],
        ),
    ] {
        assert_eq!(DerLength::new(length).as_bytes(), expected);
    }
    for significant in 1..=8 {
        let value = 1_u64 << ((significant - 1) * 8);
        let encoded = DerLength::new(value);
        assert!(encoded.as_bytes().len() <= 9);
        assert_eq!(
            encoded.as_bytes().len(),
            if value < 128 { 1 } else { significant + 1 }
        );
    }
}

#[test]
fn canonical_length_frames_round_trip_through_the_real_reader() {
    // A real primitive OCTET STRING uses the generated length directly;
    // no synthetic parser grammar or local encoder decoder is used here.
    for length in [0_usize, 127, 128, 255, 256, 65536] {
        let mut bytes = vec![4];
        bytes.extend_from_slice(DerLength::new(length as u64).as_bytes());
        bytes.resize(bytes.len() + length, 7);
        let account = Memory::new(Arc::new(MemoryAccount::new(1024, 1_000_000)));
        let parser = Parser::new(Encoding::Der, structured_asn1::Limits::default(), account);
        let mut reader = parser.read(&bytes, 10).unwrap();
        let value = reader.next_element().unwrap().unwrap();
        assert_eq!(value.contents().len(), length);
        assert!(reader.is_empty());
    }
}
