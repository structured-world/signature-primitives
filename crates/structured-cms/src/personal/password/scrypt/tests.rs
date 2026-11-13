use super::salsa8;

#[test]
fn rfc7914_salsa_core_vector() {
    // RFC 7914 §8. Words are little-endian interpretations of the octets.
    let mut words = [
        0x219a_877e,
        0x86c9_3e4f,
        0xe640_a97c,
        0x268f_7141,
        0x5b55_eeba,
        0xb5c1_618c,
        0x1146_f80d,
        0x1d3b_cd6d,
        0x19f3_24ee,
        0x853d_9bdf,
        0x4b1e_1214,
        0x32aa_c55a,
        0x291d_0276,
        0x2948_c709,
        0x8dc6_ebed,
        0x5ec2_b8b8,
    ];
    salsa8(&mut words);
    assert_eq!(
        words,
        [
            0x9c85_1fa4,
            0x99cc_0866,
            0xcbca_813b,
            0x05ef_0c02,
            0x8121_4b04,
            0x7d33_fda2,
            0x631c_7bfd,
            0x292f_6896,
            0x6831_39b4,
            0xbce6_c9e3,
            0xb7c5_6bfe,
            0xba96_6da0,
            0x10cc_24e4,
            0x5c74_912c,
            0x3d67_ad24,
            0x818f_61c7
        ]
    );
}

#[test]
fn salsa_accepts_maximum_stream_counter_words() {
    // These words are arbitrary block data, even when both are all ones.
    let mut words = [u32::MAX; 16];
    salsa8(&mut words);
    assert_ne!(words, [u32::MAX; 16]);
}
