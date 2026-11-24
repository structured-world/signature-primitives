//! Public streaming and restored-state contracts.

use structured_base64::{Base64Codec, Base64Error};

const SENTINEL: u8 = 0xa5;

// RFC 4648 section 10 plus binary bytes across the full octet range.
#[test]
fn known_vectors() {
    let vectors: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"f", b"Zg=="),
        (b"fo", b"Zm8="),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg=="),
        (b"fooba", b"Zm9vYmE="),
        (b"foobar", b"Zm9vYmFy"),
        (&[0, 255, 16, 128, 127, 1, 254], b"AP8QgH8B/g=="),
    ];
    for &(plain, encoded) in vectors {
        let mut out = [SENTINEL; 32];
        let mut encoder = Base64Codec::new(true, 0);
        let capacity = Base64Codec::encoded_capacity(0, plain.len()).unwrap();
        let written = encoder.update(plain, &mut out[..capacity]).unwrap();
        let end = written + encoder.finish(&mut out[written..capacity]).unwrap();
        assert_eq!(&out[..end], encoded);
        assert!(out[end..].iter().all(|&byte| byte == SENTINEL));

        let mut decoder = Base64Codec::new(false, 0);
        let capacity = Base64Codec::decoded_capacity(encoded.len()).unwrap();
        let written = decoder.update(encoded, &mut out[..capacity]).unwrap();
        assert_eq!(&out[..written], plain);
        assert_eq!(decoder.finish(&mut out[written..capacity]), Ok(0));
    }
}

fn restore(state: Base64Codec) -> Base64Codec {
    Base64Codec {
        encode: state.encode,
        columns: state.columns,
        carry: state.carry,
        position: state.position,
        line_position: state.line_position,
        finished: state.finished,
        input_offset: state.input_offset,
    }
}

fn update_boundary(state: &mut Base64Codec, input: &[u8], minimum: usize, expected: &[u8]) {
    for len in 0..minimum {
        let mut out = [SENTINEL; 32];
        assert_eq!(
            restore(*state).update(input, &mut out[..len]),
            Err(Base64Error::OutputFull)
        );
        assert!(out[len..].iter().all(|&byte| byte == SENTINEL));
    }
    let mut out = [SENTINEL; 32];
    assert_eq!(state.update(input, &mut out[..minimum]), Ok(expected.len()));
    assert_eq!(&out[..expected.len()], expected);
    assert!(out[expected.len()..].iter().all(|&byte| byte == SENTINEL));
    *state = restore(*state);
}

fn finish_boundary(mut state: Base64Codec, expected: &[u8]) {
    if expected.is_empty() {
        assert_eq!(state.finish(&mut []), Ok(0));
        return;
    }
    let mut out = [SENTINEL; 32];
    for len in 0..=expected.len() {
        assert_eq!(
            restore(state).finish(&mut out[..len]),
            Err(Base64Error::OutputFull)
        );
    }
    out.fill(SENTINEL);
    assert_eq!(
        state.finish(&mut out[..=expected.len()]),
        Ok(expected.len())
    );
    assert_eq!(&out[..expected.len()], expected);
    assert!(out[expected.len()..].iter().all(|&byte| byte == SENTINEL));
}

// Resume from every input split with separately sized output buffers.
#[test]
fn encode_splits_with_wrapping() {
    let plain = b"fooba";
    let encoded = b"Zm9vYmE=";
    for columns in 0..=encoded.len() + 1 {
        let expected = encoded
            .chunks(if columns == 0 { encoded.len() } else { columns })
            .collect::<Vec<_>>()
            .join(&b'\n');
        let wrapped_len = |symbols| {
            if columns == 0 || symbols == 0 {
                symbols
            } else {
                symbols + (symbols - 1) / columns
            }
        };
        let before_finish = wrapped_len(6);
        for split in 0..=plain.len() {
            let first = wrapped_len(split + split / 3);
            let mut state = Base64Codec::new(true, columns);
            update_boundary(&mut state, &plain[..split], first, &expected[..first]);
            update_boundary(
                &mut state,
                &plain[split..],
                before_finish - first,
                &expected[first..before_finish],
            );
            finish_boundary(state, &expected[before_finish..]);
        }
    }
}

// Only sextets that emit a byte require output capacity.
#[test]
fn decode_splits_across_padding_and_whitespace() {
    let input = b" Zm\t9v\r\nYmE= ";
    let plain = b"fooba";
    let counts = [0, 0, 0, 1, 1, 2, 3, 3, 3, 3, 4, 5, 5, 5];
    for split in 0..=input.len() {
        let mut state = Base64Codec::new(false, 23);
        let first = counts[split];
        update_boundary(&mut state, &input[..split], first, &plain[..first]);
        update_boundary(
            &mut state,
            &input[split..],
            plain.len() - first,
            &plain[first..],
        );
        finish_boundary(state, b"");
    }
}

#[test]
fn bulk_prefix_preserves_scalar_error_precedence_and_resume_state() {
    // Single-byte calls force scalar decoding. Match every transition after
    // bulk groups, including when output fills before the first invalid byte.
    for byte in [b'A', b'\n', b'=', b'!', 0xff] {
        for index in 0..40 {
            let mut input = *b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
            input[index] = byte;
            for capacity in 0..=30 {
                let mut bulk = Base64Codec::new(false, 0);
                let mut bulk_out = [SENTINEL; 32];
                let answer = bulk.update(&input, &mut bulk_out[..capacity]);
                let mut scalar = Base64Codec::new(false, 0);
                let mut scalar_out = [SENTINEL; 32];
                let expected = input.iter().try_fold(0, |written, byte| {
                    scalar
                        .update(
                            core::slice::from_ref(byte),
                            &mut scalar_out[written..capacity],
                        )
                        .map(|count| written + count)
                });
                assert_eq!(
                    answer, expected,
                    "offset {index}, byte {byte}, capacity {capacity}"
                );
                if answer.is_ok() {
                    assert_eq!(bulk, scalar);
                    assert_eq!(bulk_out, scalar_out);
                }
            }
        }
    }
}

#[test]
fn bulk_decode_resumes_after_wrapping_and_chunk_boundaries() {
    // Exercise both line boundaries inside quartets and arbitrary resumption.
    let plain = [0x5a; 301];
    for columns in [63, 64, 75, 76] {
        let mut encoder = Base64Codec::new(true, columns);
        let mut wire = [0; 512];
        let used = encoder.update(&plain, &mut wire).unwrap();
        let end = used + encoder.finish(&mut wire[used..]).unwrap();
        for chunk in [1, 17, 63, 76, 191, 512] {
            let mut decoder = Base64Codec::new(false, 0);
            let mut output = [SENTINEL; 302];
            let mut written = 0;
            for part in wire[..end].chunks(chunk) {
                written += decoder.update(part, &mut output[written..301]).unwrap();
            }
            assert_eq!(decoder.finish(&mut []), Ok(0));
            assert_eq!(&output[..written], &plain);
            assert_eq!(output[301], SENTINEL);
        }
    }
}

// The compatible profile ignores pad bits, but still enforces the group
// grammar and requires the complete padding across chunk boundaries.
#[test]
fn decode_padding_and_invalid_bytes() {
    let mut out = [SENTINEL; 12];
    let mut state = Base64Codec::new(false, 0);
    assert_eq!(state.update(b"Zh=\t", &mut out), Ok(1));
    assert_eq!(out[0], b'f');
    assert_eq!(
        restore(state).finish(&mut out),
        Err(Base64Error::InvalidLength(4))
    );
    assert_eq!(
        restore(state).update(b"A", &mut out),
        Err(Base64Error::InvalidByte(4, b'A'))
    );
    update_boundary(&mut state, b"\r=\n", 0, b"");
    assert_eq!(
        state.update(b"Z", &mut out),
        Err(Base64Error::InvalidByte(7, b'Z'))
    );
    assert_eq!(Base64Codec::new(false, 0).update(b"Zm9=", &mut out), Ok(2));
    assert_eq!(&out[..2], b"fo");

    for (input, offset) in [
        (b"=AAA", 0),
        (b"A=AA", 1),
        (b"AA=A", 3),
        (b"AAA\0", 3),
        (b"AAA\x0b", 3),
        (b"AAA-", 3),
        (b"AAA_", 3),
    ] {
        assert_eq!(
            Base64Codec::new(false, 0).update(input, &mut out),
            Err(Base64Error::InvalidByte(offset, input[offset]))
        );
    }
    for len in 1..4 {
        let mut state = Base64Codec::new(false, 0);
        assert_eq!(state.update(&b"AAAA"[..len], &mut out), Ok(len - 1));
        assert_eq!(state.finish(&mut []), Err(Base64Error::InvalidLength(len)));
    }
}

// A final call with no bytes to emit can use an empty slice.
#[test]
fn empty_and_closed_streams() {
    for encode in [false, true] {
        let mut state = Base64Codec::new(encode, 4);
        assert_eq!(state.update(b"", &mut []), Ok(0));
        finish_boundary(state, b"");
        assert_eq!(state.finish(&mut []), Ok(0));
        assert_eq!(
            state.update(b"A", &mut [SENTINEL]),
            Err(if encode {
                Base64Error::Invalid
            } else {
                Base64Error::InvalidByte(0, b'A')
            })
        );
    }
    assert_eq!(
        Base64Codec::new(false, 0).update(b" \t\r\n", &mut []),
        Ok(0)
    );
    assert_eq!(
        Base64Codec::new(false, 0).update(b"?", &mut []),
        Err(Base64Error::InvalidByte(0, b'?'))
    );
}

// Restored fields must be checked even with empty input or output.
#[test]
fn invalid_external_states() {
    let encoder = Base64Codec::new(true, 0);
    let decoder = Base64Codec::new(false, 0);
    let invalid = [
        Base64Codec {
            position: 3,
            line_position: 3,
            ..encoder
        },
        Base64Codec {
            position: 1,
            line_position: 1,
            finished: true,
            ..encoder
        },
        Base64Codec {
            carry: 1,
            ..encoder
        },
        Base64Codec {
            position: 1,
            ..encoder
        },
        Base64Codec {
            position: 1,
            columns: 3,
            ..encoder
        },
        Base64Codec {
            columns: 4,
            line_position: 5,
            position: 1,
            ..encoder
        },
        Base64Codec {
            columns: 2,
            line_position: 2,
            position: 1,
            ..encoder
        },
        Base64Codec {
            line_position: 1,
            ..decoder
        },
        Base64Codec {
            carry: 64,
            position: 3,
            ..decoder
        },
        Base64Codec {
            carry: 1,
            ..decoder
        },
        Base64Codec {
            position: 2,
            finished: true,
            ..decoder
        },
        Base64Codec {
            position: usize::MAX,
            ..decoder
        },
    ];
    for mut state in invalid {
        assert_eq!(state.update(b"", &mut []), Err(Base64Error::Invalid));
        assert_eq!(state.finish(&mut []), Err(Base64Error::Invalid));
        let mut out = [SENTINEL];
        assert_eq!(state.update(b"A", &mut out), Err(Base64Error::Invalid));
        assert_eq!(out, [SENTINEL]);
    }
}

// Counter overflow refuses without a panic. Wrapping at the same width
// resets the counter before the next symbol.
#[test]
fn counter_and_capacity_overflow() {
    let mut decoder = Base64Codec {
        input_offset: usize::MAX,
        ..Base64Codec::new(false, 0)
    };
    assert_eq!(decoder.update(b" ", &mut []), Err(Base64Error::Invalid));
    assert_eq!(decoder.input_offset, usize::MAX);

    let mut state = Base64Codec {
        position: 2,
        line_position: usize::MAX - 1,
        ..Base64Codec::new(true, 0)
    };
    let mut out = [SENTINEL; 8];
    assert_eq!(
        restore(state).update(b"\0", &mut out),
        Err(Base64Error::Invalid)
    );
    assert_eq!(restore(state).finish(&mut out), Err(Base64Error::Invalid));
    state.columns = usize::MAX;
    assert_eq!(state.update(b"\0", &mut out), Ok(3));
    assert_eq!(&out[..3], b"A\nA");
    assert_eq!(state.line_position, 1);
    let largest = (usize::MAX / 4) * 3;
    assert_eq!(Base64Codec::encoded_capacity(0, largest + 1), None);
    assert_eq!(
        Base64Codec::encoded_capacity(0, largest),
        Some(usize::MAX - 2)
    );
    assert_eq!(Base64Codec::encoded_capacity(2, largest), None);
    assert_eq!(
        Base64Codec::decoded_capacity(usize::MAX),
        Some((usize::MAX / 4 + 1) * 3 + 8)
    );
    assert_eq!(Base64Codec::encoded_capacity(0, 0), Some(1));
    assert_eq!(Base64Codec::encoded_capacity(0, 3), Some(5));
    assert_eq!(Base64Codec::encoded_capacity(1, 3), Some(13));
    assert_eq!(Base64Codec::encoded_capacity(2, 4), Some(17));
    assert_eq!(Base64Codec::decoded_capacity(5), Some(14));
}
