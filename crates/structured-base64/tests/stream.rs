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

// A sextet with no output and a padding byte still require one free byte.
#[test]
fn decode_splits_across_padding_and_whitespace() {
    let input = b" Zm\t9v\r\nYmE= ";
    let plain = b"fooba";
    let counts = [0, 0, 0, 1, 1, 2, 3, 3, 3, 3, 4, 5, 5, 5];
    for split in 0..=input.len() {
        let mut state = Base64Codec::new(false, 23);
        let first = counts[split];
        let first_slack = usize::from(matches!(split, 2 | 9 | 12 | 13));
        update_boundary(
            &mut state,
            &input[..split],
            first + first_slack,
            &plain[..first],
        );
        let second_slack = usize::from(split < 12);
        update_boundary(
            &mut state,
            &input[split..],
            plain.len() - first + second_slack,
            &plain[first..],
        );
        finish_boundary(state, b"");
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
    assert_eq!(restore(state).finish(&mut out), Err(Base64Error::Truncated));
    assert_eq!(
        restore(state).update(b"A", &mut out),
        Err(Base64Error::Invalid)
    );
    update_boundary(&mut state, b"\r=\n", 1, b"");
    assert_eq!(state.update(b"Z", &mut out), Err(Base64Error::Invalid));
    assert_eq!(Base64Codec::new(false, 0).update(b"Zm9=", &mut out), Ok(2));
    assert_eq!(&out[..2], b"fo");

    for input in [
        b"=AAA", b"A=AA", b"AA=A", b"AAA\0", b"AAA\x0b", b"AAA-", b"AAA_",
    ] {
        assert_eq!(
            Base64Codec::new(false, 0).update(input, &mut out),
            Err(Base64Error::Invalid)
        );
    }
    for len in 1..4 {
        let mut state = Base64Codec::new(false, 0);
        assert_eq!(state.update(&b"AAAA"[..len], &mut out), Ok(len - 1));
        assert_eq!(state.finish(&mut out), Err(Base64Error::Truncated));
    }
}

// Finalization needs caller spare capacity even when the output is empty.
#[test]
fn empty_and_closed_streams() {
    for encode in [false, true] {
        let mut state = Base64Codec::new(encode, 4);
        assert_eq!(state.update(b"", &mut []), Ok(0));
        finish_boundary(state, b"");
        assert_eq!(state.finish(&mut [SENTINEL]), Ok(0));
        assert_eq!(
            state.update(b"A", &mut [SENTINEL]),
            Err(Base64Error::Invalid)
        );
    }
    assert_eq!(
        Base64Codec::new(false, 0).update(b" \t\r\n", &mut []),
        Ok(0)
    );
    assert_eq!(
        Base64Codec::new(false, 0).update(b"?", &mut []),
        Err(Base64Error::OutputFull)
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
    assert_eq!(Base64Codec::encoded_capacity(0, usize::MAX / 4 + 1), None);
    assert_eq!(Base64Codec::decoded_capacity(usize::MAX / 3 + 1), None);
    assert!(Base64Codec::encoded_capacity(0, usize::MAX / 4).is_some());
    assert!(Base64Codec::decoded_capacity(usize::MAX / 3).is_some());
}
