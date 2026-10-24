use super::{Decoder, Step};
use crate::bytes::Form;
use alloc::vec::Vec;

fn decoded(form: Form, raw: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = Decoder::new(form);
    let mut at = 0;
    let mut out = Vec::new();
    loop {
        match decoder.step(raw.get(at).copied()) {
            Step::More => at += 1,
            Step::Byte { value, consumed } => {
                out.push(value);
                if consumed {
                    at += 1;
                }
            }
            Step::End => return Some(out),
            Step::Malformed => return None,
        }
    }
}

#[test]
fn every_literal_escape_follows_iso_32000_table_three() {
    // ISO32000-1§7.3.4.2/Table3 defines exactly these escape meanings;
    // every unlisted byte loses only the backslash. EOF octal is padded
    // by absence, not by appending another digit or a guessed character.
    for byte in u8::MIN..=u8::MAX {
        let raw = [b'\\', byte];
        let octal = byte & 7;
        let expected: &[u8] = match byte {
            b'\n' | b'\r' => &[],
            b'n' => b"\n",
            b'r' => b"\r",
            b't' => b"\t",
            b'b' => &[8],
            b'f' => &[12],
            b'0'..=b'7' => core::slice::from_ref(&octal),
            _ => core::slice::from_ref(&byte),
        };
        assert_eq!(decoded(Form::Literal, &raw).unwrap(), expected);
    }
}

#[test]
fn eof_and_invalid_fragments_cannot_reset_the_decoder() {
    // A suspended prefix has a unique interpretation only after the
    // required remaining bytes arrive. Malformed state stays terminal.
    for (form, raw) in [
        (Form::Name, b"#".as_slice()),
        (Form::Name, b"#0"),
        (Form::Name, b"#00"),
        (Form::Literal, b"\\"),
        (Form::Hexadecimal, b"FG"),
    ] {
        assert!(decoded(form, raw).is_none());
    }
    assert_eq!(decoded(Form::Hexadecimal, b"F").unwrap(), &[0xf0]);
    assert_eq!(decoded(Form::Literal, b"\r\n\rX").unwrap(), b"\n\nX");
    let mut decoder = Decoder::new(Form::Name);
    assert!(matches!(decoder.step(Some(0)), Step::Malformed));
    assert!(matches!(decoder.step(Some(b'A')), Step::Malformed));
}
