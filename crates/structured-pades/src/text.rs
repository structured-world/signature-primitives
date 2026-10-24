//! PDF text strings, without altering the original signed byte spelling.

use crate::error::{Error, ErrorKind, Syntax};
use crate::model::admit;
use crate::source::Location;
use structured_asn1::memory::{OwnedText, Work};

pub(crate) fn read(bytes: &[u8], location: Location, work: &impl Work) -> crate::Result<OwnedText> {
    admit(work, location, bytes.len() as u64)?;
    let malformed = || Error {
        kind: ErrorKind::Syntax(Syntax::String),
        location,
    };
    let mut output = work.vector();
    let mut put = |character: char| {
        let mut scratch = [0; 4];
        output
            .try_extend_from_slice(character.encode_utf8(&mut scratch).as_bytes())
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })
    };
    // ISO 32000-1 §7.9.2.2 selects UTF-16BE only by its initial BOM;
    // otherwise Annex D.3/Table D.2 selects PDFDocEncoding, not Latin-1.
    // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
    if let Some(content) = bytes.strip_prefix(&[0xfe, 0xff]) {
        if content.len() % 2 != 0 {
            return Err(malformed());
        }
        for character in char::decode_utf16(
            content
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_be_bytes),
        ) {
            put(character.map_err(|_| malformed())?)?;
        }
    } else {
        for &byte in bytes {
            put(pdf_doc(byte).ok_or_else(malformed)?)?;
        }
    }
    OwnedText::from_utf8(output)
        .map(OwnedText::into_owned)
        .map_err(|cause| match cause.kind() {
            structured_asn1::memory::TextErrorKind::Resource(cause) => Error {
                kind: ErrorKind::Resource(cause),
                location,
            },
            structured_asn1::memory::TextErrorKind::Utf8(_) => malformed(),
        })
}

fn pdf_doc(byte: u8) -> Option<char> {
    let scalar = match byte {
        0..=8 | 11..=12 | 14..=23 | 127 | 159 | 173 => return None,
        24..=31 => [0x2d8, 0x2c7, 0x2c6, 0x2d9, 0x2dd, 0x2db, 0x2da, 0x2dc][usize::from(byte - 24)],
        128..=158 => [
            0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x192, 0x2044, 0x2039, 0x203a, 0x2212,
            0x2030, 0x201e, 0x201c, 0x201d, 0x2018, 0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x141,
            0x152, 0x160, 0x178, 0x17d, 0x131, 0x142, 0x153, 0x161, 0x17e,
        ][usize::from(byte - 128)],
        160 => 0x20ac,
        _ => u32::from(byte),
    };
    char::from_u32(scalar)
}
