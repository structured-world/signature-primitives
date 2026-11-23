use super::{Candidate, Error, Finding, Format, Limits, acquire::Source, charge};
use structured_asn1::{Span, memory::Execution, range::RangeSource};

pub(super) const fn at(format: Format, finding: Finding, length: usize) -> Candidate {
    Candidate {
        format,
        finding,
        range: Span {
            start: 0,
            length: length as u64,
        },
    }
}

pub(super) fn prefix(bytes: &[u8], total: u64) -> [Option<Candidate>; 9] {
    [
        cms(bytes, total),
        png(bytes),
        jpeg(bytes, total),
        gif(bytes, Format::Gif87a, b"GIF87a"),
        gif(bytes, Format::Gif89a, b"GIF89a"),
        tiff(bytes, total, false),
        tiff(bytes, total, true),
        webp(bytes, total),
        bmp(bytes, total),
    ]
}

fn marker(bytes: &[u8], magic: &[u8]) -> Option<bool> {
    if bytes.starts_with(magic) {
        Some(true)
    } else if bytes.len() >= 2 && magic.starts_with(bytes) {
        Some(false)
    } else {
        None
    }
}

fn fixed(
    bytes: &[u8],
    format: Format,
    magic: &[u8],
    needed: usize,
    inspect: impl FnOnce(&[u8]) -> Finding,
) -> Option<Candidate> {
    marker(bytes, magic)?;
    let length = bytes.len().min(needed);
    let finding = bytes.get(..needed).map_or(Finding::Incomplete, inspect);
    Some(at(format, finding, length))
}

fn decide(valid: bool) -> Finding {
    if valid {
        Finding::Framing
    } else {
        Finding::Conflicting
    }
}

fn png(bytes: &[u8]) -> Option<Candidate> {
    // PNG Third Edition §§5.2 and 11.2.2: signature and first IHDR.
    // https://www.w3.org/TR/png-3/#11IHDR
    fixed(bytes, Format::Png, b"\x89PNG\r\n\x1a\n", 33, |head| {
        let be = |at| u32::from_be_bytes(word(head, at));
        decide(
            be(8) == 13
                && &head[12..16] == b"IHDR"
                && (1..=0x7fff_ffff).contains(&be(16))
                && (1..=0x7fff_ffff).contains(&be(20)),
        )
    })
}

fn jpeg(bytes: &[u8], total: u64) -> Option<Candidate> {
    // T.81 Annex B.1/B.2: SOI then marker framing. APP0/APP1 is optional.
    // https://www.itu.int/rec/T-REC-T.81
    if !marker(bytes, b"\xff\xd8")? {
        return None;
    }
    let mut pos = 2;
    while bytes.get(pos) == Some(&0xff) {
        pos += 1;
    }
    let (finding, used) = match bytes.get(pos) {
        None => (Finding::Incomplete, pos),
        Some(0x01) if pos > 2 => (Finding::Framing, pos + 1),
        Some(0xc0..=0xcf | 0xda..=0xfe) if pos > 2 => match bytes.get(pos + 1..pos + 3) {
            Some([a, b]) => {
                let len = u64::from(u16::from_be_bytes([*a, *b]));
                let finding = if len < 2 {
                    Finding::Conflicting
                } else if len > total - (pos + 1) as u64 {
                    Finding::Incomplete
                } else {
                    Finding::Framing
                };
                (finding, pos + 3)
            }
            _ => (Finding::Incomplete, bytes.len()),
        },
        Some(_) => (Finding::Conflicting, pos + 1),
    };
    Some(at(Format::Jpeg, finding, used))
}

fn gif(bytes: &[u8], format: Format, magic: &[u8]) -> Option<Candidate> {
    // GIF89a §§17–18: logical screen descriptor follows the version header.
    // https://www.w3.org/Graphics/GIF/spec-gif89a.txt
    fixed(bytes, format, magic, 13, |head| {
        decide(head[6..8] != [0, 0] && head[8..10] != [0, 0])
    })
}

fn tiff(bytes: &[u8], total: u64, big: bool) -> Option<Candidate> {
    // TIFF 6.0 §2: byte order, magic 42 and an aligned first IFD offset.
    // https://printtechnologies.org/standards/files/tiff-v6.pdf
    let (format, magic, large) = if big {
        (Format::TiffBigEndian, b"MM\0*", b"MM\0+")
    } else {
        (Format::TiffLittleEndian, b"II*\0", b"II+\0")
    };
    if bytes.starts_with(large) {
        return Some(at(format, Finding::Unsupported, 4));
    }
    fixed(bytes, format, magic, 8, |head| {
        let octets = word(head, 4);
        let offset = if big {
            u32::from_be_bytes(octets)
        } else {
            u32::from_le_bytes(octets)
        };
        if offset < 8 || offset % 2 != 0 {
            Finding::Conflicting
        } else if u64::from(offset) + 2 > total {
            Finding::Incomplete
        } else {
            Finding::Framing
        }
    })
}

fn webp(bytes: &[u8], total: u64) -> Option<Candidate> {
    // RFC 9649 §§2.2–2.3: RIFF form type and first image/extended chunk.
    // https://www.rfc-editor.org/rfc/rfc9649#section-2.3
    if !bytes.starts_with(b"RIFF") {
        return None;
    }
    let form = bytes.get(8..12)?;
    if form != b"WEBP" {
        return None;
    }
    fixed(bytes, Format::WebP, b"RIFF", 20, |head| {
        let size = u64::from(u32::from_le_bytes(word(head, 4))) + 8;
        let chunk = u64::from(u32::from_le_bytes(word(head, 16)));
        let valid = match &head[12..16] {
            b"VP8 " => chunk >= 10,
            b"VP8L" => chunk >= 5,
            b"VP8X" => chunk == 10,
            _ => false,
        };
        if !valid || 20 + chunk + (chunk & 1) > size {
            Finding::Conflicting
        } else if size > total {
            Finding::Incomplete
        } else {
            Finding::Framing
        }
    })
}

fn bmp(bytes: &[u8], total: u64) -> Option<Candidate> {
    // BITMAPFILEHEADER identifies its DIB and offset independently.
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
    fixed(bytes, Format::Bmp, b"BM", 18, |head| {
        let size = u64::from(u32::from_le_bytes(word(head, 2)));
        let data = u64::from(u32::from_le_bytes(word(head, 10)));
        let dib = u64::from(u32::from_le_bytes(word(head, 14)));
        if head[6..10] != [0; 4] || data < 14 + dib || data > size {
            Finding::Conflicting
        } else if size > total {
            Finding::Incomplete
        } else if matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124) {
            Finding::Framing
        } else {
            Finding::Unsupported
        }
    })
}

fn word(bytes: &[u8], at: usize) -> [u8; 4] {
    [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]
}

// Selects only the exact CMS SignedData OID in ContentInfo, then checks its
// explicit wrapper and SEQUENCE framing. A generic SEQUENCE is not a marker.
// RFC 5652 §§3 and 5.1. https://www.rfc-editor.org/rfc/rfc5652#section-3
fn cms(bytes: &[u8], total: u64) -> Option<Candidate> {
    let (outer, extent) = tlv(bytes, 0, 0x30)?;
    let (value, size) = tlv(bytes, outer, 0x06)?;
    let oid = structured_cms::oid::SIGNED_DATA.as_bytes();
    if size != Some(oid.len() as u64) {
        return None;
    }
    let end_oid = value.checked_add(oid.len())?;
    if bytes.get(value..end_oid)? != oid {
        return None;
    }
    let (finding, used) = match tlv(bytes, end_oid, 0xa0) {
        Some((inner, wrap)) => match tlv(bytes, inner, 0x30) {
            Some((body, length)) => {
                let finding = cms_extent(total, [outer, inner, body], [extent, wrap, length]);
                cms_version(bytes, body, length, finding)
            }
            None if bytes.get(inner).is_none_or(|byte| *byte == 0x30) => {
                (Finding::Incomplete, inner)
            }
            None => (Finding::Conflicting, inner + 1),
        },
        None if bytes.get(end_oid).is_none_or(|byte| *byte == 0xa0) => {
            (Finding::Incomplete, end_oid)
        }
        None => (Finding::Conflicting, end_oid + 1),
    };
    Some(at(Format::CmsSignedData, finding, used))
}

fn cms_version(
    bytes: &[u8],
    body: usize,
    length: Option<u64>,
    extent: Finding,
) -> (Finding, usize) {
    if extent != Finding::Framing {
        return (extent, body);
    }
    if length.is_some_and(|length| length < 3) {
        return (Finding::Conflicting, body);
    }
    if bytes.get(body).is_some_and(|byte| *byte != 2) {
        return (Finding::Conflicting, body + 1);
    }
    let Some((value, Some(1))) = tlv(bytes, body, 2) else {
        return (Finding::Incomplete, body);
    };
    if length.is_some_and(|length| (value - body) as u64 >= length) {
        return (Finding::Conflicting, value);
    }
    match bytes.get(value) {
        Some(1 | 3 | 4 | 5) => (Finding::Framing, value + 1),
        Some(_) => (Finding::Conflicting, value + 1),
        None => (Finding::Incomplete, value),
    }
}

fn cms_extent(total: u64, offsets: [usize; 3], lengths: [Option<u64>; 3]) -> Finding {
    let mut outer = None;
    for (offset, length) in offsets.into_iter().zip(lengths) {
        if outer.is_some_and(|end| (offset as u64) > end) {
            return Finding::Conflicting;
        }
        if let Some(length) = length {
            let Some(end) = (offset as u64).checked_add(length) else {
                return Finding::Unsupported;
            };
            if outer.is_some_and(|limit| end > limit) {
                return Finding::Conflicting;
            }
            if end > total {
                return Finding::Incomplete;
            }
            outer = Some(end);
        }
    }
    Finding::Framing
}

fn tlv(bytes: &[u8], start: usize, tag: u8) -> Option<(usize, Option<u64>)> {
    if *bytes.get(start)? != tag {
        return None;
    }
    let at = start + 2;
    match *bytes.get(start + 1)? {
        length @ 0..=127 => Some((at, Some(u64::from(length)))),
        0x80 if tag & 0x20 != 0 => Some((at, None)),
        word @ 0x81..=0x88 => {
            let end = at + usize::from(word & 0x7f);
            let mut length = 0;
            for &byte in bytes.get(at..end)? {
                length = length << 8 | u64::from(byte);
            }
            Some((end, Some(length)))
        }
        _ => None,
    }
}

pub(super) async fn pdf<S: RangeSource>(
    source: &Source<'_, S>,
    prefix: &[u8],
    limits: Limits,
    work: &Execution<'_>,
) -> Result<Option<Candidate>, Error<S::Error>> {
    // ISO 32000-1 §7.5.2: header version; §7.5.5: startxref and %%EOF.
    // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
    if marker(prefix, b"%PDF-").is_none() {
        return Ok(None);
    }
    let finding = match prefix.get(5..9) {
        Some([b'1', b'.', b'0'..=b'7', b'\r' | b'\n']) => pdf_footer(source, limits, work).await?,
        Some([b'0'..=b'9', b'.', b'0'..=b'9', b'\r' | b'\n']) => Finding::Unsupported,
        Some(_) => Finding::Conflicting,
        None => Finding::Incomplete,
    };
    Ok(Some(at(Format::Pdf, finding, prefix.len().min(9))))
}

async fn pdf_footer<S: RangeSource>(
    source: &Source<'_, S>,
    limits: Limits,
    work: &Execution<'_>,
) -> Result<Finding, Error<S::Error>> {
    let total = source.original_stamp().length;
    let length = total.min(limits.pdf_suffix as u64);
    let range = Span {
        start: total - length,
        length,
    };
    let suffix = source.read(range, work).await?;
    charge(work, range, 12)?;
    let Some((offset, end)) = pdf_offset(&suffix) else {
        return Ok(Finding::Incomplete);
    };
    if offset >= range.start + end as u64 {
        return Ok(Finding::Conflicting);
    }
    let xref = Span {
        start: offset,
        length: (total - offset).min(128),
    };
    let bytes = source.read(xref, work).await?;
    charge(work, xref, 12)?;
    let mut fields = bytes
        .split(|&byte| pdf_space(byte))
        .filter(|field| !field.is_empty());
    Ok(match (fields.next(), fields.next(), fields.next()) {
        (Some(b"xref"), Some(start), Some(count))
            if decimal(start).is_some() && decimal(count).is_some() =>
        {
            Finding::Framing
        }
        (Some(object), Some(generation), Some(b"obj"))
            if decimal(object).is_some()
                && decimal(generation).is_some()
                && pdf_xref_type(&bytes) =>
        {
            Finding::Framing
        }
        _ => Finding::Incomplete,
    })
}

fn pdf_offset(bytes: &[u8]) -> Option<(u64, usize)> {
    // The first valid footer searched from the end can precede unrelated
    // trailing data. Coexisting format evidence is kept by the caller.
    for (end, token) in bytes.windows(5).enumerate().rev() {
        if token != b"%%EOF"
            || !bytes
                .get(end + 5)
                .is_none_or(|byte| matches!(byte, b'\r' | b'\n'))
            || !end
                .checked_sub(1)
                .and_then(|offset| bytes.get(offset))
                .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            continue;
        }
        let before = trim_pdf(&bytes[..end]);
        let start = before.iter().rposition(|byte| !byte.is_ascii_digit())? + 1;
        let Some(offset) = decimal(&before[start..]) else {
            continue;
        };
        let keyword = trim_pdf(&before[..start]);
        if let Some(earlier) = keyword.strip_suffix(b"startxref")
            && keyword.len() < start
            && earlier
                .last()
                .is_none_or(|byte| matches!(byte, b'\r' | b'\n'))
        {
            return Some((offset, earlier.len()));
        }
    }
    None
}

fn pdf_space(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn trim_pdf(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|&byte| !pdf_space(byte))
        .map_or(&[], |end| &bytes[..=end])
}

fn pdf_xref_type(bytes: &[u8]) -> bool {
    // ISO 32000-1 §7.5.8.2: the cross-reference stream dictionary has Type XRef.
    let dictionary = bytes.split(|&byte| byte == b'>').next().unwrap_or_default();
    dictionary.windows(5).enumerate().any(|(start, token)| {
        if token != b"/Type" {
            return false;
        }
        let tail = &dictionary[start + token.len()..];
        let next = tail
            .iter()
            .position(|&byte| !pdf_space(byte))
            .unwrap_or(tail.len());
        tail[next..].strip_prefix(b"/XRef").is_some_and(|after| {
            after
                .first()
                .is_none_or(|&byte| pdf_space(byte) || byte == b'/')
        })
    })
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0_u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}
