use super::{Candidate, Error, Finding, Format, Namespace, charge, framing::at};
use structured_asn1::{
    Span,
    memory::{Execution, MemoryError, OwnedText},
};
use xmlparser::{ElementEnd, Error as TokenError, StreamError, Token, Tokenizer};

#[derive(Clone, Copy)]
enum Encoding {
    Utf8,
    Utf16 { little: bool },
}

pub(super) enum Text<'s, 'q> {
    Borrowed(&'s str),
    Owned(OwnedText<Execution<'q>>),
}
impl Text<'_, '_> {
    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Owned(text) => text.as_str(),
        }
    }
}

pub(super) struct Input<'s, 'q> {
    pub(super) text: Text<'s, 'q>,
    encoding: Encoding,
    bom: usize,
    invalid: bool,
}

impl Input<'_, '_> {
    pub(super) fn complete(&self) -> bool {
        !self.invalid
    }

    fn original(&self, byte: usize) -> usize {
        match self.encoding {
            Encoding::Utf8 => self.bom + byte,
            Encoding::Utf16 { .. } => {
                self.bom + self.text.as_str()[..byte].encode_utf16().count() * 2
            }
        }
    }

    pub(super) fn declaration(&self, label: Option<&str>, version: &str) -> Finding {
        if version != "1.0" {
            return Finding::Unsupported;
        }
        let Some(label) = label else {
            return if matches!(self.encoding, Encoding::Utf16 { .. }) && self.bom == 0 {
                Finding::Conflicting
            } else {
                Finding::Framing
            };
        };
        let generic = label.eq_ignore_ascii_case("UTF-16");
        let utf8 = label.eq_ignore_ascii_case("UTF-8");
        let little = label.eq_ignore_ascii_case("UTF-16LE");
        let big = label.eq_ignore_ascii_case("UTF-16BE");
        match self.encoding {
            Encoding::Utf8 if utf8 || (self.bom == 0 && label.eq_ignore_ascii_case("US-ASCII")) => {
                Finding::Framing
            }
            Encoding::Utf8 if self.bom != 0 || generic || little || big => Finding::Conflicting,
            Encoding::Utf8 => Finding::Unsupported,
            Encoding::Utf16 { little: order }
                if (generic && self.bom != 0) || (order && little) || (!order && big) =>
            {
                Finding::Framing
            }
            Encoding::Utf16 { .. } => Finding::Conflicting,
        }
    }
}

pub(super) fn input<'s, 'q>(
    bytes: &'s [u8],
    work: &Execution<'q>,
) -> Result<Result<Input<'s, 'q>, Finding>, MemoryError> {
    // XML 1.0 §4.3.3 and informative Appendix F. A UCS-4 or EBCDIC
    // XML byte signature does not select a supported decoder.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-guessing
    let (encoding, bom) = match bytes {
        [0, 0, 0xfe, 0xff, ..]
        | [0xff, 0xfe, 0, 0, ..]
        | [0, 0, 0xff, 0xfe, ..]
        | [0xfe, 0xff, 0, 0, ..]
        | [0, 0, 0, b'<', ..]
        | [b'<', 0, 0, 0, ..]
        | [0, b'<', 0, 0, ..]
        | [0, 0, b'<', 0, ..]
        | [0x4c, 0x6f, 0xa7, 0x94, ..] => {
            return Ok(Err(Finding::Unsupported));
        }
        [0xef, 0xbb, 0xbf, ..] => (Encoding::Utf8, 3),
        [0xff, 0xfe, ..] => (Encoding::Utf16 { little: true }, 2),
        [0xfe, 0xff, ..] => (Encoding::Utf16 { little: false }, 2),
        [b'<', 0, b'?', 0, ..] => (Encoding::Utf16 { little: true }, 0),
        [0, b'<', 0, b'?', ..] => (Encoding::Utf16 { little: false }, 0),
        _ => (Encoding::Utf8, 0),
    };
    let raw = &bytes[bom..];
    let (mut text, invalid) = match encoding {
        Encoding::Utf8 => match core::str::from_utf8(raw) {
            Ok(text) => (Text::Borrowed(text), false),
            Err(error) => (
                Text::Borrowed(
                    core::str::from_utf8(&raw[..error.valid_up_to()]).expect("UTF-8 valid prefix"),
                ),
                true,
            ),
        },
        Encoding::Utf16 { little } => utf16(raw, little, work)?,
    };
    // The tokenizer's declaration discriminator accepts a space after "xml".
    // XML 1.0 production [3] also admits the other three S octets. Replacing
    // only that separator keeps original offsets and the same grammar.
    if matches!(
        text.as_str().as_bytes(),
        [b'<', b'?', b'x', b'm', b'l', b'\t' | b'\r' | b'\n', ..]
    ) {
        let original = text.as_str();
        let mut copy = OwnedText::try_from_str(&original[..5], work)?;
        copy.try_push_str(" ")?;
        copy.try_push_str(&original[6..])?;
        text = Text::Owned(copy);
    }
    Ok(Ok(Input {
        text,
        encoding,
        bom,
        invalid,
    }))
}

fn utf16<'s, 'q>(
    raw: &[u8],
    little: bool,
    work: &Execution<'q>,
) -> Result<(Text<'s, 'q>, bool), MemoryError> {
    let mut out = OwnedText::try_from_str("", work)?;
    let (pairs, remainder) = raw.as_chunks::<2>();
    let units = pairs.iter().map(|&octets| {
        if little {
            u16::from_le_bytes(octets)
        } else {
            u16::from_be_bytes(octets)
        }
    });
    for value in char::decode_utf16(units) {
        let Ok(scalar) = value else {
            return Ok((Text::Owned(out), true));
        };
        out.try_push_str(scalar.encode_utf8(&mut [0; 4]))?;
    }
    Ok((Text::Owned(out), !remainder.is_empty()))
}

type Reading = (Candidate, Option<Namespace>);

pub(super) fn probe<E>(bytes: &[u8], work: &Execution<'_>) -> Result<Option<Reading>, Error<E>> {
    // Avoid transcoding, allocating or validating UTF-8 for non-XML binary input.
    let range = Span {
        start: 0,
        length: bytes.len() as u64,
    };
    let head = bytes.first().copied();
    if !matches!(
        head,
        Some(b'<' | b' ' | b'\t' | b'\n' | b'\r' | 0xef | 0xff | 0xfe | 0 | 0x4c)
    ) {
        return Ok(None);
    }
    charge(work, range, 12)?;
    let input = match input(bytes, work).map_err(|cause| Error::Resource { range, cause })? {
        Ok(input) => input,
        Err(finding) => return Ok(Some((at(Format::Xml, finding, 4), None))),
    };
    let text = input.text.as_str();
    let significant = text.trim_start_matches(xml_space);
    if !significant.starts_with('<') {
        return Ok(None);
    }
    root(&input, text, work).map_err(|cause| Error::Resource { range, cause })
}

fn root(
    input: &Input<'_, '_>,
    text: &str,
    work: &Execution<'_>,
) -> Result<Option<Reading>, MemoryError> {
    let mut tokens = Tokenizer::from(text);
    let mut base = 0;
    let mut consumed = 0;
    let mut dtd = false;
    let mut uncertain_namespace = false;
    while let Some(token) = tokens.next() {
        let rest = text[base + consumed..].trim_start_matches(xml_space);
        if let Ok(token) = token {
            consumed = token.span().end();
        }
        match token {
            Ok(Token::Declaration {
                encoding,
                version,
                span,
                ..
            }) => {
                let finding = if span.start() != 0 || base != 0 {
                    Finding::Conflicting
                } else {
                    input.declaration(encoding.map(|label| label.as_str()), version.as_str())
                };
                if finding != Finding::Framing {
                    return Ok(Some((
                        at(Format::Xml, finding, input.original(base + span.end())),
                        None,
                    )));
                }
            }
            Ok(Token::DtdStart { span, .. }) if !dtd => {
                dtd = true;
                uncertain_namespace = true;
                let start = base + span.end();
                let Some(end) = subset_end(&text.as_bytes()[start..]) else {
                    return Ok(Some((
                        at(Format::Xml, Finding::Incomplete, input.original(text.len())),
                        None,
                    )));
                };
                base = start + end;
                consumed = 0;
                tokens = Tokenizer::from(&text[base..]);
            }
            Ok(Token::EmptyDtd { external_id, .. }) if !dtd => {
                dtd = true;
                uncertain_namespace = external_id.is_some();
            }
            Ok(Token::ElementStart { prefix, span, .. }) => {
                let (finding, namespace, end) = opening(
                    &mut tokens,
                    prefix.as_str(),
                    span.end(),
                    uncertain_namespace,
                    work,
                )?;
                return Ok(Some((
                    at(Format::Xml, finding, input.original(base + end)),
                    Some(namespace),
                )));
            }
            Ok(Token::Comment { .. } | Token::ProcessingInstruction { .. }) => {}
            Err(error) => {
                let finding = if incomplete(error) || prologue_prefix(rest) {
                    Finding::Incomplete
                } else {
                    Finding::Conflicting
                };
                return Ok(Some((
                    at(Format::Xml, finding, input.original(text.len())),
                    None,
                )));
            }
            _ => {
                return Ok(Some((
                    at(
                        Format::Xml,
                        Finding::Conflicting,
                        input.original(text.len()),
                    ),
                    None,
                )));
            }
        }
    }
    Ok(Some((
        at(Format::Xml, Finding::Incomplete, input.original(text.len())),
        None,
    )))
}

fn opening(
    tokens: &mut Tokenizer<'_>,
    prefix: &str,
    name_end: usize,
    opaque: bool,
    work: &Execution<'_>,
) -> Result<(Finding, Namespace, usize), MemoryError> {
    let mut declared = None;
    for token in tokens {
        match token {
            Ok(Token::Attribute {
                prefix: attr_prefix,
                local,
                value,
                span,
            }) => {
                if is_binding(prefix, attr_prefix.as_str(), local.as_str())
                    && declared.replace(value.as_str()).is_some()
                {
                    return Ok((Finding::Conflicting, Namespace::Unknown, span.end()));
                }
            }
            Ok(Token::ElementEnd {
                end: ElementEnd::Open | ElementEnd::Empty,
                span,
            }) => {
                let namespace = if opaque {
                    Namespace::Unknown
                } else {
                    namespace(prefix, declared, work)?
                };
                return Ok((Finding::Framing, namespace, span.end()));
            }
            Err(error) if incomplete(error) => break,
            _ => return Ok((Finding::Conflicting, Namespace::Unknown, name_end)),
        }
    }
    Ok((Finding::Incomplete, Namespace::Unknown, name_end))
}

pub(super) fn is_binding(prefix: &str, attribute_prefix: &str, local: &str) -> bool {
    if prefix.is_empty() {
        attribute_prefix.is_empty() && local == "xmlns"
    } else {
        attribute_prefix == "xmlns" && prefix == local
    }
}

fn namespace(
    prefix: &str,
    declaration: Option<&str>,
    work: &Execution<'_>,
) -> Result<Namespace, MemoryError> {
    const XML: &str = "http://www.w3.org/XML/1998/namespace";
    match declaration {
        Some(value) if value.contains(['&', '\r', '\n', '\t']) => Ok(Namespace::Unknown),
        Some(value)
            if !value.is_empty() && prefix != "xmlns" && (prefix != "xml" || value == XML) =>
        {
            Ok(Namespace::Uri(
                OwnedText::try_from_str(value, work)?.into_owned(),
            ))
        }
        None if prefix == "xml" => Ok(Namespace::Uri(
            OwnedText::try_from_str(XML, work)?.into_owned(),
        )),
        None | Some("") if prefix.is_empty() => Ok(Namespace::None),
        _ => Ok(Namespace::Unknown),
    }
}

fn xml_space(ch: char) -> bool {
    matches!(ch, ' ' | '\r' | '\n' | '\t')
}

fn prologue_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (start, end) in [
        (b"<!--".as_slice(), b"-->".as_slice()),
        (b"<?".as_slice(), b"?>".as_slice()),
        (b"<!DOCTYPE".as_slice(), b">".as_slice()),
    ] {
        if start.starts_with(bytes)
            || (bytes.starts_with(start) && after(&bytes[start.len()..], end).is_none())
        {
            return true;
        }
    }
    false
}

fn incomplete(error: TokenError) -> bool {
    let cause = match error {
        TokenError::InvalidDeclaration(cause, _)
        | TokenError::InvalidComment(cause, _)
        | TokenError::InvalidPI(cause, _)
        | TokenError::InvalidDoctype(cause, _)
        | TokenError::InvalidEntity(cause, _)
        | TokenError::InvalidElement(cause, _)
        | TokenError::InvalidAttribute(cause, _)
        | TokenError::InvalidCdata(cause, _)
        | TokenError::InvalidCharData(cause, _) => cause,
        TokenError::UnknownToken(_) => return false,
    };
    cause == StreamError::UnexpectedEndOfStream
}

fn subset_end(bytes: &[u8]) -> Option<usize> {
    // XML 1.0 §2.8, production [28]. Skip opaque internal declarations,
    // honoring literals, comments and PIs without including any entities.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-prolog-dtd
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let rest = &bytes[at..];
        if rest.starts_with(b"<!--") {
            at += 4 + after(&rest[4..], b"-->")?;
        } else if rest.starts_with(b"<?") {
            at += 2 + after(&rest[2..], b"?>")?;
        } else if matches!(byte, b'\'' | b'"') {
            at += 2 + rest[1..].iter().position(|&next| next == byte)?;
        } else if byte == b']' {
            at += 1;
            while matches!(bytes.get(at), Some(b' ' | b'\r' | b'\n' | b'\t')) {
                at += 1;
            }
            return (bytes.get(at) == Some(&b'>')).then_some(at + 1);
        } else {
            at += 1;
        }
    }
    None
}

fn after(bytes: &[u8], marker: &[u8]) -> Option<usize> {
    bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|index| index + marker.len())
}
