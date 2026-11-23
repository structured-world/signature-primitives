//! Allocation-free lexical inspection of the bounded PDF xref record.

use super::{decimal, pdf_space};

pub(super) fn xref(bytes: &[u8]) -> bool {
    let mut tokens = Tokens(bytes);
    match (tokens.next(), tokens.next(), tokens.next()) {
        (Some(Token::Atom(b"xref")), Some(Token::Atom(start)), Some(Token::Atom(count))) => {
            decimal(start).is_some() && decimal(count).is_some()
        }
        (Some(Token::Atom(object)), Some(Token::Atom(generation)), Some(Token::Atom(b"obj"))) => {
            decimal(object).is_some() && decimal(generation).is_some() && stream_type(&mut tokens)
        }
        _ => false,
    }
}

fn stream_type(tokens: &mut Tokens<'_>) -> bool {
    // ISO 32000-1 §§7.3.7 and 7.5.8.2: the outer dictionary is unordered,
    // and its Type key names the XRef stream. Values can contain dictionaries.
    // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
    if tokens.next() != Some(Token::Dictionary) {
        return false;
    }
    let mut kind = None;
    while let Some(key) = tokens.next() {
        let name = match key {
            Token::EndDictionary => return kind == Some(true),
            Token::Name(name) => name,
            _ => return false,
        };
        let Some(value) = tokens.next() else {
            return false;
        };
        if named(name, b"Type")
            && kind
                .replace(matches!(value, Token::Name(value) if named(value, b"XRef")))
                .is_some()
        {
            return false;
        }
        if !tokens.skip_value(value) {
            return false;
        }
    }
    false
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Token<'a> {
    Atom(&'a [u8]),
    Name(&'a [u8]),
    String,
    Dictionary,
    EndDictionary,
    Array,
    EndArray,
}

#[derive(Copy, Clone)]
struct Tokens<'a>(&'a [u8]);

impl<'a> Tokens<'a> {
    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            let first = self.0.iter().position(|&byte| !pdf_space(byte))?;
            self.0 = &self.0[first..];
            if self.0[0] != b'%' {
                break;
            }
            let end = self
                .0
                .iter()
                .position(|&byte| matches!(byte, b'\r' | b'\n'))?;
            self.0 = &self.0[end..];
        }
        let (token, consumed) = match self.0 {
            [b'<', b'<', ..] => (Token::Dictionary, 2),
            [b'>', b'>', ..] => (Token::EndDictionary, 2),
            [b'[', ..] => (Token::Array, 1),
            [b']', ..] => (Token::EndArray, 1),
            [b'(', rest @ ..] => (Token::String, literal_end(rest)? + 1),
            [b'<', rest @ ..] => (Token::String, hex_end(rest)? + 1),
            [b'/', rest @ ..] => {
                let length = word_length(rest);
                (Token::Name(&rest[..length]), length + 1)
            }
            _ => {
                let length = word_length(self.0);
                if length == 0 {
                    return None;
                }
                (Token::Atom(&self.0[..length]), length)
            }
        };
        self.0 = &self.0[consumed..];
        Some(token)
    }

    fn skip_value(&mut self, value: Token<'_>) -> bool {
        match value {
            Token::Dictionary | Token::Array => self.skip_composite(value == Token::Dictionary),
            Token::Atom(first) => {
                // An indirect reference is one value. A simple integer is
                // also valid, so look ahead without consuming the next key.
                if decimal(first).is_some() {
                    let mut after = *self;
                    if matches!(after.next(), Some(Token::Atom(number)) if decimal(number).is_some())
                        && after.next() == Some(Token::Atom(b"R"))
                    {
                        *self = after;
                    }
                }
                true
            }
            Token::Name(_) | Token::String => true,
            Token::EndDictionary | Token::EndArray => false,
        }
    }

    fn skip_composite(&mut self, dictionary: bool) -> bool {
        // One bit per delimiter is sufficient for the 128-byte probe. Each
        // open token consumes an original byte and the scan never recurses.
        let mut stack = u128::from(dictionary);
        let mut depth = 1;
        while let Some(token) = self.next() {
            match token {
                Token::Dictionary | Token::Array if depth < 128 => {
                    stack = (stack << 1) | u128::from(token == Token::Dictionary);
                    depth += 1;
                }
                Token::Dictionary | Token::Array => return false,
                Token::EndDictionary | Token::EndArray => {
                    if (stack & 1 != 0) != (token == Token::EndDictionary) {
                        return false;
                    }
                    depth -= 1;
                    if depth == 0 {
                        return true;
                    }
                    stack >>= 1;
                }
                _ => {}
            }
        }
        false
    }
}

fn word_length(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|&byte| {
            pdf_space(byte)
                || matches!(
                    byte,
                    b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
                )
        })
        .unwrap_or(bytes.len())
}

fn literal_end(bytes: &[u8]) -> Option<usize> {
    let mut depth = 1;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn hex_end(bytes: &[u8]) -> Option<usize> {
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'>' {
            return Some(index + 1);
        }
        if !byte.is_ascii_hexdigit() && !pdf_space(byte) {
            return None;
        }
    }
    None
}

fn named(mut raw: &[u8], name: &[u8]) -> bool {
    // ISO 32000-1 §7.3.5 permits # followed by two hex digits in a name.
    for &expected in name {
        let (byte, rest) = match raw {
            [b'#', hi, lo, rest @ ..] => {
                let (Some(hi), Some(lo)) =
                    (char::from(*hi).to_digit(16), char::from(*lo).to_digit(16))
                else {
                    return false;
                };
                (hi * 16 + lo, rest)
            }
            [byte, rest @ ..] => (u32::from(*byte), rest),
            [] => return false,
        };
        if byte != u32::from(expected) {
            return false;
        }
        raw = rest;
    }
    raw.is_empty()
}
