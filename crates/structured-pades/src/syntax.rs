//! Bounded original-range PDF object grammar, with iterative container frames.

mod value;
pub(crate) use value::read_into;

use crate::Session;
use crate::arena::{Arena, Children, Integer, Name, NodeId};
use crate::byte_machine::{Decoder, Step};
use crate::bytes::{Form, is_space};
use crate::error::{Error, ErrorKind, Limit, ReadFailure, Syntax};
use crate::object::Value;
use crate::range::{RangeReader, RangeSource};
use crate::source::{Location, Source};
use structured_asn1::memory::{OwnedVec, Work};

#[derive(Clone, Copy)]
enum Container {
    Array,
    Dictionary,
}

pub(crate) enum NumberKind {
    Integer,
    Real { fractional: bool },
}

#[derive(Clone, Copy)]
struct Frame {
    node: NodeId,
    kind: Container,
    start: u64,
    children: Children,
}

/// Reads one original PDF VALUE, not a complete file, indirect stream or a
/// signature verdict. Returned ranges keep the original source snapshot.
/// Whitespace/comments before the value are consumed; unrelated following
/// tokens are not included in [`Value::end`]. All nesting is iterative.
pub async fn read<'s, S: RangeSource, W: Work>(
    source: &S,
    session: &'s Session,
    operation: &W,
    offset: u64,
) -> Result<Value<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
    let reader = RangeReader::new(source, session, operation)?;
    let stamp = reader.stamp();
    if offset > stamp.length {
        return Err(Error {
            kind: ErrorKind::Foreign,
            location: location(0, stamp.length),
        }
        .into());
    }
    let work = reader.execution();
    let mut cursor = Cursor { reader, at: offset };
    let (arena, root) = read_into(&mut cursor, session, Arena::new(&work).into_owned()).await?;
    Ok(Value {
        arena,
        root,
        session,
        stamp,
        end: cursor.at,
    })
}

pub(crate) struct Cursor<'q, S: RangeSource> {
    pub(crate) reader: RangeReader<'q, S>,
    pub(crate) at: u64,
}

impl<S: RangeSource> Cursor<'_, S> {
    pub(crate) fn location(&self, start: u64, length: u64) -> Location {
        self.reader.location(start, length)
    }

    pub(crate) fn failure(&self, code: Syntax, at: u64) -> ReadFailure<S::Error> {
        Error {
            kind: ErrorKind::Syntax(code),
            location: self.location(at, 0),
        }
        .into()
    }

    pub(crate) async fn peek(&mut self) -> Result<Option<u8>, ReadFailure<S::Error>> {
        Ok(self.reader.byte_at(self.at).await?)
    }

    pub(crate) async fn take(&mut self) -> Result<Option<u8>, ReadFailure<S::Error>> {
        let byte = self.peek().await?;
        if byte.is_some() {
            self.at += 1;
        }
        Ok(byte)
    }

    pub(crate) async fn skip(&mut self) -> Result<(), ReadFailure<S::Error>> {
        loop {
            let Some(byte) = self.peek().await? else {
                return Ok(());
            };
            if is_space(byte) {
                self.at += 1;
                continue;
            }
            if byte != b'%' {
                return Ok(());
            }
            self.at += 1;
            let mut terminated = false;
            while let Some(byte) = self.take().await? {
                if byte == b'\r' || byte == b'\n' {
                    terminated = true;
                    break;
                }
            }
            if !terminated && self.at < self.reader.stamp().length {
                return Err(self.failure(Syntax::End, self.at));
            }
        }
    }

    pub(crate) async fn keyword(&mut self, expected: &[u8]) -> Result<(), ReadFailure<S::Error>> {
        let start = self.at;
        for &byte in expected {
            if self.take().await? != Some(byte) {
                return Err(self.failure(Syntax::Token, start));
            }
        }
        if let Some(next) = self.peek().await?
            && !boundary(next)
        {
            return Err(self.failure(Syntax::Token, self.at));
        }
        Ok(())
    }

    pub(crate) async fn looking(&mut self, expected: &[u8]) -> Result<bool, ReadFailure<S::Error>> {
        let start = self.at;
        for (index, &byte) in expected.iter().enumerate() {
            let Some(at) = start.checked_add(index as u64) else {
                return Ok(false);
            };
            if self.reader.byte_at(at).await? != Some(byte) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) async fn natural(&mut self) -> Result<u64, ReadFailure<S::Error>> {
        let at = self.at;
        let (integer, real) = self.number().await?;
        if !matches!(real, NumberKind::Integer) || integer.negative {
            return Err(self.failure(Syntax::Number, at));
        }
        integer.magnitude.ok_or_else(|| {
            Error {
                kind: ErrorKind::Unsupported(crate::error::Unsupported::NumericRange),
                location: self.location(at, self.at - at),
            }
            .into()
        })
    }

    pub(crate) async fn space(&mut self) -> Result<(), ReadFailure<S::Error>> {
        while self.peek().await?.is_some_and(is_space) {
            self.at += 1;
        }
        Ok(())
    }

    async fn name<W: Work>(
        &mut self,
        names: &mut OwnedVec<u8, W>,
    ) -> Result<Name, ReadFailure<S::Error>> {
        let start = names.len();
        self.at += 1; // leading slash was already inspected
        let mut decoder = Decoder::new(Form::Name);
        loop {
            let input = match self.peek().await? {
                Some(byte) if !boundary(byte) => Some(byte),
                _ => None,
            };
            match decoder.step(input) {
                Step::More => {
                    debug_assert!(input.is_some());
                    self.at += 1;
                }
                Step::Byte { value, consumed } => {
                    if consumed {
                        self.at += 1;
                    }
                    names
                        .try_push(value)
                        .map_err(|cause| refused(cause, self.location(self.at, 0)))?;
                }
                Step::End => break,
                Step::Malformed => return Err(self.failure(Syntax::Name, self.at)),
            }
        }
        Ok(Name {
            start,
            length: names.len() - start,
        })
    }

    async fn literal(
        &mut self,
        session: &Session,
        outer_depth: u64,
    ) -> Result<(), ReadFailure<S::Error>> {
        let start = self.at;
        self.at += 1;
        let mut depth = 1;
        let mut escaped = false;
        check_depth(session, outer_depth + depth, self.location(start, 1))?;
        while let Some(byte) = self.take().await? {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'(' => {
                    depth += 1;
                    check_depth(session, outer_depth + depth, self.location(self.at - 1, 1))?;
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(self.failure(Syntax::String, self.at))
    }

    async fn hexadecimal(&mut self) -> Result<(), ReadFailure<S::Error>> {
        let mut decoder = Decoder::new(Form::Hexadecimal);
        loop {
            let Some(byte) = self.take().await? else {
                return Err(self.failure(Syntax::String, self.at));
            };
            if byte == b'>' {
                match decoder.step(None) {
                    Step::End | Step::Byte { .. } => return Ok(()),
                    _ => return Err(self.failure(Syntax::String, self.at - 1)),
                }
            }
            if matches!(decoder.step(Some(byte)), Step::Malformed) {
                return Err(self.failure(Syntax::String, self.at - 1));
            }
        }
    }

    pub(crate) async fn number(&mut self) -> Result<(Integer, NumberKind), ReadFailure<S::Error>> {
        let start = self.at;
        let negative = self.peek().await? == Some(b'-');
        if matches!(self.peek().await?, Some(b'+' | b'-')) {
            self.at += 1;
        }
        let mut magnitude = Some(0_u64);
        let mut real = false;
        let mut fractional = false;
        let mut digits = 0_u64;
        while let Some(byte) = self.peek().await? {
            if byte.is_ascii_digit() {
                if real {
                    fractional |= byte != b'0';
                } else {
                    magnitude = magnitude.and_then(|value| {
                        value
                            .checked_mul(10)
                            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                    });
                }
                digits += 1;
                self.at += 1;
                continue;
            }
            if byte == b'.' && !real {
                real = true;
                self.at += 1;
                continue;
            }
            if boundary(byte) {
                break;
            }
            return Err(self.failure(Syntax::Number, self.at));
        }
        if digits == 0 {
            return Err(self.failure(Syntax::Number, start));
        }
        Ok((
            Integer {
                negative,
                magnitude,
            },
            if real {
                NumberKind::Real { fractional }
            } else {
                NumberKind::Integer
            },
        ))
    }

    async fn reference(
        &mut self,
        first: Integer,
    ) -> Result<Option<(u64, u16)>, ReadFailure<S::Error>> {
        let after_first = self.at;
        self.skip().await?;
        if self.at == after_first || !matches!(self.peek().await?, Some(b'0'..=b'9')) {
            return Ok(None);
        }
        let generation = match self.number().await {
            Ok((integer, NumberKind::Integer)) => integer,
            Ok(_) => return Ok(None),
            // This is lookahead for a reference, not recovery from a parsed
            // reference. The first INTEGER is independently valid; its caller
            // will parse any unrelated malformed following token normally.
            Err(ReadFailure::Format(error)) if error.kind == ErrorKind::Syntax(Syntax::Number) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let after_generation = self.at;
        self.skip().await?;
        if self.at == after_generation || self.peek().await? != Some(b'R') {
            return Ok(None);
        }
        self.at += 1;
        if let Some(next) = self.peek().await?
            && !boundary(next)
        {
            return Ok(None);
        }
        let (Some(number), Some(generation)) = (first.magnitude, generation.magnitude) else {
            return Err(Error {
                kind: ErrorKind::Unsupported(crate::error::Unsupported::NumericRange),
                location: self.location(after_first, self.at - after_first),
            }
            .into());
        };
        let generation =
            u16::try_from(generation).map_err(|_| self.failure(Syntax::Object, after_first))?;
        Ok(Some((number, generation)))
    }
}

fn boundary(byte: u8) -> bool {
    is_space(byte)
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

fn location(start: u64, length: u64) -> Location {
    Location::new(Source::File, start, length).expect("bounded original object range")
}

fn refused(cause: structured_asn1::memory::MemoryError, location: Location) -> Error {
    Error {
        kind: ErrorKind::Resource(cause),
        location,
    }
}

fn check_depth(session: &Session, depth: u64, location: Location) -> crate::Result<()> {
    if depth > u64::from(session.limits().processing.max_depth) {
        return Err(Error {
            kind: ErrorKind::Limit(Limit::Depth),
            location,
        });
    }
    Ok(())
}
