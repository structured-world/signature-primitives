//! Structural stream extents and bounded decoding, independent of rendering.

use crate::arena::{Arena, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::admit;
use crate::range::{RangeReader, RangeSource};
use crate::syntax::{Cursor, read_into};
use structured_asn1::{
    Span,
    memory::{Memory, OwnedVec, Work},
};
pub(crate) mod plan;

#[derive(Clone, Copy)]
pub(crate) struct Indirect {
    pub(crate) number: u64,
    pub(crate) generation: u16,
    pub(crate) value: NodeId,
    pub(crate) start: u64,
    pub(crate) stream: Option<u64>,
}

pub(crate) async fn open<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    arena: Arena<Memory>,
) -> Result<(Arena<Memory>, Indirect), ReadFailure<S::Error>> {
    let start = cursor.at;
    let number = cursor.natural().await?;
    if number == 0 {
        return Err(cursor.failure(Syntax::Object, start));
    }
    let gap = cursor.at;
    cursor.skip().await?;
    if gap == cursor.at {
        return Err(cursor.failure(Syntax::Object, gap));
    }
    let generation = u16::try_from(cursor.natural().await?)
        .map_err(|_| cursor.failure(Syntax::Object, cursor.at))?;
    let gap = cursor.at;
    cursor.skip().await?;
    if gap == cursor.at {
        return Err(cursor.failure(Syntax::Object, gap));
    }
    cursor.keyword(b"obj").await?;
    let session = cursor.reader.session();
    let (arena, value) = read_into(cursor, session, arena).await?;
    cursor.skip().await?;
    let stream = if cursor.looking(b"stream").await? {
        cursor.keyword(b"stream").await?;
        // ISO 32000-1 §7.3.8.1 requires LF or CRLF after stream. Bare CR
        // is not a substitute, and payload leading whitespace is not skipped.
        match cursor.take().await? {
            Some(b'\n') => {}
            Some(b'\r') if cursor.take().await? == Some(b'\n') => {}
            _ => return Err(cursor.failure(Syntax::Stream, cursor.at)),
        }
        Some(cursor.at)
    } else {
        cursor.keyword(b"endobj").await?;
        None
    };
    Ok((
        arena,
        Indirect {
            number,
            generation,
            value,
            start,
            stream,
        },
    ))
}

pub(crate) async fn close<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    start: u64,
    length: u64,
) -> Result<Span, ReadFailure<S::Error>> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| cursor.failure(Syntax::Stream, start))?;
    if end > cursor.reader.stamp().length {
        return Err(cursor.failure(Syntax::Stream, start));
    }
    cursor.at = end;
    if cursor.peek().await? == Some(b'\r') {
        cursor.at += 1;
    }
    if cursor.peek().await? == Some(b'\n') {
        cursor.at += 1;
    }
    cursor.keyword(b"endstream").await?;
    cursor.skip().await?;
    cursor.keyword(b"endobj").await?;
    Ok(Span { start, length })
}

#[derive(Clone, Copy)]
pub(crate) enum Filter {
    Hex,
    Base85,
    RunLength,
    Lzw { early: u8 },
    Flate,
}

#[derive(Clone, Copy)]
enum Prediction {
    None,
    Tiff {
        row: usize,
        colors: usize,
        samples: usize,
        bits: usize,
    },
    Png {
        row: usize,
        bpp: usize,
    },
}

pub(crate) struct Step {
    filter: Filter,
    prediction: Prediction,
}

pub(crate) async fn decoded<S: RangeSource, W: Work>(
    reader: &mut RangeReader<'_, S>,
    body: Span,
    arena: &Arena<W>,
    dictionary: NodeId,
    revision: usize,
) -> Result<OwnedVec<u8, Memory>, ReadFailure<S::Error>> {
    decoded_extent(reader, body, arena, dictionary, revision, true)
        .await
        .map(|(bytes, _)| bytes)
}

pub(crate) async fn decoded_extent<S: RangeSource, W: Work>(
    reader: &mut RangeReader<'_, S>,
    body: Span,
    arena: &Arena<W>,
    dictionary: NodeId,
    revision: usize,
    bounded: bool,
) -> Result<(OwnedVec<u8, Memory>, u64), ReadFailure<S::Error>> {
    let input = plan::Direct {
        arena,
        root: dictionary,
    };
    let mut builder = plan::Builder::new(
        &reader.execution(),
        reader.location(body.start, body.length),
    );
    builder
        .advance(&input, &reader.execution())
        .map_err(|error| match error {
            plan::Failure::Fault(error) => ReadFailure::Format(error),
            plan::Failure::Need { .. } => unreachable!("direct controls refuse references"),
        })?;
    execute(reader, body, &builder.finish(), revision, bounded).await
}

pub(crate) async fn execute<S: RangeSource>(
    reader: &mut RangeReader<'_, S>,
    body: Span,
    plans: &[Step],
    revision: usize,
    bounded: bool,
) -> Result<(OwnedVec<u8, Memory>, u64), ReadFailure<S::Error>> {
    let work = reader.execution();
    let location = reader.location(body.start, body.length);
    if plans.is_empty() {
        let mut output = work.vector();
        reader.session().decode(body.length, location)?;
        for offset in body.start..body.start + body.length {
            let byte = reader.byte_at(offset).await?.ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location,
            })?;
            output.try_push(byte).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        return Ok((output.into_owned(), body.length));
    }
    let mut previous: Option<OwnedVec<u8, Memory>> = None;
    let mut consumed = body.length;
    for (ordinal, plan) in plans.iter().enumerate() {
        let mut output = if let Some(prior) = previous.take() {
            let slice = crate::range::Slice::new(&prior, reader.stamp().snapshot);
            let mut nested = RangeReader::in_source(
                &slice,
                reader.session(),
                &work,
                crate::source::Source::Decoded {
                    stream: body,
                    revision,
                    stage: ordinal,
                },
            )
            .map_err(|error| crate::document::resolve::convert(ReadFailure::Input(error)))?;
            decode(
                &mut nested,
                Span {
                    start: 0,
                    length: prior.len() as u64,
                },
                plan.filter,
                true,
            )
            .await
            .map_err(crate::document::resolve::convert)?
            .0
        } else {
            let (output, extent) = decode(reader, body, plan.filter, bounded).await?;
            consumed = extent;
            output
        };
        predictor(&mut output, plan.prediction, &work, location)?;
        previous = Some(output);
    }
    Ok((previous.expect("nonempty filter array"), consumed))
}

fn prediction_shape(
    prediction: u64,
    colors: u64,
    bits: u64,
    columns: u64,
    location: crate::source::Location,
) -> crate::Result<Prediction> {
    let malformed = || Error {
        kind: ErrorKind::Syntax(Syntax::Stream),
        location,
    };
    if colors == 0 || columns == 0 || !matches!(bits, 1 | 2 | 4 | 8 | 16) {
        return Err(malformed());
    }
    let samples = colors.checked_mul(columns).ok_or_else(malformed)?;
    let row_bits = samples.checked_mul(bits).ok_or_else(malformed)?;
    let row = usize::try_from(row_bits.checked_add(7).ok_or_else(malformed)? / 8)
        .map_err(|_| malformed())?;
    let bpp = usize::try_from(
        colors
            .checked_mul(bits)
            .and_then(|value| value.checked_add(7))
            .ok_or_else(malformed)?
            / 8,
    )
    .map_err(|_| malformed())?;
    if prediction == 2 {
        let colors = usize::try_from(colors).map_err(|_| malformed())?;
        let samples = usize::try_from(samples).map_err(|_| malformed())?;
        let bits = usize::try_from(bits).expect("bounded sample width");
        return Ok(Prediction::Tiff {
            row,
            colors,
            samples,
            bits,
        });
    }
    if !(10..=15).contains(&prediction) {
        return Err(malformed());
    }
    row.checked_add(1).ok_or_else(malformed)?;
    Ok(Prediction::Png { row, bpp })
}

fn predictor(
    output: &mut OwnedVec<u8, Memory>,
    prediction: Prediction,
    work: &impl Work,
    location: crate::source::Location,
) -> crate::Result<()> {
    let malformed = || Error {
        kind: ErrorKind::Syntax(Syntax::Stream),
        location,
    };
    let (row, bpp) = match prediction {
        Prediction::None => return Ok(()),
        Prediction::Tiff {
            row,
            colors,
            samples,
            bits,
        } => {
            if !output.len().is_multiple_of(row) {
                return Err(malformed());
            }
            for start in (0..output.len()).step_by(row) {
                admit(work, location, samples as u64 * bits as u64 * 2)?;
                for sample in colors..samples {
                    let bit = sample * bits;
                    let prior = (sample - colors) * bits;
                    let mut value = 0_u32;
                    let mut left = 0_u32;
                    for index in 0..bits {
                        value = (value << 1)
                            | u32::from(
                                (output[start + (bit + index) / 8] >> (7 - (bit + index) % 8)) & 1,
                            );
                        left = (left << 1)
                            | u32::from(
                                (output[start + (prior + index) / 8] >> (7 - (prior + index) % 8))
                                    & 1,
                            );
                    }
                    let value = (value + left) & ((1_u32 << bits) - 1);
                    for index in 0..bits {
                        let shift = 7 - (bit + index) % 8;
                        let byte = &mut output[start + (bit + index) / 8];
                        *byte = (*byte & !(1 << shift))
                            | (u8::try_from((value >> (bits - 1 - index)) & 1).expect("bit")
                                << shift);
                    }
                }
            }
            return Ok(());
        }
        Prediction::Png { row, bpp } => (row, bpp),
    };
    let stride = row + 1;
    if !output.len().is_multiple_of(stride) {
        return Err(malformed());
    }
    let mut read = 0;
    let mut write = 0;
    while read < output.len() {
        admit(work, location, row as u64 * 8 + 1)?;
        let filter = output[read];
        read += 1;
        // ISO32000-1 §7.4.4.4/Table10 limits 10..14 on ENCODING only;
        // decoding all PNG predictors follows each row's explicit tag.
        // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
        if filter > 4 {
            return Err(malformed());
        }
        for column in 0..row {
            let left = if column >= bpp {
                output[write + column - bpp]
            } else {
                0
            };
            let above = if write >= row {
                output[write + column - row]
            } else {
                0
            };
            let upper_left = if write >= row && column >= bpp {
                output[write + column - row - bpp]
            } else {
                0
            };
            let predicted = match filter {
                0 => 0,
                1 => left,
                2 => above,
                3 => left.midpoint(above),
                4 => paeth(left, above, upper_left),
                _ => unreachable!("checked filter"),
            };
            output[write + column] = output[read + column].wrapping_add(predicted);
        }
        read += row;
        write += row;
    }
    admit(work, location, (output.len() - write) as u64)?;
    while output.len() > write {
        output.pop().expect("nonempty compacted tail");
    }
    Ok(())
}

fn paeth(left: u8, above: u8, upper_left: u8) -> u8 {
    let prediction = i32::from(left) + i32::from(above) - i32::from(upper_left);
    let a = (prediction - i32::from(left)).abs();
    let b = (prediction - i32::from(above)).abs();
    let c = (prediction - i32::from(upper_left)).abs();
    if a <= b && a <= c {
        left
    } else if b <= c {
        above
    } else {
        upper_left
    }
}

struct Input<'a, 'q, S: RangeSource> {
    reader: &'a mut RangeReader<'q, S>,
    at: u64,
    end: u64,
    bounded: bool,
}

impl<S: RangeSource> Input<'_, '_, S> {
    async fn next(&mut self) -> Result<Option<u8>, ReadFailure<S::Error>> {
        if self.at == self.end {
            return Ok(None);
        }
        let byte = self
            .reader
            .byte_at(self.at)
            .await?
            .ok_or_else(|| self.error())?;
        self.at += 1;
        Ok(Some(byte))
    }

    fn error(&self) -> Error {
        Error {
            kind: ErrorKind::Syntax(Syntax::Stream),
            location: self.reader.location(self.at, 0),
        }
    }

    fn put<W: Work>(&self, output: &mut OwnedVec<u8, W>, byte: u8) -> crate::Result<()> {
        let location = self.reader.location(self.at, 0);
        self.reader.session().decode(1, location)?;
        output.try_push(byte).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })
    }

    async fn finish(&mut self) -> Result<(), ReadFailure<S::Error>> {
        if !self.bounded {
            return Ok(());
        }
        while let Some(byte) = self.next().await? {
            if !crate::bytes::is_space(byte) {
                return Err(self.error().into());
            }
        }
        Ok(())
    }
}

pub(crate) async fn decode<S: RangeSource>(
    reader: &mut RangeReader<'_, S>,
    body: Span,
    filter: Filter,
    bounded: bool,
) -> Result<(OwnedVec<u8, Memory>, u64), ReadFailure<S::Error>> {
    let location = reader.location(body.start, body.length);
    let end = body.start.checked_add(body.length).ok_or(Error {
        kind: ErrorKind::Foreign,
        location,
    })?;
    if end > reader.stamp().length {
        return Err(Error {
            kind: ErrorKind::Foreign,
            location,
        }
        .into());
    }
    let work = reader.execution();
    let mut output = work.vector();
    let mut input = Input {
        reader,
        at: body.start,
        end,
        bounded,
    };
    match filter {
        Filter::Hex => {
            let mut high = None;
            let mut closed = false;
            while let Some(byte) = input.next().await? {
                if crate::bytes::is_space(byte) {
                    continue;
                }
                if byte == b'>' {
                    closed = true;
                    break;
                }
                let value = match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => return Err(input.error().into()),
                };
                if let Some(first) = high.take() {
                    input.put(&mut output, first * 16 + value)?;
                } else {
                    high = Some(value);
                }
            }
            if !closed {
                return Err(input.error().into());
            }
            if let Some(first) = high {
                input.put(&mut output, first * 16)?;
            }
            input.finish().await?;
        }
        Filter::Base85 => base85(&mut input, &mut output).await?,
        Filter::RunLength => loop {
            let length = input.next().await?.ok_or_else(|| input.error())?;
            if length == 128 {
                input.finish().await?;
                break;
            }
            if length < 128 {
                for _ in 0..=length {
                    let byte = input.next().await?.ok_or_else(|| input.error())?;
                    input.put(&mut output, byte)?;
                }
            } else {
                let byte = input.next().await?.ok_or_else(|| input.error())?;
                for _ in 0..257 - u16::from(length) {
                    input.put(&mut output, byte)?;
                }
            }
        },
        Filter::Lzw { early } => lzw(&mut input, &mut output, early).await?,
        Filter::Flate => flate(&mut input, &mut output).await?,
    }
    Ok((output.into_owned(), input.at - body.start))
}

async fn lzw<S: RangeSource, W: Work>(
    input: &mut Input<'_, '_, S>,
    output: &mut OwnedVec<u8, W>,
    early: u8,
) -> Result<(), ReadFailure<S::Error>> {
    if early > 1 {
        return Err(input.error().into());
    }
    let work = input.reader.execution();
    let location = input.reader.location(input.at, 0);
    let mut prefixes = work.vector();
    let mut suffixes = work.vector();
    let mut stack = work.vector();
    prefixes
        .try_extend_from_slice(&[0_u16; 4096])
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    suffixes
        .try_extend_from_slice(&[0_u8; 4096])
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    let mut bits = 0_u32;
    let mut count = 0_u8;
    let mut width = 9_u8;
    let mut next = 258_u16;
    let mut previous = None;
    loop {
        while count < width {
            bits = (bits << 8) | u32::from(input.next().await?.ok_or_else(|| input.error())?);
            count += 8;
        }
        count -= width;
        let code = u16::try_from((bits >> count) & ((1_u32 << width) - 1)).expect("12-bit code");
        if code == 256 {
            width = 9;
            next = 258;
            previous = None;
            continue;
        }
        if code == 257 {
            input.finish().await?;
            return Ok(());
        }
        if code > next || (code == next && previous.is_none()) {
            return Err(input.error().into());
        }
        let mut cursor = if code == next {
            previous.expect("checked previous")
        } else {
            code
        };
        while cursor >= 258 {
            admit(&work, location, 1)?;
            if cursor >= next {
                return Err(input.error().into());
            }
            stack
                .try_push(suffixes[usize::from(cursor)])
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            cursor = prefixes[usize::from(cursor)];
        }
        if cursor > 255 {
            return Err(input.error().into());
        }
        let first = u8::try_from(cursor).expect("literal code");
        input.put(output, first)?;
        while let Some(byte) = stack.pop() {
            input.put(output, byte)?;
        }
        if code == next {
            input.put(output, first)?;
        }
        if let Some(old) = previous
            && next < 4096
        {
            admit(&work, location, 1)?;
            prefixes[usize::from(next)] = old;
            suffixes[usize::from(next)] = first;
            next += 1;
            if width < 12 && next + u16::from(early) == 1_u16 << width {
                width += 1;
            }
        }
        previous = Some(code);
    }
}

async fn base85<S: RangeSource, W: Work>(
    input: &mut Input<'_, '_, S>,
    output: &mut OwnedVec<u8, W>,
) -> Result<(), ReadFailure<S::Error>> {
    let mut value = 0_u64;
    let mut digits = 0_u8;
    loop {
        let byte = input.next().await?.ok_or_else(|| input.error())?;
        if crate::bytes::is_space(byte) {
            continue;
        }
        if byte == b'~' {
            if input.next().await? != Some(b'>') || digits == 1 {
                return Err(input.error().into());
            }
            if digits != 0 {
                let count = digits - 1;
                for _ in digits..5 {
                    value = value * 85 + 84;
                }
                let decoded = u32::try_from(value)
                    .map_err(|_| input.error())?
                    .to_be_bytes();
                for &byte in &decoded[..usize::from(count)] {
                    input.put(output, byte)?;
                }
            }
            input.finish().await?;
            break;
        }
        if byte == b'z' {
            if digits != 0 {
                return Err(input.error().into());
            }
            for _ in 0..4 {
                input.put(output, 0)?;
            }
            continue;
        }
        if !(b'!'..=b'u').contains(&byte) {
            return Err(input.error().into());
        }
        value = value * 85 + u64::from(byte - b'!');
        digits += 1;
        if digits == 5 {
            for byte in u32::try_from(value)
                .map_err(|_| input.error())?
                .to_be_bytes()
            {
                input.put(output, byte)?;
            }
            value = 0;
            digits = 0;
        }
    }
    Ok(())
}

struct InflateBuffers<W: Work> {
    inflater: OwnedVec<miniz_oxide::inflate::core::DecompressorOxide, W>,
    scratch: OwnedVec<u8, W>,
}

fn inflate_buffers<W: Work>(
    work: &W,
    location: crate::source::Location,
) -> crate::Result<InflateBuffers<W>> {
    use miniz_oxide::inflate::core::DecompressorOxide;
    let mut inflater = work.vector();
    inflater.try_reserve_exact(1).map_err(|cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    })?;
    admit(
        work,
        location,
        core::mem::size_of::<DecompressorOxide>() as u64,
    )?;
    inflater
        .try_push(DecompressorOxide::new())
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    let mut scratch = work.vector();
    scratch.try_reserve_exact(32768).map_err(|cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    })?;
    for _ in 0..8 {
        scratch
            .try_extend_from_slice(&[0_u8; 4096])
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
    }
    Ok(InflateBuffers { inflater, scratch })
}

async fn flate<S: RangeSource, W: Work>(
    input: &mut Input<'_, '_, S>,
    output: &mut OwnedVec<u8, W>,
) -> Result<(), ReadFailure<S::Error>> {
    use miniz_oxide::inflate::{
        TINFLStatus,
        core::{decompress_with_limit, inflate_flags},
    };
    let work = input.reader.execution();
    let location = input.reader.location(input.at, 0);
    let InflateBuffers {
        mut inflater,
        mut scratch,
    } = inflate_buffers(&work, location)?;
    let mut chunk = [0_u8; 4096];
    let mut filled = 0;
    let mut consumed = 0;
    let mut output_at = 0;
    let mut block = true;
    loop {
        if consumed == filled {
            filled = 0;
            consumed = 0;
            while filled < chunk.len() {
                let Some(byte) = input.next().await? else {
                    break;
                };
                chunk[filled] = byte;
                filled += 1;
            }
        }
        // miniz 0.9.1 init_tree has three alphabets (288/32/19), at most
        // 15 bits per code, 1024 lookup slots and 576 tree slots per table.
        // STOP_ON_BLOCK_BOUNDARY bounds this setup to ONE block per admission.
        if block {
            admit(&work, location, 3 * (1024 + 576 + 288 * 16 + 32))?;
            block = false;
        }
        let allowance = 4096_usize.min(32768 - output_at).min(
            usize::try_from(input.reader.session().decoded_remaining().min(4096))
                .expect("bounded output allowance"),
        );
        output.try_reserve(allowance).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        admit(
            &work,
            location,
            (filled - consumed) as u64 * 16 + allowance as u64 * 16 + 1,
        )?;
        let mut flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY;
        if input.at < input.end {
            flags |= inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
        }
        let (status, used, written) = decompress_with_limit(
            &mut inflater[0],
            &chunk[consumed..filled],
            &mut scratch,
            output_at,
            allowance,
            flags,
        );
        // No source/provider callback or await occurs between the allowance
        // check and this commit. The decoder cannot change session counters.
        input.reader.session().decode(written as u64, location)?;
        consumed += used;
        output
            .try_extend_from_slice(&scratch[output_at..output_at + written])
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        output_at = (output_at + written) % 32768;
        match status {
            TINFLStatus::Done => {
                input.at -= (filled - consumed) as u64;
                input.finish().await?;
                return Ok(());
            }
            TINFLStatus::BlockBoundary => block = true,
            TINFLStatus::NeedsMoreInput if input.at < input.end && consumed == filled => {}
            TINFLStatus::HasMoreOutput if written != 0 => {}
            TINFLStatus::HasMoreOutput if allowance == 0 => {
                return Err(Error {
                    kind: ErrorKind::Limit(crate::error::Limit::Decoded),
                    location,
                }
                .into());
            }
            _ => return Err(input.error().into()),
        }
    }
}
