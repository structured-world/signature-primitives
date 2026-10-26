use super::{FIELD, required};
use crate::AlgorithmIdentifier;
use crate::error::{CallbackError, CallbackResult, Located};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;
use structured_asn1::{Element, Parser, ScopedReader, Span, Tag, universal};

#[derive(Debug, Clone, Copy)]
enum Chunk<'a> {
    Empty,
    Header { bytes: [u8; 11], len: usize },
    Original { bytes: &'a [u8], at: u64 },
}

/// Exact alternative signed input. Only modified DER framing is synthesized;
/// every payload is borrowed from its original source. Construction and replay
/// retain the producing ceiling and current Work, without a whole-input copy.
/// Certificate/CRL inputs omit the native algorithm and alternative value;
/// requests omit only the alternative-value attribute.
#[derive(Debug)]
pub struct Preimage<'a> {
    chunks: [Chunk<'a>; 7],
    length: u64,
    parser: &'a Parser,
    context: Span,
}
impl Preimage<'_> {
    /// Total DER stream length, with checked arithmetic during preparation.
    #[must_use]
    pub fn encoded_len(&self) -> u64 {
        self.length
    }
    /// Original enclosing TBS/CRI range, not a physical span of generated DER.
    #[must_use]
    pub fn context(&self) -> Span {
        self.context
    }

    /// Visit every chunk in order, stopping on the first original cause.
    /// `None` marks generated DER framing, never an invented source offset.
    /// Admit input scans, copies and backend work through the supplied execution.
    /// The short header borrow cannot escape the visitor.
    ///
    /// ```compile_fail
    /// use structured_asn1::memory::Memory;
    /// use structured_pkix::hybrid::Preimage;
    /// fn escape<'a>(input: &Preimage<'a>, work: &Memory) -> &'a [u8] {
    ///     let mut saved: &'a [u8] = &[];
    ///     input.visit(work, |bytes, _, _| {
    ///         saved = bytes;
    ///         Ok::<(), core::convert::Infallible>(())
    ///     }).unwrap();
    ///     saved
    /// }
    /// ```
    pub fn visit<W: Work, E>(
        &self,
        work: &W,
        mut visitor: impl FnMut(
            &[u8],
            Option<Span>,
            &structured_asn1::memory::Execution<'_>,
        ) -> core::result::Result<(), E>,
    ) -> CallbackResult<(), E> {
        let execution = work.execution_for(self.parser);
        for chunk in &self.chunks {
            let (bytes, span) = match chunk {
                Chunk::Empty => continue,
                Chunk::Header { bytes, len } => (&bytes[..*len], None),
                Chunk::Original { bytes, at } => (
                    *bytes,
                    Some(Span {
                        start: *at,
                        length: bytes.len() as u64,
                    }),
                ),
            };
            execution
                .charge_work(1)
                .map_err(|e| Error::resource(e, FIELD, self.context.start))?;
            visitor(bytes, span, &execution).map_err(CallbackError::Callback)?;
        }
        Ok(())
    }
}

fn header(tag: u8, length: u64) -> Chunk<'static> {
    let mut bytes = [0; 11];
    bytes[0] = tag;
    let length = structured_asn1::length::DerLength::new(length);
    let width = length.as_bytes().len();
    bytes[1..=width].copy_from_slice(length.as_bytes());
    Chunk::Header {
        bytes,
        len: 1 + width,
    }
}
fn width(chunk: Chunk<'_>) -> u64 {
    match chunk {
        Chunk::Empty => 0,
        Chunk::Header { len, .. } => len as u64,
        Chunk::Original { bytes, .. } => bytes.len() as u64,
    }
}
fn checked_add(left: u64, right: u64, at: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| Error::new(ErrorCode::ValueTooLarge, FIELD, at))
}
fn portion(element: Element<'_>, start: u64, end: u64) -> Result<Chunk<'_>> {
    let contents = element.contents_span();
    if start < contents.start || end < start || end > contents.end() {
        return Err(Error::new(ErrorCode::ForeignReader, FIELD, start));
    }
    if start == end {
        return Ok(Chunk::Empty);
    }
    let begin = usize::try_from(start - contents.start)
        .map_err(|_| Error::new(ErrorCode::ValueTooLarge, FIELD, start))?;
    let length = usize::try_from(end - start)
        .map_err(|_| Error::new(ErrorCode::ValueTooLarge, FIELD, start))?;
    Ok(Chunk::Original {
        bytes: &element.contents()[begin..begin + length],
        at: start,
    })
}

pub(super) fn extensions<'a>(
    mut reader: ScopedReader<'a, '_>,
    native: AlgorithmIdentifier<'a>,
    tag: u32,
    remove: Span,
) -> Result<Preimage<'a>> {
    // X.509(2019)§§7.2.2/7.10.3 omit the native signature component AND
    // altSignatureValue. Only their ancestor lengths change in original DER.
    // https://www.itu.int/rec/T-REC-X.509-201910-I/en
    let tbs = required(&mut reader, Tag::constructed(universal::SEQUENCE))?;
    super::components::end(&reader)?;
    let mut inside = reader.enter(&tbs).field(FIELD)?;
    let mut wrapper = None;
    while let Some(element) = inside.next_element().field(FIELD)? {
        if element.tag() == Tag::context(true, tag) {
            wrapper = Some(element);
        }
    }
    let wrapper =
        wrapper.ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, tbs.span().start))?;
    let mut outer = inside.enter(&wrapper).field(FIELD)?;
    let sequence = required(&mut outer, Tag::constructed(universal::SEQUENCE))?;
    super::components::end(&outer)?;
    let native = Span {
        start: native.offset(),
        length: native.as_bytes().len() as u64,
    };
    build(&reader, tbs, wrapper, sequence, Some(native), remove, true)
}

pub(super) fn request<'a>(
    reader: &ScopedReader<'a, '_>,
    cri: Element<'a>,
    attributes: Element<'a>,
    remove: Span,
) -> Result<Preimage<'a>> {
    build(reader, cri, attributes, attributes, None, remove, false)
}

fn build<'a>(
    reader: &ScopedReader<'a, '_>,
    root: Element<'a>,
    wrapper: Element<'a>,
    members: Element<'a>,
    native: Option<Span>,
    remove: Span,
    explicit: bool,
) -> Result<Preimage<'a>> {
    reader.charge(64).field(FIELD)?;
    if wrapper.span().end() != root.contents_span().end() {
        return Err(Error::new(
            ErrorCode::TrailingData,
            FIELD,
            wrapper.span().end(),
        ));
    }
    let mut chunks = [Chunk::Empty; 7];
    let start = root.contents_span().start;
    match native {
        Some(native) => {
            chunks[1] = portion(root, start, native.start)?;
            chunks[2] = portion(root, native.end(), wrapper.span().start)?;
        }
        None => chunks[1] = portion(root, start, wrapper.span().start)?,
    }
    chunks[5] = portion(members, members.contents_span().start, remove.start)?;
    chunks[6] = portion(members, remove.end(), members.contents_span().end())?;
    let at = root.span().start;
    let kept = checked_add(width(chunks[5]), width(chunks[6]), at)?;
    if explicit {
        chunks[4] = header(48, kept);
        chunks[3] = header(
            if wrapper.tag() == Tag::context(true, 3) {
                0xa3
            } else {
                0xa0
            },
            checked_add(width(chunks[4]), kept, at)?,
        );
    } else {
        chunks[3] = header(0xa0, kept);
    }
    let mut length = 0;
    for chunk in &chunks[1..] {
        length = checked_add(length, width(*chunk), at)?;
    }
    chunks[0] = header(48, length);
    length = checked_add(length, width(chunks[0]), at)?;
    Ok(Preimage {
        chunks,
        length,
        parser: reader.parser(),
        context: root.span(),
    })
}
