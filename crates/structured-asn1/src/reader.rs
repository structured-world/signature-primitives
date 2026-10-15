//! Reading elements in sequence, and descending into the constructed ones.
//!
//! Three invariants hold throughout. Nothing copies the document: elements
//! borrow it and carry the range they occupy. Nothing recurses: depth is
//! bounded by the caller's budget rather than by the stack. An element carries
//! no path; the path belongs to the reader that produced it.

use crate::error::{Error, ErrorCode, Limit, Path, Result};
use crate::length::{self, Encoding, Length};
use crate::limits::{Budget, BudgetView, Limits};
use crate::memory::{Memory, Work};
use crate::tag::{self, Tag, universal};
use crate::value::{self, BitString, Integer, Oid};

mod integer;
pub use integer::IntegerReading;

/// Holds the budget for one parse and hands out readers that share it.
#[derive(Debug)]
pub struct Parser {
    budget: Budget,
    encoding: Encoding,
}

impl Parser {
    /// A parser for one document, in one encoding, with one budget.
    #[must_use]
    pub fn new(encoding: Encoding, limits: Limits, memory: Memory) -> Self {
        Self {
            budget: Budget::new(limits, memory),
            encoding,
        }
    }

    /// A parser for DER, with the default budget.
    #[must_use]
    pub fn der(memory: Memory) -> Self {
        Self::new(Encoding::Der, Limits::default(), memory)
    }

    /// A parser that also accepts the BER forms CMS permits.
    #[must_use]
    pub fn ber(memory: Memory) -> Self {
        Self::new(Encoding::Ber, Limits::default(), memory)
    }

    /// The limits this parser was given.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.budget.limits()
    }

    /// The aggregate account shared with other parsers and retained results.
    ///
    /// `Limits.max_work` additionally bounds this parser's scanning, not later
    /// owned-result processing. Memory's cumulative work bounds the whole domain.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.budget.memory()
    }

    /// Borrows this session's cumulative work ceiling and a current account.
    ///
    /// This creates no reader, allocation or owning account clone. It allows
    /// schema scratch to keep the same local ceiling while a reader cursor
    /// advances. Selecting an aggregate account does not reset earlier work;
    /// existing retained capacity stays with its original storage owner.
    #[must_use]
    pub fn execution_in<'work>(
        &'work self,
        memory: &'work Memory,
    ) -> crate::memory::Execution<'work> {
        crate::memory::Execution::new(memory, BudgetView::root(&self.budget))
    }

    /// A reader over `data`, whose first byte sits at `base` in the document.
    ///
    /// `base` is what makes an error's offset and an element's span mean
    /// something to a caller holding a whole document while handing this parser
    /// a window into it.
    ///
    /// Refused when the end of `data` would not fit an offset. Checking that
    /// here is what lets every offset computed while reading be ordinary
    /// arithmetic: each is at most `base + data.len()`.
    pub fn read<'a>(&'a self, data: &'a [u8], base: u64) -> Result<Reader<'a>> {
        self.read_as(data, base, self.encoding)
    }

    /// A reader over `data` under a chosen encoding, sharing this parser's
    /// budget.
    ///
    /// For a window whose schema fixes its encoding regardless of what this
    /// parser was built for: the value of a certificate extension is DER even
    /// when the parser was made lenient for the envelope the certificate
    /// arrived in.
    pub fn read_as<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
    ) -> Result<Reader<'a>> {
        self.read_as_in(data, base, encoding, self.memory())
    }

    fn read_as_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        u64::try_from(data.len())
            .ok()
            .and_then(|length| base.checked_add(length))
            .ok_or_else(|| Error::new(ErrorCode::OffsetTooLarge, base, Path::default()))?;

        Ok(Reader {
            data,
            pos: 0,
            base,
            depth: 0,
            next_index: 0,
            path: Path::default(),
            encoding,
            parser: self,
            execution: execution.clone(),
            query: None,
        })
    }

    /// A reader over bytes another element carries as its value, one level
    /// below the reader that element was found in.
    ///
    /// For an encoding wrapped in a primitive, an octet string above all: a
    /// certificate extension's value, a signed message's content. `outer` is
    /// [`Reader::depth`] of the reader the carrying element came from. A
    /// reader made with [`Parser::read_as`] would count the wrapped structure
    /// from the top again, and a caller's depth ceiling would bound each
    /// wrapping rather than the document.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::LimitExceeded`] where the level is past the depth
    /// ceiling, and what [`Parser::read_as`] refuses.
    pub fn read_nested<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> Result<Reader<'a>> {
        self.read_nested_in(data, base, encoding, outer, self.memory())
    }

    /// Nested lazy reader using the current execution domain from creation.
    ///
    /// Original offsets, depth and this parser session's cumulative ceilings
    /// remain in force. New storage and deferred work use `execution`.
    pub fn read_nested_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        self.read_depth_in(data, base, encoding, outer.checked_add(1), execution)
    }

    pub(crate) fn read_source_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        self.read_depth_in(data, base, encoding, Some(depth), execution)
    }

    fn read_depth_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        depth: Option<u32>,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        let mut reader = self.read_as_in(data, base, encoding, execution)?;
        let depth = depth.ok_or_else(|| {
            Error::new(
                ErrorCode::LimitExceeded(Limit::Depth),
                base,
                Path::default(),
            )
        })?;
        self.budget
            .depth(depth)
            .map_err(|limit| Error::new(ErrorCode::LimitExceeded(limit), base, Path::default()))?;
        reader.depth = depth;
        Ok(reader)
    }

    /// Reads an original source window under the current query's ceilings.
    ///
    /// The original parser, encoding, offsets and inherited depth remain the
    /// source's. Its cumulative limits and the query operation's limits both
    /// apply before work; the current aggregate account is charged once.
    /// Further foreign-source transitions retain the same operation owner,
    /// rather than accumulating a chain of unrelated source budgets.
    pub fn read_nested_query_in<'a>(
        &'a self,
        query: &Reader<'a>,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> Result<Reader<'a>> {
        self.read_nested_operation_in(
            data,
            base,
            encoding,
            outer,
            query.budget().operation(),
            query.memory(),
        )
    }

    /// Reads an original source window at its actual depth under a current query.
    ///
    /// A fresh ASN.1 document carried by another format, such as XML base64,
    /// starts at depth zero: that carrier is not an ASN.1 enclosing element.
    /// Existing nested windows retain their actual inherited depth instead.
    /// Source and current-operation cumulative work/depth ceilings both apply;
    /// storage and new work use the current account, charged once. This does
    /// not create a parser or reset either session's prior work. The caller
    /// supplies the original source provenance, as for `read_nested_query_in`.
    pub fn read_query_in<'a>(
        &'a self,
        query: &Reader<'a>,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> Result<Reader<'a>> {
        self.read_query_budget_in(
            data,
            base,
            encoding,
            depth,
            query.budget().operation(),
            query.memory(),
        )
    }

    pub(crate) fn read_nested_operation_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
        operation: &'a Budget,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        let depth = nested_depth(outer, base)?;
        self.read_query_budget_in(data, base, encoding, depth, operation, execution)
    }

    pub(crate) fn read_query_budget_in<'a>(
        &'a self,
        data: &'a [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
        operation: &'a Budget,
        execution: &Memory,
    ) -> Result<Reader<'a>> {
        let budget = BudgetView::query(&self.budget, operation);
        budget
            .depth(depth)
            .map_err(|limit| Error::new(ErrorCode::LimitExceeded(limit), base, Path::default()))?;
        budget
            .work_in(1, execution)
            .map_err(|limit| Error::new(ErrorCode::LimitExceeded(limit), base, Path::default()))?;
        let mut reader = self.read_as_in(data, base, encoding, execution)?;
        reader.query = Some(operation);
        reader.depth = depth;
        Ok(reader)
    }
}

fn nested_depth(outer: u32, base: u64) -> Result<u32> {
    outer.checked_add(1).ok_or_else(|| {
        Error::new(
            ErrorCode::LimitExceeded(Limit::Depth),
            base,
            Path::default(),
        )
    })
}

/// Where in a document one run of bytes sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Offset of the first byte, counted in the whole document.
    pub start: u64,
    /// How many bytes.
    pub length: u64,
}

impl Span {
    /// The offset just past the last byte.
    ///
    /// Ordinary arithmetic: a span is only ever built by a reader, which
    /// refuses a window whose end does not fit an offset, so `start + length`
    /// has already been shown to fit.
    #[must_use]
    pub fn end(self) -> u64 {
        self.start + self.length
    }
}

/// One element, as it was found.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    tag: Tag,
    contents: &'a [u8],
    bytes: &'a [u8],
    contents_span: Span,
    whole: Span,
    indefinite: bool,
    index: u32,
}

impl<'a> Element<'a> {
    /// What kind of element this is.
    #[must_use]
    pub fn tag(self) -> Tag {
        self.tag
    }

    /// The contents, borrowed from the document.
    ///
    /// For an indefinite-length element this is everything up to but not
    /// including the end-of-contents marker.
    #[must_use]
    pub fn contents(self) -> &'a [u8] {
        self.contents
    }

    /// The whole element as it arrived, header included.
    ///
    /// What a signature is computed over wherever a schema says the signature
    /// covers an element as encoded, and what identity is compared on wherever
    /// a schema says two structures are the same one when their bytes are.
    /// Handing these back rather than re-encoding what was understood is the
    /// difference between checking a signature over the document somebody was
    /// sent and checking it over this parser's opinion of that document.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Where the contents sit in the document.
    #[must_use]
    pub fn contents_span(self) -> Span {
        self.contents_span
    }

    /// Where the whole element sits, header included.
    ///
    /// This is the range a signature is computed over wherever a schema says
    /// the signature covers an element as encoded.
    #[must_use]
    pub fn span(self) -> Span {
        self.whole
    }

    /// Whether the length was written in the indefinite form.
    #[must_use]
    pub fn is_indefinite(self) -> bool {
        self.indefinite
    }

    /// Its position among the elements of the container it was read from.
    #[must_use]
    pub fn index(self) -> u32 {
        self.index
    }
}

/// Reads the elements of one container, in order.
///
/// Cloning one keeps where it is and how deep it sits, so a caller that has to
/// come back to a container later can put the reader aside rather than start
/// again from the document and count the nesting as one.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,
    depth: u32,
    next_index: u32,
    path: Path,
    encoding: Encoding,
    parser: &'a Parser,
    execution: Memory,
    query: Option<&'a Budget>,
}

impl<'a> Reader<'a> {
    /// Current domain for deferred work, copies and new storage.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        &self.execution
    }

    /// Borrows both the current account and original cumulative work ceiling.
    ///
    /// Schema scratch must use this boundary when work belongs to the parse:
    /// allocator growth, copying and sorting then retain the session ceiling
    /// as well as the aggregate account. Independently retained results use
    /// [`Self::memory`] instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, memory::{Memory, MemoryAccount, Work}};
    /// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1024, 1024))));
    /// let reader = parser.read(&[], 900).unwrap();
    /// let mut scratch = reader.execution().vector();
    /// scratch.try_push(7_u8)?;
    /// assert_eq!(&*scratch, &[7]);
    /// # Ok::<(), structured_asn1::memory::MemoryError>(())
    /// ```
    #[must_use]
    pub fn execution(&self) -> crate::memory::Execution<'_> {
        crate::memory::Execution::new(self.memory(), self.budget())
    }

    /// Borrows the source/query budgets independently of this reader cursor.
    ///
    /// Supply the operation account explicitly so scratch can keep the same
    /// admission while the cursor advances. This creates no allocation or
    /// owning account clone and cannot discard an inherited query ceiling.
    #[must_use]
    pub fn execution_in<'work>(&self, memory: &'work Memory) -> crate::memory::Execution<'work>
    where
        'a: 'work,
    {
        crate::memory::Execution::new(memory, self.budget())
    }

    /// Selects the domain for subsequent execution without moving existing
    /// storage charges. Offsets, depth and parser-session cumulative limits
    /// remain unchanged; a new domain does not reset that session ceiling.
    #[must_use]
    pub fn with_execution(mut self, execution: &Memory) -> Self {
        self.execution = execution.clone();
        self
    }

    /// Moves this cursor into a current query without copying its retained path.
    /// Original parser, data, offsets and depth remain unchanged. Both source
    /// and operation admission apply before changing execution; existing path
    /// capacity keeps its original owner until actually freed.
    pub fn with_query<'query>(self, query: &Reader<'query>) -> Result<Reader<'query>>
    where
        'a: 'query,
    {
        let operation = query.budget().operation();
        let budget = BudgetView::query(&self.parser.budget, operation);
        budget.depth(self.depth).map_err(|limit| {
            Error::new(
                ErrorCode::LimitExceeded(limit),
                self.offset(),
                Path::default(),
            )
        })?;
        budget.work_in(1, query.memory()).map_err(|limit| {
            Error::new(
                ErrorCode::LimitExceeded(limit),
                self.offset(),
                Path::default(),
            )
        })?;
        Ok(Reader {
            data: self.data,
            pos: self.pos,
            base: self.base,
            depth: self.depth,
            next_index: self.next_index,
            path: self.path,
            encoding: self.encoding,
            parser: self.parser,
            execution: query.memory().clone(),
            query: Some(operation),
        })
    }

    /// Copies the reader position and diagnostic path fallibly in the same domain.
    pub fn try_clone(&self) -> Result<Self> {
        self.admit_path(0)
            .map_err(|reason| Error::resource(reason, self.offset()))?;
        Ok(Self {
            data: self.data,
            pos: self.pos,
            base: self.base,
            depth: self.depth,
            next_index: self.next_index,
            path: self
                .path
                .try_copy_in(self.memory())
                .map_err(|reason| Error::resource(reason, self.offset()))?,
            encoding: self.encoding,
            parser: self.parser,
            execution: self.execution.clone(),
            query: self.query,
        })
    }
    /// Whether every element here has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Original parser, whose session ceilings remain cumulative across
    /// deferred reads. Use [`Self::memory`] for the current execution domain;
    /// the parser's storage domain may belong to an earlier operation.
    #[must_use]
    pub fn parser(&self) -> &'a Parser {
        self.parser
    }

    /// The shared budget, by way of the parser.
    fn budget(&self) -> BudgetView<'a> {
        match self.query {
            Some(operation) => BudgetView::query(&self.parser.budget, operation),
            None => BudgetView::root(&self.parser.budget),
        }
    }

    /// Charges caller-side scanning to the shared work budget.
    ///
    /// For a schema layer that walks an element's contents itself, text
    /// validation and named-bit walks among them: the walk costs what the
    /// bytes cost, and a caller bounding work must see that cost on the
    /// same meter the reads use.
    pub fn charge(&self, amount: u64) -> Result<()> {
        self.budget()
            .work_in(amount, self.memory())
            .map_err(|limit| self.fail_at(ErrorCode::LimitExceeded(limit), self.offset()))
    }

    /// How many containers deep this reader sits, counted as the depth
    /// ceiling counts it. What [`Parser::read_nested`] is given for a value
    /// found here.
    #[must_use]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// The offset of the next unread byte, in the document.
    ///
    /// Ordinary arithmetic, because `pos` never exceeds the length of `data`
    /// and `base` plus that length was shown to fit when this reader was made.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.base + self.pos as u64
    }

    /// The bytes not yet read.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    /// The path to this container, for a caller building its own diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which encoding this reader accepts, for a schema whose own rules
    /// differ between the two, such as the ordering DER requires of a set.
    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// A reader over an element's own bytes, header included, under a chosen
    /// encoding.
    ///
    /// For a structure whose schema fixes its encoding regardless of the
    /// container's: a certificate is DER even when the envelope carrying it
    /// is BER, and reading it with the container's leniency would let
    /// spellings survive that the certificate's own rules refuse. The
    /// element's header is read again under the chosen rules, so a header
    /// only the lenient encoding accepts is refused too. Offsets stay offsets
    /// in the document and the budget stays the shared one.
    pub fn reread(&self, element: &Element<'a>, encoding: Encoding) -> Result<Reader<'a>> {
        self.admit_path(0)
            .map_err(|reason| Error::resource(reason, element.whole.start))?;
        Ok(Reader {
            data: element.bytes,
            pos: 0,
            base: element.whole.start,
            depth: self.depth,
            next_index: 0,
            path: self
                .path
                .try_copy_in(self.memory())
                .map_err(|reason| Error::resource(reason, element.whole.start))?,
            encoding,
            parser: self.parser,
            execution: self.execution.clone(),
            query: self.query,
        })
    }

    /// Reads the next element, or `None` at the end of this container.
    pub fn next_element(&mut self) -> Result<Option<Element<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }

        let header = self.read_header()?;

        // An end-of-contents marker belongs to whichever reader opened the
        // indefinite element, and that reader stops before handing it out.
        // Meeting one here means it closes something never opened.
        if header.tag.is_end_of_contents() {
            return Err(self.fail_at(ErrorCode::MalformedEndOfContents, header.start));
        }

        self.finish(header).map(Some)
    }

    /// Reads the next element and requires it to carry `tag`.
    pub fn expect(&mut self, tag: Tag) -> Result<Element<'a>> {
        let offset = self.offset();
        match self.next_element()? {
            Some(element) if element.tag == tag => Ok(element),
            // Named under the element that carried the wrong tag: it was read,
            // so it has an index, and the fault is that element rather than
            // the container holding it. Nothing was read in the other arm, so
            // there is no element to name and the container is the answer.
            Some(element) => Err(self.fail_under(ErrorCode::UnexpectedTag, &element)),
            None => Err(self.fail_at(ErrorCode::UnexpectedEnd, offset)),
        }
    }

    /// Reads and discards the next element, whatever it is.
    ///
    /// This is how a schema layer steps over an extension it does not know: the
    /// element is skipped within its declared length, so an unknown tag costs
    /// what a known one costs and cannot make the reader wander.
    pub fn skip(&mut self) -> Result<bool> {
        Ok(self.next_element()?.is_some())
    }

    /// A reader over the contents of a constructed element read from here.
    ///
    /// Refused for a primitive element: its contents are a value rather than
    /// further elements, and reading them as elements is how a parser is
    /// talked into finding structure inside an octet string that nobody put
    /// there.
    pub fn enter(&self, element: &Element<'a>) -> Result<Reader<'a>> {
        if !element.tag.is_constructed() {
            return Err(self.fail_under(ErrorCode::WrongConstruction, element));
        }

        // Check depth before copying/growing a path: a rejected descent must
        // not perform the allocation it was supposed to prevent.
        let depth = self.depth.checked_add(1).ok_or_else(|| {
            self.fail_under_at(
                ErrorCode::LimitExceeded(Limit::Depth),
                element,
                element.contents_span.start,
            )
        })?;
        self.budget().depth(depth).map_err(|limit| {
            self.fail_under_at(
                ErrorCode::LimitExceeded(limit),
                element,
                element.contents_span.start,
            )
        })?;
        self.admit_path(1)
            .map_err(|reason| Error::resource(reason, element.contents_span.start))?;
        let mut path = self
            .path
            .try_copy_in(self.memory())
            .map_err(|reason| Error::resource(reason, element.contents_span.start))?;
        path.push(self.memory(), element.index)
            .map_err(|reason| Error::resource(reason, element.contents_span.start))?;

        Ok(Reader {
            data: element.contents,
            pos: 0,
            base: element.contents_span.start,
            depth,
            next_index: 0,
            path,
            encoding: self.encoding,
            parser: self.parser,
            execution: self.execution.clone(),
            query: self.query,
        })
    }

    /// Reads an element's contents as an object identifier.
    pub fn oid(&self, element: &Element<'a>) -> Result<Oid<'a>> {
        self.primitive(element)?;
        // The arcs are scanned byte by byte, so the scan is charged to the
        // shared work budget like the headers are: one long identifier must
        // not cost time the caller's limits never metered.
        self.budget()
            .work_in(element.contents.len() as u64, self.memory())
            .map_err(|limit| self.fail_under(ErrorCode::LimitExceeded(limit), element))?;
        value::oid(element.contents).map_err(|code| self.fail_under(code, element))
    }

    /// Reads an element's contents as an integer.
    pub fn integer(&self, element: &Element<'a>) -> Result<Integer<'a>> {
        self.primitive(element)?;
        value::integer(element.contents).map_err(|code| self.fail_under(code, element))
    }

    /// Reads an element's contents as a bit string.
    ///
    /// The segmented form BER allows for a constructed bit string is refused:
    /// every bit string this product reads is covered by a signature computed
    /// over the bytes, where one value with two spellings is one value too
    /// many.
    pub fn bit_string(&self, element: &Element<'a>) -> Result<BitString<'a>> {
        self.primitive(element)?;
        value::bit_string(element.contents, self.encoding)
            .map_err(|code| self.fail_under(code, element))
    }

    /// Reads an element's contents as a boolean.
    pub fn boolean(&self, element: &Element<'a>) -> Result<bool> {
        self.primitive(element)?;
        value::boolean(element.contents, self.encoding)
            .map_err(|code| self.fail_under(code, element))
    }

    /// Reads an element's contents as a null, which has none.
    pub fn null(&self, element: &Element<'a>) -> Result<()> {
        self.primitive(element)?;
        value::null(element.contents).map_err(|code| self.fail_under(code, element))
    }

    /// Reads an element's contents as a real, and answers only whether they
    /// are a value of the type.
    ///
    /// The number itself is not read: no schema this product parses has a
    /// real in it, and one arrives only inside a value preserved for
    /// somebody else, who is promised octets that are what they claim.
    pub fn real(&self, element: &Element<'a>) -> Result<()> {
        self.primitive(element)?;
        // The decimal form's field is walked digit by digit, so the scan is
        // charged to the shared work budget like the headers are: one long
        // value must not cost time the caller's limits never metered.
        self.budget()
            .work_in(element.contents.len() as u64, self.memory())
            .map_err(|limit| self.fail_under(ErrorCode::LimitExceeded(limit), element))?;
        value::real(element.contents, self.encoding).map_err(|code| self.fail_under(code, element))
    }

    /// Reads the next element as an object identifier.
    pub fn read_oid(&mut self) -> Result<Oid<'a>> {
        let element = self.expect(Tag::primitive(universal::OID))?;
        self.oid(&element)
    }

    /// Reads the next element as an integer.
    pub fn read_integer(&mut self) -> Result<Integer<'a>> {
        let element = self.expect(Tag::primitive(universal::INTEGER))?;
        self.integer(&element)
    }

    /// Reads the next element as a bit string.
    pub fn read_bit_string(&mut self) -> Result<BitString<'a>> {
        let element = self.expect(Tag::primitive(universal::BIT_STRING))?;
        self.bit_string(&element)
    }

    /// Reads the next element as a boolean.
    pub fn read_boolean(&mut self) -> Result<bool> {
        let element = self.expect(Tag::primitive(universal::BOOLEAN))?;
        self.boolean(&element)
    }

    fn primitive(&self, element: &Element<'a>) -> Result<()> {
        if element.tag.is_constructed() {
            return Err(self.fail_under(ErrorCode::WrongConstruction, element));
        }
        Ok(())
    }

    /// An error naming an element read from this container.
    #[must_use]
    pub fn fail_under(&self, code: ErrorCode, element: &Element<'a>) -> Error {
        self.fail_under_at(code, element, element.whole.start)
    }

    fn fail_under_at(&self, code: ErrorCode, element: &Element<'a>, offset: u64) -> Error {
        match self.path_into(element.index, &[]) {
            Ok(path) => Error::new(code, offset, path),
            Err(reason) => Error::resource(reason, offset),
        }
    }

    fn fail_at(&self, code: ErrorCode, offset: u64) -> Error {
        if let Err(reason) = self.admit_path(0) {
            return Error::resource(reason, offset);
        }
        match self.path.try_copy_in(self.memory()) {
            Ok(path) => Error::new(code, offset, path),
            Err(reason) => Error::resource(reason, offset),
        }
    }

    fn read_header(&mut self) -> Result<Header> {
        let start = self.offset();
        self.budget()
            .element()
            .map_err(|limit| self.fail_at(ErrorCode::LimitExceeded(limit), start))?;

        let rest = &self.data[self.pos..];
        header_at(rest, self.encoding, start, self.budget(), self.memory())
            .map_err(|(code, at)| self.fail_at(code, at))
    }

    fn finish(&mut self, header: Header) -> Result<Element<'a>> {
        let contents_at = self.pos + header.len;
        let contents_start = header.start + header.len as u64;

        let (contents_len, total_len, indefinite) = match header.length {
            Length::Definite(length) => {
                self.budget()
                    .length(length)
                    .map_err(|limit| self.fail_at(ErrorCode::LimitExceeded(limit), header.start))?;

                let length = usize::try_from(length)
                    .map_err(|_| self.fail_at(ErrorCode::LengthTooLarge, header.start))?;

                let end = contents_at
                    .checked_add(length)
                    .ok_or_else(|| self.fail_at(ErrorCode::LengthTooLarge, header.start))?;

                if end > self.data.len() {
                    return Err(self.fail_at(ErrorCode::UnexpectedEnd, header.start));
                }

                (length, header.len + length, false)
            }
            Length::Indefinite => {
                if !header.tag.is_constructed() {
                    return Err(self.fail_at(ErrorCode::WrongConstruction, header.start));
                }
                let contents_len =
                    self.scan_to_end_of_contents(contents_at, contents_start, self.next_index)?;

                // An indefinite element declares no length, so nothing has held
                // it to one yet. Its size is what the scan just measured, and a
                // container assembled from many small children would otherwise
                // pass a budget its declared-length siblings could not.
                self.budget()
                    .length(contents_len as u64)
                    .map_err(|limit| self.fail_at(ErrorCode::LimitExceeded(limit), header.start))?;

                // Two further bytes for the end-of-contents marker, which is
                // exactly two: the scan refuses any other spelling of it.
                (contents_len, header.len + contents_len + 2, true)
            }
        };

        let contents = &self.data[contents_at..contents_at + contents_len];
        // The element as it arrived, header and any end-of-contents marker
        // included. Both bounds were established above, so the slice exists.
        let bytes = &self.data[self.pos..self.pos + total_len];
        let index = self.next_index;

        self.pos += total_len;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| self.fail_at(ErrorCode::LimitExceeded(Limit::Elements), header.start))?;

        Ok(Element {
            tag: header.tag,
            contents,
            bytes,
            contents_span: Span {
                start: contents_start,
                length: contents_len as u64,
            },
            whole: Span {
                start: header.start,
                length: total_len as u64,
            },
            indefinite,
            index,
        })
    }

    /// Finds where an indefinite-length element's contents end.
    ///
    /// Walks the elements inside it with an explicit stack rather than by
    /// recursing, so a document nested a million deep is refused by the depth
    /// budget instead of ending the process.
    ///
    /// A measurement, not a reading: the elements it steps over are charged to
    /// the element budget later, where they are actually read. This costs
    /// work.
    fn scan_to_end_of_contents(
        &self,
        from: usize,
        from_offset: u64,
        own_index: u32,
    ) -> Result<usize> {
        let mut cursor = from;
        let mut offset = from_offset;

        // The index of the next element at each level entered so far, so an
        // error inside nested contents names where it is rather than naming the
        // container the scan started from.
        let mut trail = self.execution().vector::<u32>();
        let mut index: u32 = 0;

        // Assembled only where an error is returned: building it per header is
        // work proportional to depth times children, which the work budget
        // does not count.
        let fail = |code: ErrorCode, at: u64, trail: &[u32]| match self.path_into(own_index, trail)
        {
            Ok(path) => Error::new(code, at, path),
            Err(reason) => Error::resource(reason, at),
        };
        let spent =
            |limit: Limit, at: u64, trail: &[u32]| fail(ErrorCode::LimitExceeded(limit), at, trail);

        loop {
            let depth = u32::try_from(trail.len())
                .ok()
                .and_then(|nested| self.depth.checked_add(nested))
                .and_then(|depth| depth.checked_add(1))
                .ok_or_else(|| spent(Limit::Depth, offset, &trail))?;
            self.budget()
                .depth(depth)
                .map_err(|limit| spent(limit, offset, &trail))?;

            let rest = self
                .data
                .get(cursor..)
                .filter(|rest| !rest.is_empty())
                .ok_or_else(|| fail(ErrorCode::UnterminatedContents, from_offset, &trail))?;

            let header = header_at(rest, self.encoding, offset, self.budget(), self.memory())
                .map_err(|(code, at)| fail(code, at, &trail))?;
            let inner_tag = header.tag;
            let inner_length = header.length;
            let header_len = header.len;

            if inner_tag.is_end_of_contents() {
                // Exactly two octets. A zero length written the long way reads
                // as a zero length, and taking it for the marker would end the
                // element short and leave the rest of the marker to be read as
                // another element.
                if header_len != 2 || !matches!(inner_length, Length::Definite(0)) {
                    return Err(fail(ErrorCode::MalformedEndOfContents, offset, &trail));
                }
                match trail.pop() {
                    // This one closes the element the scan was opened for.
                    None => return Ok(cursor - from),
                    // Back at the level that container sat on, with it read.
                    Some(outer) => {
                        index = outer
                            .checked_add(1)
                            .ok_or_else(|| spent(Limit::Elements, offset, &trail))?;
                    }
                }
                cursor += header_len;
                offset += header_len as u64;
                continue;
            }

            let step = match inner_length {
                Length::Indefinite => {
                    if !inner_tag.is_constructed() {
                        return Err(fail(ErrorCode::WrongConstruction, offset, &trail));
                    }
                    // The index this container itself sits at, so a fault
                    // inside it is reported under it rather than beside it.
                    trail
                        .try_push(index)
                        .map_err(|reason| Error::resource(reason, offset))?;
                    index = 0;
                    header_len
                }
                Length::Definite(length) => {
                    self.budget()
                        .length(length)
                        .map_err(|limit| spent(limit, offset, &trail))?;
                    let length = usize::try_from(length)
                        .map_err(|_| fail(ErrorCode::LengthTooLarge, offset, &trail))?;
                    index = index
                        .checked_add(1)
                        .ok_or_else(|| spent(Limit::Elements, offset, &trail))?;
                    header_len
                        .checked_add(length)
                        .ok_or_else(|| fail(ErrorCode::LengthTooLarge, offset, &trail))?
                }
            };

            cursor = cursor
                .checked_add(step)
                .ok_or_else(|| fail(ErrorCode::LengthTooLarge, offset, &trail))?;
            if cursor > self.data.len() {
                return Err(fail(ErrorCode::UnexpectedEnd, offset, &trail));
            }
            offset += step as u64;
        }
    }

    /// The path to a point inside an element of this container: this
    /// container's path, the element's own index, then the index of each
    /// nested container entered on the way.
    fn path_into(
        &self,
        own_index: u32,
        trail: &[u32],
    ) -> core::result::Result<Path, crate::memory::MemoryError> {
        let additional = trail
            .len()
            .checked_add(1)
            .ok_or(crate::memory::MemoryError::WorkExceeded)?;
        self.admit_path(additional)?;
        let mut path = self.path.try_copy_in(self.memory())?;
        path.push(self.memory(), own_index)?;
        for index in trail {
            path.push(self.memory(), *index)?;
        }
        Ok(path)
    }

    fn admit_path(
        &self,
        additional: usize,
    ) -> core::result::Result<(), crate::memory::MemoryError> {
        let work = self.path.copy_work(additional)?;
        self.budget()
            .local_work(work)
            .map_err(|_| crate::memory::MemoryError::WorkExceeded)
    }
}

#[derive(Clone, Copy)]
struct Header {
    tag: Tag,
    length: Length,
    start: u64,
    len: usize,
}

/// Both ordinary parsing and indefinite scans use the same pre-admission path.
fn header_at(
    input: &[u8],
    encoding: Encoding,
    start: u64,
    budget: BudgetView<'_>,
    execution: &Memory,
) -> core::result::Result<Header, (ErrorCode, u64)> {
    // Common short headers use one aggregate atomic admission for both bytes.
    // Extra high-tag octets and long lengths spend only before they are examined.
    budget
        .work_in(2, execution)
        .map_err(|limit| (ErrorCode::LimitExceeded(limit), start))?;
    let mut credit = 2;
    let mut charge = |amount: u64| {
        if amount <= credit {
            credit -= amount;
            return Ok(());
        }
        let additional = amount - credit;
        credit = 0;
        budget
            .work_in(additional, execution)
            .map_err(ErrorCode::LimitExceeded)
    };
    let (tag, tag_len) = tag::read_accounted(input, start, &mut charge)?;
    let (length, length_len) = length::read_accounted(
        &input[tag_len..],
        encoding,
        start + tag_len as u64,
        &mut charge,
    )?;
    Ok(Header {
        tag,
        length,
        start,
        len: tag_len + length_len,
    })
}

#[cfg(test)]
mod tests;
