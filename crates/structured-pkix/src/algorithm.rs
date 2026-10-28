//! Which algorithm, and the parameters that go with it.
//!
//! The identifier is kept as it was encoded and is not interpreted here. What
//! may be verified with a key, and how, belongs to the algorithm registry; this
//! layer's job is to hand that registry exactly what the certificate said,
//! including parameters it does not understand.

use crate::error::{Error, ErrorCode, Located, Result};
use core::num::NonZeroUsize;
use structured_asn1::memory::{Memory, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, ScopedReader, Span, Tag, universal};

pub mod digest;
pub mod ml_dsa;
pub mod pss;
pub mod signature;

/// An algorithm and its parameters, as the certificate wrote them.
#[derive(Debug, Clone, Copy)]
pub struct AlgorithmIdentifier<'a> {
    algorithm: Oid<'a>,
    // A parameter follows the OID, so its relative start is nonzero. It is
    // the last schema component; only an indefinite root's EOC follows it.
    parameter_start: Option<NonZeroUsize>,
    null_parameter: bool,
    der: &'a [u8],
    offset: u64,
    field: &'static str,
    parser: &'a Parser,
    outer: u32,
    encoding: Encoding,
    indefinite: bool,
}

/// Borrowed producing execution, without retaining an algorithm, parser
/// input buffer or account owner. This is not a document/value identity.
#[derive(Debug, Clone, Copy)]
pub struct Producer<'a> {
    parser: &'a Parser,
}
impl<'a> Producer<'a> {
    /// Funds new work against this producer and the current operation.
    #[must_use]
    pub fn execution_in<'q, W: Work>(&self, work: &'q W) -> structured_asn1::memory::Execution<'q>
    where
        'a: 'q,
    {
        work.execution_for(self.parser)
    }
}

/// Original bytes nested one level inside an identifier's reader, carrying
/// only what reading them in place needs: a key that inherits parameters
/// keeps this rather than the authority's whole identifier.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Nested<'a> {
    bytes: &'a [u8],
    at: u64,
    parser: &'a Parser,
    outer: u32,
    encoding: Encoding,
}

impl<'a> Nested<'a> {
    pub(crate) fn execution_origin(self) -> Producer<'a> {
        Producer {
            parser: self.parser,
        }
    }

    pub(crate) fn encoding(self) -> Encoding {
        self.encoding
    }
    pub(crate) fn execution_in<'q, W: Work>(
        self,
        work: &'q W,
    ) -> structured_asn1::memory::Execution<'q>
    where
        'a: 'q,
    {
        work.execution_for(self.parser)
    }

    /// Original start, without opening or scanning the nested value.
    pub(crate) fn offset(self) -> u64 {
        self.at
    }

    pub(crate) fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Opens the single element these bytes hold. Source parser, offsets,
    /// encoding and depth stay original; `execution` pays for the decoding.
    pub(crate) fn open<'operation, W: Work>(
        self,
        execution: &'operation W,
        field: &'static str,
    ) -> Result<(ScopedReader<'a, 'operation>, Element<'a>)>
    where
        'a: 'operation,
    {
        let mut reader = execution
            .read_scoped_nested(self.parser, self.bytes, self.at, self.encoding, self.outer)
            .field(field)?;
        let element = reader
            .next_element()
            .field(field)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, field, reader.offset()))?;
        if !reader.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, field, reader.offset()));
        }
        Ok((reader, element))
    }
}

// Raw schema fields are deliberately a different type from the validated
// identifier. Only a fault-free reading can cross the crypto-facing boundary.
#[derive(Debug, Clone, Copy)]
struct AlgorithmFields<'a> {
    algorithm: Oid<'a>,
    parameter_start: Option<NonZeroUsize>,
    null_parameter: bool,
    der: &'a [u8],
    offset: u64,
    field: &'static str,
    parser: &'a Parser,
    outer: u32,
    encoding: Encoding,
    indefinite: bool,
}

/// Original algorithm fields plus a recoverable parameter-syntax diagnostic.
///
/// A malformed reading is inspection data, not valid BER/DER or a provider
/// input. Only [`Self::identifier`] can expose a validated identifier. No input
/// bytes are copied and the diagnostic itself has no allocated storage.
///
/// ```compile_fail
/// use structured_pkix::algorithm::{AlgorithmIdentifier, AlgorithmReading};
/// fn crypto_input(_: AlgorithmIdentifier<'_>) {}
/// fn unchecked(reading: AlgorithmReading<'_>) {
///     crypto_input(reading); // Inspection data is not a validated identifier.
/// }
/// ```
#[derive(Debug)]
pub struct AlgorithmReading<'a> {
    fields: AlgorithmFields<'a>,
    fault: Option<Error>,
}

impl<'a> AlgorithmReading<'a> {
    /// The original, successfully decoded OID; not a supported capability.
    #[must_use]
    pub fn algorithm(&self) -> Oid<'a> {
        self.fields.algorithm
    }

    /// The whole original parameter encoding, including any malformed form.
    #[must_use]
    pub fn parameters(&self) -> Option<&'a [u8]> {
        parameter_bytes(
            self.fields.der,
            self.fields.parameter_start,
            self.fields.indefinite,
        )
    }

    /// Original parameter range in the producing reader's coordinates.
    /// Joined content requires its caller-owned source map for physical ranges.
    #[must_use]
    pub fn parameters_span(&self) -> Option<Span> {
        let start = self.fields.parameter_start?.get();
        Some(Span {
            start: self.fields.offset + start as u64,
            length: self.parameters()?.len() as u64,
        })
    }

    /// A primitive NULL whose complete parameter validation succeeded.
    /// A malformed form, including constructed NULL, never has this fact.
    #[must_use]
    pub fn has_null_parameter(&self) -> bool {
        self.fields.null_parameter
    }

    /// Whole original algorithm encoding, including an original IMPLICIT tag.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.fields.der
    }

    /// Original enclosing algorithm position in the producing source.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.fields.offset
    }

    /// Encoding used by the producing reader, without a replacement parser.
    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.fields.encoding
    }

    /// Whether this inspection reading belongs to the supplied parser session.
    /// This checks original provenance even when no validated identifier exists;
    /// account identity alone does not establish source/session identity.
    #[must_use]
    pub fn same_session(&self, parent: &Reader<'_>) -> bool {
        core::ptr::eq(self.fields.parser, parent.parser())
    }

    /// Parameter syntax fault; resource and processing failures are never here.
    #[must_use]
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }

    /// A validated identifier only when the complete parameter check succeeded.
    /// Selected-provider parameter/profile acceptance still belongs to that provider.
    #[must_use]
    pub fn identifier(&self) -> Option<AlgorithmIdentifier<'a>> {
        if self.fault.is_some() {
            return None;
        }
        Some(self.fields.identifier())
    }

    /// Requires a validated provider input, returning the original syntax fault.
    /// This is a scalar provenance check; no reparse, allocation or parameter
    /// normalization is performed. Selected-provider acceptance is separate.
    pub fn require_identifier(&self) -> Result<AlgorithmIdentifier<'a>> {
        match &self.fault {
            Some(error) => Err(error.clone()),
            None => Ok(self.fields.identifier()),
        }
    }

    /// Paid written-value identity for inspection, not parameter acceptance.
    /// Malformed parameters retain exact encoded identity; only two validated
    /// primitive NULL values can ignore their BER length spelling. Absence is
    /// never inferred as a default. Both readings require this producing parser.
    pub fn same_written_in(&self, other: &Self, parent: &Reader<'_>) -> Result<bool> {
        written_matches(&self.fields, &other.fields, parent, false)
    }

    fn into_identifier(self) -> Result<AlgorithmIdentifier<'a>> {
        match self.fault {
            Some(error) => Err(error),
            None => Ok(self.fields.identifier()),
        }
    }
}

impl<'a> AlgorithmFields<'a> {
    // Called only after the reading's fault gate. The raw type never escapes.
    fn identifier(self) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier {
            algorithm: self.algorithm,
            parameter_start: self.parameter_start,
            null_parameter: self.null_parameter,
            der: self.der,
            offset: self.offset,
            field: self.field,
            parser: self.parser,
            outer: self.outer,
            encoding: self.encoding,
            indefinite: self.indefinite,
        }
    }
}

fn parameter_bytes(bytes: &[u8], start: Option<NonZeroUsize>, indefinite: bool) -> Option<&[u8]> {
    let start = start?.get();
    let end = bytes.len() - if indefinite { 2 } else { 0 };
    Some(&bytes[start..end])
}

trait WrittenValue {
    fn oid_bytes(&self) -> &[u8];
    fn parameter_bytes(&self) -> Option<&[u8]>;
    fn valid_null(&self) -> bool;
    fn producer(&self) -> &Parser;
    fn field(&self) -> &'static str;
    fn offset(&self) -> u64;
}

impl WrittenValue for AlgorithmFields<'_> {
    fn oid_bytes(&self) -> &[u8] {
        self.algorithm.as_bytes()
    }
    fn parameter_bytes(&self) -> Option<&[u8]> {
        parameter_bytes(self.der, self.parameter_start, self.indefinite)
    }
    fn valid_null(&self) -> bool {
        self.null_parameter
    }
    fn producer(&self) -> &Parser {
        self.parser
    }
    fn field(&self) -> &'static str {
        self.field
    }
    fn offset(&self) -> u64 {
        self.offset
    }
}

impl WrittenValue for AlgorithmIdentifier<'_> {
    fn oid_bytes(&self) -> &[u8] {
        self.algorithm.as_bytes()
    }
    fn parameter_bytes(&self) -> Option<&[u8]> {
        self.parameters()
    }
    fn valid_null(&self) -> bool {
        self.null_parameter
    }
    fn producer(&self) -> &Parser {
        self.parser
    }
    fn field(&self) -> &'static str {
        self.field
    }
    fn offset(&self) -> u64 {
        self.offset
    }
}

fn require_written_parsers(
    left: &impl WrittenValue,
    right: &impl WrittenValue,
    parent: &Reader<'_>,
) -> Result<()> {
    if !core::ptr::eq(left.producer(), parent.parser()) {
        return Err(Error::new(
            ErrorCode::ForeignReader,
            left.field(),
            left.offset(),
        ));
    }
    if !core::ptr::eq(right.producer(), parent.parser()) {
        return Err(Error::new(
            ErrorCode::ForeignReader,
            right.field(),
            right.offset(),
        ));
    }
    Ok(())
}

fn written_matches(
    left: &impl WrittenValue,
    right: &impl WrittenValue,
    parent: &Reader<'_>,
    defaults: bool,
) -> Result<bool> {
    require_written_parsers(left, right, parent)?;
    written_values(left, right, parent, defaults)
}

fn written_values(
    left: &impl WrittenValue,
    right: &impl WrittenValue,
    parent: &Reader<'_>,
    defaults: bool,
) -> Result<bool> {
    let charge = |amount| {
        parent.charge(amount).map_err(|error| {
            Error::new(
                ErrorCode::Encoding(error.code()),
                right.field(),
                right.offset(),
            )
        })
    };
    charge(1)?;
    let kind = left.oid_bytes();
    if kind.len() != right.oid_bytes().len() {
        return Ok(false);
    }
    charge(kind.len() as u64)?;
    if kind != right.oid_bytes() {
        return Ok(false);
    }
    if defaults || (left.valid_null() && right.valid_null()) {
        return Ok(true);
    }
    let (Some(first), Some(second)) = (left.parameter_bytes(), right.parameter_bytes()) else {
        return Ok(left.parameter_bytes().is_none() && right.parameter_bytes().is_none());
    };
    if first.len() != second.len() {
        return Ok(false);
    }
    charge(first.len() as u64)?;
    Ok(first == second)
}

impl<'a> AlgorithmIdentifier<'a> {
    /// Whether a written primitive NULL was validated by the producing reader.
    /// Original parameter bytes remain unchanged; absence is not NULL here.
    #[must_use]
    pub fn has_null_parameter(self) -> bool {
        self.null_parameter
    }

    /// Compares written values without assuming algorithm-specific defaults.
    /// Two validated primitive NULLs share a value despite BER length spelling;
    /// other parameters retain opaque encoded identity. Both identifiers must
    /// come from this producing parser. This is not algorithm acceptance.
    ///
    /// # Errors
    /// Returns a located resource refusal or a foreign-parser error before
    /// comparing identifiers from another parsing session.
    pub fn same_written_in(self, other: &Self, parent: &Reader<'_>) -> Result<bool> {
        self.value_matches(other, parent, false)
    }

    /// Compares RFC5754 §2 SHA224/256/384/512 identifiers with absent/NULL defaults.
    /// Unknown algorithms retain written-value semantics, not a guessed default.
    /// Invalid known parameters and resource/caller refusals remain errors.
    /// Selected-provider support and signature-profile acceptance are separate.
    /// <https://www.rfc-editor.org/rfc/rfc5754#section-2>
    ///
    /// # Errors
    /// Returns invalid known parameters, foreign-parser misuse, or resource
    /// refusal separately from an ordinary identity mismatch.
    pub fn digest_matches_in(self, other: &Self, parent: &Reader<'_>) -> Result<bool> {
        self.value_matches(other, parent, true)
    }

    fn value_matches(self, other: &Self, parent: &Reader<'_>, digest: bool) -> Result<bool> {
        require_written_parsers(&self, other, parent)?;
        let sha2 = if digest {
            let known = self.validate_digest_params(parent)?;
            other.validate_digest_params(parent)?;
            known
        } else {
            false
        };
        written_values(&self, other, parent, sha2)
    }

    fn validate_digest_params(self, parent: &Reader<'_>) -> Result<bool> {
        let charge = |amount| {
            parent.charge(amount).map_err(|error| {
                Error::new(ErrorCode::Encoding(error.code()), self.field, self.offset)
            })
        };
        charge(1)?;
        let kind = self.algorithm.as_bytes();
        if kind.len() != 9 {
            return Ok(false);
        }
        charge(9)?;
        if kind[..8] != [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2] || kind[8] < 1 || kind[8] > 4 {
            return Ok(false);
        }
        if self.parameter_start.is_some() && !self.null_parameter {
            // RFC5754 §2 permits only absent or NULL parameters for these four
            // SHA2 identifiers. Unknown algorithms get no inferred default.
            // https://www.rfc-editor.org/rfc/rfc5754#section-2
            return Err(Error::new(
                ErrorCode::MalformedValue,
                self.field,
                self.offset,
            ));
        }
        Ok(true)
    }
    /// Which algorithm.
    #[must_use]
    pub fn algorithm(self) -> Oid<'a> {
        self.algorithm
    }

    /// The parameters, as the whole encoded element, or `None` where the
    /// certificate wrote none.
    ///
    /// Kept encoded because what they mean depends on the algorithm: the same
    /// bytes are a curve for one and a hash function and salt length for
    /// another.
    #[must_use]
    pub fn parameters(self) -> Option<&'a [u8]> {
        parameter_bytes(self.der, self.parameter_start, self.indefinite)
    }

    /// Original algorithm element offset, without scanning or deriving a new range.
    #[must_use]
    pub fn offset(self) -> u64 {
        self.offset
    }

    /// Encoding selected by the original schema reader for this identifier.
    #[must_use]
    pub fn encoding(self) -> Encoding {
        self.encoding
    }

    /// Opens the whole original parameter TLV at its original reader depth.
    ///
    /// `parent` must belong to the original parser session; rebinding its
    /// current execution account is allowed. A foreign session is rejected
    /// before lookup, work or allocation. Both current funding and the original
    /// cumulative session ceiling govern all later decoding. Absence is only
    /// returned after admission, never as a resource fallback.
    ///
    /// The returned depth equals an immediate `inside.reread(parameter, encoding)`
    /// after this identifier was read, including an IMPLICIT context envelope.
    /// It includes the parameter header, not just its contents; no replacement
    /// parser, canonical serialization or extra parameter nesting is introduced.
    pub fn parameters_reader_in<'query>(
        self,
        parent: &Reader<'query>,
        field: &'static str,
    ) -> Result<Option<Reader<'query>>>
    where
        'a: 'query,
    {
        if !self.same_session(parent) {
            return Err(Error::new(ErrorCode::ForeignReader, field, self.offset));
        }
        let at = self
            .parameter_start
            .map_or(self.offset, |start| self.offset + start.get() as u64);
        parent
            .execution()
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, at))?;
        let Some(parameter) = self.parameters() else {
            return Ok(None);
        };
        self.parser
            .read_nested_query_in(parent, parameter, at, self.encoding, self.outer)
            .field(field)
            .map(Some)
    }

    /// Rebind original metadata queries without parsing or owning an account.
    pub(crate) fn query_in<'operation, W: Work>(
        &self,
        execution: &'operation W,
    ) -> structured_asn1::memory::Execution<'operation>
    where
        'a: 'operation,
    {
        execution.execution_for(self.parser)
    }

    pub(crate) fn source_parser(self) -> &'a Parser {
        self.parser
    }

    /// Retains only the original parser-session funding capability. No
    /// bytes are parsed, copied, hashed or interpreted by this projection.
    #[must_use]
    pub fn execution_origin(self) -> Producer<'a> {
        Producer {
            parser: self.parser,
        }
    }

    /// The written parameters, readable in place.
    pub(crate) fn parameters_nested(self) -> Option<Nested<'a>> {
        let start = self.parameter_start?.get();
        Some(self.nested(self.parameters()?, self.offset + start as u64))
    }

    /// Original bytes at `at` that sit one level inside this identifier's
    /// reader: its parameters, or the sibling key bits of an enclosing SPKI.
    pub(crate) fn nested(self, bytes: &'a [u8], at: u64) -> Nested<'a> {
        Nested {
            bytes,
            at,
            parser: self.parser,
            outer: self.outer,
            encoding: self.encoding,
        }
    }

    /// Whether this original identifier was produced by this parser session.
    /// Account equality does not establish source/session identity. This O(1)
    /// metadata predicate reads no parameters and spends no data-dependent work.
    #[must_use]
    pub fn same_session(self, parent: &ScopedReader<'_, '_>) -> bool {
        core::ptr::eq(self.parser, parent.parser())
    }

    /// The whole identifier as it was encoded.
    ///
    /// For [`read_implicit`], this retains the original context tag, not a
    /// synthesized SEQUENCE suitable for reparsing as an untagged identifier.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.der
    }

    /// Whether the parameters are absent, or the null that means the same
    /// thing for the algorithms that spell it that way.
    #[must_use]
    pub fn has_no_parameters(self) -> bool {
        // The NULL validated under the document's own encoding, not the DER
        // bytes `05 00`: BER may write its zero length in long form
        // (X.690 §8.1.3.5, §8.8; RFC 5652 §1 makes a signed message BER).
        self.parameters().is_none() || self.null_parameter
    }

    /// Whether two identifiers name the same algorithm with the same
    /// parameters.
    ///
    /// An absent parameter and an explicit null are treated as the same, and
    /// nothing else is. Issuers disagree about which of the two to write for
    /// the algorithms that take no parameters, and both say the same thing;
    /// any other difference changes what is being verified.
    ///
    /// The equivalence is deliberately not algorithm-specific. Which
    /// parameter encodings an algorithm permits at all, including that the
    /// Edwards-curve identifiers forbid the null form, is the algorithm
    /// registry's decision, made against the identifier inside the signed
    /// bytes. This comparison only asks whether the unsigned outer identifier
    /// agrees with that signed one, and absent versus null cannot change
    /// which algorithm that is: an outer null beside a signed absent is a
    /// malformed spelling of the same identity, not a different algorithm
    /// escaping the mismatch check.
    ///
    /// Deferred comparisons charge the supplied current operation. Their
    /// resource diagnostics identify `self`'s original field and offset; they
    /// do not assert that the two identifiers share a source. Parser-local
    /// limits apply only when comparing through the producing reader.
    ///
    /// # Errors
    /// Returns a resource refusal before an unfunded byte comparison.
    ///
    /// # Examples
    /// ```
    /// # extern crate alloc;
    /// # use alloc::sync::Arc;
    /// # use structured_asn1::{Parser, Tag, universal};
    /// # use structured_asn1::memory::{Memory, MemoryAccount};
    /// # let execution = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// # let parser = Parser::der(execution.clone());
    /// # let mut reader = parser.read(b"\x30\x04\x06\x02\x2a\x03", 0).unwrap();
    /// # let element = reader.expect(Tag::constructed(universal::SEQUENCE)).unwrap();
    /// let identifier = structured_pkix::algorithm::read(&reader, &element, "algorithm")?;
    /// assert!(identifier.matches(&identifier, &execution)?);
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn matches(self, other: &AlgorithmIdentifier<'_>, execution: &Memory) -> Result<bool> {
        self.matches_with(other, |work| {
            execution
                .charge_work(work)
                .map_err(|reason| Error::resource(reason, self.field, self.offset))
        })
    }

    pub(crate) fn matches_in(
        self,
        other: &AlgorithmIdentifier<'_>,
        parent: &Reader<'_>,
    ) -> Result<bool> {
        self.matches_with(other, |work| {
            parent.charge(work).map_err(|error| {
                Error::new(ErrorCode::Encoding(error.code()), self.field, self.offset)
            })
        })
    }

    fn matches_with(
        self,
        other: &AlgorithmIdentifier<'_>,
        mut charge: impl FnMut(u64) -> Result<()>,
    ) -> Result<bool> {
        charge(1)?;
        if self.algorithm.as_bytes().len() != other.algorithm.as_bytes().len() {
            return Ok(false);
        }
        charge(self.algorithm.as_bytes().len() as u64)?;
        if self.algorithm != other.algorithm {
            return Ok(false);
        }
        if self.has_no_parameters() && other.has_no_parameters() {
            return Ok(true);
        }
        let (Some(left), Some(right)) = (self.parameters(), other.parameters()) else {
            return Ok(false);
        };
        if left.len() != right.len() {
            return Ok(false);
        }
        charge(left.len() as u64)?;
        Ok(left == right)
    }
}

/// Reads an algorithm identifier from an element a schema said is one.
///
/// It is public because certificates are not the only place this structure
/// appears: a signed message names a digest and a signature algorithm the same
/// way, and reading them a second time somewhere else would be a second set of
/// rules about what parameters are allowed to look like.
///
/// # Errors
///
/// Reports the encoding fault and the field it was in.
pub fn read<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    read_tagged(
        parent,
        element,
        Tag::constructed(universal::SEQUENCE),
        field,
    )
}

/// Reads an original `[number] IMPLICIT AlgorithmIdentifier` without retagging.
///
/// The caller supplies the tag number selected by its trusted schema. For
/// example, `CMSAlgorithmProtection` uses `[1]` for a signature and `[2]` for a
/// MAC (RFC6211 §2); that cardinality/choice rule belongs to the CMS schema.
/// The same inner algorithm/parameter core as [`read`] preserves original
/// bytes, encoding, inherited depth and current producing execution ceilings.
/// <https://www.rfc-editor.org/rfc/rfc6211#section-2>
pub fn read_implicit<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    number: u32,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    read_tagged(parent, element, Tag::context(true, number), field)
}

/// Inspects a uniquely shaped identifier while retaining parameter syntax faults.
///
/// The OID and at most one whole parameter must be unambiguous. Invalid
/// parameter syntax is preserved as [`AlgorithmReading::fault`], never as a
/// validated identifier. Resource/caller refusals, missing fields and ambiguous
/// schema remain errors. This does not authorize malformed crypto input.
pub fn read_inspection<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<AlgorithmReading<'a>> {
    read_fields::<true>(
        parent,
        element,
        Tag::constructed(universal::SEQUENCE),
        field,
    )
}

/// Original IMPLICIT counterpart of [`read_inspection`], sharing the same kernel.
pub fn read_implicit_inspection<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    number: u32,
    field: &'static str,
) -> Result<AlgorithmReading<'a>> {
    read_fields::<true>(parent, element, Tag::context(true, number), field)
}

fn read_fields<'a, const INSPECTION: bool>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    expected: Tag,
    field: &'static str,
) -> Result<AlgorithmReading<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);
    if element.tag() != expected {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let mut inside = parent.enter(element).field(field)?;
    let algorithm = inside.read_oid().field(field)?;
    let parameter = inside.next_element().field(field)?;
    let mut fault = None;
    let mut null_parameter = false;
    if let Some(parameter) = &parameter {
        match crate::name::walk_der(&inside, parameter, field, crate::name::Strings::Checked) {
            Ok(()) => {
                // The shared walker validates primitive NULL contents. A
                // constructed/nonempty NULL cannot acquire this cached fact.
                // X.690 (02/2021) §8.8.1–2: primitive, with empty contents.
                // https://www.itu.int/rec/T-REC-X.690-202102-I/en
                null_parameter = parameter.tag() == Tag::primitive(universal::NULL);
            }
            Err(error) => {
                if !INSPECTION || error.is_resource() || error.code() == ErrorCode::ForeignReader {
                    return Err(error);
                }
                fault = Some(error);
            }
        }
    }
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    let parameter_start = match parameter {
        None => None,
        Some(parameter) => {
            let start = usize::try_from(parameter.span().start - element.span().start)
                .map_err(|_| fail(ErrorCode::ValueTooLarge))?;
            Some(NonZeroUsize::new(start).expect("the algorithm OID precedes its parameters"))
        }
    };
    Ok(AlgorithmReading {
        fields: AlgorithmFields {
            algorithm,
            parameter_start,
            null_parameter,
            der: element.as_bytes(),
            offset: element.span().start,
            field,
            parser: parent.parser(),
            outer: parent.depth(),
            encoding: inside.encoding(),
            indefinite: element.is_indefinite(),
        },
        fault,
    })
}

fn read_tagged<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    expected: Tag,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    read_fields::<false>(parent, element, expected, field)?.into_identifier()
}

#[cfg(test)]
mod tests;
