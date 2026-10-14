//! Which algorithm, and the parameters that go with it.
//!
//! The identifier is kept as it was encoded and is not interpreted here. What
//! may be verified with a key, and how, belongs to the algorithm registry; this
//! layer's job is to hand that registry exactly what the certificate said,
//! including parameters it does not understand.

use crate::error::{Error, ErrorCode, Located, Result};
use core::num::NonZeroUsize;
use structured_asn1::memory::{Memory, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, Tag, universal};

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
        for operand in [self, *other] {
            if !core::ptr::eq(operand.parser, parent.parser()) {
                return Err(Error::new(
                    ErrorCode::ForeignReader,
                    operand.field,
                    operand.offset,
                ));
            }
        }
        let charge = |amount| {
            parent.charge(amount).map_err(|error| {
                Error::new(ErrorCode::Encoding(error.code()), other.field, other.offset)
            })
        };
        let sha2 = if digest {
            let known = self.validate_digest_params(parent)?;
            other.validate_digest_params(parent)?;
            known
        } else {
            false
        };
        charge(1)?;
        let kind = self.algorithm.as_bytes();
        if kind.len() != other.algorithm.as_bytes().len() {
            return Ok(false);
        }
        charge(kind.len() as u64)?;
        if self.algorithm != other.algorithm {
            return Ok(false);
        }
        if sha2 {
            return Ok(true);
        }
        if self.null_parameter && other.null_parameter {
            return Ok(true);
        }
        let (Some(left), Some(right)) = (self.parameters(), other.parameters()) else {
            return Ok(self.parameter_start.is_none() && other.parameter_start.is_none());
        };
        if left.len() != right.len() {
            return Ok(false);
        }
        charge(left.len() as u64)?;
        Ok(left == right)
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
        let start = self.parameter_start?.get();
        let end = self.der.len() - if self.indefinite { 2 } else { 0 };
        Some(&self.der[start..end])
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

    /// Whether this original identifier was produced by this parser session.
    /// Account equality does not establish source/session identity. This O(1)
    /// metadata predicate reads no parameters and spends no data-dependent work.
    #[must_use]
    pub fn same_session(self, parent: &Reader<'_>) -> bool {
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
        // A null is two bytes: the tag and a zero length.
        self.parameters()
            .is_none_or(|parameters| parameters == [0x05, 0x00])
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
    parent: &Reader<'a>,
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

fn read_tagged<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    expected: Tag,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != expected {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut inside = parent.enter(element).field(field)?;
    let algorithm = inside.read_oid().field(field)?;
    let parameter = inside.next_element().field(field)?;

    // What the parameter says is the registry's business: a curve, a hash,
    // the salt length of a padding scheme. It is handed the bytes on the
    // promise that they are the encoding the document claims, so the whole
    // value is held to that and not only its outer header.
    let mut null_parameter = false;
    if let Some(parameter) = &parameter {
        crate::name::walk_der(&inside, parameter, field, crate::name::Strings::Checked)?;
        if parameter.tag() == Tag::primitive(universal::NULL) {
            inside.null(parameter).field(field)?;
            null_parameter = true;
        }
    }
    // The schema has room for one parameter and no more, and a second would
    // leave which of them the algorithm takes with no answer.
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

    Ok(AlgorithmIdentifier {
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
    })
}

#[cfg(test)]
mod tests;
