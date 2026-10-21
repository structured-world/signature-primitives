//! Streaming DER framing of an effective key, not key or algorithm acceptance.
//!
//! RFC5755 §7.3 hashes a whole DER `SubjectPublicKeyInfo`, including inherited
//! parameters. Hashing only the original SPKI is wrong when DSA parameters
//! came from an issuer. No joined buffer or parser over synthesized data is
//! needed: only tag/length framing changes, all payload remains borrowed.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-7.3>

use crate::algorithm::Nested;
use crate::error::{Error, ErrorCode, Located, Result};
use crate::path::WorkingKey;
use structured_asn1::memory::{Execution, MemoryError, Work};
use structured_asn1::{Encoding, Span};

const FIELD: &str = "subjectPublicKeyInfo.effectiveDER";

/// Which part failed to reach a streaming consumer. Framing is synthesized;
/// it has no invented contiguous source span. Other parts retain their source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Canonical tag/length or the zero unused-bits octet.
    Framing,
    /// Original algorithm OID contents.
    Algorithm,
    /// Original effective parameter TLV, possibly from an issuer.
    Parameters,
    /// Original public-key octets, without BIT STRING framing.
    PublicKey,
}

/// Source/current processing refusal or the original visitor failure.
#[derive(Debug)]
pub enum VisitError<E> {
    /// Original located PKIX/resource failure.
    Processing {
        /// Part whose metadata could not be admitted.
        part: Part,
        /// Real enclosing source, not a physical range of synthesized framing.
        context: Span,
        /// Original source/current failure.
        source: Error,
    },
    /// The consumer refused this part; no subsequent part is emitted.
    Callback {
        /// Part the visitor refused.
        part: Part,
        /// Real enclosing input context; framing itself has no original range.
        context: Span,
        /// Original visitor cause.
        source: E,
    },
}

#[derive(Debug)]
struct Header {
    bytes: [u8; 11],
    len: usize,
}
impl Header {
    fn new(tag: u8, length: u64) -> Self {
        let mut bytes = [0; 11];
        bytes[0] = tag;
        if length < 128 {
            bytes[1] = u8::try_from(length).expect("short DER length is below 128");
            return Self { bytes, len: 2 };
        }
        let count = u8::try_from((64 - length.leading_zeros()).div_ceil(8))
            .expect("a u64 length uses at most eight octets");
        bytes[1] = 0x80 | count;
        let count = usize::from(count);
        bytes[2..2 + count].copy_from_slice(&length.to_be_bytes()[8 - count..]);
        Self {
            bytes,
            len: 2 + count,
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Immutable DER chunks over the original key and effective parameter sources.
///
/// This proves canonical outer framing and parameter DER, not that a key's
/// algorithm-specific payload is valid. A selected provider must check the
/// original `WorkingKey` against its algorithm rules before using this stream.
/// In particular, inherited parameters cannot repair an invalid written NULL.
/// The type owns no allocation, account, parser or operation borrow.
#[derive(Debug)]
pub struct EffectiveSpki<'a> {
    key: WorkingKey<'a>,
    parameters: Option<Nested<'a>>,
    sequence: Header,
    algorithm: Header,
    oid: Header,
    bits: Header,
    length: u64,
}

fn overflow(at: u64) -> Error {
    Error::resource(MemoryError::WorkExceeded, FIELD, at)
}
fn add(left: u64, right: u64, at: u64) -> Result<u64> {
    left.checked_add(right).ok_or_else(|| overflow(at))
}

impl<'a> EffectiveSpki<'a> {
    /// Prepare canonical framing without copying any original payload.
    /// DER parameters already validated by their original identifier need no
    /// new scan. BER sources are held to DER in their original nested context;
    /// noncanonical parameter TLVs are rejected rather than silently rewritten.
    /// Written NULL is retained when there is no effective inherited value.
    pub fn read<W: Work>(key: WorkingKey<'a>, work: &W) -> Result<Self> {
        let own = key.key().algorithm();
        let execution = own.query_in(work);
        // Four length headers have at most eight significant length octets.
        execution
            .charge_work(64)
            .map_err(|e| Error::resource(e, FIELD, own.offset()))?;
        let bytes = key.key().whole_octets(FIELD)?;
        let parameters = key.parameter_source().or_else(|| own.parameters_nested());
        if let Some(source) = parameters.filter(|source| !source.encoding().is_der()) {
            // Source encoding is known from the immutable, validated identifier.
            // Opening is required only for BER: checking DER includes its header.
            let (reader, element) = source.open(work, FIELD)?;
            if !reader.encoding().is_der() {
                let mut strict = reader.reread(&element, Encoding::Der).field(FIELD)?;
                let original = strict
                    .next_element()
                    .field(FIELD)?
                    .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, source.offset()))?;
                crate::der::conforms(&strict, &original, FIELD)?;
            }
        }
        let at = own.offset();
        let oid = Header::new(6, own.algorithm().as_bytes().len() as u64);
        let algorithm_len = add(oid.len as u64, own.algorithm().as_bytes().len() as u64, at)?;
        let algorithm_len = add(
            algorithm_len,
            parameters.map_or(0, |p| p.as_bytes().len() as u64),
            at,
        )?;
        let algorithm = Header::new(48, algorithm_len);
        let mut bits = Header::new(3, add(bytes.len() as u64, 1, at)?);
        bits.bytes[bits.len] = 0;
        bits.len += 1;
        let content = add(
            add(algorithm.len as u64, algorithm_len, at)?,
            add(bits.len as u64, bytes.len() as u64, at)?,
            at,
        )?;
        let sequence = Header::new(48, content);
        let length = add(sequence.len as u64, content, at)?;
        Ok(Self {
            key,
            parameters,
            sequence,
            algorithm,
            oid,
            bits,
            length,
        })
    }

    /// Total encoded width, including all synthesized framing.
    #[must_use]
    pub fn encoded_len(&self) -> u64 {
        self.length
    }

    /// Original effective key, including its parameter provenance.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'a> {
        self.key
    }

    /// Original key-source ceiling with the current operation's work/account.
    /// Construction scans nothing; the selected key validator admits its own
    /// work and uses shared readers for any independently sourced parameters.
    pub fn execution_in<'q, W: Work>(&'q self, work: &'q W) -> Execution<'q> {
        self.key.key().algorithm().query_in(work)
    }

    /// Emit every part once in DER order with its source/current execution.
    /// The visitor admits its byte scan, output copies and transitive storage.
    /// Metadata admission precedes each callback. A failure stops immediately;
    /// successful partial completion is never returned, but external visitor
    /// side effects cannot be rolled back by this method. Header borrows cannot
    /// escape a callback, and no complete SPKI buffer is allocated.
    ///
    /// The synthesized header borrow cannot be retained as document data:
    ///
    /// ```compile_fail
    /// use structured_asn1::memory::Memory;
    /// use structured_pkix::key::effective::EffectiveSpki;
    /// fn escape(view: &EffectiveSpki<'static>, work: &Memory) -> &'static [u8] {
    ///     let mut saved: &'static [u8] = &[];
    ///     let _ = view.visit(work, |_, bytes, _| {
    ///         saved = bytes;
    ///         Ok::<_, core::convert::Infallible>(())
    ///     });
    ///     saved
    /// }
    /// ```
    pub fn visit<W: Work, E>(
        &self,
        work: &W,
        mut visitor: impl FnMut(Part, &[u8], &Execution<'_>) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), VisitError<E>> {
        let own = self.key.key().algorithm();
        let execution = own.query_in(work);
        let context = Span {
            start: own.offset(),
            length: own.as_bytes().len() as u64,
        };
        for bytes in [
            self.sequence.bytes(),
            self.algorithm.bytes(),
            self.oid.bytes(),
        ] {
            emit(Part::Framing, bytes, &execution, context, &mut visitor)?;
        }
        emit(
            Part::Algorithm,
            own.algorithm().as_bytes(),
            &execution,
            context,
            &mut visitor,
        )?;
        if let Some(source) = self.parameters {
            emit(
                Part::Parameters,
                source.as_bytes(),
                &source.execution_in(work),
                Span {
                    start: source.offset(),
                    length: source.as_bytes().len() as u64,
                },
                &mut visitor,
            )?;
        }
        emit(
            Part::Framing,
            self.bits.bytes(),
            &execution,
            context,
            &mut visitor,
        )?;
        emit(
            Part::PublicKey,
            self.key.key().key().as_bytes(),
            &execution,
            Span {
                start: self.key.key().key_offset(),
                length: self.key.key().key().as_bytes().len() as u64,
            },
            &mut visitor,
        )
    }
}

fn emit<E>(
    part: Part,
    bytes: &[u8],
    work: &Execution<'_>,
    context: Span,
    visitor: &mut impl FnMut(Part, &[u8], &Execution<'_>) -> core::result::Result<(), E>,
) -> core::result::Result<(), VisitError<E>> {
    work.charge_work(1).map_err(|e| VisitError::Processing {
        part,
        context,
        source: Error::resource(e, FIELD, context.start),
    })?;
    visitor(part, bytes, work).map_err(|source| VisitError::Callback {
        part,
        context,
        source,
    })
}
