//! One frozen original source set for simultaneous timestamp/material checks.

use super::Role;
use crate::binary::{self, Location, OwnedBinaryXml, OwnedDecoded};
use crate::prepare::Prepared;
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::{
    Encoding, Reader,
    memory::{MemoryError, Work},
};
use structured_cms::timestamp::Token;

/// Independently retained original XML token source. There are no internal
/// borrowed pointers, re-encoding, copied parser or reset source ceilings.
pub struct TokenSource<N, D, G> {
    location: Location<N, D, G>,
    signature: N,
    property: N,
    role: Role,
    stamp: usize,
    ordinal: usize,
    encoding: Encoding,
    source: OwnedDecoded,
}
impl<N: Copy, D: Copy, G: Copy> TokenSource<N, D, G> {
    /// Original root or nested signature owning this timestamp input.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Actual original token enclosure and source generation.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// Original timestamp property, separately from its encoded token element.
    #[must_use]
    pub fn property(&self) -> N {
        self.property
    }
    /// Actual common input role of the enclosing timestamp property.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
    /// Ordinal in the frozen property set: prepared root properties followed by
    /// child properties in original depth-first counter order.
    #[must_use]
    pub fn stamp_index(&self) -> usize {
        self.stamp
    }
    /// Original token ordinal within that timestamp property.
    #[must_use]
    pub fn token_index(&self) -> usize {
        self.ordinal
    }
    /// Original decoded buffer, unchanged and not a physical XML byte range.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.source.bytes
    }
}

/// Scoped complete CMS token together with its producing query reader. This
/// is inspection only; readable diagnostics never establish positive evidence.
pub struct TokenReading<'source> {
    reader: Reader<'source>,
    token: Token<'source>,
}

/// One inseparable original source/parsed-token pair from a frozen pool.
/// Callers cannot attach a parsed token to a different XML enclosure.
#[derive(Clone, Copy)]
pub struct TokenEntry<'view, 'source, N, D, G> {
    pub(super) source: &'view TokenSource<N, D, G>,
    pub(super) reading: &'view TokenReading<'source>,
}
impl<'source> TokenReading<'source> {
    /// Current operation plus original parser/depth/source coordinate context.
    #[must_use]
    pub fn reader(&self) -> &Reader<'source> {
        &self.reader
    }
    /// Original envelope, retained faults, signer and carried material.
    #[must_use]
    pub fn token(&self) -> &Token<'source> {
        &self.token
    }
}

/// All sources are frozen before any parsed token borrows them. Both slices
/// have identical ordinals; no successfully parsed prefix is returned on failure.
pub struct TokenView<'source, N, D, G> {
    sources: &'source [TokenSource<N, D, G>],
    readings: &'source [TokenReading<'source>],
    snapshot: Snapshot<D, G>,
    signature: N,
}
impl<'source, N, D, G> TokenView<'source, N, D, G> {
    /// Select one original token pair in constant time. This is not a positive
    /// proof or a complete-token census; requirements still bind EVERY token.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<TokenEntry<'_, 'source, N, D, G>> {
        Some(TokenEntry {
            source: self.sources.get(index)?,
            reading: self.readings.get(index)?,
        })
    }
    /// Independent original source ownership for each corresponding reading.
    #[must_use]
    pub fn sources(&self) -> &'source [TokenSource<N, D, G>] {
        self.sources
    }
    /// All parsed tokens, preserving prepared-property and encapsulated-token order.
    #[must_use]
    pub fn readings(&self) -> &'source [TokenReading<'source>] {
        self.readings
    }
}

impl<'source, N: Copy, D: Copy, G: Copy> TokenView<'source, N, D, G> {
    /// Original source generation, including an empty token-source set.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original XML signature whose unsigned properties contain these tokens.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }

    pub(super) fn reborrow<'query>(&self) -> TokenView<'query, N, D, G>
    where
        'source: 'query,
    {
        TokenView {
            sources: self.sources,
            readings: self.readings,
            snapshot: self.snapshot,
            signature: self.signature,
        }
    }
}

/// Source/parse/visitor refusal, preserving original coordinate classes.
#[derive(Debug)]
pub enum TokenPipelineError<E, VE, N, D, G> {
    /// Child catalogue belongs to another root or source, before any decoding.
    Foreign {
        /// Expected original root signature.
        node: N,
    },
    /// XML/generation/current-operation failure.
    Access(AccessError<E, N>),
    /// Original Encoding selection refused through the shared binary kernel;
    /// unsupported/unknown forms are not silently replaced by another codec.
    Encoding(binary::Error<E, core::convert::Infallible, N, D, G>),
    /// Original source Reader could not be opened under both active ceilings.
    Reader {
        /// Original XML token.
        location: Location<N, D, G>,
        /// Original decoded-coordinate cause.
        cause: structured_asn1::Error,
    },
    /// Complete CMS timestamp envelope schema/inspection failure.
    Token {
        /// Original XML token.
        location: Location<N, D, G>,
        /// Unchanged decoded-coordinate CMS cause.
        cause: structured_cms::Error,
    },
    /// Source/parsed catalogue admission failed before growth.
    Resource {
        /// Actual original enclosing property/token.
        node: N,
        /// Unchanged resource refusal.
        cause: MemoryError,
    },
    /// Exact visitor failure; external visitor side effects are not rolled back.
    Visitor(VE),
}

/// Pipeline result using this XML owner's original cause and identity domain.
pub type TokenPipelineResult<T, X, VE> = Result<
    T,
    TokenPipelineError<
        <X as Xml>::Error,
        VE,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
>;

/// Retains each actual token once, freezes ownership, then parses through the
/// same CMS Token kernel used by standalone checks. A scoped visitor may inspect
/// all carried certificate/status sources and perform common complete checks
/// without a second token decode or retaining temporary XML/binary borrows.
/// No provider, source acquisition, TSA selection, trust or B level is implied.
///
/// ```compile_fail
/// use structured_asn1::Reader;
/// use structured_cms::timestamp::Token;
/// use structured_xades::{binary::OwnedBinaryXml,prepare::Prepared,timestamp};
/// fn escape<'a,X:OwnedBinaryXml>(xml:&X,prepared:&Prepared<X>,operation:&Reader<'_>)
///   -> timestamp::TokenPipelineResult<&'a Token<'a>,X,()> {
///   timestamp::with_tokens(xml,prepared,operation,|_,view|Ok(view.readings()[0].token()))
/// }
/// ```
pub fn with_tokens<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        TokenView<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> TokenPipelineResult<R, X, VE> {
    with_inputs(xml, prepared, None, operation, visitor)
}

/// Freeze and parse root AND every nested counter's timestamp tokens once.
/// The complete child census is source-bound before any binary decoding; the
/// visitor sees one source/reading pool, with each token's actual owning signature.
/// No token is omitted because it lacks positive evidence or usable TSA material.
///
/// ```compile_fail
/// use structured_asn1::Reader;
/// use structured_xades::{binary::OwnedBinaryXml, prepare::Prepared, timestamp};
/// fn escape<'a,X:OwnedBinaryXml>(xml:&X, prepared:&Prepared<X>, operation:&Reader<'_>,
///     counters:&timestamp::CounterTimestamps<X::Id,X::Document,X::Generation>)
///     -> timestamp::TokenPipelineResult<&'a [u8],X,()> {
///     timestamp::with_counter_tokens(xml,prepared,counters,operation,|_,view|Ok(view.sources()[0].bytes()))
/// }
/// ```
pub fn with_counter_tokens<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    counters: &super::CounterTimestamps<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        TokenView<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> TokenPipelineResult<R, X, VE> {
    with_inputs(xml, prepared, Some(counters), operation, visitor)
}

impl<N: Copy, D: Copy, G: Copy> TokenEntry<'_, '_, N, D, G> {
    pub(super) fn reader_in<'query>(
        &'query self,
        operation: &Reader<'query>,
    ) -> structured_asn1::Result<Reader<'query>> {
        self.source
            .source
            .reader_in(operation, self.source.encoding)
    }
}

fn with_inputs<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    counters: Option<&super::CounterTimestamps<X::Id, X::Document, X::Generation>>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        TokenView<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> TokenPipelineResult<R, X, VE> {
    let layout = prepared.bound().containers();
    let execution = operation.execution();
    let access = Access::new(xml, layout.snapshot(), &execution);
    admit(&access, layout.signature())?;
    if let Some(counters) = counters
        && (counters.snapshot != layout.snapshot()
            || !access
                .equal_id(counters.signature, layout.signature())
                .map_err(|cause| TokenPipelineError::Resource {
                    node: layout.signature(),
                    cause,
                })?)
    {
        return Err(TokenPipelineError::Foreign {
            node: layout.signature(),
        });
    }
    let mut sources = execution.vector();
    let children = counters
        .into_iter()
        .flat_map(|counters| counters.entries.iter().map(super::CounterStamp::stamp));
    let mut timestamps = prepared.timestamps().iter().chain(children).enumerate();
    loop {
        admit(&access, layout.signature())?;
        let Some((stamp, timestamp)) = timestamps.next() else {
            break;
        };
        for ordinal in 0..timestamp.tokens().len() {
            admit(&access, timestamp.node())?;
            let node = timestamp.tokens()[ordinal];
            let location = Location {
                snapshot: layout.snapshot(),
                node,
            };
            let encoding = binary::selected_encoding(&access, location)
                .map_err(TokenPipelineError::Encoding)?;
            let source = binary::owned_source(xml, location, operation)
                .map_err(TokenPipelineError::Access)?
                .value;
            sources
                .try_push(TokenSource {
                    location,
                    signature: timestamp.signature,
                    property: timestamp.node(),
                    role: timestamp.role(),
                    stamp,
                    ordinal,
                    encoding,
                    source,
                })
                .map_err(|cause| TokenPipelineError::Resource { node, cause })?;
        }
    }
    let mut readings = execution.vector();
    for index in 0..sources.len() {
        admit(&access, layout.signature())?;
        let source = &sources[index];
        let mut reader = source
            .source
            .reader_in(operation, source.encoding)
            .map_err(|cause| TokenPipelineError::Reader {
                location: source.location,
                cause,
            })?;
        let token = Token::read_from(&mut reader).map_err(|cause| TokenPipelineError::Token {
            location: source.location,
            cause,
        })?;
        readings
            .try_push(TokenReading { reader, token })
            .map_err(|cause| TokenPipelineError::Resource {
                node: source.location.node,
                cause,
            })?;
    }
    admit(&access, layout.signature())?;
    let result = visitor(
        operation,
        TokenView {
            sources: &sources,
            readings: &readings,
            snapshot: layout.snapshot(),
            signature: layout.signature(),
        },
    )
    .map_err(TokenPipelineError::Visitor)?;
    admit(&access, layout.signature())?;
    Ok(result)
}

fn admit<X: Xml, W: Work, VE>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> TokenPipelineResult<(), X, VE> {
    access
        .query(node, |_, _, work| Ok(work.charge_work(1)))
        .map_err(TokenPipelineError::Access)?
        .map_err(|cause| TokenPipelineError::Resource { node, cause })
}
