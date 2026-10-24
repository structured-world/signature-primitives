//! Source-bound signature dictionaries and exact ordered `ByteRange` coverage.

use crate::arena::{Kind, NodeId};
use crate::document::{Document, Reading};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, get, named, unsigned};
use crate::range::{RangeReader, RangeSource};
use crate::source::{Location, Source};
use structured_asn1::{
    Span,
    memory::{Memory, OwnedVec, Work},
};

/// The declared cryptographic container profile, independently of validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    /// Detached CMS signature required by the `PAdES` baseline profile.
    CadesDetached,
    /// RFC 3161 document timestamp.
    Rfc3161,
    /// Legacy detached PKCS #7 container, not a `PAdES` baseline declaration.
    Pkcs7Detached,
    /// Another original subfilter value, retained without reinterpretation.
    Other,
}

/// Coverage classification derived from original source spans, not supplied
/// by a caller or inferred from successful cryptographic verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Exactly one complete historical revision, excluding only Contents.
    Revision(usize),
    /// Readable ordered ranges that omit additional document bytes.
    Partial,
}

pub(crate) struct Entry {
    pub(crate) owner: usize,
    pub(crate) node: NodeId,
    pub(crate) contents: NodeId,
    pub(crate) ranges: OwnedVec<Span, Memory>,
    pub(crate) sub_filter: Option<SubFilter>,
    pub(crate) coverage: Coverage,
    pub(crate) timestamp: bool,
    pub(crate) definition: (u64, u16),
}

/// One original signature-shaped dictionary whose required input could not
/// be read. It remains in the complete census and cannot mint an actor.
pub struct Failure {
    /// Actual dictionary enclosure, distinct from the failed field's location.
    pub location: Location,
    /// Unchanged syntax, ambiguity or unsupported scalar-query cause.
    pub cause: Error,
    /// Actual containing indirect object identity.
    pub definition: (u64, u16),
    /// Original physical update, including compressed members.
    pub revision: usize,
    /// Original Type/SubFilter identified a document timestamp candidate.
    pub document_timestamp: bool,
    /// Actual Contents value enclosure when present, regardless of its type.
    pub contents: Option<Location>,
}

pub(crate) enum Position {
    Readable(usize),
    Unreadable(usize),
}

/// Format role proven by the original index/container grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    /// Ordinary value, including definitions not reachable from the catalog.
    Object,
    /// A structurally decoded object-stream transport.
    ObjectStream,
    /// A source-bound cross-reference stream, not a dictionary name guess.
    CrossReference,
}
/// Every actual indirect definition, independent of latest xref reachability.
#[derive(Debug, Clone, Copy)]
pub struct Definition {
    /// Original object number and generation.
    pub identity: (u64, u16),
    /// Original value coordinates, with physical enclosure for decoded objects.
    pub location: Location,
    /// Whole physical indirect record or original decoded member value.
    pub encoded: Location,
    /// Actual update containing the definition.
    pub revision: usize,
    /// Proven transport role, separately from value semantics or permissions.
    pub kind: DefinitionKind,
}

/// A complete-census member, without filtering by parse or math success.
pub enum Candidate<'a, 's, D, G> {
    /// Source-bound required fields were readable.
    Readable(Signature<'a, 's, D, G>),
    /// Original required fields were unreadable; the cause is retained.
    Unreadable(&'a Failure),
}

/// Complete catalogue ownership. Each entry points into one retained original
/// reading; neither a copied dictionary nor caller-provided coverage can mint
/// a signature input association.
pub struct Catalogue<'s, D, G> {
    pub(crate) readings: OwnedVec<Reading<'s, D, G>, Memory>,
    pub(crate) entries: OwnedVec<Entry, Memory>,
    pub(crate) failures: OwnedVec<Failure, Memory>,
    pub(crate) order: OwnedVec<Position, Memory>,
    pub(crate) definitions: OwnedVec<Definition, Memory>,
}

impl<'s, D: Copy + Eq, G: Copy + Eq> Catalogue<'s, D, G> {
    /// Number of readable signature dictionaries, including unindexed ones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the complete traversal found no readable signatures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// One source-bound signature handle, without cloning its source storage.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Signature<'_, 's, D, G>> {
        self.entries.get(index).map(|entry| Signature {
            catalogue: self,
            entry,
        })
    }
    /// Count of ALL actual candidates, including malformed/unavailable inputs.
    #[must_use]
    pub fn candidates(&self) -> usize {
        self.order.len()
    }
    /// Source-order member of the complete physical/decoded census.
    ///
    /// # Panics
    /// Panics if an internally recorded readable ordinal leaves its catalogue.
    #[must_use]
    pub fn candidate(&self, index: usize) -> Option<Candidate<'_, 's, D, G>> {
        self.order.get(index).map(|position| match position {
            Position::Readable(index) => {
                Candidate::Readable(self.get(*index).expect("original readable ordinal"))
            }
            Position::Unreadable(index) => Candidate::Unreadable(&self.failures[*index]),
        })
    }
    /// Every original unreadable input, without losing readable siblings.
    #[must_use]
    pub fn failures(&self) -> &[Failure] {
        &self.failures
    }
    /// Full physical/member inventory, including unindexed non-signature data.
    #[must_use]
    pub fn definitions(&self) -> &[Definition] {
        &self.definitions
    }
}

/// A signature handle borrows the actual catalogue member that established its
/// original dictionary, Contents and coverage association.
#[derive(Clone, Copy)]
pub struct Signature<'a, 's, D, G> {
    catalogue: &'a Catalogue<'s, D, G>,
    entry: &'a Entry,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Signature<'a, 's, D, G> {
    /// Exact original dictionary range and coordinate domain.
    #[must_use]
    pub fn location(self) -> Location {
        self.owner().value.arena.nodes[self.entry.node.0].location
    }

    /// Entire original encoded Contents string, including its delimiters.
    #[must_use]
    pub fn contents(self) -> Location {
        self.owner().value.arena.nodes[self.entry.contents.0].location
    }

    /// Original ordered byte ranges. Their sum is not a substitute for the
    /// exact exclusion/coverage classification.
    #[must_use]
    pub fn ranges(self) -> &'a [Span] {
        &self.entry.ranges
    }

    /// Whether original ranges cover a complete historical revision.
    #[must_use]
    pub fn coverage(self) -> Coverage {
        self.entry.coverage
    }

    /// Original recognized `SubFilter` value.
    #[must_use]
    pub fn sub_filter(self) -> Option<SubFilter> {
        self.entry.sub_filter
    }

    /// Original Type is `DocTimeStamp`, independently of the `SubFilter` value.
    #[must_use]
    pub fn is_document_timestamp(self) -> bool {
        self.entry.timestamp
    }

    /// Original containing indirect object, including an object-stream member.
    #[must_use]
    pub fn definition(self) -> (u64, u16) {
        self.entry.definition
    }

    /// Physical incremental update in which this dictionary was defined.
    #[must_use]
    pub fn defined_revision(self) -> usize {
        self.owner().revision
    }

    pub(crate) fn catalogue(self) -> &'a Catalogue<'s, D, G> {
        self.catalogue
    }

    pub(crate) fn owner(&self) -> &'a Reading<'s, D, G> {
        &self.catalogue.readings[self.entry.owner]
    }

    pub(crate) fn node(&self) -> NodeId {
        self.entry.node
    }
}

/// Bounded replay of the original ordered `ByteRange` members. It cannot be
/// constructed from arbitrary replacement spans or a different document.
pub struct Covered<'q, S: RangeSource> {
    reader: RangeReader<'q, S>,
    ranges: &'q [Span],
}

/// Original range acquisition or sticky receiver refusal.
#[derive(Debug)]
pub enum CoveredError<E> {
    /// Original file/source processing cause and location.
    Input(crate::range::InputError<E>),
    /// The CMS driver retains the original callback/processing cause.
    Receiver(structured_cms::stream::Refused),
}

impl<S: RangeSource> structured_cms::stream::AsyncSource for Covered<'_, S> {
    type Error = CoveredError<S::Error>;

    async fn stream<'q, W: Work + 'q, R: structured_cms::stream::Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        execution: &'q W,
    ) -> Result<(), Self::Error> {
        for span in self.ranges {
            execution.charge_work(1).map_err(|cause| {
                CoveredError::Input(crate::range::InputError::Resource {
                    location: self.reader.location(span.start, span.length),
                    cause,
                })
            })?;
            let mut at = span.start;
            let end = span.start + span.length;
            while at < end {
                let bytes = self
                    .reader
                    .chunk_at(at, end)
                    .await
                    .map_err(CoveredError::Input)?;
                receiver.write(bytes).map_err(CoveredError::Receiver)?;
                at += bytes.len() as u64;
            }
        }
        self.reader
            .check(self.reader.location(0, self.reader.stamp().length))
            .map_err(CoveredError::Input)
    }
}

pub(crate) fn inspect<S: RangeSource, W: Work>(
    document: &Document<'_, S>,
    reading: &Reading<'_, S::Document, S::Generation>,
    owner: usize,
    entries: &mut OwnedVec<Entry, W>,
    failures: &mut OwnedVec<Failure, W>,
    order: &mut OwnedVec<Position, W>,
    work: &impl Work,
) -> crate::Result<()> {
    inspect_part(
        document,
        reading,
        owner,
        0..reading.value.arena.nodes.len(),
        (reading.number, reading.generation),
        Inspection {
            entries,
            failures,
            order,
        },
        work,
    )
}

struct Header {
    byte_range: Option<NodeId>,
    contents: Option<NodeId>,
    timestamp: bool,
    signature: bool,
    sub_filter: Option<SubFilter>,
}

fn header(
    arena: &crate::arena::Arena<impl Work>,
    node_id: NodeId,
    work: &impl Work,
) -> crate::Result<Header> {
    let byte_range = get(arena, node_id, b"ByteRange", work)?;
    let contents = get(arena, node_id, b"Contents", work)?;
    let type_value = get(arena, node_id, b"Type", work)?;
    let timestamp = type_value
        .map(|node| named(arena, node, b"DocTimeStamp", work))
        .transpose()?
        .unwrap_or(false);
    let signature = type_value
        .map(|node| named(arena, node, b"Sig", work))
        .transpose()?
        .unwrap_or(false);
    let sub_filter = if let Some(sub) = get(arena, node_id, b"SubFilter", work)? {
        Some(if named(arena, sub, b"ETSI.CAdES.detached", work)? {
            SubFilter::CadesDetached
        } else if named(arena, sub, b"ETSI.RFC3161", work)? {
            SubFilter::Rfc3161
        } else if named(arena, sub, b"adbe.pkcs7.detached", work)? {
            SubFilter::Pkcs7Detached
        } else {
            SubFilter::Other
        })
    } else {
        None
    };
    Ok(Header {
        byte_range,
        contents,
        timestamp,
        signature,
        sub_filter,
    })
}

pub(crate) struct Inspection<'a, W: Work> {
    pub(crate) entries: &'a mut OwnedVec<Entry, W>,
    pub(crate) failures: &'a mut OwnedVec<Failure, W>,
    pub(crate) order: &'a mut OwnedVec<Position, W>,
}

pub(crate) fn inspect_part<S: RangeSource, W: Work>(
    document: &Document<'_, S>,
    reading: &Reading<'_, S::Document, S::Generation>,
    owner: usize,
    nodes: core::ops::Range<usize>,
    definition: (u64, u16),
    output: Inspection<'_, W>,
    work: &impl Work,
) -> crate::Result<()> {
    let Inspection {
        entries,
        failures,
        order,
    } = output;
    let arena = &reading.value.arena;
    for (index, node) in arena.nodes[nodes.clone()].iter().enumerate() {
        admit(work, node.location, 1)?;
        if !matches!(node.kind, Kind::Dictionary(_, _)) {
            continue;
        }
        let node_id = NodeId(nodes.start + index);
        let Header {
            byte_range,
            contents,
            timestamp,
            signature,
            sub_filter,
        } = header(arena, node_id, work)?;
        if byte_range.is_none()
            && !timestamp
            && !signature
            && sub_filter != Some(SubFilter::Rfc3161)
        {
            continue;
        }
        let read = || -> crate::Result<Entry> {
            let byte_range = byte_range.ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: node.location,
            })?;
            let contents = contents.ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: node.location,
            })?;
            if !matches!(arena.nodes[contents.0].kind, Kind::String(_)) {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::String),
                    location: arena.nodes[contents.0].location,
                });
            }
            let original = arena.nodes[contents.0].location;
            let (ranges, coverage) =
                parsed_ranges(document, arena, byte_range, original, node.location, work)?;
            Ok(Entry {
                owner,
                node: node_id,
                contents,
                ranges,
                sub_filter,
                coverage,
                timestamp,
                definition,
            })
        };
        let position = match read() {
            Ok(entry) => {
                let ordinal = entries.len();
                entries.try_push(entry).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: node.location,
                })?;
                Position::Readable(ordinal)
            }
            Err(cause)
                if matches!(
                    cause.kind,
                    ErrorKind::Resource(_) | ErrorKind::Limit(_) | ErrorKind::Foreign
                ) =>
            {
                return Err(cause);
            }
            Err(cause) => {
                let ordinal = failures.len();
                failures
                    .try_push(Failure {
                        location: node.location,
                        cause,
                        definition,
                        revision: reading.revision,
                        document_timestamp: timestamp || sub_filter == Some(SubFilter::Rfc3161),
                        contents: contents.map(|node| arena.nodes[node.0].location),
                    })
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: node.location,
                    })?;
                Position::Unreadable(ordinal)
            }
        };
        order.try_push(position).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: node.location,
        })?;
    }
    Ok(())
}

fn parsed_ranges<S: RangeSource, W: Work>(
    document: &Document<'_, S>,
    arena: &crate::arena::Arena<impl Work>,
    byte_range: NodeId,
    original: Location,
    location: Location,
    work: &W,
) -> crate::Result<(OwnedVec<Span>, Coverage)> {
    let Kind::Array(children) = arena.nodes[byte_range.0].kind else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Number),
            location: arena.nodes[byte_range.0].location,
        });
    };
    if children.length == 0 || children.length % 2 != 0 {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Number),
            location: arena.nodes[byte_range.0].location,
        });
    }
    let mut next = children.first;
    let mut ranges = work.vector();
    let mut previous_end = 0;
    while let Some(start_link) = next {
        admit(work, location, 2)?;
        let first = arena.links[start_link];
        let second = arena.links[first.next.expect("even ByteRange array")];
        next = second.next;
        let start = unsigned(arena, first.value, work)?;
        let length = unsigned(arena, second.value, work)?;
        let end = start.checked_add(length).ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Number),
            location,
        })?;
        if start < previous_end || end > document.stamp.length {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location: arena.nodes[first.value.0].location,
            });
        }
        ranges
            .try_push(Span { start, length })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        previous_end = end;
    }
    let mut coverage = Coverage::Partial;
    if original.source() == Source::File
        && ranges.len() == 2
        && ranges[0].start == 0
        && ranges[0].length == original.span().start
        && ranges[1].start == original.end()
    {
        for revision in 0..document.revisions() {
            admit(work, location, 1)?;
            if document.revision(revision).expect("bounded revision").end == previous_end {
                coverage = Coverage::Revision(revision);
                break;
            }
        }
    }
    Ok((ranges.into_owned(), coverage))
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Creates the original-range source for the common asynchronous CMS
    /// digest/signature driver, without materializing the PDF or its ranges.
    pub fn covered<'q, W: Work>(
        &'q self,
        signature: Signature<'q, 's, S::Document, S::Generation>,
        operation: &'q W,
    ) -> Result<Covered<'q, S>, ReadFailure<S::Error>> {
        let owner = signature.owner();
        if !core::ptr::eq(owner.value.session, self.session) || owner.value.stamp != self.stamp {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: signature.location(),
            }
            .into());
        }
        let reader = RangeReader::new(self.source, self.session, operation)?;
        if reader.stamp() != self.stamp {
            return Err(crate::range::InputError::Changed {
                location: signature.location(),
            }
            .into());
        }
        Ok(Covered {
            reader,
            ranges: &signature.entry.ranges,
        })
    }
    /// Reads signature Contents as decoded bytes with independent actual
    /// capacity ownership. This retains padding: VRI names hash the complete
    /// decoded value, while CMS parsing separately identifies its DER extent.
    pub async fn contents<W: Work>(
        &self,
        signature: Signature<'_, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<OwnedVec<u8, Memory>, ReadFailure<S::Error>> {
        let owner = signature.owner();
        self.string(owner, signature.entry.contents, usize::MAX, operation)
            .await
    }
}
