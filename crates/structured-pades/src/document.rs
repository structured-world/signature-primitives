//! Immutable PDF revision index over caller-owned original range acquisition.

mod catalogue;
mod compare;
mod controls;
mod graph;
mod members;
pub(crate) mod resolve;
#[cfg(test)]
mod tests;
pub(crate) use graph::Key as GraphKey;
pub use graph::{Graph, GraphMembers, GraphObject};
pub use resolve::Reading;

use crate::Session;
use crate::arena::{Arena, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, get, unsigned};
use crate::range::{RangeReader, RangeSource, Stamp};
use crate::source::{Location, Source};
use crate::syntax::Cursor;
use crate::xref::{Entry, Target};
use structured_asn1::memory::{Memory, OwnedVec, SortError, Work};

/// Historical trailer and exact terminal record belonging to one update.
#[derive(Debug, Clone, Copy)]
pub struct Revision {
    /// Absolute original offset of the primary cross-reference section.
    pub xref: u64,
    /// First byte following this update's `%%EOF` line.
    pub end: u64,
}

struct Historical {
    facts: Revision,
    trailer: NodeId,
}

struct Section {
    offset: u64,
    end: u64,
    trailer: crate::source::Location,
    table: bool,
    ignored_footer: Option<(u64, u64)>,
}

/// A source-bound immutable index. Reading metadata is distinct from checking
/// signatures or accepting document permissions and certificate trust.
pub struct Document<'s, S: RangeSource> {
    pub(crate) source: &'s S,
    pub(crate) session: &'s Session,
    pub(crate) stamp: Stamp<S::Document, S::Generation>,
    arena: Arena<Memory>,
    history: OwnedVec<Historical, Memory>,
    entries: OwnedVec<Entry, Memory>,
    sections: OwnedVec<Section, Memory>,
}

#[derive(Clone, Copy)]
struct Forward {
    main: u64,
    upper: u64,
    start_entries: usize,
    section_end: u64,
    primary: usize,
    revision: usize,
    location: Location,
}
struct Records<'a, W: Work> {
    entries: &'a mut OwnedVec<Entry, W>,
    sections: &'a mut OwnedVec<Section, W>,
    lengths: &'a mut OwnedVec<crate::xref::DeferredLength, W>,
}
impl<W: Work> Records<'_, W> {
    fn reborrow(&mut self) -> Records<'_, W> {
        Records {
            entries: self.entries,
            sections: self.sections,
            lengths: self.lengths,
        }
    }
}

async fn forward<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    mut arena: Arena<Memory>,
    records: Records<'_, W>,
    context: Forward,
    work: &impl Work,
) -> Result<(Arena<Memory>, u64), ReadFailure<S::Error>> {
    let Forward {
        main,
        upper,
        start_entries,
        section_end,
        primary,
        revision,
        location,
    } = context;
    let Records {
        entries,
        sections,
        lengths,
    } = records;
    // Annex F.3.4/F.3.11 makes a first-page xref point FORWARD
    // to the main xref. They describe one physical revision, not
    // a newer file whose EOF occurs before its own main table.
    if main >= upper {
        return Err(cursor.failure(Syntax::CrossReference, main));
    }
    for entry in &mut entries[start_entries..] {
        admit(work, entry.location, 1)?;
        entry.priority += 2;
    }
    cursor.at = section_end;
    cursor.skip().await?;
    if cursor.looking(b"startxref").await? {
        let start = cursor.at;
        cursor.keyword(b"startxref").await?;
        cursor.space().await?;
        cursor.natural().await?;
        let end = finish_footer(cursor).await?;
        sections[primary].ignored_footer = Some((start, end));
    }
    cursor.at = main;
    let table = cursor.looking(b"xref").await?;
    let (next, main_section) = if table {
        crate::xref::table(cursor, arena, entries, revision, 0).await?
    } else {
        crate::xref::stream(cursor, arena, entries, revision, 0).await?
    };
    arena = next;
    if main_section.previous.is_some() {
        return Err(cursor.failure(Syntax::Cycle, main));
    }
    sections
        .try_push(Section {
            offset: main,
            end: main_section.end,
            trailer: arena.nodes[main_section.trailer.0].location,
            table,
            ignored_footer: None,
        })
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    if let Some(length) = main_section.length {
        lengths.try_push(length).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: length.location,
        })?;
    }
    if let Some(hybrid) = main_section.hybrid {
        if hybrid >= upper {
            return Err(cursor.failure(Syntax::CrossReference, hybrid));
        }
        cursor.at = hybrid;
        let (next, supplement) = crate::xref::stream(cursor, arena, entries, revision, 1).await?;
        arena = next;
        if supplement.hybrid.is_some() {
            return Err(cursor.failure(Syntax::CrossReference, hybrid));
        }
        sections
            .try_push(Section {
                offset: hybrid,
                end: supplement.end,
                trailer: arena.nodes[supplement.trailer.0].location,
                table: false,
                ignored_footer: None,
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        if let Some(length) = supplement.length {
            lengths.try_push(length).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: length.location,
            })?;
        }
    }
    Ok((arena, main_section.end))
}

#[derive(Clone, Copy)]
struct Supplement {
    hybrid: u64,
    upper: u64,
    revision: usize,
    location: Location,
}

async fn supplement<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    mut arena: Arena<Memory>,
    records: Records<'_, W>,
    context: Supplement,
) -> Result<Arena<Memory>, ReadFailure<S::Error>> {
    let Supplement {
        hybrid,
        upper,
        revision,
        location,
    } = context;
    let Records {
        entries,
        sections,
        lengths,
    } = records;
    if hybrid >= upper {
        return Err(cursor.failure(Syntax::CrossReference, hybrid));
    }
    cursor.at = hybrid;
    let (next, supplemental) = crate::xref::stream(cursor, arena, entries, revision, 1).await?;
    arena = next;
    sections
        .try_push(Section {
            offset: hybrid,
            end: supplemental.end,
            trailer: arena.nodes[supplemental.trailer.0].location,
            table: false,
            ignored_footer: None,
        })
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    if let Some(length) = supplemental.length {
        lengths.try_push(length).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: length.location,
        })?;
    }
    // The table trailer owns Prev. A supplementary stream must
    // not redirect the primary history chain (§7.5.8.4).
    if supplemental.hybrid.is_some() {
        return Err(cursor.failure(Syntax::CrossReference, hybrid));
    }
    Ok(arena)
}

fn save_section<W: Work>(
    sections: &mut OwnedVec<Section, W>,
    lengths: &mut OwnedVec<crate::xref::DeferredLength, W>,
    arena: &Arena<Memory>,
    section: crate::xref::Section,
    (offset, table): (u64, bool),
    location: Location,
) -> crate::Result<()> {
    sections
        .try_push(Section {
            offset,
            end: section.end,
            trailer: arena.nodes[section.trailer.0].location,
            table,
            ignored_footer: None,
        })
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    if let Some(length) = section.length {
        lengths.try_push(length).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: length.location,
        })?;
    }
    Ok(())
}

struct RevisionTail {
    offset: u64,
    final_section_end: u64,
    final_end: Option<u64>,
    trailer: NodeId,
}

async fn revision_tail<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    arena: &Arena<Memory>,
    sections: &[Section],
    tail: RevisionTail,
    work: &impl Work,
) -> Result<Historical, ReadFailure<S::Error>> {
    let RevisionTail {
        offset,
        final_section_end,
        final_end,
        trailer,
    } = tail;
    let location = cursor.location(offset, 0);
    cursor.at = final_section_end;
    let end = footer(cursor, offset).await?;
    for section in sections {
        admit(work, section.trailer, 1)?;
        if section.end > end {
            return Err(cursor.failure(Syntax::CrossReference, section.offset));
        }
    }
    if final_end.is_some_and(|expected| end != expected) {
        return Err(cursor.failure(Syntax::StartXref, end));
    }
    if get(arena, trailer, b"Encrypt", work)?.is_some() {
        return Err(Error {
            kind: ErrorKind::Unsupported(crate::error::Unsupported::Encryption),
            location,
        }
        .into());
    }
    Ok(Historical {
        facts: Revision { xref: offset, end },
        trailer,
    })
}

struct Primary {
    offset: u64,
    upper: u64,
    start_entries: usize,
    section_index: usize,
    revision: usize,
    location: Location,
}
struct Advanced {
    arena: Arena<Memory>,
    historical: Historical,
    forward: Option<u64>,
}

async fn advance_revision<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    mut arena: Arena<Memory>,
    records: Records<'_, W>,
    context: Primary,
    section: crate::xref::Section,
    expected_end: Option<u64>,
    work: &impl Work,
) -> Result<Advanced, ReadFailure<S::Error>> {
    let Records {
        entries,
        sections,
        lengths,
    } = records;
    let Primary {
        offset,
        upper,
        start_entries,
        section_index: primary,
        revision,
        location,
    } = context;
    let mut final_section_end = section.end;
    let forward = section.previous.filter(|&previous| previous > offset);
    if let Some(main) = forward {
        (arena, final_section_end) = self::forward(
            cursor,
            arena,
            Records {
                entries,
                sections,
                lengths,
            },
            Forward {
                main,
                upper,
                start_entries,
                section_end: section.end,
                primary,
                revision,
                location,
            },
            work,
        )
        .await?;
    }
    let historical = revision_tail(
        cursor,
        &arena,
        &sections[primary..],
        RevisionTail {
            offset,
            final_section_end,
            final_end: expected_end,
            trailer: section.trailer,
        },
        work,
    )
    .await?;
    Ok(Advanced {
        arena,
        historical,
        forward,
    })
}

async fn primary_section<S: RangeSource, W: Work>(
    cursor: &mut Cursor<'_, S>,
    arena: Arena<Memory>,
    records: Records<'_, W>,
    offset: u64,
    revision: usize,
) -> Result<(Arena<Memory>, crate::xref::Section), ReadFailure<S::Error>> {
    // Both xref spellings share the source-qualified dictionary decoder.
    let table = cursor.looking(b"xref").await?;
    let (arena, section) = if table {
        crate::xref::table(cursor, arena, records.entries, revision, 0).await?
    } else {
        crate::xref::stream(cursor, arena, records.entries, revision, 0).await?
    };
    save_section(
        records.sections,
        records.lengths,
        &arena,
        section,
        (offset, table),
        cursor.location(offset, 0),
    )?;
    Ok((arena, section))
}

fn chronological<W: Work>(
    history: &mut [Historical],
    entries: &mut OwnedVec<Entry, W>,
    location: Location,
    work: &impl Work,
) -> crate::Result<()> {
    // Wire discovery is newest-first. Exposed revision ordinals are
    // chronological; each row is remapped once before building the index.
    let count = history.len();
    admit(work, location, count as u64)?;
    history.reverse();
    for entry in &mut **entries {
        admit(work, entry.location, 1)?;
        entry.revision = count - 1 - entry.revision;
        if let Source::Decoded {
            stream,
            revision,
            stage,
        } = entry.location.source()
        {
            let span = entry.location.span();
            entry.location = Location::new(
                Source::Decoded {
                    stream,
                    revision: count - 1 - revision,
                    stage,
                },
                span.start,
                span.length,
            )
            .expect("unchanged validated decoded extent");
        }
    }
    entries
        .try_sort_unstable_by(|left, right| {
            admit(work, right.location, 1)?;
            Ok::<_, Error>(
                left.number
                    .cmp(&right.number)
                    .then_with(|| left.revision.cmp(&right.revision))
                    .then_with(|| left.priority.cmp(&right.priority)),
            )
        })
        .map_err(|error| match error {
            SortError::Resource(cause) => Error {
                kind: ErrorKind::Resource(cause),
                location,
            },
            SortError::Comparison(error) => error,
        })?;
    // Duplicated entries in one revision have no unique resolver result.
    // Hybrid precedence is applied by its stream reader before this gate.
    for pair in entries.windows(2) {
        admit(work, pair[1].location, 1)?;
        if pair[0].number == pair[1].number
            && pair[0].revision == pair[1].revision
            && pair[0].priority == pair[1].priority
        {
            return Err(Error {
                kind: ErrorKind::Ambiguous(Syntax::CrossReference),
                location: pair[1].location,
            });
        }
    }
    Ok(())
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Follows the declared cross-reference history without reconstructing or
    /// repairing offsets. Every await retains current and original execution.
    ///
    /// # Panics
    /// Panics if internally reassigning a historical ordinal invalidates an
    /// already checked decoded extent.
    pub async fn read<W: Work>(
        source: &'s S,
        session: &'s Session,
        operation: &W,
    ) -> Result<Self, ReadFailure<S::Error>> {
        let reader = RangeReader::new(source, session, operation)?;
        let stamp = reader.stamp();
        let work = reader.execution();
        let mut cursor = Cursor { reader, at: 0 };
        header(&mut cursor).await?;
        let (mut offset, final_end) = terminal(&mut cursor).await?;
        let mut upper = stamp.length;
        let mut arena = Arena::new(&work).into_owned();
        let mut history = work.vector();
        let mut entries = work.vector();
        let mut lengths = work.vector();
        let mut sections = work.vector();
        let mut records = Records {
            entries: &mut entries,
            sections: &mut sections,
            lengths: &mut lengths,
        };
        loop {
            let location = cursor.location(offset, 0);
            session.revision(location)?;
            if offset >= upper {
                return Err(cursor.failure(Syntax::Cycle, offset));
            }
            cursor.at = offset;
            let start_entries = records.entries.len();
            let primary = records.sections.len();
            let (next, section) = primary_section(
                &mut cursor,
                arena,
                records.reborrow(),
                offset,
                history.len(),
            )
            .await?;
            arena = next;
            if let Some(hybrid) = section.hybrid {
                arena = supplement(
                    &mut cursor,
                    arena,
                    records.reborrow(),
                    Supplement {
                        hybrid,
                        upper,
                        revision: history.len(),
                        location,
                    },
                )
                .await?;
            }
            let Advanced {
                arena: next,
                historical,
                forward,
            } = advance_revision(
                &mut cursor,
                arena,
                records.reborrow(),
                Primary {
                    offset,
                    upper,
                    start_entries,
                    section_index: primary,
                    revision: history.len(),
                    location,
                },
                section,
                if history.is_empty() {
                    Some(final_end)
                } else {
                    None
                },
                &work,
            )
            .await?;
            arena = next;
            history.try_push(historical).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            let Some(previous) = section.previous.filter(|_| forward.is_none()) else {
                break;
            };
            upper = offset;
            offset = previous;
        }
        chronological(&mut history, &mut entries, cursor.location(0, 0), &work)?;
        cursor.reader.check(cursor.location(0, stamp.length))?;
        let document = Self {
            source,
            session,
            stamp,
            arena,
            history: history.into_owned(),
            entries: entries.into_owned(),
            sections: sections.into_owned(),
        };
        document.validate_lengths(&lengths, &work).await?;
        Ok(document)
    }

    async fn validate_lengths<W: Work>(
        &self,
        lengths: &[crate::xref::DeferredLength],
        work: &W,
    ) -> Result<(), ReadFailure<S::Error>> {
        let count = self.history.len();
        for length in lengths {
            admit(work, length.location, 1)?;
            let owner = self
                .object(
                    count - 1 - length.revision,
                    length.number,
                    length.generation,
                    work,
                )
                .await?
                .ok_or(Error {
                    kind: ErrorKind::Syntax(Syntax::Stream),
                    location: length.location,
                })?;
            if owner.stream.is_some()
                || unsigned(&owner.value.arena, owner.value.root, work)? != length.actual
            {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Stream),
                    location: length.location,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Original immutable document identity used by every revision query.
    #[must_use]
    pub fn stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.stamp
    }

    pub(crate) fn check(
        &self,
        operation: &impl Work,
        location: Location,
    ) -> Result<(), crate::range::InputError<S::Error>> {
        self.session
            .query(operation)
            .charge_work(1)
            .map_err(|cause| crate::range::InputError::Resource { location, cause })?;
        if self.source.stamp() != self.stamp {
            return Err(crate::range::InputError::Changed { location });
        }
        Ok(())
    }

    fn original_reader<'q, W: Work>(
        &'q self,
        operation: &'q W,
    ) -> Result<RangeReader<'q, S>, crate::range::InputError<S::Error>> {
        let reader = RangeReader::new(self.source, self.session, operation)?;
        if reader.stamp() != self.stamp {
            return Err(crate::range::InputError::Changed {
                location: reader.location(0, 0),
            });
        }
        Ok(reader)
    }

    pub(crate) async fn string<W: Work>(
        &self,
        owner: &Reading<'_, S::Document, S::Generation>,
        node: NodeId,
        maximum: usize,
        operation: &W,
    ) -> Result<OwnedVec<u8, Memory>, ReadFailure<S::Error>> {
        self.string_in(owner, owner.decoded.as_deref(), node, maximum, operation)
            .await
    }

    pub(crate) async fn string_in<W: Work>(
        &self,
        owner: &Reading<'_, S::Document, S::Generation>,
        decoded: Option<&[u8]>,
        node: NodeId,
        maximum: usize,
        operation: &W,
    ) -> Result<OwnedVec<u8, Memory>, ReadFailure<S::Error>> {
        let original = owner.value.arena.nodes[node.0];
        let crate::arena::Kind::String(form) = original.kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::String),
                location: original.location,
            }
            .into());
        };
        if !core::ptr::eq(owner.value.session, self.session) || owner.value.stamp != self.stamp {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: original.location,
            }
            .into());
        }
        self.check(operation, original.location)?;
        let body = structured_asn1::Span {
            start: original.location.span().start + 1,
            length: original.location.span().length - 2,
        };
        let output = if let Some(decoded) = decoded {
            if original.location.source() == Source::File {
                return Err(Error {
                    kind: ErrorKind::Foreign,
                    location: original.location,
                }
                .into());
            }
            let slice = crate::range::Slice::new(decoded, self.stamp.snapshot);
            let mut reader =
                RangeReader::in_source(&slice, self.session, operation, original.location.source())
                    .map_err(|cause| resolve::convert(ReadFailure::Input(cause)))?;
            reader
                .decode_bytes_limit(body, form, maximum)
                .await
                .map_err(resolve::convert)?
                .into_owned()
        } else {
            if original.location.source() != Source::File {
                return Err(Error {
                    kind: ErrorKind::Foreign,
                    location: original.location,
                }
                .into());
            }
            let mut reader = RangeReader::new(self.source, self.session, operation)?;
            reader
                .decode_bytes_limit(body, form, maximum)
                .await?
                .into_owned()
        };
        self.check(operation, original.location)?;
        Ok(output)
    }

    /// Number of chronological incremental revisions.
    #[must_use]
    pub fn revisions(&self) -> usize {
        self.history.len()
    }

    /// Fixed-size revision metadata. The caller must still check the live
    /// snapshot when executing a source-dependent verification operation.
    #[must_use]
    pub fn revision(&self, ordinal: usize) -> Option<Revision> {
        self.history.get(ordinal).map(|entry| entry.facts)
    }

    pub(crate) async fn root<W: Work>(
        &self,
        revision: usize,
        operation: &W,
    ) -> Result<Reading<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let Some(historical) = self.history.get(revision) else {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: Location::new(Source::File, 0, 0).expect("file point"),
            }
            .into());
        };
        let root = crate::model::required(&self.arena, historical.trailer, b"Root", &work)?;
        let crate::arena::Kind::Reference { number, generation } = self.arena.nodes[root.0].kind
        else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Trailer),
                location: self.arena.nodes[root.0].location,
            }
            .into());
        };
        self.object(revision, number, generation, &work)
            .await?
            .ok_or(
                Error {
                    kind: ErrorKind::Syntax(Syntax::Trailer),
                    location: self.arena.nodes[root.0].location,
                }
                .into(),
            )
    }

    pub(crate) async fn select<W: Work>(
        &self,
        mut owner: Reading<'s, S::Document, S::Generation>,
        key: &[u8],
        operation: &W,
    ) -> Result<Option<Reading<'s, S::Document, S::Generation>>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let Some(node) = get(&owner.value.arena, owner.value.root, key, &work)? else {
            return Ok(None);
        };
        if matches!(
            owner.value.arena.nodes[node.0].kind,
            crate::arena::Kind::Reference { .. }
        ) {
            match self.resolve_value(&owner, node, &work).await? {
                Some(resolve::ResolvedValue::Owned(value)) => Ok(Some(value)),
                None => Ok(None),
                Some(resolve::ResolvedValue::Borrowed { .. }) => {
                    unreachable!("an indirect selection owns its resolved reading")
                }
            }
        } else {
            owner.value.root = node;
            owner.stream = None;
            Ok(Some(owner))
        }
    }

    pub(crate) fn target(
        &self,
        revision: usize,
        number: u64,
        generation: u16,
        operation: &impl Work,
    ) -> crate::Result<Option<Target>> {
        let location = Location::new(Source::File, 0, 0).expect("file point");
        if revision >= self.history.len() {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        let work = self.session.query(operation);
        let mut low = 0;
        let mut high = self.entries.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.entries[middle];
            admit(&work, entry.location, 1)?;
            if entry.number < number || (entry.number == number && entry.revision <= revision) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == 0 {
            return Ok(None);
        }
        let entry = self.entries[low - 1];
        admit(&work, entry.location, 1)?;
        if entry.number != number {
            return Ok(None);
        }
        Ok(match entry.target {
            Target::File {
                generation: actual, ..
            } if generation == actual => Some(entry.target),
            Target::Compressed { .. } if generation == 0 => Some(entry.target),
            _ => None,
        })
    }
}

async fn header<S: RangeSource>(cursor: &mut Cursor<'_, S>) -> Result<(), ReadFailure<S::Error>> {
    if !cursor.looking(b"%PDF-1.").await? {
        return Err(cursor.failure(Syntax::Header, 0));
    }
    cursor.at = 7;
    if !matches!(cursor.take().await?, Some(b'0'..=b'7'))
        || !matches!(cursor.take().await?, Some(b'\r' | b'\n'))
    {
        return Err(cursor.failure(Syntax::Header, cursor.at));
    }
    Ok(())
}

async fn terminal<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
) -> Result<(u64, u64), ReadFailure<S::Error>> {
    // Search from EOF, not a caller-chosen fixed tail window. Work is admitted
    // by each access, and the cache makes reverse access a bounded range read.
    let mut at = cursor.reader.stamp().length;
    while at > 0 {
        at -= 1;
        if cursor.reader.byte_at(at).await? != Some(b's') {
            continue;
        }
        cursor.at = at;
        if !cursor.looking(b"startxref").await? {
            continue;
        }
        cursor.keyword(b"startxref").await?;
        cursor.space().await?;
        let offset = cursor.natural().await?;
        let end = finish_footer(cursor).await?;
        cursor.space().await?;
        if cursor.peek().await?.is_some() {
            return Err(cursor.failure(Syntax::StartXref, cursor.at));
        }
        return Ok((offset, end));
    }
    Err(cursor.failure(Syntax::StartXref, 0))
}

async fn footer<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    expected: u64,
) -> Result<u64, ReadFailure<S::Error>> {
    cursor.skip().await?;
    cursor.keyword(b"startxref").await?;
    cursor.space().await?;
    let at = cursor.at;
    if cursor.natural().await? != expected {
        return Err(cursor.failure(Syntax::StartXref, at));
    }
    finish_footer(cursor).await
}

async fn finish_footer<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
) -> Result<u64, ReadFailure<S::Error>> {
    cursor.space().await?;
    if !cursor.looking(b"%%EOF").await? {
        return Err(cursor.failure(Syntax::StartXref, cursor.at));
    }
    cursor.at += 5;
    match cursor.peek().await? {
        Some(b'\r') => {
            cursor.at += 1;
            if cursor.peek().await? == Some(b'\n') {
                cursor.at += 1;
            }
        }
        Some(b'\n') => cursor.at += 1,
        None => {}
        _ => return Err(cursor.failure(Syntax::StartXref, cursor.at)),
    }
    Ok(cursor.at)
}
