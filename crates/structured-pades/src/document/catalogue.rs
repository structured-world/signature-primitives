//! Physical census and indexed compressed signatures use the same value parser.

use super::{Document, Reading};
use crate::arena::{Arena, Kind};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, get, named, required, unsigned};
use crate::object::Value;
use crate::range::RangeSource;
use crate::signature::{Catalogue, inspect, inspect_part};
use crate::syntax::{Cursor, read_into};
use crate::xref::Target;
use structured_asn1::memory::{OwnedVec, SortError, Work};

struct Census<'a, 's, D, G, W: Work> {
    readings: &'a mut OwnedVec<Reading<'s, D, G>, W>,
    signatures: &'a mut OwnedVec<crate::signature::Entry, W>,
    failures: &'a mut OwnedVec<crate::signature::Failure, W>,
    order: &'a mut OwnedVec<crate::signature::Position, W>,
    definitions: &'a mut OwnedVec<crate::signature::Definition, W>,
}

#[derive(Clone, Copy)]
struct Physical {
    start: u64,
    revision: usize,
    xref_stream: bool,
}

struct Scan<'a> {
    table: Option<&'a super::Section>,
    revision: Option<usize>,
    ignored_footer: Option<u64>,
    xref_stream: bool,
}

struct Expected {
    offset: u64,
    number: u64,
    generation: u16,
    member: Option<(u64, u64)>,
    location: crate::source::Location,
    found: bool,
}

impl<S: RangeSource> Document<'_, S> {
    fn expected<W: Work>(&self, work: &W) -> crate::Result<OwnedVec<Expected, W>> {
        let mut expected = work.vector();
        for entry in &self.entries {
            admit(work, entry.location, 1)?;
            let generation = match entry.target {
                Target::File { generation, .. } => generation,
                Target::Compressed { .. } => 0,
                _ => continue,
            };
            if self.target(entry.revision, entry.number, generation, work)? != Some(entry.target) {
                continue;
            }
            let (offset, number, generation, member) = match entry.target {
                Target::File { offset, generation } => (offset, entry.number, generation, None),
                Target::Compressed { stream, index } => {
                    let Some(Target::File {
                        offset,
                        generation: 0,
                    }) = self.target(entry.revision, stream, 0, work)?
                    else {
                        return Err(Error {
                            kind: ErrorKind::Syntax(Syntax::CrossReference),
                            location: entry.location,
                        });
                    };
                    (offset, stream, 0, Some((index, entry.number)))
                }
                _ => unreachable!("only selected file/compressed rows"),
            };
            expected
                .try_push(Expected {
                    offset,
                    number,
                    generation,
                    member,
                    location: entry.location,
                    found: false,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: entry.location,
                })?;
        }
        expected
            .try_sort_unstable_by(|a, b| {
                admit(work, b.location, 1)?;
                Ok::<_, Error>(a.offset.cmp(&b.offset))
            })
            .map_err(|cause| match cause {
                SortError::Comparison(cause) => cause,
                SortError::Resource(cause) => Error {
                    kind: ErrorKind::Resource(cause),
                    location: self.arena.nodes[self.history[0].trailer.0].location,
                },
            })?;
        Ok(expected)
    }
}

fn first_at(expected: &[Expected], offset: u64, work: &impl Work) -> crate::Result<usize> {
    let mut low = 0;
    let mut high = expected.len();
    while low < high {
        let middle = low + (high - low) / 2;
        admit(work, expected[middle].location, 1)?;
        if expected[middle].offset < offset {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

fn check_expected(
    expected: &mut [Expected],
    identity: (u64, u16),
    members: Option<&[super::members::Member]>,
    start: u64,
    work: &impl Work,
) -> crate::Result<()> {
    let mut entry = first_at(expected, start, work)?;
    while entry < expected.len() {
        admit(work, expected[entry].location, 1)?;
        if expected[entry].offset != start {
            break;
        }
        let item = &mut expected[entry];
        if item.number != identity.0 || item.generation != identity.1 {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::CrossReference),
                location: item.location,
            });
        }
        if let Some((index, number)) = item.member {
            let index = usize::try_from(index).map_err(|_| Error {
                kind: ErrorKind::Syntax(Syntax::CrossReference),
                location: item.location,
            })?;
            if members.is_none_or(|members| {
                members
                    .get(index)
                    .is_none_or(|member| member.number != number)
            }) {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::CrossReference),
                    location: item.location,
                });
            }
        }
        item.found = true;
        entry += 1;
    }
    Ok(())
}

impl<'s, S: RangeSource> Document<'s, S> {
    async fn physical_reading(
        &self,
        cursor: &mut Cursor<'_, S>,
        revision: usize,
        work: &impl Work,
    ) -> Result<Reading<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let start = cursor.at;
        let (arena, indirect) = crate::stream::open(cursor, Arena::new(work).into_owned()).await?;
        let mut stream = None;
        if let Some(body) = indirect.stream {
            let length = required(&arena, indirect.value, b"Length", work)?;
            let length = match arena.nodes[length.0].kind {
                Kind::Reference { number, generation } => {
                    let value = self
                        .object(revision, number, generation, work)
                        .await?
                        .ok_or_else(|| cursor.failure(Syntax::Stream, body))?;
                    value.value.root().unsigned(work)?
                }
                _ => unsigned(&arena, length, work)?,
            };
            stream = Some(crate::stream::close(cursor, body, length).await?);
        }
        if cursor.at > self.history[revision].facts.end {
            return Err(cursor.failure(Syntax::Object, start));
        }
        let reading = Reading {
            value: Value {
                arena,
                root: indirect.value,
                session: self.session,
                stamp: self.stamp,
                end: cursor.at,
            },
            decoded: None,
            stream,
            number: indirect.number,
            generation: indirect.generation,
            revision,
        };
        Ok(reading)
    }

    fn inspect_members<W: Work>(
        &self,
        group: Reading<'s, S::Document, S::Generation>,
        members: &[super::members::Member],
        location: crate::source::Location,
        census: Census<'_, 's, S::Document, S::Generation, W>,
        work: &impl Work,
    ) -> crate::Result<()> {
        let Census {
            readings,
            signatures,
            failures,
            order,
            definitions,
        } = census;
        let revision = group.revision;
        let before = order.len();
        for member in members {
            admit(work, location, 1)?;
            let location = group.value.arena.nodes[member.root.0].location;
            definitions
                .try_push(crate::signature::Definition {
                    identity: (member.number, 0),
                    location,
                    encoded: location,
                    revision,
                    kind: crate::signature::DefinitionKind::Object,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            inspect_part(
                self,
                &group,
                readings.len(),
                member.nodes.clone(),
                (member.number, 0),
                crate::signature::Inspection {
                    entries: signatures,
                    failures,
                    order,
                },
                work,
            )?;
        }
        if order.len() != before {
            readings.try_push(group).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        Ok(())
    }

    async fn census_object<W: Work>(
        &self,
        cursor: &mut Cursor<'_, S>,
        point: Physical,
        census: Census<'_, 's, S::Document, S::Generation, W>,
        expected: &mut [Expected],
        work: &impl Work,
    ) -> Result<(), ReadFailure<S::Error>> {
        let Physical {
            start,
            revision,
            xref_stream,
        } = point;
        let Census {
            readings,
            signatures,
            failures,
            order,
            definitions,
        } = census;
        let reading = self.physical_reading(cursor, revision, work).await?;
        let mut object_stream = false;
        if reading.stream.is_some()
            && let Some(kind) = get(&reading.value.arena, reading.value.root, b"Type", work)?
        {
            object_stream = if let Kind::Reference { number, generation } =
                reading.value.arena.nodes[kind.0].kind
            {
                let kind = self.object(revision, number, generation, work).await?;
                if let Some(kind) = kind {
                    kind.value.root().name_equals(b"ObjStm", work)?
                } else {
                    false
                }
            } else {
                named(&reading.value.arena, kind, b"ObjStm", work)?
            };
        }
        let members = if object_stream {
            self.all_members(&reading, work).await?
        } else {
            None
        };
        definitions
            .try_push(crate::signature::Definition {
                identity: (reading.number, reading.generation),
                location: reading.value.root().location(),
                encoded: cursor.location(start, cursor.at - start),
                revision,
                kind: if xref_stream {
                    crate::signature::DefinitionKind::CrossReference
                } else if object_stream {
                    crate::signature::DefinitionKind::ObjectStream
                } else {
                    crate::signature::DefinitionKind::Object
                },
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.location(start, 0),
            })?;
        check_expected(
            expected,
            (reading.number, reading.generation),
            members.as_ref().map(|(_, values)| &values[..]),
            start,
            work,
        )?;
        let before = order.len();
        inspect(
            self,
            &reading,
            readings.len(),
            signatures,
            failures,
            order,
            work,
        )?;
        if order.len() != before {
            readings.try_push(reading).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.location(start, 0),
            })?;
        }
        if let Some((group, members)) = members {
            self.inspect_members(
                group,
                &members,
                cursor.location(start, 0),
                Census {
                    readings,
                    signatures,
                    failures,
                    order,
                    definitions,
                },
                work,
            )?;
        }
        Ok(())
    }

    fn scan_point(
        &self,
        start: u64,
        location: crate::source::Location,
        seen: &mut [bool],
        work: &impl Work,
    ) -> crate::Result<Scan<'_>> {
        let mut table = None;
        let mut revision = None;
        let mut ignored_footer = None;
        let mut xref_stream = false;
        for (ordinal, section) in self.sections.iter().enumerate() {
            admit(work, location, 1)?;
            if section.offset == start {
                seen[ordinal] = true;
                if section.table {
                    table = Some(section);
                } else {
                    xref_stream = true;
                }
            }
            if let Some((at, end)) = section.ignored_footer
                && at == start
            {
                ignored_footer = Some(end);
            }
        }
        for (ordinal, historical) in self.history.iter().enumerate() {
            admit(work, location, 1)?;
            if revision.is_none() && start < historical.facts.end {
                revision = Some(ordinal);
            }
        }
        Ok(Scan {
            table,
            revision,
            ignored_footer,
            xref_stream,
        })
    }

    async fn census_trailer<W: Work>(
        &self,
        cursor: &mut Cursor<'_, S>,
        section: &super::Section,
        revision: Option<usize>,
        start: u64,
        census: Census<'_, 's, S::Document, S::Generation, W>,
        work: &impl Work,
    ) -> Result<(), ReadFailure<S::Error>> {
        let Census {
            readings,
            signatures,
            failures,
            order,
            definitions: _,
        } = census;
        cursor.at = section.trailer.span().start;
        let (arena, root) = read_into(cursor, self.session, Arena::new(work).into_owned()).await?;
        if cursor.at != section.end {
            return Err(cursor.failure(Syntax::CrossReference, cursor.at));
        }
        let reading = Reading {
            value: Value {
                arena,
                root,
                session: self.session,
                stamp: self.stamp,
                end: cursor.at,
            },
            decoded: None,
            stream: None,
            number: 0,
            generation: 0,
            revision: revision.ok_or_else(|| cursor.failure(Syntax::Trailer, start))?,
        };
        let before = order.len();
        inspect(
            self,
            &reading,
            readings.len(),
            signatures,
            failures,
            order,
            work,
        )?;
        if order.len() != before {
            readings.try_push(reading).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.location(start, 0),
            })?;
        }
        Ok(())
    }

    fn check_census(
        &self,
        cursor: &Cursor<'_, S>,
        seen: &[bool],
        expected: &[Expected],
        work: &impl Work,
    ) -> Result<(), ReadFailure<S::Error>> {
        for (ordinal, &encountered) in seen.iter().enumerate() {
            admit(work, cursor.location(self.sections[ordinal].offset, 0), 1)?;
            if !encountered {
                return Err(cursor.failure(Syntax::CrossReference, self.sections[ordinal].offset));
            }
        }
        for item in expected {
            admit(work, item.location, 1)?;
            if !item.found {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::CrossReference),
                    location: item.location,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Enumerates physical signature dictionaries, including definitions not
    /// selected by the latest xref, and historically indexed compressed values.
    /// Stream payload bytes are skipped by their resolved Length, never scanned
    /// for apparent `obj` or signature text inside binary/string content.
    pub async fn catalogue<W: Work>(
        &self,
        operation: &W,
    ) -> Result<Catalogue<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let reader = self.original_reader(operation)?;
        let work = reader.execution();
        let mut cursor = Cursor { reader, at: 0 };
        let mut readings = work.vector();
        let mut signatures = work.vector();
        let mut failures = work.vector();
        let mut order = work.vector();
        let mut definitions = work.vector();
        let mut expected = self.expected(&work)?;
        let mut seen = work.vector();
        for _ in &self.sections {
            seen.try_push(false).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.location(0, 0),
            })?;
        }
        while cursor.at < self.stamp.length {
            cursor.skip().await?;
            if cursor.peek().await?.is_none() {
                break;
            }
            let start = cursor.at;
            let Scan {
                table,
                revision,
                ignored_footer,
                xref_stream,
            } = self.scan_point(start, cursor.location(start, 0), &mut seen, &work)?;
            if let Some(end) = ignored_footer {
                cursor.at = end;
                continue;
            }
            if let Some(section) = table {
                self.census_trailer(
                    &mut cursor,
                    section,
                    revision,
                    start,
                    Census {
                        readings: &mut readings,
                        signatures: &mut signatures,
                        failures: &mut failures,
                        order: &mut order,
                        definitions: &mut definitions,
                    },
                    &work,
                )
                .await?;
                continue;
            }
            if cursor.looking(b"startxref").await? {
                cursor.keyword(b"startxref").await?;
                cursor.space().await?;
                let offset = cursor.natural().await?;
                let end = super::finish_footer(&mut cursor).await?;
                let mut found = false;
                for historical in &self.history {
                    admit(&work, cursor.location(start, 0), 1)?;
                    if historical.facts.xref == offset && historical.facts.end == end {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(cursor.failure(Syntax::StartXref, start));
                }
                continue;
            }
            let revision = revision.ok_or_else(|| cursor.failure(Syntax::Object, start))?;
            self.census_object(
                &mut cursor,
                Physical {
                    start,
                    revision,
                    xref_stream,
                },
                Census {
                    readings: &mut readings,
                    signatures: &mut signatures,
                    failures: &mut failures,
                    order: &mut order,
                    definitions: &mut definitions,
                },
                &mut expected,
                &work,
            )
            .await?;
        }
        self.check_census(&cursor, &seen, &expected, &work)?;
        cursor.reader.check(cursor.location(0, self.stamp.length))?;
        Ok(Catalogue {
            readings: readings.into_owned(),
            entries: signatures.into_owned(),
            failures: failures.into_owned(),
            order: order.into_owned(),
            definitions: definitions.into_owned(),
        })
    }
}
