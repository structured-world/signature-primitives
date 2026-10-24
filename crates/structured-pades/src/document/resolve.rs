//! Iterative dependency frames for stream lengths and compressed members.

use super::Document;
use crate::arena::{Arena, Kind, NodeId};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, required, unsigned};
use crate::object::Value;
use crate::range::{RangeReader, RangeSource};
use crate::source::Location;
use crate::stream::Indirect;
use crate::syntax::Cursor;
use crate::xref::Target;
use structured_asn1::{
    Span,
    memory::{Memory, OwnedVec, Work},
};

/// Independently retained object metadata and any decoded source storage.
/// Encoded file strings remain ranges in the immutable original document.
pub struct Reading<'s, D, G> {
    pub(crate) value: Value<'s, D, G>,
    pub(crate) decoded: Option<OwnedVec<u8, Memory>>,
    pub(crate) stream: Option<Span>,
    pub(crate) number: u64,
    pub(crate) generation: u16,
    pub(crate) revision: usize,
}

#[expect(
    clippy::large_enum_variant,
    reason = "direct values borrow their owner while indirect values transfer their existing funded reading without an additional box"
)]
pub(crate) enum ResolvedValue<'a, 's, D, G> {
    Borrowed {
        reading: &'a Reading<'s, D, G>,
        node: NodeId,
    },
    Owned(Reading<'s, D, G>),
}
impl<'s, D, G> ResolvedValue<'_, 's, D, G> {
    pub(crate) fn parts(&self) -> (&Reading<'s, D, G>, NodeId) {
        match self {
            Self::Borrowed { reading, node } => (reading, *node),
            Self::Owned(reading) => (reading, reading.value.root),
        }
    }
}

impl<D: Copy + Eq, G: Copy + Eq> Reading<'_, D, G> {
    /// Parsed original value, without a signature or trust assertion.
    #[must_use]
    pub fn value(&self) -> &Value<'_, D, G> {
        &self.value
    }

    /// Original indirect object number and generation selected by the index.
    #[must_use]
    pub fn identity(&self) -> (u64, u16) {
        (self.number, self.generation)
    }

    /// Historical resolution context for this reading.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }

    /// Encoded stream body in the physical file, excluding delimiters.
    #[must_use]
    pub fn stream(&self) -> Option<Span> {
        self.stream
    }
}

struct Pending<'s, D, G> {
    reading: Reading<'s, D, G>,
    indirect: Indirect,
}

#[expect(
    clippy::large_enum_variant,
    reason = "one funded iterative frame owns its suspended parsing state; per-state boxes would add allocation and rollback boundaries"
)]
enum State<'b, 's, D, G> {
    Start,
    Length(Pending<'s, D, G>),
    Member {
        index: u64,
    },
    Controls {
        controls: super::controls::Controls<'b, 's, D, G>,
        member: Option<(u64, u64)>,
    },
    Reference,
}

struct Frame<'b, 's, D, G> {
    number: u64,
    generation: u16,
    state: State<'b, 's, D, G>,
}

struct Completion<'s, D, G> {
    object: Option<Reading<'s, D, G>>,
}
impl<'s, D, G> Completion<'s, D, G> {
    fn present(value: Reading<'s, D, G>) -> Self {
        Self {
            object: Some(value),
        }
    }
}

struct Resolution<'a, 'q, 'b, 's, S: RangeSource, W: Work> {
    reader: &'a mut RangeReader<'q, S>,
    frames: &'a mut OwnedVec<Frame<'b, 's, S::Document, S::Generation>, W>,
    completed: &'a mut Option<Completion<'s, S::Document, S::Generation>>,
}

#[derive(Clone, Copy)]
enum Request<'b, 's, D, G> {
    Object {
        number: u64,
        generation: u16,
    },
    Stream {
        reading: &'b Reading<'s, D, G>,
        object_stream: bool,
    },
}
#[expect(
    clippy::large_enum_variant,
    reason = "the completed iterative resolver transfers an already owned reading without allocating an output envelope"
)]
enum Output<'s, D, G> {
    Object(Option<Reading<'s, D, G>>),
    Stream(Prepared),
}
pub(super) struct Prepared {
    pub(super) plans: OwnedVec<crate::stream::Step>,
    pub(super) body: Span,
    pub(super) layout: Option<(u64, u64)>,
}
pub(crate) struct Decoded {
    pub(crate) bytes: OwnedVec<u8>,
    pub(crate) body: Span,
    pub(crate) layout: Option<(u64, u64)>,
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// ISO32000-1 §7.3.9: defined null and missing indirect targets have the
    /// same null value. Schema callers decide whether absence is permitted.
    pub(crate) async fn resolve_value<'a, W: Work>(
        &self,
        reading: &'a Reading<'s, S::Document, S::Generation>,
        node: NodeId,
        operation: &W,
    ) -> Result<Option<ResolvedValue<'a, 's, S::Document, S::Generation>>, ReadFailure<S::Error>>
    {
        let work = self.session.query(operation);
        let location = reading.value.root().location();
        self.check(&work, location)?;
        if !core::ptr::eq(reading.value.session, self.session) || reading.value.stamp != self.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        admit(&work, location, 1)?;
        match reading.value.arena.nodes[node.0].kind {
            Kind::Null => Ok(None),
            Kind::Reference { number, generation } => {
                let Some(value) = self
                    .object(reading.revision, number, generation, &work)
                    .await?
                else {
                    return Ok(None);
                };
                admit(&work, value.value.root().location(), 1)?;
                if matches!(value.value.arena.nodes[value.value.root.0].kind, Kind::Null) {
                    return Ok(None);
                }
                Ok(Some(ResolvedValue::Owned(value)))
            }
            _ => Ok(Some(ResolvedValue::Borrowed { reading, node })),
        }
    }

    /// Resolves an indirect identity at a specific revision. Free, unknown,
    /// generation-mismatched and absent references are PDF null (None).
    /// References, stream lengths and object-stream dependencies use explicit
    /// bounded frames; no input-controlled Rust recursion or boxed future.
    pub async fn object<W: Work>(
        &self,
        revision: usize,
        number: u64,
        generation: u16,
        operation: &W,
    ) -> Result<Option<Reading<'s, S::Document, S::Generation>>, ReadFailure<S::Error>> {
        match self
            .resolve(revision, Request::Object { number, generation }, operation)
            .await?
        {
            Output::Object(value) => Ok(value),
            Output::Stream(_) => unreachable!("object resolution request"),
        }
    }

    pub(crate) async fn stream_data<W: Work>(
        &self,
        reading: &Reading<'s, S::Document, S::Generation>,
        object_stream: bool,
        operation: &W,
    ) -> Result<Decoded, ReadFailure<S::Error>> {
        let prepared = self.stream_plan(reading, object_stream, operation).await?;
        let mut reader = RangeReader::new(self.source, self.session, operation)?;
        let location = reading.value.root().location();
        if reader.stamp() != self.stamp {
            return Err(crate::range::InputError::Changed { location }.into());
        }
        let (bytes, _) = crate::stream::execute(
            &mut reader,
            prepared.body,
            &prepared.plans,
            reading.revision,
            true,
        )
        .await?;
        reader.check(location)?;
        Ok(Decoded {
            bytes,
            body: prepared.body,
            layout: prepared.layout,
        })
    }

    pub(super) async fn stream_plan<W: Work>(
        &self,
        reading: &Reading<'s, S::Document, S::Generation>,
        object_stream: bool,
        operation: &W,
    ) -> Result<Prepared, ReadFailure<S::Error>> {
        if !core::ptr::eq(reading.value.session, self.session) || reading.value.stamp != self.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: reading.value.root().location(),
            }
            .into());
        }
        match self
            .resolve(
                reading.revision,
                Request::Stream {
                    reading,
                    object_stream,
                },
                operation,
            )
            .await?
        {
            Output::Stream(value) => Ok(value),
            Output::Object(_) => unreachable!("stream resolution request"),
        }
    }

    async fn load_file<'b, W: Work, Q: Work>(
        &self,
        revision: usize,
        mut frame: Frame<'b, 's, S::Document, S::Generation>,
        offset: u64,
        context: Resolution<'_, '_, 'b, 's, S, W>,
        work: &Q,
    ) -> Result<(), ReadFailure<S::Error>> {
        let Resolution {
            reader,
            frames,
            completed,
        } = context;
        let mut cursor = Cursor {
            reader: reader.fork()?,
            at: offset,
        };
        let (arena, indirect) =
            crate::stream::open(&mut cursor, Arena::new(work).into_owned()).await?;
        if indirect.number != frame.number || indirect.generation != frame.generation {
            return Err(cursor.failure(Syntax::Object, offset));
        }
        let value = Value {
            arena,
            root: indirect.value,
            session: self.session,
            stamp: self.stamp,
            end: cursor.at,
        };
        let reading = Reading {
            value,
            decoded: None,
            stream: None,
            number: frame.number,
            generation: frame.generation,
            revision,
        };
        if indirect.stream.is_some() {
            let length = required(&reading.value.arena, indirect.value, b"Length", work)?;
            if let Kind::Reference { number, generation } = reading.value.arena.nodes[length.0].kind
            {
                frame.state = State::Length(Pending { reading, indirect });
                suspend(
                    frames,
                    frame,
                    (number, generation),
                    self,
                    cursor.location(offset, 0),
                    work,
                )?;
                return Ok(());
            }
            let length = unsigned(&reading.value.arena, length, work)?;
            *completed = Some(Completion::present(
                finish(&mut cursor, Pending { reading, indirect }, length).await?,
            ));
        } else if let Some((number, generation)) = reading.value.root().reference() {
            frame.state = State::Reference;
            suspend(
                frames,
                frame,
                (number, generation),
                self,
                cursor.location(offset, 0),
                work,
            )?;
            return Ok(());
        } else {
            *completed = Some(Completion::present(reading));
        }
        Ok(())
    }

    async fn control<'b, W: Work>(
        &self,
        revision: usize,
        (number, generation): (u64, u16),
        mut controls: super::controls::Controls<'b, 's, S::Document, S::Generation>,
        selected: Option<(u64, u64)>,
        context: Resolution<'_, '_, 'b, 's, S, W>,
        work: &impl Work,
    ) -> Result<Option<Prepared>, ReadFailure<S::Error>> {
        let Resolution {
            reader,
            frames,
            completed,
        } = context;
        let mut frame = Frame {
            number,
            generation,
            state: State::Start,
        };
        if controls.waiting() {
            controls.supply(
                completed
                    .take()
                    .expect("completed control dependency")
                    .object,
                work,
            )?;
        }
        match controls.advance(work) {
            Err(crate::stream::plan::Failure::Fault(error)) => return Err(error.into()),
            Err(crate::stream::plan::Failure::Need { number, generation }) => {
                frame.state = State::Controls {
                    controls,
                    member: selected,
                };
                suspend(
                    frames,
                    frame,
                    (number, generation),
                    self,
                    reader.location(0, 0),
                    work,
                )?;
                return Ok(None);
            }
            Ok(()) => {}
        }
        let location = controls.container.value.root().location();
        let body = controls.container.stream.ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Stream),
            location,
        })?;
        let plans = controls.plans();
        let layout = controls.layout;
        if let Some((_, selected)) = selected {
            let (count, _) = layout.expect("object-stream controls");
            if selected >= count {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Object),
                    location,
                }
                .into());
            }
        }
        if let Some((number, selected)) = selected {
            let (bytes, _) = crate::stream::execute(reader, body, &plans, revision, true).await?;
            drop(plans);
            let (count, first) = layout.expect("object-stream controls");
            let reading = member(
                self,
                reader,
                bytes,
                body,
                (count, first),
                (number, selected),
                revision,
            )
            .await?;
            if let Some((number, generation)) = reading.value.root().reference() {
                frame.state = State::Reference;
                suspend(frames, frame, (number, generation), self, location, work)?;
                return Ok(None);
            }
            *completed = Some(Completion::present(reading));
        } else {
            debug_assert!(frames.is_empty());
            reader.check(location)?;
            return Ok(Some(Prepared {
                plans,
                body,
                layout,
            }));
        }
        Ok(None)
    }

    fn compressed<'b, W: Work>(
        &self,
        revision: usize,
        mut frame: Frame<'b, 's, S::Document, S::Generation>,
        (stream, index): (u64, u64),
        frames: &mut OwnedVec<Frame<'b, 's, S::Document, S::Generation>, W>,
        location: Location,
        work: &impl Work,
    ) -> crate::Result<()> {
        if !matches!(
            self.target(revision, stream, 0, work)?,
            Some(Target::File { .. })
        ) {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location,
            });
        }
        frame.state = State::Member { index };
        suspend(frames, frame, (stream, 0), self, location, work)
    }

    async fn resolve<W: Work>(
        &self,
        revision: usize,
        request: Request<'_, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Output<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let mut reader = self.original_reader(operation)?;
        let work = reader.execution();
        let mut frames = work.vector();
        let frame = initial(request, &work);
        push(&mut frames, frame, self, reader.location(0, 0), &work)?;
        let mut completed = None;
        while let Some(frame) = frames.pop() {
            admit(&work, reader.location(0, 0), 1)?;
            match frame.state {
                State::Start => {
                    match self.target(revision, frame.number, frame.generation, &work)? {
                        None => completed = Some(Completion { object: None }),
                        Some(Target::File { offset, .. }) => {
                            self.load_file(
                                revision,
                                frame,
                                offset,
                                Resolution {
                                    reader: &mut reader,
                                    frames: &mut frames,
                                    completed: &mut completed,
                                },
                                &work,
                            )
                            .await?;
                        }
                        Some(Target::Compressed { stream, index }) => {
                            self.compressed(
                                revision,
                                frame,
                                (stream, index),
                                &mut frames,
                                reader.location(0, 0),
                                &work,
                            )?;
                            continue;
                        }
                        Some(Target::Free { .. } | Target::Null) => {
                            unreachable!("filtered resolver target")
                        }
                    }
                }
                State::Length(pending) => {
                    completed = Some(Completion::present(
                        resolved_length(&reader, pending, completed.take(), &work).await?,
                    ));
                }
                State::Member { index } => {
                    member_controls(
                        frame,
                        index,
                        Resolution {
                            reader: &mut reader,
                            frames: &mut frames,
                            completed: &mut completed,
                        },
                        &work,
                    )?;
                    continue;
                }
                State::Controls {
                    controls,
                    member: selected,
                } => {
                    if let Some(prepared) = self
                        .control(
                            revision,
                            (frame.number, frame.generation),
                            controls,
                            selected,
                            Resolution {
                                reader: &mut reader,
                                frames: &mut frames,
                                completed: &mut completed,
                            },
                            &work,
                        )
                        .await?
                    {
                        return Ok(Output::Stream(prepared));
                    }
                }
                State::Reference => {
                    debug_assert!(completed.is_some());
                }
            }
            if frames.is_empty() {
                reader.check(reader.location(0, self.stamp.length))?;
                return Ok(Output::Object(
                    completed.expect("completed root frame").object,
                ));
            }
        }
        unreachable!("initial root frame")
    }
}

async fn resolved_length<'s, S: RangeSource>(
    reader: &RangeReader<'_, S>,
    pending: Pending<'s, S::Document, S::Generation>,
    completed: Option<Completion<'s, S::Document, S::Generation>>,
    work: &impl Work,
) -> Result<Reading<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
    let Some(Completion {
        object: Some(length),
    }) = completed
    else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Stream),
            location: pending.reading.value.root().location(),
        }
        .into());
    };
    let length = length.value.root().unsigned(work)?;
    let mut cursor = Cursor {
        reader: reader.fork()?,
        at: 0,
    };
    finish(&mut cursor, pending, length).await
}

fn member_controls<'b, 's, S: RangeSource, W: Work>(
    mut frame: Frame<'b, 's, S::Document, S::Generation>,
    index: u64,
    context: Resolution<'_, '_, 'b, 's, S, W>,
    work: &impl Work,
) -> Result<(), ReadFailure<S::Error>> {
    let Resolution {
        reader,
        frames,
        completed,
    } = context;
    let Some(Completion {
        object: Some(container),
    }) = completed.take()
    else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location: reader.location(0, 0),
        }
        .into());
    };
    frame.state = State::Controls {
        controls: super::controls::Controls::new(
            super::controls::Owner::Owned(container),
            true,
            work,
        ),
        member: Some((frame.number, index)),
    };
    frames
        .try_push(frame)
        .map_err(|cause| resource(cause, reader.location(0, 0)))?;
    Ok(())
}

fn initial<'b, 's, D: Copy + Eq, G: Copy + Eq>(
    request: Request<'b, 's, D, G>,
    work: &impl Work,
) -> Frame<'b, 's, D, G> {
    match request {
        Request::Object { number, generation } => Frame {
            number,
            generation,
            state: State::Start,
        },
        Request::Stream {
            reading,
            object_stream,
        } => Frame {
            number: reading.number,
            generation: reading.generation,
            state: State::Controls {
                controls: super::controls::Controls::new(
                    super::controls::Owner::Borrowed(reading),
                    object_stream,
                    work,
                ),
                member: None,
            },
        },
    }
}

fn suspend<'b, 's, S: RangeSource, W: Work>(
    frames: &mut OwnedVec<Frame<'b, 's, S::Document, S::Generation>, W>,
    frame: Frame<'b, 's, S::Document, S::Generation>,
    (number, generation): (u64, u16),
    document: &Document<'_, S>,
    location: Location,
    work: &impl Work,
) -> crate::Result<()> {
    frames
        .try_push(frame)
        .map_err(|cause| resource(cause, location))?;
    push(
        frames,
        Frame {
            number,
            generation,
            state: State::Start,
        },
        document,
        location,
        work,
    )
}

fn resource(cause: structured_asn1::memory::MemoryError, location: Location) -> Error {
    Error {
        kind: ErrorKind::Resource(cause),
        location,
    }
}

fn push<'b, 's, S: RangeSource, W: Work>(
    frames: &mut OwnedVec<Frame<'b, 's, S::Document, S::Generation>, W>,
    frame: Frame<'b, 's, S::Document, S::Generation>,
    document: &Document<'_, S>,
    location: Location,
    work: &impl Work,
) -> crate::Result<()> {
    // Iterative frames also obey a fixed safety ceiling, independently of a
    // caller accidentally selecting an unbounded nesting allowance.
    if frames.len() >= 512
        || frames.len() as u64 >= u64::from(document.session.limits().processing.max_depth)
    {
        return Err(Error {
            kind: ErrorKind::Limit(crate::error::Limit::Depth),
            location,
        });
    }
    for prior in frames.iter() {
        admit(work, location, 1)?;
        if prior.number == frame.number && prior.generation == frame.generation {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Cycle),
                location,
            });
        }
    }
    frames
        .try_push(frame)
        .map_err(|cause| resource(cause, location))
}

async fn finish<'s, S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    mut pending: Pending<'s, S::Document, S::Generation>,
    length: u64,
) -> Result<Reading<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
    let body = crate::stream::close(
        cursor,
        pending.indirect.stream.expect("pending stream"),
        length,
    )
    .await?;
    pending.reading.stream = Some(body);
    pending.reading.value.end = cursor.at;
    Ok(pending.reading)
}

async fn member<'s, S: RangeSource>(
    document: &Document<'s, S>,
    reader: &mut RangeReader<'_, S>,
    decoded: OwnedVec<u8>,
    body: Span,
    (count, first): (u64, u64),
    (number, selected): (u64, u64),
    revision: usize,
) -> Result<Reading<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
    let work = reader.execution();
    let location = reader.location(body.start, body.length);
    if selected >= count || count > first / 4 {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        }
        .into());
    }
    let slots = super::members::directory(
        document.session,
        document.stamp,
        &decoded,
        body,
        (count, first),
        revision,
        &work,
    )
    .await
    .map_err(convert)?;
    let ordinal = usize::try_from(selected).expect("parsed object-stream directory length");
    let slot = &slots[ordinal];
    if slot.number != number {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        }
        .into());
    }
    let value = super::members::selected(
        document.session,
        document.stamp,
        &decoded,
        body,
        slot,
        revision,
        &work,
    )
    .await
    .map_err(convert)?;
    Ok(Reading {
        value,
        decoded: Some(decoded),
        stream: None,
        number,
        generation: 0,
        revision,
    })
}

pub(crate) fn convert<E>(error: ReadFailure<core::convert::Infallible>) -> ReadFailure<E> {
    match error {
        ReadFailure::Format(error) => ReadFailure::Format(error),
        ReadFailure::Input(error) => ReadFailure::Input(match error {
            crate::range::InputError::Resource { location, cause } => {
                crate::range::InputError::Resource { location, cause }
            }
            crate::range::InputError::Changed { location } => {
                crate::range::InputError::Changed { location }
            }
            crate::range::InputError::Contract { location } => {
                crate::range::InputError::Contract { location }
            }
            crate::range::InputError::Cause { cause, .. } => match cause {},
        }),
    }
}
