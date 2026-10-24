//! One stream-control schema for direct xrefs and resolved ordinary streams.

use super::{Filter, Prediction, Step};
use crate::{
    arena::{Kind, Node},
    error::{Error, ErrorKind, Syntax, Unsupported},
    model::admit,
    source::Location,
};
use structured_asn1::memory::{Memory, OwnedVec, Work};

pub(crate) enum Failure {
    Fault(Error),
    Need { number: u64, generation: u16 },
}
impl From<Error> for Failure {
    fn from(value: Error) -> Self {
        Self::Fault(value)
    }
}

/// Resolving a value is a capability boundary. Xref dictionaries implement it
/// by refusing references; ordinary streams suspend the same schema until the
/// iterative document resolver supplies the original referenced object.
pub(crate) trait Input {
    type At: Copy;
    fn root(&self) -> Self::At;
    fn node(&self, at: Self::At) -> Node;
    fn resolve(&self, at: Self::At, work: &impl Work) -> Result<Option<Self::At>, Failure>;
    fn get(&self, at: Self::At, key: &[u8], work: &impl Work) -> Result<Option<Self::At>, Failure>;
    fn named(&self, at: Self::At, name: &[u8], work: &impl Work) -> Result<bool, Failure>;
    fn unsigned(&self, at: Self::At, work: &impl Work) -> Result<u64, Failure>;
    fn link(&self, owner: Self::At, link: usize) -> (Self::At, Option<usize>);
}

#[derive(Clone, Copy)]
enum Cursor<A> {
    One(Option<A>),
    Array { owner: A, next: Option<usize> },
}
impl<A: Copy> Cursor<A> {
    fn peek<I: Input<At = A>>(&self, input: &I) -> Option<A> {
        match *self {
            Self::One(value) => value,
            Self::Array { owner, next } => next.map(|next| input.link(owner, next).0),
        }
    }
    fn advance<I: Input<At = A>>(&mut self, input: &I) {
        *self = match *self {
            Self::One(_) => Self::One(None),
            Self::Array { owner, next } => Self::Array {
                owner,
                next: next.and_then(|next| input.link(owner, next).1),
            },
        };
    }
}

pub(crate) struct Builder<A: Copy> {
    cursors: Option<(Cursor<A>, Cursor<A>)>,
    plans: OwnedVec<Step, Memory>,
    done: bool,
    location: Location,
}

impl<A: Copy> Builder<A> {
    pub(crate) fn new(work: &impl Work, location: Location) -> Self {
        Self {
            cursors: None,
            plans: work.vector().into_owned(),
            done: false,
            location,
        }
    }
    /// Header work is bounded and performed before any filter traversal. Once
    /// a step is committed its cursor never rewinds on an indirect dependency.
    pub(crate) fn advance<I: Input<At = A>>(
        &mut self,
        input: &I,
        work: &impl Work,
    ) -> Result<(), Failure> {
        if self.done {
            return Ok(());
        }
        let malformed = || Error {
            kind: ErrorKind::Syntax(Syntax::Stream),
            location: self.location,
        };
        if self.cursors.is_none() {
            if input.get(input.root(), b"F", work)?.is_some() {
                return Err(Error {
                    kind: ErrorKind::Unsupported(Unsupported::ExternalStream),
                    location: self.location,
                }
                .into());
            }
            let Some(filters) = input.get(input.root(), b"Filter", work)? else {
                self.done = true;
                return Ok(());
            };
            let (filters, count) = match input.node(filters).kind {
                Kind::Name(_) => (Cursor::One(Some(filters)), 1),
                Kind::Array(children) if children.length != 0 => (
                    Cursor::Array {
                        owner: filters,
                        next: children.first,
                    },
                    children.length,
                ),
                _ => return Err(malformed().into()),
            };
            let parameters = input.get(input.root(), b"DecodeParms", work)?;
            let parameters = match parameters {
                Some(parameters) => match input.node(parameters).kind {
                    Kind::Dictionary(_, _) if count == 1 => Cursor::One(Some(parameters)),
                    Kind::Array(children) if children.length == count => Cursor::Array {
                        owner: parameters,
                        next: children.first,
                    },
                    _ => return Err(malformed().into()),
                },
                None => Cursor::One(None),
            };
            self.cursors = Some((filters, parameters));
        }
        loop {
            admit(work, self.location, 1)?;
            let (filters, parameters) = self.cursors.as_ref().expect("prepared cursors");
            let Some(filter) = filters.peek(input) else {
                self.done = true;
                return Ok(());
            };
            let filter = input.resolve(filter, work)?.ok_or_else(malformed)?;
            let parameter = parameters
                .peek(input)
                .map(|at| input.resolve(at, work))
                .transpose()?
                .flatten();
            if let Some(parameter) = parameter
                && !matches!(input.node(parameter).kind, Kind::Dictionary(_, _))
            {
                return Err(malformed().into());
            }
            let step = step(input, filter, parameter, work, self.location)?;
            // Transfer, rather than clone, the retained buffer's keeper. Even
            // a spare-capacity insertion uses the active producing execution.
            let stored = core::mem::replace(&mut self.plans, work.vector().into_owned());
            let mut plans = stored.with_execution(work).map_err(|_| {
                Failure::Fault(Error {
                    kind: ErrorKind::Foreign,
                    location: self.location,
                })
            })?;
            plans.try_push(step).map_err(|cause| {
                Failure::Fault(Error {
                    kind: ErrorKind::Resource(cause),
                    location: self.location,
                })
            })?;
            self.plans = plans.into_owned();
            let (filters, parameters) = self.cursors.as_mut().expect("prepared cursors");
            filters.advance(input);
            parameters.advance(input);
        }
    }
    pub(crate) fn finish(self) -> OwnedVec<Step, Memory> {
        debug_assert!(self.done);
        self.plans
    }
}

fn number<I: Input>(
    input: &I,
    at: I::At,
    key: &[u8],
    default: u64,
    work: &impl Work,
) -> Result<u64, Failure> {
    match input.get(at, key, work)? {
        Some(value) => input.unsigned(value, work),
        None => Ok(default),
    }
}

fn step<I: Input>(
    input: &I,
    filter: I::At,
    parameter: Option<I::At>,
    work: &impl Work,
    location: Location,
) -> Result<Step, Failure> {
    let filter = if input.named(filter, b"FlateDecode", work)? {
        Filter::Flate
    } else if input.named(filter, b"LZWDecode", work)? {
        let early = parameter
            .map(|at| number(input, at, b"EarlyChange", 1, work))
            .transpose()?
            .unwrap_or(1);
        if early > 1 {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location,
            }
            .into());
        }
        Filter::Lzw {
            early: u8::try_from(early).expect("checked LZW bit"),
        }
    } else if input.named(filter, b"ASCIIHexDecode", work)? {
        Filter::Hex
    } else if input.named(filter, b"ASCII85Decode", work)? {
        Filter::Base85
    } else if input.named(filter, b"RunLengthDecode", work)? {
        Filter::RunLength
    } else {
        return Err(Error {
            kind: ErrorKind::Unsupported(Unsupported::Filter),
            location: input.node(filter).location,
        }
        .into());
    };
    let prediction = if let Some(parameter) = parameter {
        if matches!(filter, Filter::Flate | Filter::Lzw { .. }) {
            let predictor = number(input, parameter, b"Predictor", 1, work)?;
            if predictor == 1 {
                Prediction::None
            } else {
                let colors = number(input, parameter, b"Colors", 1, work)?;
                let bits = number(input, parameter, b"BitsPerComponent", 8, work)?;
                let columns = number(input, parameter, b"Columns", 1, work)?;
                super::prediction_shape(
                    predictor,
                    colors,
                    bits,
                    columns,
                    input.node(parameter).location,
                )?
            }
        } else {
            Prediction::None
        }
    } else {
        Prediction::None
    };
    Ok(Step { filter, prediction })
}

pub(crate) struct Direct<'a, W: Work> {
    pub(crate) arena: &'a crate::arena::Arena<W>,
    pub(crate) root: crate::arena::NodeId,
}
impl<W: Work> Input for Direct<'_, W> {
    type At = crate::arena::NodeId;
    fn root(&self) -> Self::At {
        self.root
    }
    fn node(&self, at: Self::At) -> Node {
        self.arena.nodes[at.0]
    }
    fn resolve(&self, at: Self::At, work: &impl Work) -> Result<Option<Self::At>, Failure> {
        let node = self.node(at);
        admit(work, node.location, 1)?;
        match node.kind {
            Kind::Reference { .. } => Err(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location: node.location,
            }
            .into()),
            Kind::Null => Ok(None),
            _ => Ok(Some(at)),
        }
    }
    fn get(&self, at: Self::At, key: &[u8], work: &impl Work) -> Result<Option<Self::At>, Failure> {
        crate::model::get(self.arena, at, key, work)?
            .map(|value| self.resolve(value, work))
            .transpose()
            .map(Option::flatten)
    }
    fn named(&self, at: Self::At, name: &[u8], work: &impl Work) -> Result<bool, Failure> {
        Ok(crate::model::named(self.arena, at, name, work)?)
    }
    fn unsigned(&self, at: Self::At, work: &impl Work) -> Result<u64, Failure> {
        Ok(crate::model::unsigned(self.arena, at, work)?)
    }
    fn link(&self, _: Self::At, link: usize) -> (Self::At, Option<usize>) {
        let link = self.arena.links[link];
        (link.value, link.next)
    }
}
