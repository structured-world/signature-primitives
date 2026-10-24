//! One paid semantic dictionary index and iterative duplicate-value comparison.
//!
//! ISO 32000-1:2008 §7.3.7 makes dictionary order irrelevant and null entries
//! absent. Duplicate non-null keys violate syntax. Inspection retains the
//! first original value and a fault only when all copies have the same typed
//! value; conflicting copies have no unique interpretation and are refused.
//! <https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf>

use crate::arena::{Arena, Children, Entry, Fields, Kind, Name, NodeId};
use crate::byte_machine::{Decoder, Step};
use crate::bytes::Form;
use crate::error::{Error, ErrorKind, Fault, ReadFailure, Result, Syntax};
use crate::range::{RangeReader, RangeSource};
use crate::source::Location;
use core::cmp::Ordering;
use structured_asn1::memory::{MemoryError, Work};

pub(crate) async fn finish<S: RangeSource, W: Work>(
    arena: &mut Arena<W>,
    children: Children,
    location: Location,
    reader: &mut RangeReader<'_, S>,
) -> core::result::Result<Fields, ReadFailure<S::Error>> {
    let work = reader.execution();
    let mut ordered = work.vector();
    let mut next = children.first;
    while let Some(key_link) = next {
        work.charge_work(2)
            .map_err(|cause| refusal(cause, location))?;
        let key = arena.links[key_link];
        let value = arena.links[key.next.expect("complete dictionary pair")];
        next = value.next;
        if matches!(arena.nodes[value.value.0].kind, Kind::Null) {
            continue;
        }
        ordered
            .try_push(Entry {
                key: key.value,
                value: value.value,
            })
            .map_err(|cause| refusal(cause, location))?;
    }
    ordered
        .try_sort_unstable_by(|left, right| {
            let names = compare_names(arena, left.key, right.key, &work)?;
            // Sorting is unstable, so the original node ordinal explicitly keeps
            // the FIRST encoding as the selected reading among equal keys.
            Ok::<_, Error>(names.then_with(|| left.key.0.cmp(&right.key.0)))
        })
        .map_err(|error| match error {
            structured_asn1::memory::SortError::Resource(cause) => refusal(cause, location),
            structured_asn1::memory::SortError::Comparison(error) => error,
        })?;
    let start = arena.fields.len();
    let mut at = 0;
    let mut second_window = None;
    while at < ordered.len() {
        let selected = ordered[at];
        at += 1;
        while at < ordered.len() {
            if compare_names(arena, selected.key, ordered[at].key, &work)? != Ordering::Equal {
                break;
            }
            let duplicate = ordered[at];
            let place = arena.nodes[duplicate.key.0].location;
            if !same(
                arena,
                selected.value,
                duplicate.value,
                reader,
                &mut second_window,
            )
            .await?
            {
                return Err(Error {
                    kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                    location: place,
                }
                .into());
            }
            arena
                .faults
                .try_push(Fault {
                    code: Syntax::Dictionary,
                    location: place,
                })
                .map_err(|cause| refusal(cause, place))?;
            at += 1;
        }
        arena
            .fields
            .try_push(selected)
            .map_err(|cause| refusal(cause, location))?;
    }
    Ok(Fields {
        start,
        length: arena.fields.len() - start,
    })
}

pub(crate) fn lookup<W: Work>(
    arena: &Arena<W>,
    fields: Fields,
    expected: &[u8],
    work: &impl Work,
    location: Location,
) -> Result<Option<NodeId>> {
    let mut low = fields.start;
    let mut high = low + fields.length;
    while low < high {
        work.charge_work(1)
            .map_err(|cause| refusal(cause, location))?;
        let middle = low + (high - low) / 2;
        let entry = arena.fields[middle];
        let name = name(arena, entry.key);
        work.charge_work(name.length.min(expected.len()) as u64)
            .map_err(|cause| refusal(cause, arena.nodes[entry.key.0].location))?;
        match arena.names[name.start..name.start + name.length].cmp(expected) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Ok(Some(entry.value)),
        }
    }
    Ok(None)
}

fn name<W: Work>(arena: &Arena<W>, node: NodeId) -> Name {
    let Kind::Name(name) = arena.nodes[node.0].kind else {
        unreachable!("parsed dictionary key")
    };
    name
}

fn compare_names<W: Work>(
    arena: &Arena<W>,
    left: NodeId,
    right: NodeId,
    work: &impl Work,
) -> Result<Ordering> {
    compare_names_between(arena, left, arena, right, work)
}

pub(crate) fn compare_names_between<A: Work, B: Work>(
    a_arena: &Arena<A>,
    left: NodeId,
    b_arena: &Arena<B>,
    right: NodeId,
    work: &impl Work,
) -> Result<Ordering> {
    let a = name(a_arena, left);
    let b = name(b_arena, right);
    work.charge_work(a.length.min(b.length) as u64)
        .map_err(|cause| refusal(cause, b_arena.nodes[right.0].location))?;
    Ok(a_arena.names[a.start..a.start + a.length].cmp(&b_arena.names[b.start..b.start + b.length]))
}

#[derive(Clone, Copy)]
enum Compare {
    Values(NodeId, NodeId),
    Array {
        left: Option<usize>,
        right: Option<usize>,
    },
    Dictionary {
        left: Fields,
        right: Fields,
        at: usize,
    },
}

pub(crate) fn scalar<A: Work, B: Work>(
    a_arena: &Arena<A>,
    left: NodeId,
    b_arena: &Arena<B>,
    right: NodeId,
    work: &impl Work,
) -> Result<Option<bool>> {
    work.charge_work(1)
        .map_err(|cause| refusal(cause, b_arena.nodes[right.0].location))?;
    let result = match (a_arena.nodes[left.0].kind, b_arena.nodes[right.0].kind) {
        (Kind::Null, Kind::Null) => true,
        (Kind::Boolean(a), Kind::Boolean(b)) => a == b,
        (
            Kind::Reference {
                number: a,
                generation: ag,
            },
            Kind::Reference {
                number: b,
                generation: bg,
            },
        ) => a == b && ag == bg,
        (Kind::Name(_), Kind::Name(_)) => {
            compare_names_between(a_arena, left, b_arena, right, work)? == Ordering::Equal
        }
        (Kind::Integer(a), Kind::Integer(b))
        | (
            Kind::Real {
                integer: a,
                fractional: false,
            },
            Kind::Real {
                integer: b,
                fractional: false,
            },
        ) if a.magnitude.is_some() && b.magnitude.is_some() => {
            a.magnitude == b.magnitude && (a.magnitude == Some(0) || a.negative == b.negative)
        }
        (Kind::Integer(_), Kind::Integer(_))
        | (Kind::Real { .. }, Kind::Real { .. })
        | (Kind::String(_), Kind::String(_))
        | (Kind::Array(_), Kind::Array(_))
        | (Kind::Dictionary(_, _), Kind::Dictionary(_, _)) => return Ok(None),
        _ => false,
    };
    Ok(Some(result))
}

// The frame stack holds only active cursors, O(depth), never all siblings or
// cloned subtrees. It allocates/funds actual capacity before each stack push.
async fn same<'q, S: RangeSource, W: Work>(
    arena: &Arena<W>,
    left: NodeId,
    right: NodeId,
    reader: &mut RangeReader<'q, S>,
    other: &mut Option<RangeReader<'q, S>>,
) -> core::result::Result<bool, ReadFailure<S::Error>> {
    same_between(arena, left, arena, right, reader, other).await
}

enum ChildrenStep {
    End,
    Different,
    Pair(NodeId, NodeId),
}

fn next_children(
    a_arena: &Arena<impl Work>,
    b_arena: &Arena<impl Work>,
    frame: &mut Compare,
    work: &impl Work,
) -> crate::Result<ChildrenStep> {
    match *frame {
        Compare::Array { left, right } => {
            let (Some(left), Some(right)) = (left, right) else {
                return Ok(ChildrenStep::End);
            };
            let a = a_arena.links[left];
            let b = b_arena.links[right];
            *frame = Compare::Array {
                left: a.next,
                right: b.next,
            };
            Ok(ChildrenStep::Pair(a.value, b.value))
        }
        Compare::Dictionary { left, right, at } => {
            if at == left.length {
                return Ok(ChildrenStep::End);
            }
            let a = a_arena.fields[left.start + at];
            let b = b_arena.fields[right.start + at];
            if compare_names_between(a_arena, a.key, b_arena, b.key, work)? != Ordering::Equal {
                return Ok(ChildrenStep::Different);
            }
            *frame = Compare::Dictionary {
                left,
                right,
                at: at + 1,
            };
            Ok(ChildrenStep::Pair(a.value, b.value))
        }
        Compare::Values(_, _) => unreachable!("only child cursors advance here"),
    }
}

pub(crate) async fn same_between<'q, S: RangeSource, A: Work, B: Work>(
    a_arena: &Arena<A>,
    left: NodeId,
    b_arena: &Arena<B>,
    right: NodeId,
    reader: &mut RangeReader<'q, S>,
    other: &mut Option<RangeReader<'q, S>>,
) -> core::result::Result<bool, ReadFailure<S::Error>> {
    let work = reader.execution();
    let location = b_arena.nodes[right.0].location;
    let mut pending = work.vector();
    pending
        .try_push(Compare::Values(left, right))
        .map_err(|cause| refusal(cause, location))?;
    while let Some(frame) = pending.last_mut() {
        work.charge_work(1)
            .map_err(|cause| refusal(cause, location))?;
        match *frame {
            Compare::Array { .. } | Compare::Dictionary { .. } => {
                match next_children(a_arena, b_arena, frame, &work)? {
                    ChildrenStep::End => {
                        pending.pop();
                    }
                    ChildrenStep::Different => return Ok(false),
                    ChildrenStep::Pair(a, b) => pending
                        .try_push(Compare::Values(a, b))
                        .map_err(|cause| refusal(cause, location))?,
                }
            }
            Compare::Values(a, b) => {
                pending.pop();
                if let Some(equal) = scalar(a_arena, a, b_arena, b, &work)? {
                    if !equal {
                        return Ok(false);
                    }
                    continue;
                }
                match (a_arena.nodes[a.0].kind, b_arena.nodes[b.0].kind) {
                    (Kind::Integer(_), Kind::Integer(_))
                    | (Kind::Real { .. }, Kind::Real { .. }) => {
                        let second = match other.as_mut() {
                            Some(reader) => reader,
                            None => other.insert(reader.fork()?),
                        };
                        if !same_number(
                            reader,
                            a_arena.nodes[a.0].location,
                            second,
                            b_arena.nodes[b.0].location,
                        )
                        .await?
                        {
                            return Ok(false);
                        }
                    }
                    (Kind::String(a_form), Kind::String(b_form)) => {
                        let second = match other.as_mut() {
                            Some(reader) => reader,
                            None => other.insert(reader.fork()?),
                        };
                        let mut a = StringCursor::new(a_arena.nodes[a.0].location, a_form);
                        let mut b = StringCursor::new(b_arena.nodes[b.0].location, b_form);
                        loop {
                            let left = a.next(reader).await?;
                            let right = b.next(second).await?;
                            if left != right {
                                return Ok(false);
                            }
                            if left.is_none() {
                                break;
                            }
                        }
                    }
                    (Kind::Array(a), Kind::Array(b)) => {
                        if a.length != b.length {
                            return Ok(false);
                        }
                        pending
                            .try_push(Compare::Array {
                                left: a.first,
                                right: b.first,
                            })
                            .map_err(|cause| refusal(cause, location))?;
                    }
                    (Kind::Dictionary(_, a), Kind::Dictionary(_, b)) => {
                        if a.length != b.length {
                            return Ok(false);
                        }
                        pending
                            .try_push(Compare::Dictionary {
                                left: a,
                                right: b,
                                at: 0,
                            })
                            .map_err(|cause| refusal(cause, location))?;
                    }
                    _ => return Ok(false),
                }
            }
        }
    }
    Ok(true)
}

struct StringCursor {
    at: u64,
    end: u64,
    decoder: Decoder,
}

impl StringCursor {
    fn new(location: Location, form: Form) -> Self {
        Self {
            at: location.span().start + 1,
            end: location.end() - 1,
            decoder: Decoder::new(form),
        }
    }

    async fn next<S: RangeSource>(
        &mut self,
        reader: &mut RangeReader<'_, S>,
    ) -> core::result::Result<Option<u8>, ReadFailure<S::Error>> {
        loop {
            let input = if self.at < self.end {
                reader.byte_at(self.at).await?
            } else {
                None
            };
            match self.decoder.step(input) {
                Step::More => {
                    self.at += 1;
                }
                Step::Byte { value, consumed } => {
                    if consumed {
                        self.at += 1;
                    }
                    return Ok(Some(value));
                }
                Step::End => return Ok(None),
                Step::Malformed => {
                    unreachable!("string grammar validated before duplicate comparison")
                }
            }
        }
    }
}

// Decimal equality preserves arbitrarily wide values, without float rounding
// or a shared overflow sentinel. Integer and real TYPES remain separate.
struct Decimal {
    negative: bool,
    digits: u64,
    exponent: i128,
    start: u64,
    end: u64,
}

async fn decimal<S: RangeSource>(
    reader: &mut RangeReader<'_, S>,
    location: Location,
) -> core::result::Result<Decimal, ReadFailure<S::Error>> {
    let mut at = location.span().start;
    let negative = reader.byte_at(at).await? == Some(b'-');
    if matches!(reader.byte_at(at).await?, Some(b'+' | b'-')) {
        at += 1;
    }
    let mut digits = 0_u64;
    let mut point = None;
    let mut first = None;
    let mut last = 0;
    let mut start = at;
    let mut end = at;
    while at < location.end() {
        let byte = reader.byte_at(at).await?.expect("parsed numeric range");
        if byte == b'.' {
            point = Some(digits);
        } else {
            if byte != b'0' {
                if first.is_none() {
                    first = Some(digits);
                    start = at;
                }
                last = digits;
                end = at + 1;
            }
            digits += 1;
        }
        at += 1;
    }
    let Some(first) = first else {
        return Ok(Decimal {
            negative: false,
            digits: 0,
            exponent: 0,
            start,
            end: start,
        });
    };
    Ok(Decimal {
        negative,
        digits: last - first + 1,
        exponent: i128::from(point.unwrap_or(digits)) - i128::from(first),
        start,
        end,
    })
}

async fn same_number<S: RangeSource>(
    left: &mut RangeReader<'_, S>,
    a: Location,
    right: &mut RangeReader<'_, S>,
    b: Location,
) -> core::result::Result<bool, ReadFailure<S::Error>> {
    let a = decimal(left, a).await?;
    let b = decimal(right, b).await?;
    if a.negative != b.negative || a.digits != b.digits || a.exponent != b.exponent {
        return Ok(false);
    }
    let mut x = a.start;
    let mut y = b.start;
    while x < a.end && y < b.end {
        let first = left.byte_at(x).await?.expect("parsed significant digit");
        if first == b'.' {
            x += 1;
            continue;
        }
        let second = right.byte_at(y).await?.expect("parsed significant digit");
        if second == b'.' {
            y += 1;
            continue;
        }
        if first != second {
            return Ok(false);
        }
        x += 1;
        y += 1;
    }
    Ok(true)
}

fn refusal(cause: MemoryError, location: Location) -> Error {
    Error {
        kind: ErrorKind::Resource(cause),
        location,
    }
}
