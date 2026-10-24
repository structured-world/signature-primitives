//! Paid schema queries over the single flat PDF object catalogue.

use crate::arena::{Arena, Kind, NodeId};
use crate::error::{Error, ErrorKind, Result, Syntax, Unsupported};
use crate::source::Location;
use structured_asn1::memory::Work;

pub(crate) fn admit(work: &impl Work, location: Location, amount: u64) -> Result<()> {
    work.charge_work(amount).map_err(|cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    })
}

pub(crate) fn get<W: Work>(
    arena: &Arena<W>,
    node: NodeId,
    key: &[u8],
    work: &impl Work,
) -> Result<Option<NodeId>> {
    let value = arena.nodes[node.0];
    admit(work, value.location, 1)?;
    let Kind::Dictionary(_, fields) = value.kind else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location: value.location,
        });
    };
    crate::dictionary::lookup(arena, fields, key, work, value.location)
}

pub(crate) fn unsigned<W: Work>(arena: &Arena<W>, node: NodeId, work: &impl Work) -> Result<u64> {
    unsigned_value::<false, W>(arena, node, work)
}

pub(crate) fn unsigned_number<W: Work>(
    arena: &Arena<W>,
    node: NodeId,
    work: &impl Work,
) -> Result<u64> {
    unsigned_value::<true, W>(arena, node, work)
}

fn unsigned_value<const REAL: bool, W: Work>(
    arena: &Arena<W>,
    node: NodeId,
    work: &impl Work,
) -> Result<u64> {
    let value = arena.nodes[node.0];
    admit(work, value.location, 1)?;
    let integer = match value.kind {
        Kind::Integer(integer) => integer,
        Kind::Real {
            integer,
            fractional: false,
        } if REAL => integer,
        _ => {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location: value.location,
            });
        }
    };
    if integer.negative && integer.magnitude != Some(0) {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Number),
            location: value.location,
        });
    }
    integer.magnitude.ok_or(Error {
        kind: ErrorKind::Unsupported(Unsupported::NumericRange),
        location: value.location,
    })
}

pub(crate) fn named<W: Work>(
    arena: &Arena<W>,
    node: NodeId,
    expected: &[u8],
    work: &impl Work,
) -> Result<bool> {
    let value = arena.nodes[node.0];
    admit(work, value.location, 1)?;
    let Kind::Name(name) = value.kind else {
        return Ok(false);
    };
    if name.length != expected.len() {
        return Ok(false);
    }
    admit(work, value.location, name.length as u64)?;
    Ok(&arena.names[name.start..name.start + name.length] == expected)
}

pub(crate) fn required<W: Work>(
    arena: &Arena<W>,
    node: NodeId,
    key: &[u8],
    work: &impl Work,
) -> Result<NodeId> {
    get(arena, node, key, work)?.ok_or(Error {
        kind: ErrorKind::Syntax(Syntax::Dictionary),
        location: arena.nodes[node.0].location,
    })
}
