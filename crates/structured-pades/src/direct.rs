//! Direct signature fields, with the one specified `FieldMDP` Data exception.

use crate::{
    arena::{Arena, Kind, NodeId},
    error::{Error, ErrorKind},
    model::{admit, get, named},
    source::Location,
};
use structured_asn1::memory::{Memory, Work};
#[cfg(test)]
mod tests;

pub(crate) enum VisitError<E> {
    Processing(Error),
    Callback(E),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Root,
    References,
    Reference,
    Other,
}

pub(crate) fn visit<E>(
    arena: &Arena<Memory>,
    root: NodeId,
    work: &impl Work,
    mut finding: impl FnMut(Location) -> Result<(), E>,
) -> Result<(), VisitError<E>> {
    // ISO32000-1 Table252 note and Table253 Data: signature values are
    // direct, except FieldMDP's explicit reference to the analyzed catalog.
    // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
    let location = arena.nodes[root.0].location;
    let failure = |cause| {
        VisitError::Processing(Error {
            kind: ErrorKind::Resource(cause),
            location,
        })
    };
    let mut pending = work.vector();
    pending.try_push((root, Context::Root)).map_err(failure)?;
    while let Some((node, context)) = pending.pop() {
        let location = arena.nodes[node.0].location;
        admit(work, location, 1).map_err(VisitError::Processing)?;
        match arena.nodes[node.0].kind {
            Kind::Reference { .. } => finding(location).map_err(VisitError::Callback)?,
            Kind::Array(children) => {
                let mut next = children.first;
                while let Some(index) = next {
                    admit(work, location, 1).map_err(VisitError::Processing)?;
                    let link = arena.links[index];
                    next = link.next;
                    let context = if context == Context::References {
                        Context::Reference
                    } else {
                        Context::Other
                    };
                    pending.try_push((link.value, context)).map_err(failure)?;
                }
            }
            Kind::Dictionary(_, fields) => {
                let field_mdp = context == Context::Reference
                    && get(arena, node, b"TransformMethod", work)
                        .map_err(VisitError::Processing)?
                        .map(|method| named(arena, method, b"FieldMDP", work))
                        .transpose()
                        .map_err(VisitError::Processing)?
                        .unwrap_or(false);
                for ordinal in fields.start..fields.start + fields.length {
                    admit(work, location, 1).map_err(VisitError::Processing)?;
                    let field = arena.fields[ordinal];
                    if field_mdp
                        && named(arena, field.key, b"Data", work).map_err(VisitError::Processing)?
                        && matches!(arena.nodes[field.value.0].kind, Kind::Reference { .. })
                    {
                        continue;
                    }
                    let next = if context == Context::Root
                        && named(arena, field.key, b"Reference", work)
                            .map_err(VisitError::Processing)?
                    {
                        Context::References
                    } else {
                        Context::Other
                    };
                    pending.try_push((field.value, next)).map_err(failure)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
