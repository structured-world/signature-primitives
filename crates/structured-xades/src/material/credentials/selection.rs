//! Source-derived credential subset, without caller-selected successes.

use super::{Error, ProcessingResult};
use crate::credential::{Checked, Credentials, ParticipantCredentials};
use crate::pki::CounterPaths;
use crate::xml::{Access, Xml};
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::timestamp::TimestampRequirements;

pub(super) type Selected<'auth, 'path, 'document, X, A, W> = OwnedVec<
    &'auth Checked<
        'path,
        'document,
        A,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    W,
>;

pub(super) fn select<'auth, 'path, 'document, X: Xml, A, W: Work, PE>(
    credentials: &'auth ParticipantCredentials<
        'path,
        'document,
        A,
        X::Id,
        X::Document,
        X::Generation,
    >,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    required: &TimestampRequirements<X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> ProcessingResult<Selected<'auth, 'path, 'document, X, A, W>, X, PE> {
    let node = credentials.signature();
    if credentials.snapshot() != access.snapshot()
        || counters.snapshot() != access.snapshot()
        || required.scope().location().snapshot != access.snapshot()
    {
        return Err(Error::Foreign { node });
    }
    let resource = |cause| Error::Resource { node, cause };
    if !access
        .equal_id(node, required.signature())
        .map_err(resource)?
        || !access
            .equal_id(node, counters.signature())
            .map_err(resource)?
        || !required
            .includes_counters(counters, access)
            .map_err(|cause| Error::Access(cause.into()))?
    {
        return Err(Error::Foreign { node });
    }
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    let mut selected = access.execution().vector();
    if let Some(root) = credentials.root() {
        append(root, &mut selected, access)?;
    }
    let mut group = 0;
    for (ordinal, actor) in counters.actors().iter().enumerate() {
        access.execution().charge_work(1).map_err(resource)?;
        let Some(next) = credentials.counters().get(group) else {
            continue;
        };
        let child = actor.signer().counter().original().child();
        if access
            .equal_id(child, next.source().original().child())
            .map_err(resource)?
        {
            if required
                .counter_in_scope(ordinal, access)
                .map_err(Error::Obligation)?
            {
                append(next.credentials(), &mut selected, access)?;
            }
            group += 1;
        }
    }
    if group != credentials.counters().len() {
        return Err(Error::Foreign { node });
    }
    Ok(selected)
}

fn append<'auth, 'path, 'document, X: Xml, A, W: Work, PE>(
    group: &'auth Credentials<'path, 'document, A, X::Id, X::Document, X::Generation>,
    output: &mut Selected<'auth, 'path, 'document, X, A, W>,
    access: &Access<'_, X, W>,
) -> Result<(), Error<X::Error, PE, X::Id>> {
    let node = group.signature();
    if group.snapshot() != access.snapshot() {
        return Err(Error::Foreign { node });
    }
    for entry in group.entries() {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| Error::Resource { node, cause })?;
        output
            .try_push(entry)
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    Ok(())
}
