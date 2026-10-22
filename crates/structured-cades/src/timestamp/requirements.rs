//! One whole earlier-actor census for modern and historical archive coverage.

use super::{ArchiveScopeError as Failure, Checked};
use crate::{
    Cades, Error, ISSUER,
    prepare::Preparation,
    source::{DocumentId, Node},
};
use structured_asn1::{
    Reader,
    memory::{Memory, Work},
};
use structured_ltv::{
    material::Coverage,
    source::{Scope, Source as _},
    timestamp::{RequiredToken, TimestampRequirements, TimestampScope},
};

pub(super) fn derive<'m, 'd>(
    timestamp: &Checked<'m, 'd, '_>,
    coverage: &Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades>,
    prepared: &Preparation<'m, 'd>,
    operation: &Reader<'d>,
) -> Result<TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>, Failure> {
    const FIELD: &str = "cades.archive.scope";
    prepared
        .document()
        .message()
        .require_session(operation, FIELD)
        .map_err(|cause| Failure::Processing(Error::Cms(cause)))?;
    let actor = timestamp.actor().ok_or(Failure::Unproven)?;
    let verified = actor.verified();
    operation
        .charge(1)
        .map_err(|cause| Failure::Processing(Error::encoding(cause, FIELD)))?;
    // Historical recipes also bind parallel roots and counters. Resolve the
    // actual retained owner in this preparation; a selected-root comparison
    // would discard an otherwise verified receipt for those owners.
    if verified.signature() != Node::of(prepared.signer().span()) {
        prepared
            .signer_encoding(verified.signature(), operation)
            .map_err(Failure::Processing)?;
    }
    let source = prepared.document();
    let work = operation.execution();
    let query = Scope::new(source, source.snapshot(), &work);
    coverage
        .require_evidence(verified, verified.property(), &query)
        .map_err(Failure::Coverage)?;
    let resource = |cause| {
        Failure::Processing(Error::resource(
            cause,
            FIELD,
            verified.property().span().start,
        ))
    };
    let mut tokens = work.vector();
    for entry in prepared.timestamps() {
        work.charge_work(1).map_err(resource)?;
        let token = entry
            .value()
            .map_or(entry.property(), |value| Node::of(value.span()));
        if token == verified.token().node && entry.owner() == verified.signature() {
            continue;
        }
        let selected = coverage
            .covers(verified, token, &query)
            .map_err(Failure::Coverage)?
            || coverage
                .covers(verified, entry.property(), &query)
                .map_err(Failure::Coverage)?;
        if selected {
            tokens
                .try_push(RequiredToken {
                    signature: entry.owner(),
                    property: entry.property(),
                    token,
                    purpose: entry.purpose(),
                })
                .map_err(resource)?;
        }
    }
    let owner = verified.signature().span();
    let catalogue = if owner.start >= prepared.signer().span().start
        && owner.end() <= prepared.signer().span().end()
    {
        prepared.counters()
    } else {
        prepared.parallel_counters()
    };
    let count = if verified.signature() == Node::of(prepared.signer().span()) {
        catalogue.len()
    } else {
        // A parallel-root catalogue can hold unrelated siblings. Reserve only
        // this owner's descendants, without copying or allocating a filter.
        counter_capacity(catalogue, verified.signature(), &work).map_err(resource)?
    };
    let mut counters = work.vector();
    let mut included = work.vector();
    counters.try_reserve_exact(count).map_err(resource)?;
    included.try_reserve_exact(count).map_err(resource)?;
    for counter in catalogue {
        work.charge_work(1).map_err(resource)?;
        if !descendant(verified.signature(), counter.node()) {
            continue;
        }
        let selected = coverage
            .covers(verified, counter.node(), &query)
            .map_err(Failure::Coverage)?;
        counters.try_push(counter.node()).map_err(resource)?;
        included.try_push(selected).map_err(resource)?;
    }
    Ok(TimestampRequirements::with_counters(
        ISSUER,
        verified.signature(),
        TimestampScope::BeforeArchive(source.locate(coverage.subject().span())),
        tokens.into_owned(),
        counters.into_owned(),
        Some(included.into_owned()),
    ))
}

fn descendant(owner: Node, child: Node) -> bool {
    let owner = owner.span();
    let child = child.span();
    child != owner && child.start >= owner.start && child.end() <= owner.end()
}

fn counter_capacity(
    catalogue: &[crate::prepare::Counter<'_>],
    owner: Node,
    work: &impl Work,
) -> Result<usize, structured_asn1::memory::MemoryError> {
    let mut count = 0;
    for counter in catalogue {
        work.charge_work(1)?;
        if descendant(owner, counter.node()) {
            count += 1;
        }
    }
    Ok(count)
}
