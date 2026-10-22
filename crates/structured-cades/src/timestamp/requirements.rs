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
    if verified.signature() != Node::of(prepared.signer().span()) {
        return Err(Failure::Foreign);
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
    let mut counters = work.vector();
    let mut included = work.vector();
    counters
        .try_reserve_exact(prepared.counters().len())
        .map_err(resource)?;
    included
        .try_reserve_exact(prepared.counters().len())
        .map_err(resource)?;
    for counter in prepared.counters() {
        work.charge_work(1).map_err(resource)?;
        let selected = coverage
            .covers(verified, counter.node(), &query)
            .map_err(Failure::Coverage)?;
        counters.try_push(counter.node()).map_err(resource)?;
        included.try_push(selected).map_err(resource)?;
    }
    Ok(TimestampRequirements::with_counters(
        ISSUER,
        Node::of(prepared.signer().span()),
        TimestampScope::BeforeArchive(source.locate(coverage.subject().span())),
        tokens.into_owned(),
        counters.into_owned(),
        Some(included.into_owned()),
    ))
}
