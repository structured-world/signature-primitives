//! Format visitation, shared original-artifact lookup and sticky refusals.

use super::{
    CheckResult, Completeness, Entry, Error, Finding, Missing, Need, ProcessingResult, Provider,
    Report, Scope, selection,
};
use crate::credential::{Checked, ParticipantCredentials};
use crate::material::Index;
use crate::pki::CounterPaths;
use crate::reference::VisitError;
use crate::timestamp::TimestampRequirements;
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::{MemoryError, OwnedMap, Work};

type EntryFor<X> = Entry<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Enumerate every authenticated credential in the ORIGINAL whole/earlier-archive
/// scope, then invoke its own format-material handler once. The private full
/// counter census and same timestamp scope determine membership, not a supplied
/// list of successful credentials. No authentication or X.509 status is replayed.
///
/// The exact-artifact index checks known dependencies; an open-format location
/// must occur in that same frozen original open catalogue. Archive mode uses
/// the same mathematical element coverage as timestamp input construction.
/// Missing material and incomplete format outcomes remain facts; all processing,
/// callback, source and current Work failures are terminal and release partial
/// reports/scratch. This does not imply status usability or application trust.
pub fn check<'auth, 'path, 'document, X: Xml, A, P: Provider<X, A>, W: Work, Q: Work, C: Work>(
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
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    scope: &Scope<'_, X::Id, X::Document, X::Generation, C>,
    provider: &P,
    access: &Access<'_, X, Q>,
) -> CheckResult<'auth, 'path, 'document, X, A, P::Error> {
    scope.require(required, index, access)?;
    let selected = selection::select::<X, A, Q, P::Error>(credentials, counters, required, access)?;
    let open = open_index::<X, W, Q, P::Error>(index, access)?;
    let node = credentials.signature();
    let mut entries = access.execution().vector();
    entries
        .try_reserve_exact(selected.len())
        .map_err(|cause| Error::Resource { node, cause })?;
    let mut complete = true;
    for credential in selected {
        let entry = one(credential, index, scope, provider, &open, access)?;
        if entry.completeness != Completeness::Complete || !entry.findings.is_empty() {
            complete = false;
        }
        entries
            .try_push(entry)
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    Ok(Report {
        credentials,
        scope: required.scope(),
        entries: entries.into_owned(),
        complete,
    })
}

fn open_index<X: Xml, W: Work, Q: Work, PE>(
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> ProcessingResult<OwnedMap<X::Id, (), Q>, X, PE> {
    let mut open = access.execution().map();
    for entry in index.opaque {
        let node = entry.location.node;
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| Error::Resource { node, cause })?;
        if entry.location.snapshot != access.snapshot() {
            return Err(Error::Foreign { node });
        }
        open.try_insert(node, ())
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    Ok(open)
}

fn one<X: Xml, A, P: Provider<X, A>, W: Work, Q: Work, C: Work>(
    credential: &Checked<'_, '_, A, X::Id, X::Document, X::Generation>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    scope: &Scope<'_, X::Id, X::Document, X::Generation, C>,
    provider: &P,
    open: &OwnedMap<X::Id, (), Q>,
    access: &Access<'_, X, Q>,
) -> ProcessingResult<EntryFor<X>, X, P::Error> {
    let source = credential.source();
    let node = source.entry().node;
    let mut findings = access.execution().vector();
    let mut ordinal = 0usize;
    let mut first = None;
    let result = access.query_fallible(node, |_, _, work| {
        let result = provider.visit(credential, index.opaque, access, |need| {
            if first.is_some() {
                return Err(());
            }
            let result = (|| {
                work.charge_work(1)
                    .map_err(|cause| Error::Resource { node, cause })?;
                let dependency = ordinal;
                ordinal = ordinal.checked_add(1).ok_or(Error::Resource {
                    node,
                    cause: MemoryError::WorkExceeded,
                })?;
                if let Some(cause) = need_missing(need, index, scope, open, access)? {
                    findings
                        .try_push(Finding { dependency, cause })
                        .map_err(|cause| Error::Resource { node, cause })?;
                }
                Ok(())
            })();
            match result {
                Ok(()) => Ok(()),
                Err(cause) => {
                    first = Some(cause);
                    Err(())
                }
            }
        });
        if let Some(cause) = first.take() {
            return Err(cause);
        }
        match result {
            Ok(value) => Ok(value),
            Err(VisitError::Processing(cause)) => Err(Error::Provider { node, cause }),
            Err(VisitError::Visitor(())) => Err(Error::CallbackProtocol { node }),
        }
    });
    let completeness = match result {
        Ok(value) => value,
        Err(AccessError::Xml(cause)) => return Err(cause),
        Err(AccessError::Changed { node }) => {
            return Err(Error::Access(AccessError::Changed { node }));
        }
        Err(AccessError::Resource { node, cause }) => {
            return Err(Error::Access(AccessError::Resource { node, cause }));
        }
    };
    Ok(Entry {
        source,
        completeness,
        findings: findings.into_owned(),
    })
}

fn need_missing<X: Xml, W: Work, Q: Work, C: Work, PE>(
    need: Need<'_, '_, X::Id, X::Document, X::Generation>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    scope: &Scope<'_, X::Id, X::Document, X::Generation, C>,
    open: &OwnedMap<X::Id, (), Q>,
    access: &Access<'_, X, Q>,
) -> Result<Option<Missing>, Error<X::Error, PE, X::Id>> {
    match need {
        Need::Missing => Ok(Some(Missing::Absent)),
        Need::Known(artifact) => scope.known(artifact, index, access),
        Need::Open(location) => {
            let node = location.node;
            if location.snapshot != access.snapshot() {
                return Err(Error::Foreign { node });
            }
            if open
                .get(&node, access.execution())
                .map_err(|cause| Error::Resource { node, cause })?
                .is_none()
            {
                return Ok(Some(Missing::Absent));
            }
            scope.open(location, access)
        }
    }
}
