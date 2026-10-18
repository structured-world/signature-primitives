//! Conditional Annex A incorporation from complete original digest/source facts.

use super::{ReferenceDigests, ReferenceSearch};
use crate::{
    certificate::Agreement,
    pki::CounterPaths,
    unsigned,
    xml::{Access, AccessError, Xml},
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::timestamp::{TimestampRequirements, TimestampScope};

/// Why a referenced value's required incorporation was not established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferencePresenceFailure {
    /// Complete known-digest search found no equal incorporated original value.
    Missing,
    /// An OCSP identifier without a digest still needs authenticated identity
    /// association; empty bytes are not successful digest evidence.
    IdentifierOnly,
    /// Open reference semantics require the owning format's interpretation.
    OtherFormat,
    /// A method/output was not available for a completed exact comparison.
    Unavailable(Agreement),
}

/// One original reference row's conditional obligation and completed outcome.
pub struct ReferencePresenceRow {
    required: bool,
    failure: Option<ReferencePresenceFailure>,
}
impl ReferencePresenceRow {
    /// Whether original container/archive presence activates Annex A inclusion.
    #[must_use]
    pub fn required(&self) -> bool {
        self.required
    }
    /// None only establishes this necessary presence condition, not trust,
    /// successful identity hints, actual actor use or a baseline level.
    #[must_use]
    pub fn failure(&self) -> Option<ReferencePresenceFailure> {
        self.failure
    }
}

/// Conditional referenced-material facts bound to the same complete report.
pub struct ReferencePresence<'report, 'references, 'source, N, D, G> {
    digests: &'report ReferenceDigests<'references, 'source, N, D, G>,
    rows: OwnedVec<ReferencePresenceRow>,
    all_present: bool,
}
impl<'report, 'references, 'source, N, D, G>
    ReferencePresence<'report, 'references, 'source, N, D, G>
{
    /// Original reference order and all exact source comparison outcomes.
    #[must_use]
    pub fn digests(&self) -> &'report ReferenceDigests<'references, 'source, N, D, G> {
        self.digests
    }
    /// Exactly one result per original reference row, with no successful subset.
    #[must_use]
    pub fn rows(&self) -> &[ReferencePresenceRow] {
        &self.rows
    }
    /// Only the activated inclusion requirements, not artifact validity or grade.
    #[must_use]
    pub fn all_required_present(&self) -> bool {
        self.all_present
    }
}

/// Invalid scope/census and processing refusal are not absent material.
#[derive(Debug)]
pub enum ReferencePresenceError<E, N> {
    /// Current original source/generation refused, including the complete
    /// timestamp/counter source verification.
    Access(AccessError<E, N>),
    /// Requirements, counter receipt or source pool does not cover the same
    /// whole selected signature; a preceding-archive subset is insufficient.
    Scope,
    /// Current metadata/storage admission failed before traversal or growth.
    Resource(MemoryError),
}

/// Conditional incorporation result in this original XML identity domain.
pub type ReferencePresenceResult<'report, 'references, 'source, X> = Result<
    ReferencePresence<
        'report,
        'references,
        'source,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    ReferencePresenceError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Evaluate Annex A.1.1–A.1.4's conditional "present elsewhere" requirement
/// from the SAME completed original digest search. Certificate/status values,
/// qualifying nonempty `AnyValidationData` and `ArchiveTimeStamp` activate their
/// respective obligations. Their URI and Number hints never replace presence.
/// The exact token source census is checked against whole-scope requirements
/// and the complete counter receipt before any output allocation. This prevents
/// a root-only/failed-token subset from reporting another pool's values missing
/// or accepting a fabricated empty source set. No parsing/hashing is repeated.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Identifier-only OCSP/open formats remain explicit unproven obligations.
/// Completed inclusion is not authentication, complete/delta applicability,
/// actor-role/reference completeness, freshness, trust or a baseline grade.
///
/// # Panics
/// Only if a privately constructed digest report contains a row outside its
/// own immutable comparison catalogue.
pub fn reference_presence<'report, 'references, 'source, X: Xml, W: Work>(
    digests: &'report ReferenceDigests<'references, 'source, X::Id, X::Document, X::Generation>,
    required: &TimestampRequirements<X::Id, X::Document, X::Generation>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> ReferencePresenceResult<'report, 'references, 'source, X> {
    require_sources(digests, required, counters, access)?;
    let prepared = digests.prepared();
    let mut certificates = false;
    let mut revocations = false;
    for entry in prepared.unsigned().entries() {
        access
            .execution()
            .charge_work(1)
            .map_err(ReferencePresenceError::Resource)?;
        match entry.role {
            unsigned::Role::Certificates | unsigned::Role::AttributeCertificates => {
                certificates = true;
            }
            unsigned::Role::Revocation | unsigned::Role::AttributeRevocation => revocations = true,
            unsigned::Role::Archive => {
                certificates = true;
                revocations = true;
            }
            _ => (),
        }
    }
    for data in prepared.validation() {
        access
            .execution()
            .charge_work(1)
            .map_err(ReferencePresenceError::Resource)?;
        if data.role() == super::Role::Any {
            certificates |= data
                .certificates()
                .is_some_and(|values| !values.entries().is_empty());
            revocations |= data
                .revocations()
                .is_some_and(|values| !values.entries().is_empty());
        }
    }
    let mut rows = access.execution().vector();
    rows.try_reserve_exact(digests.rows().len())
        .map_err(ReferencePresenceError::Resource)?;
    let mut all_present = true;
    for (ordinal, row) in digests.rows().iter().enumerate() {
        access
            .execution()
            .charge_work(1)
            .map_err(ReferencePresenceError::Resource)?;
        let property = &prepared.validation_references()[row.property()];
        let required = match property.role() {
            unsigned::Role::CertificateReferences
            | unsigned::Role::AttributeCertificateReferences => certificates,
            unsigned::Role::RevocationReferences
            | unsigned::Role::AttributeRevocationReferences => revocations,
            _ => unreachable!("privately constructed reference property role"),
        };
        let failure = if required {
            presence_failure(
                row.search(),
                digests
                    .comparisons(ordinal)
                    .expect("original comparison row"),
                access.execution(),
            )
            .map_err(ReferencePresenceError::Resource)?
        } else {
            None
        };
        if failure.is_some() {
            all_present = false;
        }
        rows.try_push(ReferencePresenceRow { required, failure })
            .map_err(ReferencePresenceError::Resource)?;
    }
    access
        .query(required.signature(), |_, _, _| Ok(()))
        .map_err(ReferencePresenceError::Access)?;
    Ok(ReferencePresence {
        digests,
        rows: rows.into_owned(),
        all_present,
    })
}

fn presence_failure<W: Work>(
    search: ReferenceSearch,
    values: &[super::MaterialDigest],
    work: &W,
) -> Result<Option<ReferencePresenceFailure>, MemoryError> {
    let mut unavailable = None;
    match search {
        ReferenceSearch::IdentifierOnly => {
            return Ok(Some(ReferencePresenceFailure::IdentifierOnly));
        }
        ReferenceSearch::OtherFormat => return Ok(Some(ReferencePresenceFailure::OtherFormat)),
        ReferenceSearch::Unavailable(cause) => {
            return Ok(Some(ReferencePresenceFailure::Unavailable(cause)));
        }
        ReferenceSearch::Compared => (),
    }
    for value in values {
        work.charge_work(1)?;
        match value.agreement() {
            Agreement::Matches => return Ok(None),
            Agreement::Differs => (),
            cause => {
                if unavailable.is_none() {
                    unavailable = Some(cause);
                }
            }
        }
    }
    Ok(Some(unavailable.map_or(
        ReferencePresenceFailure::Missing,
        ReferencePresenceFailure::Unavailable,
    )))
}

fn require_sources<X: Xml, W: Work>(
    digests: &ReferenceDigests<'_, '_, X::Id, X::Document, X::Generation>,
    required: &TimestampRequirements<X::Id, X::Document, X::Generation>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> Result<(), ReferencePresenceError<X::Error, X::Id>> {
    let original = digests.prepared().bound().containers();
    let TimestampScope::All(scope) = required.scope() else {
        return Err(ReferencePresenceError::Scope);
    };
    if original.snapshot() != access.snapshot()
        || scope.snapshot != original.snapshot()
        || counters.snapshot() != original.snapshot()
    {
        return Err(ReferencePresenceError::Scope);
    }
    access
        .query(original.signature(), |_, _, _| Ok(()))
        .map_err(ReferencePresenceError::Access)?;
    if !access
        .equal_id(scope.node, original.signature())
        .map_err(ReferencePresenceError::Resource)?
        || !access
            .equal_id(required.signature(), original.signature())
            .map_err(ReferencePresenceError::Resource)?
        || !access
            .equal_id(counters.signature(), original.signature())
            .map_err(ReferencePresenceError::Resource)?
        || !required
            .includes_counters(counters, access)
            .map_err(|cause| ReferencePresenceError::Access(cause.into()))?
    {
        return Err(ReferencePresenceError::Scope);
    }
    let Some(sources) = digests.tokens() else {
        if required.entries().is_empty() {
            return Ok(());
        }
        return Err(ReferencePresenceError::Scope);
    };
    if sources.len() != required.entries().len() {
        return Err(ReferencePresenceError::Scope);
    }
    for (source, entry) in sources.iter().zip(required.entries()) {
        access
            .execution()
            .charge_work(1)
            .map_err(ReferencePresenceError::Resource)?;
        if source.location().snapshot != original.snapshot()
            || source.role().purpose() != entry.purpose
            || !access
                .equal_id(source.signature(), entry.signature)
                .map_err(ReferencePresenceError::Resource)?
            || !access
                .equal_id(source.property(), entry.property)
                .map_err(ReferencePresenceError::Resource)?
            || !access
                .equal_id(source.location().node, entry.token)
                .map_err(ReferencePresenceError::Resource)?
        {
            return Err(ReferencePresenceError::Scope);
        }
    }
    Ok(())
}
