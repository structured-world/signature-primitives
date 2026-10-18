//! Complete original timestamp requirements for LT and one archive boundary.

use super::{InputError, Role};
use crate::binary::Location;
use crate::prepare::Prepared;
use crate::xml::{Access, Xml};
use crate::{ISSUER, Xades};
use structured_asn1::memory::{MemoryError, Work};
use structured_ltv::timestamp::{RequiredToken, TimestampRequirements, TimestampScope};

/// Protocol scope to derive from complete original preparation, not a policy
/// switch or permission to omit failed timestamps from an attained level.
#[derive(Debug, Clone, Copy)]
pub enum TimestampSelection {
    /// Every incorporated token, including archive tokens and later timestamps.
    All,
    /// Tokens preceding this archive ordinal in the prepared timestamp set.
    BeforeArchive(usize),
}

impl TimestampSelection {
    fn includes(self, ordinal: usize, role: Role) -> bool {
        match self {
            Self::All => true,
            Self::BeforeArchive(archive) => {
                ordinal < archive
                    || matches!(role, Role::AllDataObjects | Role::IndividualDataObjects)
            }
        }
    }
}

/// Source refusal and caller selection errors are not failed token assertions.
#[derive(Debug)]
pub enum RequirementError<E, N> {
    /// Original source, generation or current-operation refusal.
    Input(InputError<E, N>),
    /// Original archive input coverage could not be selected completely.
    Coverage(super::CoverageError<E, N>),
    /// Archive coverage of a countersignature could not be tested.
    Selection(structured_ltv::material::CoverageError<N>),
    /// No timestamp exists at this prepared catalogue ordinal.
    Index {
        /// Original selected signature.
        signature: N,
        /// Caller-provided ordinal, not an XML offset.
        index: usize,
    },
    /// The selected original timestamp is not an archive.
    Role {
        /// Original selected property.
        property: N,
    },
}

impl<E, N> From<InputError<E, N>> for RequirementError<E, N> {
    fn from(cause: InputError<E, N>) -> Self {
        Self::Input(cause)
    }
}

/// Timestamp census using this XML owner's original identity/error domain.
pub type RequirementResult<X> = Result<
    TimestampRequirements<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, Xades>,
    RequirementError<<X as Xml>::Error, <X as Xml>::Id>,
>;

type Entries<X, W> = structured_asn1::memory::OwnedVec<RequiredToken<<X as Xml>::Id>, W>;

/// Derive this selected signature's OWN original token set without parsing or
/// cloning token bytes. Use [`requirements_with_counters`] for a whole actor
/// census; the participant census refuses this root-only set when counters
/// are present, even when their timestamps have no successful proof yet.
/// EN319132-1 §6.3(x) requires incorporated timestamp validation data;6.3(aa)
/// requires earlier material before EACH archive, excluding its own tokens.
/// Signed data-object timestamps precede unsigned archives even though they
/// are prepared after the unsigned-property pass. Both scopes use ONE selector,
/// two paid metadata passes and one admitted exact output allocation.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// This derives obligations only, not a baseline grade, temporal/trust verdict
/// or usable material. An unsupported/failed token must still be accounted for.
pub fn requirements<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    selection: TimestampSelection,
) -> RequirementResult<X> {
    let (scope, entries) = root_entries(access, prepared, selection)?;
    let signature = prepared.bound().containers().signature();
    Ok(TimestampRequirements::new(
        ISSUER,
        signature,
        scope,
        entries.into_owned(),
    ))
}

type RootEntries<X, W> = Result<
    (
        TimestampScope<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
        Entries<X, W>,
    ),
    RequirementError<<X as Xml>::Error, <X as Xml>::Id>,
>;

fn root_entries<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    selection: TimestampSelection,
) -> RootEntries<X, W> {
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() {
        return Err(InputError::Foreign { node: signature }.into());
    }
    let pay = || {
        access
            .query(signature, |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(|cause| InputError::Resource {
                node: signature,
                cause,
            })
    };
    pay()?;
    let scope = match selection {
        TimestampSelection::All => TimestampScope::All(Location {
            snapshot: access.snapshot(),
            node: signature,
        }),
        TimestampSelection::BeforeArchive(index) => {
            let Some(selected) = prepared.timestamps().get(index) else {
                return Err(RequirementError::Index { signature, index });
            };
            if selected.role() != Role::Archive {
                return Err(RequirementError::Role {
                    property: selected.node(),
                });
            }
            TimestampScope::BeforeArchive(Location {
                snapshot: access.snapshot(),
                node: selected.node(),
            })
        }
    };
    let resource = |cause| InputError::Resource {
        node: scope.location().node,
        cause,
    };
    let mut count = 0usize;
    for (ordinal, stamp) in prepared.timestamps().iter().enumerate() {
        pay()?;
        if selection.includes(ordinal, stamp.role()) {
            count = count
                .checked_add(stamp.tokens().len())
                .ok_or_else(|| resource(MemoryError::WorkExceeded))?;
        }
    }
    let mut entries = access.execution().vector();
    entries.try_reserve_exact(count).map_err(resource)?;
    for (ordinal, stamp) in prepared.timestamps().iter().enumerate() {
        pay()?;
        if !selection.includes(ordinal, stamp.role()) {
            continue;
        }
        for token in stamp.tokens() {
            pay()?;
            entries
                .try_push(RequiredToken {
                    signature,
                    property: stamp.node(),
                    token: *token,
                    purpose: stamp.role().purpose(),
                })
                .map_err(resource)?;
        }
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(InputError::Access)?;
    Ok((scope, entries))
}

/// Derive complete root AND nested-counter token obligations. For an archive,
/// child properties enter only when its actual original input selects their
/// whole element; a later countersignature cannot become an earlier TSA actor.
/// This reuses the root input/coverage kernel, not XML ordinal arithmetic or a
/// caller-written list of successful timestamps. No canonicalization is run.
pub fn requirements_with_counters<X: super::TimestampXml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    counters: &super::CounterTimestamps<X::Id, X::Document, X::Generation>,
    selection: TimestampSelection,
) -> RequirementResult<X> {
    let signature = prepared.bound().containers().signature();
    let resource = |cause| InputError::Resource {
        node: signature,
        cause,
    };
    if counters.snapshot != access.snapshot()
        || !access
            .equal_id(counters.signature, signature)
            .map_err(resource)?
    {
        return Err(InputError::Foreign { node: signature }.into());
    }
    let (scope, mut entries) = root_entries(access, prepared, selection)?;
    let mut signatures = access.execution().vector();
    signatures
        .try_extend_from_slice(&counters.signatures)
        .map_err(resource)?;
    let coverage = match selection {
        TimestampSelection::All => None,
        TimestampSelection::BeforeArchive(index) => {
            // The root kernel above has already checked ordinal and role.
            let input = super::Input::prepare(
                access.owner(),
                prepared.bound(),
                &prepared.timestamps()[index],
                access.execution(),
            )?;
            Some(
                input
                    .element_coverage(access.execution())
                    .map_err(RequirementError::Coverage)?,
            )
        }
    };
    // EN319132-1 6.3(aa) describes material present BEFORE generating this
    // archive. 5.5.2.1 note4 permits later countersignatures. Their own actors
    // and credentials are not antecedents merely because the final LT census
    // contains them. Reuse exactly the existing original element coverage.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let covered = if let Some(coverage) = &coverage {
        let mut mask = access.execution().vector();
        let mut index = 0;
        while index < signatures.len() {
            access
                .query(signature, |_, _, work| Ok(work.charge_work(1)))
                .map_err(InputError::Access)?
                .map_err(resource)?;
            let included = coverage
                .selects(signatures[index], access)
                .map_err(RequirementError::Selection)?;
            mask.try_push(included).map_err(resource)?;
            index += 1;
        }
        Some(mask.into_owned())
    } else {
        None
    };
    for child in counters.entries() {
        let stamp = child.stamp();
        access
            .query(stamp.node(), |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(resource)?;
        if let Some(coverage) = &coverage
            && !coverage
                .selects(stamp.node(), access)
                .map_err(RequirementError::Selection)?
        {
            continue;
        }
        for token in stamp.tokens() {
            access
                .query(*token, |_, _, work| Ok(work.charge_work(1)))
                .map_err(InputError::Access)?
                .map_err(resource)?;
            entries
                .try_push(RequiredToken {
                    signature: stamp.signature,
                    property: stamp.node(),
                    token: *token,
                    purpose: stamp.role().purpose(),
                })
                .map_err(resource)?;
        }
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(InputError::Access)?;
    Ok(TimestampRequirements::with_counters(
        ISSUER,
        signature,
        scope,
        entries.into_owned(),
        signatures.into_owned(),
        covered,
    ))
}
