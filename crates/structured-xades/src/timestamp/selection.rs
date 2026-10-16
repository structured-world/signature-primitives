//! Complete original timestamp requirements for LT and one archive boundary.

use super::{InputError, Role};
use crate::binary::Location;
use crate::prepare::Prepared;
use crate::xml::{Access, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

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

/// Original source boundary actually selected by the shared requirement kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampScope<N, D, G> {
    /// Whole selected signature; no archive-precedence assertion is made.
    All(Location<N, D, G>),
    /// Original archive property, excluding its own and later unsigned tokens.
    BeforeArchive(Location<N, D, G>),
}

impl<N: Copy, D: Copy, G: Copy> TimestampScope<N, D, G> {
    /// Real enclosing signature/archive location for source checks and errors.
    #[must_use]
    pub fn location(self) -> Location<N, D, G> {
        match self {
            Self::All(location) | Self::BeforeArchive(location) => location,
        }
    }
}

/// One original token obligation; this is not a successful timestamp receipt.
#[derive(Debug, Clone, Copy)]
pub struct RequiredToken<N> {
    /// Actual root or nested signature whose input this token covers.
    pub signature: N,
    /// Original timestamp property.
    pub property: N,
    /// Original encapsulated token, independently of its decoded bytes.
    pub token: N,
    /// Actual input-selection role, never inferred from successful signatures.
    pub role: Role,
}

/// Complete original token set for one explicit protocol scope. Failed or
/// unreadable tokens cannot disappear behind a caller's successful subset.
pub struct TimestampRequirements<N, D, G> {
    signature: N,
    scope: TimestampScope<N, D, G>,
    entries: OwnedVec<RequiredToken<N>>,
    counters: Option<OwnedVec<N>>,
    // Complete source census above remains mandatory. This separate aligned
    // mask selects only actors actually covered by an earlier archive.
    counter_scope: Option<OwnedVec<bool>>,
}

impl<N: Copy, D: Copy, G: Copy> TimestampRequirements<N, D, G> {
    /// Original selected signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Actual whole-signature or preceding-archive scope.
    #[must_use]
    pub fn scope(&self) -> TimestampScope<N, D, G> {
        self.scope
    }
    /// Every original token in prepared property/token order.
    #[must_use]
    pub fn entries(&self) -> &[RequiredToken<N>] {
        &self.entries
    }
}

/// Source refusal and caller selection errors are not failed token assertions.
#[derive(Debug)]
pub enum RequirementError<E, N> {
    /// Original source, generation or current-operation refusal.
    Input(InputError<E, N>),
    /// Original archive input coverage could not be selected completely.
    Coverage(super::CoverageError<E, N>),
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
    TimestampRequirements<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    RequirementError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Checked TSA paths for every token in the SAME original scope. No token
/// authentication, temporal acceptance or application trust is repeated here.
pub struct TimestampPaths<'view, 'certificate, 'document, N, D, G> {
    required: &'view TimestampRequirements<N, D, G>,
    paths: &'view [&'view crate::pki::TimestampPath<'view, 'certificate, 'document, N, D, G>],
}

impl<'view, 'certificate, 'document, N, D, G>
    TimestampPaths<'view, 'certificate, 'document, N, D, G>
{
    /// Complete original token obligations; their scope cannot be relabelled.
    #[must_use]
    pub fn required(&self) -> &'view TimestampRequirements<N, D, G> {
        self.required
    }
    /// Actual paths in original obligation order, without copying.
    #[must_use]
    pub fn paths(
        &self,
    ) -> &'view [&'view crate::pki::TimestampPath<'view, 'certificate, 'document, N, D, G>] {
        self.paths
    }
}

/// Missing/wrong proofs cannot establish a successful partial token set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPathFailure {
    /// Every original token requires one actual checked TSA path.
    Count,
    /// A supplied path belongs to a different original token or source.
    Source {
        /// Original obligation ordinal, not an ASN.1 or XML offset.
        index: usize,
    },
}

/// Complete path association or explicit insufficient original proofs.
pub enum TimestampPathBinding<'view, 'certificate, 'document, N, D, G> {
    /// Every required token has its actual original TSA path.
    Bound(TimestampPaths<'view, 'certificate, 'document, N, D, G>),
    /// No complete proof set exists; no successful prefix is returned.
    Unproven(TimestampPathFailure),
}

impl<N: Copy + Eq, D: Copy + Eq, G: Copy + Eq> TimestampRequirements<N, D, G> {
    pub(crate) fn counter_in_scope<X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &self,
        ordinal: usize,
        access: &Access<'_, X, W>,
    ) -> super::InputResult<bool, X> {
        let node = self.scope.location().node;
        if self.scope.location().snapshot != access.snapshot() {
            return Err(InputError::Foreign { node });
        }
        access
            .query(node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(|cause| InputError::Resource { node, cause })?;
        match self.scope {
            TimestampScope::All(_) => Ok(true),
            TimestampScope::BeforeArchive(_) => {
                let Some(scope) = &self.counter_scope else {
                    return Err(InputError::Foreign { node });
                };
                scope
                    .get(ordinal)
                    .copied()
                    .ok_or(InputError::Foreign { node })
            }
        }
    }
    pub(crate) fn includes_counters<X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &self,
        counters: &crate::pki::CounterPaths<'_, '_, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> super::InputResult<bool, X> {
        let Some(expected) = &self.counters else {
            return Ok(counters.actors().is_empty());
        };
        if expected.len() != counters.actors().len() {
            return Ok(false);
        }
        for (index, actor) in counters.actors().iter().enumerate() {
            let node = actor.signer().counter().original().child();
            if !access
                .equal_id(expected[index], node)
                .map_err(|cause| InputError::Resource { node, cause })?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Associate actual paths once per original token. The SAME source/role
    /// comparison governs all-token LT and preceding-archive requirements.
    pub fn bind_paths<
        'view,
        'certificate,
        'document,
        X: Xml<Id = N, Document = D, Generation = G>,
        W: Work,
    >(
        &'view self,
        paths: &'view [&'view crate::pki::TimestampPath<'view, 'certificate, 'document, N, D, G>],
        access: &Access<'_, X, W>,
    ) -> super::InputResult<TimestampPathBinding<'view, 'certificate, 'document, N, D, G>, X> {
        let location = self.scope.location();
        if location.snapshot != access.snapshot() {
            return Err(InputError::Foreign {
                node: location.node,
            });
        }
        let pay = || {
            access
                .query(self.signature, |_, _, work| Ok(work.charge_work(1)))
                .map_err(InputError::Access)?
                .map_err(|cause| InputError::Resource {
                    node: location.node,
                    cause,
                })
        };
        pay()?;
        if paths.len() != self.entries.len() {
            return Ok(TimestampPathBinding::Unproven(TimestampPathFailure::Count));
        }
        for (index, path) in paths.iter().enumerate() {
            pay()?;
            let expected = &self.entries[index];
            let actual = path.actor().verified();
            let resource = |cause| InputError::Resource {
                node: location.node,
                cause,
            };
            if !access
                .equal_id(actual.signature(), expected.signature)
                .map_err(resource)?
                || !access
                    .equal_id(actual.property(), expected.property)
                    .map_err(resource)?
                || actual.token().snapshot != location.snapshot
                || !access
                    .equal_id(actual.token().node, expected.token)
                    .map_err(resource)?
                || actual.role() != expected.role
            {
                return Ok(TimestampPathBinding::Unproven(
                    TimestampPathFailure::Source { index },
                ));
            }
        }
        Ok(TimestampPathBinding::Bound(TimestampPaths {
            required: self,
            paths,
        }))
    }
}

/// Derive this selected signature's OWN original token set without parsing or
/// cloning token bytes. Use [`requirements_with_counters`] for a whole actor
/// census; [`crate::pki::participants`] refuses this root-only set when counters
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
                    role: stamp.role(),
                })
                .map_err(resource)?;
        }
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(InputError::Access)?;
    Ok(TimestampRequirements {
        signature,
        scope,
        entries: entries.into_owned(),
        counters: None,
        counter_scope: None,
    })
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
    let mut required = requirements(access, prepared, selection)?;
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
    let counter_scope = if let Some(coverage) = &coverage {
        let mut mask = access.execution().vector();
        let mut index = 0;
        while index < signatures.len() {
            access
                .query(signature, |_, _, work| Ok(work.charge_work(1)))
                .map_err(InputError::Access)?
                .map_err(resource)?;
            let included = coverage
                .selects(signatures[index], access)
                .map_err(RequirementError::Coverage)?;
            mask.try_push(included).map_err(resource)?;
            index += 1;
        }
        Some(mask.into_owned())
    } else {
        None
    };
    let mut entries = required
        .entries
        .with_execution(access.execution())
        .map_err(|_| InputError::Foreign { node: signature })?;
    for child in counters.entries() {
        let stamp = child.stamp();
        access
            .query(stamp.node(), |_, _, work| Ok(work.charge_work(1)))
            .map_err(InputError::Access)?
            .map_err(resource)?;
        if let Some(coverage) = &coverage
            && !coverage
                .selects(stamp.node(), access)
                .map_err(RequirementError::Coverage)?
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
                    role: stamp.role(),
                })
                .map_err(resource)?;
        }
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(InputError::Access)?;
    required.entries = entries.into_owned();
    required.counters = Some(signatures.into_owned());
    required.counter_scope = counter_scope;
    Ok(required)
}
