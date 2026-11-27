//! Original historical timestamp obligations and the shared RFC 3161 pool.

use super::{Prepared, Profile, timestamp as old};
use crate::{
    ISSUER,
    binary::{BinaryXml, Location, OwnedBinaryXml},
    timestamp::{
        self, CheckError, InputError, Role, Timestamp, TimestampSelection, TokenEntry,
        TokenPipelineResult, TokenProfile, TokenView,
        tokens::{self, TokenGroup},
    },
    xml::{Access, AccessError, Xml},
};
use structured_asn1::{
    Reader,
    memory::{Execution, MemoryError, OwnedVec, Work},
};
use structured_cms::{
    provider::SignatureProvider,
    stream::{Receiver, Source},
    timestamp::{CheckedTimestamp, TokenExtension},
};
use structured_ltv::timestamp::{RequiredToken, TimestampRequirements, TimestampScope};

/// Source-selection refusal before any token or credential check.
#[derive(Debug)]
pub enum ValidationError<E, N> {
    /// Original document or timestamp recipe refusal.
    Input(InputError<E, N>),
    /// Original child qualifying signature could not be prepared.
    Child(super::Error<E, N>),
}

/// Historical operation using the XML owner's exact error and identity types.
pub type ValidationResult<T, X> = Result<T, ValidationError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Historical role grammar or common credential processing refusal.
#[derive(Debug)]
pub enum CredentialError<E, PE, N> {
    /// Original protected role property could not be read.
    Property(crate::properties::Error<E, N>),
    /// Original actor/provider, current operation or scope refusal.
    Check(crate::credential::Error<E, PE, N>),
}

/// Role and credential evaluation using this historical source's identities.
pub type CredentialResult<'path, 'document, X, P> = Result<
    crate::credential::ParticipantCredentials<
        'path,
        'document,
        <P as crate::credential::Provider<'path, 'document, X>>::Evidence,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    CredentialError<
        <X as Xml>::Error,
        <P as crate::credential::Provider<'path, 'document, X>>::Error,
        <X as Xml>::Id,
    >,
>;

/// Assess the actual protected historical roles and all checked child roles
/// through the common credential providers and participant census.
pub fn check_credentials<
    'path,
    'document,
    X: Xml,
    P: crate::credential::Provider<'path, 'document, X>,
    W: Work,
>(
    prepared: &Prepared<X>,
    counters: &crate::pki::CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    provider: &P,
    access: &Access<'_, X, W>,
) -> CredentialResult<'path, 'document, X, P> {
    let roles = prepared.roles(access).map_err(CredentialError::Property)?;
    crate::credential::check_scope(
        prepared.binding(),
        roles.as_ref(),
        counters,
        provider,
        access,
    )
    .map_err(CredentialError::Check)
}

/// Actual timestamp grammar from the explicitly selected historical profile.
pub enum Occurrence<X: Xml> {
    /// TS 101 903 V1.1.1 `HashDataInfo` and original transforms.
    HashData(old::HashDataStamp<X>),
    /// TS 101 903 V1.2.2 Include and original method.
    Include(old::Stamp<X>),
    /// TS 103 171 implied input with the appropriate archive vocabulary.
    PreEn(Timestamp<X>),
}

impl<X: Xml> Occurrence<X> {
    /// Original timestamp property.
    #[must_use]
    pub fn node(&self) -> X::Id {
        match self {
            Self::HashData(stamp) => stamp.node(),
            Self::Include(stamp) => stamp.node(),
            Self::PreEn(stamp) => stamp.node(),
        }
    }

    /// Actual original input role.
    #[must_use]
    pub fn role(&self) -> Role {
        match self {
            Self::HashData(stamp) => stamp.role(),
            Self::Include(stamp) => stamp.role(),
            Self::PreEn(stamp) => stamp.role(),
        }
    }

    /// All original token identities, including an open XML timestamp.
    #[must_use]
    pub fn tokens(&self) -> &[X::Id] {
        match self {
            Self::HashData(stamp) => stamp.original_token().all(),
            Self::Include(stamp) => stamp.original_token().all(),
            Self::PreEn(stamp) => stamp.tokens(),
        }
    }

    pub(super) fn encoded(&self) -> &[X::Id] {
        match self {
            Self::HashData(stamp) => stamp.original_token().encoded(),
            Self::Include(stamp) => stamp.original_token().encoded(),
            Self::PreEn(stamp) => stamp.tokens(),
        }
    }

    fn group(&self, signature: X::Id) -> TokenGroup<'_, X::Id> {
        TokenGroup {
            signature,
            property: self.node(),
            role: self.role(),
            tokens: self.encoded(),
        }
    }
}

/// Complete original timestamp properties on the bound historical signature.
/// Signed object timestamps are before all unsigned timestamps and archives.
pub struct Inventory<'bound, X: Xml> {
    pub(crate) prepared: &'bound Prepared<X>,
    entries: OwnedVec<Occurrence<X>>,
    children: Option<Children<X>>,
}

struct Children<X: Xml> {
    signatures: OwnedVec<(X::Id, Option<Prepared<X>>)>,
    entries: OwnedVec<(usize, Occurrence<X>)>,
}

/// Read the prescribed original timestamp grammar without running transforms or
/// parsing any carried token. No successful subset is returned on refusal.
pub fn inventory<'bound, X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &'bound Prepared<X>,
    uri: old::HashDataUri,
) -> ValidationResult<Inventory<'bound, X>, X> {
    let entries = entries(access, prepared, uri)?;
    Ok(Inventory {
        prepared,
        entries,
        children: None,
    })
}

/// Prepare the original root and every verified countersignature in one
/// historical timestamp census. Child layouts come from the complete checked
/// counter walk of this exact signature. Plain `XMLDSig` children have no `XAdES`
/// timestamp properties but remain in the signature census.
pub fn inventory_with_counters<
    'bound,
    X: crate::binding::SignatureXml + crate::scalar::ScalarXml,
    W: Work,
>(
    access: &Access<'_, X, W>,
    prepared: &'bound Prepared<X>,
    counters: &crate::pki::CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    uri: old::HashDataUri,
) -> ValidationResult<Inventory<'bound, X>, X> {
    let mut result = inventory(access, prepared, uri)?;
    let root = result.root();
    if counters.snapshot() != root.snapshot
        || !access
            .equal_id(counters.signature(), root.node)
            .map_err(|cause| resource(root.node, cause))?
    {
        return Err(ValidationError::Input(InputError::Foreign {
            node: counters.signature(),
        }));
    }
    let mut signatures = access.execution().vector();
    let mut occurrences = access.execution().vector();
    signatures
        .try_reserve_exact(counters.actors().len())
        .map_err(|cause| resource(root.node, cause))?;
    for actor in counters.actors() {
        let signature = actor.signer().counter().original().child();
        charge::<X, W>(access.execution(), signature)?;
        let child = if let Some(layout) = actor.containers() {
            let child = super::prepare(access, &super::Layout::new(*layout))
                .map_err(ValidationError::Child)?;
            for item in entries(access, &child, uri)? {
                let node = item.node();
                occurrences
                    .try_push((signatures.len(), item))
                    .map_err(|cause| resource(node, cause))?;
            }
            Some(child)
        } else {
            None
        };
        signatures
            .try_push((signature, child))
            .map_err(|cause| resource(signature, cause))?;
    }
    admit(access, root)?;
    result.children = Some(Children {
        signatures: signatures.into_owned(),
        entries: occurrences.into_owned(),
    });
    Ok(result)
}

fn entries<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    uri: old::HashDataUri,
) -> ValidationResult<OwnedVec<Occurrence<X>>, X> {
    let layout = prepared.binding().containers();
    let root = Location {
        snapshot: layout.snapshot(),
        node: layout.signature(),
    };
    admit(access, root)?;
    let mut output = access.execution().vector();
    for property in prepared.signed_objects().iter().chain(prepared.unsigned()) {
        charge::<X, W>(access.execution(), property.node)?;
        if old::role(property.name).is_none() {
            continue;
        }
        let entry = match prepared.profile() {
            Profile::V111 => old::HashDataStamp::read(access, prepared, property.node, uri)
                .map(Occurrence::HashData),
            Profile::V122 => old::read(access, prepared, property.node).map(Occurrence::Include),
            Profile::PreEn => {
                old::read_pre_en(access, prepared, property.node).map(Occurrence::PreEn)
            }
        }
        .map_err(ValidationError::Input)?;
        output
            .try_push(entry)
            .map_err(|cause| resource(property.node, cause))?;
    }
    admit(access, root)?;
    Ok(output.into_owned())
}

impl<X: Xml> Inventory<'_, X> {
    /// Original timestamp property and all its token identities.
    #[must_use]
    pub fn entries(&self) -> &[Occurrence<X>] {
        &self.entries
    }

    pub(super) fn root(&self) -> Location<X::Id, X::Document, X::Generation> {
        let layout = self.prepared.binding().containers();
        Location {
            snapshot: layout.snapshot(),
            node: layout.signature(),
        }
    }

    /// Included child timestamp properties in the verified counter walk order.
    pub fn counter_entries(&self) -> impl Iterator<Item = (X::Id, &Occurrence<X>)> {
        self.children.iter().flat_map(|children| {
            children
                .entries
                .iter()
                .map(|(owner, item)| (children.signatures[*owner].0, item))
        })
    }

    pub(crate) fn children(&self) -> impl Iterator<Item = (X::Id, Option<&Prepared<X>>)> {
        self.children.iter().flat_map(|children| {
            children
                .signatures
                .iter()
                .map(|(node, child)| (*node, child.as_ref()))
        })
    }

    pub(crate) fn includes_counters(&self) -> bool {
        self.children.is_some()
    }

    fn source(&self, index: usize) -> Option<(&Prepared<X>, &Occurrence<X>)> {
        if let Some(item) = self.entries.get(index) {
            return Some((self.prepared, item));
        }
        let children = self.children.as_ref()?;
        let (owner, item) = children.entries.get(index - self.entries.len())?;
        Some((children.signatures[*owner].1.as_ref()?, item))
    }

    /// Derive the actual requirements before the selected archive or across the
    /// root. Open XML tokens remain obligations even without an RFC 3161 entry.
    /// This scope represents the root only. The common census refuses to use
    /// a root-only token set as the complete scope of a signature with counters.
    pub fn requirements<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        selection: TimestampSelection,
    ) -> crate::timestamp::RequirementResult<X> {
        let (scope, tokens) = self.root_requirements(access, selection)?;
        Ok(TimestampRequirements::new(
            ISSUER,
            self.root().node,
            scope,
            tokens.into_owned(),
        ))
    }

    fn root_requirements<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        selection: TimestampSelection,
    ) -> RootResult<X, W> {
        let root = self.root();
        let input = |error| crate::timestamp::RequirementError::Input(error);
        if access.snapshot() != root.snapshot {
            return Err(input(InputError::Access(AccessError::Changed {
                node: root.node,
            })));
        }
        access
            .query(root.node, |_, _, _| Ok(()))
            .map_err(|cause| input(InputError::Access(cause)))?;
        let (scope, end) = match selection {
            TimestampSelection::All => (TimestampScope::All(root), self.entries.len()),
            TimestampSelection::BeforeArchive(index) => {
                let stamp =
                    self.entries
                        .get(index)
                        .ok_or(crate::timestamp::RequirementError::Index {
                            signature: root.node,
                            index,
                        })?;
                if stamp.role() != Role::Archive {
                    return Err(crate::timestamp::RequirementError::Role {
                        property: stamp.node(),
                    });
                }
                (
                    TimestampScope::BeforeArchive(Location {
                        snapshot: root.snapshot,
                        node: stamp.node(),
                    }),
                    index,
                )
            }
        };
        let mut tokens = access.execution().vector();
        for occurrence in &self.entries[..end] {
            access.execution().charge_work(1).map_err(|cause| {
                input(InputError::Resource {
                    node: occurrence.node(),
                    cause,
                })
            })?;
            append_requirements(&mut tokens, root.node, occurrence)?;
        }
        access
            .query(root.node, |_, _, _| Ok(()))
            .map_err(|cause| input(InputError::Access(cause)))?;
        Ok((scope, tokens))
    }
}

type RootResult<X, W> = Result<
    (
        TimestampScope<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
        OwnedVec<RequiredToken<<X as Xml>::Id>, W>,
    ),
    crate::timestamp::RequirementError<<X as Xml>::Error, <X as Xml>::Id>,
>;

fn append_requirements<X: Xml, W: Work>(
    tokens: &mut OwnedVec<RequiredToken<X::Id>, W>,
    signature: X::Id,
    occurrence: &Occurrence<X>,
) -> Result<(), InputError<X::Error, X::Id>> {
    for &token in occurrence.tokens() {
        tokens
            .try_push(RequiredToken {
                signature,
                property: occurrence.node(),
                token,
                purpose: occurrence.role().purpose(),
            })
            .map_err(|cause| InputError::Resource { node: token, cause })?;
    }
    Ok(())
}

impl<X: OwnedBinaryXml> Inventory<'_, X> {
    /// Retain and parse the exact original RFC 3161 fields once, using the shared
    /// token pool. XML timestamp placeholders stay in the requirement inventory.
    pub fn with_tokens<R, VE>(
        &self,
        xml: &X,
        operation: &Reader<'_>,
        profile: TokenProfile,
        visitor: impl for<'source> FnOnce(
            &Reader<'source>,
            TokenView<'source, X::Id, X::Document, X::Generation>,
        ) -> Result<R, VE>,
    ) -> TokenPipelineResult<R, X, VE> {
        let root = self.root();
        let groups = self.entries.iter().map(|item| item.group(root.node)).chain(
            self.counter_entries()
                .map(|(signature, item)| item.group(signature)),
        );
        tokens::with_groups(xml, root, groups, operation, profile, visitor)
    }
}

/// Checked common token facts and any positive actor from the same token/source.
pub type CheckResult<'certificate, 'document, R, X, PE, RE> = timestamp::CheckResult<
    (
        R,
        Option<timestamp::TimestampActor<'certificate, 'document, X>>,
    ),
    X,
    PE,
    RE,
>;

impl<X: old::HashDataXml + BinaryXml> Inventory<'_, X> {
    /// Check an already decoded original token against its actual historical
    /// recipe. Only a completed positive check returns a TSA actor. A missing
    /// HashDataInfo/Include target cannot be substituted by a similar node.
    #[expect(
        clippy::result_large_err,
        reason = "preserve original processing and source-map failures"
    )]
    pub fn check_actor_from<'document, 'certificate, P, R, PE, RE>(
        &self,
        checker: &timestamp::Check<'_, 'document, 'certificate, '_, X, P>,
        entry: TokenEntry<'_, '_, X::Id, X::Document, X::Generation>,
        operation: &Reader<'_>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        visitor: impl for<'checked> FnOnce(&CheckedTimestamp<'checked>) -> R,
    ) -> CheckResult<'certificate, 'document, R, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let source = entry.source();
        let (prepared, item) =
            self.source(source.stamp_index())
                .ok_or(CheckError::Input(InputError::Foreign {
                    node: source.location().node,
                }))?;
        let bound = prepared.binding();
        let layout = bound.containers();
        let execution = operation.execution();
        checker.check_site_from(
            (
                layout.snapshot(),
                layout.syntax(),
                item.group(layout.signature()),
            ),
            entry,
            (operation, &execution),
            recognizes,
            visitor,
            |work| {
                let access = Access::new(checker.xml, layout.snapshot(), work);
                prepare_input(&access, prepared, item)
            },
        )
    }
}

fn prepare_input<'xml, X: old::HashDataXml, W: Work>(
    access: &Access<'xml, X, W>,
    prepared: &Prepared<X>,
    item: &Occurrence<X>,
) -> timestamp::InputResult<Covered<'xml, X>, X> {
    match item {
        Occurrence::HashData(stamp) => {
            old::HashDataInput::prepare(access, prepared, stamp).map(Covered::HashData)
        }
        Occurrence::Include(stamp) => old::input(access, prepared, stamp).map(Covered::Include),
        Occurrence::PreEn(stamp) => timestamp::Input::prepare(
            access.owner(),
            prepared.binding(),
            stamp,
            access.execution(),
        )
        .map(Covered::PreEn),
    }
}

impl<X: old::HashDataXml> Inventory<'_, X> {
    /// Resolve the original archive input and catalogue the element subtrees
    /// it protects. A transformed byte span is not proof of whole-element
    /// coverage. Use the same archive's checked token with the shared
    /// `structured_ltv::material::archived_participants` operation.
    pub fn archive_coverage<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        index: usize,
    ) -> Result<timestamp::CoverageFor<X, W>, timestamp::RequirementError<X::Error, X::Id>> {
        use crate::timestamp::RequirementError;
        let occurrence = self.entries.get(index).ok_or(RequirementError::Index {
            signature: self.root().node,
            index,
        })?;
        if occurrence.role() != Role::Archive {
            return Err(RequirementError::Role {
                property: occurrence.node(),
            });
        }
        let covered = prepare_input(access, self.prepared, occurrence)?;
        let work = access.execution();
        match (&covered, occurrence) {
            (Covered::HashData(input), Occurrence::HashData(stamp)) => input.coverage(stamp, work),
            (Covered::Include(input), Occurrence::Include(stamp)) => input.coverage(stamp, work),
            (Covered::PreEn(input), Occurrence::PreEn(_)) => input.element_coverage(work),
            _ => {
                return Err(InputError::Foreign {
                    node: occurrence.node(),
                }
                .into());
            }
        }
        .map_err(RequirementError::Coverage)
    }

    /// Complete checked-child and root timestamp obligations. For an archive,
    /// the original selected input determines which child parts it protects.
    pub fn requirements_with_counters<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        selection: TimestampSelection,
    ) -> crate::timestamp::RequirementResult<X> {
        use crate::timestamp::RequirementError;
        let root = self.root();
        let children = self
            .children
            .as_ref()
            .ok_or(InputError::Foreign { node: root.node })?;
        let (scope, mut tokens) = self.root_requirements(access, selection)?;
        let coverage = if let TimestampSelection::BeforeArchive(index) = selection {
            Some(self.archive_coverage(access, index)?)
        } else {
            None
        };
        let work = access.execution();
        let mut signatures = work.vector();
        let mut mask = coverage.as_ref().map(|_| work.vector());
        let resource = |node, cause| InputError::Resource { node, cause };
        signatures
            .try_reserve_exact(children.signatures.len())
            .map_err(|cause| resource(root.node, cause))?;
        for &(signature, _) in &children.signatures {
            signatures
                .try_push(signature)
                .map_err(|cause| resource(signature, cause))?;
            if let (Some(coverage), Some(mask)) = (&coverage, &mut mask) {
                let covered = coverage
                    .selects(signature, access)
                    .map_err(RequirementError::Selection)?;
                mask.try_push(covered)
                    .map_err(|cause| resource(signature, cause))?;
            }
        }
        for (signature, occurrence) in self.counter_entries() {
            work.charge_work(1)
                .map_err(|cause| resource(occurrence.node(), cause))?;
            if let Some(coverage) = &coverage
                && !coverage
                    .selects(occurrence.node(), access)
                    .map_err(RequirementError::Selection)?
            {
                continue;
            }
            append_requirements(&mut tokens, signature, occurrence)?;
        }
        access
            .query(root.node, |_, _, _| Ok(()))
            .map_err(InputError::Access)?;
        Ok(TimestampRequirements::with_counters(
            ISSUER,
            root.node,
            scope,
            tokens.into_owned(),
            signatures.into_owned(),
            mask.map(OwnedVec::into_owned),
        ))
    }
}

enum Covered<'xml, X: old::HashDataXml> {
    HashData(old::HashDataInput<'xml, X>),
    Include(old::Input<'xml, X>),
    PreEn(timestamp::Input<'xml, X>),
}

impl<X: old::HashDataXml> Source for Covered<'_, X> {
    type Error = InputError<X::Error, X::Id>;

    fn stream<W: Work>(&mut self, sink: &mut impl Receiver, work: &W) -> Result<(), Self::Error> {
        match self {
            Self::HashData(input) => input.stream(sink, work),
            Self::Include(input) => input.stream(sink, work),
            Self::PreEn(input) => input.stream(sink, work),
        }
    }
}
fn resource<E, N>(node: N, cause: MemoryError) -> ValidationError<E, N> {
    ValidationError::Input(InputError::Resource { node, cause })
}

fn charge<X: Xml, W: Work>(work: &W, node: X::Id) -> ValidationResult<(), X> {
    work.charge_work(1).map_err(|cause| resource(node, cause))
}

fn admit<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    root: Location<X::Id, X::Document, X::Generation>,
) -> ValidationResult<(), X> {
    if access.snapshot() != root.snapshot {
        return Err(ValidationError::Input(InputError::Access(
            AccessError::Changed { node: root.node },
        )));
    }
    access
        .query(root.node, |_, _, _| Ok(()))
        .map_err(|cause| ValidationError::Input(InputError::Access(cause)))
}
