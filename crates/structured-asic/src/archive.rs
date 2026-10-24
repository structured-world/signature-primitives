//! Annex A.7 source-linked archive-manifest coverage and renewal graph.

use crate::{
    error::{Error as ArchiveError, resource},
    layout::{Census, Role},
    manifest::Boolean,
    xml::producer::Facts,
    zip::{Archive, MemberId},
};
use structured_asn1::{
    memory::{OwnedMap, OwnedVec, Work},
    range::RangeSource,
};

mod check;
mod inputs;
mod preservation;
pub use check::{Mathematics, ObjectsState, TimestampCheck, TimestampState};
pub use inputs::{AssertionInput, AssertionScope, InputAssociation, TimestampInputs};
pub use preservation::{ActorCheck, ActorResult, CoverageResult, RequirementsResult};

/// Readable source/coverage problems retain every original occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// The fixed latest filename is absent or ambiguous; no older fallback.
    Latest,
    /// This original archive manifest has no completed producing inspection.
    Uninspected,
    /// Original schema inspection has negative or unassessed findings.
    Syntax,
    /// The one signature reference does not select an actual timestamp member.
    Timestamp,
    /// An object URI is missing, malformed, fragmented or ambiguous.
    Target,
    /// Rootfile does not uniquely identify the immediately preceding manifest.
    Rootfile,
    /// The original predecessor sequence cycles.
    Cycle,
    /// An original archive-manifest occurrence was omitted from the sequence.
    Unreachable,
    /// A later manifest omits a prior object, manifest or timestamp.
    Dropped,
}

/// Original archive occurrence and optional exact instruction/related object.
#[derive(Debug, Clone, Copy)]
pub struct Finding<D, G> {
    /// Owning original archive manifest, absent only for latest-name selection.
    pub manifest: Option<MemberId<D, G>>,
    /// Original `DataObjectReference` ordinal, where applicable.
    pub reference: Option<usize>,
    /// Original missing/dropped/cyclic source occurrence.
    pub related: Option<MemberId<D, G>>,
    /// Completed structural result, never application trust.
    pub kind: FindingKind,
}

/// Caller/processing errors cannot become readable archive conformance faults.
#[derive(Debug)]
pub enum Error<E, D, G> {
    /// Actual source/current processing refused.
    Archive(ArchiveError<E>),
    /// More than one producing reading was supplied for one original occurrence.
    DuplicateFacts(MemberId<D, G>),
    /// A supplied reading belongs to another archive or a non-manifest member.
    ForeignFacts(MemberId<D, G>),
    /// Two actual timestamp receipts were supplied for the same original input.
    DuplicateTimestamp(MemberId<D, G>),
}
type ResultOf<T, S> = Result<
    T,
    Error<<S as RangeSource>::Error, <S as RangeSource>::Document, <S as RangeSource>::Generation>,
>;

/// One original occurrence, including uninspected/unreadable source positions.
pub struct Node<D, G> {
    member: MemberId<D, G>,
    facts: Option<usize>,
    previous: Option<usize>,
    timestamp: Option<MemberId<D, G>>,
    objects: Option<OwnedVec<Option<MemberId<D, G>>>>,
}
impl<D: Copy, G: Copy> Node<D, G> {
    /// Original manifest member identity, not its current filename spelling.
    #[must_use]
    pub fn member(&self) -> MemberId<D, G> {
        self.member
    }
    /// Original producing-facts index; None preserves a missing inspection.
    #[must_use]
    pub fn facts(&self) -> Option<usize> {
        self.facts
    }
    /// Exact predecessor node index, never CD/physical/success order.
    #[must_use]
    pub fn previous(&self) -> Option<usize> {
        self.previous
    }
    /// Exact original timestamp occurrence if the singleton URI resolved.
    #[must_use]
    pub fn timestamp(&self) -> Option<MemberId<D, G>> {
        self.timestamp
    }
    /// Every original object instruction, including unresolved positions.
    #[must_use]
    pub fn objects(&self) -> &[Option<MemberId<D, G>>] {
        match &self.objects {
            Some(objects) => objects,
            None => &[],
        }
    }
}

/// Full original A.7 graph. Positive geometry is independent of timestamp
/// mathematics, validation material, historical trust and algorithm longevity.
/// There is no fallback from an unreadable/bad latest to an earlier success.
pub struct Graph<'v, 's, N, D, G, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    facts: OwnedVec<Facts<'v, 's, N, D, G, S>>,
    nodes: OwnedVec<Node<S::Document, S::Generation>>,
    order: OwnedVec<usize>,
    findings: OwnedVec<Finding<S::Document, S::Generation>>,
    latest: Option<usize>,
    covered: OwnedMap<usize, ()>,
}
impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Graph<'v, 's, N, D, G, S> {
    /// Derives the complete sequence from original Rootfile links. A.7(1–2)
    /// requires each renewal to retain prior objects AND prior manifests/TSTs;
    /// renamed manifests may have arbitrary prefixes. Input order is irrelevant.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf>
    ///
    /// # Panics
    /// An internal immutable catalogue invariant fails if a bounded census or
    /// retained original-member ordinal cannot be selected from its catalogue.
    #[expect(
        clippy::too_many_lines,
        reason = "one transactional graph pass keeps source admission, predecessor cycle detection and cumulative prior coverage in their required order"
    )]
    pub fn inspect<W: Work>(
        census: &Census<'v, 's, S>,
        facts: OwnedVec<Facts<'v, 's, N, D, G, S>>,
        work: &W,
    ) -> ResultOf<Self, S> {
        const LATEST: &[u8] = b"META-INF/ASiCArchiveManifest.xml";
        let archive = census.archive();
        archive
            .admit(work, archive.directory_span())
            .map_err(Error::Archive)?;
        let execution = archive.session().query(work);
        let refusal = |cause| Error::Archive(resource(archive.directory_span(), cause));
        // Reject foreign sources before allocating the graph or invoking a
        // deferred target lookup. Independently retained storage is moved.
        for fact in &facts {
            execution.charge_work(1).map_err(refusal)?;
            if !core::ptr::eq(fact.catalogue().base().archive(), archive) {
                return Err(Error::ForeignFacts(fact.catalogue().base().id()));
            }
        }
        let mut by_source = execution.map();
        for (index, fact) in facts.iter().enumerate() {
            let id = fact.catalogue().base().id();
            if !matches!(
                census
                    .occurrence(id.ordinal(), &execution)
                    .map_err(Error::Archive)?
                    .map(|(_, role)| role),
                Some(Role::ArchiveManifest | Role::Manifest)
            ) {
                return Err(Error::ForeignFacts(id));
            }
            if by_source
                .try_insert(id.ordinal(), index)
                .map_err(refusal)?
                .is_some()
            {
                return Err(Error::DuplicateFacts(id));
            }
        }
        let mut nodes = execution.vector();
        let mut by_member = execution.map();
        let mut findings = execution.vector();
        let mut latest = None;
        let mut latest_count = 0usize;
        for ordinal in 0..census.len() {
            let (member, role) = census
                .occurrence(ordinal, &execution)
                .map_err(Error::Archive)?
                .expect("census length bounds its original ordinal");
            if role != Role::ArchiveManifest {
                continue;
            }
            let index = nodes.len();
            let id = member.id();
            execution.charge_work(1).map_err(refusal)?;
            if member.name().len() == LATEST.len() {
                execution
                    .charge_work(LATEST.len() as u64)
                    .map_err(refusal)?;
                if member.name() == LATEST {
                    latest_count += 1;
                    latest = Some(index);
                }
            }
            let fact = by_source
                .get(&ordinal, &execution)
                .map_err(refusal)?
                .copied();
            if fact.is_none() {
                findings
                    .try_push(Finding {
                        manifest: Some(id),
                        reference: None,
                        related: None,
                        kind: FindingKind::Uninspected,
                    })
                    .map_err(refusal)?;
            }
            nodes
                .try_push(Node {
                    member: id,
                    facts: fact,
                    previous: None,
                    timestamp: None,
                    objects: None,
                })
                .map_err(refusal)?;
            by_member.try_insert(ordinal, index).map_err(refusal)?;
        }
        if latest_count != 1 {
            latest = None;
            findings
                .try_push(Finding {
                    manifest: None,
                    reference: None,
                    related: None,
                    kind: FindingKind::Latest,
                })
                .map_err(refusal)?;
        }
        for node in &mut nodes {
            let Some(index) = node.facts else {
                continue;
            };
            let catalogue = facts[index].catalogue();
            let id = node.member;
            if !catalogue.reading().faults().is_empty() {
                findings
                    .try_push(Finding {
                        manifest: Some(id),
                        reference: None,
                        related: None,
                        kind: FindingKind::Syntax,
                    })
                    .map_err(refusal)?;
            }
            if let Some(token) = catalogue
                .signature_member(&execution)
                .map_err(Error::Archive)?
                && census
                    .occurrence(token.id().ordinal(), &execution)
                    .map_err(Error::Archive)?
                    .map(|(_, role)| role)
                    == Some(Role::Timestamp)
            {
                node.timestamp = Some(token.id());
            }
            if node.timestamp.is_none() {
                findings
                    .try_push(Finding {
                        manifest: Some(id),
                        reference: None,
                        related: None,
                        kind: FindingKind::Timestamp,
                    })
                    .map_err(refusal)?;
            }
            let mut objects = execution.vector();
            objects
                .try_reserve_exact(catalogue.objects().len())
                .map_err(refusal)?;
            let mut roots = 0usize;
            for (ordinal, object) in catalogue.reading().objects().iter().enumerate() {
                let target = catalogue
                    .object_member(ordinal, &execution)
                    .map_err(Error::Archive)?
                    .map(|member| member.id());
                objects.try_push(target).map_err(refusal)?;
                if target.is_none() {
                    findings
                        .try_push(Finding {
                            manifest: Some(id),
                            reference: Some(ordinal),
                            related: None,
                            kind: FindingKind::Target,
                        })
                        .map_err(refusal)?;
                }
                match object.rootfile {
                    Boolean::Value(true) => {
                        roots += 1;
                        let predecessor = match target {
                            Some(target) => by_member
                                .get(&target.ordinal(), &execution)
                                .map_err(refusal)?
                                .copied(),
                            None => None,
                        };
                        if predecessor.is_none() {
                            findings
                                .try_push(Finding {
                                    manifest: Some(id),
                                    reference: Some(ordinal),
                                    related: target,
                                    kind: FindingKind::Rootfile,
                                })
                                .map_err(refusal)?;
                        }
                        node.previous = predecessor;
                    }
                    Boolean::Malformed => {
                        findings
                            .try_push(Finding {
                                manifest: Some(id),
                                reference: Some(ordinal),
                                related: target,
                                kind: FindingKind::Rootfile,
                            })
                            .map_err(refusal)?;
                    }
                    Boolean::Absent | Boolean::Value(false) => {}
                }
            }
            if roots > 1 {
                node.previous = None;
                findings
                    .try_push(Finding {
                        manifest: Some(id),
                        reference: None,
                        related: None,
                        kind: FindingKind::Rootfile,
                    })
                    .map_err(refusal)?;
            }
            node.objects = Some(objects.into_owned());
        }
        let mut order = execution.vector();
        let mut visited = execution.map();
        let mut current = latest;
        while let Some(index) = current {
            execution.charge_work(1).map_err(refusal)?;
            if visited.try_insert(index, ()).map_err(refusal)?.is_some() {
                findings
                    .try_push(Finding {
                        manifest: Some(nodes[index].member),
                        reference: None,
                        related: Some(nodes[index].member),
                        kind: FindingKind::Cycle,
                    })
                    .map_err(refusal)?;
                break;
            }
            order.try_push(index).map_err(refusal)?;
            current = nodes[index].previous;
        }
        for (index, node) in nodes.iter().enumerate() {
            if visited.get(&index, &execution).map_err(refusal)?.is_none() {
                findings
                    .try_push(Finding {
                        manifest: Some(node.member),
                        reference: None,
                        related: None,
                        kind: FindingKind::Unreachable,
                    })
                    .map_err(refusal)?;
            }
        }
        execution.charge_work(order.len() as u64).map_err(refusal)?;
        order.reverse();
        let mut required = execution.map();
        let mut covered = execution.map();
        for index in &order {
            let node = &nodes[*index];
            let mut actual = execution.map();
            for target in node.objects().iter().flatten() {
                actual.try_insert(target.ordinal(), ()).map_err(refusal)?;
            }
            for (ordinal, ()) in required.try_iter(&execution).map_err(refusal)? {
                if actual.get(ordinal, &execution).map_err(refusal)?.is_none() {
                    let related = archive
                        .member(*ordinal, &execution)
                        .map_err(Error::Archive)?
                        .expect("required set only contains admitted original members")
                        .id();
                    findings
                        .try_push(Finding {
                            manifest: Some(node.member),
                            reference: None,
                            related: Some(related),
                            kind: FindingKind::Dropped,
                        })
                        .map_err(refusal)?;
                }
            }
            for target in node.objects().iter().flatten() {
                required.try_insert(target.ordinal(), ()).map_err(refusal)?;
            }
            required
                .try_insert(node.member.ordinal(), ())
                .map_err(refusal)?;
            if let Some(token) = node.timestamp {
                required.try_insert(token.ordinal(), ()).map_err(refusal)?;
            }
            covered = actual;
        }
        archive
            .admit(&execution, archive.directory_span())
            .map_err(Error::Archive)?;
        Ok(Self {
            archive,
            facts,
            nodes: nodes.into_owned(),
            order: order.into_owned(),
            findings: findings.into_owned(),
            latest,
            covered: covered.into_owned(),
        })
    }
    /// All original source-derived readings, moved without copying catalogues.
    #[must_use]
    pub fn facts(&self) -> &[Facts<'v, 's, N, D, G, S>] {
        &self.facts
    }
    /// Every original archive-manifest occurrence, including uninspected slots.
    #[must_use]
    pub fn nodes(&self) -> &[Node<S::Document, S::Generation>] {
        &self.nodes
    }
    /// Oldest-to-latest linked node indices. Findings expose any partial graph.
    #[must_use]
    pub fn order(&self) -> &[usize] {
        &self.order
    }
    /// Every original negative geometry/coverage outcome.
    #[must_use]
    pub fn findings(&self) -> &[Finding<S::Document, S::Generation>] {
        &self.findings
    }
    /// Exact fixed latest occurrence, never an earlier-success fallback.
    #[must_use]
    pub fn latest(&self) -> Option<usize> {
        self.latest
    }
    /// Complete source/layout geometry only, NOT mathematics/material/trust.
    #[must_use]
    pub fn geometry_complete(&self) -> bool {
        self.latest.is_some() && self.findings.is_empty()
    }
    /// Whether the latest original manifest declares every requested exact
    /// member. Requested long-term objects are caller input, not inferred from
    /// files introduced after an earlier timestamp. This does not check hashes.
    pub fn declares_all<W: Work>(
        &self,
        requested: &[MemberId<S::Document, S::Generation>],
        work: &W,
    ) -> Result<bool, ArchiveError<S::Error>> {
        let execution = self.archive.session().query(work);
        self.archive
            .admit(&execution, self.archive.directory_span())?;
        for id in requested {
            self.archive.original(*id, &execution)?;
            if self
                .covered
                .get(&id.ordinal(), &execution)
                .map_err(|cause| resource(self.archive.directory_span(), cause))?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(self.latest.is_some())
    }
}
