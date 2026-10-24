//! Owning signature production and actual original-member resource receipts.

use super::{Error, Source, Types};
use crate::{
    content::Content,
    error::{Error as ArchiveError, resource},
    uri::{self, Part},
    zip::{Archive, Member, MemberId, ReadFailure},
};
use core::future::Future;
use structured_asn1::{
    memory::{MemoryError, OwnedVec, Work},
    range::RangeSource,
};
use structured_xades::{
    attributes::AttributeXml,
    binary::OwnedBinaryXml,
    binding::{Coverage, Status},
    reference::{Completeness, Descriptor, Parent, ReferenceXml, VisitError},
    scalar::{ScalarXml, UriXml},
    xml::{Access, AccessError, Snapshot, Xml},
};

/// Closed receipt for one actual complete original CRC-checked input.
/// This attests acquisition, not that an XML reference consumed these bytes.
/// The trusted XML owner must establish that latter association from its actual
/// verified operation, not by comparing a filename or attaching an arbitrary ID.
pub struct Resource<'v, 's, S: RangeSource> {
    member: Member<'v, 's, S>,
}
impl<S: RangeSource> Resource<'_, '_, S> {
    /// Exact original input occurrence, independently of URI spelling.
    #[must_use]
    pub fn member(&self) -> MemberId<S::Document, S::Generation> {
        self.member.id()
    }
}

/// Complete funded input and its closed original-source receipt.
pub struct Loaded<'v, 's, S: RangeSource> {
    content: Content<'v, 's, S>,
}
impl<'v, 's, S: RangeSource> Loaded<'v, 's, S> {
    /// Transfers the same allocation to the XML owner, without a copy or new
    /// capacity charge. Keep the receipt with the actual parsing/verification
    /// state that consumes it; it is not a replay or signature capability.
    pub fn into_parts(self) -> (OwnedVec<u8>, Resource<'v, 's, S>) {
        let (member, bytes) = self.content.into_parts();
        (bytes, Resource { member })
    }
}

/// Exact resource lookup preserves negative/ambiguous inputs without selection.
pub enum Lookup<'v, 's, S: RangeSource> {
    /// One actual complete original input was acquired.
    Loaded(Loaded<'v, 's, S>),
    /// URI selects the containing XML, not another member.
    SameDocument(Part),
    /// Query/fragment selects less than the complete member.
    Part(Part),
    /// A package root is not a file resource.
    Root,
    /// No exact original member has this name.
    Missing,
    /// Several original members have exactly this name.
    Ambiguous,
    /// Completed lexical/package interpretation failed.
    Negative(uri::Negative),
}

/// The core's original archive resource boundary. It is passed to the owning
/// XML producer, never assembled from separately parsed snapshots. XML Base,
/// transforms and selected policy remain with that XML owner.
pub struct Resources<'v, 's, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    base: MemberId<S::Document, S::Generation>,
}
impl<'v, 's, S: RangeSource> Resources<'v, 's, S> {
    /// Actual original signature file whose input was moved to this producer.
    #[must_use]
    pub fn base(&self) -> MemberId<S::Document, S::Generation> {
        self.base
    }
    /// Resolves an XML-owner selected lexical reference against its ACTUAL
    /// original containing member, then transfers complete EOF/CRC-checked
    /// bytes. The caller's current Work is narrowed by the producing session.
    ///
    /// # Panics
    /// An internal immutable name-catalogue invariant fails if its unique
    /// original candidate cannot be selected from that same catalogue.
    pub async fn load<W: Work>(
        &self,
        base: MemberId<S::Document, S::Generation>,
        uri: &str,
        work: &W,
    ) -> Result<Lookup<'v, 's, S>, ReadFailure<S::Error, S::Document, S::Generation>> {
        let execution = self.archive.session().query(work);
        let fail = |cause| ReadFailure::Processing {
            member: base,
            cause,
        };
        let base = self.archive.original(base, &execution).map_err(fail)?;
        let target = uri::resolve(base.name(), uri, &execution)
            .map_err(|cause| fail(resource(base.central_span(), cause)))?;
        let names = match target {
            uri::Target::Negative(cause) => return Ok(Lookup::Negative(cause)),
            uri::Target::SameDocument(part) => return Ok(Lookup::SameDocument(part)),
            uri::Target::Root(_) => return Ok(Lookup::Root),
            uri::Target::Member {
                name,
                part: Part::Whole,
            } => self.archive.find(name.as_ref(), &execution).map_err(fail)?,
            uri::Target::Member { part, .. } => return Ok(Lookup::Part(part)),
        };
        if names.is_empty() {
            return Ok(Lookup::Missing);
        }
        if names.len() != 1 {
            return Ok(Lookup::Ambiguous);
        }
        let member = names
            .member(0, &execution)
            .map_err(fail)?
            .expect("one exact original candidate");
        let content = member.content(&execution).await?;
        Ok(Lookup::Loaded(Loaded { content }))
    }
}

/// One actual verified direct or signed-Manifest instruction. Missing inputs
/// remain None, independently of catalogue completeness and reference status.
pub struct MemberReference<'a, 'v, 's, N, S: RangeSource> {
    /// Actual original verified instruction and its authenticated parent.
    pub descriptor: Descriptor<'a, N>,
    /// Actual input consumed by that operation, not a URI-to-ID assertion.
    pub resource: Option<&'a Resource<'v, 's, S>>,
}

/// Extends the XML owner's existing verified reference catalogue with the
/// actual resources it consumed. Include every original detached instruction,
/// failed and missing inputs, and authenticated Manifest parents. Complete
/// means the complete catalogue, never just successfully acquired inputs.
pub trait MemberReferences<'v, 's, S: RangeSource>: ReferenceXml {
    /// Visits the existing operation, without reparsing or reverification.
    fn visit_member_references<VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        work: &W,
        visitor: impl for<'a> FnMut(MemberReference<'a, 'v, 's, Self::Id, S>) -> Result<(), VE>,
    ) -> Result<Completeness<Self::Id>, VisitError<Self::Error, VE>>;
}

/// Owning XML verification state. Its immutable view borrows this actual state
/// through the entire asynchronous visitor; no self-reference is required.
pub trait SignatureParsed<'v, 's, S: RangeSource>: Types {
    /// One actual document and verified-operation view, including all negatives.
    type View<'a>: Xml<
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
            Error = Self::Error,
        > + ScalarXml
        + AttributeXml
        + UriXml
        + OwnedBinaryXml
        + MemberReferences<'v, 's, S>
    where
        Self: 'a;
    /// Borrows existing state without parse, verify, clone or source acquisition.
    fn view(&self) -> Self::View<'_>;
    /// Actual whole-document root, never a detached Signature subtree.
    fn root(&self) -> Self::Id;
}

/// Separate capability from structural manifest parsing. A synchronous scoped
/// `VerifiedSession` adapter alone cannot implement this owning async contract.
pub trait SignatureFactory<'v, 's, S: RangeSource>: Types {
    /// Owns the funded input, AST, request, budgets and verification evidence.
    type Parsed<'a, W: Work + 'a>: SignatureParsed<
            'v,
            's,
            S,
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
            Error = Self::Error,
        >
    where
        Self: 'a,
        'v: 'a,
        's: 'a,
        's: 'v,
        S: 's + 'v + 'a;
    /// Produces one owning state from exactly these complete original bytes.
    /// All allocations/callbacks retain current and producing admission, and
    /// all original policy, verification and resource causes remain typed.
    fn parse_signed<'a, W: Work + 'a>(
        &'a self,
        input: OwnedVec<u8>,
        resources: &'a Resources<'v, 's, S>,
        work: &'a W,
    ) -> impl Future<Output = Result<Self::Parsed<'a, W>, Self::Error>> + 'a
    where
        'v: 'a,
        's: 'a,
        's: 'v,
        S: 's + 'v + 'a;
}

/// Fixed-output async continuation, independent of temporary document lifetimes.
pub trait SignatureVisitor<'v, 's, F: Types + ?Sized, S: RangeSource> {
    /// Independently retained output, not a borrow of the temporary view/state.
    type Output;
    /// Original visitor cause, including its resource/processing classification.
    type Error;
    /// Runs with the actual owning verification state alive through await.
    fn visit<X, W: Work>(
        self,
        source: Source<'_, 'v, 's, X, S, W>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>>
    where
        X: Xml<Id = F::Id, Document = F::Document, Generation = F::Generation, Error = F::Error>
            + ScalarXml
            + AttributeXml
            + UriXml
            + OwnedBinaryXml
            + MemberReferences<'v, 's, S>;
}

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Moves the actual complete original member into owning XML verification,
    /// then keeps its view/state/source/current operation alive through await.
    /// No separately parsed snapshot can be attached to this source receipt.
    pub async fn with_signed_xml<
        F: SignatureFactory<'v, 's, S>,
        V: SignatureVisitor<'v, 's, F, S>,
        W: Work,
    >(
        self,
        factory: &F,
        visitor: V,
        work: &W,
    ) -> Result<
        V::Output,
        Error<
            ReadFailure<S::Error, S::Document, S::Generation>,
            F::Error,
            V::Error,
            AccessError<F::Error, F::Id>,
        >,
    > {
        let archive = self.member().archive();
        let execution = archive.session().query(work);
        let (member, input) = self.into_parts();
        let failure = |cause| {
            Error::Input(ReadFailure::Processing {
                member: member.id(),
                cause,
            })
        };
        archive
            .admit(&execution, member.central_span())
            .map_err(failure)?;
        let resources = Resources {
            archive,
            base: member.id(),
        };
        let document = factory
            .parse_signed(input, &resources, &execution)
            .await
            .map_err(Error::Produce)?;
        let root = document.root();
        let xml = document.view();
        let snapshot = xml.snapshot();
        let access = Access::new(&xml, snapshot, &execution);
        access.inspect(root, |_| ()).map_err(Error::Xml)?;
        archive
            .admit(&execution, member.central_span())
            .map_err(failure)?;
        let result = visitor
            .visit(Source {
                member: &member,
                xml: &xml,
                root,
                snapshot,
                execution: &execution,
            })
            .await
            .map_err(Error::Visit)?;
        access.inspect(root, |_| ()).map_err(Error::Xml)?;
        archive
            .admit(&execution, member.central_span())
            .map_err(failure)?;
        Ok(result)
    }
}
impl<'v, 's, S: RangeSource> Member<'v, 's, S> {
    /// Complete EOF/CRC acquisition followed by the same owning signature path.
    pub async fn with_signed_xml<
        F: SignatureFactory<'v, 's, S>,
        V: SignatureVisitor<'v, 's, F, S>,
        W: Work,
    >(
        &self,
        factory: &F,
        visitor: V,
        work: &W,
    ) -> Result<
        V::Output,
        Error<
            ReadFailure<S::Error, S::Document, S::Generation>,
            F::Error,
            V::Error,
            AccessError<F::Error, F::Id>,
        >,
    > {
        self.content(work)
            .await
            .map_err(Error::Input)?
            .with_signed_xml(factory, visitor, work)
            .await
    }
}

/// Every original reference, independently of its digest/coverage outcome.
#[derive(Debug, Clone, Copy)]
pub struct Reference<N, D, G> {
    /// Original reference node, never its selected resource.
    pub node: N,
    /// Original signed instruction parent, retaining Manifest identity.
    pub parent: Parent<N>,
    /// Actual complete original resource, absent for missing/non-member input.
    pub input: Option<MemberId<D, G>>,
    /// Actual completed/failed/unchecked reference digest status.
    pub status: Status,
    /// Actual transform engine's original-element coverage.
    pub coverage: Coverage,
    /// Actual source kind observed by the original reference operation.
    pub object_location: structured_xades::reference::ObjectLocation,
}
/// All original signature occurrences, including unverified/misplaced nodes.
pub struct Signature<N, D, G> {
    /// Original wrapper/nesting location, not an assertion of legal countersignature.
    pub occurrence: crate::xml::Signature<N>,
    /// Actual signature mathematics, independently of trust or `XAdES` level.
    pub status: Status,
    /// Original complete/unchecked/incomplete instruction catalogue.
    pub completeness: Completeness<N>,
    /// Every original reference returned by that catalogue, in original order.
    pub references: OwnedVec<Reference<N, D, G>>,
}
/// Source-produced wrapper, signature and external-member facts.
pub struct Facts<'v, 's, N, D, G, S: RangeSource> {
    member: Member<'v, 's, S>,
    reading: crate::xml::Reading<N, D, G>,
    signatures: OwnedVec<Signature<N, S::Document, S::Generation>>,
}

/// One actual common `XAdES` stage composition, privately associated with this
/// source-produced original signature. Trust and container facts stay separate.
pub struct Assessment<'a, A, N, D, G, SD, SG> {
    member: MemberId<SD, SG>,
    snapshot: Snapshot<D, G>,
    signature: N,
    inner: structured_xades::baseline::Assessment<'a, A, N, D, G>,
}
impl<A, N: Copy, D: Copy, G: Copy, SD: Copy, SG: Copy> Assessment<'_, A, N, D, G, SD, SG> {
    /// Exact actual signature-file occurrence.
    #[must_use]
    pub fn member(&self) -> MemberId<SD, SG> {
        self.member
    }
    /// Exact original selected XML signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Complete original common stage reports, including negative outcomes.
    #[must_use]
    pub fn xades(&self) -> &structured_xades::baseline::Assessment<'_, A, N, D, G> {
        &self.inner
    }
}
/// No new format or trust decision is invented by this source join.
#[derive(Debug)]
pub enum LevelError<E, N, SE> {
    /// Original XML generation/current operation refused.
    Xml(AccessError<E, N>),
    /// Another actual source/signature supplied the stage evidence.
    Foreign,
    /// Original source/current operation refused.
    Archive(ArchiveError<SE>),
    /// Existing common stage composition refused substituted/mismatched reports.
    Xades(structured_xades::baseline::LevelError),
}
/// Common stage composition for the actual XML and member identity domains.
pub type AssessmentResult<'a, A, X, S> = Result<
    Assessment<
        'a,
        A,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
    LevelError<<X as Xml>::Error, <X as Xml>::Id, <S as RangeSource>::Error>,
>;
/// One original census slot, including an absent stage assessment.
pub type LevelAnswer<'r, 'a, A, N, D, G, SD, SG> = Option<&'r Assessment<'a, A, N, D, G, SD, SG>>;
/// Source-produced complete signature census or its original terminal cause.
pub type InspectionResult<'v, 's, X, S> = Result<
    Facts<'v, 's, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, S>,
    InspectError<<X as Xml>::Error, <X as Xml>::Id, <S as RangeSource>::Error>,
>;
/// A stage assessment in one actual member's identity domain.
pub type MemberAssessment<'a, A, N, D, G, S> =
    Assessment<'a, A, N, D, G, <S as RangeSource>::Document, <S as RangeSource>::Generation>;
/// Full original census join, including absent and negative stage answers.
pub type LevelsResult<'r, 'a, A, N, D, G, S> = Result<
    Levels<'r, 'a, A, N, D, G, <S as RangeSource>::Document, <S as RangeSource>::Generation>,
    JoinError<<S as RangeSource>::Error>,
>;

impl<'v, 's, X, S, W> Source<'_, 'v, 's, X, S, W>
where
    X: MemberReferences<'v, 's, S>,
    S: RangeSource,
    W: Work,
{
    /// Reuses the complete B-B/B-T/B-LT/B-LTA composition for this ACTUAL XML
    /// source. Every nested counter/TSA/material obligation remains in those
    /// existing stage reports, not replaced by a container-wide success flag.
    pub fn assess<'a, A>(
        &self,
        evidence: structured_xades::baseline::Evidence<'a, A, X::Id, X::Document, X::Generation>,
    ) -> AssessmentResult<'a, A, X, S> {
        use structured_xades::baseline::Evidence;
        let prepared = match &evidence {
            Evidence::Basic(value) => value.inputs().fields.prepared(),
            Evidence::Timestamped(value) => value.basic().inputs().fields.prepared(),
            Evidence::LongTerm(value)
            | Evidence::Archival {
                long_term: value, ..
            } => value.timed().basic().inputs().fields.prepared(),
        };
        let containers = prepared.bound().containers();
        if containers.snapshot() != self.snapshot {
            return Err(LevelError::Foreign);
        }
        let signature = containers.signature();
        let access = Access::new(self.xml, self.snapshot, self.execution);
        if !access
            .has_name(
                signature,
                structured_xades::xml::Name {
                    namespace: crate::manifest::DS,
                    local: "Signature",
                },
            )
            .map_err(LevelError::Xml)?
        {
            return Err(LevelError::Foreign);
        }
        self.member
            .archive()
            .admit(self.execution, self.member.central_span())
            .map_err(LevelError::Archive)?;
        let inner = structured_xades::baseline::assess(evidence).map_err(LevelError::Xades)?;
        Ok(Assessment {
            member: self.member.id(),
            snapshot: self.snapshot,
            signature,
            inner,
        })
    }
}

/// Every original root's requested-level projection, including unchecked roots.
pub struct Levels<'r, 'a, A, N, D, G, SD, SG> {
    answers: OwnedVec<LevelAnswer<'r, 'a, A, N, D, G, SD, SG>>,
    all_roots: bool,
}
impl<'r, 'a, A, N, D, G, SD, SG> Levels<'r, 'a, A, N, D, G, SD, SG> {
    /// Same ordinal as the complete original signature census, including nested
    /// and malformed occurrences. None is unexecuted, never a positive level.
    #[must_use]
    pub fn answers(&self) -> &[LevelAnswer<'r, 'a, A, N, D, G, SD, SG>] {
        &self.answers
    }
    /// All original direct roots have a completed positive requested-level
    /// report. This is not wrapper conformance, historical trust or acceptance.
    #[must_use]
    pub fn all_roots_requested_level_met(&self) -> bool {
        self.all_roots
    }
}
/// Invalid caller joins are processing errors rather than readable missing data.
#[derive(Debug)]
pub enum JoinError<E> {
    /// Original source/current operation refused.
    Archive(ArchiveError<E>),
    /// A receipt belongs to another source, generation or original signature.
    Foreign,
    /// Several supplied receipts select the same original signature.
    Duplicate,
}
impl<N: Copy + Eq + structured_asn1::memory::HashWork, D: Copy + Eq, G: Copy + Eq, S: RangeSource>
    Facts<'_, '_, N, D, G, S>
{
    /// Joins all actual supplied stage receipts with the FULL original census.
    /// A missing or failed root cannot disappear through success filtering.
    pub fn levels<'r, 'a, A, W: Work>(
        &self,
        supplied: &[&'r MemberAssessment<'a, A, N, D, G, S>],
        work: &W,
    ) -> LevelsResult<'r, 'a, A, N, D, G, S> {
        let archive = self.member.archive();
        let execution = archive.session().query(work);
        archive
            .admit(&execution, self.member.central_span())
            .map_err(JoinError::Archive)?;
        let refusal = |cause| JoinError::Archive(resource(self.member.central_span(), cause));
        let mut originals = execution.map();
        for (index, signature) in self.signatures.iter().enumerate() {
            originals
                .try_insert(signature.occurrence.node, index)
                .map_err(refusal)?;
        }
        let mut selected = execution.map();
        for (index, value) in supplied.iter().enumerate() {
            execution.charge_work(1).map_err(refusal)?;
            if value.member != self.member.id()
                || value.snapshot != self.reading.snapshot()
                || originals
                    .get(&value.signature, &execution)
                    .map_err(refusal)?
                    .is_none()
            {
                return Err(JoinError::Foreign);
            }
            if selected
                .try_insert(value.signature, index)
                .map_err(refusal)?
                .is_some()
            {
                return Err(JoinError::Duplicate);
            }
        }
        let mut answers = execution.vector();
        answers
            .try_reserve_exact(self.signatures.len())
            .map_err(refusal)?;
        let mut roots = 0usize;
        let mut all_roots = true;
        for signature in &self.signatures {
            let answer = selected
                .get(&signature.occurrence.node, &execution)
                .map_err(refusal)?
                .map(|index| supplied[*index]);
            if signature.occurrence.direct {
                roots += 1;
                match answer {
                    Some(value) if value.inner.all_requirements_met() => {}
                    _ => all_roots = false,
                }
            }
            answers.try_push(answer).map_err(refusal)?;
        }
        archive
            .admit(&execution, self.member.central_span())
            .map_err(JoinError::Archive)?;
        Ok(Levels {
            answers: answers.into_owned(),
            all_roots: roots != 0 && all_roots,
        })
    }
}
impl<'v, 's, N: Copy, D: Copy, G: Copy, S: RangeSource> Facts<'v, 's, N, D, G, S> {
    /// Actual signature member, established by the closed producing operation.
    #[must_use]
    pub fn member(&self) -> &Member<'v, 's, S> {
        &self.member
    }
    /// Full wrapper and descendant census, preserving original faults.
    #[must_use]
    pub fn reading(&self) -> &crate::xml::Reading<N, D, G> {
        &self.reading
    }
    /// All original mathematical/reference outcomes, without successful subsets.
    #[must_use]
    pub fn signatures(&self) -> &[Signature<N, S::Document, S::Generation>] {
        &self.signatures
    }
}
/// Original owner/processing/refusal causes do not become format negatives.
#[derive(Debug)]
pub enum InspectError<E, N, SE> {
    /// Actual original wrapper inspection or source/current storage refused.
    Wrapper(crate::xml::Error<E, N>),
    /// Actual verified operation or generation refused.
    Xml(AccessError<E, N>),
    /// Actual reference catalogue refused, preserving the visitor cause.
    References(VisitError<E, ReferenceError<SE>>),
    /// Original source/current operation refused.
    Archive(ArchiveError<SE>),
}
/// Reference association failures are terminal, never missing inputs.
#[derive(Debug)]
pub enum ReferenceError<E> {
    /// Original source/query refused.
    Archive(ArchiveError<E>),
    /// Resource belongs to another actual producing archive/session.
    Foreign,
    /// Current/source descriptor storage refused before retention.
    Resource(MemoryError),
}
impl<'v, 's, X, S, W> Source<'_, 'v, 's, X, S, W>
where
    X: AttributeXml + MemberReferences<'v, 's, S>,
    S: RangeSource,
    W: Work,
{
    /// Retains every original signature and its actual complete reference
    /// catalogue while the producing verification state is still alive.
    pub fn signatures(&self) -> InspectionResult<'v, 's, X, S> {
        let access = Access::new(self.xml, self.snapshot, self.execution);
        let reading = crate::xml::inspect(self.xml, self.root, self.execution)
            .map_err(InspectError::Wrapper)?;
        let mut signatures = self.execution.vector();
        for occurrence in reading.signatures() {
            access
                .inspect(occurrence.node, |_| ())
                .map_err(InspectError::Xml)?;
            let status = self
                .xml
                .signature_status(self.snapshot, occurrence.node, self.execution)
                .map_err(|cause| InspectError::Xml(AccessError::Xml(cause)))?;
            let mut references = self.execution.vector();
            let completeness = self
                .xml
                .visit_member_references(self.snapshot, occurrence.node, self.execution, |item| {
                    let input = if let Some(resource) = item.resource {
                        self.execution
                            .charge_work(1)
                            .map_err(ReferenceError::Resource)?;
                        if !core::ptr::eq(resource.member.archive(), self.member.archive()) {
                            return Err(ReferenceError::Foreign);
                        }
                        self.member
                            .archive()
                            .original(resource.member(), self.execution)
                            .map_err(ReferenceError::Archive)?;
                        Some(resource.member())
                    } else {
                        None
                    };
                    references
                        .try_push(Reference {
                            node: item.descriptor.reference.node,
                            parent: item.descriptor.parent,
                            input,
                            status: item.descriptor.reference.status,
                            coverage: item.descriptor.reference.coverage,
                            object_location: item.descriptor.object_location,
                        })
                        .map_err(ReferenceError::Resource)
                })
                .map_err(InspectError::References)?;
            access
                .inspect(occurrence.node, |_| ())
                .map_err(InspectError::Xml)?;
            signatures
                .try_push(Signature {
                    occurrence: *occurrence,
                    status,
                    completeness,
                    references: references.into_owned(),
                })
                .map_err(|cause| {
                    InspectError::Wrapper(crate::xml::Error::Resource {
                        node: occurrence.node,
                        cause,
                    })
                })?;
        }
        let member = self
            .member
            .archive()
            .original(self.member.id(), self.execution)
            .map_err(InspectError::Archive)?;
        access
            .inspect(self.root, |_| ())
            .map_err(InspectError::Xml)?;
        Ok(Facts {
            member,
            reading,
            signatures: signatures.into_owned(),
        })
    }
}
