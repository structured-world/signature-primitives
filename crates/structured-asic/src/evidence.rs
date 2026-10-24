//! RFC4998 execution over the actual original `ASiC` member group.

use crate::{
    content::Content,
    error::Error as ArchiveError,
    zip::{Archive, MemberId, ReadFailure},
};
use structured_asn1::{
    Reader,
    memory::{Execution, OwnedVec, Work},
    range::RangeSource,
};
use structured_cms::{
    digest::{DigestBatch, DigestMemo, PassResult},
    evidence::{
        AsyncObjects, EvidenceRecord, Membership,
        verify::{Authorities, Decision, Historical, Report, VerificationError},
    },
    provider::SignatureProvider,
    stream::StreamError,
    timestamp::{ProfileFailure, ProfileInput, TokenExtension},
};
use structured_pkix::{
    algorithm::digest::AsnDigest,
    temporal::{Instant, LeapTable},
};

mod manifest;
pub use manifest::{ManifestChecked, ManifestError, ManifestInputError};

enum PlanFailure<E> {
    Archive(ArchiveError<E>),
    Plan(structured_cms::evidence::verify::PlanError),
}

/// Original object occurrences, preserving multiplicity and supplied order.
/// The vector is moved; no member name, decoded bytes or account is cloned.
pub struct Group<'v, 's, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    members: OwnedVec<MemberId<S::Document, S::Generation>>,
}
impl<'v, 's, S: RangeSource> Group<'v, 's, S> {
    /// Admits every original member and its decoder before provider states can
    /// start. Duplicate occurrences remain duplicates for exact ERS membership.
    pub fn new<W: Work>(
        archive: &'v Archive<'s, S>,
        members: OwnedVec<MemberId<S::Document, S::Generation>>,
        work: &W,
    ) -> crate::zip::Acquisition<Self, S> {
        for id in &members {
            let member = archive
                .original(*id, work)
                .map_err(|cause| ReadFailure::Processing { member: *id, cause })?;
            member.source(work)?;
        }
        Ok(Self { archive, members })
    }
    /// Exact original objects. Traversal during verification is separately paid.
    #[must_use]
    pub fn members(&self) -> &[MemberId<S::Document, S::Generation>] {
        &self.members
    }
}

struct Objects<'g, 'v, 's, S: RangeSource>(&'g Group<'v, 's, S>);
impl<'p, P: AsnDigest<'p>, S: RangeSource> AsyncObjects<'p, P> for Objects<'_, '_, '_, S> {
    type Error = ReadFailure<S::Error, S::Document, S::Generation>;
    fn len(&self) -> usize {
        self.0.members.len()
    }
    async fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error> {
        let id = self.0.members[index];
        let member =
            self.0.archive.original(id, work).map_err(|cause| {
                StreamError::Source(ReadFailure::Processing { member: id, cause })
            })?;
        let mut source = member.source(work).map_err(StreamError::Source)?;
        batch.run_async(&mut source, work).await
    }
}

/// Complete original association and all common ERS timestamp/history answers.
/// This alone does not establish a manifest's declared reference digests.
pub struct Checked<'a, 'd, 'v, 's, S: RangeSource> {
    evidence: MemberId<S::Document, S::Generation>,
    objects: Group<'v, 's, S>,
    report: Report<'a, 'd>,
}
impl<'a, 'd, 'v, 's, S: RangeSource> Checked<'a, 'd, 'v, 's, S> {
    /// Original evidence-record member, independent of verification outcome.
    #[must_use]
    pub fn evidence(&self) -> MemberId<S::Document, S::Generation> {
        self.evidence
    }
    /// Actual group consumed by the common reduced-tree computation.
    #[must_use]
    pub fn objects(&self) -> &Group<'v, 's, S> {
        &self.objects
    }
    /// Every actual original timestamp and all chronology/history findings.
    #[must_use]
    pub fn report(&self) -> &Report<'a, 'd> {
        &self.report
    }
}

/// Archive/source refusal is separate from the common ERS execution failure.
#[derive(Debug)]
pub enum Error<SE, PE, RE, AE, HE, FE, D, G> {
    /// Original view or source/current execution did not admit this association.
    Archive(ArchiveError<SE>),
    /// Common typed preflight, object, provider, selector or profile cause.
    Check(VerificationError<ReadFailure<SE, D, G>, PE, RE, AE, HE, FE>),
}

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    #[expect(
        clippy::result_large_err,
        reason = "retained source errors must survive allocation refusal without allocating an error box"
    )]
    fn evidence_plan<'a>(
        &'a self,
        record: &'a EvidenceRecord<'a>,
        parent: &Reader<'a>,
        archive: &Archive<'_, S>,
    ) -> Result<structured_cms::evidence::verify::InputPlan<'a, 'a>, PlanFailure<S::Error>> {
        let work = parent.execution();
        let original = record.original().element();
        self.require_original(original.as_bytes(), original.span().start, parent, &work)
            .map_err(PlanFailure::Archive)?;
        if !core::ptr::eq(self.member().archive(), archive)
            || original.as_bytes().len() != self.bytes().len()
            || original.span().start != 0
        {
            return Err(PlanFailure::Archive(ArchiveError::Foreign {
                range: self.enclosure(),
            }));
        }
        record.input_plan(parent).map_err(PlanFailure::Plan)
    }
    /// Checks all original record participants, both renewal relations and
    /// chronology with the ONE shared ERS kernel. The original object group is
    /// preflighted before states and streamed once for all chain algorithms.
    #[expect(
        clippy::too_many_arguments,
        reason = "source-bound ERS keeps common provider, selected authorities, UTC and three scoped callbacks explicit"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete original diagnostic maps without allocating on a resource failure"
    )]
    pub async fn check_evidence<'a, P, PE, A, RE, HE, FE>(
        &'a self,
        record: &'a EvidenceRecord<'a>,
        parent: &Reader<'a>,
        provider: &'a P,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        objects: Group<'v, 's, S>,
        membership: Membership,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            ProfileInput<'view, 'a, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<
        Checked<'a, 'a, 'v, 's, S>,
        Error<S::Error, PE, RE, A::Error, HE, FE, S::Document, S::Generation>,
    >
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'a>,
    {
        let work = parent.execution();
        let plan = self
            .evidence_plan(record, parent, objects.archive)
            .map_err(|cause| match cause {
                PlanFailure::Archive(cause) => Error::Archive(cause),
                PlanFailure::Plan(cause) => Error::Check(VerificationError::Plan(cause)),
            })?;
        let report = plan
            .verify_async_with_profile(
                provider,
                parent,
                authorities,
                utc,
                reference,
                Objects(&objects),
                membership,
                recognizes,
                historical,
                profile,
            )
            .await
            .map_err(Error::Check)?;
        self.member()
            .archive()
            .admit(&work, self.enclosure())
            .map_err(Error::Archive)?;
        Ok(Checked {
            evidence: self.member().id(),
            objects,
            report,
        })
    }
}
