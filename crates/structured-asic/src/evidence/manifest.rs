//! Manifest object digests reuse the actual ERS all-algorithm object pass.

use super::{
    ArchiveError, AsnDigest, AsyncObjects, Authorities, Checked, Content, Decision, DigestBatch,
    DigestMemo, EvidenceRecord, Execution, Group, Historical, Instant, LeapTable, Membership,
    OwnedVec, PassResult, PlanFailure, ProfileFailure, ProfileInput, RangeSource, ReadFailure,
    Reader, SignatureProvider, StreamError, TokenExtension, VerificationError, Work,
};
use crate::{
    manifest::Slot,
    references::{Catalogue, DigestReading, Unchecked},
};
use core::convert::Infallible;
use structured_xades::{
    binary::{self, OwnedBinaryXml},
    certificate::DigestProvider,
    digest,
    xml::{Access, Xml},
};

/// Actual member input, XML reference or local result-storage refusal.
#[derive(Debug)]
pub enum ManifestInputError<IE, XE, N> {
    /// Actual ZIP acquisition, extent/CRC, source or producing query failed.
    Input(IE),
    /// Original XML method/value, native identity or provider comparison failed.
    Xml(XE),
    /// Current/source metadata storage admission failed before mutation.
    Resource {
        /// Original owning `DataObjectReference` node.
        node: N,
        /// Unchanged refusal.
        cause: structured_asn1::memory::MemoryError,
    },
    /// The closed ERS plan did not supply its required initial-chain digest.
    MissingAlgorithm,
}

type ObjectError<X, S, PE> = ManifestInputError<
    ReadFailure<
        <S as RangeSource>::Error,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
    binary::Error<
        <X as Xml>::Error,
        digest::Error<Infallible, PE>,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    <X as Xml>::Id,
>;

/// Exact ERS/provider/authority/history/profile refusal with XML object causes.
#[derive(Debug)]
pub enum ManifestError<AE, CE, XE> {
    /// Original archive/source or caller association is not this operation's.
    Archive(AE),
    /// Actual common plan, object, callback or verification refusal.
    Check(CE),
    /// Original XML generation, owner or current-query admission refused.
    Xml(XE),
}

struct Objects<'q, 'p, 'c, 'v, 's, X: Xml, S: RangeSource, W: Work, P: AsnDigest<'p>> {
    catalogue: &'c Catalogue<'v, 's, X::Id, X::Document, X::Generation, S>,
    group: &'q Group<'v, 's, S>,
    xml: &'q X,
    answers: &'q mut OwnedVec<DigestReading, W>,
    prepared: &'q [Option<Prepared<'p, P, X>>],
}
type Prepared<'p, P, X> =
    digest::Prepared<'p, P, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

fn unchecked_answers<W: Work>(
    count: usize,
    work: &W,
) -> Result<OwnedVec<DigestReading, W>, structured_asn1::memory::MemoryError> {
    let mut answers = work.vector();
    answers.try_reserve_exact(count)?;
    for _ in 0..count {
        answers.try_push(DigestReading::Unchecked(Unchecked::NotExecuted))?;
    }
    Ok(answers)
}

impl<'p, X, S, P, W0> AsyncObjects<'p, P> for Objects<'_, 'p, '_, '_, '_, X, S, W0, P>
where
    X: OwnedBinaryXml,
    S: RangeSource,
    W0: Work,
    P: AsnDigest<'p> + DigestProvider<'p, X>,
{
    type Error = ObjectError<X, S, P::Error>;
    fn len(&self) -> usize {
        self.group.members.len()
    }
    async fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error> {
        let id = self.group.members[index];
        let member = self.group.archive.original(id, work).map_err(|cause| {
            StreamError::Source(ManifestInputError::Input(ReadFailure::Processing {
                member: id,
                cause,
            }))
        })?;
        let mut source = member
            .source(work)
            .map_err(|cause| StreamError::Source(ManifestInputError::Input(cause)))?;
        let memo = batch
            .run_async(&mut source, work)
            .await
            .map_err(|cause| match cause {
                StreamError::Source(cause) => StreamError::Source(ManifestInputError::Input(cause)),
                StreamError::Callback(cause) => StreamError::Callback(cause),
                StreamError::Processing(cause) => StreamError::Processing(cause),
            })?;
        let object = self.catalogue.reading().objects()[index];
        let answer = match (object.method, object.value) {
            (Slot::One(_), Slot::One(_)) => {
                // InputPlan retains ORIGINAL chain request order. Request0 is
                // the initial tree algorithm even when native states deduplicate.
                let actual = memo
                    .for_request(0, work)
                    .map_err(StreamError::Callback)?
                    .ok_or(StreamError::Source(ManifestInputError::MissingAlgorithm))?;
                let prepared = self.prepared[index]
                    .as_ref()
                    .ok_or(StreamError::Source(ManifestInputError::MissingAlgorithm))?;
                DigestReading::Checked(
                    prepared
                        .check_finished(self.xml, actual.finished(), work)
                        .map_err(|cause| StreamError::Source(ManifestInputError::Xml(cause)))?,
                )
            }
            (Slot::One(_), _) => DigestReading::Unchecked(Unchecked::Value),
            _ => DigestReading::Unchecked(Unchecked::Method),
        };
        work.charge_work(1).map_err(|cause| {
            StreamError::Source(ManifestInputError::Resource {
                node: object.node,
                cause,
            })
        })?;
        self.answers[index] = answer;
        Ok(memo)
    }
}

/// Actual ERS report and every declared object digest from the SAME pass.
/// This alone does not attest XML production, schema/critical-extension
/// acceptance, application trust or container-level preservation continuity.
pub struct ManifestChecked<'a, 'c, 'v, 's, N, D, G, S: RangeSource> {
    catalogue: &'c Catalogue<'v, 's, N, D, G, S>,
    checked: Checked<'a, 'a, 'v, 's, S>,
    answers: OwnedVec<DigestReading>,
}
impl<'a, 'c, 'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource>
    ManifestChecked<'a, 'c, 'v, 's, N, D, G, S>
{
    /// Exact source/manifest instruction catalogue used by this operation.
    #[must_use]
    pub fn catalogue(&self) -> &'c Catalogue<'v, 's, N, D, G, S> {
        self.catalogue
    }
    /// Every original token/history/renewal answer from common ERS verification.
    #[must_use]
    pub fn evidence(&self) -> &Checked<'a, 'a, 'v, 's, S> {
        &self.checked
    }
    /// Every original object result, including not-executed or malformed fields.
    #[must_use]
    pub fn object_digests(&self) -> &[DigestReading] {
        &self.answers
    }
}

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Verifies the exact referenced member group and its declared XML hashes
    /// through one all-chain digest pass per original object. A negative URI
    /// group returns None with its full inspection catalogue left available;
    /// it never becomes a successful subset. An unrelated record is caller
    /// misuse. Original XML source provenance is a separate producing boundary.
    #[expect(
        clippy::too_many_arguments,
        reason = "the existing common ERS provider, authority, UTC and scoped profile/history inputs remain explicit"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "retain the original XML and ERS source-map failures without requiring allocation to report refusal"
    )]
    pub async fn check_manifest_evidence<'a, 'c, X, P, PE, A, RE, HE, FE>(
        &'a self,
        record: &'a EvidenceRecord<'a>,
        parent: &Reader<'a>,
        provider: &'a P,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        catalogue: &'c Catalogue<'v, 's, X::Id, X::Document, X::Generation, S>,
        xml: &X,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
        profile: impl for<'view, 'scope> FnMut(
            usize,
            ProfileInput<'view, 'a, 'a, 'scope>,
        ) -> Result<(), ProfileFailure<FE>>,
    ) -> Result<
        Option<ManifestChecked<'a, 'c, 'v, 's, X::Id, X::Document, X::Generation, S>>,
        ManifestError<
            ArchiveError<S::Error>,
            VerificationError<ObjectError<X, S, PE>, PE, RE, A::Error, HE, FE>,
            structured_xades::xml::AccessError<X::Error, X::Id>,
        >,
    >
    where
        X: OwnedBinaryXml,
        P: for<'scope> SignatureProvider<'scope, Error = PE>
            + for<'scope> DigestProvider<'scope, X>,
        A: Authorities<'a>,
    {
        let work = parent.execution();
        let resource =
            |cause| ManifestError::Archive(crate::error::resource(self.enclosure(), cause));
        let plan = self
            .evidence_plan(record, parent, catalogue.base().archive())
            .map_err(|cause| match cause {
                PlanFailure::Archive(cause) => ManifestError::Archive(cause),
                PlanFailure::Plan(cause) => ManifestError::Check(VerificationError::Plan(cause)),
            })?;
        let access = Access::new(xml, catalogue.reading().snapshot(), &work);
        let root = catalogue.reading().root();
        access.inspect(root, |_| ()).map_err(ManifestError::Xml)?;
        let Some(selected) = catalogue
            .signature_member(&work)
            .map_err(ManifestError::Archive)?
        else {
            return Ok(None);
        };
        if selected.id() != self.member().id() {
            return Err(ManifestError::Archive(ArchiveError::Foreign {
                range: self.enclosure(),
            }));
        }
        let Some(group) = catalogue.group(&work).map_err(|cause| {
            ManifestError::Check(VerificationError::Acquisition(StreamError::Source(
                ManifestInputError::Input(cause),
            )))
        })?
        else {
            return Ok(None);
        };
        let mut answers = unchecked_answers(catalogue.objects().len(), &work).map_err(resource)?;
        // XML syntax, selected-provider policy and declared widths precede ALL
        // ERS state creation. The same prepared readings compare actual outputs
        // later, without resolving, decoding or hashing an object a second time.
        let mut prepared = work.vector();
        prepared
            .try_reserve_exact(catalogue.objects().len())
            .map_err(resource)?;
        for object in catalogue.reading().objects() {
            let value = match (object.method, object.value) {
                (Slot::One(method), Slot::One(value)) => Some(
                    digest::prepare_xml(
                        xml,
                        digest::Reference {
                            snapshot: catalogue.reading().snapshot(),
                            method,
                            value,
                        },
                        provider,
                        &work,
                    )
                    .map_err(|cause| {
                        ManifestError::Check(VerificationError::Acquisition(StreamError::Source(
                            ManifestInputError::Xml(cause),
                        )))
                    })?,
                ),
                _ => None,
            };
            prepared.try_push(value).map_err(resource)?;
        }
        let objects = Objects {
            catalogue,
            group: &group,
            xml,
            answers: &mut answers,
            prepared: &prepared,
        };
        let report = plan
            .verify_async_with_profile(
                provider,
                parent,
                authorities,
                utc,
                reference,
                objects,
                Membership::Group,
                recognizes,
                historical,
                profile,
            )
            .await
            .map_err(ManifestError::Check)?;
        self.member()
            .archive()
            .admit(&work, self.enclosure())
            .map_err(ManifestError::Archive)?;
        access.inspect(root, |_| ()).map_err(ManifestError::Xml)?;
        Ok(Some(ManifestChecked {
            catalogue,
            checked: Checked {
                evidence: self.member().id(),
                objects: group,
                report,
            },
            answers: answers.into_owned(),
        }))
    }
}
