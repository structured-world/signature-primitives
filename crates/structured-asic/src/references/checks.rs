//! Complete original reference results with one native fan-out per member.

use super::{
    Access, AccessError, Agreement, ArchiveError, Catalogue, CheckError, DigestProvider,
    DigestReading, OwnedBinaryXml, RangeSource, Unchecked, VisitError, Work, binary, digest,
    resource,
};
use structured_asn1::memory::OwnedVec;

/// Every original object declaration, bound to this exact instruction catalogue.
/// This checks hashes, not ZIP-to-XML production or manifest authentication.
pub struct Checks<'c, 'v, 's, N, D, G, S: RangeSource> {
    catalogue: &'c Catalogue<'v, 's, N, D, G, S>,
    answers: OwnedVec<DigestReading>,
}
impl<'c, 'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource>
    Checks<'c, 'v, 's, N, D, G, S>
{
    /// Exact original instruction set, including negative URI/schema outcomes.
    #[must_use]
    pub fn catalogue(&self) -> &'c Catalogue<'v, 's, N, D, G, S> {
        self.catalogue
    }
    /// One result for EVERY original `DataObjectReference`, in original order.
    #[must_use]
    pub fn answers(&self) -> &[DigestReading] {
        &self.answers
    }
    pub(crate) fn into_answers(self) -> OwnedVec<DigestReading> {
        self.answers
    }
    /// Paid completed digest predicate only, never container/profile/trust.
    pub fn all_match<W: Work>(&self, work: &W) -> Result<bool, ArchiveError<S::Error>> {
        let execution = self.catalogue.base().session().query(work);
        self.catalogue
            .base()
            .archive()
            .admit(&execution, self.catalogue.base().central_span())?;
        if self.answers.is_empty() {
            return Ok(false);
        }
        for answer in &self.answers {
            execution
                .charge_work(1)
                .map_err(|cause| resource(self.catalogue.base().central_span(), cause))?;
            if *answer != DigestReading::Checked(Agreement::Matches) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct Group<D, G, W: Work> {
    member: crate::zip::MemberId<D, G>,
    references: OwnedVec<usize, W>,
}

impl<'v, 's, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, S: RangeSource>
    Catalogue<'v, 's, N, D, G, S>
{
    /// Checks all declarations without repeating URI lookup. Every method,
    /// declared width, source/decoder and policy is preflighted before ANY hash
    /// state. Aliases/repeated references to one original member share a single
    /// source pass and the existing semantic native digest fan-out.
    ///
    /// # Panics
    /// An internal grouping invariant fails if the same prepared original
    /// reference is consumed by more than one source group.
    #[expect(
        clippy::too_many_lines,
        reason = "all original methods and sources must finish preflight before any digest initialization; the two execution phases share the same funded plan"
    )]
    pub async fn check_objects<'p, X, P, W: Work>(
        &self,
        xml: &X,
        provider: &'p P,
        work: &W,
    ) -> Result<
        Checks<'_, 'v, 's, N, D, G, S>,
        CheckError<X::Error, P::Error, N, D, G, S::Error, S::Document, S::Generation>,
    >
    where
        X: OwnedBinaryXml<Id = N, Document = D, Generation = G>,
        P: DigestProvider<'p, X>,
    {
        let execution = self.base().session().query(work);
        let at = self.base().central_span();
        let archive_error =
            |cause| CheckError::Reference(AccessError::Xml(VisitError::Visitor(cause)));
        let refusal = |cause| archive_error(resource(at, cause));
        self.base()
            .archive()
            .admit(&execution, at)
            .map_err(archive_error)?;
        let access = Access::new(xml, self.reading().snapshot(), &execution);
        let fence = || {
            access
                .inspect(self.reading().root(), |_| ())
                .map_err(|cause| {
                    CheckError::Reference(match cause {
                        AccessError::Xml(cause) => AccessError::Xml(VisitError::Processing(cause)),
                        AccessError::Changed { node } => AccessError::Changed { node },
                        AccessError::Resource { node, cause } => {
                            AccessError::Resource { node, cause }
                        }
                    })
                })
        };
        fence()?;
        let mut answers = execution.vector();
        let mut prepared = execution.vector();
        answers
            .try_reserve_exact(self.objects().len())
            .map_err(refusal)?;
        prepared
            .try_reserve_exact(self.objects().len())
            .map_err(refusal)?;
        let mut groups = execution.vector();
        let mut by_member = execution.map();
        for (index, object) in self.reading().objects().iter().enumerate() {
            let instruction = match (object.method, object.value) {
                (crate::manifest::Slot::One(method), crate::manifest::Slot::One(value)) => Some(
                    digest::prepare_xml(
                        xml,
                        digest::Reference {
                            snapshot: self.reading().snapshot(),
                            method,
                            value,
                        },
                        provider,
                        &execution,
                    )
                    .map_err(|cause| {
                        CheckError::Digest(
                            cause.map_callback(|cause| cause.map_source(|never| match never {})),
                        )
                    })?,
                ),
                _ => None,
            };
            let mut answer = match (object.method, object.value) {
                (crate::manifest::Slot::One(_), crate::manifest::Slot::One(_)) => {
                    DigestReading::Unchecked(Unchecked::Input)
                }
                (crate::manifest::Slot::One(_), _) => DigestReading::Unchecked(Unchecked::Value),
                _ => DigestReading::Unchecked(Unchecked::Method),
            };
            if instruction.is_some()
                && let Some(member) = self
                    .object_member(index, &execution)
                    .map_err(archive_error)?
            {
                member.source(&execution).map_err(CheckError::Input)?;
                let group = if let Some(index) = by_member
                    .get(&member.id().ordinal(), &execution)
                    .map_err(refusal)?
                {
                    *index
                } else {
                    let index = groups.len();
                    groups
                        .try_push(Group {
                            member: member.id(),
                            references: execution.vector(),
                        })
                        .map_err(refusal)?;
                    by_member
                        .try_insert(member.id().ordinal(), index)
                        .map_err(refusal)?;
                    index
                };
                groups[group].references.try_push(index).map_err(refusal)?;
                answer = DigestReading::Unchecked(Unchecked::NotExecuted);
            }
            prepared.try_push(instruction).map_err(refusal)?;
            answers.try_push(answer).map_err(refusal)?;
        }
        fence()?;
        self.base()
            .archive()
            .admit(&execution, at)
            .map_err(archive_error)?;
        for group in groups {
            let mut instructions = execution.vector();
            instructions
                .try_reserve_exact(group.references.len())
                .map_err(refusal)?;
            for index in &group.references {
                execution.charge_work(1).map_err(refusal)?;
                instructions
                    .try_push(
                        prepared[*index]
                            .take()
                            .expect("each original reference belongs to exactly one source group"),
                    )
                    .map_err(refusal)?;
            }
            let member = self
                .base()
                .archive()
                .original(group.member, &execution)
                .map_err(archive_error)?;
            let mut source = member.source(&execution).map_err(CheckError::Input)?;
            let location = binary::Location {
                snapshot: self.reading().snapshot(),
                node: self.reading().objects()[group.references[0]].node,
            };
            let batch = digest::Batch::prepare(provider, instructions.into_owned(), &execution)
                .map_err(|cause| {
                    CheckError::Digest(binary::Error::Callback {
                        location,
                        cause: cause.map_source(|never| match never {}),
                    })
                })?;
            let result = batch
                .run(xml, &mut source, &execution)
                .await
                .map_err(CheckError::Digest)?;
            for (index, answer) in group.references.iter().zip(&*result) {
                execution.charge_work(1).map_err(refusal)?;
                answers[*index] = DigestReading::Checked(*answer);
            }
        }
        self.base()
            .archive()
            .admit(&execution, at)
            .map_err(archive_error)?;
        fence()?;
        Ok(Checks {
            catalogue: self,
            answers: answers.into_owned(),
        })
    }
}
