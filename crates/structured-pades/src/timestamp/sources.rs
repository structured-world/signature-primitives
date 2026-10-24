//! Complete original DTS sources and once-read carried validation material.

use super::{Node, Requirements};
use crate::{
    container::{Container, ErrorOf},
    document::Document,
    error::{Error, ErrorKind},
    model::admit,
    range::RangeSource,
    source::Location,
};
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_cms::{signed::revocation, timestamp::Token};

/// Completed original syntax/unavailable-input finding. Processing refusals
/// are returned by the operation rather than retained as malformed material.
#[derive(Debug)]
pub enum Fault {
    /// Original PDF dictionary or value failure.
    Pdf(Error),
    /// Original carried ASN.1 coordinates within this physical enclosure.
    Encoding {
        /// Honest PDF enclosure of the decoded Contents.
        enclosure: Location,
        /// Original located parser cause.
        cause: structured_asn1::Error,
    },
    /// Original carried CMS coordinates within this physical enclosure.
    Cms {
        /// Honest PDF enclosure of the decoded Contents.
        enclosure: Location,
        /// Original located CMS cause.
        cause: structured_cms::Error,
    },
}

/// One actual source occurrence, including unsuccessful/unreadable members.
pub enum Slot<'a, 's, D, G> {
    /// Original decoded Contents and its immutable source association.
    Value(Container<'a, 's, D, G>),
    /// Original source-shaped occurrence could not provide such a value.
    Unreadable(Fault),
}
/// Complete source set derived from the same original timestamp obligations.
pub struct Sources<'r, 'a, 's, D, G> {
    pub(super) required: &'r Requirements<'a, 's, D, G>,
    pub(super) slots: OwnedVec<Slot<'a, 's, D, G>, Memory>,
}

/// One original carried revocation and its complete first-read result.
pub struct Revocation<'d> {
    pub(crate) choice: usize,
    element: structured_asn1::Element<'d>,
    pub(crate) value: Result<revocation::Reading<'d>, revocation::Error>,
}
pub(crate) enum RevocationError {
    Pdf(Error),
    Cms(structured_cms::Error),
    Pkix(structured_pkix::Error),
}
pub(crate) fn read_revocations<'d>(
    token: &Token<'d>,
    parent: &structured_asn1::Reader<'d>,
    work: &impl Work,
    location: Location,
) -> Result<OwnedVec<Revocation<'d>>, RevocationError> {
    let mut values = work.vector();
    for (choice, element) in token.message().revocations().iter().enumerate() {
        admit(work, location, 1).map_err(RevocationError::Pdf)?;
        let reader = token
            .message()
            .revocation_reader_in(parent, choice)
            .map_err(RevocationError::Cms)?
            .expect("bounded original choice");
        let value = revocation::read(&reader, element);
        if let Err(cause) = &value
            && cause.is_terminal()
        {
            return Err(match value {
                Err(revocation::Error::Cms(cause)) => RevocationError::Cms(cause),
                Err(revocation::Error::Pkix(cause)) => RevocationError::Pkix(cause),
                Ok(_) => unreachable!("failed original reading"),
            });
        }
        values
            .try_push(Revocation {
                choice,
                element: *element,
                value,
            })
            .map_err(|cause| {
                RevocationError::Pdf(Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })
            })?;
    }
    Ok(values.into_owned())
}
impl<'d> Revocation<'d> {
    /// Original choice ordinal in this timestamp `SignedData`.
    #[must_use]
    pub fn choice(&self) -> usize {
        self.choice
    }
    /// Untouched whole original choice in its carried CMS coordinate domain.
    #[must_use]
    pub fn element(&self) -> structured_asn1::Element<'d> {
        self.element
    }
    /// Actual first-read model or the original known-format refusal.
    pub fn reading(&self) -> Result<&revocation::Reading<'d>, &revocation::Error> {
        self.value.as_ref()
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "the funded original-order catalogue stores parsed tokens in place without a separate allocation for every successful occurrence"
)]
pub(crate) enum Model<'d> {
    Known {
        token: Token<'d>,
        revocations: OwnedVec<Revocation<'d>, Memory>,
    },
    Unreadable(Fault),
    Source,
}
/// Original token models borrow retained Contents; their material is parsed
/// once, independently of timestamp arithmetic, imprint, authority or trust.
pub struct Models<'v, 'r, 'a, 's, D, G> {
    pub(crate) sources: &'v Sources<'r, 'a, 's, D, G>,
    pub(crate) values: OwnedVec<Model<'v>, Memory>,
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Reads ALL original PDF DTS occurrences without success-based filtering.
    /// Unreadable syntax remains an entry; source/allocator/work refusal aborts
    /// and releases the entire partial result.
    ///
    /// # Panics
    /// Panics if an internally unreadable source slot loses its retained failure.
    #[expect(
        clippy::result_large_err,
        reason = "original unreadable/source failures retain their encoded PDF enclosure while resource refusal cannot allocate an error box"
    )]
    pub async fn timestamp_sources<'r, 'a, W: Work>(
        &self,
        required: &'r Requirements<'a, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Sources<'r, 'a, 's, S::Document, S::Generation>, ErrorOf<S::Error>> {
        let root = required.root;
        let location = root.location();
        let work = self.session.query(operation);
        self.check(&work, location)
            .map_err(|cause| ErrorOf::Pdf(cause.into()))?;
        if !core::ptr::eq(root.owner().value.session, self.session)
            || root.owner().value.stamp != self.stamp
        {
            return Err(ErrorOf::Pdf(
                Error {
                    kind: ErrorKind::Foreign,
                    location,
                }
                .into(),
            ));
        }
        let mut slots = work.vector();
        for original in required.document_timestamps() {
            admit(&work, original.location(), 1).map_err(|cause| ErrorOf::Pdf(cause.into()))?;
            let value = if let Some(signature) = original.signature() {
                match self.container(signature, &work).await {
                    Ok(value) => Slot::Value(value),
                    Err(ErrorOf::Pdf(crate::error::ReadFailure::Format(cause)))
                        if matches!(
                            cause.kind,
                            ErrorKind::Syntax(_)
                                | ErrorKind::Ambiguous(_)
                                | ErrorKind::Unsupported(_)
                        ) =>
                    {
                        Slot::Unreadable(Fault::Pdf(cause))
                    }
                    Err(ErrorOf::Encoding { enclosure, cause }) if !cause.is_resource() => {
                        Slot::Unreadable(Fault::Encoding { enclosure, cause })
                    }
                    Err(ErrorOf::Cms { enclosure, cause }) if !cause.is_terminal() => {
                        Slot::Unreadable(Fault::Cms { enclosure, cause })
                    }
                    Err(cause) => return Err(cause),
                }
            } else {
                Slot::Unreadable(Fault::Pdf(
                    original
                        .failure()
                        .expect("unreadable original source")
                        .cause,
                ))
            };
            slots.try_push(value).map_err(|cause| {
                ErrorOf::Pdf(
                    Error {
                        kind: ErrorKind::Resource(cause),
                        location: original.location(),
                    }
                    .into(),
                )
            })?;
        }
        self.check(&work, location)
            .map_err(|cause| ErrorOf::Pdf(cause.into()))?;
        Ok(Sources {
            required,
            slots: slots.into_owned(),
        })
    }
}

impl<'r, 'a, 's, D: Copy + Eq, G: Copy + Eq> Sources<'r, 'a, 's, D, G> {
    /// Count includes every original unreadable occurrence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }
    /// Whether the complete source census contained no PDF document timestamps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    /// Actual original source under current/original metadata admission.
    pub fn get(
        &self,
        ordinal: usize,
        operation: &impl Work,
    ) -> crate::Result<Option<&Slot<'a, 's, D, G>>> {
        let work = self.required.root.owner().value.session.query(operation);
        admit(&work, self.required.root.location(), 1)?;
        Ok(self.slots.get(ordinal))
    }
    /// Reads each envelope and each carried revocation exactly once, retaining
    /// known malformed/unknown choices without a private format dispatcher.
    #[expect(
        clippy::result_large_err,
        reason = "envelope and revocation parsing preserves original diagnostic storage and PDF coordinates without allocation after failure"
    )]
    pub fn parse<'v>(
        &'v self,
        operation: &'v impl Work,
    ) -> Result<Models<'v, 'r, 'a, 's, D, G>, ErrorOf<core::convert::Infallible>> {
        let work = self.required.root.owner().value.session.query(operation);
        let location = self.required.root.location();
        let mut values = work.vector();
        for slot in &self.slots {
            admit(&work, location, 1).map_err(|cause| ErrorOf::Pdf(cause.into()))?;
            let value = match slot {
                Slot::Unreadable(_) => Model::Source,
                Slot::Value(container) => match container.read_timestamp(operation) {
                    Ok((token, parent)) => {
                        let enclosure = container.signature().contents();
                        let revocations = read_revocations(&token, &parent, &work, enclosure)
                            .map_err(|cause| match cause {
                                RevocationError::Pdf(cause) => ErrorOf::Pdf(cause.into()),
                                RevocationError::Cms(cause) => ErrorOf::Cms { enclosure, cause },
                                RevocationError::Pkix(cause) => ErrorOf::Pkix { enclosure, cause },
                            })?;
                        Model::Known { token, revocations }
                    }
                    Err(ErrorOf::Encoding { enclosure, cause }) if !cause.is_resource() => {
                        Model::Unreadable(Fault::Encoding { enclosure, cause })
                    }
                    Err(ErrorOf::Cms { enclosure, cause }) if !cause.is_terminal() => {
                        Model::Unreadable(Fault::Cms { enclosure, cause })
                    }
                    Err(cause) => return Err(cause),
                },
            };
            values.try_push(value).map_err(|cause| {
                ErrorOf::Pdf(
                    Error {
                        kind: ErrorKind::Resource(cause),
                        location,
                    }
                    .into(),
                )
            })?;
        }
        Ok(Models {
            sources: self,
            values: values.into_owned(),
        })
    }
}

impl<'d, D: Copy + Eq, G: Copy + Eq> Models<'d, '_, '_, '_, D, G> {
    /// Reopens the already parsed envelope's original source context under
    /// this operation. It performs no token or certificate reparse.
    #[expect(
        clippy::result_large_err,
        reason = "reopened scoped readers propagate the same typed PDF, ASN.1 and CMS causes as the retained original source"
    )]
    pub fn reader<'q, W: Work + 'q>(
        &'q self,
        ordinal: usize,
        operation: &W,
    ) -> Result<Option<structured_asn1::Reader<'q>>, ErrorOf<core::convert::Infallible>> {
        let root = self.sources.required.root;
        let work = root.owner().value.session.query(operation);
        admit(&work, root.location(), 1).map_err(|cause| ErrorOf::Pdf(cause.into()))?;
        if !matches!(self.values.get(ordinal), Some(Model::Known { .. })) {
            return Ok(None);
        }
        let Slot::Value(container) = &self.sources.slots[ordinal] else {
            unreachable!("a parsed token has an original Contents owner")
        };
        root.owner()
            .value
            .session
            .carried(container.der(), operation)
            .map(Some)
            .map_err(|cause| ErrorOf::Encoding {
                enclosure: container.signature().contents(),
                cause,
            })
    }
    /// Visits every carried choice with current/original admission before
    /// access. The first refusal is returned once and permanently fuses it.
    pub fn revocations<'q>(
        &'q self,
        ordinal: usize,
        operation: &'q impl Work,
    ) -> crate::Result<Option<impl Iterator<Item = crate::Result<&'q Revocation<'d>>> + 'q>> {
        let work = self
            .sources
            .required
            .root
            .owner()
            .value
            .session
            .query(operation);
        let location = self.sources.required.root.location();
        admit(&work, location, 1)?;
        let Some(Model::Known { revocations, .. }) = self.values.get(ordinal) else {
            return Ok(None);
        };
        let mut next = if revocations.is_empty() {
            None
        } else {
            Some(0)
        };
        Ok(Some(core::iter::from_fn(move || {
            let ordinal = next.take()?;
            if let Err(cause) = admit(&work, location, 1) {
                return Some(Err(cause));
            }
            let value = &revocations[ordinal];
            if ordinal + 1 < revocations.len() {
                next = Some(ordinal + 1);
            }
            Some(Ok(value))
        })))
    }
    /// Original parsed token only; absence retains an explicit failed source.
    pub fn token(
        &self,
        ordinal: usize,
        operation: &impl Work,
    ) -> crate::Result<Option<&Token<'_>>> {
        let work = self
            .sources
            .required
            .root
            .owner()
            .value
            .session
            .query(operation);
        admit(&work, self.sources.required.root.location(), 1)?;
        Ok(match self.values.get(ordinal) {
            Some(Model::Known { token, .. }) => Some(token),
            _ => None,
        })
    }
    /// Original source/parser failure for this exact occurrence, when present.
    pub fn failure(&self, ordinal: usize, operation: &impl Work) -> crate::Result<Option<&Fault>> {
        let work = self
            .sources
            .required
            .root
            .owner()
            .value
            .session
            .query(operation);
        admit(&work, self.sources.required.root.location(), 1)?;
        Ok(match self.values.get(ordinal) {
            Some(Model::Unreadable(cause)) => Some(cause),
            Some(Model::Source) => match &self.sources.slots[ordinal] {
                Slot::Unreadable(cause) => Some(cause),
                Slot::Value(_) => unreachable!("unreadable source slot"),
            },
            Some(Model::Known { .. }) | None => None,
        })
    }
    pub(crate) fn root(&self) -> Node {
        Node::of(self.sources.required.root.location())
    }
    /// Selected historical revision, or the full current source window.
    #[must_use]
    pub fn revision(&self) -> Option<usize> {
        self.sources.required.revision()
    }
    pub(crate) fn vri_timestamps(&self) -> &[super::VriTimestamp] {
        self.sources.required.vri_timestamps()
    }
    pub(crate) fn total_pdf(&self) -> usize {
        self.sources.required.total_pdf()
    }
    pub(crate) fn snapshot(&self) -> structured_ltv::source::Snapshot<D, G> {
        self.sources.required.root.owner().value.stamp.snapshot
    }
    /// Actual original PDF dictionary location at this source ordinal.
    #[must_use]
    pub fn location(&self, ordinal: usize) -> Option<Location> {
        self.sources
            .required
            .document_timestamps()
            .get(ordinal)
            .map(super::DocumentTimestamp::location)
    }
    pub(crate) fn contents(&self, ordinal: usize) -> Option<Location> {
        match &self.sources.slots[ordinal] {
            Slot::Value(value) => Some(value.signature().contents()),
            Slot::Unreadable(_) => None,
        }
    }
    /// Same complete original root/counter/PDF obligations used for this pool.
    #[must_use]
    pub fn requirements(
        &self,
    ) -> &structured_ltv::timestamp::TimestampRequirements<Node, D, G, super::Pades> {
        self.sources.required.all()
    }
}
