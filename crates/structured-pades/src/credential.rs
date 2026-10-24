//! Original protected credential authentication in the PDF source domain.

use crate::{
    Session,
    basic::Basic,
    binding::Mapping,
    error::{Error as PdfError, ErrorKind},
    model::admit,
    query::Query,
    range::RangeSource,
    timestamp::Node,
};
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_cades::credential as cms;
use structured_ltv::{
    pki::{self, CredentialGroup, CredentialReceipts},
    source::{Query as _, Snapshot},
};

/// Every original root/counter credential's independent authentication result.
pub struct Report<'m, 'd, 'p, 's, D, G, E> {
    common: cms::Report<'m, 'd, 'p, E>,
    mapping: Mapping<'m, 'd, D, G>,
    session: &'s Session,
}
/// One original complete group projected without cloning retained evidence.
pub struct Group<'a, 'm, 'd, 'p, D, G, E> {
    pub(crate) common: &'a cms::Group<'m, 'd, 'p, E>,
    mapping: Mapping<'m, 'd, D, G>,
}
impl<'d, 'p, D: Copy, G: Copy, E> CredentialGroup<'p, 'd> for Group<'_, '_, 'd, 'p, D, G, E> {
    type Id = Node;
    fn signature(&self) -> Node {
        self.mapping.node(self.common.signature())
    }
    fn len(&self) -> usize {
        self.common.len()
    }
    fn credential(&self, ordinal: usize) -> pki::Credential<'p, 'd, Node> {
        let actual = self.common.credential(ordinal);
        pki::Credential {
            signature: self.mapping.node(actual.signature),
            node: self.mapping.node(actual.node),
            authorities: actual.authorities,
        }
    }
}
/// Complete authenticated original census with stable source-domain views.
pub struct Complete<'a, 'm, 'd, 'p, D, G, E> {
    common: cms::Complete<'a, 'm, 'd, 'p, E>,
    pub(crate) mapping: Mapping<'m, 'd, D, G>,
    pub(crate) root: Option<Group<'a, 'm, 'd, 'p, D, G, E>>,
    pub(crate) counters: OwnedVec<Group<'a, 'm, 'd, 'p, D, G, E>, Memory>,
}
impl<'a, 'm, 'd, 'p, D: Copy + Eq, G: Copy + Eq, E> CredentialReceipts<'p, 'd>
    for Complete<'a, 'm, 'd, 'p, D, G, E>
{
    type Id = Node;
    type Document = D;
    type Generation = G;
    type Group = Group<'a, 'm, 'd, 'p, D, G, E>;
    fn snapshot(&self) -> Snapshot<D, G> {
        self.mapping.snapshot
    }
    fn signature(&self) -> Node {
        self.mapping.root
    }
    fn root(&self) -> Option<&Self::Group> {
        self.root.as_ref()
    }
    fn counters(&self) -> usize {
        self.counters.len()
    }
    fn counter(&self, ordinal: usize) -> (Node, &Self::Group) {
        let group = &self.counters[ordinal];
        (group.signature(), group)
    }
}
impl<'m, 'd, 'p, D: Copy + Eq, G: Copy + Eq, E> Report<'m, 'd, 'p, '_, D, G, E> {
    /// Full original authentication details, including every negative result.
    #[must_use]
    pub fn common(&self) -> &cms::Report<'m, 'd, 'p, E> {
        &self.common
    }
    /// Issues a full participant receipt only if every original authentication
    /// supplied its actual authorities. Current work funds the group views;
    /// authentication and retained evidence are neither replayed nor copied.
    ///
    /// # Panics
    /// Panics if the internally retained complete counter-group census is inconsistent.
    pub fn complete<'a>(
        &'a self,
        operation: &impl Work,
    ) -> crate::Result<Option<Complete<'a, 'm, 'd, 'p, D, G, E>>> {
        let work = self.session.query(operation);
        let location = self.mapping.carrier;
        admit(&work, location, 1)?;
        let Some(common) = self.common.complete() else {
            return Ok(None);
        };
        let root = common.root_group().map(|value| Group {
            common: value,
            mapping: self.mapping,
        });
        let mut counters = work.vector();
        counters
            .try_reserve_exact(common.counters())
            .map_err(|cause| PdfError {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        for ordinal in 0..common.counters() {
            let value = common
                .counter_group(ordinal, &work)
                .map_err(|cause| PdfError {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .expect("bounded original counter group");
            counters
                .try_push(Group {
                    common: value,
                    mapping: self.mapping,
                })
                .map_err(|cause| PdfError {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
        }
        Ok(Some(Complete {
            common,
            mapping: self.mapping,
            root,
            counters: counters.into_owned(),
        }))
    }
}
impl<'a, 'm, 'd, 'p, D, G, E> Complete<'a, 'm, 'd, 'p, D, G, E> {
    /// Exact existing CMS authentication receipt used for format dependencies.
    #[must_use]
    pub fn common(&self) -> &cms::Complete<'a, 'm, 'd, 'p, E> {
        &self.common
    }
}

/// Original PDF/current refusal versus unchanged protected-property failure.
#[derive(Debug)]
pub enum Error<E> {
    /// Original source, membership or current resource refusal.
    Pdf(PdfError),
    /// Original source generation or scoped current admission refused.
    Scope(structured_ltv::source::ScopeError<Node>),
    /// Original `PAdES` basic requirements prevent protected authentication.
    Nonconforming {
        /// Actual source signature dictionary.
        location: crate::source::Location,
    },
    /// Original CMS schema/source/handler cause in the carried domain.
    Cms(cms::CheckError<E>),
}
impl<'m, 'd, 'p, 's, D: Copy + Eq, G: Copy + Eq> Basic<'_, '_, '_, 'm, 'd, '_, 's, 'p, D, G> {
    /// Derives the original complete participant census from the SAME root,
    /// all counters, authenticated credentials and complete TSA-path receipt.
    /// No caller-defined positive receipt or selected successful subset is used.
    pub fn participants<'r, 'certificate, E, S: RangeSource<Document = D, Generation = G>>(
        &'p self,
        credentials: &'p Complete<'r, 'm, 'd, 'p, D, G, E>,
        timestamps: &'p structured_ltv::timestamp::TimestampPaths<
            'p,
            'certificate,
            'd,
            Node,
            D,
            G,
            crate::timestamp::Pades,
        >,
        query: &Query<'_, '_, S>,
    ) -> Result<
        pki::ParticipantRequirements<'p, 'd, Node, D, G, crate::timestamp::Pades>,
        pki::ParticipantError<Node>,
    > {
        let source = self.binding().prepared().container.signature();
        query.admit(self.binding().mapping.root, 1)?;
        if !query.belongs(source.owner().value.session)
            || credentials.mapping.snapshot != self.binding().mapping.snapshot
            || credentials.mapping.root != self.binding().mapping.root
        {
            return Err(pki::ParticipantError::Foreign {
                signature: self.binding().mapping.root,
            });
        }
        pki::participants(
            crate::timestamp::ISSUER,
            self.binding(),
            self.counters(),
            credentials,
            timestamps,
            query,
        )
    }

    /// Authenticates every original protected credential using the shared
    /// property kernel and this operation's actual scoped producing reader.
    /// `PAdES` root requirements are checked before the first handler call.
    pub fn authenticate_credentials<
        P: cms::Provider<'p, 'd>,
        S: RangeSource<Document = D, Generation = G>,
    >(
        &self,
        provider: &P,
        query: &Query<'_, '_, S>,
    ) -> Result<Report<'m, 'd, 'p, 's, D, G, P::Evidence>, Error<P::Error>> {
        let bound = self.binding();
        let prepared = bound.prepared();
        let signature = prepared.container.signature();
        let location = signature.location();
        query.admit(bound.mapping.root, 1).map_err(Error::Scope)?;
        if !query.belongs(signature.owner().value.session)
            || query.snapshot() != bound.mapping.snapshot
        {
            return Err(Error::Pdf(PdfError {
                kind: ErrorKind::Foreign,
                location,
            }));
        }
        if !self.all_basic_requirements_met() {
            return Err(Error::Nonconforming { location });
        }
        let work = signature.owner().value.session.query(query.execution());
        let reader = prepared
            .cms
            .signer()
            .fields_source()
            .reader_in(&work)
            .map_err(|cause| Error::Cms(cms::CheckError::Processing(cause.into())))?;
        let common = cms::check_properties(
            prepared.cms,
            bound.binding(),
            &self.counters().common,
            provider,
            &reader,
        )
        .map_err(Error::Cms)?;
        query.admit(bound.mapping.root, 1).map_err(Error::Scope)?;
        Ok(Report {
            common,
            mapping: bound.mapping,
            session: signature.owner().value.session,
        })
    }
}
