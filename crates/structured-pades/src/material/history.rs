//! Full historical DSS visibility and the unchanged inner CMS material pool.

use super::{Parsed, Placement, Validation};
use crate::{
    basic::Basic,
    binding::InnerQuery,
    document::Document,
    error::{Error, ErrorKind, ReadFailure},
    query::Query,
    range::RangeSource,
    signature::Signature,
    timestamp::{ISSUER, Node, Pades},
};
use structured_asn1::memory::{Execution, Memory, OwnedVec, Work};
use structured_ltv::{
    material::{ArtifactSource, Index, IndexError, ProjectionError},
    source::{Location, Query as _},
};
mod token;

/// Every historical DSS window, including explicit absent dictionaries. The
/// original root/source membership cannot be replaced with a caller subset.
pub struct History<'a, 's, D, G> {
    pub(crate) root: Signature<'a, 's, D, G>,
    pub(super) values: OwnedVec<Validation<'s, D, G>, Memory>,
}
/// Once-parsed material in every actual historical window.
pub struct ParsedHistory<'h, 'a, 's, D, G> {
    pub(super) owner: &'h History<'a, 's, D, G>,
    pub(super) values: OwnedVec<Parsed<'h, 's, D, G>, Memory>,
}

type UnifiedIndex<'q, 'd, D, G> =
    Index<'q, Node, D, G, Placement, structured_cades::material::Open<'d>, Execution<'q>, Pades>;

struct TokenCoverage {
    complete: bool,
    generation_revision: Option<usize>,
}

enum TokenIndexError {
    Foreign(Error),
    Index(IndexError<Node>),
}
impl From<TokenIndexError> for HistoryError {
    fn from(value: TokenIndexError) -> Self {
        match value {
            TokenIndexError::Foreign(cause) => Self::Foreign(cause),
            TokenIndexError::Index(cause) => Self::Index(cause),
        }
    }
}

/// Exact common pool projected into the enclosing PDF domain, before any
/// material/path/status acceptance. Open values retain their CMS coordinates.
pub struct Unified<'q, 'd, D, G> {
    pub(crate) session: &'q crate::Session,
    pub(crate) index: UnifiedIndex<'q, 'd, D, G>,
    pub(crate) root: Node,
    pub(crate) complete: bool,
    pub(crate) required: &'q structured_ltv::timestamp::TimestampRequirements<Node, D, G, Pades>,
    pub(crate) revision: usize,
    associations: super::vri::Associations,
}
impl<D, G> Unified<'_, '_, D, G> {
    /// Exact historical material window, independent of the file's latest
    /// revision and of whether any artifact lookup succeeds.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }
    /// DSS presence and original source conformance in the selected window.
    /// Actual participant incorporation, authentication and trust are separate.
    #[must_use]
    pub fn all_source_requirements_met(&self) -> bool {
        self.complete
    }
    /// Complete nominal VRI associations, including unmatched or late inputs.
    #[must_use]
    pub fn vri_associations(&self) -> &super::vri::Associations {
        &self.associations
    }
}

/// Original acquisition, carried-format, projection or current-query refusal.
#[derive(Debug)]
pub enum HistoryError {
    /// Original DSS/carried-format parser refusal.
    Material(super::MaterialFailure),
    /// Actual inner pool source/metadata admission failure.
    CmsIndex {
        /// Physical PDF enclosure of the logical CMS coordinates.
        enclosure: crate::source::Location,
        /// Unchanged inner source/resource cause.
        cause: IndexError<structured_cades::source::Node>,
    },
    /// Original source/projection/current allocation refusal.
    Projection(ProjectionError<Node, Error>),
    /// Actual PDF material-index refusal.
    Index(IndexError<Node>),
    /// Source membership was substituted.
    Foreign(Error),
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Enumerates each actual revision, so a late DSS or replacement cannot
    /// silently satisfy a timestamp whose original input lacks those values.
    pub async fn validation_history<'a, W: Work>(
        &self,
        root: Signature<'a, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<History<'a, 's, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = root.location();
        self.check(&work, location)?;
        if !core::ptr::eq(root.owner().value.session, self.session)
            || root.owner().value.stamp != self.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        let mut values = work.vector();
        for revision in 0..self.revisions() {
            crate::model::admit(&work, location, 1)?;
            let value = self.validation(revision, &work).await?;
            values.try_push(value).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        Ok(History {
            root,
            values: values.into_owned(),
        })
    }
}
impl<'a, 's, D: Copy + Eq, G: Copy + Eq> History<'a, 's, D, G> {
    /// Historical owners in original revision order, including absent DSS.
    #[must_use]
    pub fn revisions(&self) -> &[Validation<'s, D, G>] {
        &self.values
    }
    /// Parses each actual original window once, keeping every negative source.
    #[expect(
        clippy::result_large_err,
        reason = "historical material failure preserves the complete cause and actual original item location without an error box"
    )]
    pub fn parse<'h>(
        &'h self,
        operation: &'h impl Work,
    ) -> Result<ParsedHistory<'h, 'a, 's, D, G>, HistoryError> {
        let work = self.root.owner().value.session.query(operation);
        let mut values = work.vector();
        for value in &self.values {
            let value = value.parse(operation).map_err(HistoryError::Material)?;
            values.try_push(value).map_err(|cause| {
                HistoryError::Foreign(Error {
                    kind: ErrorKind::Resource(cause),
                    location: self.root.location(),
                })
            })?;
        }
        Ok(ParsedHistory {
            owner: self,
            values: values.into_owned(),
        })
    }
}
impl<'h, 's, D: Copy + Eq, G: Copy + Eq> ParsedHistory<'h, '_, 's, D, G> {
    /// Same full original material windows; no successful-prefix selection.
    #[must_use]
    pub fn revisions(&self) -> &[Parsed<'h, 's, D, G>] {
        &self.values
    }
    fn append_document_tokens<
        'q,
        'm: 'q,
        'd: 'q,
        'tokens: 'q,
        S: RangeSource<Document = D, Generation = G>,
    >(
        timestamps: &'q crate::timestamp::sources::Models<'tokens, '_, '_, 's, D, G>,
        mapping: crate::binding::Mapping<'m, 'd, D, G>,
        prefix: usize,
        index: &mut UnifiedIndex<'q, 'd, D, G>,
        query: &Query<'q, 's, S>,
    ) -> Result<TokenCoverage, TokenIndexError>
    where
        'h: 'q,
    {
        let mut complete = true;
        let mut generation_revision = None;
        for (timestamp, value) in timestamps.values.iter().enumerate() {
            index.admit(query).map_err(TokenIndexError::Index)?;
            let crate::timestamp::sources::Model::Known { token, revocations } = value else {
                complete = false;
                continue;
            };
            let Some(crate::timestamp::sources::Slot::Value(container)) = timestamps
                .sources
                .get(timestamp, query.execution())
                .map_err(TokenIndexError::Foreign)?
            else {
                unreachable!("a parsed token retains its original container")
            };
            if let crate::signature::Coverage::Revision(covered) = container.signature().coverage()
                && generation_revision.is_none_or(|previous| covered > previous)
            {
                generation_revision = Some(covered);
            }
            let source_ordinal = prefix.checked_add(timestamp).ok_or(TokenIndexError::Index(
                IndexError::Resource {
                    signature: mapping.root,
                    cause: structured_asn1::memory::MemoryError::CapacityOverflow,
                },
            ))?;
            let contents = timestamps
                .contents(timestamp)
                .expect("readable original token source");
            let location = Location {
                snapshot: mapping.snapshot,
                node: Node::of(contents),
            };
            if !token::append(
                index,
                token,
                revocations,
                source_ordinal,
                location,
                |choice| Placement::DocumentTimestamp { timestamp, choice },
                query,
            )
            .map_err(TokenIndexError::Index)?
            {
                complete = false;
            }
        }
        Ok(TokenCoverage {
            complete,
            generation_revision,
        })
    }

    fn append_vri_tokens<
        'q,
        'm: 'q,
        'd: 'q,
        'tokens: 'q,
        S: RangeSource<Document = D, Generation = G>,
    >(
        &'q self,
        timestamps: &'q crate::timestamp::sources::Models<'tokens, '_, '_, 's, D, G>,
        mapping: crate::binding::Mapping<'m, 'd, D, G>,
        prefix: usize,
        index: &mut UnifiedIndex<'q, 'd, D, G>,
        query: &Query<'q, 's, S>,
    ) -> Result<bool, TokenIndexError>
    where
        'h: 'q,
    {
        let mut complete = true;
        for source in timestamps.vri_timestamps() {
            index.admit(query).map_err(TokenIndexError::Index)?;
            let parsed = &self.values[source.revision];
            let super::Value::Timestamp(value) = &parsed.values()[source.item] else {
                complete = false;
                continue;
            };
            let source_ordinal = prefix
                .checked_add(timestamps.total_pdf())
                .and_then(|prefix| prefix.checked_add(source.ordinal))
                .ok_or(TokenIndexError::Index(IndexError::Resource {
                    signature: mapping.root,
                    cause: structured_asn1::memory::MemoryError::CapacityOverflow,
                }))?;
            let item = &self.owner.values[source.revision].items()[source.item];
            let location = Location {
                snapshot: mapping.snapshot,
                node: Node::dss(item.location(), source.revision),
            };
            if !token::append(
                index,
                &value.token,
                &value.revocations,
                source_ordinal,
                location,
                |choice| Placement::VriTimestamp {
                    revision: source.revision,
                    vri: source.vri,
                    choice,
                },
                query,
            )
            .map_err(TokenIndexError::Index)?
            {
                complete = false;
            }
        }
        Ok(complete)
    }

    fn selected_revision<S: RangeSource<Document = D, Generation = G>>(
        &self,
        basic: &Basic<'_, '_, '_, '_, '_, '_, 's, '_, D, G>,
        pool: &structured_cades::material::Pool<'_, '_, '_>,
        timestamps: &crate::timestamp::sources::Models<'_, '_, '_, 's, D, G>,
        query: &Query<'_, 's, S>,
    ) -> crate::Result<usize> {
        let signature = self.owner.root;
        let location = signature.location();
        let mapping = basic.binding().mapping;
        let foreign = || Error {
            kind: ErrorKind::Foreign,
            location,
        };
        if !query.belongs(signature.owner().value.session)
            || query.snapshot() != mapping.snapshot
            || mapping.root != Node::of(location)
            || !core::ptr::eq(pool.prepared(), basic.binding().prepared().cms)
        {
            return Err(foreign());
        }
        if timestamps.root() != mapping.root || timestamps.snapshot() != mapping.snapshot {
            return Err(foreign());
        }
        debug_assert!(
            !self.values.is_empty(),
            "a parsed document has an original revision"
        );
        let revision = timestamps.revision().unwrap_or(self.values.len() - 1);
        if revision >= self.values.len()
            || !matches!(signature.coverage(), crate::signature::Coverage::Revision(root) if root <= revision)
        {
            return Err(foreign());
        }
        Ok(revision)
    }

    fn source_complete<'q, 'm, 'd, S: RangeSource<Document = D, Generation = G>>(
        &self,
        pool: &structured_cades::material::Pool<'_, 'm, 'd>,
        revision: usize,
        index: &UnifiedIndex<'q, 'd, D, G>,
        query: &Query<'q, 's, S>,
    ) -> Result<bool, IndexError<Node>> {
        let mut complete = true;
        for value in pool.open() {
            index.admit(query)?;
            if value.cause.is_some() {
                complete = false;
            }
        }
        for value in &self.values[..=revision] {
            index.admit(query)?;
            if !value.all_values_readable() || !value.all_vri_material_in_dss() {
                complete = false;
            }
        }
        Ok(complete)
    }

    fn generation_covered<'q, 'd, S: RangeSource<Document = D, Generation = G>>(
        &self,
        revision: usize,
        generation_revision: Option<usize>,
        index: &UnifiedIndex<'q, 'd, D, G>,
        query: &Query<'q, 's, S>,
    ) -> Result<bool, IndexError<Node>> {
        let mut complete = true;
        // EN319142-1 §5.4.2.3(c): absent TU/TS leaves a subsequent-DTS
        // obligation. An earlier whole-file timestamp cannot satisfy it.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
        for validation in &self.owner.values[..=revision] {
            for vri in validation.vri() {
                index.admit(query)?;
                if validation.revision == 0
                    || matches!(
                        vri.generation_time(),
                        super::GenerationTime::DocumentTimestampRequired
                    ) && generation_revision.is_none_or(|covered| covered < validation.revision)
                {
                    complete = false;
                }
            }
        }
        Ok(complete)
    }

    /// Transfer the original complete inner index, preserving every embedded
    /// certificate and original occurrence, then append all historical DSS.
    ///
    /// # Panics
    /// Panics if a known parsed timestamp no longer has its retained original contents.
    #[expect(
        clippy::result_large_err,
        reason = "indexing retains exact inner and enclosing refusal contexts; resource failure must not require another allocation"
    )]
    pub async fn index<'q, 'm: 'q, 'd, 'tokens: 'q, 'p, S, P>(
        &'q self,
        basic: &Basic<'_, '_, '_, 'm, 'd, '_, 's, '_, D, G>,
        pool: &'q structured_cades::material::Pool<'_, 'm, 'd>,
        timestamps: &'q crate::timestamp::sources::Models<'tokens, '_, '_, 's, D, G>,
        provider: &'p P,
        query: &Query<'q, 's, S>,
    ) -> Result<Unified<'q, 'd, D, G>, super::vri::SourceError<S::Error, P::Error>>
    where
        S: RangeSource<Document = D, Generation = G>,
        P: structured_pkix::algorithm::digest::AsnDigest<'p>,
        'd: 'q,
        'h: 'q,
    {
        let signature = self.owner.root;
        let location = signature.location();
        let mapping = basic.binding().mapping;
        let revision = self
            .selected_revision(basic, pool, timestamps, query)
            .map_err(HistoryError::Foreign)?;
        let inner_query = InnerQuery {
            outer: query,
            mapping,
        };
        let original = pool
            .index(&inner_query)
            .map_err(|cause| HistoryError::CmsIndex {
                enclosure: mapping.carrier,
                cause,
            })?;
        let mut ordinal = 0;
        let mut index = original
            .into_projected(ISSUER, mapping.root, query, |occurrence| {
                if occurrence.location().snapshot != mapping.cms {
                    return Err(Error {
                        kind: ErrorKind::Foreign,
                        location,
                    });
                }
                let source = match occurrence.source() {
                    ArtifactSource::Material(_) => ArtifactSource::Material(ordinal),
                    source => source,
                };
                ordinal += 1;
                Ok((
                    source,
                    Location {
                        snapshot: mapping.snapshot,
                        node: mapping.node(occurrence.location().node),
                    },
                    Placement::Cms(occurrence.placement()),
                ))
            })
            .map_err(HistoryError::Projection)?;
        for parsed in &self.values[..=revision] {
            parsed
                .append(&mut index, &mut ordinal, query)
                .map_err(HistoryError::Index)?;
        }
        // EN319142-1 §6.3 Table1 requires a DSS at B-LT/B-LTA. Certificate
        // duplication is discouraged, so that DSS may be empty when every
        // used value is already incorporated in the actual CMS/token inputs.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
        let mut complete = self.owner.values[revision].is_present();
        if !self
            .source_complete(pool, revision, &index, query)
            .map_err(HistoryError::Index)?
        {
            complete = false;
        }
        let prefix = pool.prepared().timestamps().len();
        let tokens = Self::append_document_tokens(timestamps, mapping, prefix, &mut index, query)
            .map_err(HistoryError::from)?;
        let generation_revision = tokens.generation_revision;
        if !tokens.complete {
            complete = false;
        }
        if !self
            .generation_covered(revision, generation_revision, &index, query)
            .map_err(HistoryError::Index)?
        {
            complete = false;
        }
        if !self
            .append_vri_tokens(timestamps, mapping, prefix, &mut index, query)
            .map_err(HistoryError::from)?
        {
            complete = false;
        }
        let associations = super::vri::sources::associate(
            self,
            basic.binding().prepared().container,
            pool,
            timestamps,
            provider,
            query,
            revision,
        )
        .await?;
        if !associations.all_requirements_met() {
            complete = false;
        }
        Ok(Unified {
            session: signature.owner().value.session,
            index,
            root: mapping.root,
            complete,
            required: timestamps.requirements(),
            revision,
            associations,
        })
    }
}
