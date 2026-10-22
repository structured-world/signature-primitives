//! Original `ATSv3` input/index composition over the existing CMS archive core.

use super::{
    CheckError, CheckTime, Checked, Context, InputError, ProfileFailure, ProfileSource, tsp,
};
use crate::{
    Cades, Error, ISSUER,
    prepare::Preparation,
    source::{DocumentId, Node},
};
use core::cell::Cell;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Memory;
use structured_asn1::{
    Reader,
    memory::{Execution, OwnedVec, Work},
};
use structured_cms::{
    Octets,
    archive::{self, HashIndex, IndexCoverage},
    digest::{DigestBatch, DigestError, PassError},
};
use structured_cms::{
    provider::SignatureProvider,
    stream::{Receiver, Refused, Source},
};
use structured_ltv::{
    material::Coverage,
    source::{Query, Scope, Source as _},
};
use structured_ltv::{pki::CheckedPath, timestamp::Purpose};

/// No detached source exists for a carried-content operation. This
/// uninhabited type cannot supply a fabricated empty-input fallback.
#[derive(Debug)]
pub enum NoDetached {}
impl Source for NoDetached {
    type Error = core::convert::Infallible;
    fn stream<W: Work>(&mut self, _: &mut impl Receiver, _: &W) -> Result<(), Self::Error> {
        match *self {}
    }
}

/// Actual `ATSv3` preflight/content refusal, distinct from absent proof.
#[derive(Debug)]
pub enum ArchiveError<SE, PE> {
    /// Original source/schema/encoding/resource refusal.
    Processing(Error),
    /// Original archive-index digest/refusal/output-contract cause.
    Digest(DigestError<PE>),
    /// An index or imprint mechanism could not be resolved.
    Unsupported,
    /// An index or imprint identifier violates its algorithm's schema.
    MalformedAlgorithm,
    /// Actual MD5 use is forbidden by the baseline format before index hashing.
    ForbiddenDigest {
        /// Original index algorithm enclosure.
        at: u64,
    },
    /// An index hash has no original root value to which it refers.
    UnmatchedIndex,
    /// The index and timestamp imprint do not use the same digest mechanism.
    AlgorithmMismatch,
    /// Original content pass failed without a complete digest.
    Content(PassError<SE, PE>),
    /// Private prepared mapping did not produce its sole completed request.
    MissingDigest,
}

/// Sticky original range delivery, with no document buffering or second pass.
#[derive(Debug)]
pub enum ArchiveStreamError {
    /// Metadata admission failed before the next original range.
    Resource(structured_asn1::memory::MemoryError),
    /// The common driver retains the original receiver refusal.
    Receiver(Refused),
    /// No complete original content digest was prepared; never hash empty bytes.
    MissingDigest,
    /// The original archive range helper refused source membership.
    Source(structured_cms::Error),
}

enum Content<'s, 'd, S> {
    Carried(&'s Octets<'d>),
    Detached(&'s mut S),
}
impl<S: Source> Source for Content<'_, '_, S> {
    type Error = InputError<S::Error>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Carried(source) => source.stream(receiver, work).map_err(InputError::Carried),
            Self::Detached(source) => source.stream(receiver, work).map_err(InputError::Detached),
        }
    }
}

/// Independently checked archive token, exact original index coverage and its
/// derived whole-item selection. Application chronology/status/trust remain
/// separate; coverage is usable only with this exact successful token actor.
pub struct ArchiveChecked<'model, 'document, 'path> {
    timestamp: Checked<'model, 'document, 'path>,
    index: IndexCoverage,
    coverage: Coverage<Node, DocumentId<'model, 'document>, (), Memory, Cades>,
}

/// Borrowed common facts of an actual modern or historical archive receipt.
/// Private fields prevent callers from pairing one token with another input's
/// coverage. Negative checks remain negative; material requires its own actor.
#[derive(Clone, Copy)]
pub struct ArchiveView<'view, 'model, 'document, 'path> {
    timestamp: &'view Checked<'model, 'document, 'path>,
    coverage: &'view Coverage<Node, DocumentId<'model, 'document>, (), Memory, Cades>,
}
impl<'v, 'm, 'd, 'p> From<&'v ArchiveChecked<'m, 'd, 'p>> for ArchiveView<'v, 'm, 'd, 'p> {
    fn from(value: &'v ArchiveChecked<'m, 'd, 'p>) -> Self {
        Self {
            timestamp: value.timestamp(),
            coverage: value.coverage(),
        }
    }
}
impl<'v, 'm, 'd, 'p> From<&'v super::historical::HistoricalChecked<'m, 'd, 'p>>
    for ArchiveView<'v, 'm, 'd, 'p>
{
    fn from(value: &'v super::historical::HistoricalChecked<'m, 'd, 'p>) -> Self {
        Self {
            timestamp: value.timestamp(),
            coverage: value.coverage(),
        }
    }
}
impl<'m, 'd, 'p> ArchiveView<'_, 'm, 'd, 'p> {
    pub(crate) fn timestamp(&self) -> &Checked<'m, 'd, 'p> {
        self.timestamp
    }
    pub(crate) fn coverage(&self) -> &Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades> {
        self.coverage
    }
}
impl<'m, 'd, 'p> ArchiveChecked<'m, 'd, 'p> {
    /// Complete original common timestamp facts, including negative outcomes.
    #[must_use]
    pub fn timestamp(&self) -> &Checked<'m, 'd, 'p> {
        &self.timestamp
    }
    /// Actual original certificate/revocation/unsigned-value index matches.
    #[must_use]
    pub fn index(&self) -> &IndexCoverage {
        &self.index
    }
    /// Mathematical input selection; bind it to this timestamp's actual
    /// Verified receipt before claiming archived material or earlier actors.
    #[must_use]
    pub fn coverage(&self) -> &Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades> {
        &self.coverage
    }

    /// Derives the complete earlier-actor census from THIS archive's actual
    /// mathematical index coverage. Source order and genTime are not used as
    /// substitutes for coverage; the archive's own TSA is excluded. The full
    /// original counter census is retained with its explicit inclusion mask.
    pub fn requirements(
        &self,
        prepared: &Preparation<'m, 'd>,
        operation: &Reader<'d>,
    ) -> Result<
        structured_ltv::timestamp::TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>,
        ScopeError,
    > {
        super::requirements::derive(&self.timestamp, &self.coverage, prepared, operation)
    }
}

/// An earlier archive scope requires this exact successful token and source.
#[derive(Debug)]
pub enum ScopeError {
    /// Original session/work/storage refusal.
    Processing(Error),
    /// Original archive has no complete common mathematical evidence.
    Unproven,
    /// Another parallel signer/preparation in the same original `SignedData`.
    Foreign,
    /// Actual coverage/source/current-query refusal, not a missing actor.
    Coverage(structured_ltv::material::CoverageError<Node>),
}

struct Input<'s, 'm, 'd> {
    prepared: &'s Preparation<'m, 'd>,
    index: &'s HashIndex<'d>,
    hash: &'s Cell<Option<OwnedVec<u8>>>,
}
impl Source for Input<'_, '_, '_> {
    type Error = ArchiveStreamError;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let hash = self.hash.take().ok_or(ArchiveStreamError::MissingDigest)?;
        let ranges = archive::imprint_input(
            self.prepared.document().message(),
            self.prepared.signer(),
            self.index,
            &hash,
        )
        .map_err(ArchiveStreamError::Source)?;
        for range in ranges {
            work.charge_work(1).map_err(ArchiveStreamError::Resource)?;
            receiver
                .write(range)
                .map_err(ArchiveStreamError::Receiver)?;
        }
        Ok(())
    }
}

/// Full original archive check including its preflight, with original source
/// map preservation for failures from the carried `TSTInfo` profile callback.
#[derive(Debug)]
pub enum ArchiveCheckError<SE, PE, RE> {
    /// Original index/source failure before common timestamp processing.
    Before(ArchiveError<SE, PE>),
    /// Original timestamp/profile/source/provider failure and its source maps.
    Timestamp(CheckError<ArchiveStreamError, PE, RE, ArchiveError<SE, PE>>),
}

impl<'m, 'd> Context<'_, 'm, 'd> {
    /// Checks `ATSv3` against ORIGINAL attached eContent. The imprint input
    /// contains its content digest, never a copied/normalized whole document.
    /// This delegates index matching and range construction to the existing
    /// CMS archive kernel (EN319122-1 §§5.5.2–5.5.3).
    #[expect(
        clippy::result_large_err,
        reason = "index refusal and the original mapped token cause are returned without allocating on an already exhausted account"
    )]
    pub fn check_archive_carried<'a, 'p, P, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<
        ArchiveChecked<'m, 'd, 'p>,
        ArchiveCheckError<InputError<core::convert::Infallible>, PE, RE>,
    >
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let source = self
            .prepared
            .document()
            .message()
            .content()
            .content()
            .ok_or_else(|| {
                ArchiveCheckError::Before(ArchiveError::Processing(Error::Foreign {
                    at: self.entry.property().span().start,
                }))
            })?;
        self.archive(
            provider,
            path,
            certificate_parent,
            time,
            &mut Content::<NoDetached>::Carried(source),
            recognizes,
        )
    }

    /// Checks the explicit detached input only when original eContent is
    /// absent. The common source driver preserves incomplete/refused EOF;
    /// detached acquisition is never a substitute for a carried document.
    #[expect(
        clippy::result_large_err,
        reason = "detached acquisition and nested archive token failures keep their distinct original provenance without boxing"
    )]
    pub fn check_archive_detached<'a, 'p, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        detached: &mut S,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<ArchiveChecked<'m, 'd, 'p>, ArchiveCheckError<InputError<S::Error>, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if !self.prepared.document().message().content().is_detached() {
            return Err(ArchiveCheckError::Before(ArchiveError::Processing(
                Error::Foreign {
                    at: self.entry.property().span().start,
                },
            )));
        }
        self.archive(
            provider,
            path,
            certificate_parent,
            time,
            &mut Content::Detached(detached),
            recognizes,
        )
    }

    #[expect(
        clippy::result_large_err,
        reason = "one archive transaction propagates owned source maps and opaque source/provider causes without a refusal-time allocation"
    )]
    fn archive<'a, 'p, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        original: &mut S,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<ArchiveChecked<'m, 'd, 'p>, ArchiveCheckError<S::Error, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let before = ArchiveCheckError::Before;
        let processing = |cause| before(ArchiveError::Processing(cause));
        self.require_archive().map_err(processing)?;
        let index = HashIndex::of_token(self.token, self.reader)
            .map_err(|cause| processing(Error::Cms(cause)))?;
        let coverage = self.matched_index(&index, provider).map_err(before)?;
        let hash = Cell::new(None);
        let mut covered = Input {
            prepared: self.prepared,
            index: &index,
            hash: &hash,
        };
        let checked = self
            .check_profile(
                provider,
                path,
                certificate_parent,
                time,
                &mut covered,
                (recognizes, |input| {
                    let failure = |cause| ProfileFailure {
                        source: ProfileSource::Information,
                        cause,
                    };
                    let tsp::HashAlgorithmReading::Identifier(algorithm) =
                        input.info.imprint().algorithm()
                    else {
                        return Err(failure(ArchiveError::MalformedAlgorithm));
                    };
                    match archive::same_algorithm(&index, algorithm, &input.reader.execution())
                        .map_err(|cause| failure(ArchiveError::Processing(Error::Cms(cause))))?
                    {
                        Resolution::Supported(true) => {}
                        Resolution::Supported(false) => {
                            return Err(failure(ArchiveError::AlgorithmMismatch));
                        }
                        Resolution::Unsupported => return Err(failure(ArchiveError::Unsupported)),
                        Resolution::Malformed => {
                            return Err(failure(ArchiveError::MalformedAlgorithm));
                        }
                    }
                    let work = input.reader.execution();
                    let identity = match structured_pkix::algorithm::digest::resolve(
                        provider, algorithm, &work,
                    )
                    .map_err(|cause| failure(ArchiveError::Processing(Error::Pkix(cause))))?
                    {
                        Resolution::Supported(value) => value,
                        Resolution::Unsupported => return Err(failure(ArchiveError::Unsupported)),
                        Resolution::Malformed => {
                            return Err(failure(ArchiveError::MalformedAlgorithm));
                        }
                    };
                    let mut identities = work.vector();
                    identities.try_push(identity).map_err(|cause| {
                        failure(ArchiveError::Processing(Error::resource(
                            cause,
                            "cades.archive",
                            input.info.imprint().span().start,
                        )))
                    })?;
                    let batch = DigestBatch::prepare(
                        provider,
                        identities.into_owned(),
                        &work,
                        "cades.archive.content",
                        self.entry.property().span().start,
                    )
                    .map_err(|cause| failure(ArchiveError::Digest(cause)))?;
                    let memo = batch
                        .run(original, &work)
                        .map_err(|cause| failure(ArchiveError::Content(cause)))?;
                    let digest = memo
                        .for_request(0, &work)
                        .map_err(|cause| failure(ArchiveError::Digest(cause)))?
                        .ok_or_else(|| failure(ArchiveError::MissingDigest))?;
                    // P::Output may borrow the scoped information source. Retain only
                    // the finished hash bytes across that HRTB boundary; never retain
                    // a view of the temporary joined TSTInfo, state, or identity.
                    let mut retained = work.vector();
                    retained
                        .try_extend_from_slice(digest.as_bytes())
                        .map_err(|cause| {
                            failure(ArchiveError::Processing(Error::resource(
                                cause,
                                "cades.archive.content",
                                self.entry.property().span().start,
                            )))
                        })?;
                    hash.set(Some(retained.into_owned()));
                    Ok(())
                }),
            )
            .map_err(ArchiveCheckError::Timestamp)?;
        let selected = self.coverage(&coverage).map_err(processing)?;
        Ok(ArchiveChecked {
            timestamp: checked,
            index: coverage,
            coverage: selected,
        })
    }

    fn matched_index<'a, P, SE, PE>(
        &'a self,
        index: &HashIndex<'d>,
        provider: &'a P,
    ) -> Result<IndexCoverage, ArchiveError<SE, PE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let processing = ArchiveError::Processing;
        self.reader
            .charge(1 + index.algorithm().algorithm().as_bytes().len().min(8) as u64)
            .map_err(|cause| processing(Error::encoding(cause, "cades.archive.index")))?;
        if index.algorithm().algorithm()
            == structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5])
        {
            return Err(ArchiveError::ForbiddenDigest {
                at: index.algorithm().offset(),
            });
        }
        let coverage = match archive::check_index(
            index,
            self.prepared.document().message(),
            self.prepared.signer(),
            provider,
            self.reader,
        )
        .map_err(ArchiveError::Digest)?
        {
            Resolution::Supported(value) => value,
            Resolution::Unsupported => return Err(ArchiveError::Unsupported),
            Resolution::Malformed => return Err(ArchiveError::MalformedAlgorithm),
        };
        if !coverage.is_valid() {
            return Err(ArchiveError::UnmatchedIndex);
        }
        Ok(coverage)
    }
    fn coverage(
        &self,
        index: &IndexCoverage,
    ) -> crate::Result<Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades>> {
        let work = self.reader.execution();
        let resource = |cause| {
            Error::resource(
                cause,
                "cades.archive.coverage",
                self.entry.property().span().start,
            )
        };
        let mut items = work.map();
        let message = self.prepared.document().message();
        for (choice, covered) in message
            .certificate_choices()
            .iter()
            .zip(index.certificates())
        {
            work.charge_work(1).map_err(resource)?;
            let span = match choice {
                structured_cms::signed::CertificateChoice::X509(ordinal) => {
                    message.certificates()[*ordinal].span()
                }
                structured_cms::signed::CertificateChoice::Extended(value)
                | structured_cms::signed::CertificateChoice::AttributeV1(value)
                | structured_cms::signed::CertificateChoice::AttributeV2(value)
                | structured_cms::signed::CertificateChoice::Other(value) => value.span(),
            };
            items
                .try_insert(Node::of(span), *covered)
                .map_err(resource)?;
        }
        for (value, covered) in message.revocations().iter().zip(index.revocations()) {
            work.charge_work(1).map_err(resource)?;
            items
                .try_insert(Node::of(value.span()), *covered)
                .map_err(resource)?;
        }
        let mut ranges = work.vector();
        if let Some(attributes) = self.prepared.signer().signed_attributes() {
            // EN319122-1 §5.5.3 input3 includes the original signedAttrs,
            // independently of the index of UNSIGNED attribute values. Their
            // root content timestamps therefore belong to the covered census.
            // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
            ranges
                .try_push(attributes.element().span())
                .map_err(resource)?;
            for attribute in attributes.items() {
                work.charge_work(1).map_err(resource)?;
                items
                    .try_insert(Node::of(attribute.span()), true)
                    .map_err(resource)?;
            }
        }

        if let Some(attributes) = self.prepared.signer().unsigned_attributes() {
            for attribute in attributes.items() {
                work.charge_work(1).map_err(resource)?;
                // check_index constructs the complete original projection.
                // Each uncovered value clears its owning attribute below;
                // a genuinely empty set never establishes whole coverage.
                let all = !attribute.values().is_empty();
                items
                    .try_insert(Node::of(attribute.span()), all)
                    .map_err(resource)?;
            }
            for (position, covered) in index.attribute_values() {
                work.charge_work(1).map_err(resource)?;
                let attribute = &attributes.items()[position.attribute];
                let value = &attribute.values()[position.value];
                items
                    .try_insert(Node::of(value.span()), *covered)
                    .map_err(resource)?;
                if *covered {
                    ranges.try_push(value.span()).map_err(resource)?;
                } else if let Some(all) = items
                    .get_mut(&Node::of(attribute.span()), &work)
                    .map_err(resource)?
                {
                    *all = false;
                }
            }
        }
        self.include_nested(&mut items, &mut ranges, &work)?;
        let source = self.prepared.document();
        let query = Scope::new(source, source.snapshot(), &work);
        query
            .admit(self.entry.property(), 1)
            .map_err(|cause| match cause {
                structured_ltv::source::ScopeError::Changed { node } => Error::Foreign {
                    at: node.span().start,
                },
                structured_ltv::source::ScopeError::Resource { cause, .. } => resource(cause),
            })?;
        Ok(Coverage::for_token(
            ISSUER,
            source.snapshot(),
            Node::of(self.prepared.signer().span()),
            self.entry.property(),
            Node::of(
                self.entry
                    .value()
                    .expect("archive requires original token")
                    .span(),
            ),
            Purpose::Archive,
            items.into_owned(),
        ))
    }
    fn include_nested<W: Work>(
        &self,
        items: &mut structured_asn1::memory::OwnedMap<Node, bool, W>,
        ranges: &mut OwnedVec<structured_asn1::Span, W>,
        work: &W,
    ) -> crate::Result<()> {
        let resource = |cause| {
            Error::resource(
                cause,
                "cades.archive.coverage",
                self.entry.property().span().start,
            )
        };
        ranges
            .try_sort_unstable_by(|left, right| {
                work.charge_work(1)?;
                Ok::<_, structured_asn1::memory::MemoryError>(left.start.cmp(&right.start))
            })
            .map_err(|cause| match cause {
                structured_asn1::memory::SortError::Resource(cause)
                | structured_asn1::memory::SortError::Comparison(cause) => resource(cause),
            })?;
        let mut maximum = 0;
        for span in &mut *ranges {
            work.charge_work(1).map_err(resource)?;
            maximum = maximum.max(span.start + span.length);
            span.length = maximum - span.start;
        }
        for counter in self.prepared.counters() {
            let covered = contains(ranges, counter.node(), work).map_err(resource)?;
            items
                .try_insert(counter.node(), covered)
                .map_err(resource)?;
        }
        for token in self.prepared.timestamps() {
            let covered = contains(ranges, token.property(), work).map_err(resource)?;
            if token.owner() != self.entry.owner() {
                items
                    .try_insert(token.property(), covered)
                    .map_err(resource)?;
            }
            if let Some(value) = token.value() {
                items
                    .try_insert(
                        Node::of(value.span()),
                        contains(ranges, Node::of(value.span()), work).map_err(resource)?,
                    )
                    .map_err(resource)?;
            }
        }
        Ok(())
    }

    fn require_archive(&self) -> crate::Result<()> {
        // The common ATSv3 input selects a root SignedData.signerInfos item
        // (EN319122-1 §5.5.3(3)). Preparation retains counter-owned occurrences
        // with an AttributePlacement finding, never as conforming obligations
        // whose mathematical actor this root-input operation could establish.
        if self.entry.purpose() != Purpose::Archive
            || self.entry.preservation_kind().is_some()
            || self.entry.owner() != Node::of(self.prepared.signer().span())
        {
            return Err(Error::Foreign {
                at: self.entry.property().span().start,
            });
        }
        Ok(())
    }
}

fn contains(
    ranges: &[structured_asn1::Span],
    node: Node,
    work: &impl Work,
) -> Result<bool, structured_asn1::memory::MemoryError> {
    let mut from = 0;
    let mut to = ranges.len();
    let span = node.span();
    while from < to {
        work.charge_work(1)?;
        let middle = from + (to - from) / 2;
        if ranges[middle].start <= span.start {
            from = middle + 1;
        } else {
            to = middle;
        }
    }
    if from == 0 {
        return Ok(false);
    }
    let range = ranges[from - 1];
    Ok(range.start + range.length >= span.start + span.length)
}
