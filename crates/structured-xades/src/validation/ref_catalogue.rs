//! Complete digest relations over one original parsed material catalogue.

use super::{ReferenceDigestError, ReferenceKind};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, FormatDigest},
    digest::{self, StreamingDigest},
    material::{self, Retained},
    prepare::{Preparation, Prepared},
    timestamp::{CarriedMaterial, TokenSource},
    xml::{Access, Xml},
};
use core::{cmp::Ordering, ops::Range};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};
use structured_cms::{provider::Resolution, stream::RangesError};

/// How one original reference participated in the complete digest search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSearch {
    /// Every compatible original material source was compared. An empty set is
    /// genuinely empty, not a successful digest match or proof of completeness.
    Compared,
    /// No OCSP digest was written; its identifier remains an obligation.
    IdentifierOnly,
    /// An open-format reference needs its format owner's interpretation.
    OtherFormat,
    /// Method or declared-value processing completed without a usable digest.
    Unavailable(Agreement),
}

/// One original reference and its exact range in the comparison catalogue.
pub struct ReferenceRow<N> {
    property: usize,
    entry: usize,
    node: N,
    search: ReferenceSearch,
    range: Range<usize>,
}

impl<N: Copy> ReferenceRow<N> {
    /// Property ordinal in the SAME preparation's complete reference catalogue.
    #[must_use]
    pub fn property(&self) -> usize {
        self.property
    }
    /// Entry ordinal within that original property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Original `Cert`, `CRLRef`, `OCSPRef` or open-format reference element.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Whether digest search completed or another explicit obligation remains.
    #[must_use]
    pub fn search(&self) -> ReferenceSearch {
        self.search
    }
}

/// Completed digest fact for one original source, not path/authority agreement.
#[derive(Debug, Clone, Copy)]
pub struct MaterialDigest {
    source: material::ArtifactSource,
    embedded: Option<usize>,
    agreement: Agreement,
}

impl MaterialDigest {
    /// Ordinal in the SAME frozen material source catalogue retained by report.
    #[must_use]
    pub fn source(&self) -> Option<usize> {
        match self.source {
            material::ArtifactSource::Xml(index) => Some(index),
            _ => None,
        }
    }
    /// Original pool/ordinal discriminator; token ordinals never address XML
    /// sources. An embedded certificate uses its enclosing response's origin.
    #[must_use]
    pub fn origin(&self) -> material::ArtifactSource {
        self.source
    }
    /// Original certificate ordinal inside this source's OCSP basic response.
    /// None identifies the whole encapsulated certificate/CRL/OCSPResponse.
    #[must_use]
    pub fn embedded_certificate(&self) -> Option<usize> {
        self.embedded
    }
    /// Exact full-output comparison or explicit unavailable capability.
    #[must_use]
    pub fn agreement(&self) -> Agreement {
        self.agreement
    }
}

/// All references against the complete parsed original XML material pool.
/// Equal digests alone do not establish issuer/time/serial, actual actor use,
/// applicability, authentication, required incorporation or a baseline grade.
pub struct ReferenceDigests<'references, 'source, N, D, G> {
    prepared: &'references Preparation<N, D, G>,
    sources: &'source [Retained<N, D, G>],
    tokens: Option<&'source [TokenSource<N, D, G>]>,
    rows: OwnedVec<ReferenceRow<N>>,
    comparisons: OwnedVec<MaterialDigest>,
}

impl<'references, 'source, N, D, G> ReferenceDigests<'references, 'source, N, D, G> {
    /// Same complete original preparation, not a caller-selected property set.
    #[must_use]
    pub fn prepared(&self) -> &'references Preparation<N, D, G> {
        self.prepared
    }
    /// Complete frozen source pool. OCSP entries retain whole `OCSPResponse` DER.
    #[must_use]
    pub fn sources(&self) -> &'source [Retained<N, D, G>] {
        self.sources
    }
    /// Original additional token source pool, when included by the caller.
    /// This alone does not assert whole-counter/token receipt completeness.
    #[must_use]
    pub fn tokens(&self) -> Option<&'source [TokenSource<N, D, G>]> {
        self.tokens
    }
    /// Every original reference once, in original property order.
    #[must_use]
    pub fn rows(&self) -> &[ReferenceRow<N>] {
        &self.rows
    }
    /// All compatible source comparisons for this original reference ordinal.
    /// No first-match truncation; duplicates and completed mismatches survive.
    #[must_use]
    pub fn comparisons(&self, reference: usize) -> Option<&[MaterialDigest]> {
        let row = self.rows.get(reference)?;
        self.comparisons.get(row.range.clone())
    }
}

/// Complete catalogue comparison with unchanged XML/provider/resource causes.
pub type ReferenceCatalogueResult<'references, 'source, X, PE> = binary::BinaryResult<
    ReferenceDigests<
        'references,
        'source,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    X,
    ReferenceDigestError<PE>,
>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    source: usize,
    method: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SourceKey<'source> {
    kind: material::Kind,
    bytes: &'source [u8],
}

#[derive(Clone, Copy)]
struct Candidate<'source> {
    source: material::ArtifactSource,
    embedded: Option<usize>,
    kind: material::Kind,
    bytes: &'source [u8],
}

fn candidates<'source, N: Copy, D: Copy, G: Copy, W: Work>(
    view: &material::View<'source, N, D, G>,
    tokens: Option<&CarriedMaterial<'source, N, D, G>>,
    work: &W,
) -> Result<OwnedVec<Candidate<'source>, W>, MemoryError> {
    let mut values = work.vector();
    values.try_reserve_exact(view.sources().len())?;
    for (source, retained) in view.sources().iter().enumerate() {
        work.charge_work(1)?;
        values.try_push(Candidate {
            source: material::ArtifactSource::Xml(source),
            embedded: None,
            kind: retained.source().kind(),
            bytes: retained.source().bytes(),
        })?;
    }
    for basic in view.basic_responses() {
        work.charge_work(1)?;
        for (embedded, certificate) in basic.response().certificates().iter().enumerate() {
            work.charge_work(1)?;
            values.try_push(Candidate {
                source: material::ArtifactSource::Xml(basic.source_index()),
                embedded: Some(embedded),
                kind: material::Kind::Certificate,
                bytes: certificate.as_bytes(),
            })?;
        }
    }
    if let Some(tokens) = tokens {
        for (token, reading) in tokens.view.readings().iter().enumerate() {
            work.charge_work(1)?;
            for (certificate, value) in reading.token().message().certificates().iter().enumerate()
            {
                work.charge_work(1)?;
                values.try_push(Candidate {
                    source: material::ArtifactSource::TokenCertificate { token, certificate },
                    embedded: None,
                    kind: material::Kind::Certificate,
                    bytes: value.as_bytes(),
                })?;
            }
        }
        for crl in tokens.crls() {
            work.charge_work(1)?;
            values.try_push(Candidate {
                source: material::ArtifactSource::TokenRevocation(crl.origin),
                embedded: None,
                kind: material::Kind::Crl,
                bytes: crl.value.as_bytes(),
            })?;
        }
        for response in tokens.responses() {
            work.charge_work(1)?;
            values.try_push(Candidate {
                source: material::ArtifactSource::TokenRevocation(response.origin),
                embedded: None,
                kind: material::Kind::Ocsp,
                bytes: response.value.as_bytes(),
            })?;
        }
        for basic in tokens.basic_responses() {
            work.charge_work(1)?;
            for (embedded, certificate) in basic.value.certificates().iter().enumerate() {
                work.charge_work(1)?;
                values.try_push(Candidate {
                    source: material::ArtifactSource::TokenRevocation(basic.origin),
                    embedded: Some(embedded),
                    kind: material::Kind::Certificate,
                    bytes: certificate.as_bytes(),
                })?;
            }
        }
    }
    Ok(values)
}

impl HashWork for SourceKey<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        u64::try_from(self.bytes.len())
            .map_err(|_| MemoryError::WorkExceeded)?
            .checked_add(2)
            .ok_or(MemoryError::WorkExceeded)
    }
}

fn source_ids<W: Work>(
    sources: &[Candidate<'_>],
    work: &W,
) -> Result<OwnedVec<usize, W>, MemoryError> {
    let mut index = work.map();
    let mut ids = work.vector();
    ids.try_reserve_exact(sources.len())?;
    for (ordinal, source) in sources.iter().enumerate() {
        work.charge_work(1)?;
        let key = SourceKey {
            kind: source.kind,
            bytes: source.bytes,
        };
        let canonical = if let Some(&existing) = index.get(&key, work)? {
            existing
        } else {
            index.try_insert(key, ordinal)?;
            ordinal
        };
        ids.try_push(canonical)?;
    }
    Ok(ids)
}

impl HashWork for CacheKey {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

pub(super) struct Memo<'provider, 'source, X: Xml, P: StreamingDigest<X>, W: Work> {
    provider: &'provider P,
    identities: OwnedVec<FormatDigest<P::Identity>, W>,
    entries: OwnedMap<CacheKey, Option<Resolution<P::Output>>, W>,
    sources: Option<OwnedVec<usize, W>>,
    candidates: Option<OwnedVec<Candidate<'source>, W>>,
}

#[derive(Clone, Copy)]
pub(super) struct CandidatePools<'view, 'source, N, D, G> {
    pub(super) xml: &'view material::View<'source, N, D, G>,
    pub(super) tokens: Option<&'view CarriedMaterial<'source, N, D, G>>,
}

impl<N: Copy + Eq, D: Copy + Eq, G: Copy + Eq> CandidatePools<'_, '_, N, D, G> {
    pub(super) fn same_source<X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        self,
        location: Location<N, D, G>,
        access: &Access<'_, X, W>,
    ) -> Result<bool, MemoryError> {
        if self.xml.snapshot() != location.snapshot {
            return Ok(false);
        }
        if let Some(tokens) = self.tokens {
            if tokens.view.snapshot() != location.snapshot {
                return Ok(false);
            }
            if !access.equal_id(tokens.view.signature(), location.node)? {
                return Ok(false);
            }
        }
        access.equal_id(self.xml.signature(), location.node)
    }
}

impl<'provider, 'source, X: Xml, P: StreamingDigest<X>, W: Work> Memo<'provider, 'source, X, P, W> {
    pub(super) fn new(provider: &'provider P, work: &W) -> Self {
        Self {
            provider,
            identities: work.vector(),
            entries: work.map(),
            sources: None,
            candidates: None,
        }
    }
    fn row<N: Copy, D: Copy, G: Copy>(
        &mut self,
        identity: FormatDigest<P::Identity>,
        expected: &[u8],
        kind: material::Kind,
        pools: CandidatePools<'_, 'source, N, D, G>,
        comparisons: &mut OwnedVec<MaterialDigest, W>,
        work: &W,
    ) -> Result<(), digest::Error<RangesError, P::Error>> {
        let method = self.method(identity, work)?;
        if self.sources.is_none() {
            let values =
                candidates(pools.xml, pools.tokens, work).map_err(digest::Error::Resource)?;
            self.sources = Some(source_ids(&values, work).map_err(digest::Error::Resource)?);
            self.candidates = Some(values);
        }
        let count = self
            .candidates
            .as_ref()
            .expect("prepared original candidates")
            .len();
        for ordinal in 0..count {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            let candidate = self
                .candidates
                .as_ref()
                .expect("prepared original candidates")[ordinal];
            if candidate.kind != kind {
                continue;
            }
            comparisons
                .try_reserve(1)
                .map_err(digest::Error::Resource)?;
            let canonical = self
                .sources
                .as_ref()
                .expect("prepared original source identities")[ordinal];
            let agreement = self.compare(canonical, candidate.bytes, method, expected, work)?;
            comparisons
                .try_push(MaterialDigest {
                    source: candidate.source,
                    embedded: candidate.embedded,
                    agreement,
                })
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }

    pub(super) fn method(
        &mut self,
        identity: FormatDigest<P::Identity>,
        work: &W,
    ) -> Result<usize, digest::Error<RangesError, P::Error>> {
        for (index, existing) in self.identities.iter().enumerate() {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            if self
                .provider
                .compare(identity.identity(), existing.identity(), work)
                .map_err(digest::Error::Provider)?
                == Ordering::Equal
            {
                return Ok(index);
            }
        }
        let index = self.identities.len();
        self.identities
            .try_push(identity)
            .map_err(digest::Error::Resource)?;
        Ok(index)
    }

    pub(super) fn compare(
        &mut self,
        source: usize,
        bytes: &[u8],
        method: usize,
        expected: &[u8],
        work: &W,
    ) -> Result<Agreement, digest::Error<RangesError, P::Error>> {
        let key = CacheKey { source, method };
        if let Some(output) = self
            .entries
            .get(&key, work)
            .map_err(digest::Error::Resource)?
        {
            let output = output.as_ref().expect("completed prior cache entry");
            return self.matches(&self.identities[method], output, expected, work);
        }
        // Admission precedes backend allocation and consuming the exact source.
        self.entries
            .try_insert(key, None)
            .map_err(digest::Error::Resource)?;
        let identity = &self.identities[method];
        let output =
            digest::compute_resolved::<X, P, _, W>(identity, &mut [bytes], self.provider, work)?;
        let answer = self.matches(identity, &output, expected, work)?;
        *self
            .entries
            .get_mut(&key, work)
            .map_err(digest::Error::Resource)?
            .expect("admitted cache entry") = Some(output);
        Ok(answer)
    }

    fn matches(
        &self,
        identity: &FormatDigest<P::Identity>,
        output: &Resolution<P::Output>,
        expected: &[u8],
        work: &W,
    ) -> Result<Agreement, digest::Error<RangesError, P::Error>> {
        let output = match output {
            Resolution::Supported(output) => output,
            Resolution::Unsupported => return Ok(Agreement::Unsupported),
            Resolution::Malformed => return Ok(Agreement::MalformedMethod),
        };
        work.charge_work(1).map_err(digest::Error::Resource)?;
        self.provider
            .matches_output(identity.identity(), output, expected, work)
            .map(|same| {
                if same {
                    Agreement::Matches
                } else {
                    Agreement::Differs
                }
            })
            .map_err(digest::Error::Provider)
    }
}

/// Compare EVERY prepared reference with EVERY compatible original parsed
/// material view. Hashes are memoized by exact kind/bytes and complete resolved
/// provider identity, never by width, URI spelling or unauthenticated hint.
/// EN319132-1 Annex A.1.1–A.1.4 digest whole certificate/CRL/OCSPResponse DER.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Uses the same method/width/MD5 and streaming kernels as single comparisons.
/// No DER reparse/re-encoding, XML acquisition, normalization or provider change.
/// Each output is finalized once per identity/artifact, then dropped with scoped
/// scratch. Refusal drops the entire partial report; arbitrary provider side
/// effects are not rolled back. Token-carried material is a separate source pool.
pub fn compare_reference_catalogues<
    'references,
    'source,
    X: BinaryXml,
    P: StreamingDigest<X>,
    W: Work,
>(
    xml: &X,
    prepared: &'references Prepared<X>,
    view: &material::View<'source, X::Id, X::Document, X::Generation>,
    provider: &P,
    work: &W,
) -> ReferenceCatalogueResult<'references, 'source, X, P::Error> {
    compare_catalogues(xml, prepared, view, None, provider, work)
}

/// Include original timestamp-carried certificates, complete/delta CRLs and
/// WHOLE OCSP envelopes in the same paid candidate/hash memo. Equal DER copied
/// between XML and tokens shares one digest output while every location stays
/// in the report. Embedded OCSP certificates keep their enclosing token/choice.
/// No source is reparsed or copied. Both pools must belong to the same original
/// generation/selected signature before any allocation/provider work.
///
/// The carried pool's root/counter scope is unchanged; whole-signature level
/// assembly must still require the complete timestamp participant receipt.
pub fn compare_reference_catalogues_with_tokens<
    'references,
    'source,
    X: BinaryXml,
    P: StreamingDigest<X>,
    W: Work,
>(
    xml: &X,
    prepared: &'references Prepared<X>,
    view: &material::View<'source, X::Id, X::Document, X::Generation>,
    tokens: &CarriedMaterial<'source, X::Id, X::Document, X::Generation>,
    provider: &P,
    work: &W,
) -> ReferenceCatalogueResult<'references, 'source, X, P::Error> {
    compare_catalogues(xml, prepared, view, Some(tokens), provider, work)
}

fn compare_catalogues<'references, 'source, X: BinaryXml, P: StreamingDigest<X>, W: Work>(
    xml: &X,
    prepared: &'references Prepared<X>,
    view: &material::View<'source, X::Id, X::Document, X::Generation>,
    tokens: Option<&CarriedMaterial<'source, X::Id, X::Document, X::Generation>>,
    provider: &P,
    work: &W,
) -> ReferenceCatalogueResult<'references, 'source, X, P::Error> {
    let original = prepared.bound().containers();
    let location = Location {
        snapshot: original.snapshot(),
        node: original.signature(),
    };
    let access = Access::new(xml, location.snapshot, work);
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    if !(CandidatePools { xml: view, tokens })
        .same_source(location, &access)
        .map_err(|cause| binary::Error::Callback {
            location,
            cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
        })?
    {
        return Err(binary::Error::Callback {
            location,
            cause: ReferenceDigestError::Foreign,
        });
    }
    let resource = |cause| binary::Error::Callback {
        location,
        cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
    };
    let mut memo = Memo::<X, P, W>::new(provider, work);
    let mut rows = work.vector();
    let mut comparisons = work.vector();
    for (property, references) in prepared.validation_references().iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        rows.try_reserve_exact(references.entries().len())
            .map_err(resource)?;
        for (ordinal, entry) in references.entries().iter().enumerate() {
            work.charge_work(1).map_err(resource)?;
            let start = comparisons.len();
            let kind = match entry.kind() {
                ReferenceKind::Certificate => Some(material::Kind::Certificate),
                ReferenceKind::Crl => Some(material::Kind::Crl),
                ReferenceKind::Ocsp => Some(material::Kind::Ocsp),
                ReferenceKind::Other => None,
            };
            let search = if let Some(kind) = kind {
                if let Some((method, value)) = entry.digest() {
                    let reading = digest::check_with(
                        xml,
                        digest::Reference {
                            snapshot: references.snapshot(),
                            method,
                            value,
                        },
                        provider,
                        work,
                        |identity, expected, work| {
                            memo.row(
                                identity,
                                expected,
                                kind,
                                CandidatePools { xml: view, tokens },
                                &mut comparisons,
                                work,
                            )
                        },
                    )
                    .map_err(|cause| cause.map_callback(ReferenceDigestError::Digest))?;
                    match reading {
                        digest::Checked::Value(()) => ReferenceSearch::Compared,
                        digest::Checked::Answer(answer) => ReferenceSearch::Unavailable(answer),
                    }
                } else {
                    ReferenceSearch::IdentifierOnly
                }
            } else {
                ReferenceSearch::OtherFormat
            };
            rows.try_push(ReferenceRow {
                property,
                entry: ordinal,
                node: entry.node(),
                search,
                range: start..comparisons.len(),
            })
            .map_err(resource)?;
        }
    }
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    Ok(ReferenceDigests {
        prepared,
        sources: view.sources(),
        tokens: tokens.map(|carried| carried.view.sources()),
        rows: rows.into_owned(),
        comparisons: comparisons.into_owned(),
    })
}
