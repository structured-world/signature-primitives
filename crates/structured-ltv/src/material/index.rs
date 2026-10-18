//! Exact original artifact availability, distinct from validation and trust.

use super::{Coverage, CoverageError};
use crate::pki::CheckedPath;
use crate::source::{Location, Query, ScopeError, Snapshot};
use crate::timestamp::{Purpose, Verified};
use core::hash::Hash;
use core::marker::PhantomData;
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};
use structured_pkix::{Certificate, crl::CertificateList, ocsp::BasicResponse};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Certificate,
    Crl,
    Basic,
}

/// Exact identity of one original artifact: its kind and original DER. Two
/// separately parsed copies of the same value have the same identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactKey<'source> {
    pub(super) kind: Kind,
    pub(super) bytes: &'source [u8],
}

impl HashWork for ArtifactKey<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        u64::try_from(self.bytes.len())
            .map_err(|_| MemoryError::WorkExceeded)?
            .checked_add(2)
            .ok_or(MemoryError::WorkExceeded)
    }
}

/// Exact identity of a revocation choice carried in a timestamp token. These
/// ordinals do not address the format's own material pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarriedOrigin {
    /// Ordinal in the frozen timestamp token-source set.
    pub token: usize,
    /// Original choice ordinal inside that token's `SignedData` revocation set.
    pub choice: usize,
}

/// One actual location of an original certificate or status artifact. No path,
/// authorization, freshness, reason coverage or attained level is asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSource {
    /// Ordinal in the format's frozen material sources/values pool.
    Material(usize),
    /// Certificate already parsed in an original timestamp `SignedData`.
    TokenCertificate {
        /// Ordinal in the frozen timestamp source pool.
        token: usize,
        /// Ordinal in that message's parsed X.509 certificate catalogue.
        certificate: usize,
    },
    /// Original revocation choice in the separate timestamp source pool.
    TokenRevocation(CarriedOrigin),
}

/// One original occurrence, with an explicit source-pool discriminator and the
/// format's own placement of the value.
#[derive(Debug, Clone, Copy)]
pub struct Occurrence<N, D, G, P> {
    source: ArtifactSource,
    location: Location<N, D, G>,
    placement: P,
    embedded_certificate: Option<usize>,
}

impl<N: Copy, D: Copy, G: Copy, P: Copy> Occurrence<N, D, G, P> {
    /// A direct occurrence of a certificate, CRL or whole OCSP value.
    #[must_use]
    pub fn new(source: ArtifactSource, location: Location<N, D, G>, placement: P) -> Self {
        Self {
            source,
            location,
            placement,
            embedded_certificate: None,
        }
    }
    /// Actual original source pool and its ordinal, never a shared ambiguous
    /// integer for format material and timestamp token sources.
    #[must_use]
    pub fn source(&self) -> ArtifactSource {
        self.source
    }
    /// Original enclosure of the whole material value.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// Actual container role, not a permission to use it for every actor.
    #[must_use]
    pub fn placement(&self) -> P {
        self.placement
    }
    /// Certificate ordinal inside an OCSP basic response, if the artifact is
    /// embedded there. None means a direct certificate/status value.
    #[must_use]
    pub fn embedded_certificate(&self) -> Option<usize> {
        self.embedded_certificate
    }
}

struct Entry<N, D, G, P> {
    value: Occurrence<N, D, G, P>,
    next: Option<usize>,
}

/// Accounted scoped index of every original occurrence. Keys borrow original
/// DER, not copied/normalized certificate names or unqualified fingerprints.
/// The same artifact in several containers keeps ALL locations, so later
/// archive/actor checks cannot mistake a late or disallowed copy for coverage.
///
/// `P` is the format's placement of an occurrence and `O` an entry of the
/// format's schema-open catalogue; the index stores and returns both unread.
/// Only the holder of issuer `I` builds it from the format's own pools, and it
/// locates material only under coverage and evidence of the same issuer.
pub struct Index<'source, N, D, G, P, O, W: Work, I> {
    snapshot: Snapshot<D, G>,
    signature: N,
    keys: OwnedMap<ArtifactKey<'source>, (usize, usize), W>,
    entries: OwnedVec<Entry<N, D, G, P>, W>,
    open: &'source [O],
    issuer: PhantomData<I>,
}

/// Original source refusal is independent of index capacity/work refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexError<N> {
    /// Source generation or current-operation failure.
    Scope(ScopeError<N>),
    /// A supplied view/index belongs to another original source generation.
    Foreign {
        /// Original selected signature.
        signature: N,
    },
    /// Index hashing/probes/storage or occurrence traversal was not admitted.
    Resource {
        /// Original selected signature.
        signature: N,
        /// Original resource cause.
        cause: MemoryError,
    },
}

/// One original parsed artifact to locate. This is a source reference, not a
/// receipt of authentication, applicability, freshness or actor membership.
#[derive(Debug, Clone, Copy)]
pub enum ArtifactRef<'view, 'source> {
    /// Exact original certificate, including a separately supplied anchor.
    Certificate(&'view Certificate<'source>),
    /// Exact whole complete or delta CRL. A bound pair requires both artifacts.
    Crl(&'view CertificateList<'source>),
    /// Exact basic response; only a retained whole `OCSPResponse` containing it
    /// can satisfy lookup, not an unwrapped basic response injected by a caller.
    Ocsp(&'view BasicResponse<'source>),
}

impl<'source> ArtifactRef<'_, 'source> {
    /// Exact identity of the referenced artifact, borrowing its original DER.
    #[must_use]
    pub fn identity(self) -> ArtifactKey<'source> {
        match self {
            Self::Certificate(value) => ArtifactKey {
                kind: Kind::Certificate,
                bytes: value.as_bytes(),
            },
            Self::Crl(value) => ArtifactKey {
                kind: Kind::Crl,
                bytes: value.as_bytes(),
            },
            Self::Ocsp(value) => ArtifactKey {
                kind: Kind::Basic,
                bytes: value.as_bytes(),
            },
        }
    }
}

/// Exact original artifact availability under one checked archive input.
#[derive(Debug)]
pub enum Archived<N, D, G, P> {
    /// No exact artifact was incorporated in either original source pool.
    Missing,
    /// Exact copies exist, but none is covered by this particular archive input.
    /// A later property or the archive token's own material cannot repair it.
    Uncovered,
    /// At least one exact incorporated copy is mathematically covered.
    Present(Occurrence<N, D, G, P>),
}

/// Exact position of a certificate in a supplied, actually checked path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCertificate {
    /// Explicitly supplied trust-anchor certificate, if one exists. This is
    /// material availability only, never a requirement to revoke an anchor.
    Anchor,
    /// Issuer-to-subject ordinal in the checked non-anchor member catalogue.
    Member(usize),
}

/// One checked-path certificate's mathematical availability before an archive.
#[derive(Debug)]
pub struct ArchivedCertificate<N, D, G, P> {
    /// Original role; no caller-supplied certificate count is used.
    pub role: PathCertificate,
    /// Exact copies are searched using the same archive coverage receipt.
    pub availability: Archived<N, D, G, P>,
}

/// Complete certificate census for one actual checked path and archive input.
/// It deliberately retains its path: ordinals cannot be relabelled as another
/// actor after this check. Status artifacts and actor association are separate.
pub struct PathCertificates<'path, 'document, N, D, G, P> {
    path: &'path CheckedPath<'document>,
    archive: Location<N, D, G>,
    entries: OwnedVec<ArchivedCertificate<N, D, G, P>>,
    all_covered: bool,
}

impl<'path, 'document, N: Copy, D: Copy, G: Copy, P>
    PathCertificates<'path, 'document, N, D, G, P>
{
    /// Same actual common-validator path, not an independent artifact list.
    #[must_use]
    pub fn path(&self) -> &'path CheckedPath<'document> {
        self.path
    }
    /// Original archive token whose actual input coverage was used.
    #[must_use]
    pub fn archive(&self) -> Location<N, D, G> {
        self.archive
    }
    /// Every existing anchor/member certificate, including missing late copies.
    #[must_use]
    pub fn entries(&self) -> &[ArchivedCertificate<N, D, G, P>] {
        &self.entries
    }
    /// Whether every certificate in this path has an exact covered copy.
    /// This alone proves neither status completeness nor any baseline level.
    #[must_use]
    pub fn all_certificates_covered(&self) -> bool {
        self.all_covered
    }
}

/// Original source/resource failure, separately from missing archive material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveError<N> {
    /// Exact artifact hashing, lookup or source traversal refused.
    Index(IndexError<N>),
    /// The mathematical input coverage/source binding could not be established.
    Coverage(CoverageError<N>),
    /// The supplied successful token covers a different kind of input.
    NotArchive {
        /// Actual original timestamp property.
        property: N,
    },
}

impl<'source, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, P: Copy, O, W: Work, I>
    Index<'source, N, D, G, P, O, W, I>
{
    /// An empty index for this signature in the query's source generation.
    ///
    /// `open` is the format's schema-open material catalogue, retained only so
    /// that format checks find it beside the index. Requiring the issuer value
    /// keeps a caller of the format from building an index of its own.
    pub fn new<Q: Query<Id = N, Document = D, Generation = G, Work = W>>(
        _issuer: I,
        signature: N,
        open: &'source [O],
        query: &Q,
    ) -> Result<Self, IndexError<N>> {
        query.admit(signature, 1).map_err(IndexError::Scope)?;
        let execution = query.execution();
        Ok(Self {
            snapshot: query.snapshot(),
            signature,
            keys: execution.map(),
            entries: execution.vector(),
            open,
            issuer: PhantomData,
        })
    }

    /// Records one occurrence of an exact original artifact. For an OCSP value
    /// every certificate embedded in its basic response is recorded too, with
    /// the same location and placement. Hashing, probes and storage are
    /// admitted first; a refusal leaves the index for the caller to drop. The
    /// builder pays its own traversal of the format's pools with [`Self::admit`].
    pub fn insert<Q: Query<Id = N, Document = D, Generation = G, Work = W>>(
        &mut self,
        artifact: ArtifactRef<'_, 'source>,
        occurrence: Occurrence<N, D, G, P>,
        query: &Q,
    ) -> Result<(), IndexError<N>> {
        // Coverage lookups compare only the occurrence's node, so its source
        // generation must already be this index's.
        if occurrence.location.snapshot != self.snapshot || query.snapshot() != self.snapshot {
            return Err(IndexError::Foreign {
                signature: self.signature,
            });
        }
        self.insert_key(artifact.identity(), occurrence, query)?;
        if let ArtifactRef::Ocsp(response) = artifact {
            for certificate in 0..response.certificates().len() {
                self.admit(query)?;
                self.insert_key(
                    ArtifactKey {
                        kind: Kind::Certificate,
                        bytes: response.certificates()[certificate].as_bytes(),
                    },
                    Occurrence {
                        embedded_certificate: Some(certificate),
                        ..occurrence
                    },
                    query,
                )?;
            }
        }
        Ok(())
    }

    /// The format's schema-open catalogue, as supplied.
    #[must_use]
    pub fn open(&self) -> &'source [O] {
        self.open
    }

    /// Original selected signature of this index.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }

    /// Source generation of every occurrence.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }

    /// Finds all copies of this exact original certificate, including copies
    /// inside OCSP. A match is availability only, never authentication/trust.
    pub fn certificate<'view, 'query, Q: Query<Id = N, Document = D, Generation = G>>(
        &'view self,
        value: &Certificate<'_>,
        query: &'query Q,
    ) -> Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> {
        self.find(Kind::Certificate, value.as_bytes(), query)
    }
    /// Finds all whole CRL copies. An authenticated delta still needs its
    /// authenticated/bound complete source; finding either alone proves no pair.
    pub fn crl<'view, 'query, Q: Query<Id = N, Document = D, Generation = G>>(
        &'view self,
        value: &CertificateList<'_>,
        query: &'query Q,
    ) -> Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> {
        self.find(Kind::Crl, value.as_bytes(), query)
    }
    /// Finds the exact basic response only in retained whole OCSP envelopes.
    /// Good-looking status or a successful wire code does not mint evidence.
    pub fn ocsp<'view, 'query, Q: Query<Id = N, Document = D, Generation = G>>(
        &'view self,
        value: &BasicResponse<'_>,
        query: &'query Q,
    ) -> Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> {
        self.find(Kind::Basic, value.as_bytes(), query)
    }

    /// Finds all copies of this exact artifact, in source catalogue order.
    pub fn artifact<'view, 'query, Q: Query<Id = N, Document = D, Generation = G>>(
        &'view self,
        artifact: ArtifactRef<'_, '_>,
        query: &'query Q,
    ) -> Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> {
        let key = artifact.identity();
        self.find(key.kind, key.bytes, query)
    }

    /// Requires that this index was built for `signature`.
    pub fn require_signature<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        signature: N,
        query: &Q,
    ) -> Result<(), IndexError<N>> {
        self.admit(query)?;
        let same =
            query
                .equal(self.signature, signature)
                .map_err(|cause| IndexError::Resource {
                    signature: self.signature,
                    cause,
                })?;
        if !same {
            return Err(IndexError::Foreign { signature });
        }
        Ok(())
    }

    /// Locates a whole original artifact in this exact checked archive input.
    ///
    /// EN319132-1 §6.3(aa)/§5.5.2.2 requires the necessary material to have
    /// been incorporated before generating each archive timestamp. This uses
    /// the same selection the format used for actual timestamp input, so merely
    /// finding a late or self-carried copy cannot count as covered. All copies
    /// remain available; an early uncovered duplicate does not hide a covered
    /// one. This proves mathematical availability only. The caller must derive
    /// required artifacts from actual actor/path/status checks and must
    /// authenticate the TSA separately before claiming a baseline level.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn archived<Q: Query<Id = N, Document = D, Generation = G>, C: Work>(
        &self,
        artifact: ArtifactRef<'_, '_>,
        coverage: &Coverage<N, D, G, C, I>,
        evidence: &Verified<N, D, G, I>,
        query: &Q,
    ) -> Result<Archived<N, D, G, P>, ArchiveError<N>>
    where
        N: HashWork,
    {
        if evidence.purpose() != Purpose::Archive {
            return Err(ArchiveError::NotArchive {
                property: evidence.property(),
            });
        }
        // Validate even empty/missing catalogues before deriving an absence.
        if evidence.token().snapshot != self.snapshot {
            return Err(ArchiveError::Index(IndexError::Foreign {
                signature: self.signature,
            }));
        }
        self.require_signature(evidence.signature(), query)
            .map_err(ArchiveError::Index)?;
        coverage
            .require_evidence(evidence, evidence.property(), query)
            .map_err(ArchiveError::Coverage)?;
        let key = artifact.identity();
        let copies = self
            .find(key.kind, key.bytes, query)
            .map_err(ArchiveError::Index)?;
        let mut found = false;
        for copy in copies {
            let copy = copy.map_err(ArchiveError::Index)?;
            found = true;
            // The immutable coverage/evidence pair was bound once above;
            // each occurrence still checks the current source and lookup.
            if coverage
                .selects(copy.location.node, query)
                .map_err(ArchiveError::Coverage)?
            {
                return Ok(Archived::Present(copy));
            }
        }
        Ok(if found {
            Archived::Uncovered
        } else {
            Archived::Missing
        })
    }

    /// Derives certificate requirements from the actual common-validator path,
    /// including an existing anchor certificate, then checks each exact artifact
    /// against this archive's mathematical input. Missing/late copies remain
    /// facts; resource/source failure returns no successful partial census.
    ///
    /// EN319132-1 V1.3.1 §§5.4.2/5.5.2.2/6.3(aa) require the material of the
    /// actual actors before each archive. This certificate component does not
    /// assert that status, credential, countersigner or previous-TSA processing
    /// completed. The caller must supply their separately bound paths.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn archived_path<'path, 'document, Q, C: Work>(
        &self,
        path: &'path CheckedPath<'document>,
        coverage: &Coverage<N, D, G, C, I>,
        evidence: &Verified<N, D, G, I>,
        query: &Q,
    ) -> Result<PathCertificates<'path, 'document, N, D, G, P>, ArchiveError<N>>
    where
        N: HashWork,
        Q: Query<Id = N, Document = D, Generation = G>,
    {
        query
            .admit(self.signature, 1)
            .map_err(|cause| ArchiveError::Index(IndexError::Scope(cause)))?;
        let mut entries = query.execution().vector();
        let mut all_covered = true;
        let mut record = |certificate, role| {
            let availability = self.archived(
                ArtifactRef::Certificate(certificate),
                coverage,
                evidence,
                query,
            )?;
            if !matches!(availability, Archived::Present(_)) {
                all_covered = false;
            }
            entries
                .try_push(ArchivedCertificate { role, availability })
                .map_err(|cause| {
                    ArchiveError::Index(IndexError::Resource {
                        signature: self.signature,
                        cause,
                    })
                })
        };
        if let Some(certificate) = path.anchor().certificate() {
            record(certificate, PathCertificate::Anchor)?;
        }
        for (ordinal, member) in path.members().iter().enumerate() {
            self.admit(query).map_err(ArchiveError::Index)?;
            record(member.certificate(), PathCertificate::Member(ordinal))?;
        }
        Ok(PathCertificates {
            path,
            archive: evidence.token(),
            entries: entries.into_owned(),
            all_covered,
        })
    }

    /// Admits one traversal step over this index's source generation.
    pub fn admit<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        query: &Q,
    ) -> Result<(), IndexError<N>> {
        if self.snapshot != query.snapshot() {
            return Err(IndexError::Foreign {
                signature: self.signature,
            });
        }
        query.admit(self.signature, 2).map_err(IndexError::Scope)
    }

    fn insert_key<Q: Query<Id = N, Document = D, Generation = G, Work = W>>(
        &mut self,
        key: ArtifactKey<'source>,
        value: Occurrence<N, D, G, P>,
        query: &Q,
    ) -> Result<(), IndexError<N>> {
        query.admit(self.signature, 1).map_err(IndexError::Scope)?;
        let resource = |cause| IndexError::Resource {
            signature: self.signature,
            cause,
        };
        let previous = self
            .keys
            .get(&key, query.execution())
            .map(Option::<&(usize, usize)>::copied)
            .map_err(resource)?;
        let next = self.entries.len();
        self.entries
            .try_push(Entry { value, next: None })
            .map_err(resource)?;
        let head = previous.map_or(next, |(head, _)| head);
        self.keys.try_insert(key, (head, next)).map_err(resource)?;
        if let Some((_, tail)) = previous {
            self.entries[tail].next = Some(next);
        }
        Ok(())
    }

    fn find<'view, 'query, Q: Query<Id = N, Document = D, Generation = G>>(
        &'view self,
        kind: Kind,
        bytes: &[u8],
        query: &'query Q,
    ) -> Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> {
        self.admit(query)?;
        query.admit(self.signature, 1).map_err(IndexError::Scope)?;
        let next = self
            .keys
            .get(&ArtifactKey { kind, bytes }, query.execution())
            .map(|value| value.map(|&(head, _)| head))
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })?;
        Ok(Occurrences {
            index: self,
            query,
            next,
        })
    }
}

/// Every copy of one artifact, or the refusal to look it up.
pub type Lookup<'view, 'query, 'source, N, D, G, P, O, W, Q, I> =
    Result<Occurrences<'view, 'query, 'source, N, D, G, P, O, W, Q, I>, IndexError<N>>;

/// Source-catalogue-order traversal of every copy; current Work pays metadata
/// access even when index storage belongs to an earlier execution. The first
/// source/resource refusal is returned once and fuses the iterator.
pub struct Occurrences<'view, 'query, 'source, N, D, G, P, O, W: Work, Q, I> {
    index: &'view Index<'source, N, D, G, P, O, W, I>,
    query: &'query Q,
    next: Option<usize>,
}

impl<N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, P: Copy, O, W: Work, Q, I> Iterator
    for Occurrences<'_, '_, '_, N, D, G, P, O, W, Q, I>
where
    Q: Query<Id = N, Document = D, Generation = G>,
{
    type Item = Result<Occurrence<N, D, G, P>, IndexError<N>>;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next.take()?;
        if let Err(error) = self.index.admit(self.query) {
            return Some(Err(error));
        }
        let entry = &self.index.entries[next];
        self.next = entry.next;
        Some(Ok(entry.value))
    }
}

impl<N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, P: Copy, O, W: Work, Q, I> core::iter::FusedIterator
    for Occurrences<'_, '_, '_, N, D, G, P, O, W, Q, I>
where
    Q: Query<Id = N, Document = D, Generation = G>,
{
}
