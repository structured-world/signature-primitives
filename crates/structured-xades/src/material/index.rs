//! Exact original artifact availability, distinct from validation and trust.

use super::{Placement, Value, View};
use crate::binary::Location;
use crate::timestamp::{
    CarriedMaterial, CarriedOrigin, CoverageError, ElementCoverage, Role, Verified,
};
use crate::xml::{Access, AccessError, Snapshot, Xml};
use core::hash::Hash;
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};
use structured_pkix::{Certificate, crl::CertificateList, ocsp::BasicResponse};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Certificate,
    Crl,
    Basic,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Key<'source> {
    pub(super) kind: Kind,
    pub(super) bytes: &'source [u8],
}

impl HashWork for Key<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        u64::try_from(self.bytes.len())
            .map_err(|_| MemoryError::WorkExceeded)?
            .checked_add(2)
            .ok_or(MemoryError::WorkExceeded)
    }
}

/// One actual location of an original certificate or status artifact. No path,
/// authorization, freshness, reason coverage or attained level is asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSource {
    /// Ordinal in the frozen XML material sources/values pool.
    Xml(usize),
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

/// One original occurrence, with an explicit source-pool discriminator.
#[derive(Debug, Clone, Copy)]
pub struct Occurrence<N, D, G> {
    source: ArtifactSource,
    location: Location<N, D, G>,
    placement: Placement<N>,
    embedded_certificate: Option<usize>,
}

impl<N: Copy, D: Copy, G: Copy> Occurrence<N, D, G> {
    /// Actual original source pool and its ordinal, never a shared ambiguous
    /// integer for XML material and timestamp token sources.
    #[must_use]
    pub fn source(&self) -> ArtifactSource {
        self.source
    }
    /// Original XML enclosure of the whole material value.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// Actual container role, not a permission to use it for every actor.
    #[must_use]
    pub fn placement(&self) -> Placement<N> {
        self.placement
    }
    /// Certificate ordinal inside an OCSP basic response, if the artifact is
    /// embedded there. None means a direct certificate/status value.
    #[must_use]
    pub fn embedded_certificate(&self) -> Option<usize> {
        self.embedded_certificate
    }
}

struct Entry<N, D, G> {
    value: Occurrence<N, D, G>,
    next: Option<usize>,
}

/// Accounted scoped index of every original occurrence. Keys borrow original
/// DER, not copied/normalized certificate names or unqualified fingerprints.
/// The same artifact in several containers keeps ALL locations, so later
/// archive/actor checks cannot mistake a late or disallowed copy for coverage.
pub struct Index<'source, N, D, G, W: Work> {
    snapshot: Snapshot<D, G>,
    signature: N,
    keys: OwnedMap<Key<'source>, (usize, usize), W>,
    entries: OwnedVec<Entry<N, D, G>, W>,
    // Original schema-open catalogue, not an assertion of its format or use.
    // Borrow the already retained immutable pool; no copied catalogue/charge.
    pub(super) opaque: &'source [super::Opaque<N, D, G>],
}

/// Original source refusal is independent of index capacity/work refusal.
#[derive(Debug)]
pub enum IndexError<E, N> {
    /// XML source/generation/current-operation failure.
    Access(AccessError<E, N>),
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
    pub(super) fn identity(self) -> Key<'source> {
        match self {
            Self::Certificate(value) => Key {
                kind: Kind::Certificate,
                bytes: value.as_bytes(),
            },
            Self::Crl(value) => Key {
                kind: Kind::Crl,
                bytes: value.as_bytes(),
            },
            Self::Ocsp(value) => Key {
                kind: Kind::Basic,
                bytes: value.as_bytes(),
            },
        }
    }
}

/// Exact original artifact availability under one checked archive input.
#[derive(Debug)]
pub enum Archived<N, D, G> {
    /// No exact artifact was incorporated in either original source pool.
    Missing,
    /// Exact copies exist, but none is covered by this particular archive input.
    /// A later property or the archive token's own material cannot repair it.
    Uncovered,
    /// At least one exact incorporated copy is mathematically covered.
    Present(Occurrence<N, D, G>),
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
pub struct ArchivedCertificate<N, D, G> {
    /// Original role; no caller-supplied certificate count is used.
    pub role: PathCertificate,
    /// Exact copies are searched using the same archive coverage receipt.
    pub availability: Archived<N, D, G>,
}

/// Complete certificate census for one actual checked path and archive input.
/// It deliberately retains its path: ordinals cannot be relabelled as another
/// actor after this check. Status artifacts and actor association are separate.
pub struct PathCertificates<'path, 'document, N, D, G> {
    path: &'path crate::pki::CheckedPath<'document>,
    archive: Location<N, D, G>,
    entries: OwnedVec<ArchivedCertificate<N, D, G>>,
    all_covered: bool,
}

impl<'path, 'document, N: Copy, D: Copy, G: Copy> PathCertificates<'path, 'document, N, D, G> {
    /// Same actual common-validator path, not an independent artifact list.
    #[must_use]
    pub fn path(&self) -> &'path crate::pki::CheckedPath<'document> {
        self.path
    }
    /// Original archive token whose actual input coverage was used.
    #[must_use]
    pub fn archive(&self) -> Location<N, D, G> {
        self.archive
    }
    /// Every existing anchor/member certificate, including missing late copies.
    #[must_use]
    pub fn entries(&self) -> &[ArchivedCertificate<N, D, G>] {
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
#[derive(Debug)]
pub enum ArchiveError<E, N> {
    /// Exact artifact hashing, lookup or source traversal refused.
    Index(IndexError<E, N>),
    /// The mathematical input coverage/source binding could not be established.
    Coverage(CoverageError<E, N>),
    /// The supplied successful token covers a different timestamp role.
    NotArchive {
        /// Actual original timestamp property.
        property: N,
    },
}

type IndexResult<T, X> = Result<T, IndexError<<X as Xml>::Error, <X as Xml>::Id>>;

impl<'source, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, W: Work> Index<'source, N, D, G, W> {
    /// Builds from the already parsed/frozen set without decoding values again.
    /// All source and embedded certificate metadata, exact hashing/equality,
    /// hidden table probes, entries and duplicate links are funded before work.
    /// Refusal drops the complete partial index, preserving original sources.
    pub fn build<X: Xml<Id = N, Document = D, Generation = G>>(
        view: &View<'source, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<Self, X> {
        let signature = view.signature;
        if view.snapshot != access.snapshot() {
            return Err(IndexError::Foreign { signature });
        }
        let (keys, entries) = access
            .query(signature, |_, _, work| Ok((work.map(), work.vector())))
            .map_err(IndexError::Access)?;
        let mut index = Self {
            snapshot: view.snapshot,
            signature,
            keys,
            entries,
            opaque: view.opaque(),
        };
        let mut next_basic = 0;
        for ordinal in 0..view.values.len() {
            index.admit(access)?;
            let value = &view.values[ordinal];
            let placement = view.sources[ordinal].placement();
            let (kind, bytes) = match &value.value {
                Value::Certificate(value) => (Kind::Certificate, value.as_bytes()),
                Value::Crl(value) => (Kind::Crl, value.as_bytes()),
                Value::Ocsp(_) => {
                    if let Some(basic) = view.basic.get(next_basic)
                        && basic.source_index() == ordinal
                    {
                        index.insert_basic(basic, placement, access)?;
                        next_basic += 1;
                    }
                    continue;
                }
            };
            index.insert(
                Key { kind, bytes },
                Occurrence {
                    source: ArtifactSource::Xml(ordinal),
                    location: value.location,
                    placement,
                    embedded_certificate: None,
                },
                access,
            )?;
        }
        index.admit(access)?;
        Ok(index)
    }

    /// Builds one exact-artifact index from both already parsed original
    /// source sets. XML-pool occurrences stay first; token-pool
    /// occurrences retain their explicit pool/ordinal and actual placement.
    /// All growth belongs to this current execution. Any late refusal drops
    /// the complete partial index instead of returning a mutable prefix.
    pub fn build_with_tokens<X: Xml<Id = N, Document = D, Generation = G>>(
        view: &View<'source, N, D, G>,
        material: &CarriedMaterial<'source, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<Self, X> {
        if material.view.snapshot() != view.snapshot || material.view.signature() != view.signature
        {
            return Err(IndexError::Foreign {
                signature: view.signature,
            });
        }
        Self::build(view, access)?.include_token_material(material, access)
    }

    fn include_token_material<X: Xml<Id = N, Document = D, Generation = G>>(
        mut self,
        material: &CarriedMaterial<'source, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<Self, X> {
        self.admit(access)?;
        if material.view.snapshot() != self.snapshot || material.view.signature() != self.signature
        {
            return Err(IndexError::Foreign {
                signature: self.signature,
            });
        }
        for token in 0..material.view.readings().len() {
            self.admit(access)?;
            let source = &material.view.sources()[token];
            let certificates = material.view.readings()[token]
                .token()
                .message()
                .certificates();
            let mut certificate = 0;
            while certificate < certificates.len() {
                self.admit(access)?;
                self.insert(
                    Key {
                        kind: Kind::Certificate,
                        bytes: certificates[certificate].as_bytes(),
                    },
                    Occurrence {
                        source: ArtifactSource::TokenCertificate { token, certificate },
                        location: source.location(),
                        placement: Placement::TimestampToken {
                            property: source.property(),
                            token: source.location().node,
                            role: source.role(),
                        },
                        embedded_certificate: None,
                    },
                    access,
                )?;
                certificate += 1;
            }
        }
        for ordinal in 0..material.crls().len() {
            self.admit(access)?;
            let value = &material.crls()[ordinal];
            let occurrence = Self::carried_occurrence(material, value.origin);
            self.insert(
                Key {
                    kind: Kind::Crl,
                    bytes: value.value.as_bytes(),
                },
                occurrence,
                access,
            )?;
        }
        for ordinal in 0..material.basic_responses().len() {
            self.admit(access)?;
            let value = &material.basic_responses()[ordinal];
            let occurrence = Self::carried_occurrence(material, value.origin);
            self.insert_response(&value.value, occurrence, access)?;
        }
        self.admit(access)?;
        Ok(self)
    }

    fn carried_occurrence(
        material: &CarriedMaterial<'source, N, D, G>,
        origin: CarriedOrigin,
    ) -> Occurrence<N, D, G> {
        let source = &material.view.sources()[origin.token];
        Occurrence {
            source: ArtifactSource::TokenRevocation(origin),
            location: source.location(),
            placement: Placement::TimestampToken {
                property: source.property(),
                token: source.location().node,
                role: source.role(),
            },
            embedded_certificate: None,
        }
    }

    /// Finds all copies of this exact original certificate, including copies
    /// inside OCSP. A match is availability only, never authentication/trust.
    pub fn certificate<'view, 'xml, X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &'view self,
        value: &Certificate<'_>,
        access: &'view Access<'xml, X, Q>,
    ) -> IndexResult<Occurrences<'view, 'xml, 'source, X, W, Q>, X> {
        self.find(Kind::Certificate, value.as_bytes(), access)
    }
    /// Finds all whole CRL copies. An authenticated delta still needs its
    /// authenticated/bound complete source; finding either alone proves no pair.
    pub fn crl<'view, 'xml, X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &'view self,
        value: &CertificateList<'_>,
        access: &'view Access<'xml, X, Q>,
    ) -> IndexResult<Occurrences<'view, 'xml, 'source, X, W, Q>, X> {
        self.find(Kind::Crl, value.as_bytes(), access)
    }
    /// Finds the exact basic response only in retained whole OCSP envelopes.
    /// Good-looking status or a successful wire code does not mint evidence.
    pub fn ocsp<'view, 'xml, X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &'view self,
        value: &BasicResponse<'_>,
        access: &'view Access<'xml, X, Q>,
    ) -> IndexResult<Occurrences<'view, 'xml, 'source, X, W, Q>, X> {
        self.find(Kind::Basic, value.as_bytes(), access)
    }

    pub(super) fn artifact<'view, 'xml, X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &'view self,
        artifact: ArtifactRef<'_, '_>,
        access: &'view Access<'xml, X, Q>,
    ) -> IndexResult<Occurrences<'view, 'xml, 'source, X, W, Q>, X> {
        let key = artifact.identity();
        self.find(key.kind, key.bytes, access)
    }

    pub(super) fn require_signature<X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &self,
        signature: N,
        access: &Access<'_, X, Q>,
    ) -> IndexResult<(), X> {
        self.admit(access)?;
        let same = access
            .equal_id(self.signature, signature)
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
    /// the same selection kernel as actual timestamp replay, so merely finding
    /// a late or self-carried copy cannot count as covered. All copies remain
    /// available; an early uncovered duplicate does not hide a covered one.
    /// This proves mathematical availability only. The root operation must
    /// derive required artifacts from actual actor/path/status checks and must
    /// authenticate the TSA separately before claiming a baseline level.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn archived<X: Xml<Id = N, Document = D, Generation = G>, Q: Work, C: Work>(
        &self,
        artifact: ArtifactRef<'_, '_>,
        coverage: &ElementCoverage<N, D, G, C>,
        evidence: &Verified<N, D, G>,
        access: &Access<'_, X, Q>,
    ) -> Result<Archived<N, D, G>, ArchiveError<X::Error, N>>
    where
        N: HashWork,
    {
        if evidence.role() != Role::Archive {
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
        self.require_signature(evidence.signature(), access)
            .map_err(ArchiveError::Index)?;
        coverage
            .require_evidence(evidence, evidence.property(), access)
            .map_err(ArchiveError::Coverage)?;
        let key = artifact.identity();
        let copies = self
            .find(key.kind, key.bytes, access)
            .map_err(ArchiveError::Index)?;
        let mut found = false;
        for copy in copies {
            let copy = copy.map_err(ArchiveError::Index)?;
            found = true;
            // The immutable coverage/evidence pair was bound once above;
            // each occurrence still checks the current XML view and lookup.
            if coverage
                .selects(copy.location.node, access)
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
    /// completed. The root operation must supply their separately bound paths.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn archived_path<
        'path,
        'document,
        X: Xml<Id = N, Document = D, Generation = G>,
        Q: Work,
        C: Work,
    >(
        &self,
        path: &'path crate::pki::CheckedPath<'document>,
        coverage: &ElementCoverage<N, D, G, C>,
        evidence: &Verified<N, D, G>,
        access: &Access<'_, X, Q>,
    ) -> Result<PathCertificates<'path, 'document, N, D, G>, ArchiveError<X::Error, N>>
    where
        N: HashWork,
    {
        let mut entries = access
            .query(self.signature, |_, _, work| Ok(work.vector()))
            .map_err(|cause| ArchiveError::Index(IndexError::Access(cause)))?;
        let mut all_covered = true;
        let mut record = |certificate, role| {
            let availability = self.archived(
                ArtifactRef::Certificate(certificate),
                coverage,
                evidence,
                access,
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
            self.admit(access).map_err(ArchiveError::Index)?;
            record(member.certificate(), PathCertificate::Member(ordinal))?;
        }
        Ok(PathCertificates {
            path,
            archive: evidence.token(),
            entries: entries.into_owned(),
            all_covered,
        })
    }

    fn admit<X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &self,
        access: &Access<'_, X, Q>,
    ) -> IndexResult<(), X> {
        if self.snapshot != access.snapshot() {
            return Err(IndexError::Foreign {
                signature: self.signature,
            });
        }
        access
            .query(self.signature, |_, _, work| Ok(work.charge_work(1)))
            .map_err(IndexError::Access)?
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })
    }

    fn insert<X: Xml<Id = N, Document = D, Generation = G>>(
        &mut self,
        key: Key<'source>,
        value: Occurrence<N, D, G>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<(), X> {
        let previous = access
            .query(self.signature, |_, _, work| {
                Ok(self
                    .keys
                    .get(&key, work)
                    .map(Option::<&(usize, usize)>::copied))
            })
            .map_err(IndexError::Access)?
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })?;
        let next = self.entries.len();
        self.entries
            .try_push(Entry { value, next: None })
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })?;
        let head = previous.map_or(next, |(head, _)| head);
        self.keys
            .try_insert(key, (head, next))
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })?;
        if let Some((_, tail)) = previous {
            self.entries[tail].next = Some(next);
        }
        Ok(())
    }

    fn insert_basic<X: Xml<Id = N, Document = D, Generation = G>>(
        &mut self,
        basic: &super::Basic<'source, N, D, G>,
        placement: Placement<N>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<(), X> {
        self.insert_response(
            basic.response(),
            Occurrence {
                source: ArtifactSource::Xml(basic.source_index()),
                location: basic.location(),
                placement,
                embedded_certificate: None,
            },
            access,
        )
    }

    fn insert_response<X: Xml<Id = N, Document = D, Generation = G>>(
        &mut self,
        response: &BasicResponse<'source>,
        occurrence: Occurrence<N, D, G>,
        access: &Access<'_, X, W>,
    ) -> IndexResult<(), X> {
        self.insert(
            Key {
                kind: Kind::Basic,
                bytes: response.as_bytes(),
            },
            occurrence,
            access,
        )?;
        for certificate in 0..response.certificates().len() {
            self.admit(access)?;
            self.insert(
                Key {
                    kind: Kind::Certificate,
                    bytes: response.certificates()[certificate].as_bytes(),
                },
                Occurrence {
                    embedded_certificate: Some(certificate),
                    ..occurrence
                },
                access,
            )?;
        }
        Ok(())
    }

    fn find<'view, 'xml, X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &'view self,
        kind: Kind,
        bytes: &[u8],
        access: &'view Access<'xml, X, Q>,
    ) -> IndexResult<Occurrences<'view, 'xml, 'source, X, W, Q>, X> {
        self.admit(access)?;
        let next = access
            .query(self.signature, |_, _, work| {
                Ok(self
                    .keys
                    .get(&Key { kind, bytes }, work)
                    .map(|value| value.map(|&(head, _)| head)))
            })
            .map_err(IndexError::Access)?
            .map_err(|cause| IndexError::Resource {
                signature: self.signature,
                cause,
            })?;
        Ok(Occurrences {
            index: self,
            access,
            next,
        })
    }
}

/// Source-catalogue-order traversal of every copy; current Work pays metadata
/// access even when index storage belongs to an earlier execution. The first
/// source/resource refusal is returned once and fuses the iterator.
pub struct Occurrences<'view, 'xml, 'source, X: Xml, W: Work, Q: Work> {
    index: &'view Index<'source, X::Id, X::Document, X::Generation, W>,
    access: &'view Access<'xml, X, Q>,
    next: Option<usize>,
}

impl<X: Xml, W: Work, Q: Work> Iterator for Occurrences<'_, '_, '_, X, W, Q> {
    type Item = IndexResult<Occurrence<X::Id, X::Document, X::Generation>, X>;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next.take()?;
        if let Err(error) = self.index.admit(self.access) {
            return Some(Err(error));
        }
        let entry = &self.index.entries[next];
        self.next = entry.next;
        Some(Ok(entry.value))
    }
}
impl<X: Xml, W: Work, Q: Work> core::iter::FusedIterator for Occurrences<'_, '_, '_, X, W, Q> {}
