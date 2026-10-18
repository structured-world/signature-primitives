//! Annex A root-path certificate references, separate from material placement.

use super::{ReferenceDigestError, ReferenceSearch, ref_catalogue::Memo};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, CheckedPathCertificate, DigestProvider},
    digest,
    material::PathCertificate,
    pki::CheckedPath,
    prepare::{Preparation, Prepared},
    unsigned,
    xml::{Access, Xml},
};
use core::ops::Range;
use structured_asn1::digest::Digest;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// One original `CompleteCertificateRefsV2` entry and its root-path comparisons.
pub struct RootReferenceRow<N> {
    property: usize,
    entry: usize,
    node: N,
    search: ReferenceSearch,
    range: Range<usize>,
}
impl<N: Copy> RootReferenceRow<N> {
    /// Original property ordinal in the same preparation.
    #[must_use]
    pub fn property(&self) -> usize {
        self.property
    }
    /// Original entry ordinal in that property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Original Cert enclosure.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Exact method/declared-digest outcome, not an invented mismatch.
    #[must_use]
    pub fn search(&self) -> ReferenceSearch {
        self.search
    }
}

/// Root certificate rules of Annex A.1.1(1–2), bound to the actual selected
/// path. Optional TSA/status-authority references, exclusive credential CAs,
/// incorporated presence and authentication/status remain separate checks.
pub struct RootPathReferences<'prepared, 'path, 'document, N, D, G> {
    prepared: &'prepared Preparation<N, D, G>,
    path: &'path CheckedPath<'document>,
    rows: OwnedVec<RootReferenceRow<N>>,
    comparisons: OwnedVec<Agreement>,
    root_rules: bool,
}
impl<'p, 'v, 'd, N: Copy, D: Copy, G: Copy> RootPathReferences<'p, 'v, 'd, N, D, G> {
    /// Same original root preparation, without replaying signature verification.
    #[must_use]
    pub fn prepared(&self) -> &'p Preparation<N, D, G> {
        self.prepared
    }
    /// Actual checked path associated with the selected root key/certificate.
    #[must_use]
    pub fn path(&self) -> &'v CheckedPath<'d> {
        self.path
    }
    /// Every original ordinary certificate reference, including unsupported ones.
    #[must_use]
    pub fn rows(&self) -> &[RootReferenceRow<N>] {
        &self.rows
    }
    /// Each row compares the anchor (if certificate-backed), then every member
    /// in issuer-to-target order. The target is the forbidden signing certificate.
    #[must_use]
    pub fn comparisons(&self, row: usize) -> Option<&[Agreement]> {
        let row = self.rows.get(row)?;
        self.comparisons.get(row.range.clone())
    }
    /// Original candidate role and bytes without scanning or reparsing them.
    #[must_use]
    pub fn candidate(
        &self,
        index: usize,
    ) -> Option<(PathCertificate, &'v structured_pkix::Certificate<'d>)> {
        candidate(self.path, index)
    }
    /// Only A.1.1(1–2): every existing anchor/CA certificate was referenced and
    /// every entry excludes the signing certificate. This is NOT all Annex A
    /// rules, presence, status, application trust or a baseline grade.
    #[must_use]
    pub fn root_path_rules_met(&self) -> bool {
        self.root_rules
    }
}

/// Actual selected-path reference report or the unchanged terminal cause.
pub type RootPathReferenceResult<'p, 'v, 'd, X, E> = binary::BinaryResult<
    RootPathReferences<'p, 'v, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    ReferenceDigestError<E>,
>;

fn candidate<'v, 'd>(
    path: &'v CheckedPath<'d>,
    mut ordinal: usize,
) -> Option<(PathCertificate, &'v structured_pkix::Certificate<'d>)> {
    if let Some(anchor) = path.anchor().certificate() {
        if ordinal == 0 {
            return Some((PathCertificate::Anchor, anchor));
        }
        ordinal -= 1;
    }
    path.members()
        .get(ordinal)
        .map(|member| (PathCertificate::Member(ordinal), member.certificate()))
}

fn candidate_ids<W: Work>(
    path: &CheckedPath<'_>,
    work: &W,
) -> Result<OwnedVec<usize, W>, MemoryError> {
    let mut ids = work.vector();
    let mut index = work.map();
    let mut ordinal = 0;
    while let Some((_, certificate)) = candidate(path, ordinal) {
        work.charge_work(1)?;
        let bytes = certificate.as_bytes();
        let identity = if let Some(&identity) = index.get(&bytes, work)? {
            identity
        } else {
            index.try_insert(bytes, ordinal)?;
            ordinal
        };
        ids.try_push(identity)?;
        ordinal += 1;
    }
    Ok(ids)
}

struct PathComparisons<'provider, 'path, 'document, P: Digest<'provider>, W: Work> {
    path: &'path CheckedPath<'document>,
    memo: Memo<'provider, 'document, P, W>,
    ids: Option<OwnedVec<usize, W>>,
    covered: OwnedVec<bool, W>,
    comparisons: OwnedVec<Agreement, W>,
}
impl<'provider, 'path, 'document, P: Digest<'provider>, W: Work>
    PathComparisons<'provider, 'path, 'document, P, W>
{
    fn new(path: &'path CheckedPath<'document>, provider: &'provider P, work: &W) -> Self {
        Self {
            path,
            memo: Memo::new(provider, work),
            ids: None,
            covered: work.vector(),
            comparisons: work.vector(),
        }
    }
    fn compare(
        &mut self,
        identity: crate::certificate::FormatDigest<P::Identity>,
        expected: &[u8],
        work: &W,
    ) -> Result<(), digest::Error<structured_cms::stream::RangesError, P::Error>> {
        let method = self.memo.method(identity, work)?;
        if self.ids.is_none() {
            let ids = candidate_ids(self.path, work).map_err(digest::Error::Resource)?;
            let mut covered = work.vector();
            covered
                .try_reserve_exact(ids.len())
                .map_err(digest::Error::Resource)?;
            for _ in 0..ids.len() {
                covered.try_push(false).map_err(digest::Error::Resource)?;
            }
            self.covered = covered;
            self.ids = Some(ids);
        }
        let ids = self
            .ids
            .as_ref()
            .expect("admitted original path candidates");
        for ordinal in 0..ids.len() {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            let (_, certificate) =
                candidate(self.path, ordinal).expect("original immutable path candidate");
            let agreement =
                self.memo
                    .compare(ids[ordinal], certificate.as_bytes(), method, expected, work)?;
            if agreement == Agreement::Matches {
                self.covered[ordinal] = true;
            }
            self.comparisons
                .try_push(agreement)
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }
}

/// Check the complete ordinary certificate reference catalogue against the
/// SAME actually selected certificate path. A.1.1(1–2) requires anchor/CA
/// references and forbids the signing certificate. Extra references can relate
/// to other actual TSA/status paths; they are not rejected merely for differing
/// from this root path. Unsupported comparisons cannot prove signer exclusion.
/// Every reference shares the existing method/width/MD5/streaming core and one
/// full-provider-identity/exact-certificate memo. No XML copy, re-encoding,
/// acquisition, signature/path replay or new crypto dispatcher is needed.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only if privately constructed original path/reference cardinality changes.
pub fn check_root_certificate_references<
    'p,
    'v,
    'd,
    'q,
    X: BinaryXml,
    P: DigestProvider<'q, X>,
    W: Work,
>(
    xml: &X,
    prepared: &'p Prepared<X>,
    selected: &CheckedPathCertificate<'v, 'd, X::Id, X::Document, X::Generation>,
    provider: &'q P,
    work: &W,
) -> RootPathReferenceResult<'p, 'v, 'd, X, P::Error> {
    let source = prepared.bound().containers();
    let location = Location {
        snapshot: source.snapshot(),
        node: source.signature(),
    };
    let access = Access::new(xml, location.snapshot, work);
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    if !core::ptr::eq(selected.selected().reference(), prepared.certificates()) {
        return Err(binary::Error::Callback {
            location,
            cause: ReferenceDigestError::Foreign,
        });
    }
    if !selected.is_bound() {
        return Err(binary::Error::Callback {
            location,
            cause: ReferenceDigestError::UnboundPath,
        });
    }
    let resource = |cause| binary::Error::Callback {
        location,
        cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
    };
    let path = selected.digests().path();
    let mut state = PathComparisons::<P, W>::new(path, provider, work);
    let mut rows = work.vector();
    let mut root_rules = true;
    for (property, references) in prepared.validation_references().iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        if references.role() != unsigned::Role::CertificateReferences {
            continue;
        }
        work.charge_work(
            u64::try_from(state.covered.len()).map_err(|_| resource(MemoryError::WorkExceeded))?,
        )
        .map_err(resource)?;
        state.covered.fill(false);
        let mut signer_excluded = true;
        for (entry, reference) in references.entries().iter().enumerate() {
            work.charge_work(1).map_err(resource)?;
            let (method, value) = reference.digest().expect("original mandatory CertDigest");
            let start = state.comparisons.len();
            let checked = digest::check_with(
                xml,
                digest::Reference {
                    snapshot: references.snapshot(),
                    method,
                    value,
                },
                provider,
                work,
                |identity, expected, work| state.compare(identity, expected, work),
            )
            .map_err(|cause| cause.map_callback(ReferenceDigestError::Digest))?;
            let search = match checked {
                digest::Checked::Value(()) => {
                    signer_excluded &= state.comparisons.last() == Some(&Agreement::Differs);
                    ReferenceSearch::Compared
                }
                digest::Checked::Answer(answer) => {
                    signer_excluded = false;
                    ReferenceSearch::Unavailable(answer)
                }
            };
            rows.try_push(RootReferenceRow {
                property,
                entry,
                node: reference.node(),
                search,
                range: start..state.comparisons.len(),
            })
            .map_err(resource)?;
        }
        if state.covered.is_empty() {
            root_rules = false;
            continue;
        }
        let signer = state.covered.len() - 1;
        for ordinal in 0..signer {
            work.charge_work(1).map_err(resource)?;
            root_rules &= state.covered[ordinal];
        }
        root_rules &= signer_excluded;
    }
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    Ok(RootPathReferences {
        prepared,
        path,
        rows: rows.into_owned(),
        comparisons: state.comparisons.into_owned(),
        root_rules,
    })
}
