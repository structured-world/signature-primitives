//! Source-derived actors for all-token LT or one preceding-archive obligation.

use super::origin::Origin;
use super::{AuthorityClosure, AuthorityClosureError, AuthorityNode, CheckedPath, PathStatuses};
use crate::source::{Location, Query, ScopeError, Snapshot};
use crate::timestamp::{ObligationError, TimestampPaths, TimestampScope};
use core::marker::PhantomData;
use structured_asn1::memory::{HashWork, MemoryError, OwnedVec, Work};
use structured_pkix::path::EffectiveAnchor;

/// Original actor requiring validation data, independent of selected path reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Participant<N> {
    /// Actual selected root signer.
    Signer(N),
    /// Actual incorporated countersignature, including one without signed
    /// properties of its own.
    Counter {
        /// Original child signature.
        signature: N,
        /// Original counter property.
        property: N,
    },
    /// Original protected credential and an authority used by its handler.
    Credential {
        /// Signature protecting the credential.
        signature: N,
        /// Original credential payload.
        node: N,
        /// Ordinal in the handler's authority path set, or zero for a direct/format-specific authority.
        authority: usize,
    },
    /// An actual timestamp in the original whole-signature/archive scope.
    Timestamp {
        /// Original timestamp property.
        property: N,
        /// Original encapsulated token element.
        token: N,
    },
}

/// Actual X.509 requirements from already associated participant evidence.
#[derive(Clone, Copy)]
pub enum ParticipantAuthority<'path, 'document> {
    /// Every member and existing anchor of this actual checked path is needed.
    Path(&'path CheckedPath<'document>),
    /// Explicit direct anchor; its existing certificate is material, but the
    /// anchor never becomes a non-anchor revocation obligation.
    Anchor(&'path EffectiveAnchor<'document>),
    /// Explicit credential-format evidence needed no X.509 path. This does NOT
    /// prove absence/incorporation of other format-specific validation material.
    CertificateFree,
}

/// Actual certificate requirements of an authenticated credential format.
/// These are explicit format facts, not a fallback from missing evidence.
#[derive(Clone, Copy)]
pub enum Authorities<'path, 'document> {
    /// All independently checked authority paths used by authentication.
    /// An empty slice is incomplete provider evidence, not certificate-free.
    Paths(&'path [&'path CheckedPath<'document>]),
    /// The credential was authenticated directly by this explicitly selected
    /// effective trust anchor. Incorporate its existing certificate when needed;
    /// do not invent a non-anchor chain or a revocation obligation for it.
    DirectAnchor(&'path EffectiveAnchor<'document>),
    /// This concrete format authenticated the original credential without
    /// requiring X.509 certificate paths. Its format-specific evidence remains
    /// mandatory; this does not establish any other required validation material.
    CertificateFree,
}

/// The format layer's binding of a signature to its signing certificate's path.
///
/// Implemented on the format's own receipt, so a later check can require that
/// very receipt rather than an equivalent one. Only the issuer derives a
/// census from it ([`participants`] takes the issuer value).
pub trait SignerReceipt<'path, 'document> {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;

    /// The selected signature in its exact source generation.
    fn signature(&self) -> Location<Self::Id, Self::Document, Self::Generation>;
    /// The checked signer path, or `None` when the format has not established
    /// the signing certificate or its signed path restrictions.
    fn path(&self) -> Option<&'path CheckedPath<'document>>;
}

/// One incorporated countersignature and its signer's checked path.
#[derive(Clone, Copy)]
pub struct Counter<'path, 'document, N> {
    /// Original child signature.
    pub signature: N,
    /// Original counter property.
    pub property: N,
    /// Checked path of the child's actual signer.
    pub path: &'path CheckedPath<'document>,
}

/// The format layer's complete census of incorporated countersignatures.
///
/// It lists every original counter in source order, never a successful subset.
pub trait CounterReceipts<'path, 'document> {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;

    /// Original root source and generation under which all counters were visited.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;
    /// Root signature whose complete incorporated counters were checked.
    fn signature(&self) -> Self::Id;
    /// Number of countersignatures in the census.
    fn len(&self) -> usize;
    /// Whether the census is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The countersignature at this census ordinal.
    ///
    /// # Panics
    /// When `ordinal` is not below [`Self::len`].
    fn counter(&self, ordinal: usize) -> Counter<'path, 'document, Self::Id>;
}

/// One authenticated credential: its payload, protecting signature and authorities.
#[derive(Clone, Copy)]
pub struct Credential<'path, 'document, N> {
    /// Signature protecting the credential.
    pub signature: N,
    /// Original credential payload.
    pub node: N,
    /// Actual authority inputs of its authentication.
    pub authorities: Authorities<'path, 'document>,
}

/// Every authenticated credential of one signature, in original order.
pub trait CredentialGroup<'path, 'document> {
    /// Original node identity.
    type Id: Copy;

    /// Signature whose protected properties hold these credentials.
    fn signature(&self) -> Self::Id;
    /// Number of authenticated credentials.
    fn len(&self) -> usize;
    /// Whether the group is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The credential at this ordinal.
    ///
    /// # Panics
    /// When `ordinal` is not below [`Self::len`].
    fn credential(&self, ordinal: usize) -> Credential<'path, 'document, Self::Id>;
}

/// The format layer's complete credential census of a root and its counters.
///
/// Counter groups appear in census order and only for counters that carry
/// credentials; every other counter stays in the counter census.
pub trait CredentialReceipts<'path, 'document> {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;
    /// One signature's credentials.
    type Group: CredentialGroup<'path, 'document, Id = Self::Id>;

    /// Original root source and generation for the whole participant set.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;
    /// Original root signature, independent of every credential issuer.
    fn signature(&self) -> Self::Id;
    /// The root's credentials, if it has a credential property.
    fn root(&self) -> Option<&Self::Group>;
    /// Number of counters with credentials.
    fn counters(&self) -> usize;
    /// The counter child signature and its credentials at this ordinal.
    ///
    /// # Panics
    /// When `ordinal` is not below [`Self::counters`].
    fn counter(&self, ordinal: usize) -> (Self::Id, &Self::Group);
}

/// One source actor and its actual authority, not a caller-supplied path count.
pub struct ParticipantRequirement<'path, 'document, N> {
    participant: Participant<N>,
    authority: ParticipantAuthority<'path, 'document>,
}

impl<'path, 'document, N: Copy> ParticipantRequirement<'path, 'document, N> {
    /// Original root/counter/credential/earlier-token source.
    #[must_use]
    pub fn participant(&self) -> Participant<N> {
        self.participant
    }
    /// Actual path/anchor or explicit non-X509 format authority.
    #[must_use]
    pub fn authority(&self) -> ParticipantAuthority<'path, 'document> {
        self.authority
    }
}

/// All source-derived actor paths for ONE original validation-data scope.
/// Paths shared by several actors remain separately attributed. Status-input
/// closure, placement/coverage, format-specific material and trust are separate;
/// this object cannot assert a baseline grade or turn negative facts into Good.
/// It keeps the issuer `I` of the timestamp census it was derived from.
pub struct ParticipantRequirements<'path, 'document, N, D, G, I> {
    scope: TimestampScope<N, D, G>,
    signature: N,
    entries: OwnedVec<ParticipantRequirement<'path, 'document, N>>,
    origins: Origins<'path>,
    issuer: PhantomData<I>,
}

struct Origins<'a> {
    signer: Origin<'a>,
    counters: Origin<'a>,
    credentials: Origin<'a>,
    timestamps: Origin<'a>,
}

impl<'path, 'document, N: Copy, D: Copy, G: Copy, I>
    ParticipantRequirements<'path, 'document, N, D, G, I>
{
    /// Whole selected signature or exact preceding-archive scope.
    #[must_use]
    pub fn scope(&self) -> TimestampScope<N, D, G> {
        self.scope
    }
    /// Original selected root signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Every participant authority, preserving signer/counter/credential/token order.
    #[must_use]
    pub fn entries(&self) -> &[ParticipantRequirement<'path, 'document, N>] {
        &self.entries
    }

    /// Whether this census was derived from exactly this credential receipt.
    /// Constant-time identity only: the caller admits its current query first;
    /// no authentication is replayed.
    #[must_use]
    pub fn same_credentials<C>(&self, credentials: &C) -> bool {
        self.origins.credentials.matches(credentials)
    }

    /// Require the exact live input receipts that produced this complete
    /// participant census. Equivalent IDs, a different valid path/provider
    /// context or independently collected credentials do not establish that
    /// relation. This is a current-operation metadata query, not a replay of
    /// parsing, crypto, credential authentication or catalogue allocation.
    pub fn require_inputs<S, C, R, Q>(
        &self,
        signer: &S,
        counters: &C,
        credentials: &R,
        timestamps: &TimestampPaths<'_, '_, '_, N, D, G, I>,
        query: &Q,
    ) -> Result<(), ParticipantError<N>>
    where
        D: Eq,
        G: Eq,
        Q: Query<Id = N, Document = D, Generation = G>,
    {
        let signature = self.signature;
        if self.scope.location().snapshot != query.snapshot() {
            return Err(ParticipantError::Foreign { signature });
        }
        // One dispatch plus the four constant-time identity comparisons.
        query.admit(signature, 5)?;
        if !self.origins.signer.matches(signer)
            || !self.origins.counters.matches(counters)
            || !self.same_credentials(credentials)
            || !self.origins.timestamps.matches(timestamps)
        {
            return Err(ParticipantError::Foreign { signature });
        }
        Ok(())
    }
}

/// Insufficient/mixed inputs and resource errors remain distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantError<N> {
    /// Timestamp obligations omitted the complete actual counter-source census.
    CounterTimestamps,
    /// Counter timestamp membership or its scope refused.
    Obligation(ObligationError<N>),
    /// Current original source/generation/operation refused.
    Scope(ScopeError<N>),
    /// A proof belongs to another root signature or source generation.
    Foreign {
        /// Expected original root signature.
        signature: N,
    },
    /// The original selected root key/certificate or its signed path digest
    /// restrictions were not established. No partial participant set escapes.
    UnprovenSigner,
    /// An authenticated credential reported an empty authority path set: that
    /// is incomplete provider evidence, distinct from certificate-free proof.
    MissingAuthorities {
        /// Original credential payload.
        node: N,
    },
    /// Traversal, identity comparison or retained metadata was not admitted.
    Resource {
        /// Original actor or enclosing scope source.
        node: N,
        /// Actual current-operation refusal.
        cause: MemoryError,
    },
}

/// Complete source-actor requirements in the query's identity domain.
pub type ParticipantResult<'path, 'document, Q, I> = Result<
    ParticipantRequirements<
        'path,
        'document,
        <Q as Query>::Id,
        <Q as Query>::Document,
        <Q as Query>::Generation,
        I,
    >,
    ParticipantError<<Q as Query>::Id>,
>;

impl<N> From<ScopeError<N>> for ParticipantError<N> {
    fn from(cause: ScopeError<N>) -> Self {
        Self::Scope(cause)
    }
}

/// Complete participant roots and every reachable validation authority. The
/// original participant attribution is retained even when several actors use
/// the same path. This is input completeness, not Good status or a B-LTA grade.
pub struct ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G, I> {
    requirements: &'requirements ParticipantRequirements<'view, 'document, N, D, G, I>,
    authorities: AuthorityClosure<'view, 'certificate, 'document>,
}

impl<'requirements, 'view, 'certificate, 'document, N, D, G, I>
    ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G, I>
{
    /// Complete original signer/counter/credential/earlier-token requirements.
    #[must_use]
    pub fn requirements(
        &self,
    ) -> &'requirements ParticipantRequirements<'view, 'document, N, D, G, I> {
        self.requirements
    }

    /// Complete per-path inputs and their original actual status authorities.
    #[must_use]
    pub fn authorities(&self) -> &AuthorityClosure<'view, 'certificate, 'document> {
        &self.authorities
    }
}

/// A missing actor input is distinct from a negative authenticated status.
#[derive(Debug)]
pub enum ParticipantClosureError<N> {
    /// Source/generation/current operation refused before input processing.
    Scope(ScopeError<N>),
    /// The requirements belong to another original source generation.
    Foreign,
    /// One root is required per Path actor, preserving source order; direct
    /// anchors and certificate-free credentials do not acquire a status root.
    Count,
    /// The root was substituted with a different live checked-path receipt.
    Path {
        /// Original participant-requirement ordinal.
        participant: usize,
    },
    /// Original status-authority closure could not be established.
    Authority(AuthorityClosureError),
    /// Current input traversal refused before its work.
    Resource(MemoryError),
}

/// The closure of one census, or the refusal to close it.
pub type ClosureResult<'requirements, 'view, 'certificate, 'document, N, D, G, I> = Result<
    ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G, I>,
    ParticipantClosureError<N>,
>;

impl<'path, 'document, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, I>
    ParticipantRequirements<'path, 'document, N, D, G, I>
{
    /// Associate EVERY source-derived Path actor with its complete status inputs,
    /// then follow the existing CRL/OCSP authority kernel. Evaluation labels are
    /// explicit original inputs, not guessed from a claimed signing time or
    /// token order; their usability and historical trust remain separate checks.
    /// Paths may legitimately repeat for several actors or distinct evaluation
    /// labels. Direct anchors retain their separate certificate-material
    /// obligation. No parse, provider, hash, status evaluation or signature is
    /// repeated.
    pub fn close_statuses<'requirements, 'view, 'certificate, Q>(
        &'requirements self,
        roots: &'view [&'view PathStatuses<'view, 'certificate, 'document>],
        supplied: &'view [AuthorityNode<'view, 'certificate, 'document>],
        query: &Q,
    ) -> ClosureResult<'requirements, 'view, 'certificate, 'document, N, D, G, I>
    where
        Q: Query<Id = N, Document = D, Generation = G>,
        'path: 'view,
    {
        if self.scope.location().snapshot != query.snapshot() {
            return Err(ParticipantClosureError::Foreign);
        }
        query
            .admit(self.signature, 1)
            .map_err(ParticipantClosureError::Scope)?;
        let work = query.execution();
        let mut cursor = 0;
        for (participant, entry) in self.entries.iter().enumerate() {
            work.charge_work(1)
                .map_err(ParticipantClosureError::Resource)?;
            let ParticipantAuthority::Path(path) = entry.authority else {
                continue;
            };
            let Some(root) = roots.get(cursor) else {
                return Err(ParticipantClosureError::Count);
            };
            if !core::ptr::eq(path, root.path()) {
                return Err(ParticipantClosureError::Path { participant });
            }
            cursor += 1;
        }
        if cursor != roots.len() {
            return Err(ParticipantClosureError::Count);
        }
        let authorities = super::close_authorities(roots, supplied, work)
            .map_err(ParticipantClosureError::Authority)?;
        Ok(ParticipantClosure {
            requirements: self,
            authorities,
        })
    }
}

struct Collect<'path, 'document, N, W: Work> {
    entries: OwnedVec<ParticipantRequirement<'path, 'document, N>, W>,
}

impl<'path, 'document, N: Copy, W: Work> Collect<'path, 'document, N, W> {
    fn push<Q: Query<Id = N, Work = W>>(
        &mut self,
        participant: Participant<N>,
        authority: ParticipantAuthority<'path, 'document>,
        node: N,
        query: &Q,
    ) -> Result<(), ParticipantError<N>> {
        query.admit(node, 2)?;
        self.entries
            .try_push(ParticipantRequirement {
                participant,
                authority,
            })
            .map_err(|cause| ParticipantError::Resource { node, cause })
    }

    fn credentials<Q: Query<Id = N, Work = W>, R: CredentialGroup<'path, 'document, Id = N>>(
        &mut self,
        credentials: &R,
        query: &Q,
    ) -> Result<(), ParticipantError<N>> {
        for ordinal in 0..credentials.len() {
            query.admit(credentials.signature(), 2)?;
            let credential = credentials.credential(ordinal);
            let node = credential.node;
            let participant = |authority| Participant::Credential {
                signature: credential.signature,
                node,
                authority,
            };
            match credential.authorities {
                // The enum contract makes an empty path set incomplete provider
                // evidence; letting it through would drop the credential's actor.
                Authorities::Paths([]) => {
                    return Err(ParticipantError::MissingAuthorities { node });
                }
                Authorities::Paths(paths) => {
                    for (index, path) in paths.iter().enumerate() {
                        self.push(
                            participant(index),
                            ParticipantAuthority::Path(path),
                            node,
                            query,
                        )?;
                    }
                }
                Authorities::DirectAnchor(anchor) => self.push(
                    participant(0),
                    ParticipantAuthority::Anchor(anchor),
                    node,
                    query,
                )?,
                Authorities::CertificateFree => self.push(
                    participant(0),
                    ParticipantAuthority::CertificateFree,
                    node,
                    query,
                )?,
            }
        }
        Ok(())
    }
}

// Credential groups are an ordered SUBSET of the full original counters.
// A linear merge preserves source identity without quadratic rescanning or
// another retained hash index. Unmatched foreign groups cannot disappear.
fn counter_and_role_requirements<'path, 'document, C, R, Q, I>(
    collect: &mut Collect<'path, 'document, Q::Id, Q::Work>,
    counters: &C,
    credentials: &R,
    timestamps: &TimestampPaths<'path, '_, 'document, Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
) -> Result<(), ParticipantError<Q::Id>>
where
    Q: Query,
    C: CounterReceipts<'path, 'document, Id = Q::Id>,
    R: CredentialReceipts<'path, 'document, Id = Q::Id>,
{
    let signature = counters.signature();
    let mut ordinal = 0;
    while ordinal < counters.len() {
        query.admit(signature, 2)?;
        let selected = timestamps
            .required()
            .counter_in_scope(ordinal, query)
            .map_err(ParticipantError::Obligation)?;
        let counter = counters.counter(ordinal);
        ordinal += 1;
        if !selected {
            continue;
        }
        collect.push(
            Participant::Counter {
                signature: counter.signature,
                property: counter.property,
            },
            ParticipantAuthority::Path(counter.path),
            counter.property,
            query,
        )?;
    }
    if let Some(root) = credentials.root() {
        collect.credentials(root, query)?;
    }
    let mut credential = 0;
    let mut ordinal = 0;
    while ordinal < counters.len() && credential < credentials.counters() {
        query.admit(signature, 2)?;
        let (child, group) = credentials.counter(credential);
        let same = query
            .equal(counters.counter(ordinal).signature, child)
            .map_err(|cause| ParticipantError::Resource {
                node: signature,
                cause,
            })?;
        if same {
            if timestamps
                .required()
                .counter_in_scope(ordinal, query)
                .map_err(ParticipantError::Obligation)?
            {
                collect.credentials(group, query)?;
            }
            credential += 1;
        }
        ordinal += 1;
    }
    if credential != credentials.counters() {
        return Err(ParticipantError::Foreign { signature });
    }
    Ok(())
}

/// Derive the complete actor set from actual source-bound receipts.
/// Root certificate binding, the complete incorporated-counter set, every
/// protected credential group and every original token in the explicit scope
/// must already have completed their corresponding shared checks. The SAME
/// kernel serves all-token LT and6.3(aa)'s preceding-archive obligations; only
/// the latter excludes later counters/credentials and the current/later TSA
/// using the SAME original archive coverage, not token success counts.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// No provider, parse, certificate hash or signature is repeated. A late
/// source/admission refusal releases all partial output; direct anchors and
/// certificate-free format proofs are not silently treated as ordinary paths.
///
/// The census names neither receipt type, and the receipt traits are open to
/// any implementation, so requiring the issuer value is what keeps a caller of
/// the format from deriving the format's census from receipts of its own.
pub fn participants<'path, 'document, S, C, R, Q, I>(
    _issuer: I,
    signer: &'path S,
    counters: &'path C,
    credentials: &'path R,
    timestamps: &'path TimestampPaths<'path, '_, 'document, Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
) -> ParticipantResult<'path, 'document, Q, I>
where
    Q: Query,
    S: SignerReceipt<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    C: CounterReceipts<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    R: CredentialReceipts<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
{
    let selected = signer.signature();
    let signature = selected.node;
    let scope = timestamps.required().scope();
    if selected.snapshot != query.snapshot()
        || counters.snapshot() != query.snapshot()
        || credentials.snapshot() != query.snapshot()
        || scope.location().snapshot != query.snapshot()
    {
        return Err(ParticipantError::Foreign { signature });
    }
    query.admit(signature, 1)?;
    let entries = query.execution().vector();
    for actual in [
        counters.signature(),
        credentials.signature(),
        timestamps.required().signature(),
    ] {
        let cost = signature
            .hash_work()
            .and_then(|cost| {
                cost.checked_add(actual.hash_work()?)
                    .ok_or(MemoryError::WorkExceeded)
            })
            .map_err(|cause| ParticipantError::Resource {
                node: signature,
                cause,
            })?;
        query
            .execution()
            .charge_work(cost)
            .map_err(|cause| ParticipantError::Resource {
                node: signature,
                cause,
            })?;
        if actual != signature {
            return Err(ParticipantError::Foreign { signature });
        }
    }
    let Some(path) = signer.path() else {
        return Err(ParticipantError::UnprovenSigner);
    };
    if !timestamps
        .required()
        .includes_counters(counters, query)
        .map_err(ParticipantError::Scope)?
    {
        return Err(ParticipantError::CounterTimestamps);
    }
    let mut collect = Collect { entries };
    collect.push(
        Participant::Signer(signature),
        ParticipantAuthority::Path(path),
        signature,
        query,
    )?;
    counter_and_role_requirements(&mut collect, counters, credentials, timestamps, query)?;
    for path in timestamps.paths() {
        query.admit(signature, 2)?;
        let source = path.actor().verified();
        collect.push(
            Participant::Timestamp {
                property: source.property(),
                token: source.token().node,
            },
            ParticipantAuthority::Path(path.path()),
            source.property(),
            query,
        )?;
    }
    query.admit(signature, 1)?;
    Ok(ParticipantRequirements {
        scope,
        signature,
        entries: collect.entries.into_owned(),
        origins: Origins {
            signer: Origin::of(signer),
            counters: Origin::of(counters),
            credentials: Origin::of(credentials),
            timestamps: Origin::of(timestamps),
        },
        issuer: PhantomData,
    })
}
