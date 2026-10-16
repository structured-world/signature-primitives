//! Source-derived actors for all-token LT or one preceding-archive obligation.

use super::origin::Origin;
use super::{
    AuthorityClosure, AuthorityClosureError, AuthorityNode, CheckedPath, CounterPaths, PathStatuses,
};
use crate::certificate::CheckedPathCertificate;
use crate::credential::{Authorities, Credentials, ParticipantCredentials};
use crate::timestamp::{TimestampPaths, TimestampScope};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::{HashWork, MemoryError, OwnedVec, Work};
use structured_pkix::path::EffectiveAnchor;

/// Original actor requiring validation data, independent of selected path reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Participant<N> {
    /// Actual selected root signer.
    Signer(N),
    /// Actual incorporated counter, including plain `XMLDSig` counters.
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
pub struct ParticipantRequirements<'path, 'document, N, D, G> {
    scope: TimestampScope<N, D, G>,
    signature: N,
    entries: OwnedVec<ParticipantRequirement<'path, 'document, N>>,
    origins: Origins<'path>,
}

struct Origins<'a> {
    signer: Origin<'a>,
    counters: Origin<'a>,
    credentials: Origin<'a>,
    timestamps: Origin<'a>,
}

impl<'path, 'document, N: Copy, D: Copy, G: Copy>
    ParticipantRequirements<'path, 'document, N, D, G>
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

    // Constant-time identity only. The composition boundary admits its current
    // source/query work before calling this; no authentication is replayed.
    pub(crate) fn same_credentials<E>(
        &self,
        credentials: &ParticipantCredentials<'_, '_, E, N, D, G>,
    ) -> bool {
        self.origins.credentials.matches(credentials)
    }

    /// Require the exact live input receipts that produced this complete
    /// participant census. Equivalent IDs, a different valid path/provider
    /// context or independently collected credentials do not establish that
    /// relation. This is a current-operation metadata query, not a replay of
    /// parsing, crypto, credential authentication or catalogue allocation.
    pub fn require_inputs<X: Xml<Id = N, Document = D, Generation = G>, W: Work, E>(
        &self,
        signer: &CheckedPathCertificate<'_, '_, N, D, G>,
        counters: &CounterPaths<'_, '_, N, D, G>,
        credentials: &ParticipantCredentials<'_, '_, E, N, D, G>,
        timestamps: &TimestampPaths<'_, '_, '_, N, D, G>,
        access: &Access<'_, X, W>,
    ) -> Result<(), ParticipantError<X::Error, N>>
    where
        D: Eq,
        G: Eq,
    {
        let signature = self.signature;
        if self.scope.location().snapshot != access.snapshot() {
            return Err(ParticipantError::Foreign { signature });
        }
        access
            .query(signature, |_, _, work| Ok(work.charge_work(4)))
            .map_err(ParticipantError::Access)?
            .map_err(|cause| ParticipantError::Resource {
                node: signature,
                cause,
            })?;
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
#[derive(Debug)]
pub enum ParticipantError<E, N> {
    /// Timestamp obligations omitted the complete actual counter-source census.
    CounterTimestamps,
    /// Original counter timestamp membership/admission refusal.
    Timestamp(crate::timestamp::InputError<E, N>),
    /// Current original source/generation/operation refused.
    Access(AccessError<E, N>),
    /// A proof belongs to another root signature or source generation.
    Foreign {
        /// Expected original root signature.
        signature: N,
    },
    /// The original selected root key/certificate or its signed path digest
    /// restrictions were not established. No partial participant set escapes.
    UnprovenSigner,
    /// Traversal, identity comparison or retained metadata was not admitted.
    Resource {
        /// Original actor or enclosing scope source.
        node: N,
        /// Actual current-operation refusal.
        cause: MemoryError,
    },
}

/// Complete participant roots and every reachable validation authority. The
/// original participant attribution is retained even when several actors use
/// the same path. This is input completeness, not Good status or a B-LTA grade.
pub struct ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G> {
    requirements: &'requirements ParticipantRequirements<'view, 'document, N, D, G>,
    authorities: AuthorityClosure<'view, 'certificate, 'document>,
}

impl<'requirements, 'view, 'certificate, 'document, N, D, G>
    ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>
{
    /// Complete original signer/counter/credential/earlier-token requirements.
    #[must_use]
    pub fn requirements(
        &self,
    ) -> &'requirements ParticipantRequirements<'view, 'document, N, D, G> {
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
pub enum ParticipantClosureError<E, N> {
    /// Source/generation/current operation refused before input processing.
    Access(AccessError<E, N>),
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

/// Participant/authority input closure in the XML owner's identity domain.
pub type ParticipantClosureResult<'requirements, 'view, 'certificate, 'document, X> = Result<
    ParticipantClosure<
        'requirements,
        'view,
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    ParticipantClosureError<<X as Xml>::Error, <X as Xml>::Id>,
>;

impl<'path, 'document, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq>
    ParticipantRequirements<'path, 'document, N, D, G>
{
    /// Associate EVERY source-derived Path actor with its complete status inputs,
    /// then follow the existing CRL/OCSP authority kernel. Evaluation labels are
    /// explicit original inputs, not guessed from `SigningTime` or token order;
    /// their usability and historical trust remain separate checks. Paths may
    /// legitimately repeat for several actors or distinct evaluation labels.
    /// Direct anchors retain their separate certificate-material obligation.
    /// No parse, provider, hash, status evaluation or signature is repeated.
    pub fn close_statuses<'requirements, 'view, 'certificate, X, W>(
        &'requirements self,
        roots: &'view [&'view PathStatuses<'view, 'certificate, 'document>],
        supplied: &'view [AuthorityNode<'view, 'certificate, 'document>],
        access: &Access<'_, X, W>,
    ) -> ParticipantClosureResult<'requirements, 'view, 'certificate, 'document, X>
    where
        X: Xml<Id = N, Document = D, Generation = G>,
        W: Work,
        'path: 'view,
    {
        if self.scope.location().snapshot != access.snapshot() {
            return Err(ParticipantClosureError::Foreign);
        }
        access
            .query(self.signature, |_, _, _| Ok(()))
            .map_err(ParticipantClosureError::Access)?;
        let work = access.execution();
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

/// Complete source-actor requirements in the XML owner's identity domain.
pub type ParticipantResult<'path, 'document, X> = Result<
    ParticipantRequirements<
        'path,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    ParticipantError<<X as Xml>::Error, <X as Xml>::Id>,
>;

struct Collect<'path, 'document, N, W: Work> {
    entries: OwnedVec<ParticipantRequirement<'path, 'document, N>, W>,
}

impl<'path, 'document, N: Copy, W: Work> Collect<'path, 'document, N, W> {
    fn admit<X: Xml<Id = N>>(
        node: N,
        access: &Access<'_, X, W>,
    ) -> Result<(), ParticipantError<X::Error, N>> {
        access
            .query(node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(ParticipantError::Access)?
            .map_err(|cause| ParticipantError::Resource { node, cause })
    }

    fn push<X: Xml<Id = N>>(
        &mut self,
        participant: Participant<N>,
        authority: ParticipantAuthority<'path, 'document>,
        node: N,
        access: &Access<'_, X, W>,
    ) -> Result<(), ParticipantError<X::Error, N>> {
        Self::admit(node, access)?;
        self.entries
            .try_push(ParticipantRequirement {
                participant,
                authority,
            })
            .map_err(|cause| ParticipantError::Resource { node, cause })
    }

    fn credentials<X: Xml<Id = N>, E>(
        &mut self,
        credentials: &Credentials<'path, 'document, E, N, X::Document, X::Generation>,
        access: &Access<'_, X, W>,
    ) -> Result<(), ParticipantError<X::Error, N>> {
        for credential in credentials.entries() {
            Self::admit(credentials.signature(), access)?;
            let source = credential.source();
            let node = source.entry().node;
            let participant = |authority| Participant::Credential {
                signature: source.signature(),
                node,
                authority,
            };
            match credential.authorities() {
                Authorities::Paths(paths) => {
                    for (index, path) in paths.iter().enumerate() {
                        self.push(
                            participant(index),
                            ParticipantAuthority::Path(path),
                            node,
                            access,
                        )?;
                    }
                }
                Authorities::DirectAnchor(anchor) => self.push(
                    participant(0),
                    ParticipantAuthority::Anchor(anchor),
                    node,
                    access,
                )?,
                Authorities::CertificateFree => self.push(
                    participant(0),
                    ParticipantAuthority::CertificateFree,
                    node,
                    access,
                )?,
            }
        }
        Ok(())
    }
}

// Credential groups are an ordered SUBSET of the full original counters.
// A linear merge preserves source identity without quadratic rescanning or
// another retained hash index. Unmatched foreign groups cannot disappear.
fn counter_and_role_requirements<'path, 'document, X: Xml, W: Work, E>(
    collect: &mut Collect<'path, 'document, X::Id, W>,
    counters: &CounterPaths<'path, 'document, X::Id, X::Document, X::Generation>,
    credentials: &ParticipantCredentials<'path, 'document, E, X::Id, X::Document, X::Generation>,
    timestamps: &TimestampPaths<'path, '_, 'document, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> Result<(), ParticipantError<X::Error, X::Id>> {
    let signature = counters.signature();
    let mut ordinal = 0;
    while ordinal < counters.actors().len() {
        Collect::admit(signature, access)?;
        let selected = timestamps
            .required()
            .counter_in_scope(ordinal, access)
            .map_err(ParticipantError::Timestamp)?;
        let actor = &counters.actors()[ordinal];
        ordinal += 1;
        if !selected {
            continue;
        }
        let source = actor.signer().counter().original();
        collect.push(
            Participant::Counter {
                signature: source.child(),
                property: source.node(),
            },
            ParticipantAuthority::Path(actor.signer().path()),
            source.node(),
            access,
        )?;
    }
    if let Some(root) = credentials.root() {
        collect.credentials(root, access)?;
    }
    let mut credential = 0;
    let mut ordinal = 0;
    while ordinal < counters.actors().len() && credential < credentials.counters().len() {
        Collect::admit(signature, access)?;
        let actor = &counters.actors()[ordinal];
        let counter = &credentials.counters()[credential];
        let same = access
            .equal_id(
                actor.signer().counter().original().child(),
                counter.source().original().child(),
            )
            .map_err(|cause| ParticipantError::Resource {
                node: signature,
                cause,
            })?;
        if same {
            if timestamps
                .required()
                .counter_in_scope(ordinal, access)
                .map_err(ParticipantError::Timestamp)?
            {
                collect.credentials(counter.credentials(), access)?;
            }
            credential += 1;
        }
        ordinal += 1;
    }
    if credential != credentials.counters().len() {
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
/// using the SAME original archive-element coverage, not token success counts.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// No provider, parse, certificate hash or signature is repeated. A late
/// source/admission refusal releases all partial output; direct anchors and
/// certificate-free format proofs are not silently treated as ordinary paths.
pub fn participants<'path, 'document, X: Xml, W: Work, E>(
    signer: &'path CheckedPathCertificate<'path, 'document, X::Id, X::Document, X::Generation>,
    counters: &'path CounterPaths<'path, 'document, X::Id, X::Document, X::Generation>,
    credentials: &'path ParticipantCredentials<
        'path,
        'document,
        E,
        X::Id,
        X::Document,
        X::Generation,
    >,
    timestamps: &'path TimestampPaths<'path, '_, 'document, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> ParticipantResult<'path, 'document, X> {
    let references = signer.selected().reference();
    let signature = references.signature();
    let scope = timestamps.required().scope();
    if references.snapshot() != access.snapshot()
        || counters.snapshot() != access.snapshot()
        || credentials.snapshot() != access.snapshot()
        || scope.location().snapshot != access.snapshot()
    {
        return Err(ParticipantError::Foreign { signature });
    }
    let entries = access
        .query(signature, |_, _, work| Ok(work.vector()))
        .map_err(ParticipantError::Access)?;
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
        access
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
    if !signer.is_bound() {
        return Err(ParticipantError::UnprovenSigner);
    }
    if !timestamps
        .required()
        .includes_counters(counters, access)
        .map_err(ParticipantError::Timestamp)?
    {
        return Err(ParticipantError::CounterTimestamps);
    }
    let mut collect = Collect { entries };
    collect.push(
        Participant::Signer(signature),
        ParticipantAuthority::Path(signer.digests().path()),
        signature,
        access,
    )?;
    counter_and_role_requirements(&mut collect, counters, credentials, timestamps, access)?;
    for path in timestamps.paths() {
        Collect::admit(signature, access)?;
        let source = path.actor().verified();
        collect.push(
            Participant::Timestamp {
                property: source.property(),
                token: source.token().node,
            },
            ParticipantAuthority::Path(path.path()),
            source.property(),
            access,
        )?;
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(ParticipantError::Access)?;
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
    })
}
