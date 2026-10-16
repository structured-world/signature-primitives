//! Source-bound independent credentials and their actual authority paths.

use crate::pki::CheckedPath;
use crate::role;
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// One original credential protected by the selected `SignedProperties` binding.
/// Construction is private; a self-claimed role cannot become a credential.
#[derive(Debug, Clone, Copy)]
pub struct Credential<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    entry: role::Entry<N>,
}

impl<N: Copy, D: Copy, G: Copy> Credential<N, D, G> {
    /// Exact original source/generation, never a reconstructed assertion.
    #[must_use]
    pub fn snapshot(self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Signature protecting this original credential's role property.
    #[must_use]
    pub fn signature(self) -> N {
        self.signature
    }
    /// Original payload, group and selected credential syntax.
    #[must_use]
    pub fn entry(self) -> role::Entry<N> {
        self.entry
    }
}

/// Actual certificate requirements of the authenticated credential format.
/// These are explicit format facts, not a fallback from missing evidence.
#[derive(Clone, Copy)]
pub enum Authorities<'path, 'document> {
    /// All independently checked authority paths used by authentication.
    /// An empty slice is incomplete provider evidence, not certificate-free.
    Paths(&'path [&'path CheckedPath<'document>]),
    /// The credential was authenticated directly by this explicitly selected
    /// effective trust anchor. Incorporate its existing certificate when needed;
    /// do not invent a non-anchor chain or a revocation obligation for it.
    DirectAnchor(&'path structured_pkix::path::EffectiveAnchor<'document>),
    /// This concrete format authenticated the original credential without
    /// requiring X.509 certificate paths. Its format-specific evidence remains
    /// mandatory; this does not establish any other required validation material.
    CertificateFree,
}

/// Completed format authentication, separate from application authorization.
pub enum Authentication<'path, 'document, E> {
    /// This original credential format has no selected authentication handler.
    Unsupported,
    /// The selected handler completed and rejected the original credential.
    Rejected,
    /// Original signature/issuer authentication succeeded using exactly these
    /// checked authority paths and their effective keys. This is not approval
    /// of asserted roles, historical trust or revocation/freshness.
    Authenticated {
        /// Actual format-specific authentication receipt, not a trusted flag.
        evidence: E,
        /// Actual format authority/anchor requirements used by this receipt.
        authorities: Authorities<'path, 'document>,
    },
}

/// Format-specific authentication at the original protected credential source.
///
/// EN319132-1 §5.2.6 leaves concrete `SignedAssertion` and
/// `OtherAttributeCertificate` content types outside `XAdES`. Their owner reuses
/// its actual format/signature mechanisms; this core does not invent SAML,
/// attribute-certificate syntax or another crypto dispatcher.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Implementations authenticate THIS exact original credential, including its
/// binding to the signer where required by its format, with the returned paths'
/// actual effective keys. They must not substitute a receipt for another
/// credential or omit a path used by authentication. Source decoding, signature
/// work, retained evidence and all intermediate capacity are pre-admitted under
/// current Access/Work and the format owner's enforced limits. Errors preserve
/// resource/processing causes and truthful inner-source provenance. No implicit
/// acquisition, reparsing XML or application authorization is performed here.
pub trait Provider<'path, 'document, X: Xml> {
    /// Actual retained format evidence; may own admitted data or original IDs.
    type Evidence;
    /// Original format/provider/resource failure, not semantic rejection.
    type Error;

    /// Authenticate this original source once under the current operation.
    fn authenticate<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        credential: Credential<X::Id, X::Document, X::Generation>,
    ) -> Result<Authentication<'path, 'document, Self::Evidence>, Self::Error>;
}

/// Actual authentication result retained with its immutable original source.
pub struct Checked<'path, 'document, E, N, D, G> {
    source: Credential<N, D, G>,
    evidence: E,
    authorities: Authorities<'path, 'document>,
}

impl<'path, 'document, E, N: Copy, D: Copy, G: Copy> Checked<'path, 'document, E, N, D, G> {
    /// Same original protected credential processed by the format owner.
    #[must_use]
    pub fn source(&self) -> Credential<N, D, G> {
        self.source
    }
    /// Original retained authentication evidence, without cloning it.
    #[must_use]
    pub fn evidence(&self) -> &E {
        &self.evidence
    }
    /// Actual authority inputs, including an explicit direct anchor or
    /// certificate-free format. Subsequent path traversal must be paid.
    #[must_use]
    pub fn authorities(&self) -> Authorities<'path, 'document> {
        self.authorities
    }
}

/// Complete credential-actor set for this original signed role catalogue.
/// This is neither a baseline grade nor proof of status/material availability.
pub struct Credentials<'path, 'document, E, N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    entries: OwnedVec<Checked<'path, 'document, E, N, D, G>>,
}

impl<'path, 'document, E, N: Copy, D: Copy, G: Copy> Credentials<'path, 'document, E, N, D, G> {
    /// Original protected role source/generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original selected signature, independent of a credential issuer.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Every independently authenticated credential in original order.
    #[must_use]
    pub fn entries(&self) -> &[Checked<'path, 'document, E, N, D, G>] {
        &self.entries
    }
}

/// Refusal does not return a successfully checked credential prefix.
#[derive(Debug)]
pub enum Error<E, PE, N> {
    /// Caller supplied a complete counter set from another selected signature.
    Foreign {
        /// Original root signature expected by this operation.
        signature: N,
    },
    /// Original source/generation or operation refused.
    Access(AccessError<E, N>),
    /// The selected original format is unsupported, not absent or authenticated.
    Unsupported {
        /// Original credential payload.
        node: N,
    },
    /// Completed original credential authentication was negative.
    Rejected {
        /// Original credential payload.
        node: N,
    },
    /// A handler selected certificate paths but returned an empty set. Direct
    /// anchors and certificate-free formats require their explicit arms; this
    /// is incomplete provider evidence, not bad XML.
    MissingAuthorities {
        /// Original credential payload.
        node: N,
    },
    /// Original provider failure with its credential source retained.
    Provider {
        /// Original credential payload.
        node: N,
        /// Unchanged provider/resource cause.
        cause: PE,
    },
    /// Retained catalogue storage/copy work was not admitted.
    Resource {
        /// Original credential payload or catalogue for empty input.
        node: N,
        /// Actual memory/work refusal.
        cause: MemoryError,
    },
}

/// Complete original credential authentication and retained-source result.
pub type CheckResult<'path, 'document, X, P> = Result<
    Credentials<
        'path,
        'document,
        <P as Provider<'path, 'document, X>>::Evidence,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    Error<<X as Xml>::Error, <P as Provider<'path, 'document, X>>::Error, <X as Xml>::Id>,
>;

/// Authenticate EVERY original non-claimed credential before returning the
/// complete authority-input set required by EN319132-1 §6.3(aa). The original
/// catalogue determines this set, never a caller-selected list of successes.
/// Claimed roles are traversed and paid but need no independent issuer check.
/// A late unsupported/rejected credential or terminal refusal drops all earlier
/// retained evidence. External provider side effects cannot be rolled back.
pub fn check<'path, 'document, X: Xml, P: Provider<'path, 'document, X>, W: Work>(
    roles: &role::Catalogue<X>,
    provider: &P,
    access: &Access<'_, X, W>,
) -> CheckResult<'path, 'document, X, P> {
    if roles.snapshot() != access.snapshot() {
        return Err(Error::Access(AccessError::Changed { node: roles.node() }));
    }
    let mut entries = access
        .query(roles.node(), |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    for entry in roles.entries() {
        access
            .query(entry.node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource {
                node: entry.node,
                cause,
            })?;
        if entry.kind == role::Kind::Claimed {
            continue;
        }
        let source = Credential {
            snapshot: roles.snapshot(),
            signature: roles.signature(),
            entry: *entry,
        };
        let outcome = access
            .query(entry.node, |_, _, _| {
                Ok(provider.authenticate(access, source))
            })
            .map_err(Error::Access)?
            .map_err(|cause| Error::Provider {
                node: entry.node,
                cause,
            })?;
        let (evidence, authorities) = match outcome {
            Authentication::Unsupported => return Err(Error::Unsupported { node: entry.node }),
            Authentication::Rejected => return Err(Error::Rejected { node: entry.node }),
            Authentication::Authenticated {
                evidence,
                authorities,
            } => (evidence, authorities),
        };
        if let Authorities::Paths(paths) = authorities
            && paths.is_empty()
        {
            return Err(Error::MissingAuthorities { node: entry.node });
        }
        entries
            .try_push(Checked {
                source,
                evidence,
                authorities,
            })
            .map_err(|cause| Error::Resource {
                node: entry.node,
                cause,
            })?;
    }
    access
        .query(roles.node(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    Ok(Credentials {
        snapshot: roles.snapshot(),
        signature: roles.signature(),
        entries: entries.into_owned(),
    })
}

/// Actual credentials of one incorporated counter, retaining its source edge.
pub struct CounterCredentials<'path, 'document, E, N, D, G> {
    source: crate::counter::Checked<N, D, G>,
    credentials: Credentials<'path, 'document, E, N, D, G>,
}

impl<'path, 'document, E, N, D, G> CounterCredentials<'path, 'document, E, N, D, G> {
    /// Original checked child/parent signature coverage receipt.
    #[must_use]
    pub fn source(&self) -> &crate::counter::Checked<N, D, G> {
        &self.source
    }
    /// Every credential of this counter, without a copied catalogue/evidence.
    #[must_use]
    pub fn credentials(&self) -> &Credentials<'path, 'document, E, N, D, G> {
        &self.credentials
    }
}

/// Complete current-role credentials of the root and all incorporated counters.
/// No caller-provided success list determines which groups are visited. Other
/// actor path/status/material and format-specific obligations remain separate.
pub struct ParticipantCredentials<'path, 'document, E, N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    root: Option<Credentials<'path, 'document, E, N, D, G>>,
    counters: OwnedVec<CounterCredentials<'path, 'document, E, N, D, G>>,
}

impl<'path, 'document, E, N: Copy, D: Copy, G: Copy>
    ParticipantCredentials<'path, 'document, E, N, D, G>
{
    /// Original root source and generation for the whole participant set.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original root signature, independent of every credential issuer.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// All original root credentials, if a role property was present.
    #[must_use]
    pub fn root(&self) -> Option<&Credentials<'path, 'document, E, N, D, G>> {
        self.root.as_ref()
    }
    /// Every incorporated counter with a protected current role property.
    /// Other counters remain in the separate complete counter-signer census.
    #[must_use]
    pub fn counters(&self) -> &[CounterCredentials<'path, 'document, E, N, D, G>] {
        &self.counters
    }
}

/// Source-bound complete credential participants in this XML identity domain.
pub type ParticipantResult<'path, 'document, X, P> = Result<
    ParticipantCredentials<
        'path,
        'document,
        <P as Provider<'path, 'document, X>>::Evidence,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    Error<<X as Xml>::Error, <P as Provider<'path, 'document, X>>::Error, <X as Xml>::Id>,
>;

/// Check every credential group of the original root and COMPLETE counter set.
/// Reuses `check` rather than another credential decoder/authenticator. Missing
/// paths, unsupported formats and all late refusals release partial groups.
/// No root/counter signature or certificate-path mathematics is repeated.
pub fn check_participants<'path, 'document, X: Xml, P: Provider<'path, 'document, X>, W: Work>(
    prepared: &crate::prepare::Prepared<X>,
    counters: &crate::pki::CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    provider: &P,
    access: &Access<'_, X, W>,
) -> ParticipantResult<'path, 'document, X, P> {
    use structured_asn1::memory::HashWork;
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() || counters.snapshot() != access.snapshot() {
        return Err(Error::Access(AccessError::Changed { node: signature }));
    }
    let mut groups = access
        .query(signature, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    let cost = signature
        .hash_work()
        .and_then(|cost| {
            cost.checked_add(counters.signature().hash_work()?)
                .ok_or(MemoryError::WorkExceeded)
        })
        .map_err(|cause| Error::Resource {
            node: signature,
            cause,
        })?;
    access
        .execution()
        .charge_work(cost)
        .map_err(|cause| Error::Resource {
            node: signature,
            cause,
        })?;
    if signature != counters.signature() {
        return Err(Error::Foreign { signature });
    }
    let root = match prepared.roles() {
        Some(roles) => Some(check(roles, provider, access)?),
        None => None,
    };
    for actor in counters.actors() {
        access
            .query(signature, |_, _, work| Ok(work.charge_work(1)))
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource {
                node: signature,
                cause,
            })?;
        let Some(roles) = actor.roles() else {
            continue;
        };
        let credentials = check(roles, provider, access)?;
        groups
            .try_push(CounterCredentials {
                source: *actor.signer().counter(),
                credentials,
            })
            .map_err(|cause| Error::Resource {
                node: roles.node(),
                cause,
            })?;
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    Ok(ParticipantCredentials {
        snapshot: layout.snapshot(),
        signature,
        root,
        counters: groups.into_owned(),
    })
}
