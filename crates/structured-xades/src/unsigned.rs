//! Complete unsigned-property inventory and requested-profile presence rules.

use crate::binding::Bound;
use crate::container::XADES;
use crate::properties::{Error, PropertyResult};
use crate::timestamp::XADES_141;
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Requested structural requirements, never an assertion of an attained level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirements {
    /// B-B requirements; presence of additional material does not promote level.
    Basic,
    /// B-T also requires at least one signature timestamp container.
    Timestamped,
    /// B-LT forbids reference-only validation substitutes and requires full data.
    LongTerm,
    /// B-LTA additionally requires an archive timestamp container.
    Archival,
}

/// Known role of an original unsigned property; inner semantics remain separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Enveloped child signature.
    Counter,
    /// Signature-value timestamp.
    SignatureTimestamp,
    /// Certificate values.
    Certificates,
    /// Revocation values.
    Revocation,
    /// Attribute-authority certificate values.
    AttributeCertificates,
    /// Attribute/assertion revocation values.
    AttributeRevocation,
    /// General validation material.
    AnyValidation,
    /// Timestamp-specific validation material.
    TimestampValidation,
    /// Current archive timestamp.
    Archive,
    /// Recomputed indirectly signed object digests.
    RenewedDigests,
    /// Referenced signature-policy document.
    PolicyStore,
    /// Complete certificate references, without values.
    CertificateReferences,
    /// Complete revocation references, without values.
    RevocationReferences,
    /// Attribute certificate references, without values.
    AttributeCertificateReferences,
    /// Attribute revocation references, without values.
    AttributeRevocationReferences,
    /// Timestamp over signature and validation references.
    SignatureAndReferencesTimestamp,
    /// Timestamp over validation references.
    ReferencesTimestamp,
    /// Schema-permitted foreign property, requiring explicit processing.
    Extension,
}

/// One original entry in document order, retaining unknown extension identity.
#[derive(Debug, Clone, Copy)]
pub struct Entry<N> {
    /// Original XML node.
    pub node: N,
    /// Known schema role, not an authentication or completeness result.
    pub role: Role,
}

/// Full inventory. It cannot claim path/status validity or an attained B level.
#[derive(Debug)]
pub struct Catalogue<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    parent: Option<N>,
    data: Option<N>,
    entries: OwnedVec<Entry<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Catalogue<N, D, G> {
    /// Original XML document and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Selected signature whose unsigned properties were traversed.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Present original unsigned-signature-properties container.
    #[must_use]
    pub fn parent(&self) -> Option<N> {
        self.parent
    }
    /// Original optional unsigned-data-object container, kept independently of
    /// signature properties; its application payload is not an `XAdES` verdict.
    #[must_use]
    pub fn data_objects(&self) -> Option<N> {
        self.data
    }
    /// All original entries, preserving order for archive coverage.
    #[must_use]
    pub fn entries(&self) -> &[Entry<N>] {
        &self.entries
    }
}

/// Inventory using the XML owner's identity types.
pub type Reading<X> = Catalogue<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Checks the credential-presence condition of §6.3(r/s/w). Self-claimed roles
/// alone do not permit attribute-authority certificate/status material. A parsed
/// credential permits the structural property, but its issuer authentication,
/// path, status and asserted role must still be checked independently.
pub fn check_credential_material<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    inventory: &Reading<X>,
    roles: Option<&crate::role::Catalogue<X>>,
) -> PropertyResult<(), X> {
    if access.snapshot() != inventory.snapshot {
        return Err(Error::Access(AccessError::Changed {
            node: inventory.signature,
        }));
    }
    let mut credential = false;
    if let Some(roles) = roles {
        if roles.snapshot() != inventory.snapshot
            || !access
                .equal_id(roles.signature(), inventory.signature)
                .map_err(|cause| {
                    Error::Access(AccessError::Resource {
                        node: roles.node(),
                        cause,
                    })
                })?
        {
            return Err(Error::Access(AccessError::Changed { node: roles.node() }));
        }
        for index in 0..roles.entries().len() {
            access
                .query(roles.node(), |_, _, work| Ok(work.charge_work(1)))
                .map_err(Error::Access)?
                .map_err(|cause| Error::Resource {
                    node: roles.node(),
                    cause,
                })?;
            if roles.entries()[index].kind != crate::role::Kind::Claimed {
                credential = true;
                break;
            }
        }
    }
    for index in 0..inventory.entries.len() {
        access
            .query(inventory.signature, |_, _, work| Ok(work.charge_work(1)))
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource {
                node: inventory.signature,
                cause,
            })?;
        let entry = inventory.entries[index];
        if !credential
            && matches!(
                entry.role,
                Role::AttributeCertificates
                    | Role::AttributeRevocation
                    | Role::AttributeCertificateReferences
                    | Role::AttributeRevocationReferences
            )
        {
            return Err(Error::Forbidden { node: entry.node });
        }
    }
    Ok(())
}

/// Inventories every original unsigned property before profile execution.
/// Required containers and prohibited reference-only forms follow EN319132-1
/// §6.3 table2. Their mere presence is insufficient: timestamp mathematics,
/// signer/authority paths and conditional material completeness remain mandatory.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    requirements: Requirements,
) -> PropertyResult<Reading<X>, X> {
    let layout = bound.containers();
    let signature = layout.signature();
    if access.snapshot() != layout.snapshot() {
        return Err(Error::Access(AccessError::Changed { node: signature }));
    }
    let [parent, data] = containers(access, layout.unsigned())?;
    let mut entries = access
        .query(signature, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    let mut singletons = [false; 9];
    let mut signature_timestamp = false;
    let mut archive_timestamp = false;
    if let Some(parent) = parent {
        for child in access.children(parent) {
            let node = child.map_err(Error::Child)?;
            let role = classify(access, node)?;
            // Reference-only forms are not validation-material service options
            // for B-LT/B-LTA, even if an XML schema accepts their syntax.
            let singleton = match role {
                Role::Certificates => Some(0),
                Role::Revocation => Some(1),
                Role::AttributeCertificates => Some(2),
                Role::AttributeRevocation => Some(3),
                Role::PolicyStore => Some(4),
                Role::CertificateReferences => Some(5),
                Role::RevocationReferences => Some(6),
                Role::AttributeCertificateReferences => Some(7),
                Role::AttributeRevocationReferences => Some(8),
                _ => None,
            };
            if let Some(index) = singleton {
                if singletons[index] {
                    return Err(Error::Duplicate { node });
                }
                singletons[index] = true;
            }
            if matches!(
                requirements,
                Requirements::LongTerm | Requirements::Archival
            ) && matches!(
                role,
                Role::CertificateReferences
                    | Role::RevocationReferences
                    | Role::AttributeCertificateReferences
                    | Role::AttributeRevocationReferences
                    | Role::SignatureAndReferencesTimestamp
                    | Role::ReferencesTimestamp
            ) {
                return Err(Error::Forbidden { node });
            }
            signature_timestamp |= role == Role::SignatureTimestamp;
            archive_timestamp |= role == Role::Archive;
            entries
                .try_push(Entry { node, role })
                .map_err(|cause| Error::Resource { node, cause })?;
        }
        if entries.is_empty() {
            return Err(Error::Missing {
                parent,
                local: "unsigned property",
            });
        }
    }
    if requirements != Requirements::Basic && !signature_timestamp {
        return Err(Error::Missing {
            parent: signature,
            local: "SignatureTimeStamp",
        });
    }
    if requirements == Requirements::Archival && !archive_timestamp {
        return Err(Error::Missing {
            parent: signature,
            local: "ArchiveTimeStamp",
        });
    }
    Ok(Catalogue {
        snapshot: layout.snapshot(),
        signature,
        parent,
        data,
        entries: entries.into_owned(),
    })
}

pub(crate) fn containers<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    unsigned: Option<X::Id>,
) -> PropertyResult<[Option<X::Id>; 2], X> {
    let mut fields = [None; 2];
    let Some(unsigned) = unsigned else {
        return Ok(fields);
    };
    for child in access.children(unsigned) {
        let node = child.map_err(Error::Child)?;
        if access
            .has_name(
                node,
                Name {
                    namespace: XADES,
                    local: "UnsignedSignatureProperties",
                },
            )
            .map_err(Error::Access)?
        {
            if fields[0].is_some() {
                return Err(Error::Duplicate { node });
            }
            if fields[1].is_some() {
                return Err(Error::Order { node });
            }
            fields[0] = Some(node);
        } else if access
            .has_name(
                node,
                Name {
                    namespace: XADES,
                    local: "UnsignedDataObjectProperties",
                },
            )
            .map_err(Error::Access)?
        {
            if fields[1].is_some() {
                return Err(Error::Duplicate { node });
            }
            fields[1] = Some(node);
            let mut populated = false;
            for child in access.children(node) {
                let child = child.map_err(Error::Child)?;
                if !access
                    .has_name(
                        child,
                        Name {
                            namespace: XADES,
                            local: "UnsignedDataObjectProperty",
                        },
                    )
                    .map_err(Error::Access)?
                {
                    return Err(Error::Unexpected { node: child });
                }
                populated = true;
            }
            if !populated {
                return Err(Error::Missing {
                    parent: node,
                    local: "UnsignedDataObjectProperty",
                });
            }
        } else {
            return Err(Error::Unexpected { node });
        }
    }
    Ok(fields)
}

fn classify<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> PropertyResult<Role, X> {
    for local in [
        "CompleteCertificateRefs",
        "AttributeCertificateRefs",
        "SigAndRefsTimeStamp",
        "RefsOnlyTimeStamp",
        "ArchiveTimeStamp",
    ] {
        if access
            .has_name(
                node,
                Name {
                    namespace: XADES,
                    local,
                },
            )
            .map_err(Error::Access)?
        {
            return Err(Error::Forbidden { node });
        }
    }
    for (namespace, local, role) in [
        (XADES, "CounterSignature", Role::Counter),
        (XADES, "SignatureTimeStamp", Role::SignatureTimestamp),
        (XADES, "CertificateValues", Role::Certificates),
        (XADES, "RevocationValues", Role::Revocation),
        (
            XADES,
            "AttrAuthoritiesCertValues",
            Role::AttributeCertificates,
        ),
        (
            XADES,
            "AttributeRevocationValues",
            Role::AttributeRevocation,
        ),
        (XADES, "CompleteRevocationRefs", Role::RevocationReferences),
        (
            XADES,
            "AttributeRevocationRefs",
            Role::AttributeRevocationReferences,
        ),
        (
            XADES_141,
            "CompleteCertificateRefsV2",
            Role::CertificateReferences,
        ),
        (
            XADES_141,
            "AttributeCertificateRefsV2",
            Role::AttributeCertificateReferences,
        ),
        (
            XADES_141,
            "SigAndRefsTimeStampV2",
            Role::SignatureAndReferencesTimestamp,
        ),
        (XADES_141, "RefsOnlyTimeStampV2", Role::ReferencesTimestamp),
        (XADES_141, "AnyValidationData", Role::AnyValidation),
        (
            XADES_141,
            "TimeStampValidationData",
            Role::TimestampValidation,
        ),
        (XADES_141, "ArchiveTimeStamp", Role::Archive),
        (XADES_141, "RenewedDigestsV2", Role::RenewedDigests),
        (XADES_141, "SignaturePolicyStore", Role::PolicyStore),
    ] {
        if access
            .has_name(node, Name { namespace, local })
            .map_err(Error::Access)?
        {
            return Ok(role);
        }
    }
    let foreign = access
        .inspect(node, |value| {
            let crate::xml::Node::Element(name) = value else {
                return Ok(false);
            };
            if name.namespace.is_empty() {
                return Ok(false);
            }
            Ok(!access.equal(name.namespace, XADES)?)
        })
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })?;
    if !foreign {
        return Err(Error::Unexpected { node });
    }
    Ok(Role::Extension)
}
