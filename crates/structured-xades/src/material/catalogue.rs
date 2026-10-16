//! Structural material catalogues; completeness is established from actual paths.

use super::Kind;
use crate::container::XADES;
use crate::properties::{Error, PropertyResult};
use crate::xml::{Access, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// One original value in a validation-material property, in document order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry<N> {
    /// A specified ASN.1 material encoding, not yet parsed or authenticated.
    Encapsulated {
        /// Original encapsulated-value node.
        node: N,
        /// Actual PKI schema specified for that node.
        kind: Kind,
    },
    /// Schema-permitted non-X509 certificate. Presence cannot satisfy a required
    /// X509 path certificate merely by being counted as a material entry.
    OtherCertificate {
        /// Original opaque `OtherCertificate` element.
        node: N,
    },
    /// Schema-permitted other status format. It is not a CRL or OCSP response
    /// without an explicit qualified format recognizer and authentication path.
    OtherStatus {
        /// Original opaque `OtherValue` element.
        node: N,
    },
}

/// Original complete structural catalogue, separate from material validation.
#[derive(Debug)]
pub struct Catalogue<N, D, G> {
    snapshot: Snapshot<D, G>,
    parent: N,
    entries: OwnedVec<Entry<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Catalogue<N, D, G> {
    /// Original XML document/generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }

    /// Original certificate/revocation-values element, including attribute roles.
    #[must_use]
    pub fn parent(&self) -> N {
        self.parent
    }

    /// Original entries in document order. Obtaining the slice performs no scan;
    /// consumers must fund their subsequent data-dependent processing.
    #[must_use]
    pub fn entries(&self) -> &[Entry<N>] {
        &self.entries
    }
}

/// Catalogue using the XML owner's source identities.
pub type Reading<X> = Catalogue<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

// Original material roles shared by retention and conditional-copy checks.
// This is not a baseline inventory: plain/older counters do not acquire the
// root's B-level property prohibitions merely by carrying validation values.
#[derive(Clone, Copy)]
pub(super) enum ContainerKind {
    Certificates,
    Revocation,
    AttributeCertificates,
    AttributeRevocation,
}

impl ContainerKind {
    pub(super) fn attribute(self) -> bool {
        matches!(
            self,
            Self::AttributeCertificates | Self::AttributeRevocation
        )
    }
    pub(super) fn certificates(self) -> bool {
        matches!(self, Self::Certificates | Self::AttributeCertificates)
    }
    pub(super) fn inventory(role: crate::unsigned::Role) -> Option<Self> {
        match role {
            crate::unsigned::Role::Certificates => Some(Self::Certificates),
            crate::unsigned::Role::Revocation => Some(Self::Revocation),
            crate::unsigned::Role::AttributeCertificates => Some(Self::AttributeCertificates),
            crate::unsigned::Role::AttributeRevocation => Some(Self::AttributeRevocation),
            _ => None,
        }
    }
}

pub(super) fn container_kind<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PropertyResult<Option<ContainerKind>, X> {
    for (local, kind) in [
        ("CertificateValues", ContainerKind::Certificates),
        ("RevocationValues", ContainerKind::Revocation),
        (
            "AttrAuthoritiesCertValues",
            ContainerKind::AttributeCertificates,
        ),
        (
            "AttributeRevocationValues",
            ContainerKind::AttributeRevocation,
        ),
    ] {
        if named(access, node, local)? {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}

/// Reads one complete material property, without decoding or provider side effects.
///
/// EN319132-1 V1.3.1 Annex C's normative schema permits an empty
/// `CertificateValues` choice and an empty `RevocationValues` sequence. A present
/// CRL/OCSP/other-status group instead requires at least one member. These schema
/// facts do not prove or disprove the conditional B-LT material completeness.
/// <https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<Reading<X>, X> {
    // Annex C gives attribute-authority containers the SAME value types.
    // Their conditional role/authentication rules remain with the profile,
    // not a second certificate/revocation grammar here.
    let kind = container_kind(access, parent)?.ok_or(Error::Unexpected { node: parent })?;
    let certificates = kind.certificates();
    let mut entries = access
        .query(parent, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    if certificates {
        for child in access.children(parent) {
            let node = child.map_err(Error::Child)?;
            let entry = if named(access, node, "EncapsulatedX509Certificate")? {
                Entry::Encapsulated {
                    node,
                    kind: Kind::Certificate,
                }
            } else if named(access, node, "OtherCertificate")? {
                Entry::OtherCertificate { node }
            } else {
                return Err(Error::Unexpected { node });
            };
            entries
                .try_push(entry)
                .map_err(|cause| Error::Resource { node, cause })?;
        }
    } else {
        let mut previous = None;
        for child in access.children(parent) {
            let group = child.map_err(Error::Child)?;
            let (rank, member, kind) = if named(access, group, "CRLValues")? {
                (0, "EncapsulatedCRLValue", Some(Kind::Crl))
            } else if named(access, group, "OCSPValues")? {
                (1, "EncapsulatedOCSPValue", Some(Kind::Ocsp))
            } else if named(access, group, "OtherValues")? {
                (2, "OtherValue", None)
            } else {
                return Err(Error::Unexpected { node: group });
            };
            if let Some(earlier) = previous {
                if rank == earlier {
                    return Err(Error::Duplicate { node: group });
                }
                if rank < earlier {
                    return Err(Error::Order { node: group });
                }
            }
            previous = Some(rank);
            let mut present = false;
            for child in access.children(group) {
                let node = child.map_err(Error::Child)?;
                if !named(access, node, member)? {
                    return Err(Error::Unexpected { node });
                }
                let entry = match kind {
                    Some(kind) => Entry::Encapsulated { node, kind },
                    None => Entry::OtherStatus { node },
                };
                entries
                    .try_push(entry)
                    .map_err(|cause| Error::Resource { node, cause })?;
                present = true;
            }
            if !present {
                return Err(Error::Missing {
                    parent: group,
                    local: member,
                });
            }
        }
    }
    Ok(Catalogue {
        snapshot: access.snapshot(),
        parent,
        entries: entries.into_owned(),
    })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &'static str,
) -> PropertyResult<bool, X> {
    access
        .has_name(
            node,
            Name {
                namespace: XADES,
                local,
            },
        )
        .map_err(Error::Access)
}
