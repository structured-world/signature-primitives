//! Original signed role claims, distinct from independently validated credentials.

use crate::container::XADES;
use crate::properties::{Error, PropertyResult, Reading};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Role-value syntax; signature coverage does not authenticate an external issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Signer's opaque self-asserted role.
    Claimed,
    /// Original encapsulated X509 attribute certificate.
    AttributeCertificate,
    /// Opaque other attribute certificate, needing an explicit format handler.
    OtherCertificate,
    /// Original signed assertion, needing its own selected-signature checking.
    Assertion,
}

/// Original value in its enclosing role group.
#[derive(Debug, Clone, Copy)]
pub struct Entry<N> {
    /// Original credential/claim payload node.
    pub node: N,
    /// Original containing group, not a reconstructed wrapper.
    pub group: N,
    /// Actual syntax role, without a trust conclusion.
    pub kind: Kind,
}

/// Original role catalogue for later credential/path/status processing.
#[derive(Debug)]
pub struct Roles<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    entries: OwnedVec<Entry<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Roles<N, D, G> {
    /// Original signed document/generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Signature protecting these original role claims.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original `SignerRoleV2` container.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original values, retaining all independently signed credentials.
    #[must_use]
    pub fn entries(&self) -> &[Entry<N>] {
        &self.entries
    }
}

/// Role catalogue using the XML owner's identity types.
pub type Catalogue<X> = Roles<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Reads the optional current role property through its original signed source.
/// EN319132-1 §5.2.6 / Annex C permits empty `SignerRoleV2`, but each present list
/// requires a member. `CertifiedRole` selects exactly one certificate syntax.
/// The resulting explicit credentials drive conditional validation-material
/// requirements; their presence must not become an issuer/authentication verdict.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &Reading<X>,
) -> PropertyResult<Option<Catalogue<X>>, X> {
    if access.snapshot() != signed.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: signed.parent(),
        }));
    }
    // Even absence belongs to the original current generation.
    access
        .query(signed.parent(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    let Some(node) = signed.role() else {
        return Ok(None);
    };
    read_node(access, signed.snapshot(), signed.signature(), node).map(Some)
}

// Counter actor discovery uses the SAME structural property sections and role
// kernel without requiring that a counter itself claims the root's B level.
pub(crate) fn locate<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
) -> PropertyResult<Option<X::Id>, X> {
    let (parent, _) = crate::properties::sections(access, layout)?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    let mut selected = None;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        if access
            .has_name(
                node,
                Name {
                    namespace: XADES,
                    local: "SignerRoleV2",
                },
            )
            .map_err(Error::Access)?
        {
            if selected.is_some() {
                return Err(Error::Duplicate { node });
            }
            selected = Some(node);
        }
    }
    Ok(selected)
}

// Caller has established whole-SignedProperties authentication and selected
// this original node from those properties, never an arbitrary external node.
pub(crate) fn read_node<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    node: X::Id,
) -> PropertyResult<Catalogue<X>, X> {
    if snapshot != access.snapshot() {
        return Err(Error::Access(AccessError::Changed { node }));
    }
    let mut entries = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    let mut previous = None;
    for child in access.children(node) {
        let group = child.map_err(Error::Child)?;
        let rank = rank(access, group)?;
        if previous == Some(rank) {
            return Err(Error::Duplicate { node: group });
        }
        if previous.is_some_and(|value| value > rank) {
            return Err(Error::Order { node: group });
        }
        previous = Some(rank);
        let mut populated = false;
        for child in access.children(group) {
            let child = child.map_err(Error::Child)?;
            let (payload, kind) = match rank {
                0 => {
                    expect(access, child, "ClaimedRole")?;
                    (child, Kind::Claimed)
                }
                1 => {
                    expect(access, child, "CertifiedRole")?;
                    credential(access, child)?
                }
                _ => {
                    expect(access, child, "SignedAssertion")?;
                    (child, Kind::Assertion)
                }
            };
            entries
                .try_push(Entry {
                    node: payload,
                    group,
                    kind,
                })
                .map_err(|cause| Error::Resource { node: child, cause })?;
            populated = true;
        }
        if !populated {
            return Err(Error::Missing {
                parent: group,
                local: "role value",
            });
        }
    }
    Ok(Roles {
        snapshot,
        signature,
        node,
        entries: entries.into_owned(),
    })
}

fn rank<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> PropertyResult<usize, X> {
    for (rank, local) in ["ClaimedRoles", "CertifiedRolesV2", "SignedAssertions"]
        .into_iter()
        .enumerate()
    {
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
            return Ok(rank);
        }
    }
    Err(Error::Unexpected { node })
}

fn expect<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &'static str,
) -> PropertyResult<(), X> {
    if !access
        .has_name(
            node,
            Name {
                namespace: XADES,
                local,
            },
        )
        .map_err(Error::Access)?
    {
        return Err(Error::Unexpected { node });
    }
    Ok(())
}

fn credential<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PropertyResult<(X::Id, Kind), X> {
    let mut children = access.children(node);
    let value = children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent: node,
            local: "attribute certificate",
        })?;
    let kind = if access
        .has_name(
            value,
            Name {
                namespace: XADES,
                local: "X509AttributeCertificate",
            },
        )
        .map_err(Error::Access)?
    {
        Kind::AttributeCertificate
    } else {
        expect(access, value, "OtherAttributeCertificate")?;
        Kind::OtherCertificate
    };
    if let Some(extra) = children.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    Ok((value, kind))
}
