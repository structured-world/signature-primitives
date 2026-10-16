//! Annex A original reference fields, distinct from authenticated material.

use crate::{
    certificate,
    container::XADES,
    properties::{self, Error, PropertyResult},
    timestamp::XADES_141,
    unsigned,
    xml::{Access, Name, Snapshot, Xml},
};
use structured_asn1::memory::{OwnedVec, Work};

/// Referenced artifact schema; no issuer, presence or digest agreement follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceKind {
    /// One certificate reference from an unsigned V2 reference property.
    Certificate,
    /// One CRL reference.
    Crl,
    /// One OCSP response reference.
    Ocsp,
    /// An original open-format `OtherRef`, requiring separate interpretation.
    Other,
}

/// Original scalar obligation, retained without copying a normalized value.
#[derive(Clone, Copy, Debug)]
pub enum ReferenceField<N> {
    /// Optional original unqualified URI attribute.
    Uri(N),
    /// Arbitrary-width XSD1.0 integer simple content.
    Integer(N),
    /// XSD1.0 dateTime simple content; no implicit timezone is introduced.
    DateTime(N),
    /// Original base64Binary simple content.
    Binary(N),
}

/// Original artifact identifier, retained for actual semantic comparison.
/// These selectors neither authenticate a responder nor override digest bytes.
#[derive(Clone, Copy, Debug)]
pub enum ReferenceIdentifier<N> {
    /// No identifier was written (or the entry is an opaque `OtherRef`).
    Absent,
    /// Optional DER RFC5035 issuer/serial hint on an original certificate entry.
    Certificate {
        /// Original base64 `IssuerSerialV2` element.
        issuer_serial: N,
    },
    /// Original CRL identifier fields; Number and URI are acquisition hints.
    Crl {
        /// Original `CRLIdentifier` carrying the optional URI attribute.
        node: N,
        /// Original RFC4514 distinguished-name string.
        issuer: N,
        /// Original XSD1.0 issue time.
        time: N,
        /// Original arbitrary-width CRL number, when written.
        number: Option<N>,
    },
    /// Original OCSP responder identifier and production time.
    Ocsp {
        /// Original `OCSPIdentifier` carrying the optional URI attribute.
        node: N,
        /// Selected original responder schema branch.
        responder: ResponderIdentifier<N>,
        /// Original XSD1.0 production time.
        time: N,
    },
}

/// Original OCSP responder choice; name and key hash cannot be interchanged.
#[derive(Clone, Copy, Debug)]
pub enum ResponderIdentifier<N> {
    /// Original RFC4514 distinguished-name string.
    Name(N),
    /// Original base64 DER byKey field, as specified by Annex A.1.2.
    Key(N),
}

/// Parsed field selectors of one original reference. This type cannot replace
/// the protected signing-certificate reference catalogue in key/path checking.
pub struct ReferenceEntry<N> {
    node: N,
    kind: ReferenceKind,
    digest: Option<(N, N)>,
    identifier: ReferenceIdentifier<N>,
}

impl<N: Copy> ReferenceEntry<N> {
    /// Original `Cert`, `CRLRef`, `OCSPRef` or opaque `OtherRef`.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Actual artifact schema, not validation or authentication.
    #[must_use]
    pub fn kind(&self) -> ReferenceKind {
        self.kind
    }
    /// Original method/value nodes when this schema carries a digest.
    #[must_use]
    pub fn digest(&self) -> Option<(N, N)> {
        self.digest
    }
    /// Original identifier selectors, without reparsing the reference grammar.
    #[must_use]
    pub fn identifier(&self) -> ReferenceIdentifier<N> {
        self.identifier
    }
    /// Fixed-size scalar obligations derived from the same identifier model.
    /// No copied catalogue or normalized string storage is retained.
    #[must_use]
    pub fn fields(&self) -> [Option<ReferenceField<N>>; 4] {
        let digest = self.digest.map(|(_, node)| ReferenceField::Binary(node));
        match self.identifier {
            ReferenceIdentifier::Certificate { issuer_serial } => [
                digest,
                Some(ReferenceField::Uri(self.node)),
                Some(ReferenceField::Binary(issuer_serial)),
                None,
            ],
            ReferenceIdentifier::Crl {
                node, time, number, ..
            } => [
                digest,
                Some(ReferenceField::DateTime(time)),
                Some(ReferenceField::Uri(node)),
                number.map(ReferenceField::Integer),
            ],
            ReferenceIdentifier::Ocsp {
                node,
                responder,
                time,
            } => [
                match responder {
                    ResponderIdentifier::Key(node) => Some(ReferenceField::Binary(node)),
                    ResponderIdentifier::Name(_) => None,
                },
                Some(ReferenceField::DateTime(time)),
                Some(ReferenceField::Uri(node)),
                digest,
            ],
            ReferenceIdentifier::Absent => [
                digest,
                if self.kind == ReferenceKind::Certificate {
                    Some(ReferenceField::Uri(self.node))
                } else {
                    None
                },
                None,
                None,
            ],
        }
    }
}

/// One complete original unsigned reference property. Original certificate
/// paths, authority restrictions and actual artifact comparisons remain separate.
pub struct ReferenceProperty<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    role: unsigned::Role,
    entries: OwnedVec<ReferenceEntry<N>>,
}

impl<N: Copy, D: Copy, G: Copy> ReferenceProperty<N, D, G> {
    /// Original document/generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Root owning this exact unsigned property.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original reference property.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Ordinary versus attribute certificate/status reference role.
    #[must_use]
    pub fn role(&self) -> unsigned::Role {
        self.role
    }
    /// Complete original ordered references, including opaque ones.
    #[must_use]
    pub fn entries(&self) -> &[ReferenceEntry<N>] {
        &self.entries
    }
}

type Reading<X> = ReferenceProperty<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

// EN319132-1 V1.3.1 Annex A.1.1–A.1.4/C: each written group is nonempty.
// A.1.2 additionally forbids empty CompleteRevocationRefs despite the XSD's
// individually optional groups; schema optionality alone is insufficient.
// V2's local CertRefs is in 1.4.1; the imported CertIDListV2's Cert is in 1.3.2.
// https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
pub(crate) fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    original: unsigned::Entry<X::Id>,
) -> PropertyResult<Reading<X>, X> {
    let node = original.node;
    let mut entries = access.execution().vector();
    match original.role {
        unsigned::Role::CertificateReferences | unsigned::Role::AttributeCertificateReferences => {
            let mut children = access.children(node);
            let list = required(&mut children, node, "CertRefs")?;
            expect(access, list, XADES_141, "CertRefs")?;
            finish(&mut children)?;
            read_group(access, list, ReferenceKind::Certificate, &mut entries)?;
        }
        unsigned::Role::RevocationReferences | unsigned::Role::AttributeRevocationReferences => {
            let mut prior = None;
            for child in access.children(node) {
                let child = child.map_err(Error::Child)?;
                let (rank, kind) = if named(access, child, XADES, "CRLRefs")? {
                    (0, ReferenceKind::Crl)
                } else if named(access, child, XADES, "OCSPRefs")? {
                    (1, ReferenceKind::Ocsp)
                } else if named(access, child, XADES, "OtherRefs")? {
                    (2, ReferenceKind::Other)
                } else {
                    return Err(Error::Unexpected { node: child });
                };
                if let Some(previous) = prior {
                    if rank == previous {
                        return Err(Error::Duplicate { node: child });
                    }
                    if rank < previous {
                        return Err(Error::Order { node: child });
                    }
                }
                prior = Some(rank);
                read_group(access, child, kind, &mut entries)?;
            }
            if original.role == unsigned::Role::RevocationReferences && entries.is_empty() {
                return Err(Error::Missing {
                    parent: node,
                    local: "CRLRefs, OCSPRefs or OtherRefs",
                });
            }
        }
        _ => return Err(Error::Unexpected { node }),
    }
    Ok(ReferenceProperty {
        snapshot: access.snapshot(),
        signature,
        node,
        role: original.role,
        entries: entries.into_owned(),
    })
}

fn read_group<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    kind: ReferenceKind,
    entries: &mut OwnedVec<ReferenceEntry<X::Id>, W>,
) -> PropertyResult<(), X> {
    let local = match kind {
        ReferenceKind::Certificate => "Cert",
        ReferenceKind::Crl => "CRLRef",
        ReferenceKind::Ocsp => "OCSPRef",
        ReferenceKind::Other => "OtherRef",
    };
    let mut found = false;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        expect(access, node, XADES, local)?;
        let mut entry = ReferenceEntry {
            node,
            kind,
            digest: None,
            identifier: ReferenceIdentifier::Absent,
        };
        match kind {
            ReferenceKind::Certificate => {
                let reference = certificate::read_entry(access, node)?;
                entry.digest = Some((reference.method(), reference.digest()));
                if let Some(issuer) = reference.issuer_serial() {
                    properties::simple_content(access, issuer)?;
                    entry.identifier = ReferenceIdentifier::Certificate {
                        issuer_serial: issuer,
                    };
                }
            }
            ReferenceKind::Crl => crl(access, &mut entry)?,
            ReferenceKind::Ocsp => ocsp(access, &mut entry)?,
            ReferenceKind::Other => {}
        }
        entries
            .try_push(entry)
            .map_err(|cause| Error::Resource { node, cause })?;
        found = true;
    }
    if !found {
        return Err(Error::Missing { parent, local });
    }
    Ok(())
}

fn crl<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    entry: &mut ReferenceEntry<X::Id>,
) -> PropertyResult<(), X> {
    let mut children = access.children(entry.node);
    let digest = required(&mut children, entry.node, "DigestAlgAndValue")?;
    expect(access, digest, XADES, "DigestAlgAndValue")?;
    let (method, value) = properties::digest_value(access, digest)?;
    entry.digest = Some((method, value));
    if let Some(identifier) = children.next() {
        let identifier = identifier.map_err(Error::Child)?;
        expect(access, identifier, XADES, "CRLIdentifier")?;
        let mut fields = access.children(identifier);
        let issuer = required(&mut fields, identifier, "Issuer")?;
        simple(access, issuer, "Issuer")?;
        let time = required(&mut fields, identifier, "IssueTime")?;
        simple(access, time, "IssueTime")?;
        let mut crl_number = None;
        if let Some(number) = fields.next() {
            let number = number.map_err(Error::Child)?;
            simple(access, number, "Number")?;
            crl_number = Some(number);
        }
        finish(&mut fields)?;
        entry.identifier = ReferenceIdentifier::Crl {
            node: identifier,
            issuer,
            time,
            number: crl_number,
        };
    }
    finish(&mut children)
}

fn ocsp<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    entry: &mut ReferenceEntry<X::Id>,
) -> PropertyResult<(), X> {
    let mut children = access.children(entry.node);
    let identifier = required(&mut children, entry.node, "OCSPIdentifier")?;
    expect(access, identifier, XADES, "OCSPIdentifier")?;
    let mut fields = access.children(identifier);
    let responder = required(&mut fields, identifier, "ResponderID")?;
    expect(access, responder, XADES, "ResponderID")?;
    let mut choice = access.children(responder);
    let value = required(&mut choice, responder, "ByName or ByKey")?;
    let responder = if named(access, value, XADES, "ByKey")? {
        ResponderIdentifier::Key(value)
    } else {
        expect(access, value, XADES, "ByName")?;
        ResponderIdentifier::Name(value)
    };
    properties::simple_content(access, value)?;
    finish(&mut choice)?;
    let time = required(&mut fields, identifier, "ProducedAt")?;
    simple(access, time, "ProducedAt")?;
    finish(&mut fields)?;
    entry.identifier = ReferenceIdentifier::Ocsp {
        node: identifier,
        responder,
        time,
    };
    if let Some(digest) = children.next() {
        let digest = digest.map_err(Error::Child)?;
        expect(access, digest, XADES, "DigestAlgAndValue")?;
        let (method, value) = properties::digest_value(access, digest)?;
        entry.digest = Some((method, value));
    }
    finish(&mut children)
}

fn required<X: Xml, W: Work>(
    children: &mut crate::xml::Children<'_, '_, X, W>,
    parent: X::Id,
    local: &'static str,
) -> PropertyResult<X::Id, X> {
    children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing { parent, local })
}
fn finish<X: Xml, W: Work>(
    children: &mut crate::xml::Children<'_, '_, X, W>,
) -> PropertyResult<(), X> {
    if let Some(extra) = children.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    Ok(())
}
fn simple<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &str,
) -> PropertyResult<(), X> {
    expect(access, node, XADES, local)?;
    properties::simple_content(access, node)
}
fn expect<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> PropertyResult<(), X> {
    if !named(access, node, namespace, local)? {
        return Err(Error::Unexpected { node });
    }
    Ok(())
}
fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> PropertyResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(Error::Access)
}
