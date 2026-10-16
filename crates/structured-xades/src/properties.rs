//! Bound original signed-property roles, before their scalar/PKI checks.

use crate::binding::Bound;
use crate::container::{DS, XADES};
use crate::xml::{Access, AccessError, ChildError, Name, Node, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

mod claimed_time;
pub use claimed_time::{
    CalendarFact, CalendarValue, CalendarXml, ClaimedTime, ClaimedTimeBinding, ClaimedTimeError,
    ClaimedTimeFailure, ClaimedTimeResult, DateTimeFact, DateTimeXml, check_time,
};

const SIGNATURE_PROPERTIES: &[&str] = &[
    "SigningTime",
    "SigningCertificateV2",
    "SignaturePolicyIdentifier",
    "SignatureProductionPlaceV2",
    "SignerRoleV2",
];
const LEGACY_PROPERTIES: &[&str] = &[
    "SigningCertificate",
    "SignatureProductionPlace",
    "SignerRole",
];
const OBJECT_PROPERTIES: &[&str] = &[
    "DataObjectFormat",
    "CommitmentTypeIndication",
    "AllDataObjectsTimeStamp",
    "IndividualDataObjectsTimeStamp",
];

/// Schema role of an authenticated original data-object property.
/// Scalar contents, referenced object selection and timestamp checks are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataObjectRole {
    /// Description, identifier, MIME type and encoding of a referenced object.
    Format,
    /// Original commitment type and its selected data-object references.
    Commitment,
    /// Timestamp on all selected signature data objects.
    AllTimestamp,
    /// Timestamp on explicitly selected signature data objects.
    IndividualTimestamp,
    /// Original schema-permitted foreign-namespace property.
    Extension,
}

/// One original property within the fully authenticated `SignedProperties`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataObject<N> {
    /// Original element, never a reconstructed property or URI string.
    pub node: N,
    /// Structural role; this does not assert the property's semantic validity.
    pub role: DataObjectRole,
}

/// Complete structural data-object property catalogue in its original order.
#[derive(Debug)]
pub struct DataObjects<N> {
    parent: N,
    entries: OwnedVec<DataObject<N>>,
}

impl<N: Copy> DataObjects<N> {
    /// Original `SignedDataObjectProperties` element.
    #[must_use]
    pub fn parent(&self) -> N {
        self.parent
    }

    /// Original entries, all protected by the enclosing selected binding.
    /// Taking this slice performs no traversal; later processing must be funded.
    #[must_use]
    pub fn entries(&self) -> &[DataObject<N>] {
        &self.entries
    }
}

/// Failure selecting the signed signature properties of this baseline.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Caller selected no property of the requested original schema role.
    Selection {
        /// Original signed property container.
        parent: N,
        /// Caller-provided data-object property ordinal.
        index: usize,
    },
    /// Present simple content violates the named property's lexical contract.
    Lexical {
        /// Original value element; no physical XML byte offset is invented.
        node: N,
        /// Schema/property local name.
        local: &'static str,
    },
    /// Original XML/source/current-operation refusal.
    Access(AccessError<E, N>),
    /// Original element-only container failure.
    Child(ChildError<E, N>),
    /// A required original property is absent.
    Missing {
        /// Original enclosing node.
        parent: N,
        /// Required property's local name.
        local: &'static str,
    },
    /// A singleton property occurs more than once.
    Duplicate {
        /// Repeated original property.
        node: N,
    },
    /// Original property is outside its schema sequence position.
    Order {
        /// Original out-of-order property.
        node: N,
    },
    /// Legacy property explicitly excluded by the current baseline.
    Forbidden {
        /// Original excluded property.
        node: N,
    },
    /// This namespace/name has no role in the container's schema.
    Unexpected {
        /// Original unexpected node.
        node: N,
    },
    /// Extension metadata could not be retained before storage growth.
    Resource {
        /// Original extension node.
        node: N,
        /// Original allocation/work refusal.
        cause: MemoryError,
    },
}

/// Selected original roles authenticated by the bound signature's full coverage.
///
/// This is a structural reading, not a baseline-level assertion: `SigningTime`
/// lexical validation, certificate digest binding, and optional property content
/// checks remain necessary. Unknown foreign-namespace extensions are retained
/// for explicit processing, never silently interpreted as known properties.
pub struct Signed<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    parent: N,
    time: N,
    certificate: N,
    policy: Option<N>,
    place: Option<N>,
    role: Option<N>,
    extensions: OwnedVec<N>,
    objects: Option<DataObjects<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Signed<N, D, G> {
    /// Original source generation carrying all selected properties.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Exact selected signature authenticating these original properties.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original `SignedSignatureProperties` node.
    #[must_use]
    pub fn parent(&self) -> N {
        self.parent
    }
    /// Original claimed `SigningTime`; no UTC/trust claim is made by this reading.
    #[must_use]
    pub fn signing_time(&self) -> N {
        self.time
    }
    /// Original mandatory `SigningCertificateV2`, before its PKI binding check.
    #[must_use]
    pub fn signing_certificate(&self) -> N {
        self.certificate
    }
    /// Original optional policy identifier, before policy-content validation.
    #[must_use]
    pub fn policy(&self) -> Option<N> {
        self.policy
    }
    /// Original optional `SignatureProductionPlaceV2`.
    #[must_use]
    pub fn place(&self) -> Option<N> {
        self.place
    }
    /// Original optional `SignerRoleV2`.
    #[must_use]
    pub fn role(&self) -> Option<N> {
        self.role
    }
    /// Original foreign-namespace extension identities, in document order.
    #[must_use]
    pub fn extensions(&self) -> &[N] {
        &self.extensions
    }

    /// Original optional signed data-object property catalogue. Empty and absent
    /// remain distinct; no timestamp or referenced-object assertion is inferred.
    #[must_use]
    pub fn data_objects(&self) -> Option<&DataObjects<N>> {
        self.objects.as_ref()
    }
}

/// Reading using the selected XML owner's original identities.
pub type Reading<X> = Signed<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// Failure retaining original source and XML owner causes.
pub type PropertyResult<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// Rejects element children of a simple-typed property. XML character validity
/// and normalization are already established by the original XML owner; this
/// only enforces the schema's absence of element children, without collecting
/// text, trimming whitespace or substituting scalar lexical validation.
pub(crate) fn simple_content<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<(), X> {
    let mut child = access.first_child(parent).map_err(Error::Access)?;
    while let Some(node) = child {
        if access
            .inspect(node, |value| matches!(value, Node::Element(_)))
            .map_err(Error::Access)?
        {
            return Err(Error::Unexpected { node });
        }
        child = access.next_sibling(parent, node).map_err(Error::Access)?;
    }
    Ok(())
}

/// The shared `DigestAlgAndValueType` grammar used by certificate and policy
/// references. Selected algorithm parameters/base64 decoding belong to their
/// existing owner kernels, not another XML/crypto parser here.
pub(crate) fn digest_value<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<(X::Id, X::Id), X> {
    let mut children = access.children(parent);
    let method = children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent,
            local: "DigestMethod",
        })?;
    if !access
        .has_name(
            method,
            Name {
                namespace: DS,
                local: "DigestMethod",
            },
        )
        .map_err(Error::Access)?
    {
        return Err(Error::Unexpected { node: method });
    }
    let value = children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent,
            local: "DigestValue",
        })?;
    if !access
        .has_name(
            value,
            Name {
                namespace: DS,
                local: "DigestValue",
            },
        )
        .map_err(Error::Access)?
    {
        return Err(Error::Unexpected { node: value });
    }
    if let Some(extra) = children.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    simple_content(access, value)?;
    Ok((method, value))
}

pub(crate) type Sections<X> = (Option<<X as Xml>::Id>, Option<<X as Xml>::Id>);

// One structural SignedProperties field kernel. An incorporated counter's
// credential census does not impose the root's current baseline requirements.
pub(crate) fn sections<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
) -> PropertyResult<Sections<X>, X> {
    if layout.snapshot() != access.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: layout.signed(),
        }));
    }
    let mut parent = None;
    let mut objects = None;
    for child in access.children(layout.signed()) {
        let node = child.map_err(Error::Child)?;
        if named(access, node, "SignedSignatureProperties")? {
            if parent.is_some() {
                return Err(Error::Duplicate { node });
            }
            if objects.is_some() {
                return Err(Error::Order { node });
            }
            parent = Some(node);
        } else if named(access, node, "SignedDataObjectProperties")? {
            if objects.is_some() {
                return Err(Error::Duplicate { node });
            }
            objects = Some(node);
        } else {
            return Err(Error::Unexpected { node });
        }
    }
    Ok((parent, objects))
}

/// Selects the current baseline's original signed signature-property roles.
///
/// EN319132-1 V1.3.1 §6.3/Table2 requires `SigningTime` and `SigningCertificateV2`,
/// and excludes their legacy certificate/place/role alternatives. The schema's
/// sequence and singleton cardinalities still apply in addition to the table.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
) -> PropertyResult<Reading<X>, X> {
    let layout = bound.containers();
    let (parent, objects) = sections(access, layout)?;
    let parent = parent.ok_or(Error::Missing {
        parent: layout.signed(),
        local: "SignedSignatureProperties",
    })?;
    let mut fields = [None; 5];
    let mut previous = 0;
    let mut extensions = access
        .query(parent, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        let kind = classify(access, node, SIGNATURE_PROPERTIES, LEGACY_PROPERTIES)?;
        let rank = match kind {
            Kind::Known(rank) => {
                if fields[rank].is_some() {
                    return Err(Error::Duplicate { node });
                }
                fields[rank] = Some(node);
                rank
            }
            Kind::Extension => {
                extensions
                    .try_push(node)
                    .map_err(|cause| Error::Resource { node, cause })?;
                SIGNATURE_PROPERTIES.len()
            }
            Kind::Forbidden => return Err(Error::Forbidden { node }),
            Kind::Unexpected => return Err(Error::Unexpected { node }),
        };
        if rank < previous {
            return Err(Error::Order { node });
        }
        previous = rank;
    }
    let time = fields[0].ok_or(Error::Missing {
        parent,
        local: "SigningTime",
    })?;
    let certificate = fields[1].ok_or(Error::Missing {
        parent,
        local: "SigningCertificateV2",
    })?;
    simple_content(access, time)?;
    if let Some(place) = fields[3] {
        production_place(access, place)?;
    }
    let objects = objects
        .map(|parent| read_objects(access, parent))
        .transpose()?;
    Ok(Signed {
        snapshot: layout.snapshot(),
        signature: layout.signature(),
        parent,
        time,
        certificate,
        policy: fields[2],
        place: fields[3],
        role: fields[4],
        extensions: extensions.into_owned(),
        objects,
    })
}

fn production_place<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<(), X> {
    // EN319132-1 V1.3.1 §5.2.5: V2 includes StreetAddress in this position,
    // and an empty property must not be generated although the XSD permits it.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    const FIELDS: &[&str] = &[
        "City",
        "StreetAddress",
        "StateOrProvince",
        "PostalCode",
        "CountryName",
    ];
    let mut seen = [false; 5];
    let mut previous = None;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        let rank = match classify(access, node, FIELDS, &[])? {
            Kind::Known(rank) => rank,
            Kind::Forbidden | Kind::Unexpected | Kind::Extension => {
                return Err(Error::Unexpected { node });
            }
        };
        if seen[rank] {
            return Err(Error::Duplicate { node });
        }
        if let Some(previous) = previous
            && rank < previous
        {
            return Err(Error::Order { node });
        }
        seen[rank] = true;
        previous = Some(rank);
        simple_content(access, node)?;
    }
    if previous.is_none() {
        return Err(Error::Missing {
            parent,
            local: "production-place field",
        });
    }
    Ok(())
}

enum Kind {
    Known(usize),
    Extension,
    Forbidden,
    Unexpected,
}

fn classify<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    known: &[&str],
    forbidden: &[&str],
) -> PropertyResult<Kind, X> {
    access
        .inspect(node, |value| {
            let Node::Element(actual) = value else {
                return Ok(Kind::Unexpected);
            };
            // XSD 1.0 §3.10.4, Wildcard allows Namespace Name 2.3:
            // ##other does not include an absent namespace.
            // https://www.w3.org/TR/xmlschema-1/#cvc-wildcard-namespace
            if actual.namespace.is_empty() {
                return Ok(Kind::Unexpected);
            }
            if !access.equal(actual.namespace, XADES)? {
                return Ok(Kind::Extension);
            }
            for (rank, local) in known.iter().enumerate() {
                if access.equal(actual.local, local)? {
                    return Ok(Kind::Known(rank));
                }
            }
            for local in forbidden {
                if access.equal(actual.local, local)? {
                    return Ok(Kind::Forbidden);
                }
            }
            Ok(Kind::Unexpected)
        })
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })
}

pub(crate) fn read_objects<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<DataObjects<X::Id>, X> {
    // EN319132-1 V1.3.1 Annex C: each known sequence member is optional and
    // repeatable; foreign ##other properties follow every known member.
    // https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd
    let mut entries = access
        .query(parent, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    let mut previous = 0;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        let (rank, role) = match classify(access, node, OBJECT_PROPERTIES, &[])? {
            Kind::Known(rank) => {
                let roles = [
                    DataObjectRole::Format,
                    DataObjectRole::Commitment,
                    DataObjectRole::AllTimestamp,
                    DataObjectRole::IndividualTimestamp,
                ];
                debug_assert!(rank < roles.len());
                (rank, roles[rank])
            }
            Kind::Extension => (OBJECT_PROPERTIES.len(), DataObjectRole::Extension),
            Kind::Forbidden | Kind::Unexpected => return Err(Error::Unexpected { node }),
        };
        if rank < previous {
            return Err(Error::Order { node });
        }
        entries
            .try_push(DataObject { node, role })
            .map_err(|cause| Error::Resource { node, cause })?;
        previous = rank;
    }
    Ok(DataObjects {
        parent,
        entries: entries.into_owned(),
    })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &str,
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
