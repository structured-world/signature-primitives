//! Directly incorporated ETSI TS 101 903 V1.2.2 qualifying properties.
//!
//! Read the original layout with [`crate::container::locate_with_syntax`].
//! Legacy evidence has a separate type from the EN baseline preparation.
//! <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.02.02_60/ts_101903v010202p.pdf>

use crate::binding::{self, SignatureXml};
use crate::container::{self, DS, XADES_122};
use crate::properties;
use crate::scalar::{self, ScalarXml};
use crate::xml::{Access, Name, Node, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

mod signer;
pub mod timestamp;
pub use signer::{
    CertificateMatch, SignerCheck, SignerError, SignerResult, SigningReferences, check_signer,
};

/// Original V1.2.2 container identities selected under caller policy.
pub struct Layout<X: Xml>(container::Layout<X>);

impl<X: Xml> Layout<X> {
    pub(crate) fn new(original: container::Layout<X>) -> Self {
        Self(original)
    }

    /// Original signature carrying the qualifying properties.
    #[must_use]
    pub fn signature(&self) -> X::Id {
        self.0.signature()
    }

    /// Original source of these element identities.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.0.snapshot()
    }

    /// Original signed-properties container.
    #[must_use]
    pub fn signed(&self) -> X::Id {
        self.0.signed()
    }

    /// Original optional unsigned-properties container, including empty ones.
    #[must_use]
    pub fn unsigned(&self) -> Option<X::Id> {
        self.0.unsigned()
    }
}

/// Why original legacy property preparation stopped.
#[derive(Debug)]
pub enum Error<E, N> {
    /// The selected signature or the required authenticated coverage failed.
    Binding(binding::BindingError<E, N>),
    /// An original property did not satisfy the applicable grammar.
    Property(properties::Error<E, N>),
    /// The original serial element could not establish an XML Schema integer.
    Serial(scalar::Error<E, N>),
}

impl<E, N> From<properties::Error<E, N>> for Error<E, N> {
    fn from(error: properties::Error<E, N>) -> Self {
        Self::Property(error)
    }
}

/// Located processing result for the original XML source.
pub type Result<T, X> = core::result::Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// Original signer-certificate protection selected by §4.4.1.
pub enum SignerCertificate<X: Xml> {
    /// Original signed V1 certificate identifiers in their supplied order.
    References(SigningReferences<X>),
    /// The selected signature authenticates this complete original `KeyInfo`.
    KeyInfo {
        /// Original `KeyInfo` node.
        node: X::Id,
        /// Original `SignedInfo` reference providing element coverage.
        reference: X::Id,
        /// Embedded `X509Certificate` elements in their original order.
        certificates: OwnedVec<X::Id>,
    },
}

/// An original property and its position in a V1.2.2 schema sequence.
#[derive(Debug, Clone, Copy)]
pub struct Property<N> {
    /// Original element identity.
    pub node: N,
    /// Normative local name identifying its structural role.
    pub name: &'static str,
}

/// Original authenticated layout and schema-selected legacy properties.
///
/// Certificate/key comparison, optional property content and timestamp checks
/// still have to complete before a relying party can use their results.
pub struct Prepared<X: Xml> {
    bound: binding::Selected<X>,
    signed: OwnedVec<Property<X::Id>>,
    data: OwnedVec<Property<X::Id>>,
    unsigned: OwnedVec<Property<X::Id>>,
    objects: OwnedVec<Property<X::Id>>,
    signer: SignerCertificate<X>,
}

impl<X: Xml> Prepared<X> {
    /// Original signer-certificate protection offered by the document.
    #[must_use]
    pub fn signer(&self) -> &SignerCertificate<X> {
        &self.signer
    }

    /// Original signed signature properties, in schema/document order.
    #[must_use]
    pub fn signed(&self) -> &[Property<X::Id>] {
        &self.signed
    }

    /// Original signed data-object properties, in schema/document order.
    #[must_use]
    pub fn signed_objects(&self) -> &[Property<X::Id>] {
        &self.data
    }

    /// Original unsigned signature properties, in schema/document order.
    #[must_use]
    pub fn unsigned(&self) -> &[Property<X::Id>] {
        &self.unsigned
    }

    /// Original unsigned data-object properties, in document order.
    #[must_use]
    pub fn unsigned_objects(&self) -> &[Property<X::Id>] {
        &self.objects
    }

    /// Original authenticated `SignedProperties` reference node.
    #[must_use]
    pub fn reference(&self) -> X::Id {
        self.bound.reference()
    }
}

// ETSI TS 101 903 V1.2.2 §§6.2.1–6.2.5 and its published schema.
// The unsigned choice selects one timestamp kind, whose branch may repeat.
// https://uri.etsi.org/01903/v1.2.2/XAdES.xsd
struct Rule(&'static str, u8, bool);

const SIGNED: &[Rule] = &[
    Rule("SigningTime", 0, false),
    Rule("SigningCertificate", 1, false),
    Rule("SignaturePolicyIdentifier", 2, false),
    Rule("SignatureProductionPlace", 3, false),
    Rule("SignerRole", 4, false),
];
const DATA: &[Rule] = &[
    Rule("DataObjectFormat", 0, true),
    Rule("CommitmentTypeIndication", 1, true),
    Rule("AllDataObjectsTimeStamp", 2, true),
    Rule("IndividualDataObjectsTimeStamp", 3, true),
];
const UNSIGNED: &[Rule] = &[
    Rule("CounterSignature", 0, true),
    Rule("SignatureTimeStamp", 1, true),
    Rule("CompleteCertificateRefs", 2, false),
    Rule("CompleteRevocationRefs", 3, false),
    Rule("AttributeCertificateRefs", 4, false),
    Rule("AttributeRevocationRefs", 5, false),
    Rule("SigAndRefsTimeStamp", 6, true),
    Rule("RefsOnlyTimeStamp", 6, true),
    Rule("CertificateValues", 7, false),
    Rule("RevocationValues", 8, false),
    Rule("ArchiveTimeStamp", 9, true),
];

/// Authenticate the original `SignedProperties` and read the legacy sequences.
///
/// The caller supplies an opt-in layout from the same XML generation. §4.4.1
/// requires a signed `SigningCertificate` or a signed `KeyInfo` containing the
/// selected certificate. This stage locates the protected certificate claims.
/// The XML owner checks each `X509SerialNumber` as an unbounded XML Schema integer.
pub fn prepare<X: SignatureXml + ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &Layout<X>,
) -> Result<Prepared<X>, X> {
    let bound = binding::bind(access, &layout.0).map_err(Error::Binding)?;
    let (signed_node, data) = pair(
        access,
        layout.signed(),
        "SignedSignatureProperties",
        "SignedDataObjectProperties",
    )
    .map_err(Error::Property)?;
    let signed_node = signed_node.ok_or(Error::Property(properties::Error::Missing {
        parent: layout.signed(),
        local: "SignedSignatureProperties",
    }))?;
    let signed = sequence(access, Some(signed_node), SIGNED).map_err(Error::Property)?;
    let data = sequence(access, data, DATA).map_err(Error::Property)?;
    let (unsigned, objects) = match layout.unsigned() {
        Some(parent) => pair(
            access,
            parent,
            "UnsignedSignatureProperties",
            "UnsignedDataObjectProperties",
        )
        .map_err(Error::Property)?,
        None => (None, None),
    };
    let unsigned = sequence(access, unsigned, UNSIGNED).map_err(Error::Property)?;
    let objects = sequence(
        access,
        objects,
        &[Rule("UnsignedDataObjectProperty", 0, true)],
    )
    .map_err(Error::Property)?;
    let protection = match signed
        .iter()
        .find(|entry| entry.name == "SigningCertificate")
    {
        Some(entry) => SignerCertificate::References(SigningReferences(
            crate::certificate::read_legacy(access, layout.signature(), entry.node)?,
        )),
        None => signed_key_info(access, layout.signature())?,
    };
    Ok(Prepared {
        bound,
        signed,
        data,
        unsigned,
        objects,
        signer: protection,
    })
}

type Pair<N> = (Option<N>, Option<N>);

fn pair<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    first: &'static str,
    second: &'static str,
) -> properties::PropertyResult<Pair<X::Id>, X> {
    let mut slots = (None, None);
    for child in access.children(parent) {
        let node = child.map_err(properties::Error::Child)?;
        let slot = if named(access, node, XADES_122, first)? {
            if slots.1.is_some() {
                return Err(properties::Error::Order { node });
            }
            &mut slots.0
        } else if named(access, node, XADES_122, second)? {
            &mut slots.1
        } else {
            return Err(properties::Error::Unexpected { node });
        };
        if slot.replace(node).is_some() {
            return Err(properties::Error::Duplicate { node });
        }
    }
    Ok(slots)
}

fn sequence<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: Option<X::Id>,
    rules: &[Rule],
) -> properties::PropertyResult<OwnedVec<Property<X::Id>>, X> {
    let mut entries = access.execution().vector();
    if let Some(parent) = parent {
        let mut previous: Option<&Rule> = None;
        for child in access.children(parent) {
            let node = child.map_err(properties::Error::Child)?;
            let rule = access
                .inspect(node, |item| -> core::result::Result<_, _> {
                    if let Node::Element(name) = item
                        && access.equal(name.namespace, XADES_122)?
                    {
                        for rule in rules {
                            if access.equal(name.local, rule.0)? {
                                return Ok(Some(rule));
                            }
                        }
                    }
                    Ok(None)
                })
                .map_err(properties::Error::Access)?
                .map_err(|cause| properties::Error::Resource { node, cause })?
                .ok_or(properties::Error::Unexpected { node })?;
            if let Some(prior) = previous {
                if prior.1 > rule.1 {
                    return Err(properties::Error::Order { node });
                }
                if prior.1 == rule.1 {
                    if prior.0 != rule.0 {
                        return Err(properties::Error::Unexpected { node });
                    }
                    if !rule.2 {
                        return Err(properties::Error::Duplicate { node });
                    }
                }
            }
            previous = Some(rule);
            entries
                .try_push(Property { node, name: rule.0 })
                .map_err(|cause| properties::Error::Resource { node, cause })?;
        }
    }
    Ok(entries.into_owned())
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> properties::PropertyResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(properties::Error::Access)
}

fn optional<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    namespace: &str,
    local: &str,
) -> properties::PropertyResult<Option<X::Id>, X> {
    let mut found = None;
    for child in access.children(parent) {
        let node = child.map_err(properties::Error::Child)?;
        if named(access, node, namespace, local)? && found.replace(node).is_some() {
            return Err(properties::Error::Duplicate { node });
        }
    }
    Ok(found)
}

fn signed_key_info<X: SignatureXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
) -> Result<SignerCertificate<X>, X> {
    let node = optional(access, signature, DS, "KeyInfo")
        .map_err(Error::Property)?
        .ok_or(Error::Property(properties::Error::Missing {
            parent: signature,
            local: "KeyInfo",
        }))?;
    let (reference, _) =
        binding::covering_reference(access, signature, binding::Purpose::LegacyKeyInfo(node))
            .map_err(Error::Binding)?;
    let mut certificates = access.execution().vector();
    for child in access.children(node) {
        let child = child.map_err(|e| Error::Property(properties::Error::Child(e)))?;
        if named(access, child, DS, "X509Data").map_err(Error::Property)? {
            for item in access.children(child) {
                let item = item.map_err(|e| Error::Property(properties::Error::Child(e)))?;
                if named(access, item, DS, "X509Certificate").map_err(Error::Property)? {
                    certificates.try_push(item).map_err(|cause| {
                        Error::Property(properties::Error::Resource { node: item, cause })
                    })?;
                }
            }
        }
    }
    if certificates.is_empty() {
        return Err(Error::Property(properties::Error::Missing {
            parent: node,
            local: "X509Certificate",
        }));
    }
    Ok(SignerCertificate::KeyInfo {
        node,
        reference,
        certificates: certificates.into_owned(),
    })
}
