//! Directly incorporated ETSI TS 101 903 and TS 103 171 historical profiles.
//!
//! Select the original layout with [`locate`] and its historical profile.
//! <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.02.02_60/ts_101903v010202p.pdf>

use crate::binding::{self, SignatureXml};
use crate::container::{self, DS, Syntax, XADES_111};
use crate::properties;
use crate::scalar::{self, ScalarXml};
use crate::xml::{Access, Name, Node, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

mod signer;
pub mod timestamp;
pub use signer::{
    CertificateMatch, SignerCheck, SignerError, SignerResult, SigningReferences, check_signer,
};

/// The caller-selected historical vocabulary and profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// ETSI TS 101 903 V1.1.1.
    V111,
    /// ETSI TS 101 903 V1.2.2.
    V122,
    /// ETSI TS 103 171 V2.1.1 over the 1.3.2 vocabulary.
    PreEn,
}

impl Profile {
    pub(crate) const fn syntax(self) -> Syntax {
        match self {
            Self::V111 => Syntax::Ts101903V111,
            Self::V122 => Syntax::Ts101903V122,
            Self::PreEn => Syntax::Ts103171,
        }
    }

    /// Exact namespace used by the qualifying properties.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        self.syntax().namespace()
    }

    /// Exact namespace used by the digest pair inside historical properties.
    #[must_use]
    pub const fn digest_namespace(self) -> &'static str {
        match self {
            Self::V111 => XADES_111,
            Self::V122 | Self::PreEn => DS,
        }
    }

    /// Required Type of the reference that signs the historical properties.
    #[must_use]
    pub const fn signed_properties_type(self) -> &'static str {
        match self {
            Self::V111 => binding::SIGNED_PROPERTIES_111,
            Self::V122 => binding::SIGNED_PROPERTIES_122,
            Self::PreEn => binding::SIGNED_PROPERTIES,
        }
    }
}

/// Locate an explicitly chosen historical profile. The 1.3.2 namespace alone
/// does not authorize interpretation as a pre-EN signature.
pub fn locate<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    profile: Profile,
) -> container::ContainerResult<Layout<X>, X> {
    container::locate_historical(access, signature, profile.syntax()).map(Layout::new)
}

/// Original historical container identities selected under caller policy.
pub struct Layout<X: Xml>(container::Layout<X>);

impl<X: Xml> Layout<X> {
    pub(crate) fn new(original: container::Layout<X>) -> Self {
        Self(original)
    }

    /// Explicit historical processing profile for this source.
    #[must_use]
    pub fn profile(&self) -> Profile {
        profile(self.0.syntax())
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

fn profile(syntax: Syntax) -> Profile {
    match syntax {
        Syntax::Ts101903V111 => Profile::V111,
        Syntax::Ts101903V122 => Profile::V122,
        Syntax::Ts103171 => Profile::PreEn,
        Syntax::En319132 => unreachable!("historical layout"),
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

/// An original property in the selected historical vocabulary.
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
    /// Explicit historical processing profile for this signature.
    #[must_use]
    pub fn profile(&self) -> Profile {
        profile(self.bound.containers().syntax())
    }

    /// Original authenticated signed-properties receipt for this profile.
    #[must_use]
    pub fn binding(&self) -> &binding::Selected<X> {
        &self.bound
    }

    /// Read the original signed policy in this historical vocabulary.
    pub fn policy<W: Work>(
        &self,
        access: &Access<'_, X, W>,
    ) -> properties::PropertyResult<Option<crate::policy::Original<X>>, X> {
        let layout = self.bound.containers();
        if layout.snapshot() != access.snapshot() {
            return Err(properties::Error::Access(
                crate::xml::AccessError::Changed {
                    node: layout.signed(),
                },
            ));
        }
        let profile = self.profile();
        for entry in &self.signed {
            access
                .execution()
                .charge_work(1)
                .map_err(|cause| properties::Error::Resource {
                    node: entry.node,
                    cause,
                })?;
            if entry.name == "SignaturePolicyIdentifier" {
                return crate::policy::read_in(
                    access,
                    layout.signature(),
                    entry.node,
                    (profile.namespace(), profile.digest_namespace()),
                )
                .map(Some);
            }
        }
        Ok(None)
    }

    /// Read the exact original material enclosure selected by this signature.
    /// The result is a structural catalogue and carries no authentication or
    /// path decision.
    pub fn values<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        node: X::Id,
    ) -> properties::PropertyResult<crate::extended::ValuesFor<X>, X> {
        if self.bound.containers().snapshot() != access.snapshot() {
            return Err(properties::Error::Access(
                crate::xml::AccessError::Changed { node },
            ));
        }
        for entry in &self.unsigned {
            if !access
                .equal_id(node, entry.node)
                .map_err(|cause| properties::Error::Resource { node, cause })?
            {
                continue;
            }
            let certificates = match entry.name {
                "CertificateValues" | "AttrAuthoritiesCertValues" => true,
                "RevocationValues" | "AttributeRevocationValues" => false,
                _ => return Err(properties::Error::Unexpected { node }),
            };
            return crate::material::read_values_in(
                access,
                node,
                self.profile().namespace(),
                certificates,
            );
        }
        Err(properties::Error::Unexpected { node })
    }

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

    pub(crate) fn after_signature_timestamp(&self) -> Option<X::Id> {
        if self.profile() == Profile::PreEn {
            return None;
        }
        let tail = self.unsigned.last()?;
        // The tail is sufficient because preparation enforces the same ranks.
        // TS 101 903 V1.1.1 §6.2.5 and V1.2.2 UnsignedSignaturePropertiesType.
        // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.01.01_60/ts_101903v010101p.pdf
        UNSIGNED
            .iter()
            .find(|rule| rule.0 == tail.name && rule.1 > SIGNATURE_TIMESTAMP.1)?;
        Some(tail.node)
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
const SIGNATURE_TIMESTAMP: Rule = Rule("SignatureTimeStamp", 1, true);
const UNSIGNED: &[Rule] = &[
    Rule("CounterSignature", 0, true),
    SIGNATURE_TIMESTAMP,
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
const PRE_EN_UNSIGNED: &[Rule] = &[
    Rule("CounterSignature", 0, true),
    Rule("SignatureTimeStamp", 0, true),
    Rule("CompleteCertificateRefs", 0, false),
    Rule("CompleteRevocationRefs", 0, false),
    Rule("AttributeCertificateRefs", 0, false),
    Rule("AttributeRevocationRefs", 0, false),
    Rule("SigAndRefsTimeStamp", 0, true),
    Rule("RefsOnlyTimeStamp", 0, true),
    Rule("CertificateValues", 0, false),
    Rule("RevocationValues", 0, false),
    Rule("AttrAuthoritiesCertValues", 0, false),
    Rule("AttributeRevocationValues", 0, false),
    Rule("TimeStampValidationData", 0, true),
    Rule("ArchiveTimeStamp", 0, true),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Signature,
    Data,
    Unsigned,
    UnsignedObjects,
}

impl Group {
    const fn rules(self, profile: Profile) -> &'static [Rule] {
        match self {
            Self::Signature => SIGNED,
            Self::Data => DATA,
            Self::Unsigned if matches!(profile, Profile::PreEn) => PRE_EN_UNSIGNED,
            Self::Unsigned => UNSIGNED,
            Self::UnsignedObjects => &[Rule("UnsignedDataObjectProperty", 0, true)],
        }
    }
}

/// Authenticate the original `SignedProperties` and read its historical fields.
///
/// The caller supplies an opt-in layout from the same XML generation. The
/// certificate claim is taken from the signed `SigningCertificate`; V1.2.2
/// §4.4.1 also allows a signed `KeyInfo` containing the selected certificate.
/// The XML owner checks each `X509SerialNumber` as an unbounded XML Schema integer.
pub fn prepare<X: SignatureXml + ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &Layout<X>,
) -> Result<Prepared<X>, X> {
    let bound = binding::bind(access, &layout.0).map_err(Error::Binding)?;
    let profile = layout.profile();
    let namespace = profile.namespace();
    let (signed_node, data) = pair(
        access,
        layout.signed(),
        namespace,
        "SignedSignatureProperties",
        "SignedDataObjectProperties",
    )
    .map_err(Error::Property)?;
    let signed_node = signed_node.ok_or(Error::Property(properties::Error::Missing {
        parent: layout.signed(),
        local: "SignedSignatureProperties",
    }))?;
    let signed =
        sequence(access, Some(signed_node), profile, Group::Signature).map_err(Error::Property)?;
    let data = sequence(access, data, profile, Group::Data).map_err(Error::Property)?;
    if profile != Profile::V122 {
        for required in &SIGNED[..if profile == Profile::V111 { 3 } else { 2 }] {
            if !signed.iter().any(|property| property.name == required.0) {
                return Err(properties::Error::Missing {
                    parent: signed_node,
                    local: required.0,
                }
                .into());
            }
        }
    }
    let (unsigned, objects) = match layout.unsigned() {
        Some(parent) => pair(
            access,
            parent,
            namespace,
            "UnsignedSignatureProperties",
            "UnsignedDataObjectProperties",
        )
        .map_err(Error::Property)?,
        None => (None, None),
    };
    let unsigned = sequence(access, unsigned, profile, Group::Unsigned).map_err(Error::Property)?;
    let objects =
        sequence(access, objects, profile, Group::UnsignedObjects).map_err(Error::Property)?;
    let protection = match signed
        .iter()
        .find(|entry| entry.name == "SigningCertificate")
    {
        Some(entry) => SignerCertificate::References(SigningReferences(
            crate::certificate::read_legacy(access, layout.signature(), entry.node, profile)?,
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
    namespace: &str,
    first: &'static str,
    second: &'static str,
) -> properties::PropertyResult<Pair<X::Id>, X> {
    let mut slots = (None, None);
    for child in access.children(parent) {
        let node = child.map_err(properties::Error::Child)?;
        let slot = if named(access, node, namespace, first)? {
            if slots.1.is_some() {
                return Err(properties::Error::Order { node });
            }
            &mut slots.0
        } else if named(access, node, namespace, second)? {
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
    profile: Profile,
    group: Group,
) -> properties::PropertyResult<OwnedVec<Property<X::Id>>, X> {
    let mut entries = access.execution().vector();
    if let Some(parent) = parent {
        let mut previous: Option<&Rule> = None;
        let rules = group.rules(profile);
        let unordered = group == Group::Unsigned && profile == Profile::PreEn;
        let mut seen = 0u32;
        for child in access.children(parent) {
            let node = child.map_err(properties::Error::Child)?;
            let rule = access
                .inspect(node, |item| -> core::result::Result<_, _> {
                    if let Node::Element(name) = item {
                        let original = access.equal(name.namespace, profile.namespace())?;
                        let archive_namespace = unordered
                            && access.equal(name.namespace, crate::timestamp::XADES_141)?;
                        if original || archive_namespace {
                            for (index, rule) in rules.iter().enumerate() {
                                if (if archive_namespace {
                                    matches!(rule.0, "TimeStampValidationData" | "ArchiveTimeStamp")
                                } else {
                                    rule.0 != "TimeStampValidationData"
                                }) && access.equal(name.local, rule.0)?
                                {
                                    return Ok(Some((index, rule)));
                                }
                            }
                        }
                    }
                    Ok(None)
                })
                .map_err(properties::Error::Access)?
                .map_err(|cause| properties::Error::Resource { node, cause })?
                .ok_or(properties::Error::Unexpected { node })?;
            let (index, rule) = rule;
            if profile == Profile::V111
                && matches!(
                    rule.0,
                    "AttributeCertificateRefs" | "AttributeRevocationRefs"
                )
            {
                return Err(properties::Error::Unexpected { node });
            }
            if unordered {
                let mask = 1 << index;
                if !rule.2 && seen & mask != 0 {
                    return Err(properties::Error::Duplicate { node });
                }
                seen |= mask;
            } else if let Some(prior) = previous {
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
