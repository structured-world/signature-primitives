//! TS 101 903 V1.1.1 explicit timestamp references.

use super::{
    InputError, InputResult, Name, Part, Prepared, Profile, Receiver, Refused, ReplayOutcome,
    Resolution, Role, Stop, Token, Work, Xml, append_group, direct_references, is, push, read_role,
    same,
};
use crate::{
    container::{DS, XADES_111},
    xml::{Access, AccessError, Snapshot},
};
use structured_asn1::memory::OwnedVec;
use structured_cms::stream::Source;

/// Caller-selected lexical spelling of the original `HashDataInfo` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDataUri {
    /// The lowercase spelling required by TS 101 903 V1.1.1 Annex B.
    Standard,
    /// Explicit compatibility with documents using uppercase `URI`.
    Uppercase,
}

impl HashDataUri {
    const fn name(self) -> Name<'static> {
        Name {
            namespace: "",
            local: match self {
                Self::Standard => "uri",
                Self::Uppercase => "URI",
            },
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::Standard => Self::Uppercase,
            Self::Uppercase => Self::Standard,
        }
    }
}

/// Source description of one structurally checked timestamp input.
#[derive(Debug, Clone, Copy)]
pub struct HashDataInfo<N> {
    /// Original property supplying the base and URI.
    pub node: N,
    /// Exact original URI attribute, selected by the caller's policy.
    pub uri_attribute: Name<'static>,
    /// Original optional wrapper containing the actual XML transforms.
    pub transforms: Option<N>,
    /// Original timestamp role, including the stricter archive octet rules.
    pub role: Role,
}

/// Original target of a resolved historical hash reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDataTarget<N> {
    /// Exact original element eligible for the timestamp's role.
    Element(N),
    /// Authenticated `SignedInfo` reference with the same original raw source.
    /// The legacy transforms run on that source, before the reference's own
    /// transformations. Comparing URI spelling cannot establish identity.
    Reference(N),
}

/// XML-owned resolution and replay under the same selected verification scope.
pub trait HashDataXml: super::LegacyXml {
    /// Resolve this actual URI and original source without running transforms.
    fn resolve_hash_data<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        data: HashDataInfo<Self::Id>,
        execution: &W,
    ) -> Result<Resolution<HashDataTarget<Self::Id>>, Self::Error>;

    /// Resolve again in the same generation, admit the expected source before
    /// delivering a byte, then execute exactly the original XML transforms.
    /// TS 101 903 V1.1.1 §7.7.1 additionally requires the replayed data-object
    /// and `SignedInfo` octets to equal the ones originally used by `XMLDSig`.
    /// Resolve establishes source identity. When replay differs from the
    /// original signature processing, the owner checks that octet obligation
    /// before reporting completion. Policy, resource, and source errors
    /// preserve their original causes.
    fn replay_hash_data<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        data: HashDataInfo<Self::Id>,
        expected: HashDataTarget<Self::Id>,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<ReplayOutcome<Self::Error>, Self::Error>;
}

/// Original V1.1.1 timestamp from the selected historical signature.
pub struct HashDataStamp<X: Xml> {
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    node: X::Id,
    role: Role,
    sources: OwnedVec<HashDataInfo<X::Id>>,
    token: Token<X::Id>,
}

impl<X: Xml> HashDataStamp<X> {
    /// Original timestamp property.
    #[must_use]
    pub fn node(&self) -> X::Id {
        self.node
    }

    /// Timestamp input role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Original token, with the XML placeholder kept distinct.
    #[must_use]
    pub fn token(&self) -> Token<X::Id> {
        self.token
    }

    /// Original input declarations in document order.
    #[must_use]
    pub fn sources(&self) -> &[HashDataInfo<X::Id>] {
        &self.sources
    }

    /// Read the V1.1.1 timestamp grammar without canonicalization or decoding.
    /// <https://uri.etsi.org/01903/v1.1.1/XAdES.xsd>
    pub fn read<W: Work>(
        access: &Access<'_, X, W>,
        prepared: &Prepared<X>,
        node: X::Id,
        uri: HashDataUri,
    ) -> InputResult<Self, X> {
        if prepared.profile() != Profile::V111 {
            return Err(InputError::Unexpected { node });
        }
        let (signature, role) = read_role(access, prepared, node)?;
        let mut sources = access.execution().vector();
        let mut token = None;
        for child in access.children(node) {
            let child = child.map_err(InputError::Child)?;
            if token.is_some() {
                return Err(InputError::Unexpected { node: child });
            }
            if is(access, child, XADES_111, "HashDataInfo")? {
                sources
                    .try_push(read_info(access, child, uri, role)?)
                    .map_err(|cause| InputError::Resource { node: child, cause })?;
            } else if is(access, child, XADES_111, "EncapsulatedTimeStamp")? {
                token = Some(Token::Encapsulated(child));
            } else if is(access, child, XADES_111, "XMLTimeStamp")? {
                token = Some(Token::Xml(child));
            } else {
                return Err(InputError::Unexpected { node: child });
            }
        }
        if sources.is_empty() {
            return Err(InputError::Missing {
                node,
                local: "HashDataInfo",
            });
        }
        let token = token.ok_or(InputError::Missing {
            node,
            local: "EncapsulatedTimeStamp or XMLTimeStamp",
        })?;
        Ok(Self {
            snapshot: access.snapshot(),
            signature,
            node,
            role,
            sources: sources.into_owned(),
            token,
        })
    }
}

fn read_info<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    uri: HashDataUri,
    role: Role,
) -> InputResult<HashDataInfo<X::Id>, X> {
    if access
        .attribute(node, uri.other().name(), |value| value.is_some())
        .map_err(InputError::Access)?
    {
        return Err(InputError::Unexpected { node });
    }
    let uri_attribute = uri.name();
    if !access
        .attribute(node, uri_attribute, |value| value.is_some())
        .map_err(InputError::Access)?
    {
        return Err(InputError::Missing {
            node,
            local: uri_attribute.local,
        });
    }
    let mut transforms = None;
    for child in access.children(node) {
        let child = child.map_err(InputError::Child)?;
        if !is(access, child, XADES_111, "Transforms")? {
            return Err(InputError::Unexpected { node: child });
        }
        if transforms.replace(child).is_some() {
            return Err(InputError::Duplicate { node: child });
        }
    }
    if let Some(parent) = transforms {
        let mut found = false;
        for child in access.children(parent) {
            let child = child.map_err(InputError::Child)?;
            if !is(access, child, DS, "Transform")? {
                return Err(InputError::Unexpected { node: child });
            }
            if !access
                .attribute(
                    child,
                    Name {
                        namespace: "",
                        local: "Algorithm",
                    },
                    |value| value.is_some(),
                )
                .map_err(InputError::Access)?
            {
                return Err(InputError::Missing {
                    node: child,
                    local: "Algorithm",
                });
            }
            found = true;
        }
        if !found {
            return Err(InputError::Missing {
                node: parent,
                local: "Transform",
            });
        }
    }
    Ok(HashDataInfo {
        node,
        uri_attribute,
        transforms,
        role,
    })
}

/// Replayable hash input containing only resolved targets of this timestamp.
pub struct HashDataInput<'a, X: HashDataXml> {
    xml: &'a X,
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    parts: OwnedVec<ResolvedPart<X::Id>>,
}

type ResolvedPart<N> = (HashDataInfo<N>, HashDataTarget<N>);

impl<'a, X: HashDataXml> HashDataInput<'a, X> {
    /// Bind the source's explicit instructions to the timestamp's required
    /// input before any transform work or digest callback.
    pub fn prepare<W: Work>(
        access: &Access<'a, X, W>,
        prepared: &Prepared<X>,
        stamp: &HashDataStamp<X>,
    ) -> InputResult<Self, X> {
        let layout = prepared.bound.containers();
        if layout.snapshot() != stamp.snapshot || access.snapshot() != stamp.snapshot {
            return Err(InputError::Access(AccessError::Changed {
                node: stamp.node,
            }));
        }
        if prepared.profile() != Profile::V111
            || !same(access, layout.signature(), stamp.signature)?
        {
            return Err(InputError::Foreign { node: stamp.node });
        }
        let mut required = access.execution().vector();
        expected(access, prepared, stamp, &mut required)?;
        let individual = stamp.role == Role::IndividualDataObjects;
        if !individual && required.len() != stamp.sources.len() {
            return Err(InputError::Unexpected { node: stamp.node });
        }
        let mut parts = access.execution().vector();
        for (index, &data) in stamp.sources.iter().enumerate() {
            let resolved = access
                .query(data.node, |xml, snapshot, work| {
                    xml.resolve_hash_data(snapshot, stamp.signature, data, work)
                })
                .map_err(InputError::Access)?;
            if let Resolution::Resolved(target) = resolved {
                let matched = if individual {
                    contains_reference(access, target, &required)?
                } else {
                    matches_part(access, target, required[index])?
                };
                if matched {
                    parts
                        .try_push((data, target))
                        .map_err(|cause| InputError::Resource {
                            node: data.node,
                            cause,
                        })?;
                    continue;
                }
            }
            return Err(InputError::Reference {
                node: data.node,
                resolution: resolved.map(|_| ()),
            });
        }
        Ok(Self {
            xml: access.owner(),
            snapshot: stamp.snapshot,
            signature: stamp.signature,
            parts: parts.into_owned(),
        })
    }
}

fn matches_part<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    target: HashDataTarget<X::Id>,
    part: Part<X::Id>,
) -> InputResult<bool, X> {
    match (target, part) {
        (HashDataTarget::Element(actual), Part::Element(expected))
        | (HashDataTarget::Reference(actual), Part::Reference(expected)) => {
            same(access, actual, expected)
        }
        _ => Ok(false),
    }
}

fn contains_reference<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    target: HashDataTarget<X::Id>,
    candidates: &[Part<X::Id>],
) -> InputResult<bool, X> {
    for &part in candidates {
        if matches_part(access, target, part)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn expected<X: HashDataXml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    stamp: &HashDataStamp<X>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    // TS 101 903 V1.1.1 §§7.2.10–7.7.1, explicit roles in the specified order.
    // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.01.01_60/ts_101903v010101p.pdf
    let layout = prepared.bound.containers();
    if matches!(
        stamp.role,
        Role::AllDataObjects | Role::IndividualDataObjects | Role::Archive
    ) {
        direct_references(access, stamp.signature, Some(layout.signed()), parts)?;
    }
    let mut add = |node| push(parts, stamp.node, Part::Element(node));
    if stamp.role == Role::Archive {
        add(crate::timestamp::singleton(
            access,
            stamp.signature,
            DS,
            "SignedInfo",
        )?)?;
        add(crate::timestamp::singleton(
            access,
            layout.signed(),
            XADES_111,
            "SignedSignatureProperties",
        )?)?;
        if let Some(objects) = crate::timestamp::optional(
            access,
            layout.signed(),
            XADES_111,
            "SignedDataObjectProperties",
        )? {
            add(objects)?;
        }
    }
    if matches!(
        stamp.role,
        Role::Signature | Role::SignatureAndReferences | Role::Archive
    ) {
        add(crate::timestamp::singleton(
            access,
            stamp.signature,
            DS,
            "SignatureValue",
        )?)?;
    }
    if matches!(stamp.role, Role::SignatureAndReferences | Role::Archive) {
        append_group(
            access,
            prepared,
            stamp.node,
            "SignatureTimeStamp",
            true,
            &mut add,
        )?;
    }
    if matches!(
        stamp.role,
        Role::SignatureAndReferences | Role::ReferencesOnly | Role::Archive
    ) {
        for local in ["CompleteCertificateRefs", "CompleteRevocationRefs"] {
            append_group(access, prepared, stamp.node, local, true, &mut add)?;
        }
    }
    if stamp.role == Role::Archive {
        for (local, mandatory) in [
            ("CertificateValues", true),
            ("RevocationValues", true),
            ("SigAndRefsTimeStamp", false),
            ("RefsOnlyTimeStamp", false),
            ("ArchiveTimeStamp", false),
        ] {
            append_group(access, prepared, stamp.node, local, mandatory, &mut add)?;
        }
    }
    Ok(())
}

impl<X: HashDataXml> Source for HashDataInput<'_, X> {
    type Error = InputError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        let access = Access::new(self.xml, self.snapshot, execution);
        let mut sink = Stop {
            receiver,
            refused: false,
        };
        for &(data, target) in &self.parts {
            let result = access
                .query(data.node, |xml, snapshot, work| {
                    xml.replay_hash_data(snapshot, self.signature, data, target, &mut sink, work)
                })
                .map_err(InputError::Access)?;
            if sink.refused {
                return Err(InputError::Receiver(Refused));
            }
            if let ReplayOutcome::Unavailable(cause) = result {
                return Err(InputError::Unavailable {
                    node: data.node,
                    cause,
                });
            }
        }
        Ok(())
    }
}
