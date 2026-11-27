//! Explicit Include-based timestamp inputs from TS 101 903 V1.2.2 §§7.1.4–7.7.

use super::{Prepared, Profile};
use crate::binding::Status;
use crate::container::{DS, XADES_122};
use crate::reference::{
    Boolean, LexicalSource, Parent, ReferenceXml, Replay, ReplayOutcome, Resolution,
};
use crate::timestamp::{InputError, InputResult, Role, Stop, TimestampXml};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};
use structured_cms::stream::{Receiver, Refused, Source};

mod hash_data;
pub use hash_data::{
    HashDataInfo, HashDataInput, HashDataStamp, HashDataTarget, HashDataUri, HashDataXml,
};

const URI: Name<'_> = Name {
    namespace: "",
    local: "URI",
};
const REFERENCED_DATA: Name<'_> = Name {
    namespace: "",
    local: "referencedData",
};

/// Permitted token forms. `XMLTimeStamp` is a schema placeholder in §7.1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<N> {
    /// Original base64-encoded timestamp token.
    Encapsulated(N),
    /// Original XML token; its semantics are unspecified by this edition.
    Xml(N),
}

/// XML-owned resolution of original legacy Includes and default canonicalization.
pub trait LegacyXml: TimestampXml {
    /// Resolves the Include's original URI to an element of this snapshot.
    ///
    /// This is the owner's same-document URI and unique-ID resolution under
    /// current policy. No external acquisition or element reconstruction occurs.
    fn resolve_legacy_element<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        include: Self::Id,
        execution: &W,
    ) -> Result<Resolution<Self::Id>, Self::Error>;

    /// Streams an original element under the implicit `XMLDSig` canonicalization
    /// specified by §7.1.4 when the timestamp declares no explicit method.
    fn canonicalize_legacy_default<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error>;
}

/// One original `TimeStampType` occurrence and its explicit input statements.
pub struct Stamp<X: Xml> {
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    node: X::Id,
    role: Role,
    includes: OwnedVec<X::Id>,
    method: Option<X::Id>,
    token: Token<X::Id>,
}

impl<X: Xml> Stamp<X> {
    /// Original timestamp element.
    #[must_use]
    pub fn node(&self) -> X::Id {
        self.node
    }

    /// Original role of the timestamp and its required input.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Original `XMLDSig` canonicalization method and parameters, when declared.
    #[must_use]
    pub fn method(&self) -> Option<X::Id> {
        self.method
    }

    /// Original single token in the chosen schema branch.
    #[must_use]
    pub fn token(&self) -> Token<X::Id> {
        self.token
    }
}

pub(super) fn role(local: &str) -> Option<Role> {
    match local {
        "SignatureTimeStamp" => Some(Role::Signature),
        "AllDataObjectsTimeStamp" => Some(Role::AllDataObjects),
        "IndividualDataObjectsTimeStamp" => Some(Role::IndividualDataObjects),
        "SigAndRefsTimeStamp" => Some(Role::SignatureAndReferences),
        "RefsOnlyTimeStamp" => Some(Role::ReferencesOnly),
        "ArchiveTimeStamp" => Some(Role::Archive),
        _ => None,
    }
}

impl<N> Token<N> {
    pub(super) fn encoded(&self) -> &[N] {
        match self {
            Self::Encapsulated(node) => core::slice::from_ref(node),
            Self::Xml(_) => &[],
        }
    }

    pub(super) fn all(&self) -> &[N] {
        match self {
            Self::Encapsulated(node) | Self::Xml(node) => core::slice::from_ref(node),
        }
    }
}

impl<X: Xml> Stamp<X> {
    pub(super) fn original_token(&self) -> &Token<X::Id> {
        &self.token
    }
}

/// Reads a timestamp in the selected legacy source.
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    node: X::Id,
) -> InputResult<Stamp<X>, X> {
    if prepared.profile() != Profile::V122 {
        return Err(InputError::Unexpected { node });
    }
    let (signature, role) = read_role(access, prepared, node)?;
    read_stamp(access, signature, node, role)
}

/// Read an original TS 103 171 timestamp through the common replay and check
/// path. Both archive vocabularies use their own source recipes.
/// <https://www.etsi.org/deliver/etsi_ts/103100_103199/103171/02.01.01_60/ts_103171v020101p.pdf>
pub fn read_pre_en<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    node: X::Id,
) -> InputResult<crate::timestamp::Timestamp<X>, X> {
    use crate::timestamp::{self, ExtendedKind, ReferenceSyntax, XADES_141};
    if prepared.profile() != Profile::PreEn {
        return Err(InputError::Unexpected { node });
    }
    let (signature, role) = read_role(access, prepared, node)?;
    let bound = prepared.binding();
    let kind = match role {
        Role::Archive if is(access, node, XADES_141, "ArchiveTimeStamp")? => {
            ExtendedKind::Archive141
        }
        Role::Archive => ExtendedKind::Archive132,
        Role::SignatureAndReferences => {
            ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original)
        }
        Role::ReferencesOnly => ExtendedKind::ReferencesOnly(ReferenceSyntax::Original),
        _ => {
            let layout = bound.containers();
            let namespace = Profile::PreEn.namespace();
            let parent = match role {
                Role::Signature => timestamp::unsigned_parent(access, bound, node)?,
                _ => timestamp::singleton(
                    access,
                    layout.signed(),
                    namespace,
                    "SignedDataObjectProperties",
                )?,
            };
            let stamp = timestamp::read_fields_in(access, signature, parent, node, role, true)?;
            if role == Role::Signature && stamp.tokens().len() != 1 {
                return Err(InputError::Duplicate {
                    node: stamp.tokens()[1],
                });
            }
            return Ok(stamp);
        }
    };
    timestamp::read_extended(access, bound, node, kind)
}

fn read_role<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    node: X::Id,
) -> InputResult<(X::Id, Role), X> {
    let snapshot = prepared.bound.containers().snapshot();
    if access.snapshot() != snapshot {
        return Err(InputError::Access(AccessError::Changed { node }));
    }
    for property in prepared.data.iter().chain(prepared.unsigned.iter()) {
        if same(access, property.node, node)? {
            let role = role(property.name).ok_or(InputError::Foreign { node })?;
            return Ok((prepared.bound.containers().signature(), role));
        }
    }
    Err(InputError::Foreign { node })
}

fn read_stamp<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    node: X::Id,
    role: Role,
) -> InputResult<Stamp<X>, X> {
    // TS 101 903 V1.2.2 §7.1.4 requires Include+, optional method, one token.
    // https://uri.etsi.org/01903/v1.2.2/XAdES.xsd
    let mut includes = access.execution().vector();
    let mut method = None;
    let mut token = None;
    for child in access.children(node) {
        let child = child.map_err(InputError::Child)?;
        if token.is_some() {
            return Err(InputError::Unexpected { node: child });
        }
        if is(access, child, XADES_122, "Include")? {
            if method.is_some() {
                return Err(InputError::Order { node: child });
            }
            if !access
                .attribute(child, URI, |value| value.is_some())
                .map_err(InputError::Access)?
            {
                return Err(InputError::Missing {
                    node: child,
                    local: "URI",
                });
            }
            if let Some(extra) = access.children(child).next() {
                return Err(InputError::Unexpected {
                    node: extra.map_err(InputError::Child)?,
                });
            }
            includes
                .try_push(child)
                .map_err(|cause| InputError::Resource { node: child, cause })?;
        } else if is(access, child, DS, "CanonicalizationMethod")? {
            if method.replace(child).is_some() {
                return Err(InputError::Duplicate { node: child });
            }
        } else if is(access, child, XADES_122, "EncapsulatedTimeStamp")? {
            token = Some(Token::Encapsulated(child));
        } else if is(access, child, XADES_122, "XMLTimeStamp")? {
            token = Some(Token::Xml(child));
        } else {
            return Err(InputError::Unexpected { node: child });
        }
    }
    if includes.is_empty() {
        return Err(InputError::Missing {
            node,
            local: "Include",
        });
    }
    let token = token.ok_or(InputError::Missing {
        node,
        local: "EncapsulatedTimeStamp or XMLTimeStamp",
    })?;
    Ok(Stamp {
        snapshot: access.snapshot(),
        signature,
        node,
        role,
        includes: includes.into_owned(),
        method,
        token,
    })
}

#[derive(Clone, Copy)]
enum Part<N> {
    Element(N),
    Reference(N),
}

/// Replayable original V1.2.2 imprint input. Every Include was checked against
/// its role before this source can stream canonicalization or reference bytes.
pub struct Input<'a, X: LegacyXml> {
    xml: &'a X,
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    method: Option<X::Id>,
    parts: OwnedVec<Part<X::Id>>,
}

/// Resolve the original Includes and enforce the selected timestamp's coverage.
///
/// This does not decode a token, assert an imprint match or obtain evidence of
/// trust. Pass the returned source to the existing CMS timestamp checker.
pub fn input<'a, X: LegacyXml, W: Work>(
    access: &Access<'a, X, W>,
    prepared: &Prepared<X>,
    stamp: &Stamp<X>,
) -> InputResult<Input<'a, X>, X> {
    let layout = prepared.bound.containers();
    let signature = layout.signature();
    if access.snapshot() != stamp.snapshot || layout.snapshot() != stamp.snapshot {
        return Err(InputError::Access(AccessError::Changed {
            node: stamp.node,
        }));
    }
    if !same(access, signature, stamp.signature)? {
        return Err(InputError::Foreign { node: stamp.node });
    }
    let mut parts = access.execution().vector();
    if stamp.role != Role::IndividualDataObjects {
        expected_parts(access, prepared, stamp, &mut parts)?;
        if parts.len() != stamp.includes.len() {
            return Err(InputError::Unexpected { node: stamp.node });
        }
    }
    let signed_info = crate::timestamp::singleton(access, signature, DS, "SignedInfo")?;
    let direct = Direct {
        signature,
        signed_info,
        properties: layout.signed(),
    };
    if stamp.role == Role::IndividualDataObjects {
        for &include in &stamp.includes {
            let part = resolve(access, direct, include, None, stamp.role)?;
            for earlier in &parts {
                if let (&Part::Reference(left), Part::Reference(right)) = (earlier, part)
                    && same(access, left, right)?
                {
                    return Err(InputError::Duplicate { node: include });
                }
            }
            push(&mut parts, include, part)?;
        }
    } else {
        for (&include, &wanted) in stamp.includes.iter().zip(parts.iter()) {
            resolve(access, direct, include, Some(wanted), stamp.role)?;
        }
    }
    Ok(Input {
        xml: access.owner(),
        snapshot: stamp.snapshot,
        signature,
        method: stamp.method,
        parts: parts.into_owned(),
    })
}

#[derive(Clone, Copy)]
struct Direct<N> {
    signature: N,
    signed_info: N,
    properties: N,
}

fn resolve<X: LegacyXml, W: Work>(
    access: &Access<'_, X, W>,
    direct: Direct<X::Id>,
    include: X::Id,
    wanted: Option<Part<X::Id>>,
    role: Role,
) -> InputResult<Part<X::Id>, X> {
    let value = access
        .query(include, |xml, snapshot, work| {
            xml.boolean_attribute(snapshot, include, REFERENCED_DATA, work)
        })
        .map_err(InputError::Access)?;
    if let Some(Part::Element(expected)) = wanted {
        if value == Boolean::Malformed {
            return Err(InputError::ReferencedData {
                node: include,
                value,
            });
        }
        let resolved = access
            .query(include, |xml, snapshot, work| {
                xml.resolve_legacy_element(snapshot, include, work)
            })
            .map_err(InputError::Access)?;
        if let Resolution::Resolved(actual) = resolved
            && same(access, expected, actual)?
        {
            return Ok(Part::Element(actual));
        }
        return Err(InputError::Reference {
            node: include,
            resolution: resolved.map(|_| ()),
        });
    }
    if value != Boolean::Value(true) {
        return Err(InputError::ReferencedData {
            node: include,
            value,
        });
    }
    let resolved = access
        .query(include, |xml, snapshot, work| {
            xml.resolve_reference(
                snapshot,
                direct.signature,
                include,
                LexicalSource::Attribute(URI),
                work,
                |entry| {
                    (
                        entry.parent,
                        entry.reference.node,
                        entry.reference.status,
                        entry.reference.target,
                    )
                },
            )
        })
        .map_err(InputError::Access)?;
    if let Resolution::Resolved((Parent::SignedInfo(parent), actual, Status::Valid, target)) =
        resolved
        && same(access, parent, direct.signed_info)?
    {
        let excluded = match target {
            Some(target) if matches!(role, Role::AllDataObjects | Role::IndividualDataObjects) => {
                same(access, target, direct.properties)?
            }
            _ => false,
        };
        let matches = match wanted {
            Some(Part::Reference(expected)) => same(access, expected, actual)?,
            None => true,
            Some(Part::Element(_)) => unreachable!("element handled before reference resolution"),
        };
        if !excluded && matches {
            return Ok(Part::Reference(actual));
        }
    }
    Err(InputError::Reference {
        node: include,
        resolution: resolved.map(|_| ()),
    })
}

fn push<N: Copy, W: Work, E>(
    parts: &mut OwnedVec<Part<N>, W>,
    context: N,
    part: Part<N>,
) -> Result<(), InputError<E, N>> {
    parts.try_push(part).map_err(|cause| InputError::Resource {
        node: context,
        cause,
    })
}

fn same<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    other: X::Id,
) -> InputResult<bool, X> {
    access
        .equal_id(node, other)
        .map_err(|cause| InputError::Resource { node, cause })
}

fn is<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> InputResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(InputError::Access)
}

fn expected_parts<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    stamp: &Stamp<X>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    let layout = prepared.bound.containers();
    let signature = layout.signature();
    let node = stamp.node;
    let mut add = |id| push(parts, node, Part::Element(id));
    match stamp.role {
        Role::AllDataObjects => direct_references(access, signature, Some(layout.signed()), parts),
        Role::Signature => add(crate::timestamp::singleton(
            access,
            signature,
            DS,
            "SignatureValue",
        )?),
        Role::SignatureAndReferences | Role::ReferencesOnly => {
            if stamp.role == Role::SignatureAndReferences {
                add(crate::timestamp::singleton(
                    access,
                    signature,
                    DS,
                    "SignatureValue",
                )?)?;
                append_group(
                    access,
                    prepared,
                    stamp.node,
                    "SignatureTimeStamp",
                    true,
                    &mut add,
                )?;
            }
            for (local, required) in REFERENCES {
                append_group(access, prepared, stamp.node, local, required, &mut add)?;
            }
            Ok(())
        }
        Role::Archive => archive(access, prepared, stamp, parts),
        Role::IndividualDataObjects => Ok(()),
    }
}

const REFERENCES: [(&str, bool); 4] = [
    ("CompleteCertificateRefs", true),
    ("CompleteRevocationRefs", true),
    ("AttributeCertificateRefs", false),
    ("AttributeRevocationRefs", false),
];

fn append_group<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    before: X::Id,
    name: &'static str,
    required: bool,
    add: &mut impl FnMut(X::Id) -> InputResult<(), X>,
) -> InputResult<(), X> {
    let mut found = false;
    for entry in &prepared.unsigned {
        if same(access, entry.node, before)? {
            break;
        }
        if entry.name == name {
            add(entry.node)?;
            found = true;
        }
    }
    if required && !found {
        return Err(InputError::Missing {
            node: before,
            local: name,
        });
    }
    Ok(())
}

fn reference_count<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
) -> InputResult<usize, X> {
    access
        .query(signature, |xml, snapshot, work| {
            xml.reference_count(snapshot, signature, work)
        })
        .map_err(InputError::Access)
}

fn each_reference<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    count: usize,
    mut visit: impl FnMut(X::Id, Option<X::Id>) -> InputResult<(), X>,
) -> InputResult<(), X> {
    for ordinal in 0..count {
        let (node, target) = access
            .query(signature, |xml, snapshot, work| {
                xml.reference(snapshot, signature, ordinal, work, |reference| {
                    (reference.node, reference.target)
                })
            })
            .map_err(InputError::Access)?;
        visit(node, target)?;
    }
    Ok(())
}

fn direct_references<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    excluded: Option<X::Id>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    let count = reference_count(access, signature)?;
    each_reference(access, signature, count, |node, target| {
        if let (Some(target), Some(excluded)) = (target, excluded)
            && same(access, target, excluded)?
        {
            return Ok(());
        }
        push(parts, node, Part::Reference(node))
    })
}

fn archive<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
    stamp: &Stamp<X>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    // Small signatures avoid indexing allocations. For larger inputs the
    // index answers only object membership; every reference stays in wire order.
    const LINEAR_REFERENCE_LIMIT: usize = 8;

    // TS 101 903 V1.2.2 §7.7 groups elements by role, not unsigned XML order.
    // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.02.02_60/ts_101903v010202p.pdf
    let signature = prepared.bound.containers().signature();
    let count = reference_count(access, signature)?;
    let refusal = |cause| InputError::Resource {
        node: stamp.node,
        cause,
    };
    let mut targets = (count > LINEAR_REFERENCE_LIMIT).then(|| access.execution().map());
    each_reference(access, signature, count, |node, target| {
        if let (Some(targets), Some(target)) = (&mut targets, target) {
            targets.try_insert(target, ()).map_err(refusal)?;
        }
        push(parts, node, Part::Reference(node))
    })?;
    let mut add = |id| push(parts, stamp.node, Part::Element(id));
    for local in ["SignedInfo", "SignatureValue"] {
        add(crate::timestamp::singleton(access, signature, DS, local)?)?;
    }
    if let Some(key) = crate::timestamp::optional(access, signature, DS, "KeyInfo")? {
        add(key)?;
    }
    for (name, required) in [
        ("SignatureTimeStamp", false),
        ("CounterSignature", false),
        ("CompleteCertificateRefs", false),
        ("CompleteRevocationRefs", false),
        ("AttributeCertificateRefs", false),
        ("AttributeRevocationRefs", false),
        ("CertificateValues", true),
        ("RevocationValues", true),
        ("SigAndRefsTimeStamp", false),
        ("RefsOnlyTimeStamp", false),
        ("ArchiveTimeStamp", false),
    ] {
        append_group(access, prepared, stamp.node, name, required, &mut add)?;
    }
    for child in access.children(signature) {
        let object = child.map_err(InputError::Child)?;
        if !is(access, object, DS, "Object")? {
            continue;
        }
        let referenced = if let Some(targets) = &targets {
            targets
                .get(&object, access.execution())
                .map_err(refusal)?
                .is_some()
        } else {
            let mut referenced = false;
            each_reference(access, signature, count, |_, target| {
                if let Some(target) = target
                    && same(access, target, object)?
                {
                    referenced = true;
                }
                Ok(())
            })?;
            referenced
        };
        if !referenced {
            add(object)?;
        }
    }
    Ok(())
}

impl<X: LegacyXml> Source for Input<'_, X> {
    type Error = InputError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        let access = Access::new(self.xml, self.snapshot, execution);
        let mut receiver = Stop {
            receiver,
            refused: false,
        };
        for part in &self.parts {
            match *part {
                Part::Element(node) => access
                    .query(node, |xml, snapshot, work| match self.method {
                        Some(method) => {
                            xml.canonicalize(snapshot, node, method, &mut receiver, work)
                        }
                        None => {
                            xml.canonicalize_legacy_default(snapshot, node, &mut receiver, work)
                        }
                    })
                    .map_err(InputError::Access)?,
                Part::Reference(node) => {
                    let replay = self
                        .method
                        .map_or(Replay::ReferenceOutput, Replay::Timestamp);
                    let outcome = access
                        .query(node, |xml, snapshot, work| {
                            xml.replay_reference(
                                snapshot,
                                self.signature,
                                node,
                                replay,
                                &mut receiver,
                                work,
                            )
                        })
                        .map_err(InputError::Access)?;
                    if let ReplayOutcome::Unavailable(cause) = outcome {
                        return Err(InputError::Unavailable { node, cause });
                    }
                }
            }
            if receiver.refused {
                return Err(InputError::Receiver(Refused));
            }
        }
        Ok(())
    }
}

impl<X: LegacyXml> Input<'_, X> {
    pub(super) fn coverage<W: Work>(
        &self,
        stamp: &Stamp<X>,
        work: &W,
    ) -> Result<crate::timestamp::CoverageFor<X, W>, crate::timestamp::CoverageError<X::Error, X::Id>>
    {
        crate::timestamp::coverage::elements(
            &Access::new(self.xml, self.snapshot, work),
            crate::binary::Location {
                snapshot: self.snapshot,
                node: stamp.node,
            },
            self.signature,
            stamp.role,
            self.parts.iter().map(|part| {
                Ok(match part {
                    Part::Element(node) => Some(*node),
                    Part::Reference(_) => None,
                })
            }),
        )
    }
}
