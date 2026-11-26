//! Source-bound inventory for directly incorporated `XAdES` C, X, XL and A.

use crate::{
    binary::{self, BinaryXml, Location},
    binding::Selected,
    container::{Syntax, XADES},
    material::{self, Catalogue},
    properties,
    timestamp::{
        self, ExtendedKind, InputError, ReferenceSyntax, Role, Timestamp, VerifiedTimestamp,
    },
    unsigned,
    validation::{self, ReferenceProperty, TargetFor},
    xml::{Access, Name, Node, Snapshot, Xml},
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// Original failure while preparing an extended-signature inventory.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original property grammar, field location or XML refusal.
    Property(properties::Error<E, N>),
    /// Original timestamp selection or syntax refusal.
    Timestamp(InputError<E, N>),
}

/// Reading result using the XML owner's actual identity and cause types.
pub type ResultFor<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;
/// Original reference-property reading in the XML owner's domain.
pub type ReferencesFor<X> =
    ReferenceProperty<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// Original material catalogue in the XML owner's domain.
pub type ValuesFor<X> = Catalogue<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// First selected artifact missing from this exact incorporated value set.
/// `None` means every selected original artifact has an identical value.
pub type IncorporationResult<X> = binary::BinaryResult<Option<usize>, X, MemoryError>;

/// Check that one original values property contains all selected artifacts for
/// its role (TS 101 903 V1.4.2 §§7.6.1 and 7.6.2). Pass the ordinary or
/// attribute-authority catalogue from this signature's [`Properties`]. Select
/// only the artifacts required in that property, excluding permitted
/// equivalents from other locations. Each original value is decoded at most
/// once and compared without re-encoding either input.
/// <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf>
pub fn check_incorporation<X: BinaryXml, W: Work>(
    xml: &X,
    catalogue: &ValuesFor<X>,
    required: &[TargetFor<'_, '_, X>],
    work: &W,
) -> IncorporationResult<X> {
    let snapshot = catalogue.snapshot();
    let location = Location {
        snapshot,
        node: catalogue.parent(),
    };
    let resource = |cause| binary::Error::Callback { location, cause };
    Access::new(xml, snapshot, work)
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let mut matched = work.vector();
    matched
        .try_reserve_exact(required.len())
        .map_err(resource)?;
    let mut remaining = required.len();
    for _ in required {
        matched.try_push(false).map_err(resource)?;
    }
    for entry in catalogue.entries() {
        if remaining == 0 {
            return Ok(None);
        }
        work.charge_work(1).map_err(resource)?;
        let material::Entry::Encapsulated { node, kind } = *entry else {
            continue;
        };
        binary::with_octets(xml, Location { snapshot, node }, work, |actual| {
            for (ordinal, &candidate) in required.iter().enumerate() {
                work.charge_work(1)?;
                let (expected_kind, expected, producer) = candidate.bytes_in();
                if matched[ordinal] || kind != expected_kind || actual.len() != expected.len() {
                    continue;
                }
                if let Some(producer) = producer {
                    producer.charge_work_in(work, expected.len() as u64)?;
                } else {
                    work.charge_work(expected.len() as u64)?;
                }
                if actual == expected {
                    matched[ordinal] = true;
                    remaining -= 1;
                }
            }
            Ok(())
        })?;
    }
    for (ordinal, &found) in matched.iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        if !found {
            return Ok(Some(ordinal));
        }
    }
    Ok(None)
}

/// Complete relevant unsigned scope from one authenticated XML generation.
/// References, material, timestamp evidence and path results remain distinct.
pub struct Properties<X: Xml> {
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    parent: Option<X::Id>,
    references: OwnedVec<ReferencesFor<X>>,
    values: OwnedVec<ValuesFor<X>>,
    timestamps: OwnedVec<Timestamp<X>>,
}

impl<X: Xml> Properties<X> {
    /// Original document and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.snapshot
    }
    /// Exact selected signature.
    #[must_use]
    pub fn signature(&self) -> X::Id {
        self.signature
    }
    /// Original direct unsigned-signature parent if one exists.
    #[must_use]
    pub fn parent(&self) -> Option<X::Id> {
        self.parent
    }
    /// Complete original C reference properties in document order.
    #[must_use]
    pub fn references(&self) -> &[ReferencesFor<X>] {
        &self.references
    }
    /// Complete original direct XL/A material properties in document order.
    #[must_use]
    pub fn values(&self) -> &[ValuesFor<X>] {
        &self.values
    }
    /// Original T, X and A timestamps in property order, followed by signed
    /// data-object timestamps. Earlier A occurrences remain independently visible.
    #[must_use]
    pub fn timestamps(&self) -> &[Timestamp<X>] {
        &self.timestamps
    }

    /// Match every original token to independently obtained original-source proof.
    /// Returns the first property with a token still unverified. A later verified
    /// archive cannot replace an unchecked earlier token. Trust and chronology
    /// use the caller's path and historical validation processing.
    pub fn first_unverified<W: Work>(
        &self,
        receipts: &[VerifiedTimestamp<X>],
        work: &W,
    ) -> Result<Option<X::Id>, MemoryError> {
        let mut tokens = work.map();
        for receipt in receipts {
            work.charge_work(1)?;
            let token = receipt.token();
            if token.snapshot == self.snapshot
                && structured_ltv::source::equal_id(receipt.signature(), self.signature, work)?
            {
                tokens.try_insert(token.node, (receipt.property(), receipt.purpose()))?;
            }
        }
        for stamp in &self.timestamps {
            work.charge_work(1)?;
            for token in stamp.tokens() {
                let Some(&(property, purpose)) = tokens.get(token, work)? else {
                    return Ok(Some(stamp.node()));
                };
                if purpose != stamp.role().purpose()
                    || !structured_ltv::source::equal_id(property, stamp.node(), work)?
                {
                    return Ok(Some(stamp.node()));
                }
            }
        }
        Ok(None)
    }
}

enum Selection {
    Timestamp,
    Extended(ExtendedKind),
    Material(usize),
    References(usize, unsigned::Role),
    Other,
}

impl Selection {
    fn of(name: Name<'_>, syntax: ReferenceSyntax) -> Self {
        use unsigned::Role;
        if name == syntax.certificates(false) {
            return Self::References(0, Role::CertificateReferences);
        }
        if name == syntax.certificates(true) {
            return Self::References(2, Role::AttributeCertificateReferences);
        }
        if name.namespace == XADES {
            match name.local {
                "CompleteRevocationRefs" => return Self::References(1, Role::RevocationReferences),
                "AttributeRevocationRefs" => {
                    return Self::References(3, Role::AttributeRevocationReferences);
                }
                "SignatureTimeStamp" => return Self::Timestamp,
                "CertificateValues" => return Self::Material(4),
                "RevocationValues" => return Self::Material(5),
                "AttrAuthoritiesCertValues" => return Self::Material(6),
                "AttributeRevocationValues" => return Self::Material(7),
                _ => {}
            }
        }
        ExtendedKind::from_name(name, syntax).map_or(Self::Other, Self::Extended)
    }
}

/// Prepare the original relevant properties in one unsigned child traversal.
/// These profiles share the 1.3.2 qualifying container. The 1.2.2 family has
/// its own legacy parser and a different model for some timestamp inputs.
pub fn prepare<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Selected<X>,
    syntax: ReferenceSyntax,
) -> ResultFor<Properties<X>, X> {
    let layout = bound.containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() || layout.syntax() != Syntax::En319132 {
        return Err(Error::Timestamp(InputError::Foreign { node: signature }));
    }
    let parent = match layout.unsigned() {
        Some(unsigned) => {
            timestamp::optional(access, unsigned, XADES, "UnsignedSignatureProperties")
                .map_err(Error::Timestamp)?
        }
        None => None,
    };
    let work = access.execution();
    let mut references = work.vector();
    let mut values = work.vector();
    let mut timestamps = work.vector();
    if let Some(parent) = parent {
        let mut seen = [false; 8];
        for child in access.children(parent) {
            let node = child.map_err(|cause| Error::Property(properties::Error::Child(cause)))?;
            let resource = |cause| Error::Property(properties::Error::Resource { node, cause });
            // All name comparisons are against fixed namespace/local lengths.
            work.charge_work(384).map_err(resource)?;
            let selected = access
                .inspect(node, |value| match value {
                    Node::Element(name) => Selection::of(name, syntax),
                    _ => Selection::Other,
                })
                .map_err(|cause| Error::Property(properties::Error::Access(cause)))?;
            match selected {
                Selection::References(slot, role) => {
                    admit(&mut seen, slot, node).map_err(Error::Property)?;
                    references
                        .try_push(
                            validation::read_references_in(access, signature, node, role, syntax)
                                .map_err(Error::Property)?,
                        )
                        .map_err(resource)?;
                }
                Selection::Timestamp => {
                    let stamp = timestamp::read_fields_in(
                        access,
                        signature,
                        parent,
                        node,
                        Role::Signature,
                        syntax == ReferenceSyntax::Original,
                    )
                    .map_err(Error::Timestamp)?;
                    timestamps.try_push(stamp).map_err(resource)?;
                }
                Selection::Extended(kind) => {
                    let stamp = timestamp::read_extended_at(access, signature, parent, node, kind)
                        .map_err(Error::Timestamp)?;
                    timestamps.try_push(stamp).map_err(resource)?;
                }
                Selection::Material(slot) => {
                    admit(&mut seen, slot, node).map_err(Error::Property)?;
                    values
                        .try_push(material::read(access, node).map_err(Error::Property)?)
                        .map_err(resource)?;
                }
                Selection::Other => {}
            }
        }
    }
    append_signed_timestamps(access, layout, &mut timestamps)?;
    Ok(Properties {
        snapshot: layout.snapshot(),
        signature,
        parent,
        references: references.into_owned(),
        values: values.into_owned(),
        timestamps: timestamps.into_owned(),
    })
}

fn append_signed_timestamps<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
    timestamps: &mut OwnedVec<Timestamp<X>, W>,
) -> ResultFor<(), X> {
    let (_, signed_objects) = properties::sections(access, layout).map_err(Error::Property)?;
    if let Some(parent) = signed_objects {
        for child in access.children(parent) {
            let node = child.map_err(|cause| Error::Property(properties::Error::Child(cause)))?;
            let named = |local| {
                access
                    .has_name(
                        node,
                        Name {
                            namespace: XADES,
                            local,
                        },
                    )
                    .map_err(|cause| Error::Property(properties::Error::Access(cause)))
            };
            let role = if named("AllDataObjectsTimeStamp")? {
                Role::AllDataObjects
            } else if named("IndividualDataObjectsTimeStamp")? {
                Role::IndividualDataObjects
            } else {
                continue;
            };
            let stamp =
                timestamp::read_fields_in(access, layout.signature(), parent, node, role, false)
                    .map_err(Error::Timestamp)?;
            timestamps
                .try_push(stamp)
                .map_err(|cause| Error::Property(properties::Error::Resource { node, cause }))?;
        }
    }
    Ok(())
}

fn admit<E, N>(seen: &mut [bool; 8], slot: usize, node: N) -> Result<(), properties::Error<E, N>> {
    if seen[slot] {
        return Err(properties::Error::Duplicate { node });
    }
    seen[slot] = true;
    Ok(())
}
