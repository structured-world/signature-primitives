//! One original-source preparation path for subsequent baseline execution.

use crate::reference::ReferenceXml;
use crate::xml::{Access, AccessError, Xml};
use crate::{
    binding, certificate, commitment, container, counter, format, header, material, policy,
    properties, renewed, role, timestamp, unsigned, validation,
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::baseline::ArchiveCensus;
use structured_ltv::source::Location;

mod uri;
pub use uri::{UriError, UriResult, check_uris};
mod fields;
pub use fields::{FieldError, FieldResult, Fields, check_fields};

/// Original refusal in the corresponding processing stage.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original direct-incorporation layout failure.
    Container(container::ContainerError<E, N>),
    /// Selected XMLDSig/whole-SignedProperties binding failure.
    Binding(binding::BindingError<E, N>),
    /// Original property/header/material structure failure.
    Property(properties::Error<E, N>),
    /// Original complete object-format/reference association failure.
    Format(format::CoverageError<E, N>),
    /// Original signed commitment schema/reference-association refusal.
    Commitment(commitment::AssociationError<E, N>),
    /// Original timestamp selection failure.
    Timestamp(timestamp::InputError<E, N>),
    /// Original validation-data selection failure.
    Validation(validation::Error<E, N>),
    /// Original source/dispatch admission refusal.
    Access(AccessError<E, N>),
    /// Accounted metadata catalogue admission refusal.
    Resource {
        /// Original selected signature.
        signature: N,
        /// Original resource cause.
        cause: MemoryError,
    },
}

/// Original prepared source models. This is NOT a verified B level: scalar/
/// optional-property semantics, certificate/key/path/status checking and actual
/// timestamp execution still have to complete. No trust/evidence constructor is
/// exposed by this object, and unknown original properties remain in inventory.
pub struct Preparation<N, D, G> {
    requirements: unsigned::Requirements,
    extended: Option<timestamp::ReferenceSyntax>,
    bound: binding::Bound<N, D, G>,
    signed: properties::Signed<N, D, G>,
    header: header::Header<N, D, G>,
    certificates: certificate::References<N, D, G>,
    formats: OwnedVec<format::CoveredFormat<N, D, G>>,
    commitments: OwnedVec<commitment::Association<N, D, G>>,
    roles: Option<role::Roles<N, D, G>>,
    policy: Option<policy::Reading<N, D, G>>,
    policy_store: Option<policy::Store<N, D, G>>,
    unsigned: unsigned::Catalogue<N, D, G>,
    timestamps: OwnedVec<timestamp::Stamp<N, D, G>>,
    material: OwnedVec<material::Catalogue<N, D, G>>,
    validation: OwnedVec<validation::Data<N, D, G>>,
    renewed: OwnedVec<renewed::Catalogue<N, D, G>>,
    references: OwnedVec<validation::ReferenceProperty<N, D, G>>,
}

impl<N, D, G> Preparation<N, D, G> {
    /// Requested structural requirements actually enforced during preparation;
    /// this does not infer a verified level from additional container presence.
    #[must_use]
    pub fn requirements(&self) -> unsigned::Requirements {
        self.requirements
    }
    /// The caller-selected extended vocabulary, if this is a shared
    /// processing preparation instead of an EN baseline preparation.
    #[must_use]
    pub fn extended_syntax(&self) -> Option<timestamp::ReferenceSyntax> {
        self.extended
    }
    /// Original authenticated whole-SignedProperties binding.
    #[must_use]
    pub fn bound(&self) -> &binding::Bound<N, D, G> {
        &self.bound
    }
    /// Original signed-property roles, including unprocessed optional fields.
    #[must_use]
    pub fn signed(&self) -> &properties::Signed<N, D, G> {
        &self.signed
    }
    /// Baseline header roles, before candidate inclusion checking.
    #[must_use]
    pub fn header(&self) -> &header::Header<N, D, G> {
        &self.header
    }
    /// Original certificate-digest references, before actual digest/key binding.
    #[must_use]
    pub fn certificates(&self) -> &certificate::References<N, D, G> {
        &self.certificates
    }
    /// Complete required reference association and exact ds:Object metadata
    /// agreement and MIME syntax; URI lexical validation remains separate.
    #[must_use]
    pub fn formats(&self) -> &[format::CoveredFormat<N, D, G>] {
        &self.formats
    }
    /// Original commitments with completed authenticated instruction lookup;
    /// URI lexical and application-policy meaning checks remain separate.
    #[must_use]
    pub fn commitments(&self) -> &[commitment::Association<N, D, G>] {
        &self.commitments
    }
    /// Original optional role credentials, without issuer trust assertions.
    #[must_use]
    pub fn roles(&self) -> Option<&role::Roles<N, D, G>> {
        self.roles.as_ref()
    }
    /// Original signed policy choice, before document or application acceptance.
    #[must_use]
    pub fn policy(&self) -> Option<&policy::Reading<N, D, G>> {
        self.policy.as_ref()
    }
    /// Original store permitted by the signed explicit policy hash. Its bytes
    /// remain untrusted until actual comparison with that signed digest.
    #[must_use]
    pub fn policy_store(&self) -> Option<&policy::Store<N, D, G>> {
        self.policy_store.as_ref()
    }
    /// Full original unsigned-property inventory; it is not a material census.
    #[must_use]
    pub fn unsigned(&self) -> &unsigned::Catalogue<N, D, G> {
        &self.unsigned
    }
    /// Selected timestamp source models, not parsed or verified token evidence.
    #[must_use]
    pub fn timestamps(&self) -> &[timestamp::Stamp<N, D, G>] {
        &self.timestamps
    }
    /// Original ordinary/attribute validation-material value catalogues.
    #[must_use]
    pub fn material(&self) -> &[material::Catalogue<N, D, G>] {
        &self.material
    }
    /// Original general/timestamp-specific validation-data catalogues.
    #[must_use]
    pub fn validation(&self) -> &[validation::Data<N, D, G>] {
        &self.validation
    }
    /// Original renewed-digest pairs. Authenticated detached Manifest matching
    /// and both actual hash comparisons remain separate execution obligations.
    #[must_use]
    pub fn renewed(&self) -> &[renewed::Catalogue<N, D, G>] {
        &self.renewed
    }
    /// Complete original optional validation-reference fields. These unsigned
    /// models cannot substitute for protected signing-certificate binding;
    /// their scalar syntax and actual artifact comparisons remain separate.
    #[must_use]
    pub fn validation_references(&self) -> &[validation::ReferenceProperty<N, D, G>] {
        &self.references
    }
}

impl<N: Copy, D: Copy, G: Copy> ArchiveCensus for Preparation<N, D, G> {
    type Id = N;
    type Document = D;
    type Generation = G;

    fn signature(&self) -> Location<N, D, G> {
        let layout = self.bound.containers();
        Location {
            snapshot: layout.snapshot(),
            node: layout.signature(),
        }
    }
    fn timestamps(&self) -> usize {
        self.timestamps.len()
    }
    fn archive(&self, ordinal: usize) -> Option<N> {
        let stamp = &self.timestamps[ordinal];
        (stamp.role() == timestamp::Role::Archive).then(|| stamp.node())
    }
}

/// Preparation using this owner's stable identity domain. Retained metadata
/// does not pin the XML adapter type or its temporary scoped view lifetime.
pub type Prepared<X> = Preparation<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Source preparation result retaining stage-specific original causes.
pub type PrepareResult<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// Original signed protection and the matching reference/timestamp catalogue.
pub struct Original<X: Xml> {
    /// Protected original properties and signing-certificate selection.
    pub prepared: crate::legacy::Prepared<X>,
    /// Original C/X/XL/A inputs for continued validation.
    pub properties: crate::extended::Properties<X>,
}

/// Original failure while preparing either extended-signature vocabulary.
#[derive(Debug)]
pub enum ExtendedError<E, N> {
    /// Layout, reference, timestamp or material preparation refusal.
    Source(Error<E, N>),
    /// Original historical signed-property or signing-certificate refusal.
    Historical(crate::legacy::Error<E, N>),
}

impl<E, N> From<Error<E, N>> for ExtendedError<E, N> {
    fn from(error: Error<E, N>) -> Self {
        Self::Source(error)
    }
}

/// Extended preparation using this XML owner's identity and error types.
pub type OriginalResult<X> = Result<Original<X>, ExtendedError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Prepares the original selected signature with one shared structural path.
/// No certificate hash, canonicalization, token/provider execution or implicit
/// acquisition occurs here. All catalogues retain their actual capacity account;
/// refusal drops partial preparation without returning a successful subset.
pub fn prepare<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    requirements: unsigned::Requirements,
    counter: Option<&counter::Binding<X>>,
) -> PrepareResult<Prepared<X>, X> {
    prepare_in(access, signature, requirements, counter, None)
}

/// Prepare directly incorporated C/X/XL/A inputs using the V2 vocabulary.
/// `requirements` selects structural obligations without claiming a baseline
/// level or treating C references as a substitute for incorporated XL values.
pub fn prepare_extended_v2<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    requirements: unsigned::Requirements,
    counter: Option<&counter::Binding<X>>,
) -> PrepareResult<Prepared<X>, X> {
    prepare_in(
        access,
        signature,
        requirements,
        counter,
        Some(timestamp::ReferenceSyntax::V2),
    )
}

/// Prepare directly incorporated C/X/XL/A inputs with the original 1.3.2
/// signed properties, signer certificate, references and replay recipes.
pub fn prepare_extended_original<X: ReferenceXml + crate::scalar::ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    requirements: unsigned::Requirements,
    counter: Option<&counter::Binding<X>>,
) -> OriginalResult<X> {
    use crate::{extended, legacy};
    // TS 101 903 V1.4.2 §§7.2.2–7.2.6 uses the original signed vocabulary.
    // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
    let layout =
        legacy::locate(access, signature, legacy::Profile::PreEn).map_err(Error::Container)?;
    if let Some(counter) = counter {
        let original = counter.original();
        if original.snapshot() != layout.snapshot()
            || !access
                .equal_id(original.child(), signature)
                .map_err(|cause| Error::Resource { signature, cause })?
        {
            return Err(
                Error::Timestamp(timestamp::InputError::Foreign { node: signature }).into(),
            );
        }
    }
    let prepared = legacy::prepare(access, &layout).map_err(ExtendedError::Historical)?;
    let properties = extended::prepare(
        access,
        prepared.binding(),
        timestamp::ReferenceSyntax::Original,
    )
    .map_err(|cause| match cause {
        extended::Error::Property(cause) => Error::Property(cause),
        extended::Error::Timestamp(cause) => Error::Timestamp(cause),
    })?;
    extended_requirements(access, signature, requirements, &properties)?;
    Ok(Original {
        prepared,
        properties,
    })
}

fn extended_requirements<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    requirements: unsigned::Requirements,
    properties: &crate::extended::Properties<X>,
) -> PrepareResult<(), X> {
    if requirements == unsigned::Requirements::Basic {
        return Ok(());
    }
    let mut signature_stamp = false;
    let mut archive = false;
    for stamp in properties.timestamps() {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| Error::Resource { signature, cause })?;
        signature_stamp |= stamp.role() == timestamp::Role::Signature;
        archive |= stamp.role() == timestamp::Role::Archive;
    }
    let missing = if !signature_stamp {
        "SignatureTimeStamp"
    } else if requirements == unsigned::Requirements::Archival && !archive {
        "ArchiveTimeStamp"
    } else {
        return Ok(());
    };
    Err(Error::Property(properties::Error::Missing {
        parent: signature,
        local: missing,
    }))
}

fn prepare_in<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    requirements: unsigned::Requirements,
    counter: Option<&counter::Binding<X>>,
    extended: Option<timestamp::ReferenceSyntax>,
) -> PrepareResult<Prepared<X>, X> {
    let layout = container::locate(access, signature).map_err(Error::Container)?;
    let bound = binding::bind(access, &layout).map_err(Error::Binding)?;
    let header = header::read(access, &bound).map_err(Error::Property)?;
    let signed = properties::read(access, &bound).map_err(Error::Property)?;
    let certificates = certificate::read(access, &signed).map_err(Error::Property)?;
    let roles = role::read(access, &signed).map_err(Error::Property)?;
    let policy = policy::read(access, &signed).map_err(Error::Property)?;
    let unsigned =
        unsigned::read_in(access, &bound, requirements, extended).map_err(Error::Property)?;
    let policy_store =
        policy::read_store(access, &unsigned, policy.as_ref()).map_err(Error::Property)?;
    unsigned::check_credential_material(access, &unsigned, roles.as_ref())
        .map_err(Error::Property)?;
    let formats =
        format::check_references(access, &bound, &signed, counter).map_err(Error::Format)?;
    let work = access.execution();
    let mut commitments = work.vector();
    let mut timestamps = work.vector();
    let mut material = work.vector();
    let mut validation = work.vector();
    let mut renewed = work.vector();
    let mut references = work.vector();
    let refusal = |cause| Error::Resource { signature, cause };
    for index in 0..unsigned.entries().len() {
        admit(access, signature)?;
        let entry = unsigned.entries()[index];
        match entry.role {
            unsigned::Role::SignatureTimestamp
            | unsigned::Role::Archive
            | unsigned::Role::SignatureAndReferencesTimestamp
            | unsigned::Role::ReferencesTimestamp => {
                let stamp = read_unsigned_stamp(access, &bound, &unsigned, entry, extended)
                    .map_err(Error::Timestamp)?;
                timestamps.try_push(stamp).map_err(refusal)?;
            }
            unsigned::Role::Certificates
            | unsigned::Role::Revocation
            | unsigned::Role::AttributeCertificates
            | unsigned::Role::AttributeRevocation => {
                let values = material::read(access, entry.node).map_err(Error::Property)?;
                material.try_push(values).map_err(refusal)?;
            }
            unsigned::Role::AnyValidation | unsigned::Role::TimestampValidation => {
                let values =
                    validation::read(access, &bound, entry.node).map_err(Error::Validation)?;
                validation.try_push(values).map_err(refusal)?;
            }
            unsigned::Role::RenewedDigests => {
                let values = renewed::read(access, &unsigned, index).map_err(Error::Property)?;
                renewed.try_push(values).map_err(refusal)?;
            }
            unsigned::Role::CertificateReferences
            | unsigned::Role::RevocationReferences
            | unsigned::Role::AttributeCertificateReferences
            | unsigned::Role::AttributeRevocationReferences => {
                let values = validation::read_references_in(
                    access,
                    signature,
                    entry.node,
                    entry.role,
                    extended.unwrap_or(timestamp::ReferenceSyntax::V2),
                )
                .map_err(Error::Property)?;
                references.try_push(values).map_err(refusal)?;
            }
            _ => {} // Preserved in the complete inventory for subsequent execution.
        }
    }
    signed_objects(
        access,
        &bound,
        &signed,
        &mut timestamps,
        &mut commitments,
        extended == Some(timestamp::ReferenceSyntax::Original),
    )?;
    Ok(Preparation {
        requirements,
        extended,
        bound,
        signed,
        header,
        certificates,
        formats,
        commitments: commitments.into_owned(),
        roles,
        policy,
        policy_store,
        unsigned,
        timestamps: timestamps.into_owned(),
        material: material.into_owned(),
        validation: validation.into_owned(),
        renewed: renewed.into_owned(),
        references: references.into_owned(),
    })
}

fn read_unsigned_stamp<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &binding::Selected<X>,
    unsigned: &unsigned::Reading<X>,
    entry: unsigned::Entry<X::Id>,
    extended: Option<timestamp::ReferenceSyntax>,
) -> timestamp::InputResult<timestamp::Timestamp<X>, X> {
    let node = entry.node;
    let Some(syntax) = extended else {
        return timestamp::read(access, bound, node);
    };
    let signature = unsigned.signature();
    let parent = unsigned
        .parent()
        .ok_or(timestamp::InputError::Foreign { node })?;
    if entry.role == unsigned::Role::SignatureTimestamp {
        return timestamp::read_fields_in(
            access,
            signature,
            parent,
            node,
            timestamp::Role::Signature,
            syntax == timestamp::ReferenceSyntax::Original,
        );
    }
    let kind = access
        .inspect(node, |value| {
            if let crate::xml::Node::Element(name) = value {
                // Four exact expanded-name comparisons, bounded by the constants.
                access.execution().charge_work(384)?;
                Ok(timestamp::ExtendedKind::from_name(name, syntax))
            } else {
                Ok(None)
            }
        })
        .map_err(timestamp::InputError::Access)?
        .map_err(|cause| timestamp::InputError::Resource { node, cause })?
        .ok_or(timestamp::InputError::Unexpected { node })?;
    timestamp::read_extended_at(access, signature, parent, node, kind)
}

fn admit<X: Xml, W: Work>(access: &Access<'_, X, W>, signature: X::Id) -> PrepareResult<(), X> {
    access
        .query(signature, |_, _, work| Ok(work.charge_work(1)))
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { signature, cause })
}

fn signed_objects<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &binding::Selected<X>,
    signed: &properties::Reading<X>,
    timestamps: &mut OwnedVec<timestamp::Timestamp<X>, W>,
    commitments: &mut OwnedVec<commitment::Prepared<X>, W>,
    historical: bool,
) -> PrepareResult<(), X> {
    let Some(objects) = signed.data_objects() else {
        return Ok(());
    };
    for index in 0..objects.entries().len() {
        admit(access, signed.signature())?;
        let entry = objects.entries()[index];
        if entry.role == properties::DataObjectRole::Commitment {
            let value =
                commitment::prepare(access, bound, signed, index).map_err(Error::Commitment)?;
            commitments
                .try_push(value)
                .map_err(|cause| Error::Resource {
                    signature: signed.signature(),
                    cause,
                })?;
            continue;
        }
        let role = match entry.role {
            properties::DataObjectRole::AllTimestamp => timestamp::Role::AllDataObjects,
            properties::DataObjectRole::IndividualTimestamp => {
                timestamp::Role::IndividualDataObjects
            }
            _ => continue,
        };
        let stamp = if historical {
            timestamp::read_fields_in(
                access,
                signed.signature(),
                objects.parent(),
                entry.node,
                role,
                true,
            )
        } else if role == timestamp::Role::AllDataObjects {
            timestamp::read_all_data_objects(access, bound, signed, entry.node)
        } else {
            timestamp::read_individual_data_objects(access, bound, signed, entry.node)
        }
        .map_err(Error::Timestamp)?;
        timestamps
            .try_push(stamp)
            .map_err(|cause| Error::Resource {
                signature: signed.signature(),
                cause,
            })?;
    }
    Ok(())
}
