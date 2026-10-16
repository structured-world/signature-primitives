//! Original counter sources; no root baseline is imposed on plain `XMLDSig`.
use super::Placement;
use super::pipeline::{
    CounterSources, Error, Open, PipelineResult, Record, admit, collect, collect_data,
    collect_validation,
};
use crate::binary::OwnedBinaryXml;
use crate::container::DS;
use crate::xml::{Access, Name};
use structured_asn1::{
    Reader,
    memory::{OwnedVec, Work},
};

pub(super) fn collect_counters<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    counters: &CounterSources<'_, '_, X>,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
    opaque: &mut OwnedVec<Open<X>, W>,
) -> PipelineResult<(), X, VE> {
    for actor in counters.actors() {
        let original = actor.signer().counter().original();
        let signature = original.child();
        admit(access, signature)?;
        if original.snapshot() != access.snapshot() {
            return Err(Error::Foreign { node: signature });
        }
        collect_key_info(xml, access, signature, operation, sources)?;
        if let Some(layout) = actor.containers() {
            let [parent, _] =
                crate::unsigned::containers(access, layout.unsigned()).map_err(Error::Property)?;
            if let Some(parent) = parent {
                collect_properties(xml, access, (signature, parent), operation, sources, opaque)?;
            }
        }
    }
    Ok(())
}

fn collect_key_info<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    signature: X::Id,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
) -> PipelineResult<(), X, VE> {
    let mut key_info = None;
    for child in access.children(signature) {
        let node =
            child.map_err(|cause| Error::Property(crate::properties::Error::Child(cause)))?;
        if access
            .has_name(
                node,
                Name {
                    namespace: DS,
                    local: "KeyInfo",
                },
            )
            .map_err(Error::Access)?
        {
            if key_info.is_some() {
                return Err(Error::Property(crate::properties::Error::Duplicate {
                    node,
                }));
            }
            key_info = Some(node);
        }
    }
    let Some(key_info) = key_info else {
        return Ok(());
    };
    for child in access.children(key_info) {
        let node =
            child.map_err(|cause| Error::Property(crate::properties::Error::Child(cause)))?;
        if access
            .has_name(
                node,
                Name {
                    namespace: DS,
                    local: "X509Data",
                },
            )
            .map_err(Error::Access)?
        {
            // XMLDSig1.1 §4.5.4 permits several related X509Data containers;
            // the root baseline's one-X509Data restriction does not apply here.
            // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-X509Data
            collect_data(xml, access, signature, node, operation, sources)?;
        }
    }
    Ok(())
}

fn collect_properties<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    scope: (X::Id, X::Id),
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
    opaque: &mut OwnedVec<Open<X>, W>,
) -> PipelineResult<(), X, VE> {
    let (signature, parent) = scope;
    let mut previous = None;
    for child in access.children(parent) {
        let node =
            child.map_err(|cause| Error::Property(crate::properties::Error::Child(cause)))?;
        admit(access, node)?;
        // These are original structural roles, not a parallel PKI grammar or
        // a profile verdict on other properties of the child signature.
        if let Some(kind) =
            super::catalogue::container_kind(access, node).map_err(Error::Property)?
        {
            let placement = if kind.attribute() {
                Placement::Attribute(node)
            } else {
                Placement::Signature(node)
            };
            let catalogue = super::read(access, node).map_err(Error::Property)?;
            collect(
                xml, access, &catalogue, placement, operation, sources, opaque,
            )?;
        } else {
            let mut validation = false;
            for local in ["AnyValidationData", "TimeStampValidationData"] {
                if access
                    .has_name(
                        node,
                        Name {
                            namespace: crate::timestamp::XADES_141,
                            local,
                        },
                    )
                    .map_err(Error::Access)?
                {
                    validation = true;
                    break;
                }
            }
            if validation {
                let data = crate::validation::read_at(access, signature, node, previous)
                    .map_err(Error::Validation)?;
                collect_validation(xml, access, &data, operation, sources, opaque)?;
            }
        }
        previous = Some(node);
    }
    Ok(())
}
