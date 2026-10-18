//! The common artifact index over this format's material pools.

use super::{Opaque, Placement, Value, View};
use crate::timestamp::CarriedMaterial;
use crate::xml::{Access, Xml};
use crate::{ISSUER, Xades};
use structured_asn1::memory::Work;
use structured_ltv::material::{
    self as ltv, ArtifactRef, ArtifactSource, CarriedOrigin, IndexError,
};

/// Exact artifact index of one signature's `XAdES` material, keyed by original
/// DER and carrying each occurrence's container placement.
pub type Index<'source, N, D, G, W> =
    ltv::Index<'source, N, D, G, Placement<N>, Opaque<N, D, G>, W, Xades>;
/// One original occurrence and its `XAdES` container placement.
pub type Occurrence<N, D, G> = ltv::Occurrence<N, D, G, Placement<N>>;
/// Archive availability of one artifact, with its `XAdES` placement.
pub type Archived<N, D, G> = ltv::Archived<N, D, G, Placement<N>>;

/// The index of this XML owner's material, or the refusal to build it.
pub type IndexResult<'source, X, W> = Result<
    Index<'source, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, W>,
    IndexError<<X as Xml>::Id>,
>;

/// Builds the index from the already parsed/frozen set without decoding values
/// again. All source and embedded certificate metadata, exact hashing/equality,
/// hidden table probes, entries and duplicate links are funded before work.
/// Refusal drops the complete partial index, preserving original sources.
pub fn index<'source, X: Xml, W: Work>(
    view: &View<'source, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> IndexResult<'source, X, W> {
    let signature = view.signature;
    if view.snapshot != access.snapshot() {
        return Err(IndexError::Foreign { signature });
    }
    let mut index = Index::new(ISSUER, signature, view.opaque(), access)?;
    let mut next_basic = 0;
    for ordinal in 0..view.values.len() {
        index.admit(access)?;
        let value = &view.values[ordinal];
        let placement = view.sources[ordinal].placement();
        let artifact = match &value.value {
            Value::Certificate(value) => ArtifactRef::Certificate(value),
            Value::Crl(value) => ArtifactRef::Crl(value),
            Value::Ocsp(_) => {
                if let Some(basic) = view.basic.get(next_basic)
                    && basic.source_index() == ordinal
                {
                    index.insert(
                        ArtifactRef::Ocsp(basic.response()),
                        Occurrence::new(
                            ArtifactSource::Material(basic.source_index()),
                            basic.location(),
                            placement,
                        ),
                        access,
                    )?;
                    next_basic += 1;
                }
                continue;
            }
        };
        index.insert(
            artifact,
            Occurrence::new(ArtifactSource::Material(ordinal), value.location, placement),
            access,
        )?;
    }
    index.admit(access)?;
    Ok(index)
}

/// Builds one exact-artifact index from both already parsed original source
/// sets. XML-pool occurrences stay first; token-pool occurrences retain their
/// explicit pool/ordinal and actual placement. All growth belongs to this
/// current execution. Any late refusal drops the complete partial index
/// instead of returning a mutable prefix.
pub fn index_with_tokens<'source, X: Xml, W: Work>(
    view: &View<'source, X::Id, X::Document, X::Generation>,
    material: &CarriedMaterial<'source, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> IndexResult<'source, X, W> {
    if material.view.snapshot() != view.snapshot {
        return Err(IndexError::Foreign {
            signature: view.signature,
        });
    }
    if !access
        .equal_id(material.view.signature(), view.signature)
        .map_err(|cause| IndexError::Resource {
            signature: view.signature,
            cause,
        })?
    {
        return Err(IndexError::Foreign {
            signature: view.signature,
        });
    }
    let mut index = index(view, access)?;
    // The two immutable source sets were bound above; each insertion still
    // admits under the current source snapshot.
    index.admit(access)?;
    for token in 0..material.view.readings().len() {
        index.admit(access)?;
        let source = &material.view.sources()[token];
        let placement = Placement::TimestampToken {
            property: source.property(),
            token: source.location().node,
            role: source.role(),
        };
        let certificates = material.view.readings()[token]
            .token()
            .message()
            .certificates();
        for (certificate, value) in certificates.iter().enumerate() {
            index.admit(access)?;
            index.insert(
                ArtifactRef::Certificate(value),
                Occurrence::new(
                    ArtifactSource::TokenCertificate { token, certificate },
                    source.location(),
                    placement,
                ),
                access,
            )?;
        }
    }
    for value in material.crls() {
        index.admit(access)?;
        index.insert(
            ArtifactRef::Crl(&value.value),
            carried(material, value.origin),
            access,
        )?;
    }
    for value in material.basic_responses() {
        index.admit(access)?;
        index.insert(
            ArtifactRef::Ocsp(&value.value),
            carried(material, value.origin),
            access,
        )?;
    }
    index.admit(access)?;
    Ok(index)
}

fn carried<N: Copy, D: Copy, G: Copy>(
    material: &CarriedMaterial<'_, N, D, G>,
    origin: CarriedOrigin,
) -> Occurrence<N, D, G> {
    let source = &material.view.sources()[origin.token];
    Occurrence::new(
        ArtifactSource::TokenRevocation(origin),
        source.location(),
        Placement::TimestampToken {
            property: source.property(),
            token: source.location().node,
            role: source.role(),
        },
    )
}
