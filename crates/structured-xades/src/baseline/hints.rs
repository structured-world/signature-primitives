//! DER syntax checks for optional certificate retrieval hints, not binding.

use super::{BasicError, Hint, HintSource, ProcessingResult};
use crate::{
    binary::BinaryXml,
    certificate,
    prepare::Prepared,
    validation::{self, ReferenceIdentifier},
    xml::Xml,
};
use structured_asn1::{
    Reader,
    memory::{OwnedVec, Work},
};

pub(super) struct EncodingChecks<N, D, G> {
    pub(super) items: OwnedVec<Hint<N, D, G>>,
    pub(super) all_conformant: bool,
}
type ResultFor<X> = ProcessingResult<
    EncodingChecks<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
>;

pub(super) fn check_encodings<X: BinaryXml>(
    prepared: &Prepared<X>,
    xml: &X,
    operation: &Reader<'_>,
) -> ResultFor<X> {
    let work = operation.execution();
    let signature = prepared.bound().containers().signature();
    let mut items = work.vector();
    // EN319132-1 §5.2.2 Note2 makes the digest authoritative; IssuerSerialV2
    // is only a retrieval hint. Do not import CMS ESS's identifier-binding
    // requirements just because that ASN.1 type supplies the common decoder.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let mut all_conformant = true;
    for (index, reference) in prepared.certificates().entries().iter().enumerate() {
        let resource = |cause| BasicError::Resource {
            node: reference.node(),
            cause,
        };
        work.charge_work(1).map_err(resource)?;
        if reference.issuer_serial().is_none() {
            continue;
        }
        items.try_reserve(1).map_err(resource)?;
        let hint = certificate::with_issuer_serial(
            xml,
            prepared.certificates(),
            index,
            operation,
            |reading| Ok::<_, core::convert::Infallible>(reading.into_parts().1),
        )
        .map_err(BasicError::Hint)?
        .ok_or(BasicError::Foreign { signature })?;
        if !hint.value.is_empty() {
            all_conformant = false;
        }
        items
            .try_push(Hint {
                location: hint.location,
                faults: hint.value,
                source: HintSource::Protected(index),
            })
            .map_err(resource)?;
    }
    // Annex A.1.1/A.1.3 import §5.2.2's CertIDListV2 including the one
    // DER IssuerSerial rule. A retrieval hint is not authoritative binding,
    // but its optional placement does not waive its declared encoding.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    for (property, references) in prepared.validation_references().iter().enumerate() {
        work.charge_work(1).map_err(|cause| BasicError::Resource {
            node: references.node(),
            cause,
        })?;
        for (entry, reference) in references.entries().iter().enumerate() {
            let resource = |cause| BasicError::Resource {
                node: reference.node(),
                cause,
            };
            work.charge_work(1).map_err(resource)?;
            if !matches!(
                reference.identifier(),
                ReferenceIdentifier::Certificate { .. }
            ) {
                continue;
            }
            items.try_reserve(1).map_err(resource)?;
            let hint = validation::with_reference_issuer_serial(
                xml,
                references,
                entry,
                operation,
                |reading| Ok::<_, core::convert::Infallible>(reading.into_parts().1),
            )
            .map_err(BasicError::Hint)?
            .ok_or(BasicError::Foreign { signature })?;
            if !hint.value.is_empty() {
                all_conformant = false;
            }
            items
                .try_push(Hint {
                    location: hint.location,
                    faults: hint.value,
                    source: HintSource::ValidationReference { property, entry },
                })
                .map_err(resource)?;
        }
    }
    Ok(EncodingChecks {
        items: items.into_owned(),
        all_conformant,
    })
}
