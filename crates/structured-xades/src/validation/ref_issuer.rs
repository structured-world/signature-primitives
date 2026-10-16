//! Shared original issuer/serial reading for unsigned certificate references.

use super::{ReferenceIdentifier, ReferenceProperty};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{self, IssuerError},
    xml::Access,
};
use structured_asn1::Reader;
use structured_cms::ess::IssuerSerialReading;

/// Read an optional original certificate-reference issuer/serial hint using
/// exactly the same DER/RFC5035 kernel as protected `SigningCertificateV2`.
/// Annex A.1.1/A.1.3 import the original clause5.2.2 `CertIDListV2` grammar.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Scope/storage, located readable faults and terminal source/resource/callback
/// causes remain unchanged. A hint cannot replace whole-certificate digest,
/// actual path use, signing-key association or incorporated-material checks.
pub fn with_reference_issuer_serial<X: BinaryXml, R, E>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(IssuerSerialReading<'source>) -> Result<R, E>,
) -> binary::BinaryResult<Option<binary::LocatedValue<R, X>>, X, IssuerError<E>> {
    let location = Location {
        snapshot: references.snapshot(),
        node: references.node(),
    };
    let work = operation.execution();
    Access::new(xml, references.snapshot(), &work)
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let Some(entry) = references.entries().get(index) else {
        return Err(binary::Error::Callback {
            location,
            cause: IssuerError::ReferenceIndex { index },
        });
    };
    let ReferenceIdentifier::Certificate {
        issuer_serial: node,
    } = entry.identifier()
    else {
        return Ok(None);
    };
    certificate::with_issuer_serial_at(
        xml,
        Location {
            snapshot: references.snapshot(),
            node,
        },
        operation,
        visitor,
    )
    .map(Some)
}
