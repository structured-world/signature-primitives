//! Original embedded validation material, separate from authentication/completeness.

use crate::binary::{self, Located, LocatedValue, Location, OwnedBinaryXml, OwnedDecoded};
use crate::container::{DS, XADES};
use crate::header;
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::{Encoding, Reader};
use structured_pkix::{Certificate, crl::CertificateList, ocsp::Response};

mod catalogue;
mod checks;
pub use checks::{CheckError, CheckResult, Checks, check_participants};
mod conditional;
pub use conditional::{
    ConditionalError, ConditionalFailure, ConditionalFinding, ConditionalPlacement,
    ConditionalResult, conditional_placement,
};
mod counters;
pub mod credentials;
pub use catalogue::{Catalogue, Entry, read};
mod pipeline;
pub use pipeline::{
    Basic, Error as PipelineError, Opaque, PipelineResult, Placement, Retained, View,
    with_counter_values, with_values,
};
pub(crate) mod exclusivity;
#[cfg(test)]
mod fixture;
mod incorporation;
mod index;
pub use incorporation::{
    IncorporatedArtifact, Incorporation, IncorporationError, IncorporationResult, incorporation,
};
mod participants;
mod timestamp_placement;
pub use timestamp_placement::{
    TimestampPlacement, TimestampPlacementError, TimestampPlacementFailure,
    TimestampPlacementFinding, TimestampPlacementResult, timestamp_placement,
};
pub mod status;
mod uses;
pub use exclusivity::{
    ExclusiveFinding, ExclusiveFindingKind, ExclusivePlacement, ExclusivityError,
    ExclusivityResult, exclusivity,
};
pub use index::{
    ArchiveError, Archived, ArchivedCertificate, ArtifactRef, ArtifactSource, Index, IndexError,
    Occurrence, Occurrences, PathCertificate, PathCertificates,
};
pub use participants::{
    AnchorMaterial, ParticipantArchiveError, ParticipantArchiveResult, ParticipantMaterial,
    archived_participants,
};
pub use uses::{ArtifactUse, ArtifactUses, ArtifactUsesResult, artifact_uses};

/// The `XAdES` schema of one original encapsulated material element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `EncapsulatedX509Certificate`, containing one DER certificate.
    Certificate,
    /// `EncapsulatedCRLValue`, containing one DER `CertificateList`.
    Crl,
    /// `EncapsulatedOCSPValue`, containing a whole DER `OCSPResponse`.
    Ocsp,
}

impl Kind {
    fn local(self) -> &'static str {
        match self {
            Self::Certificate => "EncapsulatedX509Certificate",
            Self::Crl => "EncapsulatedCRLValue",
            Self::Ocsp => "EncapsulatedOCSPValue",
        }
    }
}

/// A retained original source before PKI parsing or any authentication decision.
#[derive(Debug)]
pub struct Source<N, D, G> {
    kind: Kind,
    original: Located<OwnedDecoded, N, D, G>,
}

/// Material source using the XML owner's stable source identities.
pub type Material<X> = Source<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Refusal before a material source has been retained.
#[derive(Debug)]
pub enum RetainError<E, N> {
    /// Caller selected no original certificate in the selected `KeyInfo` header.
    HeaderIndex {
        /// Original selected signature.
        signature: N,
        /// Caller-provided certificate ordinal.
        index: usize,
    },
    /// Original XML/source/resource refusal.
    Access(AccessError<E, N>),
    /// The selected original node does not have this material's expanded name.
    Name {
        /// Original rejected node.
        node: N,
        /// Required material schema.
        kind: Kind,
    },
}

/// Retention result using the XML owner's original error and identity types.
pub type RetainResult<T, X> = Result<T, RetainError<<X as Xml>::Error, <X as Xml>::Id>>;

/// A decoded material value. Parsing does not establish a signature, status,
/// authority, freshness, path or baseline level. OCSP protocol failures remain
/// protocol failures rather than disappearing from a material catalogue.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "fixed-size parsed value avoids an extra allocation per material; any retained collection admits its full enum capacity"
)]
pub enum Value<'source> {
    /// Original certificate, retaining its producing session and ranges.
    Certificate(Certificate<'source>),
    /// Original CRL, not yet authenticated or checked for scope/freshness.
    Crl(CertificateList<'source>),
    /// Whole original OCSP envelope, with its basic response still decoded lazily.
    Ocsp(Response<'source>),
}

/// Refusal while parsing exactly one retained material value.
#[derive(Debug)]
pub enum Cause {
    /// Original reader/resource error, in decoded-source coordinates.
    Encoding(structured_asn1::Error),
    /// Original PKI schema/resource error, in decoded-source coordinates.
    Pki(structured_pkix::Error),
    /// No ASN.1 value in this material source.
    Empty {
        /// First decoded-source offset.
        offset: u64,
    },
    /// Bytes remain after the one specified PKI value.
    Trailing {
        /// First unconsumed decoded-source offset.
        offset: u64,
    },
}

/// One parsed material value or its unchanged cause, both in the original source.
pub type ReadResult<'source, N, D, G> =
    Result<Located<Value<'source>, N, D, G>, Located<Cause, N, D, G>>;

impl<N: Copy, D: Copy, G: Copy> Source<N, D, G> {
    /// Actual material schema, not a conclusion about its validity or use.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Original XML enclosure; inner offsets are in this distinct decoded source.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.original.location
    }

    /// Original decoded window, without another copy or exposing mutable storage.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.original.value.bytes
    }

    /// Parses exactly one value using the existing PKIX kernel and both budgets.
    /// Multiple results can simultaneously borrow a finalized source catalogue.
    /// EN319132-1 V1.3.1 §§5.4.2/5.4.3 fix DER for these binary values; in
    /// particular an OCSP value is `OCSPResponse`, not bare `BasicOCSPResponse`.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn read_in<'source>(
        &'source self,
        operation: &Reader<'source>,
    ) -> ReadResult<'source, N, D, G> {
        let read = || {
            let mut reader = self
                .original
                .value
                .reader_in(operation, Encoding::Der)
                .map_err(Cause::Encoding)?;
            let element = reader
                .next_element()
                .map_err(Cause::Encoding)?
                .ok_or(Cause::Empty {
                    offset: reader.offset(),
                })?;
            let value = match self.kind {
                Kind::Certificate => Value::Certificate(
                    Certificate::read_element(&reader, &element).map_err(Cause::Pki)?,
                ),
                Kind::Crl => Value::Crl(
                    CertificateList::read_element(&reader, &element).map_err(Cause::Pki)?,
                ),
                Kind::Ocsp => {
                    Value::Ocsp(Response::read_element(&reader, &element).map_err(Cause::Pki)?)
                }
            };
            if !reader.is_empty() {
                return Err(Cause::Trailing {
                    offset: reader.offset(),
                });
            }
            Ok(value)
        };
        match read() {
            Ok(value) => Ok(Located {
                location: self.location(),
                value,
            }),
            Err(value) => Err(Located {
                location: self.location(),
                value,
            }),
        }
    }
}

/// Retains one exact original material node after validating its expanded name.
/// Its containing property and selected-signature relationship must separately
/// be established by the property reader. This performs no acquisition or trust
/// decision and cannot promote an arbitrary parsed value to authenticated data.
pub fn retain<X: OwnedBinaryXml>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    kind: Kind,
    operation: &Reader<'_>,
) -> RetainResult<Material<X>, X> {
    retain_expected(xml, location, kind, XADES, kind.local(), operation)
}

/// Retains an actual selected `KeyInfo/X509Data/X509Certificate` using the same
/// owned base64/source and PKIX kernels as embedded material. Parsing uses the
/// existing shared PKIX DER certificate profile; it does not normalize another
/// certificate encoding or assert that all generic `XMLDSig` encodings are DER.
/// Neither `KeyInfo` membership nor retention establishes selected-key/path trust.
pub fn retain_header<X: OwnedBinaryXml>(
    xml: &X,
    header: &header::Reading<X>,
    index: usize,
    operation: &Reader<'_>,
) -> RetainResult<Material<X>, X> {
    let execution = operation.execution();
    let access = Access::new(xml, header.snapshot(), &execution);
    access
        .query(header.signature(), |_, _, _| Ok(()))
        .map_err(RetainError::Access)?;
    let Some(&node) = header.certificates().get(index) else {
        return Err(RetainError::HeaderIndex {
            signature: header.signature(),
            index,
        });
    };
    retain_expected(
        xml,
        Location {
            snapshot: header.snapshot(),
            node,
        },
        Kind::Certificate,
        DS,
        "X509Certificate",
        operation,
    )
}

fn retain_expected<X: OwnedBinaryXml>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    kind: Kind,
    namespace: &str,
    local: &str,
    operation: &Reader<'_>,
) -> RetainResult<Material<X>, X> {
    let execution = operation.execution();
    let access = Access::new(xml, location.snapshot, &execution);
    if !access
        .has_name(location.node, crate::xml::Name { namespace, local })
        .map_err(RetainError::Access)?
    {
        return Err(RetainError::Name {
            node: location.node,
            kind,
        });
    }
    let original: LocatedValue<OwnedDecoded, X> =
        binary::owned_source(xml, location, operation).map_err(RetainError::Access)?;
    Ok(Source { kind, original })
}
