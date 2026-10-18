//! Carried CMS revocation material, separate from XML material-pool ordinals.

use super::TokenView;
use crate::binary::Location;
use structured_asn1::{
    Element, Oid, Reader, Tag,
    memory::{MemoryError, OwnedVec, Work},
    universal,
};
use structured_cms::signed::OtherRevocationInfo;
use structured_ltv::material::CarriedOrigin;
use structured_pkix::{
    crl::CertificateList,
    ocsp::{BasicResponse, ResponseBytes},
};

/// One original carried artifact; availability is not authorization or status.
pub struct Carried<T> {
    /// Exact original token and choice, not a fingerprint or XML material index.
    pub origin: CarriedOrigin,
    /// Shared parsed original artifact, without normalization or copying.
    pub value: T,
}

/// Unsupported CMS revocation format, retained without claiming usable status.
pub struct OtherCarried<'source> {
    /// Original format identifier.
    pub kind: Oid<'source>,
    /// Whole original ANY element and its decoded-source location.
    pub value: Element<'source>,
}

/// Parsed known carried material, borrowing the frozen original token sources.
/// Embedded certificates remain available through each shared `BasicResponse`;
/// token certificates remain in the already parsed `SignedData` catalogue.
pub struct CarriedMaterial<'source, N, D, G> {
    pub(crate) view: TokenView<'source, N, D, G>,
    crls: OwnedVec<Carried<CertificateList<'source>>>,
    responses: OwnedVec<Carried<ResponseBytes<'source>>>,
    basic: OwnedVec<Carried<BasicResponse<'source>>>,
    other: OwnedVec<Carried<OtherCarried<'source>>>,
}

impl<'source, N, D, G> CarriedMaterial<'source, N, D, G> {
    /// Original complete and delta CRLs; pairing/authentication remain separate.
    #[must_use]
    pub fn crls(&self) -> &[Carried<CertificateList<'source>>] {
        &self.crls
    }
    /// Successful whole OCSP envelopes, including unsupported inner syntaxes.
    #[must_use]
    pub fn responses(&self) -> &[Carried<ResponseBytes<'source>>] {
        &self.responses
    }
    /// Known basic responses parsed once with their original embedded certificates.
    #[must_use]
    pub fn basic_responses(&self) -> &[Carried<BasicResponse<'source>>] {
        &self.basic
    }
    /// Original unsupported CMS formats, never counted as authenticated evidence.
    #[must_use]
    pub fn other(&self) -> &[Carried<OtherCarried<'source>>] {
        &self.other
    }
}

/// Original typed refusal; XML enclosure is physical identity, while inner
/// offsets refer to that token's retained decoded source, not physical XML.
#[derive(Debug)]
pub enum CarriedCause {
    /// Current operation's metadata traversal was refused.
    Encoding(structured_asn1::Error),
    /// Common CMS structural/format processing refused.
    Cms(structured_cms::Error),
    /// Shared CRL/basic-response syntax processing refused.
    Pkix(structured_pkix::Error),
    /// New catalogue metadata/capacity was refused before allocation.
    Resource(MemoryError),
}

/// Failure identifies the exact source pool and original XML enclosure even
/// after the scoped source buffers have been dropped.
#[derive(Debug)]
pub struct CarriedError<N, D, G> {
    /// Original encoded token XML enclosure and source generation.
    pub location: Location<N, D, G>,
    /// Actual token/choice; the choice may be the next not-yet-admitted item.
    pub origin: CarriedOrigin,
    /// Original cause, not converted to absent material or an untrusted status.
    pub cause: CarriedCause,
}

impl<'source, N: Copy, D: Copy, G: Copy> TokenView<'source, N, D, G> {
    /// Decodes all known revocation choices before returning any catalogue.
    /// A partial result is dropped on failure; original source buffers remain
    /// intact. Current operation and original source ceilings both govern every
    /// shared decoder. No acquisition, crypto, actor selection or B-level claim.
    pub fn material_in<'query>(
        &self,
        operation: &Reader<'query>,
    ) -> Result<CarriedMaterial<'query, N, D, G>, CarriedError<N, D, G>>
    where
        'source: 'query,
    {
        let execution = operation.execution();
        let mut crls = execution.vector();
        let mut responses = execution.vector();
        let mut basic = execution.vector();
        let mut other = execution.vector();
        if let Some(first) = self.sources().first() {
            operation
                .charge(self.sources().len() as u64)
                .map_err(|cause| CarriedError {
                    location: first.location(),
                    origin: CarriedOrigin {
                        token: 0,
                        choice: 0,
                    },
                    cause: CarriedCause::Encoding(cause),
                })?;
        }
        for token in 0..self.sources().len() {
            let source = &self.sources()[token];
            let mut choice = 0;
            loop {
                let origin = CarriedOrigin { token, choice };
                let error = |cause| CarriedError {
                    location: source.location(),
                    origin,
                    cause,
                };
                let message = self.readings()[token].token().message();
                let Some(reader) = message
                    .revocation_reader_in(operation, choice)
                    .map_err(|cause| error(CarriedCause::Cms(cause)))?
                else {
                    break;
                };
                let entry = message.revocations()[choice];
                if entry.tag() == Tag::constructed(universal::SEQUENCE) {
                    crls.try_reserve(1)
                        .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                    let value = CertificateList::read_element(&reader, &entry)
                        .map_err(|cause| error(CarriedCause::Pkix(cause)))?;
                    crls.try_push(Carried { origin, value })
                        .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                } else {
                    let format = OtherRevocationInfo::read(&reader, &entry)
                        .map_err(|cause| error(CarriedCause::Cms(cause)))?;
                    let value = OtherCarried {
                        kind: format.kind(),
                        value: format.value(),
                    };
                    if let Some(response) = format
                        .ocsp()
                        .map_err(|cause| error(CarriedCause::Cms(cause)))?
                    {
                        responses
                            .try_reserve(1)
                            .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                        if let Some(value) = response
                            .basic_in(operation)
                            .map_err(|cause| error(CarriedCause::Pkix(cause)))?
                        {
                            basic
                                .try_push(Carried { origin, value })
                                .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                        }
                        responses
                            .try_push(Carried {
                                origin,
                                value: response,
                            })
                            .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                    } else {
                        other
                            .try_push(Carried { origin, value })
                            .map_err(|cause| error(CarriedCause::Resource(cause)))?;
                    }
                }
                choice += 1;
            }
        }
        Ok(CarriedMaterial {
            view: self.reborrow(),
            crls: crls.into_owned(),
            responses: responses.into_owned(),
            basic: basic.into_owned(),
            other: other.into_owned(),
        })
    }
}
