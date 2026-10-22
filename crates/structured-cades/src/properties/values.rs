//! Original Annex A validation values, retained at their first schema reading.

use crate::source::Node;
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_pkix::{Certificate, crl::CertificateList, ocsp::BasicResponse};

/// OID-owned original revocation values. Syntax inspection does not recognize,
/// authenticate or silently discard a format which needs its own handler.
#[derive(Debug, Clone, Copy)]
pub struct OtherRevocation<'document> {
    /// Original containing revocation-values attribute.
    pub property: Node,
    /// Original open-format identifier.
    pub kind: structured_asn1::Oid<'document>,
    /// Original context wrapper, including the format OID and open values.
    pub enclosure: structured_asn1::Element<'document>,
    /// Whole original open values and producing parser/depth/encoding.
    pub values: crate::source::Value<'document>,
}

/// One original member of an actual certificate/revocation-values attribute.
pub struct Located<T> {
    /// Original containing attribute, independent of the member's coordinates.
    pub property: Node,
    /// Whole actual certificate/revocation-values SEQUENCE. Its original bytes
    /// are covered even when an early archive omits the outer Attribute header.
    pub enclosure: Node,
    /// Original ordinal within this attribute's applicable SEQUENCE OF.
    pub ordinal: usize,
    /// Parsed original model, with no re-encoding or payload copy.
    pub value: T,
}

/// Format-defined legacy validation values. OCSP entries are ORIGINAL bare
/// `BasicOCSPResponse` values (Annex A.1.4), never manufactured OCSP envelopes.
/// Reading establishes neither authentication nor historical availability.
pub struct Values<'document, W: Work = Memory> {
    pub(crate) certificates: OwnedVec<Located<Certificate<'document>>, W>,
    pub(crate) crls: OwnedVec<Located<CertificateList<'document>>, W>,
    pub(crate) ocsp: OwnedVec<Located<BasicResponse<'document>>, W>,
    pub(crate) other: OwnedVec<OtherRevocation<'document>, W>,
}
impl<'d, W: Work> Values<'d, W> {
    pub(crate) fn new(work: &W) -> Self {
        Self {
            certificates: work.vector(),
            crls: work.vector(),
            ocsp: work.vector(),
            other: work.vector(),
        }
    }
    pub(crate) fn into_owned(self) -> Values<'d> {
        Values {
            certificates: self.certificates.into_owned(),
            crls: self.crls.into_owned(),
            ocsp: self.ocsp.into_owned(),
            other: self.other.into_owned(),
        }
    }
    /// Borrowed original certificate members; traversals must use current work.
    pub fn certificates(&self) -> &[Located<Certificate<'d>>] {
        &self.certificates
    }
    /// Borrowed original complete/delta CRLs; no status authentication implied.
    pub fn crls(&self) -> &[Located<CertificateList<'d>>] {
        &self.crls
    }
    /// Borrowed original bare OCSP basic bodies; no success envelope is invented.
    pub fn ocsp_responses(&self) -> &[Located<BasicResponse<'d>>] {
        &self.ocsp
    }
    /// Original OID-owned values, without an invented status/format fallback.
    pub fn other_revocation(&self) -> &[OtherRevocation<'d>] {
        &self.other
    }
}
