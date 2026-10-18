//! Exact original referenced-artifact digests, without authority inference.

use super::{ReferenceKind, ReferenceProperty};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, DigestProvider},
    digest, material,
    xml::Access,
};
use structured_asn1::memory::Work;
use structured_cms::stream::RangesError;

/// Original bytes available for reference comparison. Independently supplied
/// path certificates/CRLs do not need fabricated XML material nodes. OCSP must
/// retain its WHOLE envelope; a bare basic response is intentionally not a target.
///
/// ```compile_fail
/// use structured_xades::validation::ReferenceTarget;
/// fn wrong(basic: &structured_pkix::ocsp::BasicResponse<'_>) {
///     let _: ReferenceTarget<'_, '_, usize, u8, u8> = ReferenceTarget::Ocsp(basic);
/// }
/// ```
#[derive(Clone, Copy)]
pub enum ReferenceTarget<'view, 'document, N, D, G> {
    /// Original parsed certificate, including an independently retained anchor.
    Certificate(&'view structured_pkix::Certificate<'document>),
    /// Original complete or delta list, without serialization or a numeric ID.
    Crl(&'view structured_pkix::crl::CertificateList<'document>),
    /// Whole original successful OCSP envelope, never only its basic payload.
    Ocsp(&'view structured_pkix::ocsp::ResponseBytes<'document>),
    /// Original XML-incorporated whole certificate/CRL/OCSPResponse source.
    Encapsulated(&'view material::Source<N, D, G>),
}

/// Exact digest processing, independent of identifier/path/authority checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceDigest {
    /// The original kind and complete declared digest were compared.
    Compared(Agreement),
    /// The supplied material has another schema kind. No provider was invoked.
    DifferentKind,
    /// This OCSP reference has no digest; its identifier still requires checking.
    IdentifierOnly,
    /// `OtherRef` has external format semantics; no generic hash is invented.
    OtherFormat,
}

/// Caller/source misuse and actual execution failures are terminal.
#[derive(Debug)]
pub enum ReferenceDigestError<PE> {
    /// Root selected-key/certificate/path binding was not established; supplied
    /// candidate bytes cannot stand for an actual signature participant.
    UnboundPath,
    /// No original reference exists at this caller-selected ordinal.
    Index {
        /// Requested ordinal, not a document byte location.
        index: usize,
    },
    /// The material/view belongs to another selected signature or immutable
    /// XML source generation.
    Foreign,
    /// The shared digest driver preserves acquisition/provider/resource causes.
    Digest(digest::Error<RangesError, PE>),
}

/// Compare a retained original reference with a retained original artifact.
/// EN319132-1 A.1.1/A.1.2/A.1.3/A.1.4 use whole certificate/CRL DER and
/// whole `OCSPResponse`, NOT merely its `BasicOCSPResponse` payload.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Reuses the existing streaming/method/width/MD5 core without serialization,
/// copying, implicit acquisition or a second algorithm dispatcher. Source
/// retention alone does not certify valid DER; parse/authenticate the actual
/// material through the material/PKIX pipeline separately. Neither agreement
/// nor a URI proves incorporation, issuer identity, path use or a baseline.
pub fn compare_reference_digest<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    source: &material::Material<X>,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<ReferenceDigest, X, ReferenceDigestError<P::Error>> {
    compare_reference_target(
        xml,
        references,
        index,
        ReferenceTarget::Encapsulated(source),
        provider,
        execution,
    )
}

/// Compare an original reference against an actual external parsed certificate
/// or CRL, or a retained whole XML envelope, through the SAME digest kernel.
/// External acquisition/path trust stays with the caller; only the CURRENT
/// operation pays this comparison and original storage ownership is unchanged.
/// This does not imply that an external value is incorporated in the signature.
/// The Annex A full-DER/whole-response and separate identifier obligations are
/// identical to [`compare_reference_digest`]; no basic-only OCSP hash is allowed.
pub fn compare_reference_target<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    target: ReferenceTarget<'_, '_, X::Id, X::Document, X::Generation>,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<ReferenceDigest, X, ReferenceDigestError<P::Error>> {
    let location = Location {
        snapshot: references.snapshot(),
        node: references.node(),
    };
    let access = Access::new(xml, references.snapshot(), execution);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let (kind, bytes) = match target {
        ReferenceTarget::Certificate(value) => (material::Kind::Certificate, value.as_bytes()),
        ReferenceTarget::Crl(value) => (material::Kind::Crl, value.as_bytes()),
        ReferenceTarget::Ocsp(value) => (material::Kind::Ocsp, value.as_bytes()),
        ReferenceTarget::Encapsulated(source) => {
            if source.location().snapshot != references.snapshot() {
                return Err(binary::Error::Callback {
                    location,
                    cause: ReferenceDigestError::Foreign,
                });
            }
            (source.kind(), source.bytes())
        }
    };
    let Some(entry) = references.entries().get(index) else {
        return Err(binary::Error::Callback {
            location,
            cause: ReferenceDigestError::Index { index },
        });
    };
    let expected_kind = match entry.kind() {
        ReferenceKind::Certificate => material::Kind::Certificate,
        ReferenceKind::Crl => material::Kind::Crl,
        ReferenceKind::Ocsp => material::Kind::Ocsp,
        ReferenceKind::Other => return Ok(ReferenceDigest::OtherFormat),
    };
    if kind != expected_kind {
        return Ok(ReferenceDigest::DifferentKind);
    }
    let Some((method, value)) = entry.digest() else {
        return Ok(ReferenceDigest::IdentifierOnly);
    };
    digest::check(
        xml,
        digest::Reference {
            snapshot: references.snapshot(),
            method,
            value,
        },
        &mut [bytes],
        provider,
        execution,
    )
    .map(ReferenceDigest::Compared)
    .map_err(|cause| cause.map_callback(ReferenceDigestError::Digest))
}
