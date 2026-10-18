//! Original DER OCSP byKey hint over the shared responder field kernel.

use super::{ReferenceIdentifier, ReferenceProperty, ResponderIdentifier};
use crate::{
    binary::{self, BinaryXml, Location},
    xml::Access,
};
use structured_asn1::{Reader, Tag};
use structured_pkix::{
    Certificate,
    algorithm::digest::AsnDigest,
    ocsp::{ResponderId, ResponderMatch},
};

/// Source/schema and visitor causes remain distinct from key disagreement.
#[derive(Debug)]
pub enum ResponderKeyError<E> {
    /// Caller selected no original reference at this ordinal.
    Index {
        /// Original caller-selected catalogue ordinal.
        index: usize,
    },
    /// Original DER reader failure, preserving decoded-source coordinates.
    Encoding(structured_asn1::Error),
    /// Original shared RFC6960 field failure, including resource causes.
    Responder(structured_pkix::Error),
    /// Unconsumed bytes after the one byKey field.
    Trailing {
        /// First unconsumed decoded-source offset.
        offset: u64,
    },
    /// Exact callback failure, without converting resource causes to mismatch.
    Callback(E),
}

/// Original XML enclosure and shared/provider failure for a responder-key query.
pub type ReferenceKeyResult<X, E> = binary::BinaryResult<
    Option<binary::LocatedValue<ResponderMatch, X>>,
    X,
    ResponderKeyError<structured_pkix::error::CallbackError<E>>,
>;

/// Visit the complete original OCSP byKey hash. Annex A.1.2 requires base64
/// of the DER-encoded RFC6960 byKey FIELD, not a naked twenty-byte digest.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// The existing binary source bridge enforces DER and both budgets. The shared
/// OCSP kernel owns tag/cardinality/hash width; no ASN.1 grammar is duplicated.
/// None means this reference uses another identifier branch, not a matching
/// responder. Even that absence checks the current original source first.
pub fn with_responder_key<X: BinaryXml, R, E>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(&'source [u8]) -> Result<R, E>,
) -> binary::BinaryResult<Option<binary::LocatedValue<R, X>>, X, ResponderKeyError<E>> {
    with_key_at(xml, references, index, operation, |hash, _, _| {
        visitor(hash)
    })
}

/// Compare the original DER byKey selector with an actual responder certificate.
/// Reuses the same shared RFC6960 identity kernel as OCSP authentication;
/// original source/depth and current query ceilings govern the hash callback.
/// The certificate's signature/path/authorization and response producedAt
/// remain independent. None identifies a different original selector branch.
pub fn matches_reference_key<'k, X: BinaryXml, D, DE>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    certificate: &Certificate<'_>,
    digest: &'k D,
    operation: &Reader<'_>,
) -> ReferenceKeyResult<X, DE>
where
    D: AsnDigest<'k, Error = DE>,
{
    with_key_at(xml, references, index, operation, |hash, reader, at| {
        ResponderId::KeyHash(hash).matches_certificate(
            certificate,
            digest,
            &reader.execution(),
            "xades.ocspIdentifier.byKey",
            at,
        )
    })
}

fn with_key_at<X: BinaryXml, R, E>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(&'source [u8], &Reader<'source>, u64) -> Result<R, E>,
) -> binary::BinaryResult<Option<binary::LocatedValue<R, X>>, X, ResponderKeyError<E>> {
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
            cause: ResponderKeyError::Index { index },
        });
    };
    let ReferenceIdentifier::Ocsp {
        responder: ResponderIdentifier::Key(node),
        ..
    } = entry.identifier()
    else {
        return Ok(None);
    };
    let location = Location {
        snapshot: references.snapshot(),
        node,
    };
    binary::with_der_reader(xml, location, operation, |reader| {
        let element = reader
            .expect(Tag::context(true, 2))
            .map_err(ResponderKeyError::Encoding)?;
        let responder =
            ResponderId::read_element(reader, &element).map_err(ResponderKeyError::Responder)?;
        if !reader.is_empty() {
            return Err(ResponderKeyError::Trailing {
                offset: reader.offset(),
            });
        }
        let ResponderId::KeyHash(hash) = responder else {
            unreachable!("checked byKey tag produced a name");
        };
        visitor(hash, reader, element.span().start)
            .map(|value| Some(binary::Located { location, value }))
            .map_err(ResponderKeyError::Callback)
    })
}
