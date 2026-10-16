//! Original RFC4514 issuer/responder names against actual retained PKIX names.

use super::{ReferenceIdentifier, ReferenceProperty, ResponderIdentifier};
use crate::{
    reference::{LexicalSource, VisitError},
    scalar::{TextValue, TextXml},
    xml::{Access, AccessError},
};
use structured_asn1::ScopedReader;
use structured_pkix::name::{Name, Selector};

/// A failed name interpretation is never a completed negative comparison.
#[derive(Debug)]
pub enum ReferenceNameError<E, N> {
    /// Current original-source/access admission failed.
    Access(AccessError<E, N>),
    /// Original XML text could not be acquired, preserving resource cause.
    Xml(E),
    /// Caller selected no reference at this catalogue ordinal.
    Index {
        /// Requested ordinal, not an XML byte location.
        index: usize,
    },
    /// The original required name has no readable simple content.
    Content {
        /// Original issuer or `ByName` element.
        node: N,
    },
    /// Shared RFC4514/Name syntax, semantic preparation or resource failure.
    Name {
        /// Original XML name enclosure. Inner offsets refer to DN text, NOT
        /// physical XML bytes; no copied-buffer offset is fabricated.
        node: N,
        /// Exact original shared cause.
        cause: structured_pkix::Error,
    },
}

/// Compare an original CRL issuer or OCSP `ByName` hint with an actual PKIX Name.
/// Annex A.1.2 refers to `XMLDSig` §4.5.4.1 DN strings; RFC4514 parsing and
/// RFC5280 name preparation remain with the existing PKIX owner.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// None denotes a different identifier branch, never successful agreement.
/// Query decoding, normalization and comparison use the current reader even
/// for independently retained material. Source storage remains on its account.
/// This does not establish digest agreement, authority, freshness or path use.
pub fn matches_reference_name<X: TextXml>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    actual: &Name<'_>,
    operation: &ScopedReader<'_, '_>,
) -> Result<Option<bool>, ReferenceNameError<X::Error, X::Id>> {
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(ReferenceNameError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(ReferenceNameError::Index { index });
    };
    let node = match entry.identifier() {
        ReferenceIdentifier::Crl { issuer, .. } => issuer,
        ReferenceIdentifier::Ocsp {
            responder: ResponderIdentifier::Name(node),
            ..
        } => node,
        _ => return Ok(None),
    };
    let compared = access
        .query(node, |xml, snapshot, work| {
            Ok(xml.with_text(
                snapshot,
                node,
                LexicalSource::SimpleContent,
                work,
                |value| {
                    let TextValue::Present(text) = value else {
                        return Err(ReferenceNameError::Content { node });
                    };
                    let selector = Selector::parse_in(text, operation)
                        .map_err(|cause| ReferenceNameError::Name { node, cause })?;
                    selector
                        .matches_name_in(actual, operation)
                        .map(Some)
                        .map_err(|cause| ReferenceNameError::Name { node, cause })
                },
            ))
        })
        .map_err(ReferenceNameError::Access)?;
    compared.map_err(|cause| match cause {
        VisitError::Processing(cause) => ReferenceNameError::Xml(cause),
        VisitError::Visitor(cause) => cause,
    })
}
