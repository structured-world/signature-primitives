//! Qualifier interpretation over the XML owner's complete normalized URI.

use super::{Qualifier, Reading};
use crate::reference::{LexicalSource, VisitError};
use crate::scalar::{UriValue, UriXml};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::{MemoryError, Work};
use structured_asn1::value::OwnedOid;

/// Established syntax/qualifier interpretation, not permanent assignment,
/// authenticated coverage or trust. URI spelling stays in its original source.
#[derive(Debug)]
pub enum Meaning {
    /// Generic URI, or `OIDAsURI`'s explicitly non-URN URI. No universal OID-to-URI
    /// resolver is specified here; no encoded OID is invented from such a URI.
    Uri,
    /// RFC3061 OID with independent original-account storage after the XML
    /// visitor's temporary joined/collapsed string has been released.
    Oid(OwnedOid),
}

/// Original XML, base syntax, qualifier and OID failures retain separate causes.
#[derive(Debug)]
pub enum MeaningError<E, N> {
    /// Original source/generation/current-operation refusal.
    Access(AccessError<E, N>),
    /// No valid complete original anyURI was established.
    Value {
        /// Original Identifier element.
        node: N,
        /// Requested base-datatype outcome, never a fabricated malformed fault.
        fact: crate::scalar::Fact,
    },
    /// `OIDAsURN` did not use the RFC3061 namespace, or `OIDAsURI` used a URN.
    Qualifier {
        /// Original Identifier element.
        node: N,
    },
    /// Original arbitrary-width ASN.1 OID conversion or resource refusal.
    Oid {
        /// Original Identifier element containing the normalized URI.
        node: N,
        /// Offset is relative to the normalized dotted-decimal suffix, NOT an
        /// invented physical XML byte coordinate. Original node stays attached.
        cause: structured_asn1::Error,
    },
}

/// Complete interpretation in this XML owner's original identity/error domain.
pub type MeaningResult<X> = Result<Meaning, MeaningError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Complete original identifier and documentation check, before trust/policy.
#[derive(Debug)]
pub enum CheckError<E, N> {
    /// Original documentation grammar/source refusal.
    Structure(crate::properties::Error<E, N>),
    /// Identifier qualifier/OID/original URI interpretation refusal.
    Meaning(MeaningError<E, N>),
    /// A documentation reference's original base-datatype refusal.
    Scalar(crate::scalar::Error<E, N>),
}

impl<E, N> From<crate::properties::Error<E, N>> for CheckError<E, N> {
    fn from(cause: crate::properties::Error<E, N>) -> Self {
        Self::Structure(cause)
    }
}

/// Complete identifier result using original source and error types.
pub type CheckResult<X> = Result<Meaning, CheckError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Check qualifier meaning AND every original documentation URI using the same
/// documentation grammar as structural reading. Failure drops a partially
/// retained numeric OID; original XML and prior capacity owners remain intact.
pub fn check<X: UriXml + crate::scalar::ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    reading: &Reading<X::Id>,
) -> CheckResult<X> {
    let meaning = check_value(access, reading).map_err(CheckError::Meaning)?;
    super::documentation_with(access, reading.documentation, |node| {
        crate::scalar::check(
            access,
            node,
            LexicalSource::SimpleContent,
            crate::scalar::Datatype::AnyUri,
        )
        .map_err(CheckError::Scalar)
    })?;
    Ok(meaning)
}

/// Interpret an already structurally selected original Identifier without
/// reparsing XML or retaining a temporary normalized string. Documentation URI
/// validation is the enclosing reader's separate obligation.
///
/// EN319132-1 V1.3.1 5.1.2 selects RFC3061 for `OIDAsURN` and explicitly excludes
/// URNs from `OIDAsURI`. RFC3061 2 permits ONLY unpadded decimal arcs; 3 includes
/// uppercase URN:OID. The existing ASN.1 numericOID kernel enforces those arc
/// rules and ASN.1 roots, including widths beyond machine integers. No percent
/// decoding, URI canonicalization, network lookup or OID assignment is implied.
/// <https://www.rfc-editor.org/rfc/rfc3061.html#section-2>
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_value<X: UriXml, W: Work>(
    access: &Access<'_, X, W>,
    reading: &Reading<X::Id>,
) -> MeaningResult<X> {
    let node = reading.identifier;
    let result = access.query_fallible(node, |xml, snapshot, work| {
        xml.with_uri(
            snapshot,
            node,
            LexicalSource::SimpleContent,
            work,
            |value| {
                use crate::scalar::Fact;
                let text = match value {
                    UriValue::Valid(text) => text,
                    value => {
                        let fact = match value {
                            UriValue::Absent => Fact::Absent,
                            UriValue::ComplexContent => Fact::ComplexContent,
                            UriValue::Malformed => Fact::Malformed,
                            UriValue::Unsupported => Fact::Unsupported,
                            UriValue::Valid(_) => unreachable!("successful URI selected above"),
                        };
                        return Err(MeaningError::Value { node, fact });
                    }
                };
                match reading.qualifier {
                    None => Ok(Meaning::Uri),
                    Some(Qualifier::Uri) => {
                        if prefix(text, "urn:", work).map_err(|cause| resource(node, cause))? {
                            return Err(MeaningError::Qualifier { node });
                        }
                        Ok(Meaning::Uri)
                    }
                    Some(Qualifier::Urn) => {
                        if !prefix(text, "urn:oid:", work).map_err(|cause| resource(node, cause))? {
                            return Err(MeaningError::Qualifier { node });
                        }
                        OwnedOid::parse_in(&text[8..], work)
                            .map(Meaning::Oid)
                            .map_err(|cause| MeaningError::Oid { node, cause })
                    }
                }
            },
        )
    });
    match result {
        Ok(value) => Ok(value),
        Err(AccessError::Xml(VisitError::Visitor(cause))) => Err(cause),
        Err(AccessError::Xml(VisitError::Processing(cause))) => {
            Err(MeaningError::Access(AccessError::Xml(cause)))
        }
        Err(AccessError::Changed { node }) => {
            Err(MeaningError::Access(AccessError::Changed { node }))
        }
        Err(AccessError::Resource { node, cause }) => Err(resource(node, cause)),
    }
}

fn prefix<W: Work>(text: &str, expected: &str, work: &W) -> Result<bool, MemoryError> {
    if text.len() < expected.len() {
        return Ok(false);
    }
    work.charge_work(expected.len() as u64)?;
    Ok(text.as_bytes()[..expected.len()].eq_ignore_ascii_case(expected.as_bytes()))
}

fn resource<E, N>(node: N, cause: MemoryError) -> MeaningError<E, N> {
    MeaningError::Access(AccessError::Resource { node, cause })
}
