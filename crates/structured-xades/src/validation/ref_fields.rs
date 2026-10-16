//! XML-owned scalar execution over the already selected reference field model.

use super::{ReferenceField, ReferenceProperty};
use crate::{
    binary::{BinaryXml, Location},
    certificate::{self, Agreement},
    properties::{DateTimeFact, DateTimeXml},
    reference::LexicalSource,
    scalar::{self, Datatype, ScalarXml},
    xml::{Access, AccessError, Name, Xml},
};
use core::convert::Infallible;
use structured_asn1::memory::{MemoryError, Work};

/// Original field processing or completed unproven syntax, never artifact
/// mismatch, missing material or provider authentication.
#[derive(Debug)]
pub enum ReferenceFieldError<E, N, D, G> {
    /// Reference metadata belongs to another original generation.
    Foreign {
        /// Original property.
        node: N,
    },
    /// Current operation, source or method inspection refused.
    Access(AccessError<E, N>),
    /// Original requested URI/integer lexical outcome.
    Scalar(scalar::Error<E, N>),
    /// The complete XML-owned dateTime reading was malformed or unsupported.
    Time {
        /// Original `IssueTime` or `ProducedAt`.
        node: N,
        /// Actual schema interpretation; no timezone default.
        fact: DateTimeFact,
    },
    /// Original base64 decoding failure in its real XML enclosure.
    Binary {
        /// Original binary node/generation.
        location: Location<N, D, G>,
        /// Original source/resource failure.
        cause: AccessError<E, N>,
    },
    /// Known prohibited or malformed method before provider dispatch.
    Method {
        /// Original `DigestMethod`.
        node: N,
        /// Completed original syntax/format finding.
        cause: Agreement,
    },
    /// Metadata admission refused before accessing the next retained entry.
    Resource {
        /// Original property.
        node: N,
        /// Exact resource cause.
        cause: MemoryError,
    },
}

/// Scalar interpretation result in the original XML owner's identity domain.
pub type ReferenceFieldResult<X> = Result<
    (),
    ReferenceFieldError<
        <X as Xml>::Error,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
>;

/// Execute each retained reference field through its XML owner's EXISTING
/// datatype/base64 kernel, without another child parse, normalization or ASN.1
/// fabrication. Hint dateTimes may genuinely omit a timezone; unlike `SigningTime`
/// they are not converted to a claimed UTC instant. Open `OtherRef` payloads retain
/// their explicit opaque kind for a format handler, not an invented validity flag.
pub fn check_reference_fields<X: ScalarXml + DateTimeXml + BinaryXml, W: Work>(
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> ReferenceFieldResult<X> {
    let node = references.node();
    if references.snapshot() != access.snapshot() {
        return Err(ReferenceFieldError::Foreign { node });
    }
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(ReferenceFieldError::Access)?;
    let mut ordinal = 0;
    while ordinal < references.entries().len() {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| ReferenceFieldError::Resource { node, cause })?;
        let entry = &references.entries()[ordinal];
        if let Some((method, _)) = entry.digest()
            && let Some(cause) = certificate::preflight_method(access, method)
                .map_err(ReferenceFieldError::Access)?
        {
            return Err(ReferenceFieldError::Method {
                node: method,
                cause,
            });
        }
        let fields = entry.fields();
        for field in fields {
            access
                .execution()
                .charge_work(1)
                .map_err(|cause| ReferenceFieldError::Resource { node, cause })?;
            if let Some(field) = field {
                check_field(access, field)?;
            }
        }
        ordinal += 1;
    }
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(ReferenceFieldError::Access)
}

fn check_field<X: ScalarXml + DateTimeXml + BinaryXml, W: Work>(
    access: &Access<'_, X, W>,
    field: ReferenceField<X::Id>,
) -> ReferenceFieldResult<X> {
    match field {
        ReferenceField::Uri(node) => {
            let uri = Name {
                namespace: "",
                local: "URI",
            };
            if access
                .attribute(node, uri, |value| value.is_some())
                .map_err(ReferenceFieldError::Access)?
            {
                scalar::check(
                    access,
                    node,
                    LexicalSource::Attribute(uri),
                    Datatype::AnyUri,
                )
                .map_err(ReferenceFieldError::Scalar)?;
            }
        }
        ReferenceField::Integer(node) => {
            scalar::check(
                access,
                node,
                LexicalSource::SimpleContent,
                Datatype::Integer,
            )
            .map_err(ReferenceFieldError::Scalar)?;
        }
        ReferenceField::DateTime(node) => {
            let fact = access
                .query(node, |xml, snapshot, work| {
                    xml.date_time(snapshot, node, work)
                })
                .map_err(ReferenceFieldError::Access)?;
            // Annex A's identifier fields are xsd:dateTime, whose timezone is
            // optional (XSD1.0 Datatypes §3.2.7). The distinct §6.3(h)
            // SigningTime UTC requirement must not leak into these hints.
            // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime
            match fact {
                DateTimeFact::Valid { .. } => (),
                fact => return Err(ReferenceFieldError::Time { node, fact }),
            }
        }
        ReferenceField::Binary(node) => {
            let location = Location {
                snapshot: access.snapshot(),
                node,
            };
            let checked = access
                .query(node, |xml, snapshot, work| {
                    xml.with_octets(snapshot, node, work, |_| Ok::<_, Infallible>(()))
                })
                .map_err(|cause| ReferenceFieldError::Binary { location, cause })?;
            checked.unwrap_or_else(|never| match never {});
        }
    }
    Ok(())
}
