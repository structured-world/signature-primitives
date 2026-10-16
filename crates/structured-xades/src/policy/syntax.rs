//! Scalar obligations of recognized original policy qualifiers.

use super::{Declaration, Original, XADES, XADES_141, named, user_notice_with};
use crate::identifier;
use crate::properties::Error;
use crate::reference::LexicalSource;
use crate::scalar::{self, Datatype, ScalarXml, UriXml};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::Work;

/// A syntax/source/resource refusal, without application-policy interpretation.
#[derive(Debug)]
pub enum SyntaxError<E, N> {
    /// Original qualifier grammar or source refusal.
    Structure(Error<E, N>),
    /// Requested original base-datatype refusal; Unsupported is not Malformed.
    Scalar(scalar::Error<E, N>),
    /// A technical-specification identifier's original URI syntax refusal.
    Identifier(identifier::CheckError<E, N>),
}

impl<E, N> From<Error<E, N>> for SyntaxError<E, N> {
    fn from(cause: Error<E, N>) -> Self {
        Self::Structure(cause)
    }
}

/// Qualifier syntax result in the original XML owner's identity/error domain.
pub type SyntaxResult<X> = Result<(), SyntaxError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Check recognized SPURI, `SPUserNotice` and `SPDocSpecification` payloads in the
/// original selected policy. Unknown `AnyType` payloads remain delegated; this
/// does not grant them semantics or assert a complete baseline level.
///
/// EN319132-1 V1.3.1 Annex C declares SPURI as anyURI and EVERY NoticeNumbers/int
/// as xsd:integer (not machine-sized, positive-only or xsd:int). Both structural
/// and syntax routes use the SAME notice grammar. No normalization, parsing or
/// narrowing of XML numbers is duplicated here, including negative/wide values.
/// <https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd>
pub fn check_qualifier_syntax<X: ScalarXml + UriXml, W: Work>(
    access: &Access<'_, X, W>,
    reading: &Original<X>,
) -> SyntaxResult<X> {
    if reading.snapshot() != access.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: reading.node(),
        })
        .into());
    }
    access
        .query(reading.node(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    let Declaration::Explicit(explicit) = reading.declaration() else {
        return Ok(());
    };
    let mut index = 0;
    while index < explicit.qualifiers.len() {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| Error::Resource {
                node: reading.node(),
                cause,
            })?;
        let qualifier = &explicit.qualifiers[index];
        let mut child = access.first_child(qualifier.node).map_err(Error::Access)?;
        while let Some(node) = child {
            if named(access, node, XADES, "SPURI")? {
                scalar::check(access, node, LexicalSource::SimpleContent, Datatype::AnyUri)
                    .map_err(SyntaxError::Scalar)?;
            } else if named(access, node, XADES, "SPUserNotice")? {
                user_notice_with(access, node, |number| {
                    scalar::check(
                        access,
                        number,
                        LexicalSource::SimpleContent,
                        Datatype::Integer,
                    )
                    .map_err(SyntaxError::Scalar)
                })?;
            } else if named(access, node, XADES_141, "SPDocSpecification")? {
                let reading = identifier::read(access, node).map_err(SyntaxError::Structure)?;
                identifier::check(access, &reading).map_err(SyntaxError::Identifier)?;
            }
            child = access
                .next_sibling(qualifier.node, node)
                .map_err(Error::Access)?;
        }
        index += 1;
    }
    access
        .query(reading.node(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    Ok(())
}
