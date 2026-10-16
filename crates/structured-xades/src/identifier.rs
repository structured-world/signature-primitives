//! The one original-source `ObjectIdentifierType` structural kernel.
//!
//! This reading does not establish URI/OID lexical validity, permanence or trust.
//! Callers retain the original nodes for the XML owner's exact scalar validation.

use crate::container::XADES;
use crate::properties::{self, Error, PropertyResult};
use crate::xml::{Access, Name, Xml};
use structured_asn1::memory::Work;

mod meaning;
pub use meaning::{
    CheckError, CheckResult, Meaning, MeaningError, MeaningResult, check, check_value,
};

/// Read one original auxiliary identifier and check every anyURI field with
/// the XML owner's scalar kernel. Structure shares [`read`]; there is no second
/// grammar or collected/normalized URI string. EN319132-1 §5.1.2 and Annex C
/// assign anyURI to Identifier and every `DocumentationReference`.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// This checks base-datatype syntax only. A written OID qualifier still needs
/// its RFC3061/URI interpretation; permanent assignment and signed binding are
/// not inferred from lexical validity. Optional absent documentation creates
/// no invented field. All source, unsupported and resource causes survive.
pub fn read_uri_syntax<X: crate::scalar::ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> UriResult<X> {
    use crate::reference::LexicalSource;
    use crate::scalar::{Datatype, check};
    read_with(access, parent, |node| {
        check(access, node, LexicalSource::SimpleContent, Datatype::AnyUri)
            .map_err(UriError::Scalar)
    })
}

/// Original structure versus requested base-datatype refusal.
#[derive(Debug)]
pub enum UriError<E, N> {
    /// The original identifier's structural/source/resource cause.
    Structure(Error<E, N>),
    /// Exact lexical or current-operation refusal at one original URI field.
    Scalar(crate::scalar::Error<E, N>),
}

impl<E, N> From<Error<E, N>> for UriError<E, N> {
    fn from(cause: Error<E, N>) -> Self {
        Self::Structure(cause)
    }
}

/// URI-syntax reading in this owner's original identity/error domain.
pub type UriResult<X> =
    Result<Reading<<X as Xml>::Id>, UriError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Explicit OID spelling selected by the schema's Qualifier enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// OID carried in a URI which is not a URN.
    Uri,
    /// OID carried in an RFC 3061 URN.
    Urn,
}

/// Original auxiliary structure, not an authenticated-property constructor.
#[derive(Debug)]
pub struct Reading<N> {
    /// Original Identifier simple-content element.
    pub identifier: N,
    /// Written qualifier; absence means a URI identifier, not an implied OID.
    pub qualifier: Option<Qualifier>,
    /// Original optional textual description.
    pub description: Option<N>,
    /// Original optional nonempty `DocumentationReferences` container.
    pub documentation: Option<N>,
}

/// Reads EN319132-1 V1.3.1 §5.1.2's auxiliary type without collecting text.
/// A caller supplies the actual ObjectIdentifier/SigPolicyId/CommitmentTypeId
/// element already selected by its enclosing schema. This function cannot
/// promote an arbitrary node to signed or trusted evidence.
///
/// The official schema enumerates `OIDAsURN`; the prose's `OIDASURN` spelling
/// does not add a third schema value. URI/OID content validation is separate.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<Reading<X::Id>, X> {
    read_with(access, parent, |node| {
        properties::simple_content(access, node)
    })
}

// Both inspection and lexical qualification share the field grammar. The
// lexical owner checks URI simple content itself: no second documentation
// traversal, redundant text scan or collected normalized string is required.
fn read_with<X: Xml, W: Work, E: From<Error<X::Error, X::Id>>>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    mut uri: impl FnMut(X::Id) -> Result<(), E>,
) -> Result<Reading<X::Id>, E> {
    let mut fields = [None; 3];
    let mut previous = 0;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        let mut selected = None;
        for (rank, local) in ["Identifier", "Description", "DocumentationReferences"]
            .iter()
            .enumerate()
        {
            if access
                .has_name(
                    node,
                    Name {
                        namespace: XADES,
                        local,
                    },
                )
                .map_err(Error::Access)?
            {
                selected = Some(rank);
                break;
            }
        }
        let rank = selected.ok_or(Error::Unexpected { node })?;
        if fields[rank].is_some() {
            return Err(Error::Duplicate { node }.into());
        }
        if rank < previous {
            return Err(Error::Order { node }.into());
        }
        fields[rank] = Some(node);
        previous = rank;
        if rank == 0 {
            uri(node)?;
        } else if rank == 1 {
            properties::simple_content(access, node)?;
        }
    }
    let identifier = fields[0].ok_or(Error::Missing {
        parent,
        local: "Identifier",
    })?;
    let qualifier = access
        .attribute(
            identifier,
            Name {
                namespace: "",
                local: "Qualifier",
            },
            |value| {
                let Some(value) = value else { return Ok(None) };
                let refusal = |cause| Error::Resource {
                    node: identifier,
                    cause,
                };
                if access.equal(value, "OIDAsURI").map_err(refusal)? {
                    return Ok(Some(Qualifier::Uri));
                }
                if access.equal(value, "OIDAsURN").map_err(refusal)? {
                    return Ok(Some(Qualifier::Urn));
                }
                Err(Error::Unexpected { node: identifier })
            },
        )
        .map_err(Error::Access)??;
    documentation_with(access, fields[2], &mut uri)?;
    Ok(Reading {
        identifier,
        qualifier,
        description: fields[1],
        documentation: fields[2],
    })
}

// Every structural, base-syntax and complete identifier route uses this exact
// documentation grammar; temporary conversion output drops if a late URI fails.
fn documentation_with<X: Xml, W: Work, E: From<Error<X::Error, X::Id>>>(
    access: &Access<'_, X, W>,
    parent: Option<X::Id>,
    mut uri: impl FnMut(X::Id) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(parent) = parent {
        let mut present = false;
        for child in access.children(parent) {
            let node = child.map_err(Error::Child)?;
            if !access
                .has_name(
                    node,
                    Name {
                        namespace: XADES,
                        local: "DocumentationReference",
                    },
                )
                .map_err(Error::Access)?
            {
                return Err(Error::Unexpected { node }.into());
            }
            uri(node)?;
            present = true;
        }
        if !present {
            return Err(Error::Missing {
                parent,
                local: "DocumentationReference",
            }
            .into());
        }
    }
    Ok(())
}
