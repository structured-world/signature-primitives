//! URI/OID scalar execution over the original prepared property models.

use super::Prepared;
use crate::reference::LexicalSource;
use crate::scalar::{Datatype, ScalarXml, UriXml};
use crate::xml::{Access, AccessError, Xml};
use crate::{commitment, format, identifier, policy, scalar};
use structured_asn1::memory::{MemoryError, Work};

/// Original URI/OID stage failure, with original source and typed cause.
#[derive(Debug)]
pub enum UriError<E, N> {
    /// Foreign source/generation or current-operation dispatch refusal.
    Access(AccessError<E, N>),
    /// Original identifier schema failed before scalar interpretation.
    Structure(crate::properties::Error<E, N>),
    /// Original URI/OID meaning or documentation refusal.
    Identifier(identifier::CheckError<E, N>),
    /// Original requested anyURI value refused or remained unsupported.
    Scalar(scalar::Error<E, N>),
    /// A recognized original policy qualifier's URI/integer refusal.
    Policy(policy::SyntaxError<E, N>),
}

/// Original prepared URI checks in the XML owner's error/identity domain.
pub type UriResult<X> = Result<(), UriError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Check all prepared object-format, commitment, policy and policy-store URI
/// values, including identifier qualifiers/documentation and recognized policy
/// qualifier integers. This reuses original selected models and the same scalar/
/// identifier kernels; it does not repeat reference resolution/provider work.
///
/// Declared attributes, dates, binary payloads, open-format semantics, type
/// derivation and complete baseline evidence are separate obligations. In
/// particular this result cannot promote an unprocessed XMLDSig/counter/path/
/// timestamp/status receipt into a successful B level. No implicit I/O occurs.
pub fn check_uris<X: ScalarXml + UriXml, W: Work>(
    prepared: &Prepared<X>,
    access: &Access<'_, X, W>,
) -> UriResult<X> {
    let layout = prepared.bound().containers();
    let root = layout.signature();
    if layout.snapshot() != access.snapshot() {
        return Err(UriError::Access(AccessError::Changed { node: root }));
    }
    access
        .query(root, |_, _, _| Ok(()))
        .map_err(UriError::Access)?;
    let mut at = 0;
    while at < prepared.formats().len() {
        admit(access, root)?;
        let original = prepared.formats()[at].original();
        format::check_encoding(access, original).map_err(UriError::Scalar)?;
        scalar::check(
            access,
            original.node(),
            LexicalSource::Attribute(crate::xml::Name {
                namespace: "",
                local: "ObjectReference",
            }),
            Datatype::AnyUri,
        )
        .map_err(UriError::Scalar)?;
        if let Some(node) = original.identifier() {
            let identifier = identifier::read(access, node).map_err(UriError::Structure)?;
            identifier::check(access, &identifier).map_err(UriError::Identifier)?;
        }
        at += 1;
    }
    let mut at = 0;
    while at < prepared.commitments().len() {
        admit(access, root)?;
        let original = prepared.commitments()[at].original();
        identifier::check(access, original.kind()).map_err(UriError::Identifier)?;
        if let commitment::Objects::References(nodes) = original.objects() {
            let mut index = 0;
            while index < nodes.len() {
                admit(access, original.node())?;
                scalar::check(
                    access,
                    nodes[index],
                    LexicalSource::SimpleContent,
                    Datatype::AnyUri,
                )
                .map_err(UriError::Scalar)?;
                index += 1;
            }
        }
        at += 1;
    }
    if let Some(original) = prepared.policy() {
        admit(access, root)?;
        if let policy::Declaration::Explicit(explicit) = original.declaration() {
            identifier::check(access, &explicit.identifier).map_err(UriError::Identifier)?;
        }
        policy::check_qualifier_syntax(access, original).map_err(UriError::Policy)?;
    }
    if let Some(original) = prepared.policy_store() {
        admit(access, root)?;
        identifier::check(access, original.specification()).map_err(UriError::Identifier)?;
        if let policy::StoredDocument::Local(node) = original.document() {
            scalar::check(access, node, LexicalSource::SimpleContent, Datatype::AnyUri)
                .map_err(UriError::Scalar)?;
        }
    }
    access
        .query(root, |_, _, _| Ok(()))
        .map_err(UriError::Access)
}

fn admit<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> UriResult<X> {
    access
        .execution()
        .charge_work(1)
        .map_err(|cause: MemoryError| UriError::Access(AccessError::Resource { node, cause }))
}
