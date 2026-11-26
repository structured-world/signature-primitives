//! Directly incorporated historical and extended timestamp inputs.

use super::{
    Access, Bound, DS, Input, InputError, InputResult, Name, OwnedVec, Part, ReferencePrefix, Role,
    Timestamp, TimestampXml, Work, XADES, XADES_141, Xml, append_archive, named, read_fields_in,
    unsigned_parent_in,
};

/// Validation-reference property vocabulary selected by the timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSyntax {
    /// The original TS 101 903 certificate-reference and X timestamp names.
    Original,
    /// The EN 319 132 certificate-reference and X timestamp names.
    V2,
}

impl ReferenceSyntax {
    pub(crate) const fn certificates(self, attribute: bool) -> Name<'static> {
        match (self, attribute) {
            (Self::Original, false) => name(XADES, "CompleteCertificateRefs"),
            (Self::Original, true) => name(XADES, "AttributeCertificateRefs"),
            (Self::V2, false) => name(XADES_141, "CompleteCertificateRefsV2"),
            (Self::V2, true) => name(XADES_141, "AttributeCertificateRefsV2"),
        }
    }
}

/// One explicit extended timestamp input and its wire property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKind {
    /// Type 1 X timestamp.
    SignatureAndReferences(ReferenceSyntax),
    /// Type 2 X timestamp.
    ReferencesOnly(ReferenceSyntax),
    /// TS 101 903 V1.3.2 archive timestamp, deprecated by V1.4.2.
    Archive132,
    /// Archive timestamp in the 1.4.1 namespace, also used for renewals.
    Archive141,
}

impl ExtendedKind {
    /// Exact property name selected for this recipe.
    #[must_use]
    pub const fn name(self) -> Name<'static> {
        match self {
            Self::SignatureAndReferences(ReferenceSyntax::Original) => {
                name(XADES, "SigAndRefsTimeStamp")
            }
            Self::SignatureAndReferences(ReferenceSyntax::V2) => {
                name(XADES_141, "SigAndRefsTimeStampV2")
            }
            Self::ReferencesOnly(ReferenceSyntax::Original) => name(XADES, "RefsOnlyTimeStamp"),
            Self::ReferencesOnly(ReferenceSyntax::V2) => name(XADES_141, "RefsOnlyTimeStampV2"),
            Self::Archive132 => name(XADES, "ArchiveTimeStamp"),
            Self::Archive141 => name(XADES_141, "ArchiveTimeStamp"),
        }
    }

    const fn role(self) -> Role {
        match self {
            Self::SignatureAndReferences(_) => Role::SignatureAndReferences,
            Self::ReferencesOnly(_) => Role::ReferencesOnly,
            Self::Archive132 | Self::Archive141 => Role::Archive,
        }
    }

    pub(crate) fn from_name(name: Name<'_>, syntax: ReferenceSyntax) -> Option<Self> {
        [
            Self::SignatureAndReferences(syntax),
            Self::ReferencesOnly(syntax),
            Self::Archive132,
            Self::Archive141,
        ]
        .into_iter()
        .find(|kind| kind.name() == name)
    }
}

const fn name(namespace: &'static str, local: &'static str) -> Name<'static> {
    Name { namespace, local }
}

/// Read an exact directly incorporated extended timestamp. The caller chooses
/// the format explicitly. Verification reuses the original-source Check API.
pub fn read_extended<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    node: X::Id,
    kind: ExtendedKind,
) -> InputResult<Timestamp<X>, X> {
    let layout = bound.containers();
    let parent = unsigned_parent_in(access, layout, node)?;
    let wire = kind.name();
    if !named(access, node, wire.namespace, wire.local)? {
        return Err(InputError::Unexpected { node });
    }
    for child in access.children(parent) {
        let child = child.map_err(InputError::Child)?;
        if access
            .equal_id(child, node)
            .map_err(|cause| InputError::Resource { node, cause })?
        {
            return read_at(access, layout.signature(), parent, node, kind);
        }
    }
    Err(InputError::Foreign { node })
}

pub(crate) fn read_at<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    parent: X::Id,
    node: X::Id,
    kind: ExtendedKind,
) -> InputResult<Timestamp<X>, X> {
    // TS 101 903 V1.4.2 §8.2.1 also permits a 1.4.1 archive without an
    // explicit method. Reading that historical encoding is independent of
    // EN 319 132-1 §4.5's explicit-method requirement for generation.
    let historical = matches!(
        kind,
        ExtendedKind::Archive132
            | ExtendedKind::Archive141
            | ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original)
            | ExtendedKind::ReferencesOnly(ReferenceSyntax::Original)
    );
    let mut stamp = read_fields_in(access, signature, parent, node, kind.role(), historical)?;
    stamp.extended = Some(kind);
    Ok(stamp)
}

impl<'a, X: TimestampXml> Input<'a, X> {
    /// Select a future extended timestamp's input from the actual staged
    /// generation. Stage required references or values first and retain this
    /// generation through the request and response.
    pub fn prepare_extended_append<W: Work>(
        xml: &'a X,
        bound: &Bound<X::Id, X::Document, X::Generation>,
        kind: ExtendedKind,
        method: X::Id,
        execution: &W,
    ) -> InputResult<Self, X> {
        let layout = bound.containers();
        let access = Access::new(xml, layout.snapshot(), execution);
        if !named(&access, method, DS, "CanonicalizationMethod")? {
            return Err(InputError::Unexpected { node: method });
        }
        let mut parts = execution.vector();
        append(&access, layout, kind, method, None, &mut parts)?;
        Ok(Self {
            xml,
            snapshot: layout.snapshot(),
            signature: layout.signature(),
            timestamp: method,
            method,
            implicit_method: false,
            role: kind.role(),
            parts: parts.into_owned(),
        })
    }
}

pub(super) fn append<X: TimestampXml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
    kind: ExtendedKind,
    context: X::Id,
    before: Option<(X::Id, X::Id)>,
    parts: &mut OwnedVec<Part<X::Id>, W>,
) -> InputResult<(), X> {
    match kind {
        ExtendedKind::Archive141 => append_archive(access, layout, context, before, parts),
        ExtendedKind::Archive132 => {
            super::append_archive_132(access, layout, context, before, parts)
        }
        ExtendedKind::SignatureAndReferences(syntax) | ExtendedKind::ReferencesOnly(syntax) => {
            let parent = match before {
                Some((parent, _)) => parent,
                None => unsigned_parent_in(access, layout, context)?,
            };
            let with_signature = matches!(kind, ExtendedKind::SignatureAndReferences(_));
            super::append_reference_properties(
                access,
                ReferencePrefix {
                    signature: layout.signature(),
                    parent,
                    context,
                    before: before.map(|(_, node)| node),
                    syntax,
                    with_signature,
                },
                parts,
            )
        }
    }
}
