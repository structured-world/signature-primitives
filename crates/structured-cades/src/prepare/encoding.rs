//! Minimal original fields retained before a counter walk's movable frame drops.

use crate::{Error, Result};
use structured_asn1::{
    Oid, Reader, Span,
    memory::{OwnedVec, Work},
};
use structured_cms::{attribute::Attribute, signer::SignerInfo};

/// Borrowed complete/inner attribute encodings, with no decoded-value clone.
#[derive(Clone, Copy)]
pub(crate) struct AttributeEncoding<'d> {
    pub(crate) kind: Oid<'d>,
    pub(crate) whole: &'d [u8],
    pub(crate) contents: &'d [u8],
    pub(crate) kind_encoding: &'d [u8],
    pub(crate) span: Span,
    pub(crate) single: Option<Span>,
}
impl<'d> AttributeEncoding<'d> {
    fn of(attribute: &Attribute<'d>) -> Self {
        Self {
            kind: attribute.kind(),
            whole: attribute.as_bytes(),
            contents: attribute.element().contents(),
            kind_encoding: attribute.kind_encoding(),
            span: attribute.span(),
            single: if attribute.values().len() == 1 {
                Some(attribute.values()[0].span())
            } else {
                None
            },
        }
    }
}

/// Source-backed encoding, without retaining/cloning the temporary `SignerInfo`.
pub(crate) struct SignerEncoding<'d> {
    fields: &'d [u8],
    signed: Option<(Span, &'d [u8])>,
    unsigned: Option<(Span, &'d [u8], &'d [u8])>,
    attributes: Option<OwnedVec<AttributeEncoding<'d>>>,
}
impl<'d> SignerEncoding<'d> {
    pub(crate) fn read(signer: &SignerInfo<'d>, reader: &Reader<'d>) -> Result<Self> {
        signer.require_session(reader, "cades.historical.signer")?;
        let attributes = if let Some(set) = signer.unsigned_attributes() {
            let work = reader.execution();
            let mut saved = work.vector();
            let resource =
                |cause| Error::resource(cause, "cades.historical.signer", signer.span().start);
            saved
                .try_reserve_exact(set.items().len())
                .map_err(resource)?;
            // Metadata must outlive this frame; original payloads remain
            // borrowed. The move/copy and its actual capacity are admitted.
            for attribute in set.items() {
                saved
                    .try_push(AttributeEncoding::of(attribute))
                    .map_err(resource)?;
            }
            Some(saved.into_owned())
        } else {
            None
        };
        Ok(Self {
            fields: signer.signed_fields(),
            signed: signer
                .signed_attributes()
                .map(|set| (set.element().span(), set.element().contents())),
            unsigned: signer.unsigned_attributes().map(|set| {
                (
                    set.element().span(),
                    set.element().as_bytes(),
                    set.element().contents(),
                )
            }),
            attributes,
        })
    }
}

/// Roots reuse their existing catalogue; counters reuse saved frame metadata.
#[derive(Clone, Copy)]
pub(crate) enum SignerView<'view, 'd> {
    Root(&'view SignerInfo<'d>),
    Counter(&'view SignerEncoding<'d>),
}
impl<'d> SignerView<'_, 'd> {
    pub(crate) fn fields(self) -> &'d [u8] {
        match self {
            Self::Root(signer) => signer.signed_fields(),
            Self::Counter(signer) => signer.fields,
        }
    }
    pub(crate) fn signed(self) -> Option<(Span, &'d [u8])> {
        match self {
            Self::Root(signer) => signer
                .signed_attributes()
                .map(|set| (set.element().span(), set.element().contents())),
            Self::Counter(signer) => signer.signed,
        }
    }
    pub(crate) fn unsigned(self) -> Option<(Span, &'d [u8], &'d [u8])> {
        match self {
            Self::Root(signer) => signer.unsigned_attributes().map(|set| {
                (
                    set.element().span(),
                    set.element().as_bytes(),
                    set.element().contents(),
                )
            }),
            Self::Counter(signer) => signer.unsigned,
        }
    }
    pub(crate) fn attributes(self) -> usize {
        match self {
            Self::Root(signer) => signer
                .unsigned_attributes()
                .map_or(0, |set| set.items().len()),
            Self::Counter(signer) => signer.attributes.as_ref().map_or(0, |set| set.len()),
        }
    }
    pub(crate) fn attribute(self, ordinal: usize) -> Option<AttributeEncoding<'d>> {
        match self {
            Self::Root(signer) => signer
                .unsigned_attributes()?
                .items()
                .get(ordinal)
                .map(AttributeEncoding::of),
            Self::Counter(signer) => signer.attributes.as_ref()?.get(ordinal).copied(),
        }
    }
}
