//! Original legacy preservation obligations, separate from modern `ATSv3`.
//!
//! EN319122-1 §5.5.3/A.2.4–5 requires preserving older archive/PoE mechanisms
//! even in another parallel root signer. Their historical encoding variants
//! and RFC4998 evidence records are not interchangeable with `ATSv3` inputs.
//! Unknown historical proof is an unavailable obligation, never a malformed
//! RFC3161 token or an implicit successful empty participant set.
//! <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>

use crate::{
    Error,
    source::{Node, Value},
};
use structured_asn1::{
    Oid, Reader,
    memory::{OwnedVec, Work},
};
use structured_cms::{attribute::Placement, signer::SignerInfo};

/// Original historical preservation mechanism, without guessing its variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Earlier archiveTimestamp, whose encodings differ between TS editions.
    ArchiveV1,
    /// RFC5126 §6.4.1 archiveTimestampV2.
    ArchiveV2,
    /// TS101733 §6.5.1 `PoE` wrapper, potentially carrying an evidence record.
    LongTermValidation,
    /// AnnexA.1.5.1 timestamp of certificate/revocation references.
    References,
    /// AnnexA.1.5.2 timestamp of the signature and its validation references.
    SignatureReferences,
}
impl Kind {
    pub(crate) fn from_oid(value: Oid<'_>) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() == 11 {
            if bytes[..10] != [42, 134, 72, 134, 247, 13, 1, 9, 16, 2] {
                return None;
            }
            match bytes[10] {
                27 => Some(Self::ArchiveV1),
                48 => Some(Self::ArchiveV2),
                26 => Some(Self::References),
                25 => Some(Self::SignatureReferences),
                _ => None,
            }
        } else if bytes == [4, 0, 0x8d, 0x45, 2, 2] {
            Some(Self::LongTermValidation)
        } else {
            None
        }
    }
    pub(crate) fn is_reference_timestamp(self) -> bool {
        matches!(self, Self::References | Self::SignatureReferences)
    }
    pub(crate) fn is_archive(self) -> bool {
        matches!(self, Self::ArchiveV1 | Self::ArchiveV2)
    }
}

/// One original obligation, retained even when absent/unreadable/unprocessed.
#[derive(Debug, Clone, Copy)]
pub struct Required<'document> {
    /// Original root or counter which contains the historical attribute.
    pub signature: Node,
    /// Whole original attribute, never a fabricated input coordinate.
    pub property: Node,
    /// Original historical format, not an inferred `ATSv3` instance.
    pub kind: Kind,
    /// Actual signed/unsigned placement from its original `SignerInfo` field.
    pub placement: Placement,
    /// Original independent field context; None is an actual empty value set.
    pub value: Option<Value<'document>>,
}

pub(crate) fn roots<'d, W: Work>(
    message: &structured_cms::SignedData<'d>,
    parent: &Reader<'d>,
    work: &W,
) -> crate::Result<OwnedVec<Required<'d>, W>> {
    let mut out = work.vector();
    for signer in message.signers() {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, "cades.preservation"))?;
        collect(signer, parent, &mut out)?;
    }
    Ok(out)
}

pub(crate) fn collect<'d, W: Work>(
    signer: &SignerInfo<'d>,
    parent: &Reader<'d>,
    out: &mut OwnedVec<Required<'d>, W>,
) -> crate::Result<()> {
    signer.require_session(parent, "cades.preservation")?;
    for (placement, set) in [
        (Placement::Signed, signer.signed_attributes()),
        (Placement::Unsigned, signer.unsigned_attributes()),
    ] {
        let Some(set) = set else {
            continue;
        };
        for attribute in set.items() {
            parent
                .charge(5 * (1 + attribute.kind().as_bytes().len().min(11) as u64))
                .map_err(|cause| Error::encoding(cause, "cades.preservation"))?;
            let kind = Kind::from_oid(attribute.kind());
            let Some(kind) = kind else {
                continue;
            };
            let resource =
                |cause| Error::resource(cause, "cades.preservation", attribute.span().start);
            if attribute.values().is_empty() {
                out.try_push(Required {
                    signature: Node::of(signer.span()),
                    property: Node::of(attribute.span()),
                    kind,
                    placement,
                    value: None,
                })
                .map_err(resource)?;
            }
            for (ordinal, value) in attribute.values().iter().enumerate() {
                let reader = attribute
                    .value_reader_in(ordinal, parent, "cades.preservation")?
                    .ok_or(Error::Foreign {
                        at: value.span().start,
                    })?;
                out.try_push(Required {
                    signature: Node::of(signer.span()),
                    property: Node::of(attribute.span()),
                    kind,
                    placement,
                    value: Some(Value::of(&reader, *value, "cades.preservation")),
                })
                .map_err(resource)?;
            }
        }
    }
    Ok(())
}
