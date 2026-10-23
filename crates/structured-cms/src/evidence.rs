//! RFC 4998 evidence records over original sources and current execution.
//!
//! Reading preserves unprotected hints and unknown timestamp formats. Neither
//! a readable record nor a matching hash establishes historical TSA validity.
//! <https://www.rfc-editor.org/rfc/rfc4998#section-3>

use crate::{
    ContentInfo, Error, ErrorCode, Octets, Result, SignedData, attribute::Attribute, oid,
    timestamp::Token,
};
use structured_asn1::{
    Element, Encoding, Oid, Parser, Reader, Span, Tag,
    memory::{OwnedVec, Work},
    universal,
};
use structured_pkix::algorithm::{self, AlgorithmIdentifier};

const FIELD: &str = "evidenceRecord";

mod input;
pub use input::{InputError, Membership, ObjectInput};
mod renewal;
pub use renewal::PriorSequence;
mod objects;
pub mod verify;

/// Original field context, independent of a movable reader cursor.
#[derive(Debug, Clone, Copy)]
pub struct Original<'d> {
    parser: &'d Parser,
    element: Element<'d>,
    encoding: Encoding,
    outer: u32,
}
impl<'d> Original<'d> {
    fn new(parent: &Reader<'d>, element: Element<'d>) -> Self {
        Self {
            parser: parent.parser(),
            element,
            encoding: parent.encoding(),
            outer: parent.depth(),
        }
    }
    /// Whole original value, including its original tag and length.
    #[must_use]
    pub fn element(&self) -> Element<'d> {
        self.element
    }
    /// Reopens this original field with both source and current query ceilings.
    pub fn reader_in<'q>(&self, query: &Reader<'q>) -> Result<Reader<'q>>
    where
        'd: 'q,
    {
        self.parser
            .read_query_in(
                query,
                self.element.as_bytes(),
                self.element.span().start,
                self.encoding,
                self.outer,
            )
            .map_err(|cause| Error::encoding(cause, FIELD))
    }
}

/// Unprotected re-encryption context, not evidence for plaintext correspondence.
#[derive(Debug)]
pub struct EncryptionInfo<'d> {
    kind: Oid<'d>,
    value: Original<'d>,
}
impl<'d> EncryptionInfo<'d> {
    /// Original encryption mechanism identifier, without algorithm dispatch.
    #[must_use]
    pub fn kind(&self) -> Oid<'d> {
        self.kind
    }
    /// Original open value for the actual encryption mechanism owner.
    #[must_use]
    pub fn value(&self) -> Original<'d> {
        self.value
    }
}

/// One reduced-tree level. Logical hashes retain original OCTET STRING pieces.
#[derive(Debug)]
pub struct PartialTree<'d> {
    original: Original<'d>,
    hashes: OwnedVec<Octets<'d>>,
}
impl<'d> PartialTree<'d> {
    /// Original sequence and its producing context.
    #[must_use]
    pub fn original(&self) -> Original<'d> {
        self.original
    }
    /// Hash values as full-width logical octets, without canonicalizing input.
    #[must_use]
    pub fn hashes(&self) -> &[Octets<'d>] {
        &self.hashes
    }
}

/// RFC3161 token or an original alternative timestamp requiring its own owner.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the normal RFC3161 model is retained inline in the quota-backed flat stamp catalogue; boxing would add a separate allocation for every token"
)]
pub enum TimeStamp<'d> {
    /// Original parsed CMS/TST envelope; inspection is not authentication.
    Rfc3161(Token<'d>),
    /// Original open timestamp format; never silently omitted from a proof.
    Other(Original<'d>),
}

/// One archive timestamp, preserving the exact renewed timestamp encoding.
#[derive(Debug)]
pub struct ArchiveTimeStamp<'d> {
    original: Original<'d>,
    algorithm: Option<AlgorithmIdentifier<'d>>,
    attributes: Option<OwnedVec<Attribute<'d>>>,
    attributes_span: Option<Span>,
    tree: Option<OwnedVec<PartialTree<'d>>>,
    timestamp: Original<'d>,
    token: TimeStamp<'d>,
}
impl<'d> ArchiveTimeStamp<'d> {
    /// Whole original archive-timestamp field.
    #[must_use]
    pub fn original(&self) -> Original<'d> {
        self.original
    }
    /// Written tree algorithm. Absence selects the actual token imprint algorithm.
    #[must_use]
    pub fn digest_algorithm(&self) -> Option<AlgorithmIdentifier<'d>> {
        self.algorithm
    }
    /// Original optional renewal attributes; absence differs from an empty set.
    #[must_use]
    pub fn attributes(&self) -> Option<&[Attribute<'d>]> {
        self.attributes.as_deref()
    }
    /// Original reduced tree. Absence means a direct-object timestamp.
    #[must_use]
    pub fn reduced_tree(&self) -> Option<&[PartialTree<'d>]> {
        self.tree.as_deref()
    }
    /// Whole original `ContentInfo` bytes used by timestamp renewal (§5.2).
    #[must_use]
    pub fn timestamp_source(&self) -> Original<'d> {
        self.timestamp
    }
    /// Parsed timestamp or explicitly unimplemented alternative format.
    #[must_use]
    pub fn timestamp(&self) -> &TimeStamp<'d> {
        &self.token
    }
}

/// One timestamp-renewal chain, in its original sequence order.
#[derive(Debug)]
pub struct Chain<'d> {
    original: Original<'d>,
    first: usize,
    end: usize,
}
impl<'d> Chain<'d> {
    /// Whole original chain including its wrapper.
    #[must_use]
    pub fn original(&self) -> Original<'d> {
        self.original
    }
    /// Range in this record's flat timestamp catalogue.
    #[must_use]
    pub fn timestamps(&self) -> core::ops::Range<usize> {
        self.first..self.end
    }
}

/// Original evidence record. Flat ownership makes traversal and drop stack-safe.
#[derive(Debug)]
pub struct EvidenceRecord<'d> {
    original: Original<'d>,
    algorithms: OwnedVec<AlgorithmIdentifier<'d>>,
    crypto: Option<OwnedVec<Attribute<'d>>>,
    encryption: Option<EncryptionInfo<'d>>,
    sequence: Original<'d>,
    chains: OwnedVec<Chain<'d>>,
    timestamps: OwnedVec<ArchiveTimeStamp<'d>>,
}
impl<'d> EvidenceRecord<'d> {
    /// Reads one original embedded record. Parent encoding/depth are inherited.
    pub fn read(parent: &Reader<'d>, element: &Element<'d>) -> Result<Self> {
        let mut inside = enter(parent, element, Tag::constructed(universal::SEQUENCE))?;
        let version = required(&mut inside)?;
        if version.tag() != Tag::primitive(universal::INTEGER) {
            return Err(syntax(ErrorCode::UnexpectedTag, version.span()));
        }
        let version = inside.integer(&version).map_err(encoding)?;
        if version.as_u64() != Some(1) {
            return Err(syntax(ErrorCode::UnsupportedVersion, element.span()));
        }
        let set = required(&mut inside)?;
        let mut members = enter(&inside, &set, Tag::constructed(universal::SEQUENCE))?;
        let work = parent.execution();
        let mut algorithms = work.vector();
        while let Some(member) = members.next_element().map_err(encoding)? {
            let value = algorithm::read(&members, &member, FIELD).map_err(Error::pkix)?;
            algorithms
                .try_push(value)
                .map_err(|cause| Error::resource(cause, FIELD, member.span().start))?;
        }
        if algorithms.is_empty() {
            return Err(syntax(ErrorCode::MissingField, set.span()));
        }
        let mut next = required(&mut inside)?;
        let crypto = if next.tag() == Tag::context(true, 0) {
            let values = attributes(&inside, &next, Tag::context(true, 0), false)?;
            next = required(&mut inside)?;
            Some(values)
        } else {
            None
        };
        let encryption = if next.tag() == Tag::context(true, 1) {
            let mut fields = enter(&inside, &next, Tag::context(true, 1))?;
            let kind = fields.read_oid().map_err(encoding)?;
            let value = required(&mut fields)?;
            finish(&fields)?;
            let result = EncryptionInfo {
                kind,
                value: Original::new(&fields, value),
            };
            next = required(&mut inside)?;
            Some(result)
        } else {
            None
        };
        let mut sequence = enter(&inside, &next, Tag::constructed(universal::SEQUENCE))?;
        let mut chains = work.vector();
        let mut timestamps = work.vector();
        while let Some(chain) = sequence.next_element().map_err(encoding)? {
            let mut entries = enter(&sequence, &chain, Tag::constructed(universal::SEQUENCE))?;
            let first = timestamps.len();
            while let Some(entry) = entries.next_element().map_err(encoding)? {
                let value = read_timestamp(&entries, entry)?;
                timestamps
                    .try_push(value)
                    .map_err(|cause| Error::resource(cause, FIELD, entry.span().start))?;
            }
            if first == timestamps.len() {
                return Err(syntax(ErrorCode::MissingField, chain.span()));
            }
            chains
                .try_push(Chain {
                    original: Original::new(&sequence, chain),
                    first,
                    end: timestamps.len(),
                })
                .map_err(|cause| Error::resource(cause, FIELD, chain.span().start))?;
        }
        if chains.is_empty() {
            return Err(syntax(ErrorCode::MissingField, next.span()));
        }
        finish(&inside)?;
        Ok(Self {
            original: Original::new(parent, *element),
            algorithms: algorithms.into_owned(),
            crypto,
            encryption,
            sequence: Original::new(&inside, next),
            chains: chains.into_owned(),
            timestamps: timestamps.into_owned(),
        })
    }
    /// Whole original record, without serializing its retained views.
    #[must_use]
    pub fn original(&self) -> Original<'d> {
        self.original
    }
    /// Declared union; semantic membership is checked with the selected provider.
    #[must_use]
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier<'d>] {
        &self.algorithms
    }
    /// Unprotected validation hints; no trust is inferred from their presence.
    #[must_use]
    pub fn crypto_infos(&self) -> Option<&[Attribute<'d>]> {
        self.crypto.as_deref()
    }
    /// Unprotected exact re-encryption context.
    #[must_use]
    pub fn encryption_info(&self) -> Option<&EncryptionInfo<'d>> {
        self.encryption.as_ref()
    }
    /// Whole original sequence of timestamp-renewal chains.
    #[must_use]
    pub fn sequence(&self) -> Original<'d> {
        self.sequence
    }
    /// Actual chain order; not a trusted chronology before verification.
    #[must_use]
    pub fn chains(&self) -> &[Chain<'d>] {
        &self.chains
    }
    /// Flat original timestamp catalogue; chain ranges select their members.
    #[must_use]
    pub fn timestamps(&self) -> &[ArchiveTimeStamp<'d>] {
        &self.timestamps
    }
}

fn read_timestamp<'d>(parent: &Reader<'d>, element: Element<'d>) -> Result<ArchiveTimeStamp<'d>> {
    let mut inside = enter(parent, &element, Tag::constructed(universal::SEQUENCE))?;
    let mut next = required(&mut inside)?;
    let algorithm = if next.tag() == Tag::context(true, 0) {
        let value = algorithm::read_implicit(&inside, &next, 0, FIELD).map_err(Error::pkix)?;
        next = required(&mut inside)?;
        Some(value)
    } else {
        None
    };
    let attributes_span = (next.tag() == Tag::context(true, 1)).then_some(next.span());
    let attributes = if next.tag() == Tag::context(true, 1) {
        let values = attributes(&inside, &next, Tag::context(true, 1), true)?;
        next = required(&mut inside)?;
        Some(values)
    } else {
        None
    };
    let tree = if next.tag() == Tag::context(true, 2) {
        let mut levels = enter(&inside, &next, Tag::context(true, 2))?;
        let work = parent.execution();
        let mut tree = work.vector();
        while let Some(level) = levels.next_element().map_err(encoding)? {
            let mut entries = enter(&levels, &level, Tag::constructed(universal::SEQUENCE))?;
            let mut hashes = work.vector();
            while let Some(hash) = entries.next_element().map_err(encoding)? {
                let value = Octets::read(&entries, &hash, FIELD)?;
                hashes
                    .try_push(value)
                    .map_err(|cause| Error::resource(cause, FIELD, hash.span().start))?;
            }
            // RFC4998 §4.2 permits arbitrary hash-list lengths. Inspection
            // preserves an empty list; proof execution still needs membership.
            tree.try_push(PartialTree {
                original: Original::new(&levels, level),
                hashes: hashes.into_owned(),
            })
            .map_err(|cause| Error::resource(cause, FIELD, level.span().start))?;
        }
        next = required(&mut inside)?;
        Some(tree.into_owned())
    } else {
        None
    };
    let (envelope, source) = ContentInfo::read_element(&inside, &next)?;
    inside
        .charge(1 + envelope.kind().as_bytes().len() as u64)
        .map_err(encoding)?;
    let token = if envelope.kind() == oid::SIGNED_DATA {
        TimeStamp::Rfc3161(Token::from_message(
            SignedData::read_element(&source, envelope.content())?,
            &source,
        )?)
    } else {
        TimeStamp::Other(Original::new(&inside, next))
    };
    finish(&inside)?;
    Ok(ArchiveTimeStamp {
        original: Original::new(parent, element),
        algorithm,
        attributes,
        attributes_span,
        tree,
        timestamp: Original::new(&inside, next),
        token,
    })
}

fn attributes<'d>(
    parent: &Reader<'d>,
    element: &Element<'d>,
    tag: Tag,
    sorted: bool,
) -> Result<OwnedVec<Attribute<'d>>> {
    let mut inside = enter(parent, element, tag)?;
    let work = parent.execution();
    let mut values = work.vector();
    let mut previous = None;
    while let Some(entry) = inside.next_element().map_err(encoding)? {
        // RFC4998 §§3.1/4.1: CryptoInfos is a SEQUENCE, Attributes a SET.
        // Only the latter receives DER SET ordering, never the former.
        if sorted && inside.encoding().is_der() {
            if let Some(previous) = previous
                && !structured_pkix::der::set_ordered(&inside, previous, &entry, FIELD)
                    .map_err(Error::pkix)?
            {
                return Err(syntax(ErrorCode::SetOrder, entry.span()));
            }
            previous = Some(entry.as_bytes());
        }
        values
            .try_push(Attribute::read(&inside, &entry, FIELD)?)
            .map_err(|cause| Error::resource(cause, FIELD, entry.span().start))?;
    }
    if values.is_empty() {
        return Err(syntax(ErrorCode::EmptyAttributes, element.span()));
    }
    Ok(values.into_owned())
}
fn enter<'d>(parent: &Reader<'d>, element: &Element<'d>, tag: Tag) -> Result<Reader<'d>> {
    if element.tag() != tag {
        return Err(syntax(ErrorCode::UnexpectedTag, element.span()));
    }
    parent.enter(element).map_err(encoding)
}
fn required<'d>(reader: &mut Reader<'d>) -> Result<Element<'d>> {
    reader
        .next_element()
        .map_err(encoding)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, FIELD, reader.offset()))
}
fn finish(reader: &Reader<'_>) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::TrailingData,
            FIELD,
            reader.offset(),
        ))
    }
}
fn syntax(code: ErrorCode, span: Span) -> Error {
    Error::schema(code, FIELD, span.start)
}
fn encoding(cause: structured_asn1::Error) -> Error {
    Error::encoding(cause, FIELD)
}
