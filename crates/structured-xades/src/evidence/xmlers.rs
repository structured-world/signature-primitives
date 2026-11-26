//! Original RFC 6283 records carried by an ETSI sealing property.

use super::{Format, Member, Records, XML_ERS};
use crate::xml::{Access, AccessError, ChildError, Name, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, SortError, Work};

/// Original grammar or access failure of an XML evidence record.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original member selection refused.
    Record(super::Error<E, N>),
    /// Original XML/generation/budget access failure.
    Access(AccessError<E, N>),
    /// Original child traversal failure.
    Child(ChildError<E, N>),
    /// A field or attribute required by Appendix A is missing.
    Missing(N, &'static str),
    /// An original field is duplicate, misplaced, or unknown.
    Unexpected(N),
    /// A mandatory Order is invalid or already used in this sequence.
    Order(N),
    /// The record uses another version of XMLERS.
    Version(N),
    /// ETSI TS 119 132-3 §4.2 admits only original RFC 3161 tokens.
    TokenType(N),
    /// Resource refusal during original-order selection.
    Resource(N, MemoryError),
}

/// Located XMLERS result using the original owner's identities.
pub type ResultFor<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// One element in a sibling sequence with an RFC 6283 `Order` attribute.
#[derive(Debug, Clone, Copy)]
pub struct Ordered<N> {
    /// Original element identity.
    pub node: N,
    /// Original positive `xs:int` value of `Order` (Appendix A).
    pub order: i32,
}

/// One original reduced hash-tree level and its binary-value elements.
pub struct Level<N> {
    /// Original Sequence and its `Order`.
    pub sequence: Ordered<N>,
    hashes: OwnedVec<N>,
}

impl<N> Level<N> {
    /// Original `DigestValue` elements, with no string reconstruction.
    #[must_use]
    pub fn hashes(&self) -> &[N] {
        &self.hashes
    }
}

/// One ordered archive timestamp in the original XML record.
pub struct Stamp<N> {
    /// Original archive wrapper and position.
    pub archive: Ordered<N>,
    /// Original `TimeStamp` subtree, including its cryptographic information.
    pub timestamp: N,
    /// Original RFC 3161 `TimeStampToken` element.
    pub token: N,
    /// Original optional ordered attributes enclosure.
    pub attributes: Option<N>,
    /// Original optional cryptographic information enclosure.
    pub cryptographic_information: Option<N>,
    crypto: OwnedVec<Ordered<N>>,
    info: OwnedVec<Ordered<N>>,
    tree: Option<OwnedVec<Level<N>>>,
}

impl<N> Stamp<N> {
    /// Original hash-tree levels in ascending `Order`.
    #[must_use]
    pub fn tree(&self) -> Option<&[Level<N>]> {
        self.tree.as_deref()
    }

    /// Original cryptographic material items, in ascending `Order`.
    #[must_use]
    pub fn cryptographic_information(&self) -> &[Ordered<N>] {
        &self.crypto
    }

    /// Original auxiliary attribute items, in ascending `Order`.
    #[must_use]
    pub fn attributes(&self) -> &[Ordered<N>] {
        &self.info
    }
}

/// One ordered timestamp-renewal chain from the original record.
pub struct Chain<N> {
    /// Original chain and actual `Order`.
    pub chain: Ordered<N>,
    /// Original `DigestMethod` XMLERS element.
    pub digest: N,
    /// Original `CanonicalizationMethod`, including its actual parameters.
    pub canonicalization: N,
    stamps: OwnedVec<Stamp<N>>,
}

impl<N> Chain<N> {
    /// Original timestamps in ascending `Order`.
    #[must_use]
    pub fn stamps(&self) -> &[Stamp<N>] {
        &self.stamps
    }
}

/// Complete source-bound XMLERS structure, including historical chain order.
pub struct Record<X: Xml> {
    snapshot: Snapshot<X::Document, X::Generation>,
    member: Member<X::Id>,
    sequence: X::Id,
    encryption: Option<X::Id>,
    supporting: Option<X::Id>,
    chains: OwnedVec<Chain<X::Id>>,
}

impl<X: Xml> Record<X> {
    /// Actual enclosing XML generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.snapshot
    }

    /// The only original evidence record associated with this structure.
    #[must_use]
    pub fn member(&self) -> Member<X::Id> {
        self.member
    }

    /// Original sequence wrapper needed for hash-tree renewal canonicalization.
    #[must_use]
    pub fn sequence(&self) -> X::Id {
        self.sequence
    }

    /// Original optional encryption mechanism, which has its own processing owner.
    #[must_use]
    pub fn encryption(&self) -> Option<X::Id> {
        self.encryption
    }

    /// Original optional supporting information enclosure.
    #[must_use]
    pub fn supporting_information(&self) -> Option<X::Id> {
        self.supporting
    }

    /// Original chains in ascending `Order`.
    #[must_use]
    pub fn chains(&self) -> &[Chain<X::Id>] {
        &self.chains
    }
}

/// Read the selected XML record in its original document without canonicalizing,
/// decoding token bytes, resolving algorithms or asserting mathematical proof.
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    records: &Records<'_, X>,
    index: usize,
) -> ResultFor<Record<X>, X> {
    let member = *records
        .members
        .get(index)
        .ok_or(Error::Record(super::Error::Index(index)))?;
    if records.snapshot() != access.snapshot() {
        return Err(Error::Record(super::Error::Foreign(member.node)));
    }
    if records.format() != Some(Format::Xml) {
        return Err(Error::Record(super::Error::Unexpected(member.node)));
    }
    let node = member.node;
    if !attribute_matches(access, node, "Version", version_one)? {
        return Err(Error::Version(node));
    }
    let [encryption, supporting, sequence] = fields(
        access,
        node,
        [
            "EncryptionInformation",
            "SupportingInformationList",
            "ArchiveTimeStampSequence",
        ],
    )?;
    let sequence = require(sequence, node, "ArchiveTimeStampSequence")?;
    let chains = ordered(access, sequence, "ArchiveTimeStampChain", |chain| {
        parse_chain(access, chain)
    })?;
    if chains[0].stamps[0].tree.is_none() {
        return Err(Error::Missing(chains[0].stamps[0].archive.node, "HashTree"));
    }
    Ok(Record {
        snapshot: access.snapshot(),
        member,
        sequence,
        encryption,
        supporting,
        chains,
    })
}

fn parse_chain<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    chain: Ordered<X::Id>,
) -> ResultFor<Chain<X::Id>, X> {
    let node = chain.node;
    let mut children = access.children(node);
    let digest = read_expected(access, node, "DigestMethod", children.next())?;
    let canonicalization = read_expected(access, node, "CanonicalizationMethod", children.next())?;
    present_attribute(access, digest, "Algorithm")?;
    present_attribute(access, canonicalization, "Algorithm")?;
    let stamps = order_items(access, node, "ArchiveTimeStamp", children, |stamp| {
        parse_stamp(access, stamp)
    })?;
    Ok(Chain {
        chain,
        digest,
        canonicalization,
        stamps,
    })
}

fn parse_stamp<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    archive: Ordered<X::Id>,
) -> ResultFor<Stamp<X::Id>, X> {
    let node = archive.node;
    let [tree, timestamp, attributes] =
        fields(access, node, ["HashTree", "TimeStamp", "Attributes"])?;
    let timestamp = require(timestamp, node, "TimeStamp")?;
    let [token, cryptographic_information] = fields(
        access,
        timestamp,
        ["TimeStampToken", "CryptographicInformationList"],
    )?;
    let token = require(token, timestamp, "TimeStampToken")?;
    if !attribute_matches(access, token, "Type", |text| text == "RFC3161")? {
        return Err(Error::TokenType(token));
    }
    let tree = tree
        .map(|tree| {
            ordered(access, tree, "Sequence", |sequence| {
                let hashes = plain_children(access, sequence.node, "DigestValue")?;
                Ok(Level { sequence, hashes })
            })
        })
        .transpose()?;
    let crypto = if let Some(crypto) = cryptographic_information {
        ordered(access, crypto, "CryptographicInformation", |value| {
            present_attribute(access, value.node, "Type")?;
            Ok(value)
        })?
    } else {
        access.execution().vector().into_owned()
    };
    let info = if let Some(info) = attributes {
        ordered(access, info, "Attribute", Ok)?
    } else {
        access.execution().vector().into_owned()
    };
    Ok(Stamp {
        archive,
        timestamp,
        token,
        attributes,
        cryptographic_information,
        crypto,
        info,
        tree,
    })
}

fn fields<const L: usize, X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    names: [&'static str; L],
) -> ResultFor<[Option<X::Id>; L], X> {
    let mut output = [None; L];
    let mut previous = 0;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        let mut found = false;
        for (rank, local) in names.iter().enumerate().skip(previous) {
            if access
                .has_name(
                    node,
                    Name {
                        namespace: XML_ERS,
                        local,
                    },
                )
                .map_err(Error::Access)?
            {
                output[rank] = Some(node);
                previous = rank + 1;
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Unexpected(node));
        }
    }
    Ok(output)
}

fn require<E, N>(field: Option<N>, parent: N, local: &'static str) -> Result<N, Error<E, N>> {
    field.ok_or(Error::Missing(parent, local))
}

fn read_expected<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    local: &'static str,
    child: Option<Result<X::Id, ChildError<X::Error, X::Id>>>,
) -> ResultFor<X::Id, X> {
    let child = require(child.transpose().map_err(Error::Child)?, parent, local)?;
    if access
        .has_name(
            child,
            Name {
                namespace: XML_ERS,
                local,
            },
        )
        .map_err(Error::Access)?
    {
        Ok(child)
    } else {
        Err(Error::Unexpected(child))
    }
}

fn plain_children<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    local: &'static str,
) -> ResultFor<OwnedVec<X::Id>, X> {
    let mut items = access.execution().vector();
    for child in access.children(parent) {
        let node = read_expected(access, parent, local, Some(child))?;
        items
            .try_push(node)
            .map_err(|cause| Error::Resource(node, cause))?;
    }
    if items.is_empty() {
        return Err(Error::Missing(parent, local));
    }
    Ok(items.into_owned())
}

fn ordered<X: Xml, W: Work, T>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    local: &'static str,
    read: impl FnMut(Ordered<X::Id>) -> ResultFor<T, X>,
) -> ResultFor<OwnedVec<T>, X> {
    order_items(access, parent, local, access.children(parent), read)
}

fn order_items<X: Xml, W: Work, T>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    local: &'static str,
    children: impl Iterator<Item = Result<X::Id, ChildError<X::Error, X::Id>>>,
    mut read: impl FnMut(Ordered<X::Id>) -> ResultFor<T, X>,
) -> ResultFor<OwnedVec<T>, X> {
    let work = access.execution();
    let mut order = work.vector();
    let mut sorted = true;
    let mut previous = 0;
    for child in children {
        let node = read_expected(access, parent, local, Some(child))?;
        let value = access
            .attribute(
                node,
                Name {
                    namespace: "",
                    local: "Order",
                },
                |text| {
                    let text = text.ok_or(Error::Missing(node, "Order"))?;
                    let trimmed = access
                        .trim_xml_whitespace(text)
                        .map_err(|cause| Error::Resource(node, cause))?;
                    work.charge_work(trimmed.len() as u64)
                        .map_err(|cause| Error::Resource(node, cause))?;
                    let value = trimmed.parse::<i32>().map_err(|_| Error::Order(node))?;
                    if value > 0 {
                        Ok(value)
                    } else {
                        Err(Error::Order(node))
                    }
                },
            )
            .map_err(Error::Access)??;
        sorted &= previous < value;
        previous = value;
        order
            .try_push(Ordered { node, order: value })
            .map_err(|cause| Error::Resource(node, cause))?;
    }
    if order.is_empty() {
        return Err(Error::Missing(parent, local));
    }
    // RFC 6283 §§2.1 and 4.1 leave XML sibling order independent of Order.
    // https://www.rfc-editor.org/rfc/rfc6283.html#section-4.1
    if !sorted {
        order
            .try_sort_unstable_by(|a, b| Ok::<_, core::convert::Infallible>(a.order.cmp(&b.order)))
            .map_err(|error| match error {
                SortError::Resource(cause) => Error::Resource(parent, cause),
                SortError::Comparison(never) => match never {},
            })?;
    }
    let mut output = work.vector();
    output
        .try_reserve_exact(order.len())
        .map_err(|cause| Error::Resource(parent, cause))?;
    previous = 0;
    for value in &order {
        work.charge_work(1)
            .map_err(|cause| Error::Resource(value.node, cause))?;
        if value.order == previous {
            return Err(Error::Order(value.node));
        }
        previous = value.order;
        output
            .try_push(read(*value)?)
            .map_err(|cause| Error::Resource(value.node, cause))?;
    }
    Ok(output.into_owned())
}

fn present_attribute<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &'static str,
) -> ResultFor<(), X> {
    access
        .attribute(
            node,
            Name {
                namespace: "",
                local,
            },
            |text| {
                if text.is_some() {
                    Ok(())
                } else {
                    Err(Error::Missing(node, local))
                }
            },
        )
        .map_err(Error::Access)?
}

fn attribute_matches<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &'static str,
    matches: impl FnOnce(&str) -> bool,
) -> ResultFor<bool, X> {
    access
        .attribute(
            node,
            Name {
                namespace: "",
                local,
            },
            |text| {
                let text = text.ok_or(Error::Missing(node, local))?;
                let trimmed = access
                    .trim_xml_whitespace(text)
                    .map_err(|cause| Error::Resource(node, cause))?;
                access
                    .execution()
                    .charge_work(trimmed.len() as u64)
                    .map_err(|cause| Error::Resource(node, cause))?;
                Ok(matches(trimmed))
            },
        )
        .map_err(Error::Access)?
}

fn version_one(value: &str) -> bool {
    // The Version attribute is xs:decimal. Its value is independent of padding.
    let value = value.strip_prefix('+').unwrap_or(value);
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    whole.trim_start_matches('0') == "1" && fraction.bytes().all(|digit| digit == b'0')
}
