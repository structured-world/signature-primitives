//! Original renewed detached-object digests, before reference/hash comparisons.

use crate::container::DS;
use crate::properties::{self, Error, PropertyResult};
use crate::timestamp::XADES_141;
use crate::unsigned;
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

mod check;
pub use check::{
    CheckError, CheckResult, Checked, PairCheck, PairOutcome, Report, SourceError, State, check,
};
mod prepared;
pub use prepared::{PreparedChecks, PreparedResult, check_prepared};

/// One pair of original base64 digest nodes. XML identity is not established by
/// either written value until actual authenticated Manifest lookup/comparison.
#[derive(Debug, Clone, Copy)]
pub struct Pair<N> {
    /// Original `RecomputedDigestValue`.
    pub node: N,
    /// Digest of the detached object's original reference-processing output.
    pub object: N,
    /// Digest of the canonical original Manifest `Reference` instruction.
    pub reference: N,
}

/// Source-bound original property, distinct from successful digest renewal.
#[derive(Debug)]
pub struct Catalogue<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    canonicalization: N,
    digest: N,
    pairs: OwnedVec<Pair<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Catalogue<N, D, G> {
    /// Original XML source generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Signature authenticating the relevant Manifest instructions.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original `RenewedDigestsV2` property.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original method for canonicalizing `Reference`, not its target object.
    #[must_use]
    pub fn canonicalization(&self) -> N {
        self.canonicalization
    }
    /// Original new digest method, including its untouched parameters.
    #[must_use]
    pub fn digest(&self) -> N {
        self.digest
    }
    /// Original digest pairs, preserving source order and every written pair.
    #[must_use]
    pub fn pairs(&self) -> &[Pair<N>] {
        &self.pairs
    }
}

/// Catalogue using the XML owner's original identity domain.
pub type Reading<X> = Catalogue<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Reads EN319132-1 §5.5.3's complete property shape from the original unsigned
/// inventory. Both values remain original nodes for the existing binary kernel;
/// this function never re-encodes, canonicalizes, hashes or acquires a target.
/// Different algorithms, authenticated detached Manifest selection, exact digest
/// comparisons and archive protection remain execution obligations.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    inventory: &unsigned::Reading<X>,
    index: usize,
) -> PropertyResult<Reading<X>, X> {
    if access.snapshot() != inventory.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: inventory.signature(),
        }));
    }
    access
        .query(inventory.signature(), |_, _, work| Ok(work.charge_work(1)))
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource {
            node: inventory.signature(),
            cause,
        })?;
    let entry = inventory.entries().get(index).ok_or(Error::Selection {
        parent: inventory.signature(),
        index,
    })?;
    if entry.role != unsigned::Role::RenewedDigests {
        return Err(Error::Unexpected { node: entry.node });
    }
    let node = entry.node;
    let mut children = access.children(node);
    let canonicalization =
        children
            .next()
            .transpose()
            .map_err(Error::Child)?
            .ok_or(Error::Missing {
                parent: node,
                local: "CanonicalizationMethod",
            })?;
    named(access, canonicalization, DS, "CanonicalizationMethod")?;
    let digest = children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent: node,
            local: "DigestMethod",
        })?;
    named(access, digest, DS, "DigestMethod")?;
    let mut pairs = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    for child in children {
        let child = child.map_err(Error::Child)?;
        named(access, child, XADES_141, "RecomputedDigestValue")?;
        let mut fields = access.children(child);
        let object = fields
            .next()
            .transpose()
            .map_err(Error::Child)?
            .ok_or(Error::Missing {
                parent: child,
                local: "NewSDODigestValue",
            })?;
        named(access, object, XADES_141, "NewSDODigestValue")?;
        properties::simple_content(access, object)?;
        let reference = fields
            .next()
            .transpose()
            .map_err(Error::Child)?
            .ok_or(Error::Missing {
                parent: child,
                local: "OriginalRefDigest",
            })?;
        named(access, reference, XADES_141, "OriginalRefDigest")?;
        properties::simple_content(access, reference)?;
        if let Some(extra) = fields.next() {
            return Err(Error::Unexpected {
                node: extra.map_err(Error::Child)?,
            });
        }
        pairs
            .try_push(Pair {
                node: child,
                object,
                reference,
            })
            .map_err(|cause| Error::Resource { node: child, cause })?;
    }
    if pairs.is_empty() {
        return Err(Error::Missing {
            parent: node,
            local: "RecomputedDigestValue",
        });
    }
    Ok(Catalogue {
        snapshot: inventory.snapshot(),
        signature: inventory.signature(),
        node,
        canonicalization,
        digest,
        pairs: pairs.into_owned(),
    })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> PropertyResult<(), X> {
    if !access
        .has_name(node, Name { namespace, local })
        .map_err(Error::Access)?
    {
        return Err(Error::Unexpected { node });
    }
    Ok(())
}
