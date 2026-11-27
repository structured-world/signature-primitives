//! Complete RFC 6283 reduced-tree imprint under the original token identity.

use super::{CanonicalInput, XmlRecordXml};
use crate::{
    binary::{self, Location},
    xml::{Access, AccessError, Snapshot, Xml},
};
use core::{cmp::Ordering, ops::Deref};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_cms::{
    stream::{Receiver, Source},
    timestamp::{ComputedInput, ImprintContext, ImprintDigest, ImprintProof, InputFailure},
};
use structured_pkix::algorithm::digest::AsnDigest;

/// Source, resource and structure refusal while computing a reduced tree.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original generation or processing refusal during canonicalization.
    Access(AccessError<E, N>),
    /// A reduced hash had the wrong full output width for this chain.
    Width(N),
    /// A reduced hash level had a decreasing original binary digest value.
    Order(N),
    /// The original members did not agree with the first complete hash list.
    Membership(N),
    /// Archived object groups and hash-tree renewals require a reduced tree.
    MissingTree(N),
    /// Resource refusal before scanning or retaining work for this field.
    Resource(N, MemoryError),
}

type ErrorFor<X> = Error<<X as Xml>::Error, <X as Xml>::Id>;

pub(super) struct Recipe<'a, X: XmlRecordXml> {
    pub xml: &'a X,
    pub snapshot: Snapshot<X::Document, X::Generation>,
    pub node: X::Id,
    pub method: X::Id,
    pub width: usize,
    pub tree: Option<&'a [super::Level<X::Id>]>,
    pub objects: Option<&'a [&'a [u8]]>,
    pub prior: Option<CanonicalInput<'a, X::Id>>,
}

pub(super) struct Prior<'a, X: XmlRecordXml> {
    pub(super) xml: &'a X,
    pub(super) snapshot: Snapshot<X::Document, X::Generation>,
    pub(super) method: X::Id,
    pub(super) input: CanonicalInput<'a, X::Id>,
}

impl<X: XmlRecordXml> Source for Prior<'_, X> {
    type Error = ErrorFor<X>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let access = Access::new(self.xml, self.snapshot, work);
        access
            .query(self.input.node(), |owner, snapshot, work| {
                owner.canonicalize_evidence(snapshot, self.method, self.input, receiver, work)
            })
            .map_err(Error::Access)
    }
}

impl<X: XmlRecordXml, P, PE> ComputedInput<P, PE> for Recipe<'_, X> {
    type Error = ErrorFor<X>;

    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        let work = context.reader().execution();
        let resource = |cause| InputFailure::Source(Error::Resource(self.node, cause));
        let tree = self
            .tree
            .map(|levels| self.decode(levels, &work))
            .transpose()
            .map_err(InputFailure::Source)?;
        let prior = if let Some(input) = self.prior {
            let mut state = context.start()?;
            let mut source = Prior {
                xml: self.xml,
                snapshot: self.snapshot,
                method: self.method,
                input,
            };
            context.stream(&mut source, &mut [&mut state])?;
            Some(state.finish()?)
        } else {
            None
        };
        let Some(tree) = tree else {
            if self.objects.is_some() {
                return Err(InputFailure::Source(Error::MissingTree(self.node)));
            }
            let prior = prior.ok_or(InputFailure::Source(Error::MissingTree(self.node)))?;
            return context.compare(&prior).map_err(InputFailure::Refused);
        };
        let mut expected = work.vector();
        if let Some(objects) = self.objects {
            expected.try_extend_from_slice(objects).map_err(resource)?;
        }
        if let Some(prior) = &prior {
            expected.try_push(prior.as_bytes()).map_err(resource)?;
        }
        let first = &tree[0];
        let mismatch = || InputFailure::Source(Error::Membership(self.node));
        let mut current = if first.len() == 1 && self.objects.is_some() && prior.is_none() {
            // ETSI TS 119 132-3 §5.2.2.1 places the whole protected group's
            // digest in the first list. RFC 6283 §3.1.1 carries this singleton
            // directly into the next level. Later chains still prove each
            // object and the preceding sequence under RFC 6283 §4.3.
            // https://www.etsi.org/deliver/etsi_ts/119100_119199/11913203/01.01.01_60/ts_11913203v010101p.pdf
            // https://www.rfc-editor.org/rfc/rfc6283.html#section-3.1.1
            sort_hashes(&mut expected, &work).map_err(resource)?;
            let group = hash_level(context, expected.iter().copied(), None, self.node)?;
            drop(expected);
            if compare(group.as_bytes(), &first[0], &work).map_err(resource)? != Ordering::Equal {
                return Err(mismatch());
            }
            group
        } else {
            ensure_membership(first, &mut expected, self.objects.is_some(), &work).map_err(
                |failure| match failure {
                    MembershipError::Resource(cause) => resource(cause),
                    MembershipError::Differs => mismatch(),
                },
            )?;
            drop(expected);
            if first.len() == 1 {
                prior.ok_or_else(mismatch)?
            } else {
                hash_level(context, first.iter().map(Deref::deref), None, self.node)?
            }
        };
        for level in &tree[1..] {
            work.charge_work(1).map_err(resource)?;
            current = hash_level(
                context,
                level.iter().map(Deref::deref),
                Some(current.as_bytes()),
                self.node,
            )?;
        }
        context.compare(&current).map_err(InputFailure::Refused)
    }
}

type Tree = OwnedVec<OwnedVec<OwnedVec<u8>>>;

impl<X: XmlRecordXml> Recipe<'_, X> {
    fn decode<W: Work>(
        &self,
        levels: &[super::Level<X::Id>],
        work: &W,
    ) -> Result<Tree, ErrorFor<X>> {
        let mut output = work.vector();
        output
            .try_reserve_exact(levels.len())
            .map_err(|cause| Error::Resource(self.node, cause))?;
        for level in levels {
            let at = level.sequence.node;
            let resource = |cause| Error::Resource(at, cause);
            let mut hashes = work.vector::<OwnedVec<u8>>();
            hashes
                .try_reserve_exact(level.hashes().len())
                .map_err(resource)?;
            for &node in level.hashes() {
                let read = binary::owned(
                    self.xml,
                    Location {
                        snapshot: self.snapshot,
                        node,
                    },
                    work,
                )
                .map_err(Error::Access)?;
                if read.value.len() != self.width {
                    return Err(Error::Width(node));
                }
                if let Some(previous) = hashes.last()
                    && compare(previous, &read.value, work).map_err(resource)? == Ordering::Greater
                {
                    return Err(Error::Order(node));
                }
                hashes.try_push(read.value).map_err(resource)?;
            }
            output.try_push(hashes.into_owned()).map_err(resource)?;
        }
        Ok(output.into_owned())
    }
}

enum MembershipError {
    Resource(MemoryError),
    Differs,
}

fn ensure_membership<W: Work>(
    first: &[OwnedVec<u8>],
    object_hashes: &mut OwnedVec<&[u8], W>,
    complete: bool,
    work: &W,
) -> Result<(), MembershipError> {
    let resource = MembershipError::Resource;
    // RFC 6283 §§3.3 and 4.3 distinguish the complete group from a
    // timestamp renewal that may share an RFC 3161 token with other objects.
    // https://www.rfc-editor.org/rfc/rfc6283.html#section-4.3
    if complete {
        if first.len() != object_hashes.len() {
            return Err(MembershipError::Differs);
        }
        sort_hashes(object_hashes, work).map_err(resource)?;
        for (actual, declared) in object_hashes.iter().zip(first) {
            if compare(actual, declared, work).map_err(resource)? != Ordering::Equal {
                return Err(MembershipError::Differs);
            }
        }
    } else {
        let Some(actual) = object_hashes.first() else {
            return Err(MembershipError::Differs);
        };
        for declared in first {
            if compare(actual, declared, work).map_err(resource)? == Ordering::Equal {
                return Ok(());
            }
        }
        return Err(MembershipError::Differs);
    }
    Ok(())
}

fn sort_hashes<W: Work>(hashes: &mut OwnedVec<&[u8], W>, work: &W) -> Result<(), MemoryError> {
    hashes
        .try_sort_unstable_by(|left, right| compare(left, right, work))
        .map_err(Into::into)
}

fn compare<W: Work>(a: &[u8], b: &[u8], work: &W) -> Result<Ordering, MemoryError> {
    work.charge_work(1 + a.len().min(b.len()) as u64)?;
    Ok(a.cmp(b))
}

type LevelResult<'c, 'r, 'd, P, E> = Result<ImprintDigest<'c, 'r, 'd, P, E>, InputFailure<E>>;

fn hash_level<'c, 'r, 'd, 'level, P: AsnDigest<'d>, E, N: Copy>(
    context: &'c ImprintContext<'r, 'd, P, Error<E, N>>,
    level: impl Iterator<Item = &'level [u8]>,
    mut previous: Option<&[u8]>,
    node: N,
) -> LevelResult<'c, 'r, 'd, P, Error<E, N>> {
    // Existing siblings are in binary ascending order. Insert exactly one
    // computed child while streaming the ordered row instead of sorting again.
    let mut state = context.start()?;
    let work = context.reader().execution();
    for digest in level {
        if let Some(child) = previous
            && compare(child, digest, &work)
                .map_err(|cause| InputFailure::Source(Error::Resource(node, cause)))?
                != Ordering::Greater
        {
            state.write(child)?;
            previous = None;
        }
        state.write(digest)?;
    }
    if let Some(child) = previous {
        state.write(child)?;
    }
    state.finish().map_err(InputFailure::Refused)
}
