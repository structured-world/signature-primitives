//! Accounted RFC4998 reduced-tree computation; no cryptographic engine here.

use super::objects::Sources;
use super::{ArchiveTimeStamp, FIELD};
use crate::{
    Error,
    digest::{DigestBatch, DigestError, DigestMemo},
    stream::{self, Sink, Source, StreamError},
    timestamp::{ComputedInput, ImprintContext, ImprintProof, InputFailure},
};
use core::cell::{OnceCell, RefCell};
use core::cmp::Ordering;
use structured_asn1::{
    digest::Resolution,
    memory::{MemoryError, OwnedVec, SortError, Work},
};
use structured_pkix::algorithm::digest::{self, AsnDigest};

/// Whether the proof names one object or exactly an entire document group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// Exactly one supplied object must occur in the first partial tree.
    Object,
    /// All supplied objects, and no others, form the first partial tree.
    Group,
}

/// Original acquisition/provider failure or a completed unusable ERS recipe.
#[derive(Debug)]
pub enum InputError<SE, PE> {
    /// Original source/depth/storage/work refusal.
    Processing(Error),
    /// The selected provider failed; its cause is preserved unchanged.
    Provider(PE),
    /// Actual covered source did not reach successful EOF.
    Source(SE),
    /// The selected provider does not implement this stream or written identity.
    Unsupported,
    /// A written digest violates its algorithm-specific syntax.
    MalformedAlgorithm,
    /// A supplied group is empty, or Object was given several sources.
    ObjectCount,
    /// The selected object/group is absent from the first partial tree.
    Membership,
    /// A declared tree hash has the wrong full output width.
    HashWidth,
    /// Provider output contradicts its own promised width.
    OutputWidth,
    /// A previous-sequence receipt names another record or another new chain.
    ForeignRenewal,
    /// Cached input came from another provider, identity or request ordinal.
    ForeignDigest,
}

/// Closed tree recipe over complete caller-supplied object streams.
///
/// Sources are visited once per required record algorithm, never buffered into
/// a whole-document allocation. Group equality is a multiset equality: repeated
/// identical objects/hashes are not collapsed.
pub struct ObjectInput<'input, 'document, S> {
    stamp: &'input ArchiveTimeStamp<'document>,
    sources: &'input mut [S],
    membership: Membership,
    previous: Option<&'input super::PriorSequence<'input, 'document>>,
}
impl<'i, 'd, S> ObjectInput<'i, 'd, S> {
    /// Selects one original archive timestamp and the actual complete input.
    #[must_use]
    pub fn new(
        stamp: &'i ArchiveTimeStamp<'d>,
        sources: &'i mut [S],
        membership: Membership,
    ) -> Self {
        Self {
            stamp,
            sources,
            membership,
            previous: None,
        }
    }
    /// Selects hash-tree renewal for this prefix's actual first new timestamp.
    /// RFC4998 §5.2(4) hashes dataHash then previousSequenceHash, unsorted;
    /// Figure4 and reported erratum7411 do not enable a silent alternative.
    #[must_use]
    pub fn renewed(
        stamp: &'i ArchiveTimeStamp<'d>,
        sources: &'i mut [S],
        membership: Membership,
        previous: &'i super::PriorSequence<'i, 'd>,
    ) -> Self {
        Self {
            stamp,
            sources,
            membership,
            previous: Some(previous),
        }
    }
}

pub(super) struct Hasher<'p, 'i, P: AsnDigest<'p>, W: Work> {
    pub(super) provider: &'p P,
    pub(super) identity: &'i P::Identity,
    pub(super) work: W,
    pub(super) at: u64,
}
impl<'p, P: AsnDigest<'p>, W: Work> Hasher<'p, '_, P, W> {
    pub(super) fn resource<SE>(&self, cause: MemoryError) -> InputError<SE, P::Error> {
        InputError::Processing(Error::resource(cause, FIELD, self.at))
    }
    pub(super) fn start<SE>(&self) -> Result<P::State, InputError<SE, P::Error>> {
        match self
            .provider
            .start(self.identity, &self.work)
            .map_err(InputError::Provider)?
        {
            Resolution::Supported(state) => Ok(state),
            Resolution::Unsupported => Err(InputError::Unsupported),
            Resolution::Malformed => Err(InputError::MalformedAlgorithm),
        }
    }
    pub(super) fn finish<SE>(
        &self,
        state: P::State,
    ) -> Result<P::Output, InputError<SE, P::Error>> {
        let output = self
            .provider
            .finish(state, &self.work)
            .map_err(InputError::Provider)?;
        if let Some(width) = self.provider.width(self.identity)
            && output.as_ref().len() != width
        {
            return Err(InputError::OutputWidth);
        }
        Ok(output)
    }
    pub(super) fn update<SE>(
        &self,
        state: &mut P::State,
        bytes: &[u8],
    ) -> Result<(), InputError<SE, P::Error>> {
        self.work
            .charge_work(1)
            .map_err(|cause| self.resource(cause))?;
        self.provider
            .update(state, bytes, &self.work)
            .map_err(InputError::Provider)
    }
    pub(super) fn hash_source<S: Source>(
        &self,
        source: &mut S,
    ) -> Result<P::Output, InputError<S::Error, P::Error>> {
        let mut state = self.start()?;
        let mut sink = Feed {
            provider: self.provider,
            state: &mut state,
        };
        stream::run(source, &mut sink, &self.work, FIELD, self.at).map_err(
            |cause| match cause {
                StreamError::Source(cause) => InputError::Source(cause),
                StreamError::Callback(cause) => InputError::Provider(cause),
                StreamError::Processing(cause) => InputError::Processing(cause),
            },
        )?;
        self.finish(state)
    }
    fn hash_list<SE>(
        &self,
        values: &[Hash<'_, P::Output>],
    ) -> Result<P::Output, InputError<SE, P::Error>> {
        let mut state = self.start()?;
        for value in values {
            self.update(&mut state, value.bytes())?;
        }
        self.finish(state)
    }
    fn compare<SE>(&self, a: &[u8], b: &[u8]) -> Result<Ordering, InputError<SE, P::Error>> {
        self.work
            .charge_work(1 + a.len().min(b.len()) as u64)
            .map_err(|cause| self.resource(cause))?;
        Ok(a.cmp(b))
    }
}

struct Feed<'p, 's, P: AsnDigest<'p>> {
    provider: &'p P,
    state: &'s mut P::State,
}
impl<'p, P: AsnDigest<'p>> Sink for Feed<'p, '_, P> {
    type Error = P::Error;
    fn write<W: Work>(&mut self, bytes: &[u8], work: &W) -> Result<(), Self::Error> {
        self.provider.update(self.state, bytes, work)
    }
}

enum Hash<'d, O> {
    Borrowed(&'d [u8]),
    Joined(OwnedVec<u8>),
    Root(Root<'d, O>),
}
impl<O: AsRef<[u8]>> Hash<'_, O> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Joined(bytes) => bytes,
            Self::Root(output) => output.output().as_ref(),
        }
    }
}

impl<P, PE, S: Source> ComputedInput<P, PE> for ObjectInput<'_, '_, S> {
    type Error = InputError<S::Error, PE>;
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        let stamp = self.stamp;
        let (root, written) = self.compute_root(context).map_err(InputFailure::Source)?;
        let identity = written.as_ref().unwrap_or(context.identity());
        let origin = stamp
            .original
            .reader_in(context.reader())
            .map_err(|cause| InputFailure::Source(InputError::Processing(cause)))?;
        let execution = origin.execution_query(context.reader());
        context
            .compare_derived(|expected, _| {
                context
                    .provider()
                    .matches(identity, root.output(), expected, &execution)
                    .map_err(InputError::Provider)
            })
            .map_err(InputFailure::Refused)
    }
}
impl<S: Source> ObjectInput<'_, '_, S> {
    fn compute_root<'p, P: AsnDigest<'p>>(
        &mut self,
        context: &ImprintContext<'_, 'p, P, InputError<S::Error, P::Error>>,
    ) -> ResolvedRoot<'_, P::Output, P::Identity, S::Error, P::Error> {
        if self.sources.is_empty()
            || (self.membership == Membership::Object && self.sources.len() != 1)
        {
            return Err(InputError::ObjectCount);
        }
        if !membership_shape(self.stamp, self.sources.len(), self.membership) {
            return Err(InputError::Membership);
        }
        if let Some(previous) = self.previous
            && !previous.contains(self.stamp)
        {
            return Err(InputError::ForeignRenewal);
        }
        let origin = self
            .stamp
            .original
            .reader_in(context.reader())
            .map_err(InputError::Processing)?;
        let work = origin.execution_query(context.reader());
        // Explicit identity can differ from the RFC3161 imprint algorithm:
        // RFC4998 §4.2(5). Absence uses the context identity without cloning it.
        let provider = context.provider();
        let written = if let Some(identifier) = self.stamp.algorithm {
            match digest::resolve(provider, &identifier, &work)
                .map_err(|cause| InputError::Processing(Error::pkix(cause)))?
            {
                Resolution::Supported(identity) => Some(identity),
                Resolution::Unsupported => return Err(InputError::Unsupported),
                Resolution::Malformed => return Err(InputError::MalformedAlgorithm),
            }
        } else {
            None
        };
        let identity = written.as_ref().unwrap_or(context.identity());
        let hasher = Hasher {
            provider,
            identity,
            work,
            at: self.stamp.original.element.span().start,
        };
        let output = root(
            &hasher,
            self.stamp,
            self.sources,
            self.membership,
            self.previous,
        )?;
        Ok((output, written))
    }
}

fn root<'s, 'p, P: AsnDigest<'p>, W: Work, S: Source>(
    hasher: &Hasher<'p, '_, P, W>,
    stamp: &'s ArchiveTimeStamp<'_>,
    sources: &mut [S],
    membership: Membership,
    previous: Option<&super::PriorSequence<'_, '_>>,
) -> RootResult<'s, P::Output, S::Error, P::Error> {
    validate_tree(hasher, stamp)?;
    let mut objects = hasher.work.vector();
    objects
        .try_reserve_exact(sources.len())
        .map_err(|cause| hasher.resource(cause))?;
    let previous_hash = previous.map(|prior| prior.hash(hasher)).transpose()?;
    for source in sources {
        let mut output = hasher.hash_source(source)?;
        if let Some(previous) = &previous_hash {
            let mut state = hasher.start()?;
            hasher.update(&mut state, output.as_ref())?;
            hasher.update(&mut state, previous.as_ref())?;
            output = hasher.finish(state)?;
        }
        objects
            .try_push(Hash::Root(Root::Owned(output)))
            .map_err(|cause| hasher.resource(cause))?;
    }
    fold(hasher, stamp, objects, membership)
}

fn validate_tree<'p, P: AsnDigest<'p>, W: Work, SE>(
    hasher: &Hasher<'p, '_, P, W>,
    stamp: &ArchiveTimeStamp<'_>,
) -> Result<(), InputError<SE, P::Error>> {
    // Validate every declared width before provider state or source I/O.
    let width = hasher.provider.width(hasher.identity);
    if let Some(tree) = &stamp.tree {
        for level in tree {
            hasher
                .work
                .charge_work(1)
                .map_err(|cause| hasher.resource(cause))?;
            for hash in &level.hashes {
                hasher
                    .work
                    .charge_work(1)
                    .map_err(|cause| hasher.resource(cause))?;
                if let Some(width) = width
                    && hash.len() != width
                {
                    return Err(InputError::HashWidth);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn membership_shape(
    stamp: &ArchiveTimeStamp<'_>,
    objects: usize,
    membership: Membership,
) -> bool {
    let Some(tree) = &stamp.tree else {
        return objects == 1;
    };
    let Some(first) = tree.first() else {
        return false;
    };
    if first.hashes.is_empty() {
        return false;
    }
    membership != Membership::Group || first.hashes.len() == objects
}

pub(super) enum Root<'s, O> {
    Owned(O),
    Borrowed(&'s O),
}
type RootResult<'s, O, SE, PE> = Result<Root<'s, O>, InputError<SE, PE>>;
type ResolvedRoot<'s, O, I, SE, PE> = Result<(Root<'s, O>, Option<I>), InputError<SE, PE>>;
impl<O> Root<'_, O> {
    pub(super) fn output(&self) -> &O {
        match self {
            Self::Owned(o) => o,
            Self::Borrowed(o) => o,
        }
    }
}

fn fold<'s, 'p, P: AsnDigest<'p>, W: Work, SE>(
    hasher: &Hasher<'p, '_, P, W>,
    stamp: &'s ArchiveTimeStamp<'_>,
    mut objects: OwnedVec<Hash<'s, P::Output>, W>,
    membership: Membership,
) -> Result<Root<'s, P::Output>, InputError<SE, P::Error>> {
    sort(hasher, &mut objects)?;
    let Some(tree) = &stamp.tree else {
        if objects.len() != 1 {
            return Err(InputError::Membership);
        }
        let Some(Hash::Root(output)) = objects.pop() else {
            unreachable!("one complete output")
        };
        return Ok(output);
    };
    let Some(first) = tree.first() else {
        return Err(InputError::Membership);
    };
    let mut siblings = hasher.work.vector();
    for hash in &first.hashes {
        siblings
            .try_push(read_hash(hash, hasher)?)
            .map_err(|cause| hasher.resource(cause))?;
    }
    sort(hasher, &mut siblings)?;
    if membership == Membership::Group {
        if objects.len() != siblings.len() {
            return Err(InputError::Membership);
        }
        for (object, hash) in objects.iter().zip(siblings.iter()) {
            if hasher.compare(object.bytes(), hash.bytes())? != Ordering::Equal {
                return Err(InputError::Membership);
            }
        }
    } else {
        let mut found = false;
        for hash in &siblings {
            if hasher.compare(objects[0].bytes(), hash.bytes())? == Ordering::Equal {
                found = true;
                break;
            }
        }
        if !found {
            return Err(InputError::Membership);
        }
    }
    let mut current = if siblings.len() == 1 {
        // A singleton leaf is already the root (RFC4998 §4.2 steps3–4).
        let Some(Hash::Root(output)) = objects.pop() else {
            unreachable!("matched singleton has one actual output")
        };
        output
    } else {
        Root::Owned(hasher.hash_list(&siblings)?)
    };
    drop(objects);
    for level in &tree[1..] {
        siblings.clear();
        siblings
            .try_push(Hash::Root(current))
            .map_err(|cause| hasher.resource(cause))?;
        for hash in &level.hashes {
            siblings
                .try_push(read_hash(hash, hasher)?)
                .map_err(|cause| hasher.resource(cause))?;
        }
        sort(hasher, &mut siblings)?;
        current = if siblings.len() == 1 {
            let Some(Hash::Root(output)) = siblings.pop() else {
                unreachable!("computed child")
            };
            output
        } else {
            Root::Owned(hasher.hash_list(&siblings)?)
        };
    }
    Ok(current)
}

fn read_hash<'d, 'p, P: AsnDigest<'p>, W: Work, SE>(
    hash: &crate::Octets<'d>,
    hasher: &Hasher<'p, '_, P, W>,
) -> Result<Hash<'d, P::Output>, InputError<SE, P::Error>> {
    if let Some(bytes) = hash.as_one() {
        return Ok(Hash::Borrowed(bytes));
    }
    let mut joined = hasher.work.vector();
    joined
        .try_reserve_exact(hash.len())
        .map_err(|cause| hasher.resource(cause))?;
    for piece in hash.pieces() {
        hasher
            .work
            .charge_work(1)
            .map_err(|cause| hasher.resource(cause))?;
        joined
            .try_extend_from_slice(piece.as_bytes())
            .map_err(|cause| hasher.resource(cause))?;
    }
    Ok(Hash::Joined(joined.into_owned()))
}

fn sort<'p, P: AsnDigest<'p>, W: Work, SE>(
    hasher: &Hasher<'p, '_, P, W>,
    siblings: &mut OwnedVec<Hash<'_, P::Output>, W>,
) -> Result<(), InputError<SE, P::Error>> {
    siblings
        .try_sort_unstable_by(|a, b| hasher.compare(a.bytes(), b.bytes()))
        .map_err(|cause| match cause {
            SortError::Resource(cause) => hasher.resource(cause),
            SortError::Comparison(cause) => cause,
        })
}

// Record verification hashes every actual object once through DigestBatch's
// full-identity fan-out. Nested joined TSTInfo checks borrow those outputs;
// identities/outputs cannot borrow that temporary inner information source.
pub(super) struct MemoSet<'p, P: AsnDigest<'p>> {
    pub(super) provider: &'p P,
    pub(super) memos: OwnedVec<DigestMemo<'p, P>>,
}
trait RootComputation<P> {
    type Output: AsRef<[u8]>;
    type Error;
    type SourceError;
    fn belongs_to_provider(&self, provider: &P) -> bool;
    fn root<'s>(
        &'s self,
        stamp: &'s ArchiveTimeStamp<'_>,
        ordinal: usize,
        membership: Membership,
        previous: Option<&super::PriorSequence<'_, '_>>,
        query: &structured_asn1::Reader<'_>,
    ) -> RootResult<'s, Self::Output, Self::SourceError, Self::Error>;
    fn matches<W: Work>(
        &self,
        ordinal: usize,
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, InputError<Self::SourceError, Self::Error>>;
}
impl<'p, P: AsnDigest<'p>> RootComputation<P> for MemoSet<'p, P> {
    type Output = P::Output;
    type Error = P::Error;
    type SourceError = core::convert::Infallible;
    fn belongs_to_provider(&self, provider: &P) -> bool {
        core::ptr::eq(self.provider, provider)
    }
    fn root<'s>(
        &'s self,
        stamp: &'s ArchiveTimeStamp<'_>,
        ordinal: usize,
        membership: Membership,
        previous: Option<&super::PriorSequence<'_, '_>>,
        query: &structured_asn1::Reader<'_>,
    ) -> Result<Root<'s, P::Output>, InputError<core::convert::Infallible, P::Error>> {
        let origin = stamp
            .original
            .reader_in(query)
            .map_err(InputError::Processing)?;
        let work = origin.execution_query(query);
        if self.memos.is_empty() || (membership == Membership::Object && self.memos.len() != 1) {
            return Err(InputError::ObjectCount);
        }
        let mut objects = work.vector();
        objects
            .try_reserve_exact(self.memos.len())
            .map_err(|cause| {
                InputError::Processing(Error::resource(
                    cause,
                    FIELD,
                    stamp.original.element.span().start,
                ))
            })?;
        let first = self.memos[0]
            .for_request(ordinal, &work)
            .map_err(map_digest)?
            .ok_or(InputError::ForeignDigest)?;
        if !first.finished().from_provider(self.provider) {
            return Err(InputError::ForeignDigest);
        }
        if let Some(prior) = previous
            && !prior.contains(stamp)
        {
            return Err(InputError::ForeignRenewal);
        }
        let hasher = Hasher {
            provider: self.provider,
            identity: first.identity(),
            work,
            at: stamp.original.element.span().start,
        };
        validate_tree(&hasher, stamp)?;
        let previous = previous.map(|prior| prior.hash(&hasher)).transpose()?;
        for memo in &self.memos {
            let value = memo
                .for_request(ordinal, &hasher.work)
                .map_err(map_digest)?
                .ok_or(InputError::ForeignDigest)?;
            if !value.finished().from_provider(self.provider) {
                return Err(InputError::ForeignDigest);
            }
            if self
                .provider
                .compare(value.identity(), hasher.identity, &hasher.work)
                .map_err(InputError::Provider)?
                != Ordering::Equal
            {
                return Err(InputError::ForeignDigest);
            }
            let output = if let Some(previous) = &previous {
                let mut state = hasher.start()?;
                hasher.update(&mut state, value.as_bytes())?;
                hasher.update(&mut state, previous.as_ref())?;
                Root::Owned(hasher.finish(state)?)
            } else {
                Root::Borrowed(value.finished().output())
            };
            objects
                .try_push(Hash::Root(output))
                .map_err(|cause| hasher.resource(cause))?;
        }
        fold(&hasher, stamp, objects, membership)
    }
    fn matches<W: Work>(
        &self,
        ordinal: usize,
        output: &P::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, InputError<core::convert::Infallible, P::Error>> {
        let first = self.memos[0]
            .for_request(ordinal, work)
            .map_err(map_digest)?
            .ok_or(InputError::ForeignDigest)?;
        self.provider
            .matches(first.identity(), output, expected, work)
            .map_err(InputError::Provider)
    }
}

// Initialize on the first actual object-input request, AFTER the same token's
// common schema/profile/key preparation. Successful output is immutable and
// owned by OnceCell; later trees borrow it without refcount, Clone or replay.
pub(super) struct LazyMemos<'s, 'p, P: AsnDigest<'p>, S: Sources<'p, P>> {
    provider: &'p P,
    algorithms: &'s [structured_pkix::algorithm::digest::Algorithm],
    sources: RefCell<S>,
    initialized: OnceCell<MemoSet<'p, P>>,
}
impl<'s, 'p, P: AsnDigest<'p>, S: Sources<'p, P>> LazyMemos<'s, 'p, P, S> {
    pub(super) fn new(
        provider: &'p P,
        algorithms: &'s [structured_pkix::algorithm::digest::Algorithm],
        sources: S,
    ) -> Self {
        Self {
            provider,
            algorithms,
            sources: RefCell::new(sources),
            initialized: OnceCell::new(),
        }
    }
    fn ready(
        &self,
        stamp: &ArchiveTimeStamp<'_>,
        query: &structured_asn1::Reader<'_>,
    ) -> Result<&MemoSet<'p, P>, InputError<S::Error, P::Error>> {
        if let Some(memos) = self.initialized.get() {
            return Ok(memos);
        }
        let origin = stamp
            .original
            .reader_in(query)
            .map_err(InputError::Processing)?;
        let work = origin.execution_query(query);
        let at = stamp.original.element.span().start;
        let resource = |cause| InputError::Processing(Error::resource(cause, FIELD, at));
        let mut sources = self
            .sources
            .try_borrow_mut()
            .map_err(|_| InputError::ForeignDigest)?;
        let mut memos = work.vector();
        memos.try_reserve_exact(sources.len()).map_err(resource)?;
        for index in 0..sources.len() {
            let mut identities = work.vector();
            for algorithm in self.algorithms {
                work.charge_work(1).map_err(resource)?;
                let identity = self
                    .provider
                    .identity(*algorithm)
                    .ok_or(InputError::Unsupported)?;
                identities.try_push(identity).map_err(resource)?;
            }
            let batch =
                DigestBatch::prepare(self.provider, identities.into_owned(), &work, FIELD, at)
                    .map_err(map_digest)?;
            let memo = sources
                .run(index, batch, &work)
                .map_err(|cause| match cause {
                    StreamError::Source(cause) => InputError::Source(cause),
                    StreamError::Callback(cause) => map_digest(cause),
                    StreamError::Processing(cause) => InputError::Processing(cause),
                })?;
            memos.try_push(memo).map_err(resource)?;
        }
        self.initialized
            .set(MemoSet {
                provider: self.provider,
                memos: memos.into_owned(),
            })
            .map_err(|_| InputError::ForeignDigest)?;
        self.initialized.get().ok_or(InputError::ForeignDigest)
    }
}
impl<'p, P: AsnDigest<'p>, S: Sources<'p, P>> RootComputation<P> for LazyMemos<'_, 'p, P, S> {
    type Output = P::Output;
    type Error = P::Error;
    type SourceError = S::Error;
    fn belongs_to_provider(&self, provider: &P) -> bool {
        core::ptr::eq(self.provider, provider)
    }
    fn root<'s>(
        &'s self,
        stamp: &'s ArchiveTimeStamp<'_>,
        ordinal: usize,
        membership: Membership,
        previous: Option<&super::PriorSequence<'_, '_>>,
        query: &structured_asn1::Reader<'_>,
    ) -> Result<Root<'s, P::Output>, InputError<S::Error, P::Error>> {
        self.ready(stamp, query)?
            .root(stamp, ordinal, membership, previous, query)
            .map_err(widen)
    }
    fn matches<W: Work>(
        &self,
        ordinal: usize,
        output: &P::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, InputError<S::Error, P::Error>> {
        self.initialized
            .get()
            .ok_or(InputError::ForeignDigest)?
            .matches(ordinal, output, expected, work)
            .map_err(widen)
    }
}
fn widen<SE, PE>(cause: InputError<core::convert::Infallible, PE>) -> InputError<SE, PE> {
    match cause {
        InputError::Processing(cause) => InputError::Processing(cause),
        InputError::Provider(cause) => InputError::Provider(cause),
        InputError::Source(never) => match never {},
        InputError::Unsupported => InputError::Unsupported,
        InputError::MalformedAlgorithm => InputError::MalformedAlgorithm,
        InputError::ObjectCount => InputError::ObjectCount,
        InputError::Membership => InputError::Membership,
        InputError::HashWidth => InputError::HashWidth,
        InputError::OutputWidth => InputError::OutputWidth,
        InputError::ForeignRenewal => InputError::ForeignRenewal,
        InputError::ForeignDigest => InputError::ForeignDigest,
    }
}
pub(super) struct CachedInput<'s, 'd, F> {
    pub(super) stamp: &'s ArchiveTimeStamp<'d>,
    pub(super) memos: &'s F,
    pub(super) ordinal: usize,
    pub(super) membership: Membership,
    pub(super) previous: Option<&'s super::PriorSequence<'s, 'd>>,
}
impl<P, PE, SE, F: RootComputation<P, Error = PE, SourceError = SE>> ComputedInput<P, PE>
    for CachedInput<'_, '_, F>
{
    type Error = InputError<SE, PE>;
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        if !self.memos.belongs_to_provider(context.provider()) {
            return Err(InputFailure::Source(InputError::ForeignDigest));
        }
        let root = self
            .memos
            .root(
                self.stamp,
                self.ordinal,
                self.membership,
                self.previous,
                context.reader(),
            )
            .map_err(InputFailure::Source)?;
        context
            .compare_derived(|expected, work| {
                self.memos
                    .matches(self.ordinal, root.output(), expected, work)
            })
            .map_err(InputFailure::Refused)
    }
}
fn map_digest<SE, PE>(cause: DigestError<PE>) -> InputError<SE, PE> {
    match cause {
        DigestError::Processing(cause) => InputError::Processing(cause),
        DigestError::Callback(cause) => InputError::Provider(cause),
        DigestError::OutputWidth { .. } => InputError::OutputWidth,
        DigestError::Unstreamable => InputError::Unsupported,
    }
}
