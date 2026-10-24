//! Both literal objects and schema-derived per-algorithm preimages use the
//! existing `DigestBatch` states and closed finalized-output provenance.

use crate::{
    digest::{DigestBatch, DigestMemo, PassResult, RequestSource},
    stream::{AsyncSource, Source},
};
use structured_asn1::{digest::Digest, memory::Work};

/// An original object group whose complete streams can suspend for acquisition.
/// Each batch already contains every requested chain algorithm. Implementations
/// must return its outputs only after that object's complete successful input.
pub trait AsyncObjects<'p, P: Digest<'p>> {
    /// Original acquisition or format-specific comparison failure.
    type Error;
    /// Number of original objects, including repeated group occurrences.
    fn len(&self) -> usize;
    /// Whether the supplied group has no objects.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Completes this batch for the original object at `index`. The supplied
    /// work applies to acquisition, validation and the batch's own callbacks.
    fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> impl core::future::Future<Output = PassResult<DigestMemo<'p, P>, Self::Error, P::Error>>;
}

/// A borrowed group of literal asynchronous object streams, without allocation.
pub struct AsyncStreams<'s, S>(pub &'s mut [S]);
impl<'p, P: Digest<'p>, S: AsyncSource> AsyncObjects<'p, P> for AsyncStreams<'_, S> {
    type Error = S::Error;
    fn len(&self) -> usize {
        self.0.len()
    }
    async fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error> {
        batch.run_async(&mut self.0[index], work).await
    }
}

pub(super) trait Sources<'p, P: Digest<'p>> {
    type Error;
    fn len(&self) -> usize;
    fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error>;
}
pub(super) struct Streams<'s, S>(pub(super) &'s mut [S]);
impl<'p, P: Digest<'p>, S: Source> Sources<'p, P> for Streams<'_, S> {
    type Error = S::Error;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error> {
        batch.run(&mut self.0[index], work)
    }
}
pub(super) struct Requests<'s, S>(pub(super) &'s mut [S]);
impl<'p, P: Digest<'p>, S: RequestSource<'p, P>> Sources<'p, P> for Requests<'_, S> {
    type Error = S::Error;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn run<W: Work>(
        &mut self,
        index: usize,
        batch: DigestBatch<'p, P>,
        work: &W,
    ) -> PassResult<DigestMemo<'p, P>, Self::Error, P::Error> {
        batch.run_requests(&mut self.0[index], work)
    }
}
