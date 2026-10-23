//! Both literal objects and schema-derived per-algorithm preimages use the
//! existing `DigestBatch` states and closed finalized-output provenance.

use crate::{
    digest::{DigestBatch, DigestMemo, PassResult, RequestSource},
    stream::Source,
};
use structured_asn1::{digest::Digest, memory::Work};

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
