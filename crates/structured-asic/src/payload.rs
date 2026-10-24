//! Sealed original member input, streamed or already completely CRC-checked.

use crate::{
    content::Content,
    zip::{Member, ReadFailure},
};
use structured_asn1::{memory::Work, range::RangeSource};
use structured_cms::stream::{AsyncSource, Receiver};

mod private {
    pub trait Sealed {}
}
impl<S: RangeSource> private::Sealed for Member<'_, '_, S> {}
impl<S: RangeSource> private::Sealed for Content<'_, '_, S> {}

/// An actual original `ASiC` occurrence. Only the streaming member and its
/// complete CRC-checked retained content implement this boundary. An arbitrary
/// slice, caller assertion or independently supplied source cannot implement it.
pub trait Payload<'v, 's, S: RangeSource>: private::Sealed {
    /// Exact original acquisition or retained-input stream.
    type Source<'q>: AsyncSource<Error = ReadFailure<S::Error, S::Document, S::Generation>>
    where
        Self: 'q;
    /// Original complete member identity and producing execution.
    fn member(&self) -> &Member<'v, 's, S>;
    /// Preflights the actual source before provider state creation.
    fn source<W: Work>(&self, work: &W) -> crate::zip::Acquisition<Self::Source<'_>, S>;
}
impl<'v, 's, S: RangeSource> Payload<'v, 's, S> for Member<'v, 's, S> {
    type Source<'q>
        = crate::zip::Source<'v, 's, S>
    where
        Self: 'q;
    fn member(&self) -> &Member<'v, 's, S> {
        self
    }
    fn source<W: Work>(
        &self,
        work: &W,
    ) -> Result<Self::Source<'_>, ReadFailure<S::Error, S::Document, S::Generation>> {
        Member::source(self, work)
    }
}
impl<'v, 's, S: RangeSource> Payload<'v, 's, S> for Content<'v, 's, S> {
    type Source<'q>
        = Retained<'q, 'v, 's, S>
    where
        Self: 'q;
    fn member(&self) -> &Member<'v, 's, S> {
        Content::member(self)
    }
    fn source<W: Work>(
        &self,
        work: &W,
    ) -> Result<Self::Source<'_>, ReadFailure<S::Error, S::Document, S::Generation>> {
        let member = self.member();
        let execution = member.session().query(work);
        member
            .archive()
            .admit(&execution, member.central_span())
            .map_err(|cause| ReadFailure::Processing {
                member: member.id(),
                cause,
            })?;
        Ok(Retained { content: self })
    }
}

/// Borrowed original immutable decoded allocation. Construction requires an
/// actual complete member receipt, not an external byte-plus-member pairing.
pub struct Retained<'q, 'v, 's, S: RangeSource> {
    content: &'q Content<'v, 's, S>,
}
impl<S: RangeSource> AsyncSource for Retained<'_, '_, '_, S> {
    type Error = ReadFailure<S::Error, S::Document, S::Generation>;
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "defer receiver calls and current admission until polling, preserving the asynchronous stream's cancellation boundary for retained bytes"
    )]
    async fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        work: &'q W,
    ) -> Result<(), Self::Error> {
        let member = self.content.member();
        let execution = member.session().query(work);
        let failure = |cause| ReadFailure::Processing {
            member: member.id(),
            cause,
        };
        member
            .archive()
            .admit(&execution, member.central_span())
            .map_err(failure)?;
        // Borrowing a chunk does not copy or decode its bytes. The receiver
        // separately admits its actual hashing/copy work under the same query.
        for bytes in self.content.bytes().chunks(4096) {
            execution
                .charge_work(1)
                .map_err(|cause| failure(crate::error::resource(member.central_span(), cause)))?;
            receiver.write(bytes).map_err(ReadFailure::Receiver)?;
        }
        member
            .archive()
            .admit(&execution, member.central_span())
            .map_err(failure)?;
        Ok(())
    }
}
