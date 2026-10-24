//! Actual complete media-type bytes, without whole-member materialization.

use crate::{
    error::{Error, resource},
    zip::{Member, MemberId, ReadFailure},
};
use structured_asn1::{
    memory::{MemoryError, Work},
    range::RangeSource,
};
use structured_cms::{
    mime::Essences,
    stream::{AsyncSource, Receiver, Refused},
};

/// MIME syntax and known `ASiC` essence, independent of application context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    /// A complete `application/vnd.etsi.asic-s+zip` value.
    Simple,
    /// A complete `application/vnd.etsi.asic-e+zip` value.
    Extended,
    /// A different complete MIME value. Original-container/data media types
    /// can be permitted by EN319162-1 §§4.3.3.1/4.4.3.1; this alone does not
    /// establish that association or reject those normative alternatives.
    Other,
    /// Original bytes do not form a complete MIME value.
    Malformed,
}

/// Original member whose complete bytes, extent and CRC were checked.
pub struct Reading<D, G> {
    member: MemberId<D, G>,
    kind: Type,
}
impl<D: Copy, G: Copy> Reading<D, G> {
    /// Exact original occurrence, not merely the filename `mimetype`.
    #[must_use]
    pub fn member(&self) -> MemberId<D, G> {
        self.member
    }
    /// MIME syntax/essence facts from that actual complete input.
    #[must_use]
    pub fn kind(&self) -> Type {
        self.kind
    }
}

struct Inspect<'a, W: Work> {
    syntax: Essences<'static, 2>,
    work: &'a W,
    refused: Option<MemoryError>,
}
impl<W: Work> Receiver for Inspect<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        if self.refused.is_some() {
            return Err(Refused);
        }
        if let Err(cause) = self.syntax.feed(bytes, self.work) {
            self.refused = Some(cause);
            return Err(Refused);
        }
        Ok(())
    }
}

impl<S: RangeSource> Member<'_, '_, S> {
    /// Streams the original full member through the existing incremental MIME
    /// grammar. There is no joined media-type buffer, new parser or replay.
    /// A malformed MIME reading still requires complete ZIP integrity.
    pub async fn read_media<W: Work>(
        &self,
        work: &W,
    ) -> Result<
        Reading<S::Document, S::Generation>,
        ReadFailure<S::Error, S::Document, S::Generation>,
    > {
        let mut source = self.source(work)?;
        let execution = self.session().query(work);
        let mut inspect = Inspect {
            syntax: Essences::new([
                ("application", "vnd.etsi.asic-s+zip"),
                ("application", "vnd.etsi.asic-e+zip"),
            ]),
            work: &execution,
            refused: None,
        };
        let result = source.stream(&mut inspect, &execution).await;
        if let Some(cause) = inspect.refused {
            return Err(ReadFailure::Processing {
                member: self.id(),
                cause: resource(self.central_span(), cause),
            });
        }
        result?;
        self.archive()
            .admit(&execution, self.central_span())
            .map_err(|cause: Error<S::Error>| ReadFailure::Processing {
                member: self.id(),
                cause,
            })?;
        let kind = if !inspect.syntax.complete() {
            Type::Malformed
        } else if inspect.syntax.matches(0) == Some(true) {
            Type::Simple
        } else if inspect.syntax.matches(1) == Some(true) {
            Type::Extended
        } else {
            Type::Other
        };
        Ok(Reading {
            member: self.id(),
            kind,
        })
    }
}
