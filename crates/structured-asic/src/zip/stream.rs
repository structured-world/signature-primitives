//! Complete member streams reuse the common sticky CMS source protocol.

use super::{Archive, Member, MemberId};
use crate::error::{Error, Limit, Unsupported, resource};
use structured_asn1::range::RangeSource;
use structured_asn1::{
    Span,
    inflate::{Envelope, Error as InflateError, Inflater, Progress},
    memory::{MemoryError, OwnedVec, Work},
};
use structured_cms::stream::{AsyncSource, Receiver, Refused};

/// Original member-acquisition result, including source identity on refusal.
pub type Acquisition<T, S> = Result<
    T,
    ReadFailure<
        <S as RangeSource>::Error,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
>;

/// The complete original member could not be delivered.
#[derive(Debug)]
pub enum ReadFailure<E, D, G> {
    /// Original range/work/storage refusal.
    Processing {
        /// Exact original occurrence.
        member: MemberId<D, G>,
        /// Original typed processing cause.
        cause: Error<E>,
    },
    /// An original envelope or payload integrity check failed.
    Integrity {
        /// Exact original occurrence.
        member: MemberId<D, G>,
        /// Physical original member enclosure.
        range: Span,
        /// Independent integrity cause.
        kind: Integrity,
    },
    /// The common stream driver retains the receiver's original refusal.
    Receiver(Refused),
}

/// Payload integrity is distinct from signature mathematics and trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// No unique consistent local record belongs to this occurrence.
    Framing,
    /// Invalid or truncated raw DEFLATE syntax.
    Compression,
    /// Declared compressed/decoded extent disagrees with complete decoding.
    Length,
    /// CRC-32 disagrees with the original central/local metadata.
    Crc,
}

/// One original entry selected before digest/provider state creation.
pub struct Source<'v, 's, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    ordinal: usize,
}

impl<'v, 's, S: RangeSource> Member<'v, 's, S> {
    /// Checks source, method and unambiguous framing before constructing a
    /// payload source. CRC and final extent remain complete-EOF obligations.
    pub fn source<W: Work>(&self, work: &W) -> Acquisition<Source<'v, 's, S>, S> {
        check(self.archive, self.ordinal, work)?;
        Ok(Source {
            archive: self.archive,
            ordinal: self.ordinal,
        })
    }

    /// Retains a complete carried CMS/XML member under actual-capacity funding.
    /// Large data objects should be streamed; no successful prefix is returned
    /// after source, CRC, decoded-length or receiver refusal.
    ///
    /// # Panics
    /// An internal framing invariant fails if a preflighted readable member
    /// lacks its already checked original payload range.
    pub async fn read_bytes<W: Work>(
        &self,
        work: &W,
    ) -> Result<OwnedVec<u8>, ReadFailure<S::Error, S::Document, S::Generation>> {
        let mut source = self.source(work)?;
        let execution = self.archive.session.query(work);
        let range = self.entry().data.expect("checked original payload");
        let mut bytes = execution.vector();
        let count = usize::try_from(self.entry().decoded)
            .map_err(|_| failure(self, resource(range, MemoryError::LimitExceeded)))?;
        bytes
            .try_reserve_exact(count)
            .map_err(|cause| failure(self, resource(range, cause)))?;
        let mut receiver = Collect {
            bytes: &mut bytes,
            first: None,
        };
        let result = source.stream(&mut receiver, &execution).await;
        if let Some(cause) = receiver.first {
            return Err(failure(self, resource(range, cause)));
        }
        result?;
        Ok(bytes.into_owned())
    }
}

struct Collect<'a, W: Work> {
    bytes: &'a mut OwnedVec<u8, W>,
    first: Option<MemoryError>,
}
impl<W: Work> Receiver for Collect<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        if self.first.is_some() {
            return Err(Refused);
        }
        if let Err(cause) = self.bytes.try_extend_from_slice(bytes) {
            self.first = Some(cause);
            return Err(Refused);
        }
        Ok(())
    }
}

fn failure<S: RangeSource>(
    member: &Member<'_, '_, S>,
    cause: Error<S::Error>,
) -> ReadFailure<S::Error, S::Document, S::Generation> {
    ReadFailure::Processing {
        member: member.id(),
        cause,
    }
}

fn check<S: RangeSource, W: Work>(
    archive: &Archive<'_, S>,
    ordinal: usize,
    work: &W,
) -> Acquisition<(), S> {
    let member = Member { archive, ordinal };
    let entry = member.entry();
    archive
        .admit(work, entry.central)
        .map_err(|cause| failure(&member, cause))?;
    if entry.flags & 0x2041 != 0 {
        return Err(failure(
            &member,
            Error::Unsupported {
                range: entry.central,
                kind: Unsupported::Encryption,
            },
        ));
    }
    if entry.method != 0 && entry.method != 8 {
        return Err(failure(
            &member,
            Error::Unsupported {
                range: entry.central,
                kind: Unsupported::Compression(entry.method),
            },
        ));
    }
    if !entry.readable || entry.data.is_none() {
        return Err(ReadFailure::Integrity {
            member: member.id(),
            range: entry.central,
            kind: Integrity::Framing,
        });
    }
    if entry.decoded > archive.session.remaining() {
        return Err(failure(
            &member,
            Error::Limit {
                range: entry.central,
                kind: Limit::Decoded,
            },
        ));
    }
    Ok(())
}

impl<S: RangeSource> AsyncSource for Source<'_, '_, S> {
    type Error = ReadFailure<S::Error, S::Document, S::Generation>;
    fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        work: &'q W,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + 'q {
        acquire(self.archive, self.ordinal, receiver, work)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one streaming transaction keeps inflater progress, cumulative output admission, CRC and exact EOF validation in a single state machine"
)]
async fn acquire<S: RangeSource, W: Work>(
    archive: &Archive<'_, S>,
    ordinal: usize,
    receiver: &mut impl Receiver,
    work: &W,
) -> Result<(), ReadFailure<S::Error, S::Document, S::Generation>> {
    check(archive, ordinal, work)?;
    let member = Member { archive, ordinal };
    let entry = member.entry();
    let range = entry.data.expect("checked original payload");
    let processing = |cause| failure(&member, cause);
    let integrity = |kind| ReadFailure::Integrity {
        member: member.id(),
        range,
        kind,
    };
    let execution = archive.session.query(work);
    let mut window = archive.window(work, range).map_err(processing)?;
    let mut inflater = if entry.method == 8 {
        Some(
            Inflater::new(Envelope::Raw, &execution).map_err(|cause| match cause {
                InflateError::Resource(cause) => processing(resource(range, cause)),
                _ => integrity(Integrity::Compression),
            })?,
        )
    } else {
        None
    };
    let mut crc = crc32fast::Hasher::new();
    let mut at = range.start;
    let mut produced = 0_u64;
    let mut quantum = 0;
    loop {
        let input = window
            .chunk_at(at, range.end())
            .await
            .map_err(|cause| processing(cause.into()))?;
        let output = if let Some(inflater) = &mut inflater {
            let remaining = entry.decoded - produced;
            if quantum == 0 {
                quantum = input.len().clamp(1, 4096);
            }
            let maximum = usize::try_from(
                remaining
                    .min(archive.session.remaining())
                    .min(quantum as u64),
            )
            .expect("bounded decoder allowance");
            let result = inflater.step(input, at + (input.len() as u64) < range.end(), maximum);
            let step = match result {
                Ok(step) => step,
                Err(InflateError::Resource(cause)) => {
                    return Err(processing(resource(range, cause)));
                }
                Err(InflateError::OutputLimit) => {
                    if archive.session.remaining() < remaining {
                        return Err(processing(Error::Limit {
                            range,
                            kind: Limit::Decoded,
                        }));
                    }
                    return Err(integrity(Integrity::Length));
                }
                Err(InflateError::Malformed { produced }) => {
                    archive
                        .session
                        .decode(produced as u64, range)
                        .map_err(processing)?;
                    return Err(integrity(Integrity::Compression));
                }
                Err(InflateError::State) => return Err(integrity(Integrity::Compression)),
            };
            at += step.consumed as u64;
            let done = step.progress == Progress::Done;
            let output = step.output;
            // Short acquisition must not prepay a 4KiB output on every
            // seven-byte input. Expand only when actual output fills the
            // allowance; full-window/high-expansion paths still reach 4KiB.
            quantum = if step.progress == Progress::Output {
                (maximum * 2).clamp(1, 4096)
            } else {
                output.len().max(input.len()).clamp(1, 4096)
            };
            archive
                .session
                .decode(output.len() as u64, range)
                .map_err(processing)?;
            produced += output.len() as u64;
            execution
                .charge_work(output.len() as u64 + 1)
                .map_err(|cause| processing(resource(range, cause)))?;
            crc.update(output);
            if !output.is_empty() {
                receiver.write(output).map_err(ReadFailure::Receiver)?;
            }
            if done {
                if at != range.end() || produced != entry.decoded {
                    return Err(integrity(Integrity::Length));
                }
                break;
            }
            continue;
        } else {
            if at == range.end() {
                break;
            }
            archive
                .session
                .decode(input.len() as u64, range)
                .map_err(processing)?;
            at += input.len() as u64;
            produced += input.len() as u64;
            input
        };
        execution
            .charge_work(output.len() as u64 + 1)
            .map_err(|cause| processing(resource(range, cause)))?;
        crc.update(output);
        receiver.write(output).map_err(ReadFailure::Receiver)?;
    }
    archive.admit(work, range).map_err(processing)?;
    if produced != entry.decoded {
        return Err(integrity(Integrity::Length));
    }
    if crc.finalize() != entry.crc {
        return Err(integrity(Integrity::Crc));
    }
    Ok(())
}
