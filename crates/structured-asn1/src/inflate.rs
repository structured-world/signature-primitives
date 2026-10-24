//! Funded, bounded raw-DEFLATE/zlib streaming over caller-supplied chunks.

use crate::memory::{MemoryError, OwnedVec, Work};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress_with_limit, inflate_flags};

/// The format's declared compression envelope, never guessed from payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Envelope {
    /// RFC 1951, used by ZIP method 8.
    Raw,
    /// RFC 1950, used by PDF `FlateDecode`.
    Zlib,
}

/// Progress of the same incremental decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// A complete block ended; the next block needs its own admission.
    Block,
    /// More original compressed input is required.
    Input,
    /// Further output can be emitted from the same bounded input.
    Output,
    /// The compression envelope completed successfully.
    Done,
}

/// One bounded borrowed decoded output, valid until the next mutable step.
pub struct Step<'a> {
    /// Compressed bytes consumed from this call's supplied prefix.
    pub consumed: usize,
    /// Newly decoded bytes, without copying the dictionary into another buffer.
    pub output: &'a [u8],
    /// Exact decoder progress, independent of syntax or resource refusal.
    pub progress: Progress,
}

/// Decoder failure, without a fabricated source location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Original source/current work or actual-capacity refusal.
    Resource(MemoryError),
    /// The format's permitted decoded output is exhausted before the next byte.
    OutputLimit,
    /// Invalid or truncated compression syntax.
    Malformed {
        /// Bytes written before syntax/checksum failure in this step. They
        /// are not returned, but still count against aggregate decode limits.
        produced: usize,
    },
    /// The caller attempted to resume a completed or failed decoder.
    State,
}

const CHUNK: usize = 4096;
const DICTIONARY: usize = 32768;

/// One actual-capacity-owned decoder and dictionary under the supplied work.
/// No opaque heap allocation, recursive traversal or engine dispatch occurs.
pub struct Inflater<W: Work> {
    state: OwnedVec<DecompressorOxide, W>,
    bytes: OwnedVec<u8, W>,
    envelope: Envelope,
    at: usize,
    block: bool,
    stopped: bool,
}

impl<W: Work> Inflater<W> {
    /// Admits actual storage and initialization before constructing decoder state.
    pub fn new(envelope: Envelope, work: &W) -> Result<Self, Error> {
        let mut inflater = work.vector();
        inflater.try_reserve_exact(1).map_err(Error::Resource)?;
        work.charge_work(core::mem::size_of::<DecompressorOxide>() as u64)
            .map_err(Error::Resource)?;
        inflater
            .try_push(DecompressorOxide::new())
            .map_err(Error::Resource)?;
        let mut bytes = work.vector();
        bytes
            .try_reserve_exact(DICTIONARY)
            .map_err(Error::Resource)?;
        for _ in 0..DICTIONARY / CHUNK {
            bytes
                .try_extend_from_slice(&[0_u8; CHUNK])
                .map_err(Error::Resource)?;
        }
        Ok(Self {
            state: inflater,
            bytes,
            envelope,
            at: 0,
            block: true,
            stopped: false,
        })
    }

    /// Maximum output of the next step. A format may reserve its destination
    /// before decoding; this does not consume input or admit a wider limit.
    #[must_use]
    pub fn output_capacity(&self, maximum: usize) -> usize {
        CHUNK.min(DICTIONARY - self.at).min(maximum)
    }

    /// Consumes at most 4096 compressed bytes and produces at most 4096 bytes.
    /// `more_input` describes bytes after the supplied slice, not after the
    /// bounded prefix chosen internally. `maximum` is the format's remaining
    /// decoded allowance, applied before the decoder can write another byte.
    ///
    /// Failure is sticky. Success does not prove the enclosing file's CRC,
    /// declared extent, signature or that no compressed trailing bytes remain.
    pub fn step<'a>(
        &'a mut self,
        input: &[u8],
        more_input: bool,
        maximum: usize,
    ) -> Result<Step<'a>, Error> {
        if self.stopped {
            return Err(Error::State);
        }
        self.stopped = true;
        if self.block {
            // miniz 0.9.1 init_tree: three alphabets, <=15 bits/code,
            // 1024 lookup and 576 tree slots/table. STOP_ON_BLOCK_BOUNDARY
            // prevents a second setup before the next explicit admission.
            self.bytes
                .work()
                .charge_work(3 * (1024 + 576 + 288 * 16 + 32))
                .map_err(Error::Resource)?;
            self.block = false;
        }
        let count = input.len().min(CHUNK);
        let allowance = self.output_capacity(maximum);
        self.bytes
            .work()
            .charge_work(count as u64 * 16 + allowance as u64 * 16 + 1)
            .map_err(Error::Resource)?;
        let mut flags = inflate_flags::TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY;
        if self.envelope == Envelope::Zlib {
            flags |= inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER;
        }
        if more_input || count < input.len() {
            flags |= inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
        }
        let (status, consumed, written) = decompress_with_limit(
            &mut self.state[0],
            &input[..count],
            &mut self.bytes,
            self.at,
            allowance,
            flags,
        );
        let progress = match status {
            TINFLStatus::Done => Progress::Done,
            TINFLStatus::BlockBoundary => {
                self.block = true;
                Progress::Block
            }
            TINFLStatus::NeedsMoreInput if more_input || count < input.len() => Progress::Input,
            TINFLStatus::HasMoreOutput if written != 0 => Progress::Output,
            TINFLStatus::HasMoreOutput if allowance == 0 => return Err(Error::OutputLimit),
            _ => return Err(Error::Malformed { produced: written }),
        };
        let start = self.at;
        self.at = (self.at + written) % DICTIONARY;
        self.stopped = progress == Progress::Done;
        Ok(Step {
            consumed,
            output: &self.bytes[start..start + written],
            progress,
        })
    }
}

#[cfg(test)]
mod tests;
