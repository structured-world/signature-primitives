//! One payload pass with sticky source, callback and resource refusal.

use crate::Error;
use structured_asn1::memory::Work;

/// A write refusal whose original cause remains held by the stream driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// A source-facing chunk receiver.
pub trait Receiver {
    /// Delivers the next complete chunk in logical order.
    ///
    /// On refusal the source must stop. The driver additionally enforces sticky
    /// refusal if a source ignores this marker, without cloning the cause.
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), Refused>;
}

/// Caller-supplied payload acquisition; successful return denotes complete EOF.
///
/// Acquisition must admit its own data-dependent work/storage before execution
/// through the supplied domain. This trait neither fetches document references
/// nor proves accounting inside arbitrary caller code.
pub trait Source {
    /// The original acquisition failure, distinct from a signature mismatch.
    type Error;

    /// Feeds every chunk once, returning an error for an incomplete source.
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> core::result::Result<(), Self::Error>;
}

/// Complete payload acquisition that may suspend between bounded chunks.
/// The same sticky receiver and cause precedence govern synchronous sources.
/// No executor, heap allocation, `Send` bound or blocking adapter is required.
pub trait AsyncSource {
    /// Original acquisition failure, distinct from callback refusal.
    type Error;

    /// Feeds every chunk once and returns success only after complete EOF.
    fn stream<'q, W: Work + 'q, R: Receiver + 'q>(
        &'q mut self,
        receiver: &'q mut R,
        execution: &'q W,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + 'q;
}

/// Feeds original ranges, including the SET tag and original signedAttrs
/// remainder returned by [`crate::attribute::Attributes::signed_bytes`].
/// No concatenation or canonical re-encoding occurs; each metadata step is
/// admitted in the current operation before dispatch.
impl<const N: usize> Source for [&[u8]; N] {
    type Error = RangesError;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Self::Error> {
        for bytes in self.iter() {
            execution.charge_work(1).map_err(RangesError::Resource)?;
            receiver.write(bytes).map_err(RangesError::Receiver)?;
        }
        Ok(())
    }
}

/// Range acquisition has no ASN.1 source location of its own.
#[derive(Debug)]
pub enum RangesError {
    /// Current work admission failed before walking a range.
    Resource(structured_asn1::memory::MemoryError),
    /// The driver holds the original sink refusal.
    Receiver(Refused),
}

/// An injected processing sink, such as a set of digest/raw verification states.
pub trait Sink {
    /// The callback's original failure, preserving provider/resource provenance.
    type Error;

    /// Processes a chunk after admitting its complete transitive operation.
    ///
    /// The driver pays dispatch; the callback pays actual hashing, copying,
    /// opaque state growth and fan-out before execution. No Clone/Send/Sync
    /// bound or particular cryptographic engine is required.
    fn write<W: Work>(
        &mut self,
        bytes: &[u8],
        execution: &W,
    ) -> core::result::Result<(), Self::Error>;
}

/// Why a payload pass could not finish.
#[derive(Debug)]
pub enum StreamError<SE, CE> {
    /// The source did not reach successful EOF.
    Source(SE),
    /// A sink callback refused, with its original cause.
    Callback(CE),
    /// Common processing refused resources before dispatch.
    Processing(Error),
}

enum Failure<E> {
    Callback(E),
    Processing(Error),
}

struct Guard<'a, S: Sink, W: Work> {
    sink: &'a mut S,
    execution: &'a W,
    field: &'static str,
    at: u64,
    failure: Option<Failure<S::Error>>,
}

impl<S: Sink, W: Work> Receiver for Guard<'_, S, W> {
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), Refused> {
        if self.failure.is_some() {
            return Err(Refused);
        }
        if let Err(reason) = self.execution.charge_work(1) {
            self.failure = Some(Failure::Processing(Error::resource(
                reason, self.field, self.at,
            )));
            return Err(Refused);
        }
        if let Err(error) = self.sink.write(bytes, self.execution) {
            self.failure = Some(Failure::Callback(error));
            return Err(Refused);
        }
        Ok(())
    }
}

/// Feeds one source once and preserves the first sink refusal without cloning.
///
/// `field`/`at` locate processing in the caller's enclosing structure; they do
/// not invent an ASN.1 position for detached bytes. A callback refusal takes
/// precedence over a later source failure caused by that refusal. A partial
/// source never returns success, even if a prefix reached the sink.
pub fn run<S: Source, C: Sink, W: Work>(
    source: &mut S,
    sink: &mut C,
    execution: &W,
    field: &'static str,
    at: u64,
) -> core::result::Result<(), StreamError<S::Error, C::Error>> {
    execution
        .charge_work(1)
        .map_err(|reason| StreamError::Processing(Error::resource(reason, field, at)))?;
    let mut guard = Guard {
        sink,
        execution,
        field,
        at,
        failure: None,
    };
    let acquired = source.stream(&mut guard, execution);
    match guard.failure {
        Some(Failure::Callback(error)) => Err(StreamError::Callback(error)),
        Some(Failure::Processing(error)) => Err(StreamError::Processing(error)),
        None => acquired.map_err(StreamError::Source),
    }
}

/// Suspends source acquisition while preserving the same sticky callback
/// refusal, admission order and complete-EOF boundary as [`run`]. Dropping the
/// future drops the borrowed driver, without producing a partial receipt.
pub async fn run_async<S: AsyncSource, C: Sink, W: Work>(
    source: &mut S,
    sink: &mut C,
    execution: &W,
    field: &'static str,
    at: u64,
) -> Result<(), StreamError<S::Error, C::Error>> {
    execution
        .charge_work(1)
        .map_err(|cause| StreamError::Processing(Error::resource(cause, field, at)))?;
    let mut guard = Guard {
        sink,
        execution,
        field,
        at,
        failure: None,
    };
    let acquired = source.stream(&mut guard, execution).await;
    match guard.failure {
        Some(Failure::Callback(error)) => Err(StreamError::Callback(error)),
        Some(Failure::Processing(error)) => Err(StreamError::Processing(error)),
        None => acquired.map_err(StreamError::Source),
    }
}
