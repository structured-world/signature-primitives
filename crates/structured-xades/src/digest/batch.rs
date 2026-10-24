//! Shared native digest fan-out over already prepared XML declarations.

use super::{
    Access, Agreement, Digest, Error, Location, OwnedVec, Prepared, PreparedValue, Reference,
    StreamError, Work, Xml, binary, compare_resolved_finished, stream,
};
use structured_cms::digest::{DigestBatch, DigestError};

enum Value {
    Answer(Agreement),
    Request {
        ordinal: usize,
        expected: OwnedVec<u8>,
    },
}
struct Declared<N, D, G> {
    reference: Reference<N, D, G>,
    value: Value,
}

/// One source pass for multiple original XML declarations. Complete native
/// identities move into the existing common batch, which sorts/deduplicates
/// them semantically. No identity/state/output clone or second dispatcher.
pub struct Batch<'p, P: Digest<'p>, N, D, G> {
    provider: &'p P,
    declarations: OwnedVec<Declared<N, D, G>>,
    native: Option<DigestBatch<'p, P>>,
}

fn map_error<SE, PE>(cause: DigestError<PE>) -> Error<SE, PE> {
    match cause {
        DigestError::Processing(cause) => Error::Stream(cause),
        DigestError::Callback(cause) => Error::Provider(cause),
        DigestError::OutputWidth { expected, actual } => Error::OutputWidth { expected, actual },
        DigestError::Unstreamable => Error::Unstreamable,
    }
}

impl<'p, P: Digest<'p>, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq> Batch<'p, P, N, D, G> {
    /// Consumes declarations whose original XML syntax, widths and provider
    /// policy have ALREADY been checked. Do not prepare a subset and start it
    /// before validating other declarations in the same operation.
    pub fn prepare<W: Work>(
        provider: &'p P,
        prepared: OwnedVec<Prepared<'p, P, N, D, G>>,
        work: &W,
    ) -> Result<Self, Error<core::convert::Infallible, P::Error>> {
        let mut identities = work.vector();
        let mut declarations = work.vector();
        identities
            .try_reserve_exact(prepared.len())
            .map_err(Error::Resource)?;
        declarations
            .try_reserve_exact(prepared.len())
            .map_err(Error::Resource)?;
        work.charge_work(core::mem::size_of_val(&*prepared) as u64)
            .map_err(Error::Resource)?;
        for prepared in prepared {
            if !core::ptr::eq(prepared.provider, provider) {
                return Err(Error::ForeignDigest);
            }
            let value = match prepared.value {
                PreparedValue::Answer(answer) => Value::Answer(answer),
                PreparedValue::Ready { identity, expected } => {
                    let ordinal = identities.len();
                    identities.try_push(identity).map_err(Error::Resource)?;
                    Value::Request { ordinal, expected }
                }
            };
            declarations
                .try_push(Declared {
                    reference: prepared.reference,
                    value,
                })
                .map_err(Error::Resource)?;
        }
        let batch = if identities.is_empty() {
            None
        } else {
            Some(
                DigestBatch::prepare(
                    provider,
                    identities.into_owned(),
                    work,
                    "xml.digest.batch",
                    0,
                )
                .map_err(map_error)?,
            )
        };
        Ok(Self {
            provider,
            declarations: declarations.into_owned(),
            native: batch,
        })
    }

    /// Checks original generations before source I/O and after await. Only the
    /// exact private request mapping supplies each actual output/identity. All
    /// declarations survive, including unsupported/malformed readings; a failed
    /// source or callback returns no successful partial answer collection.
    ///
    /// # Panics
    /// An internal preparation invariant fails if a ready declaration lacks
    /// its original native batch or private request-to-output mapping.
    pub async fn run<
        X: Xml<Id = N, Document = D, Generation = G>,
        S: stream::AsyncSource,
        W: Work,
    >(
        self,
        xml: &X,
        source: &mut S,
        work: &W,
    ) -> binary::BinaryResult<OwnedVec<Agreement>, X, Error<S::Error, P::Error>> {
        let mut answers = work.vector();
        for declared in &self.declarations {
            let location = Location {
                snapshot: declared.reference.snapshot,
                node: declared.reference.value,
            };
            Access::new(xml, location.snapshot, work)
                .inspect(location.node, |_| ())
                .map_err(|cause| binary::Error::Access { location, cause })?;
        }
        let Some(first) = self.declarations.first() else {
            return Ok(answers.into_owned());
        };
        let location = Location {
            snapshot: first.reference.snapshot,
            node: first.reference.value,
        };
        answers
            .try_reserve_exact(self.declarations.len())
            .map_err(|cause| binary::Error::Callback {
                location,
                cause: Error::Resource(cause),
            })?;
        let memo = match self.native {
            Some(batch) => Some(batch.run_async(source, work).await.map_err(|cause| {
                binary::Error::Callback {
                    location,
                    cause: match cause {
                        StreamError::Source(cause) => Error::Source(cause),
                        StreamError::Callback(cause) => map_error(cause),
                        StreamError::Processing(cause) => Error::Stream(cause),
                    },
                }
            })?),
            None => None,
        };
        for declared in self.declarations {
            let access = Access::new(xml, declared.reference.snapshot, work);
            let location = Location {
                snapshot: declared.reference.snapshot,
                node: declared.reference.value,
            };
            access
                .inspect(location.node, |_| ())
                .map_err(|cause| binary::Error::Access { location, cause })?;
            let answer = match declared.value {
                Value::Answer(answer) => answer,
                Value::Request { ordinal, expected } => {
                    let actual = memo
                        .as_ref()
                        .expect("ready declarations initialize their private batch")
                        .for_request(ordinal, work)
                        .map_err(|cause| binary::Error::Callback {
                            location,
                            cause: map_error(cause),
                        })?
                        .expect("each ready declaration has the original private request mapping");
                    // Its identity was MOVED from this exact prepared declaration
                    // into this mapping. No separately supplied identity or width
                    // can manufacture this pairing, including equal-width hashes.
                    compare_resolved_finished(
                        &access,
                        declared.reference,
                        self.provider,
                        actual.identity(),
                        actual.finished(),
                        &expected,
                    )
                    .map_err(|cause| {
                        cause.map_callback(|cause| cause.map_source(|never| match never {}))
                    })?
                }
            };
            answers
                .try_push(answer)
                .map_err(|cause| binary::Error::Callback {
                    location,
                    cause: Error::Resource(cause),
                })?;
        }
        Ok(answers.into_owned())
    }
}
