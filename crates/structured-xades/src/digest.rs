//! Streaming XML digest checks through the caller's selected provider.
//!
//! Execution is the provider's [`structured_asn1::digest::Digest`]
//! implementation; [`DigestProvider`] adds only the XML method resolution and
//! classification. No independent URI dispatcher or implicit backend is
//! selected by this crate.

use crate::binary::{self, BinaryXml, Location};
use crate::certificate::{self, Agreement, DigestProvider};
use crate::xml::{Access, Snapshot};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, Work};
use structured_cms::stream::{self, Sink, Source, StreamError};

/// Original digest method/value selectors, NOT proof of their signed coverage.
/// The enclosing property mechanism supplies its actual source-bound nodes.
#[derive(Debug, Clone, Copy)]
pub struct Reference<N, D, G> {
    /// Original XML document and generation.
    pub snapshot: Snapshot<D, G>,
    /// Original method including untouched parameters.
    pub method: N,
    /// Original base64 digest-value element.
    pub value: N,
}

/// Execution failure stays independent of completed digest agreement.
#[derive(Debug)]
pub enum Error<SE, PE> {
    /// Original complete-source acquisition/replay refusal.
    Source(SE),
    /// Original selected-provider failure, including resource/policy refusal.
    Provider(PE),
    /// Driver metadata admission failed before callback execution.
    Resource(MemoryError),
    /// Existing stream driver refused dispatch. Its location is the virtual
    /// input's start (zero), NOT a physical XML byte or decoded ASN.1 offset;
    /// the outer binary error preserves the actual XML value node/generation.
    Stream(structured_cms::Error),
    /// Backend output contradicts its already resolved fixed width. This is
    /// processing failure, not malformed declared bytes or a normal mismatch.
    OutputWidth {
        /// Fixed resolved width.
        expected: usize,
        /// Actual backend output width.
        actual: usize,
    },
}

struct Updating<'s, 'p, P: Digest<'p>> {
    provider: &'p P,
    state: &'s mut P::State,
}

impl<'p, P: Digest<'p>> Sink for Updating<'_, 'p, P> {
    type Error = P::Error;
    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        self.provider.update(self.state, bytes, execution)
    }
}

/// Resolves the actual XML method, validates declared width before source I/O,
/// then runs one exact source pass through the existing sticky stream driver.
/// No whole-input collector, parser, implicit I/O or runtime crypto dependency
/// is introduced. This produces digest agreement only, never signed coverage,
/// policy-document acceptance, timestamp evidence or an attained B level.
pub fn check<'p, X: BinaryXml, P: DigestProvider<'p, X>, S: Source, W: Work>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, Error<S::Error, P::Error>> {
    check_with(
        xml,
        reference,
        provider,
        execution,
        |identity, expected, work| {
            run_resolved::<P, S, W>(&identity, expected, source, provider, work)
        },
    )
    .map(|reading| match reading {
        Checked::Answer(answer) | Checked::Value(answer) => answer,
    })
}

pub(crate) enum Checked<T> {
    Answer(Agreement),
    Value(T),
}

// Both one-shot source checking and complete material-catalogue checking use
// this one method/declared-value kernel. Memoization cannot bypass syntax,
// width or actual resolved-algorithm classification before provider effects.
pub(crate) fn check_with<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work, SE, R>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    provider: &'p P,
    execution: &W,
    visit: impl FnOnce(
        certificate::FormatDigest<P::Identity>,
        &[u8],
        &W,
    ) -> Result<R, Error<SE, P::Error>>,
) -> binary::BinaryResult<Checked<R>, X, Error<SE, P::Error>> {
    let access = Access::new(xml, reference.snapshot, execution);
    let method = Location {
        snapshot: reference.snapshot,
        node: reference.method,
    };
    if let Some(answer) =
        certificate::preflight_method(&access, reference.method).map_err(|cause| {
            binary::Error::Access {
                location: method,
                cause,
            }
        })?
    {
        return Ok(Checked::Answer(answer));
    }
    binary::with_octets(
        xml,
        Location {
            snapshot: reference.snapshot,
            node: reference.value,
        },
        execution,
        |expected| {
            Ok::<_, core::convert::Infallible>(check_expected(
                &access, reference, expected, provider, visit,
            ))
        },
    )
    .map_err(|error| error.map_callback(|never| match never {}))?
}

fn check_expected<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work, SE, R>(
    access: &Access<'_, X, W>,
    reference: Reference<X::Id, X::Document, X::Generation>,
    expected: &[u8],
    provider: &'p P,
    visit: impl FnOnce(
        certificate::FormatDigest<P::Identity>,
        &[u8],
        &W,
    ) -> Result<R, Error<SE, P::Error>>,
) -> binary::BinaryResult<Checked<R>, X, Error<SE, P::Error>> {
    let execution = access.execution();
    let method = Location {
        snapshot: reference.snapshot,
        node: reference.method,
    };
    let resolved = access
        .query(reference.method, |_, _, _| {
            Ok(provider.resolve(access, reference.method))
        })
        .map_err(|cause| binary::Error::Access {
            location: method,
            cause,
        })?
        .map_err(|cause| binary::Error::Callback {
            location: method,
            cause: Error::Provider(cause),
        })?;
    let identity = match resolved {
        Resolution::Supported(identity) => identity,
        Resolution::Unsupported => return Ok(Checked::Answer(Agreement::Unsupported)),
        Resolution::Malformed => return Ok(Checked::Answer(Agreement::MalformedMethod)),
    };
    let identity = match certificate::baseline_digest::<X, P>(identity, provider) {
        certificate::Expected::Ready(identity) => identity,
        certificate::Expected::Answer(answer) => return Ok(Checked::Answer(answer)),
    };
    if let Some(width) = provider.width(identity.identity())
        && expected.len() != width
    {
        return Ok(Checked::Answer(Agreement::MalformedValue));
    }
    visit(identity, expected, execution)
        .map(Checked::Value)
        .map_err(|cause| binary::Error::Callback {
            location: Location {
                snapshot: reference.snapshot,
                node: reference.value,
            },
            cause,
        })
}

pub(crate) fn run_resolved<'p, P: Digest<'p>, S: Source, W: Work>(
    identity: &certificate::FormatDigest<P::Identity>,
    expected: &[u8],
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> Result<Agreement, Error<S::Error, P::Error>> {
    let width = provider.width(identity.identity());
    if let Some(width) = width
        && expected.len() != width
    {
        return Ok(Agreement::MalformedValue);
    }
    let output = match compute_resolved::<P, S, W>(identity, source, provider, execution)? {
        Resolution::Supported(output) => output,
        Resolution::Unsupported => return Ok(Agreement::Unsupported),
        Resolution::Malformed => return Ok(Agreement::MalformedMethod),
    };
    execution.charge_work(1).map_err(Error::Resource)?;
    let agrees = provider
        .matches(identity.identity(), &output, expected, execution)
        .map_err(Error::Provider)?;
    Ok(if agrees {
        Agreement::Matches
    } else {
        Agreement::Differs
    })
}

type Computation<O, SE, PE> = Result<Resolution<O>, Error<SE, PE>>;

pub(crate) fn compute_resolved<'p, P: Digest<'p>, S: Source, W: Work>(
    identity: &certificate::FormatDigest<P::Identity>,
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> Computation<P::Output, S::Error, P::Error> {
    let width = provider.width(identity.identity());
    execution.charge_work(1).map_err(Error::Resource)?;
    let mut state = match provider
        .start(identity.identity(), execution)
        .map_err(Error::Provider)?
    {
        Resolution::Supported(state) => state,
        Resolution::Unsupported => return Ok(Resolution::Unsupported),
        Resolution::Malformed => return Ok(Resolution::Malformed),
    };
    let mut updating = Updating::<P> {
        provider,
        state: &mut state,
    };
    match stream::run(source, &mut updating, execution, "xades.digestInput", 0) {
        Ok(()) => {}
        Err(StreamError::Source(cause)) => return Err(Error::Source(cause)),
        Err(StreamError::Callback(cause)) => return Err(Error::Provider(cause)),
        Err(StreamError::Processing(cause)) => return Err(Error::Stream(cause)),
    }
    execution.charge_work(1).map_err(Error::Resource)?;
    let output = provider.finish(state, execution).map_err(Error::Provider)?;
    if let Some(expected) = width
        && output.as_ref().len() != expected
    {
        return Err(Error::OutputWidth {
            expected,
            actual: output.as_ref().len(),
        });
    }
    Ok(Resolution::Supported(output))
}
