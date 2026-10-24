//! Streaming XML digest checks through the caller's selected provider.
//!
//! Execution is the provider's [`structured_asn1::digest::Digest`]
//! implementation; [`DigestProvider`] adds only the XML method resolution and
//! classification. No independent URI dispatcher or implicit backend is
//! selected by this crate.

use crate::binary::{self, BinaryXml, Location, OwnedBinaryXml};
use crate::certificate::{self, Agreement, DigestProvider};
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_cms::stream::{self, Sink, Source, StreamError};

mod batch;
pub use batch::Batch;

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
    /// A prepared XML method was paired with another provider's output.
    ForeignDigest,
    /// The provider resolved an identity but cannot stream its digest state.
    Unstreamable,
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

impl<SE, PE> Error<SE, PE> {
    /// Translates only acquisition causes, preserving provider, processing and
    /// resource classifications without replacing their original locations.
    pub fn map_source<E>(self, map: impl FnOnce(SE) -> E) -> Error<E, PE> {
        match self {
            Self::ForeignDigest => Error::ForeignDigest,
            Self::Unstreamable => Error::Unstreamable,
            Self::Source(cause) => Error::Source(map(cause)),
            Self::Provider(cause) => Error::Provider(cause),
            Self::Resource(cause) => Error::Resource(cause),
            Self::Stream(cause) => Error::Stream(cause),
            Self::OutputWidth { expected, actual } => Error::OutputWidth { expected, actual },
        }
    }
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

/// Same method/width/algorithm checks over a source that may suspend. The XML
/// owner moves its funded decoded value into this scope rather than copying a
/// callback-local digest into a second allocation before awaiting input.
pub async fn check_async<'p, X: OwnedBinaryXml, P: DigestProvider<'p, X>, S, W: Work>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, Error<S::Error, P::Error>>
where
    S: stream::AsyncSource,
{
    check_async_with::<true, X, P, S, W>(xml, reference, source, provider, execution).await
}

/// `XMLDSig` digest checking without selecting an `XAdES` baseline profile. The
/// format using this result supplies its own profile requirements; selected
/// provider algorithm/policy validation is still mandatory before source I/O.
pub async fn check_xml_async<'p, X: OwnedBinaryXml, P: DigestProvider<'p, X>, S, W: Work>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, Error<S::Error, P::Error>>
where
    S: stream::AsyncSource,
{
    check_async_with::<false, X, P, S, W>(xml, reference, source, provider, execution).await
}

/// Compares an original XML method/value with an actual already completed
/// common digest. Full semantic identity must agree before output comparison;
/// output width or matching bytes alone cannot establish that association.
/// The actual output supplies its own provider. No state, output or identity
/// is cloned, no resolver is replaced and no source is hashed again.
/// This general XML path does not select an `XAdES` baseline algorithm policy.
pub fn check_xml_finished<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    actual: structured_cms::provider::Finished<'_, P, P::Identity, P::Output>,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, Error<core::convert::Infallible, P::Error>> {
    let access = Access::new(xml, reference.snapshot, execution);
    if let Some(answer) = preflight(&access, reference)? {
        return Ok(answer);
    }
    let location = Location {
        snapshot: reference.snapshot,
        node: reference.value,
    };
    binary::with_octets(xml, location, execution, |expected| {
        Ok::<_, core::convert::Infallible>(compare_finished(&access, reference, actual, expected))
    })
    .map_err(|error| error.map_callback(|never| match never {}))?
}

fn compare_finished<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    reference: Reference<X::Id, X::Document, X::Generation>,
    actual: structured_cms::provider::Finished<'_, P, P::Identity, P::Output>,
    expected: &[u8],
) -> binary::BinaryResult<Agreement, X, Error<core::convert::Infallible, P::Error>> {
    let provider = actual.provider();
    let identity = match resolve_method(access, reference, provider)? {
        Resolution::Supported(identity) => identity,
        Resolution::Unsupported => return Ok(Agreement::Unsupported),
        Resolution::Malformed => return Ok(Agreement::MalformedMethod),
    };
    let identity = match certificate::resolved_digest::<false, X, P>(identity, provider) {
        Ok(identity) => identity,
        Err(answer) => return Ok(answer),
    };
    compare_resolved_finished(access, reference, provider, &identity, actual, expected)
}

fn compare_resolved_finished<'p, X: Xml, P: Digest<'p>, W: Work>(
    access: &Access<'_, X, W>,
    reference: Reference<X::Id, X::Document, X::Generation>,
    provider: &P,
    identity: &P::Identity,
    actual: structured_cms::provider::Finished<'_, P, P::Identity, P::Output>,
    expected: &[u8],
) -> binary::BinaryResult<Agreement, X, Error<core::convert::Infallible, P::Error>> {
    let width = provider.width(identity);
    if let Some(width) = width
        && expected.len() != width
    {
        return Ok(Agreement::MalformedValue);
    }
    let location = Location {
        snapshot: reference.snapshot,
        node: reference.value,
    };
    access
        .query_fallible(reference.value, |_, _, work| {
            work.charge_work(1).map_err(Error::Resource)?;
            if provider
                .compare(identity, actual.identity(), work)
                .map_err(Error::Provider)?
                != core::cmp::Ordering::Equal
            {
                return Ok(Agreement::Differs);
            }
            if let Some(width) = width
                && actual.output().as_ref().len() != width
            {
                return Err(Error::OutputWidth {
                    expected: width,
                    actual: actual.output().as_ref().len(),
                });
            }
            let agrees = provider
                .matches(identity, actual.output(), expected, work)
                .map_err(Error::Provider)?;
            Ok(if agrees {
                Agreement::Matches
            } else {
                Agreement::Differs
            })
        })
        .map_err(|cause| match cause {
            crate::xml::AccessError::Xml(cause) => binary::Error::Callback { location, cause },
            crate::xml::AccessError::Changed { node } => binary::Error::Access {
                location,
                cause: crate::xml::AccessError::Changed { node },
            },
            crate::xml::AccessError::Resource { node, cause } => binary::Error::Access {
                location,
                cause: crate::xml::AccessError::Resource { node, cause },
            },
        })
}

enum PreparedValue<I> {
    Answer(Agreement),
    Ready { identity: I, expected: OwnedVec<u8> },
}

/// Original XML method/value admitted and resolved before asynchronous input
/// or provider state creation. Only the declared digest bytes are retained;
/// this is not a finished digest or evidence of signed coverage.
pub struct Prepared<'p, P: Digest<'p>, N, D, G> {
    provider: &'p P,
    reference: Reference<N, D, G>,
    value: PreparedValue<P::Identity>,
}

/// Resolves and checks an original general XML digest instruction before a
/// separate shared all-algorithm pass. Malformed/unsupported readings remain
/// values; XML, policy and resource refusals remain terminal original causes.
/// Baseline algorithm restrictions belong to the enclosing profile.
pub type PreparationResult<'p, P, X> = binary::BinaryResult<
    Prepared<'p, P, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    Error<core::convert::Infallible, <P as Digest<'p>>::Error>,
>;

/// Checks original syntax and provider policy before creating digest state.
pub fn prepare_xml<'p, X: OwnedBinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    provider: &'p P,
    execution: &W,
) -> PreparationResult<'p, P, X> {
    let access = Access::new(xml, reference.snapshot, execution);
    let value = if let Some(answer) = preflight(&access, reference)? {
        PreparedValue::Answer(answer)
    } else {
        match resolve_method(&access, reference, provider)? {
            Resolution::Unsupported => PreparedValue::Answer(Agreement::Unsupported),
            Resolution::Malformed => PreparedValue::Answer(Agreement::MalformedMethod),
            Resolution::Supported(identity) => {
                match certificate::resolved_digest::<false, X, P>(identity, provider) {
                    Err(answer) => PreparedValue::Answer(answer),
                    Ok(identity) => {
                        let location = Location {
                            snapshot: reference.snapshot,
                            node: reference.value,
                        };
                        let expected = binary::owned(xml, location, execution)
                            .map_err(|cause| binary::Error::Access { location, cause })?
                            .value;
                        if let Some(width) = provider.width(&identity)
                            && expected.len() != width
                        {
                            PreparedValue::Answer(Agreement::MalformedValue)
                        } else {
                            PreparedValue::Ready { identity, expected }
                        }
                    }
                }
            }
        }
    };
    Ok(Prepared {
        provider,
        reference,
        value,
    })
}

impl<'p, P: Digest<'p>, N: Copy + Eq, D: Copy + Eq, G: Copy + Eq> Prepared<'p, P, N, D, G> {
    /// Compares the actual completed shared output without another XML decode,
    /// method resolution, hash state, source pass or identity/output clone.
    /// Reusing a stale XML generation or another provider is processing refusal.
    pub fn check_finished<X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &self,
        xml: &X,
        actual: structured_cms::provider::Finished<'_, P, P::Identity, P::Output>,
        execution: &W,
    ) -> binary::BinaryResult<Agreement, X, Error<core::convert::Infallible, P::Error>> {
        let access = Access::new(xml, self.reference.snapshot, execution);
        let location = Location {
            snapshot: self.reference.snapshot,
            node: self.reference.value,
        };
        access
            .inspect(self.reference.value, |_| ())
            .map_err(|cause| binary::Error::Access { location, cause })?;
        if !actual.from_provider(self.provider) {
            return Err(binary::Error::Callback {
                location,
                cause: Error::ForeignDigest,
            });
        }
        match &self.value {
            PreparedValue::Answer(answer) => Ok(*answer),
            PreparedValue::Ready { identity, expected } => compare_resolved_finished(
                &access,
                self.reference,
                self.provider,
                identity,
                actual,
                expected,
            ),
        }
    }
}

async fn check_async_with<
    'p,
    const BASELINE: bool,
    X: OwnedBinaryXml,
    P: DigestProvider<'p, X>,
    S: stream::AsyncSource,
    W: Work,
>(
    xml: &X,
    reference: Reference<X::Id, X::Document, X::Generation>,
    source: &mut S,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, Error<S::Error, P::Error>> {
    let access = Access::new(xml, reference.snapshot, execution);
    if let Some(answer) = preflight::<X, W, S::Error, P::Error>(&access, reference)? {
        return Ok(answer);
    }
    let location = Location {
        snapshot: reference.snapshot,
        node: reference.value,
    };
    let expected = access
        .query(reference.value, |xml, snapshot, work| {
            xml.decode_owned(snapshot, reference.value, work)
        })
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let identity = match resolve_method(&access, reference, provider)? {
        Resolution::Supported(identity) => identity,
        Resolution::Unsupported => return Ok(Agreement::Unsupported),
        Resolution::Malformed => return Ok(Agreement::MalformedMethod),
    };
    let identity = match certificate::resolved_digest::<BASELINE, X, P>(identity, provider) {
        Ok(identity) => identity,
        Err(answer) => return Ok(answer),
    };
    let width = provider.width(&identity);
    if let Some(width) = width
        && expected.len() != width
    {
        return Ok(Agreement::MalformedValue);
    }
    let state = match start_resolved::<P, W, S::Error>(&identity, provider, execution)
        .map_err(|cause| binary::Error::Callback { location, cause })?
    {
        Resolution::Supported(state) => state,
        Resolution::Unsupported => return Ok(Agreement::Unsupported),
        Resolution::Malformed => return Ok(Agreement::MalformedMethod),
    };
    let mut state = state;
    let mut updating = Updating::<P> {
        provider,
        state: &mut state,
    };
    let result = stream::run_async(source, &mut updating, execution, "xades.digestInput", 0).await;
    stream_result(result).map_err(|cause| binary::Error::Callback { location, cause })?;
    // External acquisition may suspend while the XML owner changes generation.
    // Fence finalization/comparison with the same original-node query kernel;
    // failed source/provider causes retain precedence over a later guard.
    access
        .query_fallible(reference.value, |_, _, work| {
            let output = finish_resolved(width, state, provider, work)?;
            let agrees = provider
                .matches(&identity, &output, &expected, work)
                .map_err(Error::Provider)?;
            Ok(if agrees {
                Agreement::Matches
            } else {
                Agreement::Differs
            })
        })
        .map_err(|cause| match cause {
            crate::xml::AccessError::Xml(cause) => binary::Error::Callback { location, cause },
            crate::xml::AccessError::Changed { node } => binary::Error::Access {
                location,
                cause: crate::xml::AccessError::Changed { node },
            },
            crate::xml::AccessError::Resource { node, cause } => binary::Error::Access {
                location,
                cause: crate::xml::AccessError::Resource { node, cause },
            },
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
    if let Some(answer) = preflight(&access, reference)? {
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

fn preflight<X: BinaryXml, W: Work, SE, PE>(
    access: &Access<'_, X, W>,
    reference: Reference<X::Id, X::Document, X::Generation>,
) -> binary::BinaryResult<Option<Agreement>, X, Error<SE, PE>> {
    certificate::preflight_method(access, reference.method).map_err(|cause| binary::Error::Access {
        location: Location {
            snapshot: reference.snapshot,
            node: reference.method,
        },
        cause,
    })
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
    let resolved = resolve_method(access, reference, provider)?;
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

fn resolve_method<'p, X: Xml, P: DigestProvider<'p, X>, W: Work, SE>(
    access: &Access<'_, X, W>,
    reference: Reference<X::Id, X::Document, X::Generation>,
    provider: &P,
) -> binary::BinaryResult<Resolution<P::Identity>, X, Error<SE, P::Error>> {
    let location = Location {
        snapshot: reference.snapshot,
        node: reference.method,
    };
    access
        .query(reference.method, |_, _, _| {
            Ok(provider.resolve(access, reference.method))
        })
        .map_err(|cause| binary::Error::Access { location, cause })?
        .map_err(|cause| binary::Error::Callback {
            location,
            cause: Error::Provider(cause),
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
    let mut state =
        match start_resolved::<P, W, S::Error>(identity.identity(), provider, execution)? {
            Resolution::Supported(state) => state,
            Resolution::Unsupported => return Ok(Resolution::Unsupported),
            Resolution::Malformed => return Ok(Resolution::Malformed),
        };
    let mut updating = Updating::<P> {
        provider,
        state: &mut state,
    };
    stream_result(stream::run(
        source,
        &mut updating,
        execution,
        "xades.digestInput",
        0,
    ))?;
    finish_resolved(width, state, provider, execution).map(Resolution::Supported)
}

fn stream_result<SE, PE>(result: Result<(), StreamError<SE, PE>>) -> Result<(), Error<SE, PE>> {
    match result {
        Ok(()) => {}
        Err(StreamError::Source(cause)) => return Err(Error::Source(cause)),
        Err(StreamError::Callback(cause)) => return Err(Error::Provider(cause)),
        Err(StreamError::Processing(cause)) => return Err(Error::Stream(cause)),
    }
    Ok(())
}

fn start_resolved<'p, P: Digest<'p>, W: Work, SE>(
    identity: &P::Identity,
    provider: &'p P,
    execution: &W,
) -> Result<Resolution<P::State>, Error<SE, P::Error>> {
    execution.charge_work(1).map_err(Error::Resource)?;
    provider.start(identity, execution).map_err(Error::Provider)
}

fn finish_resolved<'p, P: Digest<'p>, W: Work, SE>(
    width: Option<usize>,
    state: P::State,
    provider: &'p P,
    execution: &W,
) -> Result<P::Output, Error<SE, P::Error>> {
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
    Ok(output)
}
