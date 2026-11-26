//! Content timestamps over replayable, pre-sign XML reference plans.

use super::{Emit, Error, ResponseCheck, Writer, XADES};
use crate::{reference::ReplayOutcome, timestamp};
use structured_asn1::{
    Oid, Reader,
    digest::Resolution,
    memory::{Execution, HashWork, MemoryError, OwnedVec, Work},
};
use structured_cms::{
    digest::{DigestError, PassError, SingleDigest},
    provider::SignatureProvider,
    stream::{Receiver, Refused, Source},
    timestamp::{
        NewRequest, ProfileCheckError, RequestEncodingError, RequestExtension, TokenExtension,
        response::CheckedResponse,
    },
};
use structured_pkix::{
    AlgorithmIdentifier,
    algorithm::digest::{self, AsnDigest},
};

/// One actual staged reference and its exact Include URI if addressable.
#[derive(Clone, Copy, Debug)]
pub struct ContentReference<'a, N> {
    /// Identity of the reference instruction, not its target.
    pub node: N,
    /// URI resolving to this reference in the future timestamp property.
    pub include_uri: Option<&'a str>,
    /// Whether this reference covers the new `SignedProperties`.
    pub signed_properties: bool,
}

/// Content time-stamp scope before the signature is produced.
#[derive(Clone, Copy, Debug)]
pub enum ContentScope<'a, N> {
    /// Direct `SignedInfo` data references in document order.
    All,
    /// Explicit references in Include order.
    Individual(&'a [N]),
}

/// Immutable, replayable view of one XML-owner pre-sign operation.
///
/// The owner exposes the actual staged document, selected signature, and
/// reference plan. It checks source identities and admits resource use under
/// the current Work before lookups or replay. Finalized dependencies (for
/// example nested Manifest digest values) participate in this view. If any
/// required output cannot be established before signing, replay must fail.
pub trait ContentSource {
    /// Original reference and canonicalization-method identities.
    type Id: Copy + Eq + HashWork;
    /// Original XML policy, source, or processing refusal.
    type Error;

    /// Complete list of direct `SignedInfo` references in emission order.
    fn signed_info<W: Work>(
        &self,
        work: &W,
    ) -> Result<&[ContentReference<'_, Self::Id>], Self::Error>;

    /// Look up an actual reference of `SignedInfo` or a signed Manifest.
    /// A reference from an unrelated selection must not be resolved.
    fn reference<W: Work>(
        &self,
        node: Self::Id,
        work: &W,
    ) -> Result<Option<ContentReference<'_, Self::Id>>, Self::Error>;

    /// Verify that the exact canonicalization method is suitable for this
    /// staged input, including its parameters and compiled XML policy.
    fn admit_method<W: Work>(&self, method: Self::Id, work: &W) -> Result<(), Self::Error>;

    /// Replay the actual dereference and transforms. Convert a remaining
    /// node-set using the supplied timestamp method. Stream complete octets
    /// unchanged. Reject changed inputs and stop on receiver refusal.
    fn replay<W: Work>(
        &self,
        reference: Self::Id,
        method: Self::Id,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<ReplayOutcome<Self::Error>, Self::Error>;
}

/// Writer staged at the selected signature's `SignedDataObjectProperties`.
pub trait ContentWriter<X: ContentSource>: Writer {
    /// Check that this writer targets the same signature, document generation,
    /// reference plan and immutable inputs. Changed or foreign staging is
    /// refused before writing. This check must also work after writing a
    /// property, using the owner's invariant that the replay inputs are fixed.
    fn matches_content<W: Work>(&self, source: &X, work: &W) -> Result<bool, Self::Error>;

    /// Copy the original complete `CanonicalizationMethod` with its parameters.
    fn content_method<W: Work>(&mut self, method: X::Id, work: &W) -> Result<(), Self::Error>;
}

/// A complete content input plan with borrowed XML handles and paid storage.
pub struct ContentInput<'a, X: ContentSource> {
    source: &'a X,
    method: X::Id,
    references: Selection<'a, X::Id>,
}

enum Selection<'a, N> {
    All(&'a [ContentReference<'a, N>]),
    Individual(OwnedVec<ContentReference<'a, N>>),
}

/// A refusal before or during replay of the timestamp input.
#[derive(Debug)]
pub enum ContentInputError<E, N> {
    /// Original processing, policy, source, or resource cause from XML.
    Xml(E),
    /// The common work or allocation boundary refused.
    Resource(MemoryError),
    /// Nothing can be selected for the requested content stamp.
    Empty,
    /// An individual selection is foreign, targets `SignedProperties`, or
    /// cannot be represented by an Include in the actual property context.
    Reference(N),
    /// The owner reported missing detached bytes for this staged reference.
    Unavailable {
        /// Actual reference instruction.
        reference: N,
        /// Original failure to obtain its bytes.
        cause: E,
    },
    /// The sink refused before the complete input was available.
    Receiver(Refused),
}

impl<'a, X: ContentSource> ContentInput<'a, X> {
    /// Select the pre-sign timestamp input under EN 319 132-1 §5.2.8.
    /// All uses direct references other than `SignedProperties`. Individual
    /// uses explicitly selected references of `SignedInfo` or a signed Manifest.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn prepare<W: Work>(
        source: &'a X,
        method: X::Id,
        scope: ContentScope<'_, X::Id>,
        work: &W,
    ) -> Result<Self, ContentInputError<X::Error, X::Id>> {
        work.charge_work(1).map_err(ContentInputError::Resource)?;
        source
            .admit_method(method, work)
            .map_err(ContentInputError::Xml)?;
        let references = match scope {
            ContentScope::All => {
                let mut present = false;
                let references = source.signed_info(work).map_err(ContentInputError::Xml)?;
                for reference in references {
                    work.charge_work(1).map_err(ContentInputError::Resource)?;
                    if !reference.signed_properties {
                        present = true;
                        break;
                    }
                }
                if !present {
                    return Err(ContentInputError::Empty);
                }
                Selection::All(references)
            }
            ContentScope::Individual(selection) => {
                if selection.is_empty() {
                    return Err(ContentInputError::Empty);
                }
                let mut references = work.vector();
                for node in selection.iter().copied() {
                    work.charge_work(1).map_err(ContentInputError::Resource)?;
                    let reference = source
                        .reference(node, work)
                        .map_err(ContentInputError::Xml)?
                        .ok_or(ContentInputError::Reference(node))?;
                    if reference.signed_properties
                        || reference.include_uri.is_none_or(str::is_empty)
                        || !structured_ltv::source::equal_id(reference.node, node, work)
                            .map_err(ContentInputError::Resource)?
                    {
                        return Err(ContentInputError::Reference(node));
                    }
                    references
                        .try_push(reference)
                        .map_err(ContentInputError::Resource)?;
                }
                Selection::Individual(references.into_owned())
            }
        };
        Ok(Self {
            source,
            method,
            references,
        })
    }

    /// Compute the imprint with the selected ASN.1 provider and construct
    /// the exact request before external acquisition. The reader belongs to
    /// the original digest `AlgorithmIdentifier`.
    pub fn request<'p, P>(
        &'p self,
        provider: &'p P,
        parent: &Reader<'_>,
        request: &ContentRequest<'_>,
    ) -> ContentRequestResult<'p, 'a, X, P::Error>
    where
        P: AsnDigest<'p>,
    {
        if !request.algorithm.same_session(parent) {
            return Err(ContentRequestError::Foreign);
        }
        let work = parent.execution();
        let identity = match digest::resolve(provider, &request.algorithm, &work)
            .map_err(ContentRequestError::Identifier)?
        {
            Resolution::Supported(identity) => identity,
            Resolution::Unsupported => return Err(ContentRequestError::Unsupported),
            Resolution::Malformed => return Err(ContentRequestError::Malformed),
        };
        let prepared = SingleDigest::prepare(
            provider,
            identity,
            &work,
            "contentTimeStamp.request",
            request.algorithm.offset(),
        )
        .map_err(ContentRequestError::Digest)?;
        let output = prepared
            .run(&mut Replay(self), &work)
            .map_err(ContentRequestError::Pass)?;
        let request = NewRequest {
            algorithm: request.algorithm,
            hashed_message: output.as_bytes(),
            policy: request.policy,
            nonce: request.nonce,
            cert_req: request.cert_req,
            extensions: request.extensions,
        }
        .encode_der(parent)
        .map_err(ContentRequestError::Encoding)?;
        Ok(PendingContent {
            input: self,
            request,
        })
    }

    /// Emit a property carrying the actual checked response tokens in order.
    /// Check the staging and every response before XML emission.
    pub fn write<B: ContentWriter<X>, W: Work>(
        &self,
        stamps: &[CheckedContent<'_, '_, 'a, X>],
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        self.require(writer, work)?;
        if stamps.is_empty() {
            return Err(Error::Value("contentTimeStamp.tokens"));
        }
        for stamp in stamps {
            work.charge_work(1).map_err(Error::Resource)?;
            if !core::ptr::eq(self, stamp.input) {
                return Err(Error::Foreign);
            }
            if stamp.token().is_none() {
                return Err(Error::Prerequisites);
            }
        }
        let mut emit = Emit { writer, work };
        let property = match self.references {
            Selection::All(_) => "AllDataObjectsTimeStamp",
            Selection::Individual(_) => "IndividualDataObjectsTimeStamp",
        };
        emit.begin(XADES, property)?;
        if let Selection::Individual(references) = &self.references {
            for reference in references {
                let uri = reference.include_uri.ok_or(Error::Foreign)?;
                emit.begin(XADES, "Include")?;
                emit.attribute("URI", uri)?;
                emit.attribute("referencedData", "true")?;
                emit.end()?;
            }
        }
        work.charge_work(1).map_err(Error::Resource)?;
        emit.writer
            .content_method(self.method, work)
            .map_err(Error::Writer)?;
        for stamp in stamps {
            work.charge_work(1).map_err(Error::Resource)?;
            let (token, producer) = stamp.token().ok_or(Error::Prerequisites)?;
            let scoped = producer.execution_in(work);
            Emit {
                writer: emit.writer,
                work: &scoped,
            }
            .binary(XADES, "EncapsulatedTimeStamp", token.as_bytes())?;
        }
        emit.end()?;
        self.require(emit.writer, work)
    }

    fn require<B: ContentWriter<X>, W: Work>(
        &self,
        writer: &B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        work.charge_work(1).map_err(Error::Resource)?;
        if !writer
            .matches_content(self.source, work)
            .map_err(Error::Writer)?
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
}

struct Replay<'p, 'a, X: ContentSource>(&'p ContentInput<'a, X>);

impl<X: ContentSource> Source for Replay<'_, '_, X> {
    type Error = ContentInputError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let mut receiver = timestamp::Stop {
            receiver,
            refused: false,
        };
        let references = match &self.0.references {
            Selection::All(references) => references,
            Selection::Individual(references) => &**references,
        };
        for reference in references {
            work.charge_work(1).map_err(ContentInputError::Resource)?;
            if reference.signed_properties {
                continue;
            }
            let outcome = self
                .0
                .source
                .replay(reference.node, self.0.method, &mut receiver, work)
                .map_err(ContentInputError::Xml)?;
            if receiver.refused {
                return Err(ContentInputError::Receiver(Refused));
            }
            if let ReplayOutcome::Unavailable(cause) = outcome {
                return Err(ContentInputError::Unavailable {
                    reference: reference.node,
                    cause,
                });
            }
        }
        Ok(())
    }
}

/// RFC 3161 request parameters. The imprint comes only from the content input.
pub struct ContentRequest<'a> {
    /// Selected ASN.1 digest identifier and parameters.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Requested TSA policy, if any.
    pub policy: Option<Oid<'a>>,
    /// Caller-provided unsigned nonce.
    pub nonce: Option<&'a [u8]>,
    /// Request carriage of the TSA certificate.
    pub cert_req: bool,
    /// Complete original extensions.
    pub extensions: &'a [RequestExtension<'a>],
}

/// Refusal to generate a content timestamp request.
#[derive(Debug)]
pub enum ContentRequestError<E, N, P> {
    /// The supplied query does not belong to the identifier.
    Foreign,
    /// The identifier's original parsing or resource cause.
    Identifier(structured_pkix::Error),
    /// No usable provider identity for the selected algorithm.
    Unsupported,
    /// Invalid parameters for the selected algorithm.
    Malformed,
    /// Original digest preparation failure.
    Digest(DigestError<P>),
    /// Original input, provider, or processing failure during digesting.
    Pass(PassError<ContentInputError<E, N>, P>),
    /// Original common RFC 3161 request encoder failure.
    Encoding(RequestEncodingError),
}

/// Result of request construction in this XML owner's source and error domain.
pub type ContentRequestResult<'p, 'a, X, P> = Result<
    PendingContent<'p, 'a, X>,
    ContentRequestError<<X as ContentSource>::Error, <X as ContentSource>::Id, P>,
>;

/// The exact encoded request and the immutable plan that produced it.
pub struct PendingContent<'p, 'a, X: ContentSource> {
    input: &'p ContentInput<'a, X>,
    request: OwnedVec<u8>,
}

/// Refused to check a response against its original input and request.
#[derive(Debug)]
pub enum ContentResponseError<E, N, P, R> {
    /// No live request or a different original request was supplied.
    ForeignRequest,
    /// Resource refusal admitting request comparison.
    Resource(MemoryError),
    /// Original RFC 3161/profile check error.
    Check(ProfileCheckError<ContentInputError<E, N>, P, R, timestamp::profile::DigestError>),
}

/// Result of checking a response in this XML owner's source and error domain.
pub type ContentResponseResult<'q, 'p, 'a, X, P, R> = Result<
    CheckedContent<'q, 'p, 'a, X>,
    ContentResponseError<<X as ContentSource>::Error, <X as ContentSource>::Id, P, R>,
>;

impl<'p, 'a, X: ContentSource> PendingContent<'p, 'a, X> {
    /// Original complete DER to send through the caller's chosen TSA transport.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }

    /// Check the original response and the exact request, including the
    /// actual content replay, through the existing RFC 3161 checker.
    #[expect(
        clippy::result_large_err,
        reason = "preserve typed response and input causes without an allocation on refusal"
    )]
    pub fn check_response<'q, P, PE, RE>(
        &self,
        check: &ResponseCheck<'q, '_, P>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> ContentResponseResult<'q, 'p, 'a, X, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let requested = check
            .context
            .requested
            .as_ref()
            .ok_or(ContentResponseError::ForeignRequest)?;
        let work = check.query.execution();
        if !requested.request.same_session(requested.parent) {
            return Err(ContentResponseError::ForeignRequest);
        }
        let original = requested.request.as_bytes();
        work.charge_work_from(
            [requested.parent.parser(), check.query.parser()],
            original.len() as u64,
        )
        .map_err(ContentResponseError::Resource)?;
        if original != &*self.request {
            return Err(ContentResponseError::ForeignRequest);
        }
        let facts = check
            .response
            .check_with_profile(
                check.provider,
                check.query,
                check.context,
                &mut Replay(self.input),
                recognizes,
                |input| timestamp::profile::check(&input),
            )
            .map_err(ContentResponseError::Check)?;
        Ok(CheckedContent {
            input: self.input,
            response: check.response,
            facts,
        })
    }
}

/// Result of the common check, retaining the actual response and input plan.
pub struct CheckedContent<'q, 'p, 'a, X: ContentSource> {
    input: &'p ContentInput<'a, X>,
    response: &'q structured_cms::timestamp::Response<'q>,
    facts: CheckedResponse<'q>,
}

impl<'q, X: ContentSource> CheckedContent<'q, '_, '_, X> {
    /// Original check facts, including negative results.
    #[must_use]
    pub fn facts(&self) -> &CheckedResponse<'_> {
        &self.facts
    }

    fn token(
        &self,
    ) -> Option<(
        &structured_asn1::Element<'q>,
        structured_pkix::algorithm::Producer<'q>,
    )> {
        self.facts.timestamp()?.evidence()?;
        let token = self.response.token_element()?;
        let producer = self
            .response
            .token()?
            .signer()
            .digest_algorithm()
            .identifier()?
            .execution_origin();
        Some((token, producer))
    }
}
