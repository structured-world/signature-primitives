//! Source-bound execution of initial and renewed RFC 6283 timestamps.

use super::{CanonicalInput, Chain, Record, Stamp, XmlRecordXml, imprint};
use crate::{
    binary::{self, Location, OwnedDecoded},
    evidence::{ObjectError, Records},
    xml::{Access, AccessError, Xml},
};
use structured_asn1::{
    Encoding, Reader,
    digest::Resolution,
    memory::{Execution, MemoryError, OwnedVec, Work},
};
use structured_cms::{
    digest::{DigestBatch, DigestError, DigestMemo, PassError},
    evidence::verify::{self, Decision, Historical, OrderCause, Selection},
    provider::SignatureProvider,
    timestamp::{CheckContext, Evidence, ProfileCheckError, ProfileFailure, Token, TokenExtension},
};
use structured_pkix::{
    algorithm::digest::{Algorithm, AsnDigest},
    temporal::{Instant, LeapTable},
};

/// Explicit selection of the actual TSA certificate and its effective key.
pub trait Authority<N> {
    /// Original selector/policy refusal.
    type Error;

    /// Select the actor for this exact original token and material inventory.
    fn select<'a, W: Work>(
        &'a self,
        stamp: &Stamp<N>,
        token: &Token<'_>,
        reader: &Reader<'_>,
        work: &W,
    ) -> Result<Selection<'a>, Self::Error>;
}

/// The provider, explicit verification time, UTC and authority selection.
pub struct Check<'a, P, A> {
    /// One selected provider for the literal object digests and RFC 3161.
    pub provider: &'a P,
    /// Current operation, preserving cumulative budgets for every source.
    pub operation: &'a Reader<'a>,
    /// Selection of actual timestamp-signing actors.
    pub authorities: &'a A,
    /// Explicit leap table for ordering original UTC facts.
    pub utc: &'a LeapTable<'a>,
    /// Validation reference for the final archive timestamp.
    pub reference: Instant,
}

/// Exact archive stamp and facts supplied to the caller's historical validator.
pub struct HistoricalInput<'view, 'token, N> {
    /// Actual stamp and original XMLERS material fields.
    pub stamp: &'view Stamp<N>,
    /// Original supporting information, which has no archive-time protection.
    pub supporting: Option<N>,
    /// Existing timestamp, actor, following-token and algorithm-longevity context.
    pub evidence: Historical<'view, 'token>,
}

/// Separate source, conformance and crypto-processing refusal categories.
#[derive(Debug)]
pub enum Error<E, N, D, G, PE, AE, RE, HE> {
    /// Original XMLERS structural reading refused.
    Record(super::Error<E, N>),
    /// Original acquisition or catalogue boundary refused.
    Objects(ObjectError<E, N>),
    /// This consumer lacks an operation for the record's declared encryption.
    Encrypted(N),
    /// Original snapshot, current admission or XML lexical/algorithm failure.
    Access(AccessError<E, N>),
    /// The chain digest cannot be used or a renewal repeats the same identity.
    Algorithm(N),
    /// Decoded token reader or CMS read failed, retaining its original node.
    Token(binary::Located<TokenReadError, N, D, G>),
    /// One original token used a different or invalid digest from its chain.
    TokenAlgorithm(N),
    /// Literal object digest preparation failed.
    Digest(DigestError<PE>),
    /// An original object did not finish or the selected digest failed.
    Acquisition(PassError<ObjectError<E, N>, PE>),
    /// Certificate and working key selection refused.
    Authority(N, AE),
    /// Actual imprint, token signature, recognition or processing refused.
    Check(
        N,
        ProfileCheckError<imprint::Error<E, N>, PE, RE, Infallible>,
    ),
    /// Original historical callback refused.
    Historical(N, HE),
    /// The common chronology kernel refused processing.
    Chronology(N, structured_cms::Error),
    /// Accounted capacity or work was denied before processing.
    Resource(N, MemoryError),
}

use core::convert::Infallible;

/// Binary processing under the original token and current operation ceilings.
#[derive(Debug)]
pub enum TokenReadError {
    /// Original DER reader could not open the decoded range.
    Reader(structured_asn1::Error),
    /// Original CMS envelope could not be decoded.
    Token(structured_cms::Error),
    /// The original imprint algorithm could not be established.
    Algorithm(
        structured_cms::content_source::ContentError<
            structured_cms::timestamp::InfoError<verify::AlgorithmError>,
        >,
    ),
}

/// A completed negative or indeterminate result, with the original token node.
#[derive(Debug)]
pub enum Failure<N> {
    /// No positive mathematical evidence was established for the token.
    Token(N),
    /// Adjacent authenticated timestamps did not establish their stated order.
    Order(N, OrderCause),
    /// The original historical path/status or algorithm policy was unsatisfied.
    Historical(N, Decision),
}

/// Independent result of checking one archive timestamp in logical order.
pub struct Finding<N> {
    token: N,
    evidence: Option<Evidence>,
    decision: Decision,
}

impl<N: Copy> Finding<N> {
    /// The original RFC 3161 enclosure.
    #[must_use]
    pub fn token(&self) -> N {
        self.token
    }
    /// Independent mathematical/time evidence, if positive.
    #[must_use]
    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }
    /// Historical decision for the exact signer and renewal relation.
    #[must_use]
    pub fn historical(&self) -> Decision {
        self.decision
    }
}

/// Complete XMLERS verification for one original record.
pub struct Report<N, D, G> {
    location: Location<N, D, G>,
    signature: N,
    index: usize,
    chains: usize,
    tail: (i32, i32),
    findings: OwnedVec<Finding<N>>,
    failures: OwnedVec<Failure<N>>,
}

impl<N: Copy, D: Copy, G: Copy> Report<N, D, G> {
    /// Original RFC 6283 XML enclosure and source generation.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// All checked original tokens, including negative results.
    pub fn findings(&self) -> impl ExactSizeIterator<Item = &Finding<N>> {
        self.findings.iter().rev()
    }
    /// All independent record failures. Resource refusal cannot produce a report.
    #[must_use]
    pub fn failures(&self) -> &[Failure<N>] {
        &self.failures
    }
    /// The record, original group, every renewal and caller history all held.
    #[must_use]
    pub fn verified(&self) -> Option<crate::evidence::Verified<N, D, G>> {
        if !self.failures.is_empty() {
            return None;
        }
        Some(crate::evidence::Verified {
            location: self.location,
            signature: self.signature,
            index: self.index,
            chains: self.chains,
            stamps: self.findings.len(),
            xml_tail: Some(self.tail),
        })
    }
}

type ReportFor<X> = Report<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
type ErrorFor<X, PE, AE, RE, HE> = Error<
    <X as Xml>::Error,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
    PE,
    AE,
    RE,
    HE,
>;
/// Result in the original XML and selected backend/authority domains.
pub type VerifyResult<T, X, PE, AE, RE, HE> = Result<T, ErrorFor<X, PE, AE, RE, HE>>;

struct Parsed<'a> {
    reader: Reader<'a>,
    token: Token<'a>,
}

type ChainInputs<'a> = (OwnedVec<Algorithm>, OwnedVec<Parsed<'a>>);
type ObjectDigests<'p, P> = OwnedVec<DigestMemo<'p, P>>;

impl<P, A> Check<'_, P, A> {
    /// Verify one original XMLERS member against its complete original object
    /// group, all RFC 6283 renewals, chronology and explicit historical inputs.
    /// The scoped callback sees each actual checked token at most once.
    #[expect(
        clippy::result_large_err,
        reason = "retain original decoded and carried-source maps"
    )]
    pub fn xml<X, PE, RE, HE>(
        &self,
        xml: &X,
        records: &Records<'_, X>,
        index: usize,
        mut recognizes: impl FnMut(X::Id, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        mut historical: impl for<'v, 't> FnMut(
            HistoricalInput<'v, 't, X::Id>,
            &Execution<'_>,
        ) -> Result<Decision, HE>,
    ) -> VerifyResult<ReportFor<X>, X, PE, A::Error, RE, HE>
    where
        X: XmlRecordXml,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authority<X::Id>,
    {
        let work = self.operation.execution();
        let access = Access::new(xml, records.snapshot(), &work);
        let record = super::read(&access, records, index).map_err(Error::Record)?;
        if let Some(node) = record.encryption() {
            return Err(Error::Encrypted(node));
        }
        let location = Location {
            snapshot: record.snapshot(),
            node: record.member().node(),
        };
        let origins = token_sources(&record, xml, self.operation)?;
        let (plan, parsed) = chain_inputs(&access, &record, &origins, self.operation)?;
        let tail = record
            .chains()
            .last()
            .ok_or(Error::Algorithm(location.node))?;
        let latest = tail
            .stamps()
            .last()
            .ok_or(Error::Algorithm(location.node))?;
        let mut objects = records.objects(xml, index, &work).map_err(Error::Objects)?;
        let digests = object_digests(
            objects.sources(),
            &plan,
            self.provider,
            location.node,
            &work,
        )?;
        check_history(
            self,
            &access,
            &record,
            &plan,
            &parsed,
            &digests,
            &mut recognizes,
            &mut historical,
        )
        .map(|(findings, failures)| Report {
            location,
            signature: records.signature(),
            index,
            chains: record.chains().len(),
            tail: (tail.chain.order, latest.archive.order),
            findings,
            failures,
        })
    }
}

type Findings<N> = (OwnedVec<Finding<N>>, OwnedVec<Failure<N>>);

// Keep both callback and source errors inline, including on budget refusal.
#[expect(
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the reverse traversal shares one live chain, token and chronology state"
)]
fn check_history<X, P, A, PE, RE, HE>(
    check: &Check<'_, P, A>,
    access: &Access<'_, X, impl Work>,
    record: &Record<X>,
    plan: &[Algorithm],
    parsed: &[Parsed<'_>],
    digests: &[DigestMemo<'_, P>],
    recognizes: &mut impl FnMut(X::Id, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    historical: &mut impl for<'v, 't> FnMut(
        HistoricalInput<'v, 't, X::Id>,
        &Execution<'_>,
    ) -> Result<Decision, HE>,
) -> VerifyResult<Findings<X::Id>, X, PE, A::Error, RE, HE>
where
    X: XmlRecordXml,
    P: for<'scope> SignatureProvider<'scope, Error = PE>,
    A: Authority<X::Id>,
{
    let work = check.operation.execution();
    let xml = access.owner();
    let mut findings = work.vector();
    let mut failures = work.vector();
    let mut next_chain = None;
    let mut next_certificate = None;
    let mut token = parsed.len();
    for (chain_index, chain) in record.chains().iter().enumerate().rev() {
        for (stamp_index, stamp) in chain.stamps().iter().enumerate().rev() {
            token -= 1;
            let here = &parsed[token];
            let previous = if stamp_index > 0 {
                Some(CanonicalInput::Timestamp(&chain.stamps()[stamp_index - 1]))
            } else if chain_index > 0 {
                Some(CanonicalInput::Sequence {
                    node: record.sequence(),
                    chains: &record.chains()[..chain_index],
                })
            } else {
                None
            };
            let hashes = if stamp_index == 0 {
                Some(group_hashes::<X, _, _, _, _, _, _>(
                    digests,
                    chain_index,
                    stamp.token,
                    &work,
                )?)
            } else {
                None
            };
            let mut recipe = imprint::Recipe {
                xml,
                snapshot: record.snapshot(),
                node: stamp.token,
                method: chain.canonicalization,
                width: plan[chain_index].width(),
                tree: stamp.tree(),
                objects: hashes.as_deref(),
                prior: previous,
            };
            let selection = check
                .authorities
                .select(stamp, &here.token, &here.reader, &work)
                .map_err(|cause| Error::Authority(stamp.token, cause))?;
            let context = CheckContext {
                certificate: selection.certificate,
                certificate_parent: selection.certificate_parent,
                key: selection.key,
                requested: None,
                utc: check.utc,
                reference: None,
                window: None,
                policy_accuracy: selection.policy_accuracy,
            };
            let checked = here
                .token
                .check_historical_input_with_profile(
                    check.provider,
                    &here.reader,
                    &context,
                    &mut recipe,
                    |extension, work| recognizes(stamp.token, extension, work),
                    |_| Ok::<_, ProfileFailure<Infallible>>(()),
                )
                .map_err(|cause| Error::Check(stamp.token, cause))?;
            let following: Option<&Finding<X::Id>> = findings.last();
            let following = following.and_then(Finding::evidence);
            let later_chain = next_chain
                .and_then(|i| findings.get(i))
                .and_then(Finding::evidence);
            let decision = historical(
                HistoricalInput {
                    stamp,
                    supporting: record.supporting_information(),
                    evidence: Historical {
                        index: token,
                        current: &checked,
                        selection: &selection,
                        following,
                        following_chain: later_chain,
                        verification_time: check.reference,
                    },
                },
                &work,
            )
            .map_err(|cause| Error::Historical(stamp.token, cause))?;
            let resource = |cause| Error::Resource(stamp.token, cause);
            let evidence = checked.into_evidence();
            if let Some(current) = &evidence {
                if let (Some(next), Some(cert)) = (following, next_certificate)
                    && let Some(cause) = verify::order_evidence(
                        current,
                        selection.certificate,
                        next,
                        cert,
                        check.utc,
                        &work,
                    )
                    .map_err(|cause| Error::Chronology(stamp.token, cause))?
                {
                    failures
                        .try_push(Failure::Order(stamp.token, cause))
                        .map_err(resource)?;
                }
            } else {
                failures
                    .try_push(Failure::Token(stamp.token))
                    .map_err(resource)?;
            }
            if decision != Decision::Valid {
                failures
                    .try_push(Failure::Historical(stamp.token, decision))
                    .map_err(resource)?;
            }
            findings
                .try_push(Finding {
                    token: stamp.token,
                    evidence,
                    decision,
                })
                .map_err(resource)?;
            next_certificate = Some(selection.certificate);
        }
        next_chain = Some(findings.len() - 1);
    }
    access
        .query(record.member().node(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    Ok((findings.into_owned(), failures.into_owned()))
}

#[expect(
    clippy::result_large_err,
    reason = "retain original decoded and carried-source maps"
)]
fn chain_inputs<'a, X: XmlRecordXml, W: Work, PE, AE, RE, HE>(
    access: &Access<'_, X, W>,
    record: &Record<X>,
    sources: &'a [OwnedDecoded],
    operation: &Reader<'a>,
) -> VerifyResult<ChainInputs<'a>, X, PE, AE, RE, HE> {
    let work = operation.execution();
    let mut plan = work.vector();
    let mut parsed = work.vector();
    let mut origins = sources.iter();
    for chain in record.chains() {
        let algorithm = resolve(access, chain)?;
        if plan.last() == Some(&algorithm) {
            return Err(Error::Algorithm(chain.digest));
        }
        plan.try_push(algorithm)
            .map_err(|cause| Error::Resource(chain.digest, cause))?;
        for stamp in chain.stamps() {
            let original = origins.next().ok_or(Error::TokenAlgorithm(stamp.token))?;
            let token = parse::<X, _, _, _, _>(
                original,
                operation,
                Location {
                    snapshot: record.snapshot(),
                    node: stamp.token,
                },
                algorithm,
            )?;
            parsed
                .try_push(token)
                .map_err(|cause| Error::Resource(stamp.token, cause))?;
        }
    }
    Ok((plan.into_owned(), parsed.into_owned()))
}

#[expect(
    clippy::result_large_err,
    reason = "retain original source and processing causes"
)]
fn object_digests<'p, X, P, W, PE, AE, RE, HE>(
    objects: &mut [crate::evidence::Object<'_, X>],
    plan: &[Algorithm],
    provider: &'p P,
    node: X::Id,
    work: &W,
) -> VerifyResult<ObjectDigests<'p, P>, X, PE, AE, RE, HE>
where
    X: XmlRecordXml,
    P: AsnDigest<'p, Error = PE>,
    W: Work,
{
    let mut digests = work.vector();
    digests
        .try_reserve_exact(objects.len())
        .map_err(|cause| Error::Resource(node, cause))?;
    for source in objects {
        let node = source.node();
        let resource = |cause| Error::Resource(node, cause);
        let mut identities = work.vector();
        identities.try_reserve_exact(plan.len()).map_err(resource)?;
        for &algorithm in plan {
            work.charge_work(1).map_err(resource)?;
            let identity = provider.identity(algorithm).ok_or(Error::Algorithm(node))?;
            identities.try_push(identity).map_err(resource)?;
        }
        let batch =
            DigestBatch::prepare(provider, identities.into_owned(), work, "xmlers.objects", 0)
                .map_err(Error::Digest)?;
        let memo = batch.run(source, work).map_err(Error::Acquisition)?;
        digests.try_push(memo).map_err(resource)?;
    }
    Ok(digests.into_owned())
}

#[expect(
    clippy::result_large_err,
    reason = "same inline error contract as the verification driver"
)]
fn resolve<X: XmlRecordXml, W: Work, PE, AE, RE, HE>(
    access: &Access<'_, X, W>,
    chain: &Chain<X::Id>,
) -> VerifyResult<Algorithm, X, PE, AE, RE, HE> {
    match access
        .query(chain.digest, |xml, snapshot, work| {
            xml.evidence_digest(snapshot, chain.digest, work)
        })
        .map_err(Error::Access)?
    {
        Resolution::Supported(algorithm) => Ok(algorithm),
        Resolution::Malformed | Resolution::Unsupported => Err(Error::Algorithm(chain.digest)),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "same inline error contract as the verification driver"
)]
fn token_sources<X: XmlRecordXml, PE, AE, RE, HE>(
    record: &Record<X>,
    xml: &X,
    operation: &Reader<'_>,
) -> VerifyResult<OwnedVec<OwnedDecoded>, X, PE, AE, RE, HE> {
    let work = operation.execution();
    let mut sources = work.vector();
    for chain in record.chains() {
        work.charge_work(1)
            .map_err(|cause| Error::Resource(chain.chain.node, cause))?;
        for stamp in chain.stamps() {
            let node = stamp.token;
            let loaded = binary::owned_source(
                xml,
                Location {
                    snapshot: record.snapshot(),
                    node,
                },
                operation,
            )
            .map_err(Error::Access)?;
            sources
                .try_push(loaded.value)
                .map_err(|cause| Error::Resource(node, cause))?;
        }
    }
    Ok(sources.into_owned())
}

#[expect(
    clippy::result_large_err,
    reason = "retain original decoded and carried-source maps"
)]
fn parse<'a, X: XmlRecordXml, PE, AE, RE, HE>(
    source: &'a OwnedDecoded,
    operation: &Reader<'a>,
    location: Location<X::Id, X::Document, X::Generation>,
    expected: Algorithm,
) -> VerifyResult<Parsed<'a>, X, PE, AE, RE, HE> {
    let failure = |value| Error::Token(binary::Located { location, value });
    // RFC 6283 §3.1.2 explicitly requires DER for RFC 3161 token octets.
    // https://www.rfc-editor.org/rfc/rfc6283.html#section-3.1.2
    let mut reader = source
        .reader_in(operation, Encoding::Der)
        .map_err(|cause| failure(TokenReadError::Reader(cause)))?;
    let token =
        Token::read_from(&mut reader).map_err(|cause| failure(TokenReadError::Token(cause)))?;
    let actual = verify::token_algorithm(&token, &reader)
        .map_err(|cause| failure(TokenReadError::Algorithm(cause)))?;
    if actual != expected {
        return Err(Error::TokenAlgorithm(location.node));
    }
    Ok(Parsed { reader, token })
}

#[expect(
    clippy::result_large_err,
    reason = "same inline error contract as the verification driver"
)]
fn group_hashes<'a, 'p, X: XmlRecordXml, P, W: Work, PE, AE, RE, HE>(
    hashed: &'a [DigestMemo<'p, P>],
    index: usize,
    node: X::Id,
    work: &W,
) -> VerifyResult<OwnedVec<&'a [u8], W>, X, PE, AE, RE, HE>
where
    P: AsnDigest<'p, Error = PE>,
{
    let resource = |cause| Error::Resource(node, cause);
    let mut group = work.vector();
    group.try_reserve_exact(hashed.len()).map_err(resource)?;
    for object in hashed {
        let output = object
            .for_request(index, work)
            .map_err(Error::Digest)?
            .ok_or(Error::Algorithm(node))?;
        group.try_push(output.as_bytes()).map_err(resource)?;
    }
    Ok(group)
}
