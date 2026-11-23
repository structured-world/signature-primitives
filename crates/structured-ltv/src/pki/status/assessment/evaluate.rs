//! Authentication, authority binding and per-source interpretation.

use super::{
    Assessment, Authentication, Error, Finding, Freshness, LookupFailure, Query, Responder,
    Revoked, Source, Sources, Statement, Status, Unusable, decide,
};
use crate::pki::{CheckedPath, CrlAuthority, OcspBinding, ResponderBinding};
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_pkix::{
    Certificate, Time,
    algorithm::digest::AsnDigest,
    crl::{
        Authenticated, Authentication as ListAuthentication, BoundDelta, CertificateList,
        CombinedEntry, DeltaBinding, EntryLookup, Reasons, ScopeOutcome,
    },
    error::CallbackError,
    extension::Recognizer,
    ocsp::{self, AuthorityBinding, BasicResponse, SignatureAuthentication, TargetEvidence},
    path::{BuildError, EffectiveKey, ValidationContext, Verify, Watch},
    temporal::Reading,
};

type Result<T, V, D, R> = core::result::Result<T, Error<V, D, R>>;

#[derive(Clone, Copy)]
struct List<'a> {
    source: Authenticated<'a, 'a>,
    index: usize,
}

struct Delta<'a> {
    list: List<'a>,
    paired: bool,
}

/// Authenticate and assess every supplied artifact for this member. Multiple
/// matching sources compete only after original issuer, scope and time binding.
/// The caller chooses the trust anchor, authority candidates, verification
/// provider and delegate path settings. No fetching or clock access is performed.
///
/// `context.execution` is the current operation's shared work and memory domain.
/// The artifact signature verifier, certificate path verifier and digest
/// provider must account their transitive work. The responder's static path
/// must cover the response's production time. Context supplies its path
/// processing policy, bounds and recognizer.
pub fn assess<'p, 'a, 'd, V, F, D, P, W, R, E>(
    path: &'p CheckedPath<'a>,
    member: usize,
    sources: &[Source<'_, 'a>],
    query: &Query<'_>,
    context: &ValidationContext<'a, '_, P, W, R, E>,
    verifier: &V,
    digest: &'d D,
) -> Result<Assessment<'p, 'a>, F, D::Error, R::Error>
where
    E: Work,
    V: for<'s> Verify<Execution<'s>, Error = F>,
    P: Verify<E, Error = F>,
    D: AsnDigest<'d> + ?Sized,
    W: Watch,
    R: Recognizer<E>,
{
    let work = context.execution;
    work.charge_work(1).map_err(Error::Resource)?;
    let target = path
        .members()
        .get(member)
        .ok_or(Error::Member)?
        .certificate();
    if query.interval.upper > query.now
        || query
            .interval
            .lower
            .is_some_and(|lower| lower >= query.interval.upper)
    {
        return Err(Error::Interval);
    }
    let issuer = match member.checked_sub(1) {
        Some(index) => {
            let issuer = path.members()[index];
            Some((issuer.certificate(), issuer.key()))
        }
        None => path
            .anchor()
            .certificate()
            .map(|certificate| (certificate, EffectiveKey::standing(path.anchor().key()))),
    };
    let mut statements = work.vector();
    let mut lists = work.vector();
    let mut deltas = work.vector();
    for (index, source) in sources.iter().enumerate() {
        work.charge_work(1).map_err(Error::Resource)?;
        let positions = Sources {
            primary: index,
            base: None,
        };
        let statement = match source {
            Source::Crl { list, authorities } => {
                let failed =
                    match authenticate_list(path, list, authorities, query, verifier, work)? {
                        Ok(authenticated) => {
                            let is_delta = list
                                .tbs()
                                .extensions()
                                .get(structured_pkix::oid::DELTA_CRL_INDICATOR, work)
                                .map_err(Error::Processing)?
                                .is_some();
                            let list = List {
                                source: authenticated,
                                index,
                            };
                            if is_delta {
                                deltas
                                    .try_push(Delta {
                                        list,
                                        paired: false,
                                    })
                                    .map_err(Error::Resource)?;
                            } else {
                                lists.try_push(list).map_err(Error::Resource)?;
                            }
                            continue;
                        }
                        Err(failed) => failed,
                    };
                unusable(positions, list.tbs().this_update(), failed)
            }
            Source::Ocsp {
                response,
                nonce,
                intended_signer,
                responders,
            } => {
                let request = ocsp::Request {
                    target,
                    nonce: *nonce,
                    intended_signer: *intended_signer,
                };
                assess_response(
                    path, member, positions, response, &request, issuer, responders, query,
                    context, verifier, digest,
                )?
            }
        };
        statements.try_push(statement).map_err(Error::Resource)?;
    }
    assess_lists(target, &lists, &mut deltas, query, work, &mut statements)?;
    let status = decide::decide(&statements, query, work).map_err(Error::Resource)?;
    Ok(Assessment {
        path,
        member,
        interval: query.interval,
        now: query.now,
        statements: statements.into_owned(),
        status,
    })
}

fn authenticate_list<'a, V, F, E, D, R>(
    path: &CheckedPath<'a>,
    list: &'a CertificateList<'a>,
    authorities: &[CrlAuthority<'_, 'a>],
    query: &Query<'_>,
    verifier: &V,
    current: &E,
) -> Result<core::result::Result<Authenticated<'a, 'a>, Unusable<'a>>, F, D, R>
where
    E: Work,
    V: for<'s> Verify<Execution<'s>, Error = F>,
{
    let work = &list.execution_in(current);
    let mut failure = Unusable::Authority;
    for &authority in authorities {
        work.charge_work(1).map_err(Error::Resource)?;
        let candidate = match authority {
            CrlAuthority::Anchor => path
                .anchor()
                .certificate()
                .map(|certificate| (certificate, EffectiveKey::standing(path.anchor().key()))),
            CrlAuthority::Path(signer_path) => signer_path
                .members()
                .last()
                .map(|member| (member.certificate(), member.key())),
        };
        let Some((signer, key)) = candidate else {
            continue;
        };
        let authenticated = list
            .authenticate(signer, key, verifier, work)
            .map_err(|error| match error {
                CallbackError::Processing(cause) => Error::Processing(cause),
                CallbackError::Callback(cause) => Error::Verification(cause),
            })?;
        match authenticated {
            ListAuthentication::Authenticated(authenticated) => {
                if path
                    .crl_authority(
                        authenticated,
                        authority,
                        Reading::from(list.tbs().this_update().instant()),
                        query.utc,
                        work,
                    )
                    .map_err(Error::CrlBinding)?
                    .is_none()
                {
                    return Ok(Ok(authenticated));
                }
            }
            ListAuthentication::Rejected(cause) => failure = Unusable::CrlAuthentication(cause),
            ListAuthentication::Unsupported => failure = Unusable::UnsupportedSignature,
        }
    }
    Ok(Err(failure))
}

fn assess_lists<'a, E: Work, V, D, R>(
    target: &'a Certificate<'a>,
    lists: &[List<'a>],
    deltas: &mut [Delta<'a>],
    query: &Query<'_>,
    work: &E,
    statements: &mut OwnedVec<Statement<'a>, E>,
) -> Result<(), V, D, R> {
    // RFC 5280 §§5.2.4 and 6.3.3(c): only pair compatible original signed lists.
    // Keep each applicable pair, including equal CRL numbers and disagreements.
    for &base in lists {
        work.charge_work(1).map_err(Error::Resource)?;
        let scope = base.source.scope(target, work).map_err(Error::Processing)?;
        let (reasons, finding) = match scope {
            ScopeOutcome::Applicable(reasons) => {
                let entry = base.source.entry(target, work).map_err(Error::Processing)?;
                (
                    reasons,
                    self::entry(entry, reasons, work).map_err(Error::Processing)?,
                )
            }
            ScopeOutcome::NotApplicable(cause) => (Reasons::NONE, Finding::NotApplicable(cause)),
        };
        let positions = Sources {
            primary: base.index,
            base: None,
        };
        let value = list_statement(
            positions,
            base.source,
            None,
            (reasons, finding),
            target,
            query,
            work,
        )?;
        statements.try_push(value).map_err(Error::Resource)?;
        if let ScopeOutcome::Applicable(reasons) = scope {
            assess_deltas(
                base,
                deltas,
                target,
                (reasons, finding),
                query,
                work,
                statements,
            )?;
        }
    }
    for delta in deltas {
        work.charge_work(1).map_err(Error::Resource)?;
        if !delta.paired {
            statements
                .try_push(unusable(
                    Sources {
                        primary: delta.list.index,
                        base: None,
                    },
                    delta.list.source.crl().tbs().this_update(),
                    Unusable::DeltaWithoutBase,
                ))
                .map_err(Error::Resource)?;
        }
    }
    Ok(())
}

fn assess_deltas<'a, E: Work, V, D, R>(
    base: List<'a>,
    deltas: &mut [Delta<'a>],
    target: &'a Certificate<'a>,
    (reasons, base_finding): (Reasons, Finding<'a>),
    query: &Query<'_>,
    work: &E,
    statements: &mut OwnedVec<Statement<'a>, E>,
) -> Result<(), V, D, R> {
    for delta in deltas {
        work.charge_work(1).map_err(Error::Resource)?;
        let DeltaBinding::Bound(pair) = base
            .source
            .bind_delta(&delta.list.source, work)
            .map_err(Error::Processing)?
        else {
            continue;
        };
        let entry = pair.entry(target, work).map_err(Error::Processing)?;
        let finding = combined(pair, &entry, target, (reasons, base_finding), query);
        let positions = Sources {
            primary: delta.list.index,
            base: Some(base.index),
        };
        let value = list_statement(
            positions,
            delta.list.source,
            Some(base.source),
            (reasons, finding),
            target,
            query,
            work,
        )?;
        statements.try_push(value).map_err(Error::Resource)?;
        delta.paired = true;
    }
    Ok(())
}

fn list_statement<'a, E: Work, V, D, R>(
    sources: Sources,
    list: Authenticated<'a, 'a>,
    base: Option<Authenticated<'a, 'a>>,
    (reasons, finding): (Reasons, Finding<'a>),
    target: &Certificate<'a>,
    query: &Query<'_>,
    current: &E,
) -> Result<Statement<'a>, V, D, R> {
    let work = &list.crl().execution_in(current);
    let tbs = list.crl().tbs();
    let retention = if matches!(finding, Finding::NotRevoked(_)) {
        tbs.expired_certs_on_crl(work).map_err(Error::Processing)?
    } else {
        None
    };
    let signed = [(tbs.this_update(), list.issuer())];
    let base_signed;
    let signed = if let Some(base) = base {
        base_signed = [signed[0], (base.crl().tbs().this_update(), base.issuer())];
        &base_signed[..]
    } else {
        &signed[..]
    };
    statement(
        sources,
        Authentication::Crl {
            signer: list.issuer(),
            base_signer: base.map(Authenticated::issuer),
        },
        tbs.this_update(),
        tbs.next_update(),
        reasons,
        finding,
        signed,
        target,
        retention,
        query,
        work,
    )
    .map_err(Error::Resource)
}

fn entry<'a, E: Work>(
    entry: EntryLookup<'_, 'a>,
    reasons: Reasons,
    work: &E,
) -> structured_pkix::Result<Finding<'a>> {
    Ok(match entry {
        EntryLookup::Absent => Finding::NotRevoked(reasons),
        EntryLookup::Found(entry) => Finding::Revoked(Revoked {
            at: entry.revocation_date(),
            reason: entry.reason(work)?,
        }),
        EntryLookup::Conflict { .. } => Finding::Unusable(Unusable::EntryConflict),
        EntryLookup::Unsupported { kind, span } => {
            Finding::Unusable(Unusable::UnsupportedCritical { kind, span })
        }
    })
}

fn combined<'a>(
    pair: BoundDelta<'_, '_, 'a>,
    entry: &CombinedEntry<'_, 'a>,
    target: &Certificate<'a>,
    (reasons, base_finding): (Reasons, Finding<'a>),
    query: &Query<'_>,
) -> Finding<'a> {
    let base = pair.base().crl().tbs().this_update();
    let delta = pair.delta().crl().tbs().this_update();
    let released_before = query
        .interval
        .lower
        .is_some_and(|lower| lower >= delta.instant());
    match entry {
        // A release only locates the end of a hold at or before this delta.
        // RFC 5280 §§5.2.4, 5.3.1:
        // https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
        CombinedEntry::Removed { .. } => match base_finding {
            Finding::Revoked(revoked) if revoked.on_hold() && released_before => {
                Finding::NotRevoked(reasons)
            }
            Finding::NotRevoked(_) if released_before || query.interval.upper <= base.instant() => {
                Finding::NotRevoked(reasons)
            }
            Finding::NotRevoked(_) if delta > target.tbs().validity().not_after() => {
                Finding::HeldOrRevoked {
                    after: base,
                    removed_by: delta,
                }
            }
            Finding::NotRevoked(_) => Finding::Suspended {
                after: base,
                released_by: delta,
            },
            finding => finding,
        },
        CombinedEntry::Absent => Finding::NotRevoked(reasons),
        CombinedEntry::Revoked { entry, reason, .. } => Finding::Revoked(Revoked {
            at: entry.revocation_date(),
            reason: Some(*reason),
        }),
        CombinedEntry::Conflict { .. } => Finding::Unusable(Unusable::EntryConflict),
        CombinedEntry::Unsupported { kind, span, .. } => {
            Finding::Unusable(Unusable::UnsupportedCritical {
                kind: *kind,
                span: *span,
            })
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "retain distinct original request, source, and operation inputs"
)]
#[expect(
    clippy::too_many_lines,
    reason = "keep signature, authority and target binding together for each original candidate"
)]
fn assess_response<'a, 'd, V, F, D, P, W, R, E>(
    path: &CheckedPath<'a>,
    member: usize,
    positions: Sources,
    response: &'a BasicResponse<'a>,
    request: &ocsp::Request<'_, 'a>,
    issuer: Option<(&'a Certificate<'a>, EffectiveKey<'a>)>,
    responders: &[Responder<'_, 'a>],
    query: &Query<'_>,
    context: &ValidationContext<'a, '_, P, W, R, E>,
    verifier: &V,
    digest: &'d D,
) -> Result<Statement<'a>, F, D::Error, R::Error>
where
    E: Work,
    V: for<'s> Verify<Execution<'s>, Error = F>,
    P: Verify<E, Error = F>,
    D: AsnDigest<'d> + ?Sized,
    W: Watch,
    R: Recognizer<E>,
{
    let work = &response.execution_in(context.execution);
    let produced = response.produced_at();
    let mut failure = unusable(positions, produced, Unusable::Authority);
    let Some((issuer, issuing_key)) = issuer else {
        return Ok(failure);
    };
    for responder in core::iter::once(Responder::Issuer).chain(responders.iter().copied()) {
        work.charge_work(1).map_err(Error::Resource)?;
        let (signer, key) = match responder {
            Responder::Issuer => (issuer, issuing_key),
            Responder::Configured { certificate, key } => (certificate, key),
            Responder::Delegate { path, .. } => {
                let Some(signer) = path.members().last() else {
                    continue;
                };
                (signer.certificate(), signer.key())
            }
        };
        let authentication = response
            .authenticate_signature(signer, key, verifier, digest, work)
            .map_err(|error| match error {
                ocsp::SignatureError::Processing(cause) => Error::Processing(cause),
                ocsp::SignatureError::Verification(cause) => Error::Verification(cause),
                ocsp::SignatureError::Digest(cause) => Error::Digest(cause),
            })?;
        let proof = match authentication {
            SignatureAuthentication::Signed(proof) => proof,
            rejected => {
                let cause = match rejected {
                    SignatureAuthentication::Rejected(cause) => Unusable::OcspAuthentication(cause),
                    SignatureAuthentication::UnsupportedSignature => Unusable::UnsupportedSignature,
                    SignatureAuthentication::UnsupportedDigest => {
                        Unusable::UnsupportedResponderDigest
                    }
                    SignatureAuthentication::Signed(_) => unreachable!(),
                };
                failure = unusable(positions, produced, cause);
                continue;
            }
        };
        // RFC 6960 §4.2.2.2 permits only the issuer, an explicit locally
        // configured responder, or a direct delegate of the actual issuer.
        // https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2
        let bound = match responder {
            Responder::Issuer => proof.bind_issuer(issuer, issuing_key, work),
            Responder::Configured { .. } => {
                Ok(AuthorityBinding::Bound(proof.trust_for_issuer(issuer)))
            }
            Responder::Delegate { .. } => {
                let at_production = ValidationContext {
                    interval: structured_pkix::path::Interval::at_instant(produced.instant()),
                    ..*context
                };
                let delegation = ocsp::check_delegate(signer, issuer, issuing_key, &at_production)
                    .map_err(|error| match error {
                        BuildError::Processing(cause) => Error::Processing(cause),
                        BuildError::Verification(cause) => Error::Verification(cause),
                        BuildError::Recognition(cause) => Error::Recognition(cause),
                    })?;
                let facts = match delegation {
                    ocsp::Delegation::Accepted(facts) => facts,
                    ocsp::Delegation::Incomplete(cause) => {
                        return Err(Error::DelegateIncomplete(cause));
                    }
                    ocsp::Delegation::Rejected(_) | ocsp::Delegation::PathRejected(_) => continue,
                };
                proof.bind_delegate(facts, work)
            }
        }
        .map_err(Error::Processing)?;
        let AuthorityBinding::Bound(scoped) = bound else {
            continue;
        };
        let time = ocsp::Evaluation {
            now: Reading::from(produced.instant()),
            utc: query.utc,
            execution: work,
        };
        let outcome = scoped
            .evaluate_with_target(request, &time, digest)
            .map_err(|error| match error {
                CallbackError::Processing(cause) => Error::Processing(cause),
                CallbackError::Callback(cause) => Error::Digest(cause),
            })?;
        let Some(evidence) = outcome.evidence() else {
            let cause = match outcome.outcome() {
                TargetEvidence::Lookup(lookup) => Unusable::Lookup(match lookup {
                    ocsp::Lookup::Missing => LookupFailure::Missing,
                    ocsp::Lookup::Found(_) | ocsp::Lookup::Ambiguous { .. } => {
                        LookupFailure::Ambiguous
                    }
                    ocsp::Lookup::UnsupportedHash(_) => LookupFailure::UnsupportedHash,
                    ocsp::Lookup::MalformedHashWidth(_)
                    | ocsp::Lookup::MalformedHashAlgorithm(_) => LookupFailure::MalformedHash,
                }),
                TargetEvidence::UnsupportedCritical { kind, span } => {
                    Unusable::UnsupportedCritical {
                        kind: *kind,
                        span: *span,
                    }
                }
                TargetEvidence::UnexpectedSigner => Unusable::UnexpectedSigner,
                TargetEvidence::AttributeDelegation
                | TargetEvidence::NoRevAvail
                | TargetEvidence::Evidence(_) => Unusable::Authority,
            };
            failure = unusable(positions, produced, cause);
            continue;
        };
        let OcspBinding::Bound(bound) = path
            .bind_ocsp(member, &evidence, work)
            .map_err(Error::OcspBinding)?
        else {
            continue;
        };
        let evidence = evidence.evidence();
        if let Responder::Delegate { path, revocation } = responder {
            let ResponderBinding::Bound(proof) = bound
                .bind_responder_path(path, query.utc, work)
                .map_err(Error::Responder)?
            else {
                continue;
            };
            // RFC 6960 §4.2.2.2.1: a configured exception is distinct from
            // proof of good status and cannot exempt an unrelated certificate.
            if proof.revocation() != ocsp::ResponderRevocation::NoCheck
                && !revocation.is_some_and(|assessment| {
                    core::ptr::eq(assessment.path, path)
                        && assessment.member + 1 == path.members().len()
                        && assessment.interval.upper == produced.instant()
                        && assessment.now == query.now
                        && matches!(assessment.status, Status::NotRevoked { .. })
                })
            {
                failure = unusable(positions, produced, Unusable::ResponderRevocationUnchecked);
                continue;
            }
        }
        let finding = if matches!(
            evidence.nonce(),
            ocsp::NonceBinding::Missing | ocsp::NonceBinding::Differs
        ) {
            Finding::Unusable(Unusable::Nonce(evidence.nonce()))
        } else {
            match evidence.status() {
                ocsp::Status::Good => Finding::NotRevoked(Reasons::ALL),
                ocsp::Status::NotIssued => Finding::NotIssued,
                ocsp::Status::Revoked { time, reason } => {
                    Finding::Revoked(Revoked { at: time, reason })
                }
                ocsp::Status::Unknown => Finding::Unknown,
            }
        };
        let assertion = evidence.assertion();
        let value = statement(
            positions,
            Authentication::Ocsp {
                signer,
                authority: scoped.source(),
                assertion,
            },
            assertion.this_update(),
            assertion.next_update(),
            Reasons::ALL,
            finding,
            &[(produced, signer)],
            request.target,
            evidence.archive_cutoff(),
            query,
            work,
        )
        .map_err(Error::Resource)?;
        if value.speaks() {
            return Ok(value);
        }
        failure = value;
    }
    Ok(failure)
}

fn unusable(sources: Sources, time: Time, cause: Unusable<'_>) -> Statement<'_> {
    Statement {
        sources,
        authentication: None,
        issued: time,
        released: time,
        next_update: None,
        reasons: Reasons::NONE,
        finding: Finding::Unusable(cause),
        freshness: Freshness::NoNextUpdate,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "each input is one fact of the original evidence"
)]
fn statement<'a, E: Work>(
    sources: Sources,
    authentication: Authentication<'a>,
    issued: Time,
    next_update: Option<Time>,
    reasons: Reasons,
    finding: Finding<'a>,
    signed: &[(Time, &Certificate<'_>)],
    target: &Certificate<'_>,
    retention: Option<Reading>,
    query: &Query<'_>,
    work: &E,
) -> core::result::Result<Statement<'a>, structured_asn1::memory::MemoryError> {
    let released = signed.iter().map(|(time, _)| *time).max().unwrap_or(issued);
    let expiry = target.tbs().validity().not_after();
    let finding = if matches!(finding, Finding::NotApplicable(_) | Finding::Unusable(_)) {
        finding
    } else if signed
        .iter()
        .any(|(time, signer)| !signer.tbs().validity().contains(*time))
    {
        // EN 319 102-1 V1.4.1 §5.2.6.4 step 4.
        Finding::Unusable(Unusable::IssuedOutsideSignerValidity)
    } else if issued.instant() > query.now || released.instant() > query.now {
        // RFC 6960 §4.2.2.1. The caller supplies the assessment time.
        Finding::Unusable(Unusable::IssuedAfterNow)
    } else if matches!(finding, Finding::NotRevoked(_))
        && released > expiry
        && !retention.is_some_and(|cutoff| {
            cutoff.start() < expiry.instant()
                || (cutoff.start() == expiry.instant() && !cutoff.has_subnanosecond_remainder())
        })
    {
        // RFC 5280 §3.3: CRLs can drop expired entries. X.509 §8.5.2.12
        // and RFC 6960 §4.4.4 give explicit historical retention.
        Finding::Unusable(Unusable::IssuedAfterTargetExpiry)
    } else {
        finding
    };
    let usable = finding.knows() || matches!(finding, Finding::Unknown);
    let (reasons, freshness) = if usable {
        // Each UTC shift uses at most three binary searches of the table.
        let bits = usize::BITS - query.utc.transitions().len().leading_zeros();
        work.charge_work(24 + 6 * (u64::from(bits) + 1))?;
        (reasons, freshness(issued, next_update, query))
    } else {
        (Reasons::NONE, Freshness::NoNextUpdate)
    };
    Ok(Statement {
        sources,
        authentication: Some(authentication),
        issued,
        released,
        next_update,
        reasons,
        finding,
        freshness,
    })
}

/// EN 319 102-1 V1.4.1 §5.2.5.4 steps 1 and 2 and NOTE 3.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
fn freshness(issued: Time, next: Option<Time>, query: &Query<'_>) -> Freshness {
    if let Err(cause) = query.utc.shift(issued.instant(), 0) {
        return Freshness::Uncertain(cause);
    }
    let upper = query.interval.upper;
    if let Some(seconds) = query.max_freshness_seconds {
        let nanos = i128::from(seconds) * 1_000_000_000;
        return match query.utc.shift(upper, -nanos) {
            Ok(threshold) if issued.instant() > threshold => Freshness::Fresh,
            Ok(_) => Freshness::Stale,
            Err(cause) => Freshness::Uncertain(cause),
        };
    }
    let Some(next) = next else {
        return Freshness::NoNextUpdate;
    };
    if let Err(cause) = query.utc.shift(next.instant(), 0) {
        return Freshness::Uncertain(cause);
    }
    if next < issued {
        Freshness::ReversedUpdateInterval
    } else if upper < next.instant() {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}
