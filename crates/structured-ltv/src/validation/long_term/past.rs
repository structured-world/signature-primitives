use super::{
    Candidate, CryptoObject, Decision, Error, Horizon, Object, PastCertificate, PastSignature,
    RetryCause, Revocation, RevocationCheck, RevocationData, Signature, SubIndication as Sub,
    ValidityModel,
    poe::{Crypto, Proofs},
};
use crate::validation::Chain;
use structured_asn1::memory::Work;
use structured_pkix::{crl::Reason, temporal::Instant};

fn usable<W: Work>(
    record: &RevocationData<'_>,
    proofs: &Proofs<W>,
    work: &W,
) -> Result<bool, Error> {
    proofs.between(
        record.issuer,
        record.issuer_validity.not_before,
        Horizon::Before(record.issuer_validity.not_after),
        work,
    )
}

fn base_eligible<W: Work>(
    record: &RevocationData<'_>,
    horizon: &mut Horizon,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
    missing: &mut Option<Object>,
) -> Result<bool, Error> {
    let Some(base) = record.base else {
        return Ok(true);
    };
    // RFC 5280 §5.2.4 requires the complete CRL to interpret a delta.
    // EN 319 102-1 V1.4.1 §5.6.2.1.1 requires historical reliability
    // of the evidence used. A delta receipt cannot prove its base existed.
    // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.4
    if !proofs.by(base.object, *horizon, work)? {
        missing.get_or_insert(base.object);
        return Ok(false);
    }
    if !proofs.between(
        base.issuer,
        base.issuer_validity.not_before,
        Horizon::Before(base.issuer_validity.not_after),
        work,
    )? {
        missing.get_or_insert(base.issuer);
        return Ok(false);
    }
    if let Some(delegated) = base.delegated {
        if !proofs.by(base.object, delegated, work)? {
            missing.get_or_insert(base.object);
            return Ok(false);
        }
        horizon.tighten(delegated);
    }
    slide_crypto(base.crypto, horizon, proofs, crypto, work, missing)
}

fn permanent_revocation(status: Revocation) -> bool {
    // RFC 5280 §5.2.4 permits release from certificateHold. The caller
    // supplies only authenticated status applicable to this certificate.
    matches!(status, Revocation::Revoked { reason, .. } if reason != Some(Reason::CertificateHold))
}

struct RecordChoice<'a> {
    record: &'a RevocationData<'a>,
    horizon: Horizon,
    issuer_poe: bool,
}

impl RecordChoice<'_> {
    fn rank(&self) -> (bool, bool, Instant) {
        (
            self.issuer_poe,
            permanent_revocation(self.record.status),
            self.record.issued,
        )
    }
}

fn choose<'a, W: Work>(
    records: &'a [RevocationData<'a>],
    horizon: Horizon,
    target: bool,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
    missing: &mut Option<Object>,
) -> Result<Option<RecordChoice<'a>>, Error> {
    let mut selected: Option<RecordChoice<'_>> = None;
    let mut conflict = false;
    for record in records {
        work.charge_work(16)?;
        if record.issued >= horizon.time() {
            continue;
        }
        if !proofs.by(record.object, horizon, work)? {
            missing.get_or_insert(record.object);
            continue;
        }
        // 5.6.2.4.4 step 1 filters target evidence if issuer proof exists.
        // Otherwise the certificate block can still report its own result.
        let mut candidate = RecordChoice {
            record,
            horizon,
            issuer_poe: target && usable(record, proofs, work)?,
        };
        let rank = candidate.rank();
        if selected.as_ref().is_some_and(|best| best.rank() > rank) {
            continue;
        }
        // Historical eligibility requires evidence of reliability (EN 319
        // 102-1 V1.4.1 §5.6.2.1.1). For a delegated issuer, §5.6.2.2.4
        // NOTE 5 leaves the combination to the implementation. Require
        // proof within that issuer's limit before ranking the record.
        if let Some(delegated) = record.delegated {
            if !proofs.by(record.object, delegated, work)? {
                missing.get_or_insert(record.object);
                continue;
            }
            candidate.horizon.tighten(delegated);
        }
        if !base_eligible(
            record,
            &mut candidate.horizon,
            proofs,
            crypto,
            work,
            missing,
        )? || !slide_crypto(
            record.crypto,
            &mut candidate.horizon,
            proofs,
            crypto,
            work,
            missing,
        )? {
            continue;
        }
        // EN 319 102-1 V1.4.1 §5.6.2.2.4 steps 2(c) and 2(d) select
        // the latest eligible clear record and then apply its crypto limit.
        // A shorter horizon does not make that record ineligible.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf
        if let Some(previous) = &selected
            && previous.rank() == rank
        {
            if previous.record.status != record.status {
                conflict = true;
            } else if candidate.horizon.admits(previous.horizon.time())
                && !previous.horizon.admits(candidate.horizon.time())
            {
                selected = Some(candidate);
            }
            continue;
        }
        selected = Some(candidate);
        conflict = false;
    }
    if conflict {
        *missing = None;
        return Ok(None);
    }
    Ok(selected)
}

fn slide_crypto<W: Work>(
    objects: &[CryptoObject],
    horizon: &mut Horizon,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
    missing: &mut Option<Object>,
) -> Result<bool, Error> {
    for item in objects {
        match crypto.sunset(item.material, work)? {
            Ok(Some(at)) => {
                let limit = Horizon::Before(at);
                // 5.6.2.1.1: the authenticated bound for this exact
                // object has to predate loss of reliability.
                if !proofs.by(item.object, limit, work)? {
                    missing.get_or_insert(item.object);
                    return Ok(false);
                }
                horizon.tighten(limit);
            }
            Ok(None) => {}
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}

/// EN 319 102-1 V1.4.1 5.6.2.2.4, with the revocation authentication
/// context and applicability already decided by the evidence producer.
fn slide<W: Work>(
    path: &Candidate<'_>,
    now: Instant,
    model: ValidityModel,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
    missing: &mut Option<Object>,
) -> Result<Option<(Horizon, Option<bool>)>, Error> {
    let mut horizon = Horizon::Through(now);
    if let Some(sunset) = path.anchor_sunset {
        horizon.tighten(Horizon::Before(sunset));
    }
    let mut issuer_poe = Some(false);
    for (i, member) in path.members.iter().enumerate() {
        work.charge_work(10)?;
        if !proofs.by(member.object, horizon, work)? {
            *missing = Some(member.object);
            return Ok(None);
        }
        // EN 319 102-1 V1.4.1 §5.1.4.1 permits an explicit revocation
        // waiver. The member still needs proof and cryptographic checks.
        let RevocationCheck::Required(records) = member.revocations else {
            issuer_poe = None;
            if !slide_crypto(member.crypto, &mut horizon, proofs, crypto, work, missing)? {
                return Ok(None);
            }
            continue;
        };
        let mut missing_record = None;
        let Some(choice) = choose(
            records,
            horizon,
            i == path.members.len() - 1,
            proofs,
            crypto,
            work,
            &mut missing_record,
        )?
        else {
            *missing = missing_record;
            return Ok(None);
        };
        let record = choice.record;
        issuer_poe = Some(choice.issuer_poe);
        match record.status {
            Revocation::Revoked { at, reason } => {
                // EN 319 102-1 §5.6.2.2.4 step 2(b) refers to key
                // compromise. RFC 5280 §5.3.1 also names CA and AA causes.
                if model == ValidityModel::Shell
                    || matches!(
                        reason,
                        None | Some(
                            Reason::Unspecified
                                | Reason::KeyCompromise
                                | Reason::AuthorityCompromise
                                | Reason::AttributeAuthorityCompromise
                        )
                    )
                {
                    horizon.tighten(Horizon::Before(at));
                }
            }
            Revocation::Clear => {
                if !record
                    .fresh_before
                    .is_some_and(|end| horizon.time() < end || horizon == Horizon::Before(end))
                {
                    horizon.tighten(Horizon::Through(record.issued));
                }
            }
        }
        horizon.tighten(choice.horizon);
        if !slide_crypto(member.crypto, &mut horizon, proofs, crypto, work, missing)? {
            return Ok(None);
        }
    }
    horizon.tighten(Horizon::Through(path.validity.not_after));
    Ok(horizon
        .admits(path.validity.not_before)
        .then_some((horizon, issuer_poe)))
}

fn certificate<W: Work>(
    signature: &Signature<'_>,
    now: Instant,
    signature_proof: Option<Instant>,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<(PastCertificate, Option<bool>), Error> {
    let mut result = PastCertificate::Finding {
        sub: Sub::NoCertificateChainFound,
        path: None,
        missing_proof: None,
    };
    let mut fallback: Option<(PastCertificate, Option<bool>, bool)> = None;
    for (index, path) in signature.candidates.iter().enumerate() {
        work.charge_work(6)?;
        // A current direct-trust decision carries no historical path proof.
        if path.chain == Chain::DirectTrust {
            continue;
        }
        let mut missing_proof = None;
        let sub = if !path.recognized || path.chain == Chain::GeneralFailure {
            Sub::CertificateChainGeneralFailure
        } else if let Some((horizon, issuer_poe)) = slide(
            path,
            now,
            signature.model,
            proofs,
            crypto,
            work,
            &mut missing_proof,
        )? {
            if path.chain == Chain::Valid {
                let candidate = PastCertificate::Passed {
                    path: index,
                    horizon,
                };
                // Historical validity, signature proof and issuer proof are
                // separate requirements (EN 319 102-1 5.6.2.4.4).
                let covers = signature_proof.is_none_or(|at| horizon.admits(at));
                if covers && issuer_poe != Some(false) {
                    return Ok((candidate, issuer_poe));
                }
                if fallback.is_none_or(|(_, _, covered)| covers && !covered) {
                    fallback = Some((candidate, issuer_poe, covers));
                }
                continue;
            }
            Sub::ChainConstraintsFailure
        } else {
            Sub::NoPoe
        };
        result = PastCertificate::Finding {
            sub,
            path: Some(index),
            missing_proof,
        };
    }
    Ok(fallback.map_or((result, None), |(path, issuer_poe, _)| (path, issuer_poe)))
}

fn all_algorithm_proofs<W: Work>(
    objects: &[CryptoObject],
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<bool, Error> {
    if objects.is_empty() {
        return Ok(false);
    }
    for item in objects {
        let Some(at) = proofs.earliest(item.object, work)? else {
            return Ok(false);
        };
        if crypto.assess(item.material, at, None, work)?.is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ca_revocation_proof<W: Work>(
    signature: &Signature<'_>,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<bool, Error> {
    if let Some(at) = signature.revoked_ca_at {
        for record in signature.revocations {
            work.charge_work(1)?;
            let mut horizon = Horizon::Through(at);
            if proofs.by(record.object, horizon, work)?
                && base_eligible(record, &mut horizon, proofs, crypto, work, &mut None)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn retry_suggestion(retry: RetryCause<'_>, decision: Decision) -> Option<Instant> {
    if decision != Decision::Finding(Sub::TryLater) {
        return None;
    }
    match retry {
        RetryCause::Freshness { retry_at, .. } | RetryCause::Suspension { retry_at } => retry_at,
        RetryCause::Other => None,
    }
}

fn fresh_at_signing<W: Work>(
    record: &RevocationData<'_>,
    best: Option<Instant>,
    now: Instant,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<bool, Error> {
    let Some((best, end)) = best.zip(record.fresh_before) else {
        return Ok(false);
    };
    if best >= end {
        return Ok(false);
    }
    // EN 319 102-1 §5.6.2.4.4 step 5 checks freshness at best-signature-time.
    // The base must pass its own historical evidence limits independently.
    base_eligible(
        record,
        &mut Horizon::Through(now),
        proofs,
        crypto,
        work,
        &mut None,
    )
}

fn recoverable(sub: Sub) -> bool {
    // EN 319 102-1 §5.6.2.4.4 steps 3 to 6.
    matches!(
        sub,
        Sub::NoCertificateChainFoundNoPoe
            | Sub::RevokedNoPoe
            | Sub::RevocationOutOfBoundsNoPoe
            | Sub::RevokedCaNoPoe
            | Sub::OutOfBoundsNoPoe
            | Sub::OutOfBoundsNotRevoked
            | Sub::CryptoConstraintsFailureNoPoe
            | Sub::TryLater
    )
}

pub(super) fn signature<W: Work>(
    signature: &Signature<'_>,
    current: Decision,
    now: Instant,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<PastSignature, Error> {
    let mut report = PastSignature {
        decision: current,
        certificate: None,
        signature_poe: None,
        revocation_poe: None,
        retry_at: retry_suggestion(signature.retry, current),
    };
    let Decision::Finding(sub) = current else {
        return Ok(report);
    };
    if !recoverable(sub) {
        return Ok(report);
    }
    let best = proofs.earliest(signature.value, work)?;
    // EN 319 102-1 V1.4.1 §5.6.2.4.4: steps 4 and 5 have their own
    // predicates and do not depend on the signature-proof gate at step 3.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf
    let uses_step_three = sub != Sub::CryptoConstraintsFailureNoPoe
        && !matches!(
            (sub, signature.retry),
            (Sub::TryLater, RetryCause::Freshness { .. })
        );
    let path_proof = if uses_step_three { best } else { None };
    let (cert, issuer_poe) = certificate(signature, now, path_proof, proofs, crypto, work)?;
    report.revocation_poe = issuer_poe;
    report.certificate = Some(cert);
    let PastCertificate::Passed { horizon, .. } = cert else {
        return Ok(report);
    };
    let by_horizon = best.is_some_and(|at| horizon.admits(at));
    report.signature_poe = Some(by_horizon);
    let clear = if issuer_poe == Some(false) {
        Decision::Finding(Sub::RevocationOutOfBoundsNoPoe)
    } else {
        Decision::Passed
    };
    if sub == Sub::CryptoConstraintsFailureNoPoe
        && all_algorithm_proofs(signature.affected_crypto, proofs, crypto, work)?
    {
        report.decision = clear;
        return Ok(report);
    }
    if sub == Sub::TryLater
        && let RetryCause::Freshness { record, .. } = signature.retry
    {
        if fresh_at_signing(record, best, now, proofs, crypto, work)? {
            report.decision = clear;
            report.retry_at = None;
        }
        return Ok(report);
    }
    let Some(best) = best.filter(|_| by_horizon) else {
        return Ok(report);
    };
    let validity = signature.validity;
    report.decision = match sub {
        Sub::RevokedCaNoPoe => {
            if !ca_revocation_proof(signature, proofs, crypto, work)? {
                current
            } else if validity.contains(best) {
                clear
            } else {
                Decision::Finding(Sub::OutOfBoundsNotRevoked)
            }
        }
        Sub::NoCertificateChainFoundNoPoe
        | Sub::RevokedNoPoe
        | Sub::RevocationOutOfBoundsNoPoe
        | Sub::OutOfBoundsNoPoe
        | Sub::OutOfBoundsNotRevoked
        | Sub::TryLater
            if sub != Sub::TryLater || matches!(signature.retry, RetryCause::Suspension { .. }) =>
        {
            if best < validity.not_before {
                Decision::Finding(Sub::NotYetValid)
            } else if matches!(sub, Sub::OutOfBoundsNoPoe | Sub::OutOfBoundsNotRevoked) {
                if validity.not_before < best && best < validity.not_after {
                    clear
                } else {
                    current
                }
            } else if validity.contains(best) {
                clear
            } else if sub == Sub::NoCertificateChainFoundNoPoe {
                Decision::Finding(Sub::OutOfBoundsNoPoe)
            } else {
                Decision::Finding(Sub::OutOfBoundsNotRevoked)
            }
        }
        _ => current,
    };
    if report.decision != Decision::Finding(Sub::TryLater) {
        report.retry_at = None;
    }
    Ok(report)
}
