use super::{
    Candidate, CryptoObject, Decision, Error, Horizon, Member, PastCertificate, PastSignature,
    RetryCause, Revocation, RevocationData, Signature, SubIndication as Sub, ValidityModel,
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
    member: &'a Member<'a>,
    horizon: Horizon,
    target: bool,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<Option<RecordChoice<'a>>, Error> {
    if !proofs.by(member.object, horizon, work)? {
        return Ok(None);
    }
    let mut selected: Option<RecordChoice<'_>> = None;
    let mut conflict = false;
    for record in member.revocations {
        work.charge_work(16)?;
        if record.issued >= horizon.time() || !proofs.by(record.object, horizon, work)? {
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
        // Only independently reliable records compete for selection. A newer
        // record without historical proof cannot hide an older usable record.
        if let Some(delegated) = record.delegated {
            if !proofs.by(record.object, delegated, work)? {
                continue;
            }
            candidate.horizon.tighten(delegated);
        }
        if !slide_crypto(record.crypto, &mut candidate.horizon, proofs, crypto, work)? {
            continue;
        }
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
    Ok(if conflict { None } else { selected })
}

fn slide_crypto<W: Work>(
    objects: &[CryptoObject],
    horizon: &mut Horizon,
    proofs: &Proofs<W>,
    crypto: &Crypto<'_>,
    work: &W,
) -> Result<bool, Error> {
    for item in objects {
        match crypto.sunset(item.material, work)? {
            Ok(Some(at)) => {
                let limit = Horizon::Before(at);
                // 5.6.2.1.1: the authenticated bound for this exact
                // object has to predate loss of reliability.
                if !proofs.by(item.object, limit, work)? {
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
) -> Result<Option<(Horizon, bool)>, Error> {
    let mut horizon = Horizon::Through(now);
    if let Some(sunset) = path.anchor_sunset {
        horizon.tighten(Horizon::Before(sunset));
    }
    let mut issuer_poe = false;
    for (i, member) in path.members.iter().enumerate() {
        work.charge_work(10)?;
        let Some(choice) = choose(
            member,
            horizon,
            i == path.members.len() - 1,
            proofs,
            crypto,
            work,
        )?
        else {
            return Ok(None);
        };
        let record = choice.record;
        issuer_poe = choice.issuer_poe;
        match record.status {
            Revocation::Revoked { at, reason } => {
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
        if !slide_crypto(member.crypto, &mut horizon, proofs, crypto, work)? {
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
    };
    let mut first_valid = None;
    for (index, path) in signature.candidates.iter().enumerate() {
        work.charge_work(6)?;
        let sub = if !path.recognized || path.chain == Chain::GeneralFailure {
            Sub::CertificateChainGeneralFailure
        } else if let Some((horizon, issuer_poe)) =
            slide(path, now, signature.model, proofs, crypto, work)?
        {
            if path.chain == Chain::Valid {
                let candidate = PastCertificate::Passed {
                    path: index,
                    horizon,
                };
                // A path can validate historically yet be unusable for this
                // signature (EN 319 102-1 5.6.2.4.4 step 3). Keep the first
                // valid path for diagnostics and try the remaining candidates.
                if signature_proof.is_none_or(|at| horizon.admits(at)) {
                    return Ok((candidate, Some(issuer_poe)));
                }
                first_valid.get_or_insert((candidate, Some(issuer_poe)));
                continue;
            }
            Sub::ChainConstraintsFailure
        } else {
            Sub::NoPoe
        };
        result = PastCertificate::Finding {
            sub,
            path: Some(index),
        };
    }
    Ok(first_valid.unwrap_or((result, None)))
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
    work: &W,
) -> Result<bool, Error> {
    if let Some(at) = signature.revoked_ca_at {
        for record in signature.revocations {
            work.charge_work(1)?;
            if proofs.by(record.object, Horizon::Through(at), work)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
    };
    let Decision::Finding(sub) = current else {
        return Ok(report);
    };
    // Clause 5.6.2.4 has no recovery rule for other findings.
    if !matches!(
        sub,
        Sub::NoCertificateChainFoundNoPoe
            | Sub::RevokedNoPoe
            | Sub::RevocationOutOfBoundsNoPoe
            | Sub::RevokedCaNoPoe
            | Sub::OutOfBoundsNoPoe
            | Sub::OutOfBoundsNotRevoked
            | Sub::CryptoConstraintsFailureNoPoe
            | Sub::TryLater
    ) {
        return Ok(report);
    }
    let best = proofs.earliest(signature.value, work)?;
    let (cert, issuer_poe) = certificate(signature, now, best, proofs, crypto, work)?;
    report.revocation_poe = issuer_poe;
    report.certificate = Some(cert);
    let PastCertificate::Passed { horizon, .. } = cert else {
        return Ok(report);
    };
    let by_horizon = best.is_some_and(|at| horizon.admits(at));
    report.signature_poe = Some(by_horizon);
    let Some(best) = best.filter(|_| by_horizon) else {
        return Ok(report);
    };
    let validity = signature.validity;
    let clear = if issuer_poe == Some(true) {
        Decision::Passed
    } else {
        Decision::Finding(Sub::RevocationOutOfBoundsNoPoe)
    };
    if sub == Sub::CryptoConstraintsFailureNoPoe
        && validity.contains(best)
        && all_algorithm_proofs(signature.affected_crypto, proofs, crypto, work)?
    {
        report.decision = clear;
        return Ok(report);
    }
    if sub == Sub::TryLater
        && let RetryCause::Freshness(record) = signature.retry
    {
        if validity.contains(best) && record.fresh_before.is_some_and(|end| best < end) {
            report.decision = clear;
        }
        return Ok(report);
    }
    report.decision = match sub {
        Sub::RevokedCaNoPoe => {
            if !ca_revocation_proof(signature, proofs, work)? {
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
            if sub != Sub::TryLater || matches!(signature.retry, RetryCause::Suspension) =>
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
    Ok(report)
}
