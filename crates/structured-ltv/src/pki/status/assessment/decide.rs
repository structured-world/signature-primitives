//! Join authenticated evidence across the eight RFC 5280 reason partitions.

use super::{ExpiryEvidence, Finding, Freshness, Query, Revoked, Statement, Status, When};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::{
    Time,
    crl::{Reason, Reasons},
    temporal::Instant,
};

type Result<T> = core::result::Result<T, MemoryError>;

pub(super) fn decide<E: Work>(
    statements: &[Statement<'_>],
    query: &Query<'_>,
    expiry: Time,
    subordinate: Option<Instant>,
    execution: &E,
) -> Result<(Status, ExpiryEvidence)> {
    let deciders = deciders(statements, execution)?;
    // Nothing is compared with the interval when no source speaks.
    if deciders.iter().all(Option::is_none) {
        return Ok((Status::NoEvidence, ExpiryEvidence::Unestablished));
    }
    let bits = usize::BITS - query.utc.transitions().len().leading_zeros();
    let shift_work = 8 + 3 * (u64::from(bits) + 1);
    execution.charge_work(3 * shift_work)?;
    for label in [
        Some(query.interval.upper),
        Some(query.now),
        query.interval.lower,
    ]
    .into_iter()
    .flatten()
    {
        if let Err(reason) = query.utc.shift(label, 0) {
            return Ok((Status::Uncertain(reason), ExpiryEvidence::Unestablished));
        }
    }
    // Equally recent sources that say different things about the same reason
    // leave no single answer for it; neither is the reader's to pick.
    let (conflict, conflicted) = conflicts(statements, &deciders, query, execution)?;
    // A certificate revoked for one reason is revoked, whatever other
    // reasons say, so the deciders' answers are joined by severity. Not
    // revoked holds only where fresh deciders cover every reason together.
    // A reason in conflict has no decider to join. Uncertainty joins at the
    // rank of the worst answer it may hide, so it never hides a proven one.
    let mut severest: Option<Ranked> = None;
    let mut clear: Option<Ranked> = None;
    let mut covered = Reasons::NONE;
    let mut retained = 0;
    for (position, basis) in deciders.iter().enumerate() {
        let Some(basis) = *basis else { continue };
        if conflicted[position] {
            continue;
        }
        let latest = statements[basis];
        // Only the actual decider for this reason establishes post-expiry
        // coverage. A newer pre-expiry or conflicting assertion cannot
        // borrow coverage from another reason's retained source.
        if latest.issued > expiry
            && latest.freshness == Freshness::Fresh
            && matches!(latest.finding, Finding::NotRevoked(_))
        {
            retained |= 1 << (position + 1);
        }
        // Each decider is judged once, however many reasons it decides.
        let seen = deciders[..position]
            .iter()
            .zip(&conflicted)
            .any(|(earlier, conflicted)| !conflicted && *earlier == Some(basis));
        if seen {
            continue;
        }
        execution.charge_work(if subordinate.is_some() {
            2 * shift_work
        } else {
            shift_work
        })?;
        let Some(candidate) = judge(basis, latest, query, subordinate) else {
            continue;
        };
        let slot = if let Status::NotRevoked { .. } = candidate.status {
            covered = covered.union(latest.reasons);
            &mut clear
        } else {
            &mut severest
        };
        *slot = Some(match *slot {
            Some(current) if !outranks(candidate, current, statements) => current,
            _ => candidate,
        });
    }
    // A hold proven inside the interval stays proven when newer sources
    // drop it, as it does across a delta that removes it.
    for (index, statement) in statements.iter().enumerate() {
        execution.charge_work(1)?;
        if deciders.contains(&Some(index)) {
            continue;
        }
        if matches!(statement.finding, Finding::Revoked(revoked) if revoked.on_hold()) {
            execution.charge_work(shift_work)?;
        }
        if let Some(candidate) = persisting(index, *statement, query) {
            severest = Some(match severest {
                Some(current) if !outranks(candidate, current, statements) => current,
                _ => candidate,
            });
        }
    }
    // Disagreement about other reasons cannot undo a revocation proven for
    // one (RFC 5280 6.3.3); any other answer it could change is a conflict.
    if let Some(conflict) = conflict
        && !matches!(
            severest,
            Some(Ranked {
                status: Status::Revoked { .. },
                ..
            })
        )
    {
        return Ok((conflict, ExpiryEvidence::Unestablished));
    }
    let status = joined_status(severest, clear, covered);
    let expiry_evidence =
        if matches!(status, Status::NotRevoked { .. }) && retained == Reasons::ALL.bits() {
            ExpiryEvidence::RetainedStatus
        } else {
            ExpiryEvidence::Unestablished
        };
    Ok((status, expiry_evidence))
}

fn joined_status(severest: Option<Ranked>, clear: Option<Ranked>, covered: Reasons) -> Status {
    match (severest, clear) {
        (None, None) => Status::NoEvidence,
        // Some reasons are known clear and the rest only unknown.
        (
            Some(Ranked {
                status: Status::Unknown { .. },
                ..
            }),
            Some(Ranked { basis, .. }),
        ) => Status::PartialReasons { basis, covered },
        // A list scoped to some reasons covers those only; no fresh source
        // covers the rest (RFC 5280 6.3.3).
        (None, Some(Ranked { basis, .. })) if !covered.is_complete() => {
            Status::PartialReasons { basis, covered }
        }
        (Some(Ranked { status, .. }), _) | (None, Some(Ranked { status, .. })) => status,
    }
}

/// What one deciding statement answers, and the severity it joins at.
fn judge(
    basis: usize,
    latest: Statement<'_>,
    query: &Query<'_>,
    subordinate: Option<Instant>,
) -> Option<Ranked> {
    let (status, rank) = match latest.finding {
        Finding::NotIssued => (Status::NotIssued { basis }, Rank::NotIssued),
        Finding::Revoked(revoked) => match query.utc.shift(revoked.at.instant(), 0) {
            // An unplaced date may be a revocation the interval reaches.
            Err(reason) => (Status::Uncertain(reason), Rank::UnplacedRevocation),
            Ok(_) => match revocation(basis, latest, revoked, query, subordinate) {
                status @ Status::Uncertain(_) => (status, Rank::UnplacedFreshness),
                status => (status, Rank::of(status)),
            },
        },
        Finding::Unknown => (Status::Unknown { basis }, Rank::Unknown),
        // The suspension may cover the signature (5.2.6.4 step 4c).
        Finding::Suspended { .. } => (Status::OnHold { basis }, Rank::OnHold),
        Finding::HeldOrRevoked { .. } => (Status::HeldOrRevoked { basis }, Rank::HeldOrRevoked),
        // Only an answer without a revocation or hold asks the freshness
        // checker (5.2.6.4 step 4a); unplaced, it is fresh or not fresh.
        Finding::NotRevoked(_) => match latest.freshness {
            Freshness::Fresh => (Status::NotRevoked { basis, later: None }, Rank::Clear),
            Freshness::Uncertain(reason) => (Status::Uncertain(reason), Rank::UnplacedFreshness),
            Freshness::Stale | Freshness::NoNextUpdate | Freshness::ReversedUpdateInterval => {
                (Status::NotFresh { basis }, Rank::NotFresh)
            }
        },
        // A decider speaks, so it neither fails to apply nor is unusable.
        Finding::NotApplicable(_) | Finding::Unusable(_) => return None,
    };
    Some(Ranked {
        basis,
        status,
        rank,
    })
}

/// A decider's answer with the severity it joins at.
#[derive(Clone, Copy)]
struct Ranked {
    basis: usize,
    status: Status,
    rank: Rank,
}

/// Severity of one reason's answer, least first. An uncertain answer ranks
/// as the worst answer it may stand for: unplaced freshness is not revoked or
/// not fresh, an unplaced revocation date may be a revocation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Clear,
    Unknown,
    UnplacedFreshness,
    NotFresh,
    OnHold,
    HeldOrRevoked,
    UnplacedRevocation,
    Revoked,
    NotIssued,
}

impl Rank {
    fn of(status: Status) -> Self {
        match status {
            Status::NotIssued { .. } => Self::NotIssued,
            Status::Revoked { .. } => Self::Revoked,
            Status::HeldOrRevoked { .. } => Self::HeldOrRevoked,
            Status::OnHold { .. } => Self::OnHold,
            Status::NotFresh { .. } => Self::NotFresh,
            Status::Unknown { .. } => Self::Unknown,
            Status::Uncertain(_) => Self::UnplacedFreshness,
            Status::NotRevoked { .. }
            | Status::PartialReasons { .. }
            | Status::Conflict { .. }
            | Status::NoEvidence => Self::Clear,
        }
    }
}

/// `ReasonFlags` positions RFC 5280 6.3.3 accumulates: keyCompromise (1)
/// through aACompromise (8), the eight `Reasons::ALL` holds.
const REASONS: usize = 8;

/// For each reason, the latest issued statement that speaks for it
/// (5.2.6.4 step 4, NOTE 4). A list partitioned by reason speaks for its own
/// reasons only (RFC 5280 6.3.3 (b)(2)(i), (k)), so a newer list for other
/// reasons does not displace it. An unknown answer decides a reason only
/// when no source knows its status (RFC 6960 2.2).
fn deciders<E: Work>(
    statements: &[Statement<'_>],
    execution: &E,
) -> Result<[Option<usize>; REASONS]> {
    let mut known = [None::<usize>; REASONS];
    let mut unknown = [None::<usize>; REASONS];
    for (index, statement) in statements.iter().enumerate() {
        execution.charge_work(1)?;
        if !statement.speaks() {
            continue;
        }
        let slots = if statement.knows() {
            &mut known
        } else {
            &mut unknown
        };
        for (position, slot) in slots.iter_mut().enumerate() {
            execution.charge_work(1)?;
            if !speaks_for(statement, position) {
                continue;
            }
            *slot = Some(match *slot {
                Some(current)
                    if !supersedes(statement, &statements[current])
                        && recency(&statements[current]) >= recency(statement) =>
                {
                    current
                }
                _ => index,
            });
        }
    }
    let mut deciders = [None::<usize>; REASONS];
    for (decider, (known, unknown)) in deciders.iter_mut().zip(known.iter().zip(&unknown)) {
        *decider = known.or(*unknown);
    }
    Ok(deciders)
}

// RFC 5280 §6.3.3(i)–(k): a bound delta updates its own complete list even
// at equal thisUpdate. The standalone base is the pair's input, not an
// independent counterstatement to the result of combining them.
// https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
fn supersedes(candidate: &Statement<'_>, complete: &Statement<'_>) -> bool {
    complete.sources.base.is_none() && candidate.sources.base == Some(complete.sources.primary)
}

/// Order the status information by its own issuance time. RFC 6960 §2.4
/// distinguishes the time the asserted status was known from the time the
/// responder signed it. ETSI EN 319 102-1 V1.4.1 §5.2.5.4 NOTE 3 preserves
/// that distinction: later signing does not update the information itself.
/// <https://www.rfc-editor.org/rfc/rfc6960#section-2.4>
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
fn recency(statement: &Statement<'_>) -> (Time, u8) {
    let freshness = match statement.freshness {
        Freshness::Fresh => 2,
        Freshness::Uncertain(_) => 1,
        Freshness::Stale | Freshness::NoNextUpdate | Freshness::ReversedUpdateInterval => 0,
    };
    (statement.issued, freshness)
}

/// The reasons whose decider another source contradicts, and the first such
/// conflict: an equally recent source saying something else, or an older one
/// recording a revocation the decider dropped. Unknown answers all agree,
/// and lose to any that knows.
fn conflicts<E: Work>(
    statements: &[Statement<'_>],
    deciders: &[Option<usize>; REASONS],
    query: &Query<'_>,
    execution: &E,
) -> Result<(Option<Status>, [bool; REASONS])> {
    let mut conflict: Option<Status> = None;
    let mut conflicted = [false; REASONS];
    for ((position, basis), conflicted) in deciders.iter().enumerate().zip(&mut conflicted) {
        let Some(basis) = *basis else { continue };
        let latest = statements[basis];
        for (index, statement) in statements.iter().enumerate() {
            execution.charge_work(1)?;
            if index != basis
                && statement.knows()
                && speaks_for(statement, position)
                && ((statement.issued == latest.issued && !supersedes(&latest, statement))
                    || dropped_revocation(statement, latest, query))
                && !agree(statement.finding, latest.finding)
            {
                *conflicted = true;
                conflict.get_or_insert(Status::Conflict {
                    first: basis,
                    second: index,
                });
                break;
            }
        }
    }
    Ok((conflict, conflicted))
}

/// Whether `statement` records a permanent revocation the interval reaches
/// that the newer `latest` no longer records. An entry stays on a list until
/// one issued beyond the certificate's validity (RFC 5280 3.3), and only a
/// hold may be released before that (5.3.1); a source issued after expiry
/// is already unusable for silence. The two disagree about the signature,
/// and neither reading is the reader's to pick.
fn dropped_revocation(statement: &Statement<'_>, latest: Statement<'_>, query: &Query<'_>) -> bool {
    // RFC 6960 2.2: a later Good answer cannot silently erase never-issued.
    if statement.finding == Finding::NotIssued {
        return latest.finding != Finding::NotIssued;
    }
    matches!(
        statement.finding,
        Finding::Revoked(revoked)
            if !revoked.on_hold() && revoked.at.instant() <= query.interval.upper
    ) && !matches!(
        latest.finding,
        Finding::Revoked(revoked)
            if !revoked.on_hold() && revoked.at.instant() <= query.interval.upper
    )
}

/// A hold a source other than the decider records, when it provably held
/// at some moment the signature may have been made: from its date, no later
/// than `upper`, until the source was issued, strictly after `lower`. A
/// newer source that no longer lists it does not date the release
/// (RFC 5280 5.3.1), so it does not undo it.
fn persisting(basis: usize, statement: Statement<'_>, query: &Query<'_>) -> Option<Ranked> {
    let (status, rank) = match statement.finding {
        Finding::Revoked(revoked)
            if revoked.on_hold()
                && revoked.at.instant() <= query.interval.upper
                && query
                    .interval
                    .lower
                    .is_none_or(|lower| statement.issued.instant() > lower) =>
        {
            match query.utc.shift(revoked.at.instant(), 0) {
                // An unplaced hold date may be a hold the interval reaches.
                Err(reason) => (Status::Uncertain(reason), Rank::OnHold),
                Ok(_) => (Status::OnHold { basis }, Rank::OnHold),
            }
        }
        // A pair yields these only when the window reaches the interval.
        Finding::Suspended { .. } => (Status::OnHold { basis }, Rank::OnHold),
        Finding::HeldOrRevoked { .. } => (Status::HeldOrRevoked { basis }, Rank::HeldOrRevoked),
        _ => return None,
    };
    Some(Ranked {
        basis,
        status,
        rank,
    })
}

/// Whether the statement speaks for the reason at `position` (bit `position + 1`).
fn speaks_for(statement: &Statement<'_>, position: usize) -> bool {
    statement.reasons.bits() & (1 << (position + 1)) != 0
}

/// Whether `candidate` should replace `current` as the answer of its class:
/// a more severe outcome first, then a later revocation kept beside a clear
/// answer, then the later issued statement, then the earlier supplied one.
fn outranks(candidate: Ranked, current: Ranked, statements: &[Statement<'_>]) -> bool {
    let later = |status: Status| matches!(status, Status::NotRevoked { later: Some(_), .. });
    candidate
        .rank
        .cmp(&current.rank)
        .then(later(candidate.status).cmp(&later(current.status)))
        .then(
            statements[candidate.basis]
                .issued
                .cmp(&statements[current.basis].issued),
        )
        .then(current.basis.cmp(&candidate.basis))
        .is_gt()
}

fn agree(left: Finding<'_>, right: Finding<'_>) -> bool {
    match (left, right) {
        // RFC 5280 §6.3.3(i)(2) treats an omitted reason as unspecified.
        // Apply that default in the comparison and retain each reported value.
        // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
        (Finding::Revoked(left), Finding::Revoked(right)) => {
            left.at == right.at
                && left.reason.unwrap_or(Reason::Unspecified)
                    == right.reason.unwrap_or(Reason::Unspecified)
        }
        (left @ Finding::Suspended { .. }, right @ Finding::Suspended { .. })
        | (left @ Finding::HeldOrRevoked { .. }, right @ Finding::HeldOrRevoked { .. }) => {
            left == right
        }
        (Finding::NotRevoked(_), Finding::NotRevoked(_))
        | (Finding::Unknown, Finding::Unknown)
        | (Finding::NotIssued, Finding::NotIssued) => true,
        _ => false,
    }
}

fn revocation(
    basis: usize,
    latest: Statement<'_>,
    revoked: Revoked,
    query: &Query<'_>,
    subordinate: Option<Instant>,
) -> Status {
    let at = revoked.at.instant();
    // EN 319 102-1 V1.4.1 §5.2.6.4 step 4 invokes Common PKI v2.0
    // Part 9 §6. A recorded non-compromise revocation can leave a CA
    // valid at issuance. An unknown reason, compromise or hold cannot.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf
    // https://www.bundesnetzagentur.de/EVD/SharedDocuments/Downloads/QES/Common_PKI_v2.0_02.pdf?__blob=publicationFile&v=1
    let after = if at > query.interval.upper {
        true
    } else if let Some(issued) = subordinate
        && issued < at
        && matches!(
            revoked.reason,
            Some(
                Reason::AffiliationChanged
                    | Reason::Superseded
                    | Reason::CessationOfOperation
                    | Reason::PrivilegeWithdrawn
            )
        )
    {
        if let Err(cause) = query.utc.shift(issued, 0) {
            return Status::Uncertain(cause);
        }
        true
    } else {
        false
    };
    if after {
        // Recorded after the signature provably existed: it does not reach
        // back to the signature, but only fresh information can say that the
        // certificate was not revoked earlier. A hold dated after it clears
        // the signature the same way (ETSI EN 319 102-1 V1.4.1 5.5.4 step
        // 7a); an earlier hold since released is invisible to any later
        // source (RFC 5280 5.3.1 removeFromCRL), listed or silent alike.
        return match latest.freshness {
            Freshness::Fresh => Status::NotRevoked {
                basis,
                later: Some(revoked),
            },
            Freshness::Uncertain(reason) => Status::Uncertain(reason),
            Freshness::Stale | Freshness::NoNextUpdate | Freshness::ReversedUpdateInterval => {
                Status::NotFresh { basis }
            }
        };
    }
    if revoked.on_hold() {
        return Status::OnHold { basis };
    }
    // The signature came strictly after `lower`, so a revocation dated at
    // `lower` already preceded it.
    let when = match query.interval.lower {
        Some(lower) if at <= lower => When::Before,
        _ => When::NotProvablyAfter,
    };
    Status::Revoked {
        basis,
        revoked,
        when,
    }
}
