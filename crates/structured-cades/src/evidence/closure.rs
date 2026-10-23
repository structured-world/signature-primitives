//! Complete source-bound preservation, distinct from modern baseline promotion.
use super::record::Checked;
use crate::{
    Error,
    prepare::Preparation,
    preservation::{Kind, Required},
    source::Node,
};
use core::cmp::Ordering;
use structured_asn1::{
    Reader,
    memory::{Execution, OwnedMap, OwnedVec, SortError, Work},
};
use structured_cms::{
    evidence::verify::{self as ers, Decision, OrderCause},
    timestamp::Evidence,
};
use structured_pkix::temporal::{Instant, LeapTable};
const FIELD: &str = "cades.preservation.close";

/// Full record history at its actual next authenticated proof, never `poeDate`.
pub struct History<'view, 'prepared, 'm, 'd, 'path> {
    /// All original successful TSA actors of this source-bound proof.
    pub record: &'view Checked<'prepared, 'm, 'd, 'path>,
    /// Earliest authenticated TSA of the next proof on this SAME signature.
    /// Its complete input has already been checked; metadata is not evidence.
    pub following: Option<&'view Evidence>,
    /// Explicit current verification reference for the last proof.
    pub verification_time: Instant,
}
/// Refusal cannot become a successful partial preservation set.
#[derive(Debug)]
pub enum ClosureError<E> {
    /// Actual original source/query/work refusal.
    Processing(Error),
    /// Actual source node of a missing or incomplete proof.
    Unproven {
        /// Whole original proof attribute.
        property: Node,
    },
    /// A receipt belongs to another preparation or was supplied twice.
    Foreign {
        /// Actual supplied/selecting property.
        property: Node,
    },
    /// The original unsigned ordering dates cannot be ordered exactly.
    Date(structured_pkix::temporal::CompareError),
    /// Original proofs do not establish an acyclic preservation dependency.
    Dependency {
        /// First actual source proof.
        first: Node,
        /// Second actual source proof.
        second: Node,
    },
    /// Earlier/later authenticated generations fail the normative order.
    Chronology {
        /// Earlier source proof.
        earlier: Node,
        /// Later source proof.
        later: Node,
        /// Actual uncertainty/reversal, never a boolean fallback.
        cause: OrderCause,
    },
    /// Trusted historical validation completed adversely or remains unknown.
    History {
        /// Actual original proof.
        property: Node,
        /// Actual completed decision.
        decision: Decision,
    },
    /// Original historical validator failed to execute.
    Callback(E),
}

/// Every original ERS/PoE obligation, input, TSA and cross-proof history has
/// been closed. Private construction prevents writable facts or a successful
/// subset from bypassing the whole original census. This is not B-LTA status.
pub struct Closure<'checks, 'prepared, 'm, 'd, 'path> {
    prepared: &'prepared Preparation<'m, 'd>,
    records: OwnedVec<&'checks Checked<'prepared, 'm, 'd, 'path>>,
    index: OwnedMap<Node, usize>,
}
impl<'checks, 'prepared, 'm, 'd, 'path> Closure<'checks, 'prepared, 'm, 'd, 'path> {
    /// Same immutable complete source, never a substituted parse of equal bytes.
    #[must_use]
    pub fn prepared(&self) -> &'prepared Preparation<'m, 'd> {
        self.prepared
    }
    /// Exact original complete receipts in normative per-signature order.
    #[must_use]
    pub fn records(&self) -> &[&'checks Checked<'prepared, 'm, 'd, 'path>] {
        &self.records
    }
    /// Paid lookup for baseline/participant composition. No parsing or status
    /// callback repeats; this immutable closure already retains those receipts.
    pub fn contains<W: Work>(
        &self,
        required: &Required<'_>,
        work: &W,
    ) -> Result<bool, structured_asn1::memory::MemoryError> {
        let Some(index) = self.index.get(&required.property, work)? else {
            return Ok(false);
        };
        work.charge_work(3)?;
        let actual = self.records[*index].required;
        Ok(actual.signature == required.signature
            && actual.kind == required.kind
            && actual.placement == required.placement)
    }
}

/// Close a whole preparation. Before any historical callback, this admits the
/// ENTIRE original census, unique source identities, exact metadata order and
/// actual timestamp chronology. Historical checks then run latest-to-earliest
/// with the actual following proof, as TS101733 Annex B.3A.1 requires.
pub fn close_preservation<'checks, 'prepared, 'm, 'd, 'path, E>(
    prepared: &'prepared Preparation<'m, 'd>,
    records: &[&'checks Checked<'prepared, 'm, 'd, 'path>],
    operation: &Reader<'d>,
    utc: &LeapTable<'_>,
    reference: Instant,
    mut historical: impl FnMut(
        History<'_, 'prepared, 'm, 'd, 'path>,
        &Execution<'_>,
    ) -> Result<Decision, E>,
) -> Result<Closure<'checks, 'prepared, 'm, 'd, 'path>, ClosureError<E>> {
    prepared
        .document()
        .message()
        .require_session(operation, FIELD)
        .map_err(|cause| ClosureError::Processing(Error::Cms(cause)))?;
    let work = operation.execution();
    let resource = |cause| {
        ClosureError::Processing(Error::resource(
            cause,
            FIELD,
            prepared.signer().span().start,
        ))
    };
    let mut selected = work.vector();
    let mut index = work.map();
    selected
        .try_reserve_exact(records.len())
        .map_err(resource)?;
    for record in records {
        work.charge_work(1).map_err(resource)?;
        let property = record.required.property;
        if !core::ptr::eq(record.prepared, prepared)
            || !record.required.kind.is_evidence()
            || index
                .try_insert(property, selected.len())
                .map_err(resource)?
                .is_some()
        {
            return Err(ClosureError::Foreign { property });
        }
        if record.verified().is_none() {
            return Err(ClosureError::Unproven { property });
        }
        selected.try_push(*record).map_err(resource)?;
    }
    for required in prepared.preservation() {
        work.charge_work(1).map_err(resource)?;
        if !required.kind.is_evidence() {
            continue;
        }
        if index
            .get(&required.property, &work)
            .map_err(resource)?
            .is_none()
        {
            return Err(ClosureError::Unproven {
                property: required.property,
            });
        }
        if required.placement != structured_cms::attribute::Placement::Unsigned {
            return Err(ClosureError::Unproven {
                property: required.property,
            });
        }
    }
    // No unrelated readable proof or malformed source may disappear while
    // closing a chosen successful subset.
    if !prepared.evidence_faults().is_empty() {
        return Err(ClosureError::Unproven {
            property: prepared.evidence_faults()[0].0,
        });
    }
    order_selected(prepared, &mut selected, &index, utc, &work)?;
    check_chronology(&selected, utc, &work)?;
    check_history(&selected, reference, &mut historical, &work)?;
    // Freeze the sorted identity mapping AFTER all comparisons/callbacks.
    let mut sorted = work.map();
    for (ordinal, record) in selected.iter().enumerate() {
        sorted
            .try_insert(record.required.property, ordinal)
            .map_err(resource)?;
    }
    Ok(Closure {
        prepared,
        records: selected.into_owned(),
        index: sorted.into_owned(),
    })
}

fn order_selected<E, W: Work>(
    prepared: &Preparation<'_, '_>,
    selected: &mut OwnedVec<&Checked<'_, '_, '_, '_>, W>,
    index: &OwnedMap<Node, usize, W>,
    utc: &LeapTable<'_>,
    work: &W,
) -> Result<(), ClosureError<E>> {
    let resource = |cause| {
        ClosureError::Processing(Error::resource(
            cause,
            FIELD,
            prepared.signer().span().start,
        ))
    };
    // Coverage, not a kind priority or claimed date, determines which proof
    // came later. This also handles a qualified AnnexB ERS appended after PoE.
    // Rank a fully related per-signature dependency graph before sorting, so
    // an attacker-controlled cycle never reaches a non-total sort comparator.
    let mut ranks = work.vector();
    ranks.try_reserve_exact(selected.len()).map_err(resource)?;
    for _ in selected.iter() {
        ranks.try_push(0usize).map_err(resource)?;
    }
    for left in 0..selected.len() {
        for right in left + 1..selected.len() {
            work.charge_work(3).map_err(resource)?;
            if selected[left].required.signature != selected[right].required.signature {
                continue;
            }
            let order = precedes(prepared, selected[left], selected[right], utc, work)?;
            let later = if order == Ordering::Less { right } else { left };
            debug_assert!(ranks[later] < selected.len());
            ranks[later] += 1;
        }
    }
    selected
        .try_sort_unstable_by(|a, b| {
            work.charge_work(3).map_err(resource)?;
            let owner = a
                .required
                .signature
                .span()
                .start
                .cmp(&b.required.signature.span().start);
            if owner != Ordering::Equal {
                return Ok(owner);
            }
            let left = *index
                .get(&a.required.property, work)
                .map_err(resource)?
                .ok_or(ClosureError::Foreign {
                    property: a.required.property,
                })?;
            let right = *index
                .get(&b.required.property, work)
                .map_err(resource)?
                .ok_or(ClosureError::Foreign {
                    property: b.required.property,
                })?;
            Ok::<_, ClosureError<E>>(ranks[left].cmp(&ranks[right]).then_with(|| {
                a.required
                    .property
                    .span()
                    .start
                    .cmp(&b.required.property.span().start)
            }))
        })
        .map_err(|cause| match cause {
            SortError::Resource(cause) => resource(cause),
            SortError::Comparison(cause) => cause,
        })?;
    for left in 0..selected.len() {
        for right in left + 1..selected.len() {
            work.charge_work(3).map_err(resource)?;
            if selected[left].required.signature != selected[right].required.signature {
                continue;
            }
            if precedes(prepared, selected[left], selected[right], utc, work)? != Ordering::Less {
                return Err(ClosureError::Dependency {
                    first: selected[left].required.property,
                    second: selected[right].required.property,
                });
            }
        }
    }
    Ok(())
}

fn check_chronology<E, W: Work>(
    selected: &[&Checked<'_, '_, '_, '_>],
    utc: &LeapTable<'_>,
    work: &W,
) -> Result<(), ClosureError<E>> {
    for pair in selected.windows(2) {
        let resource = |cause| {
            ClosureError::Processing(Error::resource(
                cause,
                FIELD,
                pair[0].required.property.span().start,
            ))
        };
        work.charge_work(1).map_err(resource)?;
        if pair[0].required.signature != pair[1].required.signature {
            continue;
        }
        let a = pair[0]
            .checks()
            .last()
            .and_then(|check| check.actor())
            .ok_or(ClosureError::Unproven {
                property: pair[0].required.property,
            })?;
        let b = pair[1]
            .checks()
            .next()
            .and_then(|check| check.actor())
            .ok_or(ClosureError::Unproven {
                property: pair[1].required.property,
            })?;
        if let Some(cause) = ers::order_evidence(
            a.verified().evidence(),
            a.certificate(),
            b.verified().evidence(),
            b.certificate(),
            utc,
            work,
        )
        .map_err(|cause| ClosureError::Processing(Error::Cms(cause)))?
        {
            return Err(ClosureError::Chronology {
                earlier: pair[0].required.property,
                later: pair[1].required.property,
                cause,
            });
        }
    }
    Ok(())
}

fn check_history<'checks, 'prepared, 'm, 'd, 'path, E, W: Work>(
    selected: &[&'checks Checked<'prepared, 'm, 'd, 'path>],
    reference: Instant,
    historical: &mut impl FnMut(History<'_, 'prepared, 'm, 'd, 'path>, &W) -> Result<Decision, E>,
    work: &W,
) -> Result<(), ClosureError<E>> {
    for ordinal in (0..selected.len()).rev() {
        let resource = |cause| {
            ClosureError::Processing(Error::resource(
                cause,
                FIELD,
                selected[ordinal].required.property.span().start,
            ))
        };
        work.charge_work(1).map_err(resource)?;
        let record = selected[ordinal];
        let following = if let Some(next) = selected.get(ordinal + 1)
            && next.required.signature == record.required.signature
        {
            Some(
                next.checks()
                    .next()
                    .and_then(|check| check.actor())
                    .ok_or(ClosureError::Unproven {
                        property: next.required.property,
                    })?
                    .verified()
                    .evidence(),
            )
        } else {
            None
        };
        let decision = historical(
            History {
                record,
                following,
                verification_time: reference,
            },
            work,
        )
        .map_err(ClosureError::Callback)?;
        if decision != Decision::Valid {
            return Err(ClosureError::History {
                property: record.required.property,
                decision,
            });
        }
    }
    Ok(())
}

fn precedes<E, W: Work>(
    prepared: &Preparation<'_, '_>,
    a: &Checked<'_, '_, '_, '_>,
    b: &Checked<'_, '_, '_, '_>,
    utc: &LeapTable<'_>,
    work: &W,
) -> Result<Ordering, ClosureError<E>> {
    let resource = |cause| {
        ClosureError::Processing(Error::resource(
            cause,
            FIELD,
            a.required.property.span().start,
        ))
    };
    let ac = a.covered.as_ref().ok_or(ClosureError::Unproven {
        property: a.required.property,
    })?;
    let bc = b.covered.as_ref().ok_or(ClosureError::Unproven {
        property: b.required.property,
    })?;
    let ab = super::coverage::selects(ac, b.required.property.span(), work).map_err(resource)?;
    let ba = super::coverage::selects(bc, a.required.property.span(), work).map_err(resource)?;
    let order = match (ab, ba) {
        (false, true) => Ordering::Less,
        (true, false) => Ordering::Greater,
        _ => {
            return Err(ClosureError::Dependency {
                first: a.required.property,
                second: b.required.property,
            });
        }
    };
    if a.required.kind == Kind::LongTermValidation && b.required.kind == Kind::LongTermValidation {
        work.charge_work(2).map_err(resource)?;
        let ae = prepared
            .parsed
            .proofs
            .entries
            .get(a.proof)
            .ok_or(ClosureError::Foreign {
                property: a.required.property,
            })?;
        let be = prepared
            .parsed
            .proofs
            .entries
            .get(b.proof)
            .ok_or(ClosureError::Foreign {
                property: b.required.property,
            })?;
        let (crate::prepare::proofs::Body::Poe(a), crate::prepare::proofs::Body::Poe(b)) =
            (&ae.body, &be.body)
        else {
            return Err(ClosureError::Dependency {
                first: ae.required.property,
                second: be.required.property,
            });
        };
        if a.compare_date(b, utc, work).map_err(ClosureError::Date)? != order {
            return Err(ClosureError::Dependency {
                first: ae.required.property,
                second: be.required.property,
            });
        }
    }
    Ok(order)
}
