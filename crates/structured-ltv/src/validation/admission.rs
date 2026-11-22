//! Traversal admission for a pure evaluator with no retained allocation.
//!
//! Bounds count logical visits, not CPU instructions. A constraint assessment
//! scans hashes, scheme tiers and nested suite members at most once each. Each
//! material is assessed once, each path is selected at most once, and references
//! have at most four passes (verification plus the independent integrity axis).

use super::{Facts, Requirements};
use structured_asn1::memory::{MemoryError, Work};

fn add(left: u64, right: u64) -> Result<u64, MemoryError> {
    left.checked_add(right).ok_or(MemoryError::WorkExceeded)
}
fn mul(length: usize, units: u64) -> Result<u64, MemoryError> {
    (length as u64)
        .checked_mul(units)
        .ok_or(MemoryError::WorkExceeded)
}

pub(super) fn admit(
    facts: &Facts<'_>,
    policy: &Requirements<'_>,
    work: &impl Work,
) -> Result<(), MemoryError> {
    // Fixed enum/scalar decisions, element-set checks and result projection.
    work.charge_work(128)?;
    let constraints = policy.crypto;
    let mut per_material = add(
        32,
        add(
            mul(constraints.hashes.len(), 2)?,
            mul(constraints.schemes.len(), 8)?,
        )?,
    )?;
    for suite in constraints.suites {
        // Admit this metadata visit before following its nested slice.
        work.charge_work(1)?;
        per_material = add(per_material, add(5, mul(suite.hashes.len(), 2)?)?)?;
    }
    work.charge_work(mul(facts.references.len(), 4)?)?;
    work.charge_work(mul(facts.materials.len(), per_material)?)?;
    for path in facts.paths {
        // Includes this preflight and the later path's scalar/enum decisions.
        work.charge_work(32)?;
        let members = add(
            mul(path.authorities.len(), 2)?,
            mul(path.revocation_issuers.len(), 4)?,
        )?;
        work.charge_work(add(members, mul(path.materials.len(), per_material)?)?)?;
    }
    if facts.signature_timestamp
        && policy.timestamp_delay.is_some()
        && let Some(table) = facts.utc
    {
        // Two shifts, each with three binary searches, matching temporal::shift.
        let searches = u64::from(usize::BITS - table.transitions().len().leading_zeros() + 1);
        work.charge_work(6 * searches + 64)?;
    }
    Ok(())
}
