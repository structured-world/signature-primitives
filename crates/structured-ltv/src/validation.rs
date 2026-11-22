//! ETSI basic and with-time indication computation.
//!
//! The facts about one signature arrive already established: whether its
//! format is readable, whether every reference and the signature value
//! verified, which certification paths were built and what the trusted list
//! and the revocation evidence say about them, and what is proven about when
//! the signature was made. This module computes, under caller-selected requirements, the
//! status indication ETSI EN 319 102-1 V1.4.1 gives those facts, and keeps
//! every property's own answer beside it.
//!
//! The indication is computed at best-signature-time, the earliest proven
//! moment the signature existed, as clause 5.5.4 computes it. Whether each
//! property held across the whole interval the signature could have been
//! made in is a separate answer, reported in [`Axes`]. Neither is a legal
//! verdict, and nothing here says a signature is qualified.
//!
//! Evaluation is a pure function of its inputs: the same facts under the same
//! requirements give the same outcome, and nothing is read from a clock.
//! Past-validation (clause 5.6) is outside this process; its `NO_POE` token
//! remains representable without an artificial basic/with-time input.
//!
//! Normative processing: ETSI EN 319 102-1 V1.4.1, clauses 5.3.4 and 5.5.4:
//! <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>.

mod admission;
pub mod crypto;
pub mod indication;
pub mod policy;
mod recognition;
mod validate;
pub use recognition::Recognition;

pub use crypto::{
    Bits, Constraints, Family, Hash, HashRule, Material, Mechanism, Scheme, SchemeRule, SuiteRule,
    Unmet,
};
pub use indication::{Custom, Indication, Retry, SubIndication};
pub use policy::{ETSI_TS_119_312_V2_1_1, Element, Elements, Requirements};
pub use validate::{
    Anchor, Axes, Basis, Chain, Changes, Context, Coverage, Facts, Format, Integrity, Order,
    Outcome, Path, Process, Reference, RevocationIssuer, Signer, Time, Value,
};

/// Compute the ETSI basic/with-time result from already established facts.
/// No allocation, I/O, cryptography or evidence discovery occurs. The supplied
/// execution must cover the caller's fact-producing and current work domains.
/// A conservative traversal bound is admitted before evaluating the borrowed
/// catalogues; refusal returns no indication or partial result.
///
/// # Errors
/// Returns the original work refusal, including checked cost overflow.
pub fn validate<W: structured_asn1::memory::Work>(
    facts: &Facts<'_>,
    requirements: &Requirements<'_>,
    execution: &W,
) -> Result<Outcome, structured_asn1::memory::MemoryError> {
    admission::admit(facts, requirements, execution)?;
    Ok(validate::compute(facts, requirements))
}
