//! Same-input composition of whole-signature validation-material facts.

use super::Timed;
use crate::{
    material, pki,
    xml::{Access, Xml},
};
use structured_asn1::memory::Work;

/// Linked original time, X.509 and credential-format material reports. Public
/// input slots cannot manufacture a fact: construction verifies their exact
/// privately created participant receipts, including selected path contexts.
/// This is incorporation/placement, not Good status, chronology, algorithm
/// longevity or caller trust, and cannot by itself assert B-LT acceptance.
pub struct LongTerm<'a, T, M, C> {
    timed: &'a T,
    x509: &'a M,
    credentials: &'a C,
    material_complete: bool,
}

impl<T, M, C> LongTerm<'_, T, M, C> {
    /// Original whole-token set and root signature-time static associations.
    #[must_use]
    pub fn timed(&self) -> &T {
        self.timed
    }
    /// All original X.509 incorporation and placement findings.
    #[must_use]
    pub fn x509(&self) -> &M {
        self.x509
    }
    /// Every actual credential's own format-material interpretation/findings.
    #[must_use]
    pub fn credentials(&self) -> &C {
        self.credentials
    }
    /// Both complete material predicates, without erasing their detailed causes.
    /// This constant-time getter does not rescan any untrusted catalogue.
    #[must_use]
    pub fn all_material_requirements_met(&self) -> bool {
        self.material_complete
    }
}

type TimedFor<'a, 'r, 'p, 'v, 'c, 'd, X> =
    Timed<'a, 'r, 'p, 'v, 'c, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
type ChecksFor<'a, 'r, 'v, 'c, 'd, X> = material::Checks<
    'a,
    'r,
    'v,
    'c,
    'd,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;
type CredentialsFor<'a, 'v, 'd, A, X> = material::credentials::Report<
    'a,
    'v,
    'd,
    A,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;
/// A different scope/input receipt is a processing refusal, not absent material.
pub type MaterialResult<'a, T, M, C, X> =
    Result<LongTerm<'a, T, M, C>, pki::ParticipantError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Link the SAME complete participant/status closure and authenticated
/// credential catalogue to the root/counters/all-token time report. No source
/// parse, signature, credential authentication, status evaluation or artifact
/// lookup is repeated. Earlier-archive subsets cannot stand for whole B-LT.
/// EN319132-1 V1.3.1 §§5.4/6.3(x) require all validation material while keeping
/// status usability and application trust distinct from incorporated presence.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn long_term<'s, 'a, 'r, 'p, 'v, 'c, 'd, 'cl, 'rq, 'mv, 'mc, 'au, 'cv, A, X: Xml, W: Work>(
    timed: &'s TimedFor<'a, 'r, 'p, 'v, 'c, 'd, X>,
    x509: &'s ChecksFor<'cl, 'rq, 'mv, 'mc, 'd, X>,
    credentials: &'s CredentialsFor<'au, 'cv, 'd, A, X>,
    access: &Access<'_, X, W>,
) -> MaterialResult<
    's,
    TimedFor<'a, 'r, 'p, 'v, 'c, 'd, X>,
    ChecksFor<'cl, 'rq, 'mv, 'mc, 'd, X>,
    CredentialsFor<'au, 'cv, 'd, A, X>,
    X,
> {
    let requirements = x509.timestamps().inputs().requirements();
    if !matches!(
        requirements.scope(),
        crate::timestamp::TimestampScope::All(_)
    ) || !matches!(
        credentials.scope(),
        crate::timestamp::TimestampScope::All(_)
    ) {
        return Err(pki::ParticipantError::Foreign {
            signature: requirements.signature(),
        });
    }
    let basic = timed.basic().inputs();
    requirements.require_inputs(
        basic.certificate,
        basic.counters,
        credentials.credentials(),
        timed.paths(),
        access,
    )?;
    Ok(LongTerm {
        timed,
        x509,
        credentials,
        material_complete: x509.all_x509_requirements_met() && credentials.all_requirements_met(),
    })
}
