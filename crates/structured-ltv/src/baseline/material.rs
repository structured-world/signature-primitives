//! Same-input composition of whole-signature validation-material facts.

use super::{BasicStage, CredentialMaterial, Timed, X509Material};
use crate::pki::ParticipantError;
use crate::source::Query;
use crate::timestamp::TimestampScope;

/// Linked original time, X.509 and credential-format material reports. Public
/// input slots cannot manufacture a fact: construction verifies their exact
/// participant receipts, including selected path contexts. This is
/// incorporation/placement, not Good status, chronology, algorithm longevity
/// or caller trust, and cannot by itself assert B-LT acceptance.
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

/// A different scope/input receipt is a processing refusal, not absent material.
pub type MaterialResult<'a, T, M, C, N> = Result<LongTerm<'a, T, M, C>, ParticipantError<N>>;

type TimedOf<'a, 'c, 'd, 'path, 'document, B, Q, I> = Timed<
    'a,
    'c,
    'd,
    B,
    <B as BasicStage<'path, 'document>>::Signer,
    <Q as Query>::Id,
    <Q as Query>::Document,
    <Q as Query>::Generation,
    I,
>;

/// Link the SAME complete participant/status closure and authenticated
/// credential catalogue to the root/counters/all-token time report. No source
/// parse, signature, credential authentication, status evaluation or artifact
/// lookup is repeated. Earlier-archive subsets cannot stand for whole B-LT.
/// EN319132-1 V1.3.1 §§5.4/6.3(x) require all validation material while keeping
/// status usability and application trust distinct from incorporated presence.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn long_term<'s, 'a, 'c, 'd, 'path, 'document, B, M, C, Q, I>(
    timed: &'s TimedOf<'a, 'c, 'd, 'path, 'document, B, Q, I>,
    x509: &'s M,
    credentials: &'s C,
    query: &Q,
) -> MaterialResult<'s, TimedOf<'a, 'c, 'd, 'path, 'document, B, Q, I>, M, C, Q::Id>
where
    'document: 'path,
    B: BasicStage<'path, 'document, Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    M: X509Material<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
            Issuer = I,
        >,
    C: CredentialMaterial<Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    let requirements = x509.requirements();
    if !matches!(requirements.scope(), TimestampScope::All(_))
        || !matches!(credentials.scope(), TimestampScope::All(_))
    {
        return Err(ParticipantError::Foreign {
            signature: requirements.signature(),
        });
    }
    let basic = timed.basic();
    requirements.require_inputs(
        basic.signer(),
        basic.counters(),
        credentials.credentials(),
        timed.paths(),
        query,
    )?;
    Ok(LongTerm {
        timed,
        x509,
        credentials,
        material_complete: x509.all_x509_requirements_met() && credentials.all_requirements_met(),
    })
}
