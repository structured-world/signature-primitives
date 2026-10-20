//! Explicit requested `CAdES` level over the same complete original stage reports.
//!
//! The LTV stage constructors are reused directly: no cryptography, source
//! replay or second material dispatcher is introduced by level composition.

use crate::{
    Cades, Level,
    basic::{Basic, SignerBinding},
    material::{self, Placement},
    prepare::Preparation,
    source::{DocumentId, Node},
};
use structured_asn1::memory::Work;
use structured_ltv::baseline::{ArchiveMaterial, Archives, CredentialMaterial, LongTerm, Timed};

pub use structured_ltv::baseline::{archive_material, archives, long_term, timestamped};

/// Original root/counter basic stage with a single retained receipt lifetime.
pub type BasicOf<'a, 'm, 'd> = Basic<'a, 'a, 'm, 'd, 'a>;
/// Full original TSA census and every root signature-time static association.
pub type TimedOf<'a, 'm, 'd> = Timed<
    'a,
    'a,
    'd,
    BasicOf<'a, 'm, 'd>,
    SignerBinding<'a, 'm, 'd, 'a>,
    Node,
    DocumentId<'m, 'd>,
    (),
    Cades,
>;
/// Format material tied to the actual complete authentication receipt.
pub type CredentialsOf<'a, 'm, 'd, E> = material::credentials::Report<'a, 'a, 'm, 'd, 'a, E>;
/// Full original time and X.509/credential validation-material stages.
pub type LongTermOf<'a, 'm, 'd, E> = LongTerm<
    'a,
    TimedOf<'a, 'm, 'd>,
    material::Checks<'a, 'a, 'a, 'a, 'd, 'm>,
    CredentialsOf<'a, 'm, 'd, E>,
>;
/// Every actual prior-participant material set under its original archive.
pub type ArchivesOf<'a, 'm, 'd, E> = Archives<
    'a,
    Preparation<'m, 'd>,
    ArchiveMaterial<
        'a,
        structured_ltv::material::ParticipantMaterial<
            'a,
            'a,
            'a,
            'a,
            'd,
            Node,
            DocumentId<'m, 'd>,
            (),
            Placement,
            Cades,
        >,
        CredentialsOf<'a, 'm, 'd, E>,
    >,
>;

/// Complete stage set for one explicitly selected profile. Later stages retain
/// their actual earlier reports rather than accepting independently substituted
/// successful booleans. None of these reports decides application trust.
pub enum Evidence<'a, 'm, 'd, E> {
    /// B-B mandatory format and original signer/counter association.
    Basic(&'a BasicOf<'a, 'm, 'd>),
    /// B-T whole original TSA census and full static signature-time bounds.
    Timestamped(&'a TimedOf<'a, 'm, 'd>),
    /// B-LT all actual X.509 and credential-format incorporation/placement.
    LongTerm(&'a LongTermOf<'a, 'm, 'd, E>),
    /// B-LTA all original archive inputs, including every earlier actor's data.
    Archival {
        /// Whole signature, including its time/basic stages.
        long_term: &'a LongTermOf<'a, 'm, 'd, E>,
        /// Complete actual root archive census.
        archives: &'a ArchivesOf<'a, 'm, 'd, E>,
    },
}
impl<'a, 'm, 'd> Evidence<'a, 'm, 'd, ()> {
    /// Basic evidence without naming an unrelated credential evidence type.
    #[must_use]
    pub fn basic(report: &'a BasicOf<'a, 'm, 'd>) -> Self {
        Self::Basic(report)
    }
    /// Timestamped evidence without naming an unrelated credential type.
    #[must_use]
    pub fn timestamped(report: &'a TimedOf<'a, 'm, 'd>) -> Self {
        Self::Timestamped(report)
    }
}
impl<'m, 'd, E> Evidence<'_, 'm, 'd, E> {
    /// Exact supplied stage level, never inferred from an unsigned OID.
    #[must_use]
    pub fn level(&self) -> Level {
        match self {
            Self::Basic(_) => Level::Basic,
            Self::Timestamped(_) => Level::Timestamped,
            Self::LongTerm(_) => Level::LongTerm,
            Self::Archival { .. } => Level::Archival,
        }
    }
    fn prepared(&self) -> &Preparation<'m, 'd> {
        match self {
            Self::Basic(basic) => basic.binding().prepared(),
            Self::Timestamped(timed) => timed.basic().binding().prepared(),
            Self::LongTerm(long)
            | Self::Archival {
                long_term: long, ..
            } => long.timed().basic().binding().prepared(),
        }
    }
}

/// Requested level and all linked detailed reports. This establishes the
/// common format/static-time/incorporation/coverage predicates only. Actual
/// status usability, pre-revocation chronology, algorithm longevity and
/// historical/application trust remain explicit caller decisions.
pub struct Assessment<'a, 'm, 'd, E> {
    evidence: Evidence<'a, 'm, 'd, E>,
    met: bool,
}
impl<'a, 'm, 'd, E> Assessment<'a, 'm, 'd, E> {
    /// Original explicitly requested level.
    #[must_use]
    pub fn requested(&self) -> Level {
        self.evidence.level()
    }
    /// Every detailed original positive/negative stage fact.
    #[must_use]
    pub fn evidence(&self) -> &Evidence<'a, 'm, 'd, E> {
        &self.evidence
    }
    /// All common stage predicates hold; this is not an application acceptance.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.met
    }
}

/// Wrong stage level or substituted original preparation/credential receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelError {
    /// An actual earlier archive/PoE lacks qualified historical proof/actors.
    /// It is not malformed syntax and a modern successful prefix cannot erase it.
    UnavailablePreservation {
        /// Original historical attribute.
        property: Node,
        /// Actual historical format.
        kind: crate::preservation::Kind,
    },
    /// Supplied deeper/shallower reports cannot promote or downgrade a request.
    Mismatch {
        /// Original preparation level.
        requested: Level,
        /// Actual supplied stage set.
        supplied: Level,
    },
    /// Archive and whole-material facts use different original receipts.
    Foreign,
    /// Current comparison of the complete archive census refused.
    Resource(structured_asn1::memory::MemoryError),
}

/// Compose exactly the requested level, requiring every preceding stage.
/// EN319122-1 §6.1 and table1 define the four accumulating baseline profiles;
/// extra unsigned containers cannot promote a requested profile. Checking each
/// archive's input credential identity is current query work, even when the
/// earlier reports are already retained. No parse/provider/status replay occurs.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub fn assess<'a, 'm, 'd, E>(
    evidence: Evidence<'a, 'm, 'd, E>,
    operation: &structured_asn1::Reader<'_>,
) -> Result<Assessment<'a, 'm, 'd, E>, LevelError> {
    let prepared = evidence.prepared();
    let requested = prepared.requested();
    let supplied = evidence.level();
    if requested != supplied {
        return Err(LevelError::Mismatch {
            requested,
            supplied,
        });
    }
    prepared
        .document()
        .message()
        .require_session(operation, "cades.baseline")
        .map_err(|_| LevelError::Foreign)?;
    let work = operation.execution();
    work.charge_work(1).map_err(LevelError::Resource)?;
    if requested >= Level::Timestamped
        && let Some(required) = prepared.preservation().first()
    {
        return Err(LevelError::UnavailablePreservation {
            property: required.property,
            kind: required.kind,
        });
    }
    let met = match &evidence {
        Evidence::Basic(basic) => basic.all_basic_requirements_met(),
        Evidence::Timestamped(timed) => timed_met(timed),
        Evidence::LongTerm(long) => long_met(long),
        Evidence::Archival {
            long_term,
            archives,
        } => {
            work.charge_work(1).map_err(LevelError::Resource)?;
            if !core::ptr::eq(archives.census(), prepared) {
                return Err(LevelError::Foreign);
            }
            let credentials = long_term.credentials().credentials();
            for archive in archives.reports() {
                work.charge_work(1).map_err(LevelError::Resource)?;
                if !core::ptr::eq(archive.credentials().credentials(), credentials) {
                    return Err(LevelError::Foreign);
                }
            }
            long_met(long_term) && archives.all_archive_material_covered()
        }
    };
    let met = met && prepared.all_format_requirements_met();
    Ok(Assessment { evidence, met })
}

fn timed_met(timed: &TimedOf<'_, '_, '_>) -> bool {
    timed.basic().all_basic_requirements_met() && timed.all_static_time_requirements_met()
}
fn long_met<E>(long: &LongTermOf<'_, '_, '_, E>) -> bool {
    timed_met(long.timed()) && long.all_material_requirements_met()
}
