//! One requested baseline level over its complete linked stage reports.

use super::Basic;
use crate::{
    Xades, certificate::CheckedPathCertificate, material, prepare::Preparation,
    unsigned::Requirements,
};
use structured_ltv::baseline::{ArchiveMaterial, Archives, LongTerm, Timed};

type BasicOf<'a, N, D, G> = Basic<'a, 'a, 'a, 'a, N, D, G>;
type TimedOf<'a, N, D, G> = Timed<
    'a,
    'a,
    'a,
    BasicOf<'a, N, D, G>,
    CheckedPathCertificate<'a, 'a, N, D, G>,
    N,
    D,
    G,
    Xades,
>;
type CredentialsOf<'a, A, N, D, G> = material::credentials::Report<'a, 'a, 'a, A, N, D, G>;
type LongTermOf<'a, A, N, D, G> = LongTerm<
    'a,
    TimedOf<'a, N, D, G>,
    material::Checks<'a, 'a, 'a, 'a, 'a, N, D, G>,
    CredentialsOf<'a, A, N, D, G>,
>;
type ArchivesOf<'a, A, N, D, G> = Archives<
    'a,
    Preparation<N, D, G>,
    ArchiveMaterial<
        'a,
        structured_ltv::material::ParticipantMaterial<
            'a,
            'a,
            'a,
            'a,
            'a,
            N,
            D,
            G,
            material::Placement<N>,
            Xades,
        >,
        CredentialsOf<'a, A, N, D, G>,
    >,
>;

/// Stage reports for exactly one requested level. Each later stage already
/// retains its earlier ones, so a level never needs a separately supplied copy.
pub enum Evidence<'a, A, N, D, G> {
    /// B-B root field/header/key/digest facts.
    Basic(&'a BasicOf<'a, N, D, G>),
    /// B-T whole token census and root signature-time association.
    Timestamped(&'a TimedOf<'a, N, D, G>),
    /// B-LT whole-signature validation-material facts.
    LongTerm(&'a LongTermOf<'a, A, N, D, G>),
    /// B-LTA: whole material plus the census of every original root archive.
    Archival {
        /// Whole-signature material, including its time and basic stages.
        long_term: &'a LongTermOf<'a, A, N, D, G>,
        /// Material covered by each original archive, in source order.
        archives: &'a ArchivesOf<'a, A, N, D, G>,
    },
}

// Basic and timestamped stages carry no credential census, so their
// constructors fix `A` and callers need not name it (as `HashMap::new` does).
impl<'a, N, D, G> Evidence<'a, (), N, D, G> {
    /// B-B evidence.
    #[must_use]
    pub fn basic(report: &'a BasicOf<'a, N, D, G>) -> Self {
        Self::Basic(report)
    }
    /// B-T evidence.
    #[must_use]
    pub fn timestamped(report: &'a TimedOf<'a, N, D, G>) -> Self {
        Self::Timestamped(report)
    }
}

impl<A, N: Copy, D: Copy, G: Copy> Evidence<'_, A, N, D, G> {
    /// Structural profile these reports were produced for.
    #[must_use]
    pub fn level(&self) -> Requirements {
        match self {
            Self::Basic(_) => Requirements::Basic,
            Self::Timestamped(_) => Requirements::Timestamped,
            Self::LongTerm(_) => Requirements::LongTerm,
            Self::Archival { .. } => Requirements::Archival,
        }
    }

    fn prepared(&self) -> &Preparation<N, D, G> {
        match self {
            Self::Basic(basic) => basic.inputs().fields.prepared(),
            Self::Timestamped(timed) => timed.basic().inputs().fields.prepared(),
            Self::LongTerm(long_term) | Self::Archival { long_term, .. } => {
                long_term.timed().basic().inputs().fields.prepared()
            }
        }
    }
}

/// Requested level joined with its linked stage reports. This states only
/// that every stage predicate of that level holds; status usability,
/// chronology, algorithm longevity and caller trust stay with the caller.
pub struct Assessment<'a, A, N, D, G> {
    evidence: Evidence<'a, A, N, D, G>,
    met: bool,
}

impl<'a, A, N: Copy, D: Copy, G: Copy> Assessment<'a, A, N, D, G> {
    /// Original requested profile, equal to the evidence level.
    #[must_use]
    pub fn requested(&self) -> Requirements {
        self.evidence.level()
    }
    /// Same stage reports, retaining every detailed negative finding.
    #[must_use]
    pub fn evidence(&self) -> &Evidence<'a, A, N, D, G> {
        &self.evidence
    }
    /// Every stage predicate of the requested level holds.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.met
    }
}

/// Reports that cannot describe the requested level of one preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelError {
    /// The preparation requested a different structural profile.
    Mismatch {
        /// Profile enforced by the original preparation.
        requested: Requirements,
        /// Level of the supplied stage reports.
        supplied: Requirements,
    },
    /// The archive census uses another preparation, or one archive's material
    /// uses another authenticated credential census than the whole signature.
    Foreign,
}

/// Join the stage reports of the level that the original preparation
/// requested. A deeper or shallower stage set is refused: additional
/// containers never promote the requested profile, and a missing stage
/// cannot be assumed. No source query, cryptography or allocation occurs.
///
/// EN319132-1 V1.3.1 §6.3 and table 2 define each level as a superset of the
/// previous one, so B-LTA also needs every B-LT, B-T and B-B condition.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Errors
///
/// [`LevelError::Mismatch`] when the evidence level differs from the
/// requested profile, [`LevelError::Foreign`] when the archive census does
/// not belong to the same preparation and credential census.
pub fn assess<A, N: Copy, D: Copy, G: Copy>(
    evidence: Evidence<'_, A, N, D, G>,
) -> Result<Assessment<'_, A, N, D, G>, LevelError> {
    let requested = evidence.prepared().requirements();
    let supplied = evidence.level();
    if requested != supplied {
        return Err(LevelError::Mismatch {
            requested,
            supplied,
        });
    }
    let met = match &evidence {
        Evidence::Basic(basic) => basic.all_root_requirements_met(),
        Evidence::Timestamped(timed) => timed_met(timed),
        Evidence::LongTerm(long_term) => long_term_met(long_term),
        Evidence::Archival {
            long_term,
            archives,
        } => {
            let census = long_term.credentials().credentials();
            if !core::ptr::eq(archives.census(), evidence.prepared())
                || archives
                    .reports()
                    .iter()
                    .any(|report| !core::ptr::eq(report.credentials().credentials(), census))
            {
                return Err(LevelError::Foreign);
            }
            long_term_met(long_term) && archives.all_archive_material_covered()
        }
    };
    Ok(Assessment { evidence, met })
}

fn timed_met<N: Copy, D: Copy, G: Copy>(timed: &TimedOf<'_, N, D, G>) -> bool {
    timed.basic().all_root_requirements_met() && timed.all_static_time_requirements_met()
}

fn long_term_met<A, N: Copy, D: Copy, G: Copy>(long_term: &LongTermOf<'_, A, N, D, G>) -> bool {
    timed_met(long_term.timed()) && long_term.all_material_requirements_met()
}
