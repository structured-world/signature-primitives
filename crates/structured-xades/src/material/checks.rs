//! Cohesive whole-signature X.509 validation-material assessment.

use super::{
    ConditionalError, ConditionalPlacement, ExclusivePlacement, ExclusivityError, Index, Placement,
    TimestampPlacement, TimestampPlacementError, conditional_placement, exclusivity,
    timestamp_placement,
};
use crate::pki::CounterPaths;
use crate::prepare::Prepared;
use crate::xml::{Access, Xml};
use structured_asn1::memory::Work;
use structured_ltv::baseline::X509Material;
use structured_ltv::material::{Incorporation, IncorporationError, artifact_uses, incorporation};
use structured_ltv::pki::{ParticipantClosure, ParticipantRequirements, UsesError, authority_uses};

/// All whole-signature X.509 presence and placement checks derived from the
/// SAME complete participant/status closure and original artifact index.
/// Reports preserve negative facts; no unsuccessful subset is promoted.
///
/// Format-specific credential data, status usability, chronology, archive
/// coverage and application trust are separate. In particular a certificate-free
/// credential does not make its other format-specific evidence unnecessary.
pub struct Checks<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G> {
    presence: Incorporation<'certificate, 'document, N, D, G, Placement<N>>,
    conditional: ConditionalPlacement<'certificate, 'document, N, D, G>,
    exclusive: ExclusivePlacement<'certificate, 'document, N, D, G>,
    timestamps:
        TimestampPlacement<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>,
}

impl<N: Copy, D: Copy, G: Copy> Checks<'_, '_, '_, '_, '_, N, D, G> {
    /// Complete incorporated presence, including explicitly missing artifacts.
    #[must_use]
    pub fn presence(&self) -> &Incorporation<'_, '_, N, D, G, Placement<N>> {
        &self.presence
    }

    /// Requirements activated by each present original validation container.
    #[must_use]
    pub fn conditional(&self) -> &ConditionalPlacement<'_, '_, N, D, G> {
        &self.conditional
    }

    /// Forbidden or indeterminate exclusively credential/TSA CA copies.
    #[must_use]
    pub fn exclusive(&self) -> &ExclusivePlacement<'_, '_, N, D, G> {
        &self.exclusive
    }

    /// Each actual timestamp's own validation-material placement.
    #[must_use]
    pub fn timestamps(&self) -> &TimestampPlacement<'_, '_, '_, '_, '_, N, D, G> {
        &self.timestamps
    }

    /// Only complete X.509 incorporated presence and mandatory placement. This
    /// is NOT a B-LT grade, Good status or complete credential-format evidence.
    #[must_use]
    pub fn all_x509_requirements_met(&self) -> bool {
        self.presence.all_present()
            && self.conditional.findings().is_empty()
            && self.exclusive.findings().is_empty()
            && self.timestamps.findings().is_empty()
    }
}

impl<'v, 'd, N: Copy, D: Copy, G: Copy> X509Material<'v, 'd>
    for Checks<'_, '_, 'v, '_, 'd, N, D, G>
{
    type Id = N;
    type Document = D;
    type Generation = G;

    fn requirements(&self) -> &ParticipantRequirements<'v, 'd, N, D, G> {
        self.timestamps.inputs().requirements()
    }
    fn all_x509_requirements_met(&self) -> bool {
        Checks::all_x509_requirements_met(self)
    }
}

/// Terminal cause at its actual stage; no partial success report is returned.
#[derive(Debug)]
pub enum CheckError<'certificate, 'document, E, N> {
    /// Whole-source/counter scope or container-rule refusal.
    Conditional(ConditionalError<E, N>),
    /// Original authority attribution or artifact-census refusal.
    Uses(UsesError<N>),
    /// Original incorporated-value lookup refusal.
    Presence(IncorporationError<N>),
    /// Original certificate classification or exclusive-container refusal.
    Exclusive(ExclusivityError<'certificate, 'document, N>),
    /// Original per-token authority/placement refusal.
    Timestamp(TimestampPlacementError<N>),
}

/// Whole-signature material result in the XML owner's identity/error domain.
pub type CheckResult<'closure, 'requirements, 'view, 'certificate, 'document, X> = Result<
    Checks<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    CheckError<'certificate, 'document, <X as Xml>::Error, <X as Xml>::Id>,
>;

/// Assess all whole-signature X.509 material rules in one path. The original
/// prepared/counter/source/scope guards run first, then one purpose/artifact
/// census is reused for presence and exclusivity. Per-TSA placement uses the
/// same closure's actual roots, never a caller-written successful-token list.
///
/// EN319132-1 V1.3.1 §§5.4.2–5.4.6 and6.3(x/cc) distinguish presence, particular
/// mandatory containers, exclusively used CA data and each timestamp's data.
/// No one of these predicates implies the others. Processing/resource refusal
/// is terminal; completed missing/misplaced/indeterminate facts remain in the
/// report. This does not repeat parsing, crypto, path or status verification.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_participants<
    'closure,
    'requirements,
    'view,
    'certificate,
    'document,
    X: Xml,
    W: Work,
    Q: Work,
>(
    prepared: &Prepared<X>,
    inputs: &'closure ParticipantClosure<
        'requirements,
        'view,
        'certificate,
        'document,
        X::Id,
        X::Document,
        X::Generation,
    >,
    counters: &CounterPaths<'_, 'document, X::Id, X::Document, X::Generation>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> CheckResult<'closure, 'requirements, 'view, 'certificate, 'document, X> {
    let conditional = conditional_placement(prepared, inputs, counters, index, access)
        .map_err(CheckError::Conditional)?;
    let purposes = authority_uses(inputs, access).map_err(CheckError::Uses)?;
    let artifacts = artifact_uses(&purposes, access).map_err(CheckError::Uses)?;
    let presence = incorporation(&artifacts, index, access).map_err(CheckError::Presence)?;
    let exclusive = exclusivity(&artifacts, index, access).map_err(CheckError::Exclusive)?;
    let timestamps = timestamp_placement(inputs, index, access).map_err(CheckError::Timestamp)?;
    Ok(Checks {
        presence,
        conditional,
        exclusive,
        timestamps,
    })
}
