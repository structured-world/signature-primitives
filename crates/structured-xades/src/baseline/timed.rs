//! Whole original TSA-path census and root signature-time static association.

use super::Basic;
use crate::certificate::{
    SignatureTime, SignatureTimeBinding, SignatureTimeError, SignatureTimeFailure,
};
use crate::timestamp::{TimestampPaths, TimestampScope};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::timestamp::Purpose;

/// One actual root `SignatureTimeStamp`'s complete static certificate binding.
/// Negative results do not disappear because a different timestamp succeeded.
pub enum SignatureTimeFact<'a, 'path, 'document, N, D, G> {
    /// Exact original signature input and full generation/static path interval.
    Bound(SignatureTime<'a, 'path, 'document, N, D, G>),
    /// Completed insufficient root certificate/interval fact, not source refusal.
    Unproven {
        /// Original root `SignatureTimeStamp` property.
        property: N,
        /// Exact completed negative cause.
        cause: SignatureTimeFailure,
    },
}

/// Whole original token/TSA path set plus every root signature-time association.
/// This does not assert pre-revocation chronology, current/historical status,
/// format material completeness, algorithm-obsolescence policy or caller trust.
/// In particular it is NOT an unconditional B-T acceptance verdict.
pub struct Timed<'a, 'receipt, 'prepared, 'path, 'certificate, 'document, N, D, G> {
    basic: &'a Basic<'receipt, 'prepared, 'path, 'document, N, D, G>,
    paths: &'a TimestampPaths<'a, 'certificate, 'document, N, D, G>,
    signatures: OwnedVec<SignatureTimeFact<'a, 'path, 'document, N, D, G>>,
    static_complete: bool,
}

impl<'a, 'r, 'p, 'v, 'c, 'd, N, D, G> Timed<'a, 'r, 'p, 'v, 'c, 'd, N, D, G> {
    /// Same original root field/header/key/digest facts.
    #[must_use]
    pub fn basic(&self) -> &'a Basic<'r, 'p, 'v, 'd, N, D, G> {
        self.basic
    }
    /// Complete source-derived root AND nested-counter timestamp/TSA paths.
    #[must_use]
    pub fn paths(&self) -> &'a TimestampPaths<'a, 'c, 'd, N, D, G> {
        self.paths
    }
    /// Every original root `SignatureTimeStamp`, including negative associations.
    #[must_use]
    pub fn signatures(&self) -> &[SignatureTimeFact<'a, 'v, 'd, N, D, G>] {
        &self.signatures
    }
    /// At least one root signature timestamp exists and every such timestamp's
    /// complete accuracy interval is covered by the actual static signer path.
    /// Counter/data/archive timestamps cannot substitute for this condition.
    #[must_use]
    pub fn all_static_time_requirements_met(&self) -> bool {
        self.static_complete
    }
}

/// Terminal original source/selection/query refusal; no partial timed report.
#[derive(Debug)]
pub enum TimeError<E, N> {
    /// Wrong scope, source or selected root/counter census.
    Foreign {
        /// Original selected signature.
        signature: N,
    },
    /// Original current-operation/source failure.
    Access(AccessError<E, N>),
    /// Original complete-census membership query failed.
    Input(crate::timestamp::InputError<E, N>),
    /// Original signature-time association processing failed.
    Signature(SignatureTimeError<E, N>),
    /// Work or retained report capacity was refused before use.
    Resource {
        /// Original selecting signature/property.
        node: N,
        /// Exact resource refusal.
        cause: MemoryError,
    },
}

/// Complete original static time facts in this XML owner's identity domain.
pub type TimeResult<'a, 'r, 'p, 'v, 'c, 'd, X> = Result<
    Timed<'a, 'r, 'p, 'v, 'c, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    TimeError<<X as Xml>::Error, <X as Xml>::Id>,
>;
type Root<'a, 'r, 'p, 'v, 'd, X> =
    &'a Basic<'r, 'p, 'v, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Bind all-token TSA-path facts to the SAME root/counter source and every actual
/// root signature timestamp to the checked signer. Reuses previously established
/// complete generation intervals, not another UTC parse or certificate hash.
/// EN319132-1 §§5.3/6.3(n,o) distinguish `SignatureTimeStamp` from other roles and
/// require EACH such timestamp before expiration/revocation. This function
/// establishes the static interval part; actual revocation facts stay explicit.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn timestamped<'a, 'r, 'p, 'v, 'c, 'd, X: Xml, W: Work>(
    basic: Root<'a, 'r, 'p, 'v, 'd, X>,
    paths: &'a TimestampPaths<'a, 'c, 'd, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> TimeResult<'a, 'r, 'p, 'v, 'c, 'd, X> {
    let prepared = basic.inputs().fields.prepared();
    let signature = prepared.bound().containers().signature();
    let required = paths.required();
    let resource = |cause| TimeError::Resource {
        node: signature,
        cause,
    };
    if !matches!(required.scope(), TimestampScope::All(_))
        || required.scope().location().snapshot != access.snapshot()
        || prepared.bound().containers().snapshot() != access.snapshot()
        || !access
            .equal_id(required.signature(), signature)
            .map_err(resource)?
        || !required
            .includes_counters(basic.inputs().counters, access)
            .map_err(TimeError::Input)?
    {
        return Err(TimeError::Foreign { signature });
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(TimeError::Access)?;
    let mut signatures = access.execution().vector();
    let mut static_complete = basic.all_root_requirements_met();
    for path in paths.paths() {
        access.execution().charge_work(1).map_err(resource)?;
        let verified = path.actor().verified();
        if verified.purpose() != Purpose::Signature
            || !access
                .equal_id(verified.signature(), signature)
                .map_err(resource)?
        {
            continue;
        }
        signatures.try_reserve(1).map_err(resource)?;
        let fact = match basic
            .inputs()
            .certificate
            .bind_signature_time_path(path, access)
            .map_err(TimeError::Signature)?
        {
            SignatureTimeBinding::Bound(value) => SignatureTimeFact::Bound(value),
            SignatureTimeBinding::Unproven(cause) => {
                static_complete = false;
                SignatureTimeFact::Unproven {
                    property: verified.property(),
                    cause,
                }
            }
        };
        signatures.try_push(fact).map_err(resource)?;
    }
    if signatures.is_empty() {
        static_complete = false;
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(TimeError::Access)?;
    Ok(Timed {
        basic,
        paths,
        signatures: signatures.into_owned(),
        static_complete,
    })
}
