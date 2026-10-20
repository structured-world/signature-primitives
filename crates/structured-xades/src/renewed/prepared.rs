//! Complete original root renewal processing through the existing pair kernel.

use super::{CheckError, CheckResult, Checked, Report, check};
use crate::{
    binary::BinaryXml,
    certificate::DigestProvider,
    prepare::{Preparation, Prepared},
    timestamp::TimestampXml,
    xml::{Access, Xml},
};
use structured_asn1::memory::{OwnedVec, Work};

/// Every written root renewal result in original order, bound to the exact
/// preparation that selected it. A completed negative property remains here;
/// a terminal error never returns a successful partial collection.
pub struct PreparedChecks<'prepared, N, D, G, E> {
    prepared: &'prepared Preparation<N, D, G>,
    reports: OwnedVec<Report<N, D, G, E>>,
    agrees: bool,
}

impl<N: Copy, D: Copy, G: Copy, E> PreparedChecks<'_, N, D, G, E> {
    /// Exact original selection, without another parse or catalogue copy.
    #[must_use]
    pub fn prepared(&self) -> &Preparation<N, D, G> {
        self.prepared
    }

    /// Each written property, including unsupported and mismatching results.
    #[must_use]
    pub fn reports(&self) -> &[Report<N, D, G, E>] {
        &self.reports
    }

    /// Every WRITTEN renewal's new digest comparisons succeeded. True for no
    /// written renewals; absence does not establish algorithm longevity, archive
    /// protection, successful old-target validation or a baseline level.
    #[must_use]
    pub fn all_written_renewals_agree(&self) -> bool {
        self.agrees
    }
}

/// Complete renewal processing in this XML owner's identity/error domain.
pub type PreparedResult<'prepared, X, PE> = CheckResult<
    PreparedChecks<
        'prepared,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
        <X as Xml>::Error,
    >,
    X,
    PE,
>;

/// Process EVERY original root `RenewedDigestsV2` through [`check()`], preserving
/// original order and all negative results. The source determines the census;
/// callers cannot provide only successful properties. No property is reparsed
/// and no completed digest computation is replayed during composition.
///
/// EN319132-1 V1.3.1 §5.5.3 defines each property's original instruction/object
/// processing. This complete-root driver does not infer renewal necessity or
/// historical algorithm acceptance from container presence; those decisions
/// require the caller's policy and original archive coverage.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_prepared<
    'prepared,
    'q,
    X: TimestampXml + BinaryXml,
    P: DigestProvider<'q, X>,
    W: Work,
>(
    xml: &X,
    prepared: &'prepared Prepared<X>,
    provider: &'q P,
    work: &W,
) -> PreparedResult<'prepared, X, P::Error> {
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    let access = Access::new(xml, layout.snapshot(), work);
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(CheckError::Access)?;
    let mut reports: OwnedVec<Checked<X>, W> = work.vector();
    reports
        .try_reserve_exact(prepared.renewed().len())
        .map_err(|cause| CheckError::Resource {
            node: signature,
            cause,
        })?;
    let mut agrees = true;
    let mut ordinal = 0;
    while ordinal < prepared.renewed().len() {
        work.charge_work(1).map_err(|cause| CheckError::Resource {
            node: signature,
            cause,
        })?;
        let reading = &prepared.renewed()[ordinal];
        let report = check(xml, reading, provider, work)?;
        agrees &= report.agrees();
        reports
            .try_push(report)
            .map_err(|cause| CheckError::Resource {
                node: reading.node(),
                cause,
            })?;
        ordinal += 1;
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(CheckError::Access)?;
    Ok(PreparedChecks {
        prepared,
        reports: reports.into_owned(),
        agrees,
    })
}
