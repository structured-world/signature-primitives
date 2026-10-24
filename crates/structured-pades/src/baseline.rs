//! Format/static-time/material composition over sealed original `PAdES` receipts.

use crate::{
    basic::{Basic, Bound},
    query::Query,
    range::RangeSource,
    timestamp::{ISSUER, Node, Pades, Requirements},
};
use structured_ltv::{
    baseline::{TimeError, Timed},
    source::Query as _,
    timestamp::TimestampPaths,
};
mod archives;
mod profile;
pub use archives::Error as SealsError;
pub use archives::{Seal, Seals, seals};
pub use profile::{Assessment, AssessmentOf, Selection, assess};

/// Original root and all-counter stage with one retained receipt lifetime.
pub type BasicOf<'a, 'd, D, G> = Basic<'a, 'a, 'a, 'a, 'd, 'a, 'a, 'a, D, G>;
/// Actual SID/ESS/key/path association, independent of application trust.
pub type BindingOf<'a, 'd, D, G> = Bound<'a, 'a, 'a, 'd, 'a, 'a, 'a, D, G>;
/// All original CMS/PDF TSA paths plus the signature's static existence time.
pub type TimedOf<'a, 'd, D, G> =
    Timed<'a, 'a, 'd, BasicOf<'a, 'd, D, G>, BindingOf<'a, 'd, D, G>, Node, D, G, Pades>;

/// Closed same-source format reports, not caller-implemented positive traits.
pub type LongTermOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, C, D, G> = structured_ltv::baseline::LongTerm<
    's,
    TimedOf<'a, 'd, D, G>,
    crate::material::checks::Checks<'cl, 'r, 'a, 'c, 'd, D, G>,
    crate::material::credentials::Report<'auth, C, D, G>,
>;

/// Joins the exact original signer/counters/all-TSA time report with the
/// format's own complete X.509 and credential-material reports. The common
/// core verifies actual receipt identities; public booleans or replacement
/// trait implementations cannot manufacture the `PAdES` stage.
pub fn long_term<'s, 'a, 'cl, 'r, 'c, 'd: 'a, 'auth, C, S: RangeSource>(
    timed: &'s TimedOf<'a, 'd, S::Document, S::Generation>,
    x509: &'s crate::material::checks::Checks<'cl, 'r, 'a, 'c, 'd, S::Document, S::Generation>,
    credentials: &'s crate::material::credentials::Report<'auth, C, S::Document, S::Generation>,
    query: &Query<'_, '_, S>,
) -> Result<
    LongTermOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, C, S::Document, S::Generation>,
    structured_ltv::pki::ParticipantError<Node>,
> {
    let source = timed.basic().binding().prepared().container.signature();
    if !query.belongs(source.owner().value.session) {
        return Err(structured_ltv::pki::ParticipantError::Foreign {
            signature: Node::of(source.location()),
        });
    }
    structured_ltv::baseline::long_term(timed, x509, credentials, query)
}

/// Closed per-input X.509 and credential material composition. Both reports
/// must retain the same actual authenticated credential receipt and archive
/// scope; this performs no replay and makes no historical-trust assertion.
pub fn archive_material<'s, 'cl, 'r, 'v, 'c, 'd, 'auth, C, S: RangeSource>(
    x509: &'s structured_ltv::material::ParticipantMaterial<
        'cl,
        'r,
        'v,
        'c,
        'd,
        Node,
        S::Document,
        S::Generation,
        crate::material::Placement,
        Pades,
    >,
    credentials: &'s crate::material::credentials::Report<'auth, C, S::Document, S::Generation>,
    query: &Query<'_, '_, S>,
) -> Result<
    Seal<'s, 'cl, 'r, 'v, 'c, 'd, 'auth, S::Document, S::Generation, C>,
    structured_ltv::pki::ParticipantError<Node>,
> {
    structured_ltv::baseline::archive_material(x509, credentials, query)
}

/// Joins ALL original root/counter/DTS paths. A covering document timestamp
/// supplies existence time only when no root signature timestamp is written;
/// later renewals do not force the root signer to remain valid indefinitely.
pub fn timestamped<'a, 'd: 'a, S: RangeSource>(
    basic: &'a BasicOf<'a, 'd, S::Document, S::Generation>,
    required: &'a Requirements<'a, 'a, S::Document, S::Generation>,
    paths: &'a TimestampPaths<'a, 'a, 'd, Node, S::Document, S::Generation, Pades>,
    query: &Query<'_, '_, S>,
) -> Result<TimedOf<'a, 'd, S::Document, S::Generation>, TimeError<Node>> {
    let source = basic.binding().mapping;
    if !query.belongs(
        basic
            .binding()
            .prepared()
            .container
            .signature()
            .owner()
            .value
            .session,
    ) || query.snapshot() != source.snapshot
        || !core::ptr::eq(required.all(), paths.required())
    {
        return Err(TimeError::Foreign {
            signature: source.root,
        });
    }
    query.admit(source.root, 1).map_err(TimeError::Scope)?;
    let archive = required
        .first_existence_timestamp(query.execution())
        .map_err(|cause| match cause.kind {
            crate::ErrorKind::Resource(cause) => TimeError::Resource {
                node: source.root,
                cause,
            },
            _ => TimeError::Foreign {
                signature: source.root,
            },
        })?;
    structured_ltv::baseline::timestamped_existence(ISSUER, basic, paths, archive, query)
}
