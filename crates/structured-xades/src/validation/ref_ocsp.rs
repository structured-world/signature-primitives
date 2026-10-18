//! Original OCSP identifier against one actually authenticated response signer.

use super::{
    ReferenceIdentifier, ReferenceKeyResult, ReferenceNameError, ReferenceProperty, ReferenceTime,
    ReferenceTimeError, ResponderIdentifier, ResponderKeyError, matches_reference_key,
    matches_reference_name, matches_reference_time,
};
use crate::{
    binary::{self, BinaryXml, Location},
    properties::CalendarXml,
    scalar::TextXml,
    xml::{Access, AccessError, Xml},
};
use structured_asn1::Reader;
use structured_pkix::algorithm::digest::AsnDigest;
use structured_pkix::ocsp::{ResponderMatch, SignedResponse};

/// Completed identifier facts, separate from whole-response digest, target
/// authorization, status usability, actual participant use and incorporation.
pub struct OcspReferenceIdentity {
    responder: Option<ResponderMatch>,
    produced_at: ReferenceTime,
}

impl OcspReferenceIdentity {
    /// Both `ByName` and `ByKey` identify the same authenticated signer;
    /// the branch written inside `ResponseData` need not match the XML branch.
    /// None means mandatory time syntax was malformed or unavailable, so no
    /// responder normalization/digest callback was attempted.
    #[must_use]
    pub fn responder(&self) -> Option<ResponderMatch> {
        self.responder
    }

    /// Complete original production-time interpretation, including unstated
    /// timezone, malformed or unavailable schema facts.
    #[must_use]
    pub fn produced_at(&self) -> ReferenceTime {
        self.produced_at
    }
}

/// Exact stage/cause; processing/resource refusal is not identity disagreement.
#[derive(Debug)]
pub enum OcspReferenceError<E, PE, N, D, G> {
    /// Original source/generation/current-operation query refused.
    Access(AccessError<E, N>),
    /// No reference exists at this ordinal.
    Index {
        /// Requested ordinal, not an XML byte offset.
        index: usize,
    },
    /// Original RFC4514/Name comparison failure.
    Name(ReferenceNameError<E, N>),
    /// Original DER `ByKey` or selected digest-provider failure.
    Key(binary::Error<E, ResponderKeyError<structured_pkix::error::CallbackError<PE>>, N, D, G>),
    /// Original XML production-time or current comparison failure.
    Time(ReferenceTimeError<E, N>),
}

/// One complete original identifier result in this XML owner's source domain.
pub type OcspReferenceResult<X, PE> = Result<
    Option<binary::LocatedValue<OcspReferenceIdentity, X>>,
    OcspReferenceError<
        <X as Xml>::Error,
        PE,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
>;

/// Compare both fields of an original `OCSPIdentifier` with a response whose
/// mathematical signature and ResponderID-to-signer binding already succeeded.
/// Annex A.1.2 requires the actual responder and producedAt of the referenced
/// response. RFC6960 §4.2.1 permits either responder identifier spelling; a
/// `ByName` XML selector can identify a byKey response and conversely through the
/// SAME authenticated signer. No signature/path/hash of the response is repeated.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
/// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1>
///
/// All XML decoding, name work, key hash callbacks and calendar comparison use
/// the current operation. No successful prefix is returned on a later refusal.
/// None means a different reference kind, never agreement. The selected response
/// still needs whole-envelope digest association, issuer authorization, status
/// validity, actual use and incorporation checks; this is not a baseline grade.
///
/// # Panics
/// Only if an immutable privately constructed reference changes its selector
/// kind between the original field selection and the same field kernel.
pub fn check_ocsp_reference<'k, X, D, PE>(
    xml: &X,
    references: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    index: usize,
    signed: SignedResponse<'_, '_>,
    digest: &'k D,
    operation: &Reader<'_>,
) -> OcspReferenceResult<X, PE>
where
    X: BinaryXml + TextXml + CalendarXml,
    D: AsnDigest<'k, Error = PE>,
{
    let work = operation.execution();
    let access = Access::new(xml, references.snapshot(), &work);
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(OcspReferenceError::Access)?;
    let Some(entry) = references.entries().get(index) else {
        return Err(OcspReferenceError::Index { index });
    };
    let ReferenceIdentifier::Ocsp {
        node, responder, ..
    } = entry.identifier()
    else {
        return Ok(None);
    };
    let produced_at = matches_reference_time(
        xml,
        references,
        index,
        signed.response().produced_at(),
        operation,
    )
    .map_err(OcspReferenceError::Time)?
    .expect("original OCSP time entry");
    // Mandatory scalar syntax precedes provider work. A completed semantic
    // time mismatch/unstated zone is still readable and preserves both facts;
    // malformed/unavailable syntax cannot admit a digest resolver side effect.
    let responder = if matches!(
        produced_at,
        ReferenceTime::Malformed | ReferenceTime::Unsupported
    ) {
        None
    } else {
        Some(match responder {
            ResponderIdentifier::Name(_) => {
                match matches_reference_name(
                    xml,
                    references,
                    index,
                    signed.signer().tbs().subject(),
                    operation,
                )
                .map_err(OcspReferenceError::Name)?
                {
                    Some(true) => ResponderMatch::Matches,
                    Some(false) => ResponderMatch::Differs,
                    None => unreachable!("original ByName entry"),
                }
            }
            ResponderIdentifier::Key(_) => {
                let result: ReferenceKeyResult<X, PE> = matches_reference_key(
                    xml,
                    references,
                    index,
                    signed.signer(),
                    digest,
                    operation,
                );
                result
                    .map_err(OcspReferenceError::Key)?
                    .expect("original ByKey entry")
                    .value
            }
        })
    };
    access
        .query(node, |_, _, _| Ok(()))
        .map_err(OcspReferenceError::Access)?;
    Ok(Some(binary::Located {
        location: Location {
            snapshot: references.snapshot(),
            node,
        },
        value: OcspReferenceIdentity {
            responder,
            produced_at,
        },
    }))
}
