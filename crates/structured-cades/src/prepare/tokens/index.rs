//! Non-cryptographic `ATSv3` envelope/index inspection under original execution.

use super::{Finding, Timestamp, signing};
use crate::{Error, Result, source::Document};
use structured_asn1::{
    Reader, Span,
    digest::Resolution,
    memory::{OwnedVec, Work},
};
use structured_cms::{
    ErrorCode, archive::HashIndex, cades::Role, ess::SigningAttributes, timestamp::Token,
};
use structured_ltv::timestamp::Purpose;
use structured_pkix::algorithm::digest::Algorithm;

pub(super) fn read<'m, 'd>(
    document: &Document<'m, 'd>,
    entry: &Timestamp<'d>,
    token: &Token<'d>,
    signing: &SigningAttributes<'d>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<Option<(Resolution<Algorithm>, Span)>> {
    if entry.purpose != Purpose::Archive {
        return Ok(None);
    }
    // EN319122-1 §§5.5.2/5.5.3 define a single unsigned DER index in the
    // archive token, independently of whether a higher level is requested.
    // Reuse the same ESS reading and the profile/index kernels used by the
    // actual archive check; no provider, certificate or payload is accessed.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    let faults = structured_cms::cades::findings_from_reading(
        token.signer(),
        Role::ArchiveTimestamp,
        signing,
        parent,
    )?;
    let mut ambiguous = false;
    for cause in &*faults {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, "cades.archive.index"))?;
        if cause.field() == "atsHashIndexV3"
            && matches!(
                cause.code(),
                ErrorCode::DuplicateAttribute | ErrorCode::AttributeCardinality
            )
        {
            ambiguous = true;
        }
        signing::schema(
            document,
            Span {
                start: cause.offset(),
                length: 0,
            },
            cause.code(),
            cause.field(),
            parent,
            findings,
        )?;
    }
    if ambiguous {
        // There is no unique index to select. Keep the original occurrences
        // on the token and this profile finding, without choosing a first
        // value or reporting the same cardinality failure a second time.
        return Ok(None);
    }
    let index = match HashIndex::of_token(token, parent) {
        Ok(index) => index,
        Err(cause) => {
            if cause.is_terminal() {
                return Err(cause.into());
            }
            signing::schema(
                document,
                Span {
                    start: cause.offset(),
                    length: 0,
                },
                cause.code(),
                cause.field(),
                parent,
                findings,
            )?;
            return Ok(None);
        }
    };
    let identity = signing::digest(
        document,
        index.span(),
        index.algorithm(),
        None,
        "atsHashIndexV3.hashIndAlgorithm",
        parent,
        findings,
    )
    .map_err(signing::InspectionError::into_source)?;
    if let Resolution::Supported(algorithm) = identity {
        widths(document, &index, algorithm.width(), parent, findings)?;
    }
    // Only scalar identity/location survive: release index catalogues before
    // a potentially fragmented TSTInfo is joined by the shared reader.
    Ok(Some((identity, index.span())))
}

fn widths<'m, 'd>(
    document: &Document<'m, 'd>,
    index: &HashIndex<'_>,
    width: usize,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<()> {
    for (list, field) in [
        (index.certificates(), "atsHashIndexV3.certificatesHashIndex"),
        (index.revocations(), "atsHashIndexV3.crlsHashIndex"),
        (
            index.attribute_values(),
            "atsHashIndexV3.unsignedAttrValuesHashIndex",
        ),
    ] {
        for hash in list {
            parent
                .charge(1)
                .map_err(|cause| Error::encoding(cause, field))?;
            if hash.len() != width {
                signing::schema(
                    document,
                    index.span(),
                    ErrorCode::DigestWidth,
                    field,
                    parent,
                    findings,
                )?;
            }
        }
    }
    Ok(())
}
