//! Exact reference digest obligations over a selected actual validation set.

use super::{
    ReferenceDigestError, ReferenceKind, ReferenceProperty, TargetFor, ref_catalogue::Memo,
};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, DigestProvider},
    digest, material,
    xml::{Access, Xml},
};
use structured_asn1::memory::Work;
use structured_cms::stream::RangesError;

/// Digest membership of a selected required set of original validation objects.
/// Identifier metadata, status, authority and incorporation remain independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredReferences<N> {
    /// Every original reference and every selected artifact found a match.
    Complete,
    /// No selected compatible artifact matched this complete written digest.
    Unmatched(N),
    /// Actual method or declared hash made a conclusive relation unavailable.
    Unchecked(N, Agreement),
    /// The schema has no written digest, including other-format references.
    IdentifierOnly(N),
    /// The selected artifact ordinal has no matching original reference.
    Missing(usize),
}

/// Original source and provider refusal, separate from reference mismatch.
pub type RequiredReferenceResult<X, P> =
    binary::BinaryResult<RequiredReferences<<X as Xml>::Id>, X, ReferenceDigestError<P>>;

/// Check both directions of membership for one complete reference property by
/// its specified whole-artifact hashes. Select the applicable path/status
/// artifacts for this property's role before calling. Same artifact/method
/// hashes are memoized within the operation. Provider failures remain terminal
/// and cannot produce a partial membership result.
///
/// TS 101 903 V1.4.2 §§7.4.1–7.4.4 and EN 319 132-1 Annex A define
/// different reference roles. For XL/A, supply required XML-incorporated values
/// separately from any permitted equivalents retained outside this property.
/// <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf>
pub fn check_required_references<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    property: &ReferenceProperty<X::Id, X::Document, X::Generation>,
    required: &[TargetFor<'_, '_, X>],
    provider: &'p P,
    work: &W,
) -> RequiredReferenceResult<X, P::Error> {
    let location = Location {
        snapshot: property.snapshot(),
        node: property.node(),
    };
    let access = Access::new(xml, location.snapshot, work);
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let resource = |cause| binary::Error::Callback {
        location,
        cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
    };
    let mut matched = work.vector();
    matched
        .try_reserve_exact(required.len())
        .map_err(resource)?;
    for &artifact in required {
        work.charge_work(1).map_err(resource)?;
        if !artifact.same_source(location.snapshot) {
            return Err(binary::Error::Callback {
                location,
                cause: ReferenceDigestError::Foreign,
            });
        }
        matched.try_push(false).map_err(resource)?;
    }
    let mut memo = Memo::new(provider, work);
    for entry in property.entries() {
        work.charge_work(1).map_err(resource)?;
        let Some((method, value)) = entry.digest() else {
            return Ok(RequiredReferences::IdentifierOnly(entry.node()));
        };
        let kind = match entry.kind() {
            ReferenceKind::Certificate => material::Kind::Certificate,
            ReferenceKind::Crl => material::Kind::Crl,
            ReferenceKind::Ocsp => material::Kind::Ocsp,
            ReferenceKind::Other => return Ok(RequiredReferences::IdentifierOnly(entry.node())),
        };
        let reference = digest::Reference {
            snapshot: location.snapshot,
            method,
            value,
        };
        let compare = digest::check_with::<X, P, W, RangesError, _>(
            xml,
            reference,
            provider,
            work,
            |identity, expected, work| {
                let method = memo.method(identity, work)?;
                let mut found = None;
                for (ordinal, &artifact) in required.iter().enumerate() {
                    work.charge_work(1).map_err(digest::Error::Resource)?;
                    let (actual, bytes, producer) = artifact.bytes_in();
                    if actual != kind {
                        continue;
                    }
                    let answer = match producer {
                        Some(origin) => memo.compare(
                            ordinal,
                            bytes,
                            method,
                            expected,
                            &origin.execution_in(work),
                        )?,
                        None => memo.compare(ordinal, bytes, method, expected, work)?,
                    };
                    match answer {
                        Agreement::Matches => {
                            matched[ordinal] = true;
                            found = Some(Agreement::Matches);
                        }
                        Agreement::Differs => {}
                        unavailable if found != Some(Agreement::Matches) => {
                            found = Some(unavailable);
                        }
                        _ => {}
                    }
                }
                Ok(found.unwrap_or(Agreement::Differs))
            },
        )
        .map_err(|cause| cause.map_callback(ReferenceDigestError::Digest))?;
        match compare {
            digest::Checked::Value(Agreement::Matches) => {}
            digest::Checked::Value(Agreement::Differs) => {
                return Ok(RequiredReferences::Unmatched(entry.node()));
            }
            digest::Checked::Value(unavailable) | digest::Checked::Answer(unavailable) => {
                return Ok(RequiredReferences::Unchecked(entry.node(), unavailable));
            }
        }
    }
    for (ordinal, &found) in matched.iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        if !found {
            return Ok(RequiredReferences::Missing(ordinal));
        }
    }
    Ok(RequiredReferences::Complete)
}
