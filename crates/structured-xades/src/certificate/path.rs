//! Original signed certificate digests against the actually validated path.

use super::{
    Agreement, Catalogue, CertificateXml, CheckedCertificate, DigestError, DigestProvider,
    Expected, References,
};
use crate::binary::{self, BinaryXml, Location};
use crate::material::PathCertificate;
use crate::pki::CheckedPath;
use crate::xml::{Access, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Completed digest result for one original signed certificate reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathDigest {
    /// Original reference ordinal, preserving its first-signing-certificate role.
    pub reference: usize,
    /// Complete selected-provider outcome; unsupported/malformed is not mismatch.
    pub agreement: Agreement,
    /// Actual member matched by this digest, or the existing anchor certificate.
    pub certificate: Option<PathCertificate>,
}

/// Complete digest processing against exactly this original checked path.
/// This does not replace selected-key binding, optional hint syntax, scalar
/// validation, revocation or policy acceptance with certificate hash agreement.
pub struct PathDigests<'view, 'document, N, D, G> {
    references: &'view References<N, D, G>,
    path: &'view CheckedPath<'document>,
    entries: OwnedVec<PathDigest>,
    all_match: bool,
}

/// Path-digest result using the XML owner's original source/error identities.
pub type PathDigestResult<'view, 'document, X, PE> = binary::BinaryResult<
    PathDigests<'view, 'document, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    DigestError<PE>,
>;

/// Selected original signing certificate and every original path digest.
/// The first digest is computed once, then reused by the selected-key receipt;
/// root composition need not call the standalone first-entry checker again.
pub struct CheckedPathCertificate<'view, 'document, N, D, G> {
    selected: CheckedCertificate<'view, 'document, N, D, G>,
    digests: PathDigests<'view, 'document, N, D, G>,
}

impl<'view, 'document, N, D, G> CheckedPathCertificate<'view, 'document, N, D, G> {
    /// Actual selected certificate/key/digest facts from this same invocation.
    #[must_use]
    pub fn selected(&self) -> &CheckedCertificate<'view, 'document, N, D, G> {
        &self.selected
    }
    /// All declared original digest restrictions and the actual checked path.
    #[must_use]
    pub fn digests(&self) -> &PathDigests<'view, 'document, N, D, G> {
        &self.digests
    }
    /// Selected key/certificate binding AND agreement of all path references.
    /// Scalar/hint syntax, status, temporal/trust/policy facts remain separate.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.selected.is_bound() && self.digests.all_match()
    }
}

/// Complete selected/path digest result with original source/provider causes.
pub type PathCheckResult<'view, 'document, X, PE> = super::CertificateResult<
    CheckedPathCertificate<
        'view,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    X,
    PE,
>;

/// Bind the actual selected XML key and all signed certificate digests to the
/// supplied common-validator path. Uses the same foreign-catalogue/Cert URI
/// preflight and selected-key kernel as the standalone first-entry checker.
/// No XML/path signature verification or first certificate hash is repeated.
/// This still is not a complete baseline-level or application trust decision.
///
/// # Panics
/// Only if the private nonempty checked-path/reference construction invariant
/// is violated. Both public readers/validators reject empty inputs.
pub fn check_path<
    'view,
    'document,
    'p,
    X: BinaryXml + CertificateXml,
    P: DigestProvider<'p, X>,
    W: Work,
>(
    xml: &X,
    bound: &crate::binding::Bound<X::Id, X::Document, X::Generation>,
    references: &'view Catalogue<X>,
    path: &'view CheckedPath<'document>,
    provider: &'p P,
    execution: &W,
) -> PathCheckResult<'view, 'document, X, P::Error> {
    let certificate = path
        .members()
        .last()
        .expect("a checked path has a target")
        .certificate();
    let key = super::bind_key::<X, P::Error, W>(
        xml,
        bound,
        references,
        certificate,
        path.facts().key,
        execution,
    )?;
    let digests = match_path(xml, references, path, provider, execution)
        .map_err(super::CheckError::Digest)?;
    let digest = digests
        .entries
        .first()
        .expect("certificate references are nonempty")
        .agreement;
    Ok(CheckedPathCertificate {
        selected: CheckedCertificate {
            reference: references,
            certificate,
            key,
            digest,
        },
        digests,
    })
}

impl<'view, 'document, N, D, G> PathDigests<'view, 'document, N, D, G> {
    /// Same authenticated signed-reference catalogue whose digests were read.
    #[must_use]
    pub fn references(&self) -> &'view References<N, D, G> {
        self.references
    }
    /// Actual common-validator path used for every candidate.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
    /// Each original reference, including unsupported/malformed/unmatched ones.
    #[must_use]
    pub fn entries(&self) -> &[PathDigest] {
        &self.entries
    }
    /// Whether the first digest matches the target and all other digests match
    /// a certificate in this path. This alone is not a baseline-level verdict.
    #[must_use]
    pub fn all_match(&self) -> bool {
        self.all_match
    }
}

/// Matches the original digest restrictions with one resolution/decode per
/// reference, without re-encoding certificates or reparsing their paths.
///
/// EN319132-1 V1.3.1 §5.2.2 assigns the FIRST reference to the signing
/// certificate and permits subsequent references to path/anchor certificates.
/// A matching root digest cannot substitute for an incorrect first target.
/// The optional `IssuerSerialV2` is only an identification hint (note2), not a
/// substitute for digest agreement. Its DER syntax is a separate conformance
/// check through the shared issuer-serial kernel.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// All output storage is admitted before provider callbacks. Source/provider/
/// resource failure returns no successful partial catalogue. Completed negative
/// results are retained and do not stop inspection of subsequent references.
///
/// # Panics
/// Only if the private checked-path invariant is violated: accepted paths are
/// nonempty and their last issuer-to-subject member is the actual target.
pub fn match_path<'view, 'document, 'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    references: &'view Catalogue<X>,
    path: &'view CheckedPath<'document>,
    provider: &'p P,
    execution: &W,
) -> PathDigestResult<'view, 'document, X, P::Error> {
    let access = Access::new(xml, references.snapshot(), execution);
    let location = Location {
        snapshot: references.snapshot(),
        node: references.node(),
    };
    access
        .query(references.node(), |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let mut entries = execution.vector();
    entries
        .try_reserve_exact(references.entries().len())
        .map_err(|cause| binary::Error::Callback {
            location,
            cause: DigestError::Resource(cause),
        })?;
    let mut all_match = true;
    for ordinal in 0..references.entries().len() {
        execution
            .charge_work(1)
            .map_err(|cause| binary::Error::Callback {
                location,
                cause: DigestError::Resource(cause),
            })?;
        let reference = &references.entries()[ordinal];
        let answer = if let Some(answer) = super::preflight_method(&access, reference.method)
            .map_err(|cause| binary::Error::Access {
                location: Location {
                    node: reference.method,
                    ..location
                },
                cause,
            })? {
            PathDigest {
                reference: ordinal,
                agreement: answer,
                certificate: None,
            }
        } else {
            binary::with_octets(
                xml,
                Location {
                    node: reference.digest,
                    ..location
                },
                execution,
                |expected| {
                    Ok::<_, core::convert::Infallible>(match_reference(
                        &access, reference, ordinal, path, provider, expected,
                    ))
                },
            )
            .map_err(|error| error.map_callback(|never| match never {}))??
        };
        if answer.agreement != Agreement::Matches {
            all_match = false;
        }
        entries
            .try_push(answer)
            .map_err(|cause| binary::Error::Callback {
                location,
                cause: DigestError::Resource(cause),
            })?;
    }
    Ok(PathDigests {
        references,
        path,
        entries: entries.into_owned(),
        all_match,
    })
}

fn match_reference<'p, X: Xml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    reference: &super::Reference<X::Id>,
    ordinal: usize,
    path: &CheckedPath<'_>,
    provider: &'p P,
    expected: &[u8],
) -> binary::BinaryResult<PathDigest, X, DigestError<P::Error>> {
    let identity = match super::resolve_expected(access, reference, provider, expected)? {
        Expected::Ready(identity) => identity,
        Expected::Answer(agreement) => {
            return Ok(PathDigest {
                reference: ordinal,
                agreement,
                certificate: None,
            });
        }
    };
    let mut answer = PathDigest {
        reference: ordinal,
        agreement: Agreement::Differs,
        certificate: None,
    };
    let admit = || {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| binary::Error::Callback {
                location: Location {
                    snapshot: access.snapshot(),
                    node: reference.node,
                },
                cause: DigestError::<P::Error>::Resource(cause),
            })
    };
    let members = path.members();
    if ordinal == 0 {
        admit()?;
        let target = members.last().expect("a checked path has a target");
        answer.agreement = super::compare_resolved(
            access,
            reference,
            target.certificate(),
            provider,
            &identity,
            expected,
        )?;
        if answer.agreement == Agreement::Matches {
            answer.certificate = Some(PathCertificate::Member(members.len() - 1));
        }
        return Ok(answer);
    }
    for (index, member) in members.iter().enumerate() {
        admit()?;
        match super::compare_resolved(
            access,
            reference,
            member.certificate(),
            provider,
            &identity,
            expected,
        )? {
            Agreement::Matches => {
                answer.agreement = Agreement::Matches;
                answer.certificate = Some(PathCertificate::Member(index));
                return Ok(answer);
            }
            Agreement::Differs => {}
            // The provider cannot digest under this identity at all; no later
            // candidate can change that answer into a mismatch.
            other => {
                answer.agreement = other;
                return Ok(answer);
            }
        }
    }
    admit()?;
    if let Some(certificate) = path.anchor().certificate() {
        let agreement = super::compare_resolved(
            access,
            reference,
            certificate,
            provider,
            &identity,
            expected,
        )?;
        if agreement != Agreement::Differs {
            answer.agreement = agreement;
        }
        if agreement == Agreement::Matches {
            answer.certificate = Some(PathCertificate::Anchor);
        }
    }
    Ok(answer)
}
