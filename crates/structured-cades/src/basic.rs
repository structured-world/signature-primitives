//! Binding the original root to the actual CMS check and selected path.

use crate::Error;
use crate::prepare::Preparation;
use crate::source::{DocumentId, Node, Original};
use structured_asn1::Reader;
use structured_asn1::memory::Work;
use structured_cms::directory::{self, CertificateAgreement};
use structured_cms::ess::{Binding, BindingError, Bindings};
use structured_cms::provider::SignatureAnswer;
use structured_cms::verify::{Checked, ContentAgreement, DocumentChecks};
use structured_ltv::pki::CounterReceipts;
use structured_ltv::pki::{CheckedPath, SignerReceipt};
use structured_pkix::Certificate;
use structured_pkix::algorithm::digest::AsnDigest;

/// Same-source root field/certificate/math and complete counter composition.
/// The report preserves its inputs and does not assert timestamp chronology,
/// status usability, optional-policy acceptance or caller trust.
pub struct Basic<'receipt, 'prepared, 'model, 'document, 'path> {
    signer: &'receipt SignerBinding<'prepared, 'model, 'document, 'path>,
    counters: crate::counters::Paths<'receipt, 'model, 'document, 'path>,
    complete: bool,
}

impl<'r, 'p, 'm, 'd, 'v> Basic<'r, 'p, 'm, 'd, 'v> {
    /// Actual selected original certificate/signature binding, without replay.
    #[must_use]
    pub fn binding(&self) -> &'r SignerBinding<'p, 'm, 'd, 'v> {
        self.signer
    }
    /// Every original counter's already checked actual path.
    #[must_use]
    pub fn counter_paths(&self) -> &crate::counters::Paths<'r, 'm, 'd, 'v> {
        &self.counters
    }
    /// Only mandatory B-B format and original root/counter mathematical binding.
    /// A higher requested profile's missing timestamp cannot erase this fact.
    #[must_use]
    pub fn all_basic_requirements_met(&self) -> bool {
        self.complete
    }
}

impl<'r, 'p, 'm, 'd, 'v> structured_ltv::baseline::BasicStage<'v, 'd>
    for Basic<'r, 'p, 'm, 'd, 'v>
{
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    type Signer = SignerBinding<'p, 'm, 'd, 'v>;
    type Counters = crate::counters::Paths<'r, 'm, 'd, 'v>;
    fn signer(&self) -> &Self::Signer {
        self.signer
    }
    fn counters(&self) -> &Self::Counters {
        &self.counters
    }
    fn all_requirements_met(&self) -> bool {
        self.complete
    }
}

/// Combine original root and full counter receipts with the actual B-B format
/// reading. Receipt/source/counter membership is checked before returning a
/// report; writable booleans and selected success subsets cannot enter it.
pub fn basic<'r, 'p, 'm, 'd, 'v>(
    signer: &'r SignerBinding<'p, 'm, 'd, 'v>,
    counters: crate::counters::Paths<'r, 'm, 'd, 'v>,
    operation: &Reader<'_>,
) -> crate::Result<Basic<'r, 'p, 'm, 'd, 'v>> {
    let prepared = signer.prepared();
    prepared
        .document()
        .message()
        .require_session(operation, "cades.basic")?;
    let selected = prepared.document().locate(prepared.signer().span());
    operation
        .charge(1)
        .map_err(|cause| Error::encoding(cause, "cades.basic"))?;
    if counters.snapshot() != selected.snapshot
        || counters.signature() != selected.node
        || counters.len() != prepared.counters().len()
    {
        return Err(Error::Foreign {
            at: selected.node.span().start,
        });
    }
    for (ordinal, expected) in prepared.counters().iter().enumerate() {
        operation
            .charge(1)
            .map_err(|cause| Error::encoding(cause, "cades.basic"))?;
        if counters.counter(ordinal).signature != expected.node() {
            return Err(Error::Foreign {
                at: expected.node().span().start,
            });
        }
    }
    Ok(Basic {
        signer,
        counters,
        complete: prepared.basic_format_requirements_met() && signer.is_bound(),
    })
}

/// Original refusal at the actual shared operation, not a negative binding.
#[derive(Debug)]
pub enum BindError<E> {
    /// Source, metadata, byte comparison or capacity refused.
    Processing(Error),
    /// Existing CMS SID query failed with its original cause.
    Identifier(directory::Error),
    /// Existing ESS hash/issuer binding failed with its original cause.
    Ess(BindingError<E>),
}

/// Signed ESS validation-set restriction against the actual selected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRestriction {
    /// No later certificate identifier constrains the path.
    Unstated,
    /// Each actual path certificate belongs to every written restricted set.
    Matches,
    /// A signed restriction exists but its actual checked path was not supplied.
    PathUnavailable,
    /// A supplied path uses a certificate outside a signed restricted set.
    Differs,
    /// Original unreadable restriction or unsupported digest prevents proof.
    Unproven,
}

/// Completed root binding facts, including negative mathematical outcomes.
/// Construction performs ESS itself; externally writable `Bindings` cannot
/// manufacture a receipt. A retained path is available only for an actual
/// fully associated signer, never from a public boolean assertion.
pub struct SignerBinding<'receipt, 'model, 'document, 'path> {
    prepared: &'receipt Preparation<'model, 'document>,
    path: Option<&'path CheckedPath<'document>>,
    certificate: &'path Certificate<'document>,
    identifier: CertificateAgreement,
    ess: Bindings,
    key_matches: bool,
    included: Option<Original<'model, 'document>>,
    mathematical: bool,
    restrictions: PathRestriction,
}

impl<'r, 'm, 'd, 'p> SignerBinding<'r, 'm, 'd, 'p> {
    /// Same original requested-level preparation.
    #[must_use]
    pub fn prepared(&self) -> &'r Preparation<'m, 'd> {
        self.prepared
    }
    /// Candidate actually compared with SID, ESS and the CMS checked key.
    #[must_use]
    pub fn certificate(&self) -> &'p Certificate<'d> {
        self.certificate
    }
    /// Original signer-identifier agreement, including unreadable SKI causes.
    #[must_use]
    pub fn identifier(&self) -> &CertificateAgreement {
        &self.identifier
    }
    /// Both independently computed ESS answers. Neither absent value is success.
    #[must_use]
    pub fn ess(&self) -> Bindings {
        self.ess
    }
    /// The supplied effective key agrees with this path's actual target key.
    #[must_use]
    pub fn key_matches(&self) -> bool {
        self.key_matches
    }
    /// Exact original occurrence in root SignedData.certificates, if present.
    #[must_use]
    pub fn included(&self) -> Option<Original<'m, 'd>> {
        self.included
    }
    /// CMS arithmetic and payload binding both succeeded. This alone says
    /// nothing about the root profile, certificate, path, or caller trust.
    #[must_use]
    pub fn mathematical(&self) -> bool {
        self.mathematical
    }
    /// Actual path-set restriction result, independent of signer certHash.
    #[must_use]
    pub fn restrictions(&self) -> PathRestriction {
        self.restrictions
    }
    /// Every currently established root binding condition holds. The complete
    /// B-B assembly additionally requires all format/attribute/counter facts.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.mathematical
            && self.key_matches
            && self.included.is_some()
            && matches!(self.identifier, CertificateAgreement::Matches)
            && ess_matches(self.ess)
            && matches!(
                self.restrictions,
                PathRestriction::Unstated | PathRestriction::Matches
            )
    }
}

impl<'m, 'd, 'p> SignerReceipt<'p, 'd> for SignerBinding<'_, 'm, 'd, 'p> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    fn signature(&self) -> Original<'m, 'd> {
        self.prepared
            .document()
            .locate(self.prepared.signer().span())
    }
    fn path(&self) -> Option<&'p CheckedPath<'d>> {
        if self.is_bound() { self.path } else { None }
    }
}

/// Binds the ORIGINAL CMS checked signer and effective key to its selected
/// certificate and actual common-validator path. No signature or payload is
/// replayed. SID/name, exact incorporation and ESS use their existing kernels.
///
/// EN319122-1 §§5.2.2/6.3(a) require the protected certificate binding and its
/// original root occurrence. Trust selection, algorithm permissions and current
/// or historical revocation acceptance remain explicit caller work.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub fn bind<'a, 'r, 'm, 'd, 'p, P: AsnDigest<'a>>(
    prepared: &'r Preparation<'m, 'd>,
    document_checks: &DocumentChecks<'_>,
    checked: &Checked<'_>,
    certificate: &'p Certificate<'d>,
    path: Option<&'p CheckedPath<'d>>,
    provider: &'a P,
    parent: &Reader<'a>,
) -> Result<SignerBinding<'r, 'm, 'd, 'p>, BindError<P::Error>>
where
    'd: 'a,
{
    let at = prepared.signer().span().start;
    let processing = BindError::Processing;
    prepared
        .document()
        .message()
        .require_session(parent, "cades.basic")
        .map_err(|error| processing(Error::Cms(error)))?;
    if !core::ptr::eq(checked.signer(), prepared.signer()) {
        return Err(processing(Error::Foreign { at }));
    }
    let work = parent.execution();
    document_checks
        .require(prepared.document().message(), checked, &work)
        .map_err(|error| processing(Error::Cms(error)))?;
    let refusal = |cause| processing(Error::resource(cause, "cades.basic", at));
    work.charge_work(1).map_err(refusal)?;
    let mathematical = matches!(
        checked.content(),
        ContentAgreement::Matches | ContentAgreement::Direct
    ) && checked.signature() == Some(SignatureAnswer::Valid);
    let identifier =
        directory::matches_certificate_in(prepared.signer().sid(), certificate, parent)
            .map_err(BindError::Identifier)?;
    let mut key_matches = exact(
        checked.key().key().as_bytes(),
        certificate.tbs().public_key().as_bytes(),
        &work,
    )
    .map_err(refusal)?;
    if let Some(path) = path {
        if let Some(target) = path.members().last() {
            key_matches &= exact(
                target.certificate().as_bytes(),
                certificate.as_bytes(),
                &work,
            )
            .map_err(refusal)?;
            key_matches &=
                same_parameters(checked.key().parameters(), target.key().parameters(), &work)
                    .map_err(refusal)?;
        } else {
            key_matches = false;
        }
    } else {
        key_matches &= same_parameters(
            checked.key().parameters(),
            certificate.tbs().public_key().algorithm().parameters(),
            &work,
        )
        .map_err(refusal)?;
    }
    let mut included = None;
    for original in prepared.document().message().certificates() {
        work.charge_work(1).map_err(refusal)?;
        if exact(original.as_bytes(), certificate.as_bytes(), &work).map_err(refusal)? {
            included = Some(prepared.document().locate(original.span()));
            break;
        }
    }
    let ess = prepared
        .profile()
        .signing()
        .bind_certificate(provider, certificate, parent)
        .map_err(BindError::Ess)?;
    let restrictions = restrictions(prepared.profile().signing(), path, provider, parent)?;
    Ok(SignerBinding {
        prepared,
        path,
        certificate,
        identifier,
        ess,
        key_matches,
        included,
        mathematical,
        restrictions,
    })
}

pub(crate) fn restrictions<'a, P: AsnDigest<'a>>(
    signing: &structured_cms::ess::SigningAttributes<'a>,
    path: Option<&CheckedPath<'_>>,
    provider: &'a P,
    parent: &Reader<'a>,
) -> Result<PathRestriction, BindError<P::Error>> {
    let mut result = PathRestriction::Unstated;
    for set in [signing.v1(), signing.v2()].into_iter().flatten() {
        parent.charge(1).map_err(|cause| {
            BindError::Processing(Error::encoding(cause, "cades.ess.restrictions"))
        })?;
        if set.certificates().len() <= 1 {
            continue;
        }
        if !set.faults().is_empty() {
            return Ok(PathRestriction::Unproven);
        }
        let Some(path) = path else {
            return Ok(PathRestriction::PathUnavailable);
        };
        result = PathRestriction::Matches;
        // RFC5035 §§3/5 constrains certificates actually used, not a demand
        // that every signed identifier occur on this one path (attribute
        // certificates may also be named). Do not impose proposed erratum6566.
        // https://www.rfc-editor.org/rfc/rfc5035#section-3
        let Some((_, authorities)) = path.members().split_last() else {
            return Err(BindError::Processing(Error::Foreign {
                at: set.element().span().start,
            }));
        };
        for certificate in authorities
            .iter()
            .map(|member| member.certificate())
            .chain(path.anchor().certificate())
        {
            let answers = set
                .bind_validation_certificate(provider, certificate, parent)
                .map_err(BindError::Ess)?;
            let mut matched = false;
            let mut unsupported = false;
            for answer in &answers {
                parent.charge(1).map_err(|cause| {
                    BindError::Processing(Error::encoding(cause, "cades.ess.restrictions"))
                })?;
                if *answer == Binding::Matches {
                    matched = true;
                }
                if *answer == Binding::Unsupported {
                    unsupported = true;
                }
            }
            if !matched {
                return Ok(if unsupported {
                    PathRestriction::Unproven
                } else {
                    PathRestriction::Differs
                });
            }
        }
    }
    Ok(result)
}

pub(crate) fn ess_matches(bindings: Bindings) -> bool {
    (bindings.v1.is_some() || bindings.v2.is_some())
        && bindings.v1.is_none_or(|value| value == Binding::Matches)
        && bindings.v2.is_none_or(|value| value == Binding::Matches)
}

pub(crate) fn exact(
    left: &[u8],
    right: &[u8],
    work: &impl Work,
) -> Result<bool, structured_asn1::memory::MemoryError> {
    work.charge_work(1)?;
    if core::ptr::eq(left, right) {
        return Ok(true);
    }
    if left.len() != right.len() {
        return Ok(false);
    }
    work.charge_work(left.len() as u64)?;
    Ok(left == right)
}

fn same_parameters(
    left: Option<&[u8]>,
    right: Option<&[u8]>,
    work: &impl Work,
) -> Result<bool, structured_asn1::memory::MemoryError> {
    work.charge_work(1)?;
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => exact(left, right, work),
        _ => Ok(false),
    }
}
