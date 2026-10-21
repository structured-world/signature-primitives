//! Complete original countersignature bindings through the existing CMS driver.

use crate::Error;
use crate::basic::{PathRestriction, ess_matches, exact};
use crate::prepare::Preparation;
use crate::source::{DocumentId, Node, Original};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Reader, Span};
use structured_cms::binding::Scope;
use structured_cms::cades::Role;
use structured_cms::counter::{Visit, WalkError};
use structured_cms::directory::{self, CertificateAgreement};
use structured_cms::prepare::{self, PrepareError};
use structured_cms::provider::{SignatureAnswer, SignatureProvider};
use structured_cms::verify::{Batch, ContentAgreement, PassError};
use structured_cms::{Octets, signer::SignerInfo};
use structured_ltv::pki::{CheckedPath, Counter, CounterReceipts};
use structured_ltv::source::Snapshot;
use structured_pkix::Certificate;
use structured_pkix::algorithm::digest::AsnDigest;

/// One actual counter's execution refusal; negative document answers stay facts.
#[derive(Debug)]
pub enum CheckError<E> {
    /// Original common provenance, schema or resource refusal.
    Processing(Error),
    /// Original signature preflight/provider refusal.
    Prepare(PrepareError<E>),
    /// Original complete parent-signature pass/provider refusal.
    Verify(PassError<structured_cms::octets::SourceError, E>),
    /// Original selected-certificate hint query refusal.
    Identifier(directory::Error),
    /// Original ESS execution refusal.
    Ess(structured_cms::ess::BindingError<E>),
    /// Original signed validation-set/path restriction execution refusal.
    Restriction(crate::basic::BindError<E>),
}

/// Completed insufficiency remains distinct from a processing failure.
#[derive(Debug)]
pub enum Outcome {
    /// Original counter's arithmetic, certificate and profile binding hold.
    Bound,
    /// Its readable signature/payload/certificate/profile fact did not hold.
    Differs,
    /// Its selected provider cannot process the original mechanism.
    Unsupported(prepare::Part),
    /// Original malformed binding was retained, not turned into absence.
    Malformed(structured_cms::Error),
}

/// Actual counter result retaining the checked path and original parent link.
/// Only [`Context::check`] constructs it over the parent's ORIGINAL octets.
pub struct Binding<'model, 'document, 'path> {
    source: Original<'model, 'document>,
    parent: Node,
    path: &'path CheckedPath<'document>,
    outcome: Outcome,
    profile: structured_cms::cades::Profile<'document>,
    identifier: Option<CertificateAgreement>,
    signing: Option<structured_cms::ess::Bindings>,
    content: Option<ContentAgreement>,
    signature: Option<SignatureAnswer>,
    restrictions: Option<PathRestriction>,
}

impl<'m, 'd, 'p> Binding<'m, 'd, 'p> {
    fn unproven(
        source: Original<'m, 'd>,
        parent: Span,
        path: &'p CheckedPath<'d>,
        profile: structured_cms::cades::Profile<'d>,
    ) -> Self {
        Self {
            source,
            parent: Node::of(parent),
            path,
            outcome: Outcome::Differs,
            profile,
            identifier: None,
            signing: None,
            content: None,
            signature: None,
            restrictions: None,
        }
    }
    /// Exact original child in its immutable source generation.
    #[must_use]
    pub fn source(&self) -> Original<'m, 'd> {
        self.source
    }
    /// Original direct parent, not the root of a flattened counter list.
    #[must_use]
    pub fn parent(&self) -> Node {
        self.parent
    }
    /// Original completed answer, never a trust or root baseline verdict.
    #[must_use]
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    /// Actual original profile and every independently retained schema fault.
    #[must_use]
    pub fn profile(&self) -> &structured_cms::cades::Profile<'d> {
        &self.profile
    }
    /// Original SID result, including unreadable SKI details; None means that
    /// no target certificate was available, not a completed mismatch.
    #[must_use]
    pub fn identifier(&self) -> Option<&CertificateAgreement> {
        self.identifier.as_ref()
    }
    /// Original independent ESS answers, when certificate binding was reached.
    #[must_use]
    pub fn signing(&self) -> Option<structured_cms::ess::Bindings> {
        self.signing
    }
    /// Original payload-to-attribute answer, preserving owned malformed detail.
    #[must_use]
    pub fn content(&self) -> Option<&ContentAgreement> {
        self.content.as_ref()
    }
    /// Actual mathematical result, independently of payload/profile binding.
    #[must_use]
    pub fn signature(&self) -> Option<SignatureAnswer> {
        self.signature
    }
    /// Actual later-certificate restriction result, if that stage was reached.
    #[must_use]
    pub fn restrictions(&self) -> Option<PathRestriction> {
        self.restrictions
    }
}

/// Short borrowed selection for one original child. It cannot escape the
/// iterative walk; its returned binding may retain original bytes/path facts.
pub struct Context<'scope, 'model, 'document> {
    selected: Original<'model, 'document>,
    signer: &'scope SignerInfo<'document>,
    parent_signature: &'scope Octets<'document>,
    parent: Span,
    reader: &'scope Reader<'document>,
}

impl<'m, 'd> Context<'_, 'm, 'd> {
    /// Original child used to choose its certificate/provider, without reparsing.
    #[must_use]
    pub fn signer(&self) -> &SignerInfo<'d> {
        self.signer
    }

    /// Checks exactly this parent's signature octets through the shared CMS
    /// counter scope, original attrs and selected provider. The application only
    /// selects certificate/path/provider; it cannot supply a replacement payload
    /// or a writable successful binding. No plain counter is required to carry
    /// the root's content-type/signing-time/ESS baseline fields.
    /// RFC5652 §11.4 and EN319122-1 §5.2.7 define this input and placement.
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-11.4>
    pub fn check<'a, 'p, P>(
        &'a self,
        provider: &'a P,
        certificate: &Certificate<'d>,
        path: &'p CheckedPath<'d>,
    ) -> Result<Binding<'m, 'd, 'p>, CheckError<P::Error>>
    where
        'd: 'a,
        P: SignatureProvider<'a> + AsnDigest<'a>,
    {
        let at = self.signer.span().start;
        let processing = |error| CheckError::Processing(Error::Cms(error));
        let work = self.reader.execution();
        let resource = |cause| CheckError::Processing(Error::resource(cause, "cades.counter", at));
        let profile =
            structured_cms::cades::profile(self.signer, Role::Countersignature, self.reader)
                .map_err(processing)?;
        let conforms = profile_conforms(self.signer, &profile, self.reader)?;
        let mut result = Binding::unproven(self.selected, self.parent, path, profile);
        let Some(target) = path.members().last() else {
            return Ok(result);
        };
        let same_certificate = exact(
            target.certificate().as_bytes(),
            certificate.as_bytes(),
            &work,
        )
        .map_err(resource)?;
        result.identifier = Some(
            directory::matches_certificate_in(self.signer.sid(), certificate, self.reader)
                .map_err(CheckError::Identifier)?,
        );
        if !same_certificate
            || !matches!(result.identifier, Some(CertificateAgreement::Matches))
            || !conforms
        {
            return Ok(result);
        }
        let plan = prepare::resolve(
            provider,
            self.signer,
            target.key(),
            self.reader,
            Scope::CounterSignature,
        )
        .map_err(CheckError::Prepare)?;
        let plan = match plan {
            prepare::Preparation::Ready(plan) => plan,
            prepare::Preparation::Unsupported(part) => {
                result.outcome = Outcome::Unsupported(part);
                return Ok(result);
            }
            prepare::Preparation::Malformed(error) => {
                result.outcome = Outcome::Malformed(error);
                return Ok(result);
            }
        };
        let mut requests = work.vector();
        requests.try_push(plan).map_err(resource)?;
        let batch = Batch::prepare(provider, requests.into_owned(), &work, "cades.counter", at)
            .map_err(|source| {
                CheckError::Verify(structured_cms::stream::StreamError::Callback(source))
            })?;
        let mut original_parent = self.parent_signature;
        let checks = batch
            .run(&mut original_parent, &work)
            .map_err(CheckError::Verify)?;
        let Some(checked) = checks.into_iter().next() else {
            return Err(CheckError::Processing(Error::Foreign { at }));
        };
        let (_, _, content, signature) = checked.into_parts();
        let math = matches!(
            content,
            ContentAgreement::Direct | ContentAgreement::Matches
        ) && signature == Some(SignatureAnswer::Valid);
        result.content = Some(content);
        result.signature = signature;
        let signing = result.profile.signing();
        let ess = if signing.v1().is_some() || signing.v2().is_some() {
            let bindings = signing
                .bind_certificate(provider, certificate, self.reader)
                .map_err(CheckError::Ess)?;
            result.signing = Some(bindings);
            ess_matches(bindings)
        } else {
            true
        };
        let restriction = crate::basic::restrictions(signing, Some(path), provider, self.reader)
            .map_err(CheckError::Restriction)?;
        result.restrictions = Some(restriction);
        if math
            && ess
            && matches!(
                restriction,
                PathRestriction::Unstated | PathRestriction::Matches
            )
        {
            result.outcome = Outcome::Bound;
        }
        Ok(result)
    }
}

fn profile_conforms<E>(
    signer: &SignerInfo<'_>,
    profile: &structured_cms::cades::Profile<'_>,
    reader: &Reader<'_>,
) -> Result<bool, CheckError<E>> {
    let mut conforms = signer.faults().is_empty()
        && profile.faults().is_empty()
        && profile.signing().faults().is_empty();
    for attribute in [profile.signing().v1(), profile.signing().v2()]
        .into_iter()
        .flatten()
    {
        reader
            .charge(1)
            .map_err(|cause| CheckError::Processing(Error::encoding(cause, "cades.counter")))?;
        if !attribute.faults().is_empty() {
            conforms = false;
        }
    }
    Ok(conforms)
}

/// Complete original counter outcomes. Negative outcomes are kept; they cannot
/// be converted to the complete-path receipt required by the LTV participant set.
pub struct Bindings<'model, 'document, 'path> {
    signature: Original<'model, 'document>,
    values: OwnedVec<Option<Binding<'model, 'document, 'path>>>,
    complete: bool,
}

impl<'m, 'd, 'p> Bindings<'m, 'd, 'p> {
    /// Every original readable counter, once, in original depth-first order.
    #[must_use]
    pub fn values(&self) -> &[Option<Binding<'m, 'd, 'p>>] {
        &self.values
    }
    /// A complete actual-path census only when EVERY original counter bound.
    #[must_use]
    pub fn paths(&self) -> Option<Paths<'_, 'm, 'd, 'p>> {
        if self.complete {
            Some(Paths { bindings: self })
        } else {
            None
        }
    }
}

/// Borrowed complete actual counter paths, issued after checking all outcomes.
pub struct Paths<'receipt, 'model, 'document, 'path> {
    bindings: &'receipt Bindings<'model, 'document, 'path>,
}

impl<'m, 'd, 'p> CounterReceipts<'p, 'd> for Paths<'_, 'm, 'd, 'p> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    fn snapshot(&self) -> Snapshot<DocumentId<'m, 'd>, ()> {
        self.bindings.signature.snapshot
    }
    fn signature(&self) -> Node {
        self.bindings.signature.node
    }
    fn len(&self) -> usize {
        self.bindings.values.len()
    }
    fn counter(&self, ordinal: usize) -> Counter<'p, 'd, Node> {
        let Some(entry) = &self.bindings.values[ordinal] else {
            unreachable!("only a complete counter set exposes Paths")
        };
        Counter {
            signature: entry.source.node,
            property: entry.source.node,
            path: entry.path,
        }
    }
}

/// Original walk or selected-handler refusal; no partial result is returned.
pub type BindingsError<E> = WalkError<SelectionError<E>>;

/// Counter selection failure or a substituted original receipt.
#[derive(Debug)]
pub enum SelectionError<E> {
    /// Exact caller/provider selection failure, without conversion to mismatch.
    Callback(E),
    /// Selected result belongs to a different child, parent or source.
    Foreign {
        /// Actual child being selected.
        at: u64,
    },
}

/// Visits the complete original nested counter set, allowing only selection and
/// use of [`Context::check`]. Returned bindings are checked against the actual
/// current child/parent/source before being retained. A callback cannot replay a
/// receipt for another child, and a malformed value cannot be silently skipped.
pub fn bind<'m, 'd, 'p, E>(
    prepared: &Preparation<'m, 'd>,
    parent: &Reader<'d>,
    mut select: impl FnMut(Context<'_, 'm, 'd>) -> Result<Binding<'m, 'd, 'p>, E>,
) -> Result<Bindings<'m, 'd, 'p>, BindingsError<E>> {
    let mut complete = true;
    let values = structured_cms::counter::walk(prepared.signer(), parent, |visit, reader| {
        let Visit::Signer {
            signer,
            signature,
            parent: owner,
        } = visit
        else {
            // The prepared report retains the unreadable value and its cause.
            // No complete-path receipt will be issued for this census.
            complete = false;
            return Ok(None);
        };
        let selected = prepared.document().locate(signer.span());
        let result = select(Context {
            selected,
            signer,
            parent_signature: signature,
            parent: owner,
            reader,
        })
        .map_err(SelectionError::Callback)?;
        if result.source != selected || result.parent != Node::of(owner) {
            return Err(SelectionError::Foreign {
                at: signer.span().start,
            });
        }
        if !matches!(result.outcome, Outcome::Bound) {
            complete = false;
        }
        Ok(Some(result))
    })?;
    Ok(Bindings {
        signature: prepared.document().locate(prepared.signer().span()),
        values,
        complete,
    })
}
