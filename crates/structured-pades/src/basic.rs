//! Original PDF range verification and existing CMS certificate/path bindings.

use crate::{
    binding::Mapping,
    timestamp::{Node, Pades},
};
use crate::{
    document::Document,
    error::{Error, ErrorKind, ReadFailure},
    prepare::Preparation,
    range::RangeSource,
    signature::CoveredError,
};
use structured_asn1::{Reader, memory::Work};
use structured_cades::{
    basic::{BindError, SignerBinding},
    counters::Paths,
};
use structured_cms::{
    prepare::{self, PrepareError},
    provider::SignatureProvider,
    verify::{self, ContentMode, DocumentBatch, DocumentChecks},
};
use structured_ltv::pki::{CounterReceipts, SignerReceipt};
use structured_pkix::{Certificate, algorithm::digest::AsnDigest, path::WorkingKey};

/// Original preparation/source/provider failure or completed unsupported input.
/// Each class remains distinguishable; none can produce a positive receipt.
#[derive(Debug)]
pub enum CheckError<E, P> {
    /// Original PDF source acquisition or current/origin resource refusal.
    Pdf(ReadFailure<E>),
    /// Original selected algorithm/schema preparation refusal.
    Prepare(PrepareError<P>),
    /// Shared verification preparation failure.
    Check(verify::CheckError<P>),
    /// Original streaming input/provider failure, including sticky refusal.
    Pass(verify::PassError<CoveredError<E>, P>),
    /// Completed unsupported selected mechanism, before payload acquisition.
    Unsupported(prepare::Part),
    /// Completed malformed mechanism, before payload acquisition.
    Malformed(structured_cms::Error),
}

/// CMS facts from the actual PDF `ByteRange` pass. The private constructor
/// prevents a result over caller replacement content from entering `PAdES`.
pub struct Mathematical<'v, 'p, 'm, 'd, 'a, 's, D, G> {
    prepared: &'v Preparation<'p, 'm, 'd, 'a, 's, D, G>,
    checks: DocumentChecks<'v>,
}

impl<'v, 'p, 'm, 'd, 'a, 's, D: Copy + Eq, G: Copy + Eq>
    Mathematical<'v, 'p, 'm, 'd, 'a, 's, D, G>
{
    /// Independent content and arithmetic answers of the original PDF pass.
    #[must_use]
    pub fn checks(&self) -> &DocumentChecks<'v> {
        &self.checks
    }

    /// The exact original signature whose `ByteRange` was actually processed.
    #[must_use]
    pub fn signature(&self) -> crate::signature::Signature<'a, 's, D, G> {
        self.prepared.container.signature()
    }

    /// Both the original range input and its selected-key signature passed.
    /// Certificate association, paths and application trust remain separate.
    #[must_use]
    pub fn input_verified(&self) -> bool {
        self.checks.checks().first().is_some_and(|checked| {
            matches!(
                checked.content(),
                verify::ContentAgreement::Matches | verify::ContentAgreement::Direct
            ) && checked.signature() == Some(structured_cms::provider::SignatureAnswer::Valid)
        })
    }

    /// Compares the actual checked effective key, original SID, included
    /// certificate and all protected ESS/path restrictions through their one
    /// existing shared kernel. It does not replay the PDF or its signature.
    ///
    /// # Panics
    /// Panics if the internal single-root verification invariant is violated.
    pub fn bind<'r, 'path, 'q, P: AsnDigest<'q>>(
        &'r self,
        certificate: &'path Certificate<'d>,
        path: Option<&'path structured_ltv::pki::CheckedPath<'d>>,
        provider: &'q P,
        parent: &Reader<'q>,
    ) -> Result<Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>, BindError<P::Error>>
    where
        'd: 'q,
    {
        let checked = self.checks.checks().first().expect("one prepared root");
        let binding = structured_cades::basic::bind(
            self.prepared.cms,
            &self.checks,
            checked,
            certificate,
            path,
            provider,
            parent,
        )?;
        let source = binding.signature();
        let signature = self.prepared.container.signature();
        let mapping = Mapping {
            snapshot: signature.owner().value.stamp.snapshot,
            root: Node::of(signature.location()),
            carrier: signature.contents(),
            cms_root: source.node,
            cms: source.snapshot,
        };
        Ok(Bound {
            prepared: self.prepared,
            binding,
            mapping,
        })
    }
}

/// Actual source-bound root signer/certificate association. Its detailed
/// negative facts remain available without creating a successful path receipt.
pub struct Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G> {
    prepared: &'v Preparation<'p, 'm, 'd, 'a, 's, D, G>,
    binding: SignerBinding<'p, 'm, 'd, 'path>,
    pub(crate) mapping: Mapping<'m, 'd, D, G>,
}

impl<'d, 'path, D: Copy + Eq, G: Copy + Eq> SignerReceipt<'path, 'd>
    for Bound<'_, '_, '_, 'd, '_, '_, 'path, D, G>
{
    type Id = Node;
    type Document = D;
    type Generation = G;
    fn signature(&self) -> structured_ltv::source::Location<Node, D, G> {
        structured_ltv::source::Location {
            snapshot: self.mapping.snapshot,
            node: self.mapping.root,
        }
    }
    fn path(&self) -> Option<&'path structured_ltv::pki::CheckedPath<'d>> {
        self.binding.path()
    }
}

/// The complete checked CMS counter set in its actual PDF source domain.
pub struct Counters<'r, 'm, 'd, 'path, D, G> {
    pub(crate) common: Paths<'r, 'm, 'd, 'path>,
    mapping: Mapping<'m, 'd, D, G>,
}
impl<'d, 'path, D: Copy + Eq, G: Copy + Eq> CounterReceipts<'path, 'd>
    for Counters<'_, '_, 'd, 'path, D, G>
{
    type Id = Node;
    type Document = D;
    type Generation = G;
    fn snapshot(&self) -> structured_ltv::source::Snapshot<D, G> {
        self.mapping.snapshot
    }
    fn signature(&self) -> Node {
        self.mapping.root
    }
    fn len(&self) -> usize {
        self.common.len()
    }
    fn counter(&self, ordinal: usize) -> structured_ltv::pki::Counter<'path, 'd, Node> {
        let actual = self.common.counter(ordinal);
        structured_ltv::pki::Counter {
            signature: self.mapping.node(actual.signature),
            property: self.mapping.node(actual.property),
            path: actual.path,
        }
    }
}

impl<'v, 'p, 'm, 'd, 'a, 's, 'path, D: Copy + Eq, G: Copy + Eq>
    Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>
{
    /// Existing SID/ESS/effective-key/path result, without projection losses.
    #[must_use]
    pub fn binding(&self) -> &SignerBinding<'p, 'm, 'd, 'path> {
        &self.binding
    }

    /// Original PDF/CMS preparation, unchanged by the selected path result.
    #[must_use]
    pub fn prepared(&self) -> &'v Preparation<'p, 'm, 'd, 'a, 's, D, G> {
        self.prepared
    }
}

/// Complete root and original nested counter composition. Reuses the same
/// source-domain receipts later consumed by the common LTV participant core.
pub struct Basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D, G> {
    bound: &'r Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>,
    counters: Counters<'r, 'm, 'd, 'path, D, G>,
    complete: bool,
}

impl<D: Copy + Eq, G: Copy + Eq> Basic<'_, '_, '_, '_, '_, '_, '_, '_, D, G> {
    /// Mandatory format, actual PDF input math and whole counter census hold.
    /// This is independent of trusted time, revocation usability and trust.
    #[must_use]
    pub fn all_basic_requirements_met(&self) -> bool {
        self.complete
    }
}

impl<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D: Copy + Eq, G: Copy + Eq>
    Basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>
{
    /// Actual original signer/certificate/path binding used by this stage.
    #[must_use]
    pub fn binding(&self) -> &'r Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G> {
        self.bound
    }
    /// The complete original counter receipt set, without caller subsetting.
    #[must_use]
    pub fn counters(&self) -> &Counters<'r, 'm, 'd, 'path, D, G> {
        &self.counters
    }
    /// Carries an already checked original CMS timestamp into this PDF's
    /// source domain. The original model, parent signature and exact input
    /// remain checked by the shared `CAdES` receipt, without cryptographic replay.
    pub fn timestamp_actor<'c>(
        &self,
        actor: structured_ltv::timestamp::CheckedActor<
            'c,
            'd,
            structured_cades::source::Node,
            structured_cades::source::DocumentId<'m, 'd>,
            (),
            structured_cades::Cades,
        >,
        operation: &impl Work,
    ) -> crate::Result<structured_ltv::timestamp::CheckedActor<'c, 'd, Node, D, G, Pades>> {
        self.bound.mapping.actor(
            actor,
            &self
                .bound
                .prepared
                .container
                .signature()
                .owner()
                .value
                .session
                .query(operation),
        )
    }
}

impl<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D: Copy + Eq, G: Copy + Eq>
    structured_ltv::baseline::BasicStage<'path, 'd>
    for Basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>
{
    type Id = Node;
    type Document = D;
    type Generation = G;
    type Signer = Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>;
    type Counters = Counters<'r, 'm, 'd, 'path, D, G>;
    fn signer(&self) -> &Self::Signer {
        self.bound
    }
    fn counters(&self) -> &Self::Counters {
        &self.counters
    }
    fn all_requirements_met(&self) -> bool {
        self.complete
    }
}

/// Joins the actual root association with ALL original counters. The existing
/// common assembly checks source, selected-root and exact member provenance;
/// only `PAdES`'s independently prepared root format replaces `CAdES` B-B fields.
pub fn basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D: Copy + Eq, G: Copy + Eq>(
    bound: &'r Bound<'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>,
    counters: Paths<'r, 'm, 'd, 'path>,
    parent: &Reader<'_>,
) -> structured_cades::Result<Basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, D, G>> {
    let common = structured_cades::basic::basic(&bound.binding, counters, parent)?;
    let counters = Counters {
        common: common.into_counters(),
        mapping: bound.mapping,
    };
    let complete = bound.prepared.all_basic_format_requirements_met() && bound.binding.is_bound();
    Ok(Basic {
        bound,
        counters,
        complete,
    })
}

impl<'p, 'm, 'd, 'a, 's, D: Copy + Eq, G: Copy + Eq> Preparation<'p, 'm, 'd, 'a, 's, D, G> {
    /// Resolves and verifies the original detached root through the common
    /// asynchronous CMS driver. The source is constructed here from the exact
    /// prepared PDF signature, never accepted as a replacement caller payload.
    pub async fn verify<'v, S, P>(
        &'v self,
        document: &'v Document<'s, S>,
        provider: &'v P,
        key: WorkingKey<'v>,
        parent: &Reader<'v>,
    ) -> Result<Mathematical<'v, 'p, 'm, 'd, 'a, 's, D, G>, CheckError<S::Error, P::Error>>
    where
        'm: 'v,
        'd: 'v,
        'a: 'v,
        's: 'v,
        S: RangeSource<Document = D, Generation = G>,
        P: SignatureProvider<'v>,
    {
        let message = self.cms.document().message();
        self.container
            .require(message, parent)
            .map_err(|cause| CheckError::Pdf(cause.into()))?;
        let work = parent.execution();
        if message.signers().len() != 1 || !message.content().is_detached() {
            return Err(CheckError::Pdf(
                Error {
                    kind: ErrorKind::Syntax(crate::error::Syntax::Container),
                    location: self.container.signature().contents(),
                }
                .into(),
            ));
        }
        let plan = match prepare::resolve(
            provider,
            self.cms.signer(),
            key,
            parent,
            structured_cms::binding::Scope::Content(message.content().kind()),
        )
        .map_err(CheckError::Prepare)?
        {
            prepare::Preparation::Ready(plan) => plan,
            prepare::Preparation::Unsupported(part) => return Err(CheckError::Unsupported(part)),
            prepare::Preparation::Malformed(cause) => return Err(CheckError::Malformed(cause)),
        };
        let mut requests = work.vector();
        requests.try_push(plan).map_err(|cause| {
            CheckError::Pdf(
                Error {
                    kind: ErrorKind::Resource(cause),
                    location: self.container.signature().location(),
                }
                .into(),
            )
        })?;
        let batch = DocumentBatch::prepare(
            provider,
            message,
            requests.into_owned(),
            ContentMode::Detached,
            parent,
        )
        .map_err(CheckError::Check)?;
        let mut source = document
            .covered(self.container.signature(), &work)
            .map_err(CheckError::Pdf)?;
        let checks = batch
            .run_detached_async(&mut source)
            .await
            .map_err(CheckError::Pass)?;
        Ok(Mathematical {
            prepared: self,
            checks,
        })
    }
}
