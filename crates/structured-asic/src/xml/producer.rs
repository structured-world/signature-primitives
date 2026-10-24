//! Closed association of an actual complete ZIP input with its produced XML.

use crate::{
    manifest, references,
    zip::{Member, ReadFailure},
};
use core::future::Future;
use structured_asn1::{
    memory::{HashWork, OwnedVec, Work},
    range::RangeSource,
};
use structured_xades::{
    attributes::AttributeXml,
    binary::OwnedBinaryXml,
    scalar::{ScalarXml, UriXml},
    xml::{Access, AccessError, Snapshot, Xml},
};

pub mod signed;

/// Stable XML owner types, independent of temporary parsed-document borrows.
pub trait Types {
    /// Stable original node identity, not a phase-local position.
    type Id: Copy + Eq + HashWork;
    /// Immutable original document identity.
    type Document: Copy + Eq;
    /// Original generation, checked before and after scoped operations.
    type Generation: Copy + Eq;
    /// Original XML processing/resource refusal.
    type Error;
}

/// Actual owner of the moved input and admitted AST/arena storage. A borrowed
/// view can remain alive across await without pinning or extending a lifetime.
pub trait Parsed: Types {
    /// Structural capabilities over this actual document. Signature verification
    /// is separate and must retain this same original snapshot, root and bytes.
    type View<'a>: Xml<
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
            Error = Self::Error,
        > + ScalarXml
        + AttributeXml
        + UriXml
        + OwnedBinaryXml
    where
        Self: 'a;
    /// Borrows this document without decoding, copying input or reparsing it.
    fn view(&self) -> Self::View<'_>;
    /// Original whole-document root, not a detached/reparented subtree.
    fn root(&self) -> Self::Id;
}

/// Existing XML parser's funded ownership boundary. Parsing must consume the
/// COMPLETE supplied bytes as one XML document. Retain their actual capacity
/// charge; transfer validated text without a second buffer where supported.
/// Admit every decode, arena growth, traversal and callback through current
/// Work and the actual source limits. No default-budget parser substitutes it.
pub trait Factory: Types {
    /// Storage may borrow this operation's arena/account. The common driver
    /// keeps it alive until the entire asynchronous visitor has completed.
    type Parsed<'a, W: Work + 'a>: Parsed<
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
            Error = Self::Error,
        >
    where
        Self: 'a;
    /// Accepts the actual complete CRC-checked allocation by ownership.
    fn parse<'a, W: Work + 'a>(
        &'a self,
        input: OwnedVec<u8>,
        execution: &'a W,
    ) -> impl Future<Output = Result<Self::Parsed<'a, W>, Self::Error>> + 'a;
}

/// Fixed-output continuation. Its result cannot borrow the temporary document
/// or view; independently owned findings can retain original scalar identities.
pub trait Visitor<'v, 's, F: Types + ?Sized, S: RangeSource> {
    /// Completed independently retained result, never a temporary XML borrow.
    type Output;
    /// Visitor's original cause, preserved over any later snapshot check.
    type Error;
    /// Executes while the actual parsed owner, source and query are alive.
    fn visit<X, W: Work>(
        self,
        source: Source<'_, 'v, 's, X, S, W>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>>
    where
        X: Xml<Id = F::Id, Document = F::Document, Generation = F::Generation, Error = F::Error>
            + ScalarXml
            + AttributeXml
            + UriXml
            + OwnedBinaryXml;
}

/// The actual original member and the view produced from its complete bytes.
/// Only the closed driver constructs it. A caller cannot attach an independently
/// parsed snapshot, assert a name match, or replace the narrowed current Work.
pub struct Source<'q, 'v, 's, X: Xml, S: RangeSource, W: Work> {
    member: &'q Member<'v, 's, S>,
    xml: &'q X,
    root: X::Id,
    snapshot: Snapshot<X::Document, X::Generation>,
    execution: &'q W,
}
impl<'v, 's, X: Xml, S: RangeSource, W: Work> Source<'_, 'v, 's, X, S, W> {
    /// Actual complete original ZIP occurrence supplied to the XML owner.
    #[must_use]
    pub fn member(&self) -> &Member<'v, 's, S> {
        self.member
    }
    /// Original produced view, preserving namespace and parent context.
    #[must_use]
    pub fn xml(&self) -> &X {
        self.xml
    }
    /// Actual original root.
    #[must_use]
    pub fn root(&self) -> X::Id {
        self.root
    }
    /// Snapshot observed from the actual produced view.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.snapshot
    }
    /// Same source/current operation used for acquisition and XML production.
    #[must_use]
    pub fn execution(&self) -> &W {
        self.execution
    }
}

/// Source, producer and continuation failures retain independent original roles.
#[derive(Debug)]
pub enum Error<SE, PE, VE, XE> {
    /// Complete input/CRC, snapshot or source/current budget refused.
    Input(SE),
    /// Actual XML decoding/parsing/arena refused.
    Produce(PE),
    /// Original callback failure, including its resource/processing class.
    Visit(VE),
    /// Produced root or generation/current query refused.
    Xml(XE),
}

impl<'v, 's, S: RangeSource> Member<'v, 's, S> {
    /// Acquires exactly this original member, validates EOF/CRC and moves its
    /// funded allocation to the selected XML owner. The association is minted
    /// only around that actual owner's scoped view. Cancellation drops all
    /// driver-owned temporary storage; external visitor effects are not rolled
    /// back. No successful partial result is returned after a late refusal.
    pub async fn with_xml<F: Factory, V: Visitor<'v, 's, F, S>, W: Work>(
        &self,
        factory: &F,
        visitor: V,
        work: &W,
    ) -> Result<
        V::Output,
        Error<
            ReadFailure<S::Error, S::Document, S::Generation>,
            F::Error,
            V::Error,
            AccessError<F::Error, F::Id>,
        >,
    > {
        self.content(work)
            .await
            .map_err(Error::Input)?
            .with_xml(factory, visitor, work)
            .await
    }
}

impl<'v, 's, S: RangeSource> crate::content::Content<'v, 's, S> {
    /// Moves the already complete allocation into XML production. Raw manifest
    /// signatures/time assertions can consume this same retained input first,
    /// avoiding a second ZIP acquisition, decode, CRC pass or buffer copy.
    pub async fn with_xml<F: Factory, V: Visitor<'v, 's, F, S>, W: Work>(
        self,
        factory: &F,
        visitor: V,
        work: &W,
    ) -> Result<
        V::Output,
        Error<
            ReadFailure<S::Error, S::Document, S::Generation>,
            F::Error,
            V::Error,
            AccessError<F::Error, F::Id>,
        >,
    > {
        let archive = self.member().archive();
        let execution = archive.session().query(work);
        let (member, input) = self.into_parts();
        archive
            .admit(&execution, member.central_span())
            .map_err(|cause| {
                Error::Input(ReadFailure::Processing {
                    member: member.id(),
                    cause,
                })
            })?;
        let document = factory
            .parse(input, &execution)
            .await
            .map_err(Error::Produce)?;
        let root = document.root();
        let xml = document.view();
        let snapshot = xml.snapshot();
        let access = Access::new(&xml, snapshot, &execution);
        access.inspect(root, |_| ()).map_err(Error::Xml)?;
        member
            .archive()
            .admit(&execution, member.central_span())
            .map_err(|cause| {
                Error::Input(ReadFailure::Processing {
                    member: member.id(),
                    cause,
                })
            })?;
        let result = visitor
            .visit(Source {
                member: &member,
                xml: &xml,
                root,
                snapshot,
                execution: &execution,
            })
            .await
            .map_err(Error::Visit)?;
        access.inspect(root, |_| ()).map_err(Error::Xml)?;
        archive
            .admit(&execution, member.central_span())
            .map_err(|cause| {
                Error::Input(ReadFailure::Processing {
                    member: member.id(),
                    cause,
                })
            })?;
        Ok(result)
    }
}

/// Whole original manifest, resolved inside its producing scope. This binding
/// cannot escape the owner borrow or be constructed from independent snapshots.
pub struct Manifest<'q, 'v, 's, X: Xml, S: RangeSource, W: Work> {
    xml: &'q X,
    execution: &'q W,
    catalogue: references::Catalogue<'v, 's, X::Id, X::Document, X::Generation, S>,
}
/// Original manifest syntax and exact member resolution retain their causes.
#[derive(Debug)]
pub enum ManifestError<ME, RE> {
    /// Actual original XML structure/scalar inspection failed.
    Inspect(ME),
    /// Exact original reference or source/current admission failed.
    Resolve(RE),
}
/// Original source-produced manifest and unchanged grammar/resolution errors.
pub type ManifestResult<'q, 'v, 's, X, S, W> = Result<
    Manifest<'q, 'v, 's, X, S, W>,
    ManifestError<
        manifest::Error<<X as Xml>::Error, <X as Xml>::Id>,
        references::ResolveError<<X as Xml>::Error, <X as Xml>::Id, <S as RangeSource>::Error>,
    >,
>;
impl<'q, 'v, 's, X, S, W> Source<'q, 'v, 's, X, S, W>
where
    X: Xml + AttributeXml + ScalarXml + UriXml,
    S: RangeSource,
    W: Work,
{
    /// Inspects package inventory only from this actual produced document.
    /// Filename association remains distinct from signature authentication.
    pub fn package(
        &self,
        format: crate::package::Format,
    ) -> crate::package::InspectionResult<'v, 's, X, S> {
        let access = Access::new(self.xml, self.snapshot, self.execution);
        let base = self
            .member
            .archive()
            .original(self.member.id(), self.execution)
            .map_err(crate::package::Error::Archive)?;
        crate::package::inspect(base, &access, self.root, format)
    }
    /// Inspects and resolves the actual produced root, never an external node.
    pub fn manifest(&self) -> ManifestResult<'q, 'v, 's, X, S, W> {
        let access = Access::new(self.xml, self.snapshot, self.execution);
        let reading = manifest::inspect(&access, self.root).map_err(ManifestError::Inspect)?;
        let base = self
            .member
            .archive()
            .original(self.member.id(), self.execution)
            .map_err(|cause| ManifestError::Resolve(references::ResolveError::Archive(cause)))?;
        let catalogue = references::resolve_manifest(base, reading, self.xml, self.execution)
            .map_err(ManifestError::Resolve)?;
        Ok(Manifest {
            xml: self.xml,
            execution: self.execution,
            catalogue,
        })
    }
}
impl<'v, 's, X: Xml, S: RangeSource, W: Work> Manifest<'_, 'v, 's, X, S, W> {
    /// Original source association, still inside its actual producing scope.
    #[must_use]
    pub fn source(&self) -> Source<'_, 'v, 's, X, S, W> {
        Source {
            member: self.catalogue.base(),
            xml: self.xml,
            root: self.catalogue.reading().root(),
            snapshot: self.catalogue.reading().snapshot(),
            execution: self.execution,
        }
    }
    /// Complete syntax/reference census, independently of crypto and trust.
    #[must_use]
    pub fn catalogue(
        &self,
    ) -> &references::Catalogue<'v, 's, X::Id, X::Document, X::Generation, S> {
        &self.catalogue
    }
    /// Moves independently retained source-derived instructions without keeping
    /// the temporary AST alive. This is inspection evidence, not replay authority
    /// or authenticated manifest coverage. No catalogue or string is copied.
    pub fn into_facts(self) -> Facts<'v, 's, X::Id, X::Document, X::Generation, S> {
        Facts {
            catalogue: self.catalogue,
            digests: None,
        }
    }
}

/// Complete instructions derived inside the actual producing XML scope. Only
/// that closed scope can construct these retained facts; no public attach or
/// arbitrary member-plus-snapshot constructor exists.
pub struct Facts<'v, 's, N, D, G, S: RangeSource> {
    catalogue: references::Catalogue<'v, 's, N, D, G, S>,
    digests: Option<OwnedVec<references::DigestReading>>,
}
impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Facts<'v, 's, N, D, G, S> {
    /// Every original syntax fault, extension, rootfile and reference outcome.
    #[must_use]
    pub fn catalogue(&self) -> &references::Catalogue<'v, 's, N, D, G, S> {
        &self.catalogue
    }
    /// Every actual original object hash result. None means not executed,
    /// independently of syntax, manifest authentication and archive geometry.
    #[must_use]
    pub fn object_digests(&self) -> Option<&[references::DigestReading]> {
        self.digests.as_deref()
    }
}

impl<'v, 's, X: OwnedBinaryXml, S: RangeSource, W: Work> Manifest<'_, 'v, 's, X, S, W> {
    /// Checks every actual source instruction before retaining the source-bound
    /// facts. Repeated references share one complete member pass; the result
    /// survives AST drop without gaining XML replay authority or trust.
    pub async fn check_objects<'p, P: structured_xades::certificate::DigestProvider<'p, X>>(
        self,
        provider: &'p P,
    ) -> Result<
        Facts<'v, 's, X::Id, X::Document, X::Generation, S>,
        references::CheckError<
            X::Error,
            P::Error,
            X::Id,
            X::Document,
            X::Generation,
            S::Error,
            S::Document,
            S::Generation,
        >,
    > {
        let answers = self
            .catalogue
            .check_objects(self.xml, provider, self.execution)
            .await?
            .into_answers();
        Ok(Facts {
            catalogue: self.catalogue,
            digests: Some(answers),
        })
    }
}
