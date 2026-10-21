//! Immutable original CMS identities shared by every `CAdES` stage.

use structured_asn1::memory::{HashWork, MemoryError};
use structured_asn1::{Element, Encoding, Parser, Reader, Span};
use structured_cms::{SignedData, signer::SignerInfo};
use structured_ltv::source::{Location, Snapshot, Source};

/// Identity of the borrowed immutable `SignedData` model. No bytes are hashed,
/// copied or compared to answer identity; independently parsed copies differ.
#[derive(Clone, Copy)]
pub struct DocumentId<'model, 'document>(&'model SignedData<'document>);

impl<'m, 'd> DocumentId<'m, 'd> {
    pub(crate) fn source(self) -> Document<'m, 'd> {
        Document { message: self.0 }
    }
}

impl core::fmt::Debug for DocumentId<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DocumentId").field(&self.0.span()).finish()
    }
}

impl PartialEq for DocumentId<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}

impl Eq for DocumentId<'_, '_> {}

/// One original CMS node in this immutable document. Offsets are coordinates
/// within its original CMS source, not fabricated physical XML/PDF positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Node {
    start: u64,
    length: u64,
}

impl Node {
    pub(crate) fn of(span: Span) -> Self {
        Self {
            start: span.start,
            length: span.length,
        }
    }

    /// Exact original node range. Joined token internals keep their own CMS
    /// `SourceMap`; this range identifies their original enclosing carrier.
    #[must_use]
    pub fn span(self) -> Span {
        Span {
            start: self.start,
            length: self.length,
        }
    }
}

impl HashWork for Node {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

/// Original node plus immutable document identity.
pub type Original<'model, 'document> = Location<Node, DocumentId<'model, 'document>, ()>;

/// Saved original field context. The element cannot be rebound to invented
/// encoding/depth or another parser; opening it uses the current operation's
/// execution while retaining its original source window and origin ceilings.
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    parser: &'a Parser,
    element: Element<'a>,
    encoding: Encoding,
    outer: u32,
    field: &'static str,
}

impl<'a> Value<'a> {
    pub(crate) fn of(reader: &Reader<'a>, element: Element<'a>, field: &'static str) -> Self {
        debug_assert!(reader.depth() > 0);
        Self {
            parser: reader.parser(),
            element,
            encoding: reader.encoding(),
            outer: reader.depth() - 1,
            field,
        }
    }
    /// Whole original field; no content has been joined or re-encoded.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Opens the original whole field with origin and current query ceilings.
    /// A later source switch never replaces the current operation with a
    /// broader ancestor or an account detached from that operation.
    pub fn reader_in<'query>(&self, operation: &Reader<'query>) -> crate::Result<Reader<'query>>
    where
        'a: 'query,
    {
        self.parser
            .read_nested_query_in(
                operation,
                self.element.as_bytes(),
                self.element.span().start,
                self.encoding,
                self.outer,
            )
            .map_err(|cause| crate::Error::encoding(cause, self.field))
    }
}

/// Borrowed original document, without an extra parser or storage owner.
/// Holding this borrow prevents mutation of its parsed model. Two wrappers
/// over the SAME model share identity; separately parsed equal bytes do not.
pub struct Document<'model, 'document> {
    message: &'model SignedData<'document>,
}

impl<'m, 'd> Document<'m, 'd> {
    /// Checks producing-parser provenance before exposing this identity domain.
    pub fn new(message: &'m SignedData<'d>, parent: &Reader<'_>) -> structured_cms::Result<Self> {
        message.require_session(parent, "cades")?;
        Ok(Self { message })
    }

    /// Original full CMS container, including material and parallel signers.
    #[must_use]
    pub fn message(&self) -> &'m SignedData<'d> {
        self.message
    }

    /// Locates one of the root container's actual signers, refusing substitutes.
    pub fn signer(&self, signer: &SignerInfo<'_>) -> structured_cms::Result<Original<'m, 'd>> {
        self.message.require_signer(signer, "cades.signer")?;
        Ok(self.locate(signer.span()))
    }

    pub(crate) fn locate(&self, span: Span) -> Original<'m, 'd> {
        Location {
            snapshot: self.snapshot(),
            node: Node::of(span),
        }
    }
}

impl<'m, 'd> Source for Document<'m, 'd> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();

    fn snapshot(&self) -> Snapshot<DocumentId<'m, 'd>, ()> {
        Snapshot {
            // The reference travels with each receipt's identity. A dropped
            // model/address reused by another parse cannot create an ABA match.
            document: DocumentId(self.message),
            generation: (),
        }
    }
}
