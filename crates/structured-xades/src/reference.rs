//! Authenticated reference resolution shared by signed property mechanisms.

use crate::binding::{Reference, SignatureXml};
use crate::xml::{Name, Snapshot};
use structured_asn1::memory::Work;
use structured_cms::stream::Receiver;

/// Exact authenticated parent of an original reference instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parent<N> {
    /// Direct child of the selected signature's original `SignedInfo`.
    SignedInfo(N),
    /// Child of a Manifest authenticated by this selected signature.
    Manifest(N),
}

/// Final conversion after the original reference transform chain. Explicit
/// final canonicalization already in that chain keeps its actual method;
/// octet output is never canonicalized a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay<N> {
    /// Ordinary `XMLDSig` reference output before hashing, including its implicit
    /// C14N1.0 conversion of a remaining node-set. EN319132-1 §5.5.3 uses this
    /// output for `NewSDODigestValue`.
    ReferenceOutput,
    /// Convert a remaining node-set with this original timestamp method and
    /// parameters, as required for timestamp/archive imprint input.
    Timestamp(N),
}

/// Origin of the resource actually observed by the original operation. It is
/// never inferred from a URI string or absence of an element target identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLocation {
    /// Original document node, including a whole-document reference.
    SameDocument,
    /// Original resolver selected/admitted the external resource route. This
    /// includes typed Missing explicit bytes as well as Present bytes with
    /// original resource identity; URI spelling or target=None cannot prove it.
    Detached,
    /// Generated, unprocessed or otherwise unclassified resource.
    Unknown,
}

/// Complete replay is distinct from missing explicit detached source bytes.
/// Only the owner's original resource lookup may produce Unavailable; stale
/// identities, malformed URI/transform, policy and resource refusals remain Err.
#[derive(Debug)]
pub enum ReplayOutcome<E> {
    /// Every required byte was delivered successfully through complete EOF.
    Complete,
    /// Detached bytes are absent from the original immutable explicit request.
    /// No implicit reacquisition, re-verification or default resource is allowed.
    Unavailable(E),
}

/// Callback-local instruction metadata; target validation remains independent.
#[derive(Debug, Clone, Copy)]
pub struct Descriptor<'a, N> {
    /// Original reference and its actual target digest/coverage results.
    pub reference: Reference<'a, N>,
    /// Original authenticated instruction container.
    pub parent: Parent<N>,
    /// Original observed source kind, separately from digest/parent validity.
    pub object_location: ObjectLocation,
}

/// Original XML location supplying a reference URI to the same owner resolver.
/// The property node always supplies XML Base and source provenance; callers
/// never replace this location with a separately collected or normalized URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexicalSource<'a> {
    /// Original attribute selected by its expanded XML name.
    Attribute(Name<'a>),
    /// Direct simple content: text/CDATA in order, excluding comments/PI.
    /// Element children are malformed, not recursively flattened string values.
    /// Empty text remains present and follows the URI rules, never Missing.
    SimpleContent,
}

/// URI lookup outcome without confusing processing refusal with absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution<R> {
    /// An authenticated original reference was passed to the scoped visitor.
    Resolved(R),
    /// Original attribute is absent.
    Missing,
    /// URI does not resolve to a reference in the supplied source context.
    Unresolved,
    /// Reference is foreign or its instruction is not authenticated.
    Unauthenticated,
    /// The XML owner's configured mechanism cannot process this URI form.
    Unsupported,
}

impl<R> Resolution<R> {
    /// Maps only a successfully resolved value, preserving every lookup class.
    pub fn map<T>(self, visitor: impl FnOnce(R) -> T) -> Resolution<T> {
        match self {
            Self::Resolved(value) => Resolution::Resolved(visitor(value)),
            Self::Missing => Resolution::Missing,
            Self::Unresolved => Resolution::Unresolved,
            Self::Unauthenticated => Resolution::Unauthenticated,
            Self::Unsupported => Resolution::Unsupported,
        }
    }
}

/// Original optional XML Schema boolean, validated by the XML lexical owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boolean {
    /// Attribute was not written; this is distinct from explicit false.
    Absent,
    /// Valid lexical boolean after XML Schema whitespace handling.
    Value(bool),
    /// Present text has no XML Schema boolean value.
    Malformed,
}

/// Whether all relevant original reference instructions were processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness<N> {
    /// All selected direct and authenticated Manifest instructions were visited.
    /// Target digest outcomes/availability remain separate: Complete may include
    /// an authenticated instruction whose explicit detached bytes are missing.
    Complete,
    /// Original request did not complete required instruction discovery/auth
    /// traversal. This is not a missing-byte result for a discovered target.
    Unchecked(N),
    /// Processing stopped before a complete catalogue could be established.
    Incomplete(N),
}

/// Traversal preserves XML processing and consumer callback causes separately.
#[derive(Debug)]
pub enum VisitError<E, VE> {
    /// Original XML policy/resource/source-processing refusal.
    Processing(E),
    /// Exact visitor refusal; no later descriptor is visited.
    Visitor(VE),
}

/// XML-owned URI resolution and streaming from one selected verification session.
///
/// The owner retains the original request, compiled policy and remaining budgets.
/// No operation here performs a second signature verification, changes the
/// document, resets admission, or acquires an implicit resource. Processing and
/// resource refusals are returned as errors, never as a semantic lookup outcome.
pub trait ReferenceXml: SignatureXml {
    /// Visits the paid original authenticated instruction catalogue once.
    /// Direct and signed-Manifest references retain exact parent identities.
    /// Detached result arrays, fail-fast partial lists and an empty unprocessed
    /// Manifest list must never be relabelled Complete. No implicit verification
    /// or policy change is performed to complete the catalogue. The visitor's
    /// short descriptor borrow cannot escape; its refusal terminates traversal.
    fn visit_authenticated_references<VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        execution: &W,
        visitor: impl for<'view> FnMut(Descriptor<'view, Self::Id>) -> Result<(), VE>,
    ) -> Result<Completeness<Self::Id>, VisitError<Self::Error, VE>>;

    /// Resolves original lexical data on the property in its XML context.
    /// Only selected `SignedInfo` or authenticated Manifest instructions may reach
    /// the visitor. Its borrowed Type and view cannot escape the callback.
    /// Multiple simple-content fragments may require fallible current-operation
    /// scratch for the existing URI kernel; it cannot reset the operation or
    /// return a reader into temporary storage. Malformed simple content retains
    /// the owner's typed source cause instead of becoming absent or unresolved.
    fn resolve_reference<R, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        property: Self::Id,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(Descriptor<'view, Self::Id>) -> R,
    ) -> Result<Resolution<R>, Self::Error>;

    /// Reads an unqualified attribute through the existing XML Schema boolean
    /// kernel. Presence and malformed text must not be defaulted to false.
    fn boolean_attribute<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        attribute: Name<'_>,
        execution: &W,
    ) -> Result<Boolean, Self::Error>;

    /// Replays the original reference through the one transform/C14N kernel.
    /// The owner checks selected membership, generation and method before sink
    /// work. Final octets stay unchanged; remaining node-sets use the explicit
    /// replay mode. Receiver refusal is sticky and terminal.
    /// Direct ordinal queries and Manifest resolution feed this same kernel;
    /// retained implicit C14N 1.0 bytes are not universally equivalent output.
    fn replay_reference<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        reference: Self::Id,
        mode: Replay<Self::Id>,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<ReplayOutcome<Self::Error>, Self::Error>;
}
