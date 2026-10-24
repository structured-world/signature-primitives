//! Original manifest structure, separate from authenticated member binding.

use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_xades::{
    attributes::AttributeXml,
    reference::VisitError,
    scalar::ScalarXml,
    xml::{Access, AccessError, Name, Node, Snapshot, Xml},
};

mod fields;

/// Normative namespace of `ASiC` manifest and wrapper elements.
pub const NAMESPACE: &str = "http://uri.etsi.org/02918/v1.2.1#";
pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// One declared field retains ambiguity instead of selecting a convenient copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot<N> {
    /// The required field was not written.
    Absent,
    /// One original field exists.
    One(N),
    /// Multiple fields exist; their original locations remain in diagnostics.
    Ambiguous,
}

/// Original optional XSD boolean. Absence and written false remain distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boolean {
    /// The attribute was not written; no schema default is fabricated.
    Absent,
    /// One of the four valid lexical forms, with schema whitespace processing.
    Value(bool),
    /// A present attribute has no XSD boolean value.
    Malformed,
}

/// Original data-object instruction, not proof its digest or URI succeeded.
#[derive(Debug, Clone, Copy)]
pub struct Object<N> {
    /// Original `DataObjectReference` element.
    pub node: N,
    /// Original `XMLDSig` method selection, including ambiguous occurrences.
    pub method: Slot<N>,
    /// Original digest-value element.
    pub value: Slot<N>,
    /// Original optional OCF rootfile declaration.
    pub rootfile: Boolean,
}

/// An original extension stays available even when its semantics are unknown.
#[derive(Debug, Clone, Copy)]
pub struct Extension<N> {
    /// Original enclosing manifest or data-object instruction.
    pub owner: N,
    /// Original extension element, preserving its entire XML-owned payload.
    pub node: N,
    /// Schema-required Critical attribute and its actual lexical outcome.
    pub critical: Boolean,
}

/// Readable structure problems cannot disappear behind a successful digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Non-whitespace text in an element-only schema.
    Text,
    /// A child or attribute has no declaration in this selected type.
    Unexpected,
    /// A required child or attribute is absent.
    Missing,
    /// A singleton child occurs more than once.
    Duplicate,
    /// Required original child order is violated.
    Order,
    /// A present value fails its requested base datatype.
    Scalar,
    /// Schema-instance interpretation remains unassessed, never valid by default.
    InstanceUnassessed,
}

/// Original XML location, without a synthetic document byte offset.
#[derive(Debug, Clone, Copy)]
pub struct Fault<N> {
    /// Original offending element, attribute owner or text node.
    pub node: N,
    /// Exact structural problem.
    pub kind: FaultKind,
}

/// Processing refusal is separate from completed schema findings.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original XML, source generation or common admission refusal.
    Access(AccessError<E, N>),
    /// Original attribute traversal or visitor refusal.
    Attributes(AccessError<VisitError<E, MemoryError>, N>),
    /// Actual storage/work refused before metadata work.
    Resource {
        /// Original owning node.
        node: N,
        /// Unchanged resource cause.
        cause: MemoryError,
    },
    /// The selected root is not the `ASiCManifest` element.
    Root(N),
}

type ResultOf<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;
/// Complete original manifest reading or its unchanged processing refusal.
pub type InspectionResult<X> =
    ResultOf<Reading<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>, X>;

/// Complete original manifest instruction census. This is a schema inspection,
/// not proof this XML came from any particular ZIP member or is authenticated.
pub struct Reading<N, D, G> {
    snapshot: Snapshot<D, G>,
    root: N,
    signatures: OwnedVec<N>,
    objects: OwnedVec<Object<N>>,
    extensions: OwnedVec<Extension<N>>,
    faults: OwnedVec<Fault<N>>,
}

pub(crate) struct Builder<N, W: Work> {
    signatures: OwnedVec<N, W>,
    objects: OwnedVec<Object<N>, W>,
    extensions: OwnedVec<Extension<N>, W>,
    faults: OwnedVec<Fault<N>, W>,
}

impl<N: Copy, W: Work> Builder<N, W> {
    fn fault<E>(&mut self, node: N, kind: FaultKind) -> Result<(), Error<E, N>> {
        self.faults
            .try_push(Fault { node, kind })
            .map_err(|cause| Error::Resource { node, cause })
    }
}

impl<N: Copy, D: Copy + Eq, G: Copy + Eq> Reading<N, D, G> {
    /// Original XML source identity, not an `ASiC` member association.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original root element.
    #[must_use]
    pub fn root(&self) -> N {
        self.root
    }
    /// Original instructions, including duplicates and malformed slots.
    #[must_use]
    pub fn objects(&self) -> &[Object<N>] {
        &self.objects
    }
    /// All original signature-reference occurrences.
    #[must_use]
    pub fn signatures(&self) -> &[N] {
        &self.signatures
    }
    /// Original extension payload locations and explicit criticality.
    #[must_use]
    pub fn extensions(&self) -> &[Extension<N>] {
        &self.extensions
    }
    /// Every readable schema finding in discovery order.
    #[must_use]
    pub fn faults(&self) -> &[Fault<N>] {
        &self.faults
    }
}

/// Reads the attached EN319162-1 V1.1.1 A.3/A.4 schema through existing XML
/// access and scalar kernels. It retains every original instruction even when
/// another has malformed syntax; processing/resource refusals remain terminal.
pub fn inspect<X: AttributeXml + ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    root: X::Id,
) -> InspectionResult<X> {
    if !access
        .has_name(root, name("ASiCManifest"))
        .map_err(Error::Access)?
    {
        return Err(Error::Root(root));
    }
    let work = access.execution();
    let mut output = Builder {
        signatures: work.vector(),
        objects: work.vector(),
        extensions: work.vector(),
        faults: work.vector(),
    };
    fields::attributes(access, root, &[], &mut output)?;
    let mut stage = 0;
    let mut extension = false;
    walk(access, root, |node, element| {
        if !element {
            return output.fault(node, FaultKind::Text);
        }
        if access
            .has_name(node, name("SigReference"))
            .map_err(Error::Access)?
        {
            if stage != 0 {
                output.fault(node, FaultKind::Order)?;
            }
            if !output.signatures.is_empty() {
                output.fault(node, FaultKind::Duplicate)?;
            }
            fields::attributes(access, node, &["URI", "MimeType"], &mut output)?;
            fields::uri(access, node, &mut output)?;
            fields::empty(access, node, &mut output)?;
            output
                .signatures
                .try_push(node)
                .map_err(|cause| Error::Resource { node, cause })?;
        } else if access
            .has_name(node, name("DataObjectReference"))
            .map_err(Error::Access)?
        {
            if stage > 1 || output.signatures.is_empty() {
                output.fault(node, FaultKind::Order)?;
            }
            stage = stage.max(1);
            let value = fields::object(access, node, &mut output)?;
            output
                .objects
                .try_push(value)
                .map_err(|cause| Error::Resource { node, cause })?;
        } else if access
            .has_name(node, name("ASiCManifestExtensions"))
            .map_err(Error::Access)?
        {
            if extension {
                output.fault(node, FaultKind::Duplicate)?;
            }
            if output.objects.is_empty() {
                output.fault(node, FaultKind::Order)?;
            }
            stage = 2;
            extension = true;
            fields::extensions(access, root, node, &mut output)?;
        } else {
            output.fault(node, FaultKind::Unexpected)?;
        }
        Ok(())
    })?;
    if output.signatures.is_empty() || output.objects.is_empty() {
        output.fault(root, FaultKind::Missing)?;
    }
    Ok(Reading {
        snapshot: access.snapshot(),
        root,
        signatures: output.signatures.into_owned(),
        objects: output.objects.into_owned(),
        extensions: output.extensions.into_owned(),
        faults: output.faults.into_owned(),
    })
}

fn name(local: &'static str) -> Name<'static> {
    Name {
        namespace: NAMESPACE,
        local,
    }
}

fn walk<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    mut visit: impl FnMut(X::Id, bool) -> ResultOf<(), X>,
) -> ResultOf<(), X> {
    let mut child = access.first_child(parent).map_err(Error::Access)?;
    while let Some(node) = child {
        let class = access
            .inspect(node, |read| match read {
                Node::Element(_) => Ok(Some(true)),
                Node::Text(text) => {
                    access.execution().charge_work(text.len() as u64)?;
                    for byte in text.bytes() {
                        if !matches!(byte, b' ' | b'\r' | b'\n' | b'\t') {
                            return Ok(Some(false));
                        }
                    }
                    Ok(None)
                }
                Node::Other => Ok(None),
            })
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource { node, cause })?;
        if let Some(element) = class {
            visit(node, element)?;
        }
        child = access.next_sibling(parent, node).map_err(Error::Access)?;
    }
    Ok(())
}
