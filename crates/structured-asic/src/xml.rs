//! Original signature-file wrappers and complete XML signature occurrence census.
//!
//! XML parsing and canonicalization belong to the supplied XML owner. This
//! inspection neither detaches children nor attests ZIP-to-XML provenance.

use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_xades::{
    attributes::{self, AttributeXml},
    reference::VisitError,
    xml::{Access, AccessError, Name, Node, Snapshot, Xml},
};

pub mod producer;

/// ODF1.2 digital-signature wrapper namespace.
pub const ODF: &str = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
/// OCF container/signature-wrapper namespace.
pub const OCF: &str = "urn:oasis:names:tc:opendocument:xmlns:container";

/// Original root form, independent of its signature or profile outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// One bare ds:Signature, permitted by EN319162-1 §4.4.3.2(3e).
    Bare,
    /// The normative asic:XAdESSignatures wrapper.
    Asic,
    /// ODF's dsig:document-signatures wrapper, with its own version attribute.
    Odf,
    /// OCF's signatures wrapper.
    Ocf,
    /// Another wrapper, permitted by §4.4.3.2(3d) only with signature siblings.
    Other,
    /// The supplied root is not an XML element.
    NotElement,
}

/// Every original ds:Signature, including malformed or misplaced descendants.
#[derive(Debug, Clone, Copy)]
pub struct Signature<N> {
    /// Stable original node; no DOM/view borrow escapes inspection.
    pub node: N,
    /// Its actual parent, or None for a bare signature root.
    pub parent: Option<N>,
    /// Nearest enclosing signature, not an assertion that this is a legal counter.
    pub enclosing: Option<N>,
    /// A bare root or a direct signature child of the original wrapper.
    pub direct: bool,
}

/// Readable wrapper problems, retaining every original occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// The selected original root is not an element.
    Root,
    /// No direct signature was present.
    Missing,
    /// A wrapper child is not a ds:Signature element.
    Child,
    /// Non-whitespace text appears directly in the wrapper.
    Text,
    /// A declared wrapper does not permit the original attribute.
    Attribute,
    /// Original schema-instance semantics need separate assessment.
    InstanceUnassessed,
    /// ODF's required version is absent or not the fixed token 1.2.
    OdfVersion,
    /// A signature occurs below an invalid wrapper child, outside another signature.
    Misplaced,
}

/// One readable problem at an exact original XML node.
#[derive(Debug, Clone, Copy)]
pub struct Fault<N> {
    /// Original node, never a guessed byte offset.
    pub node: N,
    /// Independent wrapper/census problem.
    pub kind: FaultKind,
}

/// Original XML, callback and resource causes remain terminal and distinct.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original XML owner or common generation/current-work refusal.
    Access(AccessError<E, N>),
    /// Attribute traversal's first original processing/callback refusal.
    Attributes(AccessError<VisitError<E, MemoryError>, N>),
    /// Scoped storage or comparison admission failed before work.
    Resource {
        /// Actual attempted original node.
        node: N,
        /// Original refusal class.
        cause: MemoryError,
    },
}

/// Raw wrapper and complete descendant census, not a verified profile receipt.
pub struct Reading<N, D, G> {
    snapshot: Snapshot<D, G>,
    root: N,
    wrapper: Wrapper,
    signatures: OwnedVec<Signature<N>>,
    faults: OwnedVec<Fault<N>>,
}
impl<N: Copy, D: Copy, G: Copy> Reading<N, D, G> {
    /// Actual XML source and generation observed throughout the traversal.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original root; children retain its canonicalization context.
    #[must_use]
    pub fn root(&self) -> N {
        self.root
    }
    /// Original namespace-qualified root classification.
    #[must_use]
    pub fn wrapper(&self) -> Wrapper {
        self.wrapper
    }
    /// All original descendant signatures in document order, including negatives.
    #[must_use]
    pub fn signatures(&self) -> &[Signature<N>] {
        &self.signatures
    }
    /// Complete wrapper/census diagnostics in discovery order.
    #[must_use]
    pub fn faults(&self) -> &[Fault<N>] {
        &self.faults
    }
}

struct Frame<N> {
    parent: N,
    next: Option<N>,
    enclosing: Option<N>,
}
enum Kind {
    Element { signature: bool, wrapper: Wrapper },
    Text,
    Other,
}

fn classify<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> Result<Kind, Error<X::Error, X::Id>> {
    access
        .inspect(node, |value| match value {
            Node::Element(name) => {
                let cost = name
                    .namespace
                    .len()
                    .checked_add(name.local.len())
                    .and_then(|count| count.checked_mul(4))
                    .ok_or(MemoryError::WorkExceeded)?;
                access.execution().charge_work(cost as u64)?;
                let signature = name.namespace == crate::manifest::DS && name.local == "Signature";
                let wrapper = if signature {
                    Wrapper::Bare
                } else if name.namespace == crate::manifest::NAMESPACE
                    && name.local == "XAdESSignatures"
                {
                    Wrapper::Asic
                } else if name.namespace == ODF && name.local == "document-signatures" {
                    Wrapper::Odf
                } else if name.namespace == OCF && name.local == "signatures" {
                    Wrapper::Ocf
                } else {
                    Wrapper::Other
                };
                Ok(Kind::Element { signature, wrapper })
            }
            Node::Text(text) => {
                access.execution().charge_work(text.len() as u64)?;
                for byte in text.bytes() {
                    if !matches!(byte, b' ' | b'\r' | b'\n' | b'\t') {
                        return Ok(Kind::Text);
                    }
                }
                Ok(Kind::Other)
            }
            Node::Other => Ok(Kind::Other),
        })
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })
}

fn fault<N, W: Work, E>(
    output: &mut OwnedVec<Fault<N>, W>,
    node: N,
    kind: FaultKind,
) -> Result<(), Error<E, N>>
where
    N: Copy,
{
    output
        .try_push(Fault { node, kind })
        .map_err(|cause| Error::Resource { node, cause })
}

/// EN319162-1 §4.4.3.2(3) permits all five wrapper forms for general E-XAdES;
/// the baseline and simple-container wrapper restrictions are separate checks.
/// The traversal is iterative and retains nested/misplaced occurrences even
/// after a readable wrapper fault. No successful partial reading survives refusal.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf>
pub fn inspect<X: AttributeXml, W: Work>(xml: &X, root: X::Id, work: &W) -> InspectionResult<X> {
    let snapshot = xml.snapshot();
    let access = Access::new(xml, snapshot, work);
    let mut signatures = work.vector();
    let mut faults = work.vector();
    let root_kind = classify(&access, root)?;
    let wrapper = match root_kind {
        Kind::Element { signature, wrapper } => {
            if signature {
                signatures
                    .try_push(Signature {
                        node: root,
                        parent: None,
                        enclosing: None,
                        direct: true,
                    })
                    .map_err(|cause| Error::Resource { node: root, cause })?;
            }
            wrapper
        }
        Kind::Text | Kind::Other => {
            fault(&mut faults, root, FaultKind::Root)?;
            Wrapper::NotElement
        }
    };
    inspect_wrapper(&access, root, wrapper, &mut faults)?;
    inspect_descendants(&access, root, wrapper, &mut signatures, &mut faults)?;
    access.inspect(root, |_| ()).map_err(Error::Access)?;
    Ok(Reading {
        snapshot,
        root,
        wrapper,
        signatures: signatures.into_owned(),
        faults: faults.into_owned(),
    })
}

/// Complete original wrapper/signature census or unchanged owner refusal.
pub type InspectionResult<X> = Result<
    Reading<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    Error<<X as Xml>::Error, <X as Xml>::Id>,
>;

fn inspect_wrapper<X: AttributeXml, W: Work, O: Work>(
    access: &Access<'_, X, W>,
    root: X::Id,
    wrapper: Wrapper,
    faults: &mut OwnedVec<Fault<X::Id>, O>,
) -> Result<(), Error<X::Error, X::Id>> {
    let work = access.execution();
    if matches!(wrapper, Wrapper::Asic | Wrapper::Odf | Wrapper::Ocf) {
        attributes::visit(access, root, |name| {
            work.charge_work(name.namespace.len() as u64 + name.local.len() as u64 + 1)?;
            if wrapper == Wrapper::Odf && name.namespace == ODF && name.local == "version" {
                return Ok(());
            }
            let kind = if name.namespace == "http://www.w3.org/2001/XMLSchema-instance" {
                FaultKind::InstanceUnassessed
            } else {
                FaultKind::Attribute
            };
            faults.try_push(Fault { node: root, kind })
        })
        .map_err(Error::Attributes)?;
    }
    if wrapper == Wrapper::Odf {
        // ODF1.2 part3 §5.4.1 and its normative dsig RNG: required fixed
        // token 1.2. The RNG value uses the default token whitespace semantics.
        // https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-dsig-schema.rng
        let valid = access
            .attribute(
                root,
                Name {
                    namespace: ODF,
                    local: "version",
                },
                |value| {
                    let Some(value) = value else {
                        return Ok(false);
                    };
                    work.charge_work(value.len() as u64)?;
                    Ok(value.trim_matches([' ', '\t', '\r', '\n']) == "1.2")
                },
            )
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource { node: root, cause })?;
        if !valid {
            fault(faults, root, FaultKind::OdfVersion)?;
        }
    }
    Ok(())
}

fn inspect_descendants<X: AttributeXml, W: Work, O: Work>(
    access: &Access<'_, X, W>,
    root: X::Id,
    wrapper: Wrapper,
    signatures: &mut OwnedVec<Signature<X::Id>, O>,
    faults: &mut OwnedVec<Fault<X::Id>, O>,
) -> Result<(), Error<X::Error, X::Id>> {
    let work = access.execution();
    let mut stack = work.vector();
    if wrapper != Wrapper::NotElement {
        let next = access.first_child(root).map_err(Error::Access)?;
        stack
            .try_push(Frame {
                parent: root,
                next,
                enclosing: if wrapper == Wrapper::Bare {
                    Some(root)
                } else {
                    None
                },
            })
            .map_err(|cause| Error::Resource { node: root, cause })?;
    }
    let mut direct = usize::from(wrapper == Wrapper::Bare);
    while let Some(frame) = stack.last_mut() {
        let Some(node) = frame.next else {
            stack.pop();
            continue;
        };
        let parent = frame.parent;
        let outer = frame.enclosing;
        frame.next = access.next_sibling(parent, node).map_err(Error::Access)?;
        let kind = classify(access, node)?;
        let is_direct = parent == root && wrapper != Wrapper::Bare;
        let (is_element, enclosing) = match kind {
            Kind::Element { signature, .. } => {
                if signature {
                    signatures
                        .try_push(Signature {
                            node,
                            parent: Some(parent),
                            enclosing: outer,
                            direct: is_direct,
                        })
                        .map_err(|cause| Error::Resource { node, cause })?;
                    if is_direct {
                        direct += 1;
                    } else if outer.is_none() {
                        fault(faults, node, FaultKind::Misplaced)?;
                    }
                } else if is_direct {
                    fault(faults, node, FaultKind::Child)?;
                }
                (true, if signature { Some(node) } else { outer })
            }
            Kind::Text => {
                if is_direct {
                    fault(faults, node, FaultKind::Text)?;
                }
                (false, outer)
            }
            Kind::Other => (false, outer),
        };
        if is_element {
            let next = access.first_child(node).map_err(Error::Access)?;
            stack
                .try_push(Frame {
                    parent: node,
                    next,
                    enclosing,
                })
                .map_err(|cause| Error::Resource { node, cause })?;
        }
    }
    if direct == 0 {
        fault(faults, root, FaultKind::Missing)?;
    }
    Ok(())
}
