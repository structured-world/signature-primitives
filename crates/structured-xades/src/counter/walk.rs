//! Iterative original countersignature traversal with actual `XMLDSig` receipts.

use super::{Binding, Counter, CounterResult, Error, Original, bind, named};
use crate::binding::{Selected, SignatureXml};
use crate::container::{self, ContainerError, DS, Layout, XADES};
use crate::properties;
use crate::timestamp::{self, InputError};
use crate::unsigned;
use crate::xml::{Access, AccessError, Children, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// Original traversal/verification or visitor cause. Refusal never returns a
/// successful prefix, though external visitor side effects cannot be rolled back.
#[derive(Debug)]
pub enum WalkError<E, VE, N> {
    /// Original source or current-operation admission refusal.
    Access(AccessError<E, N>),
    /// Malformed direct child container, without a fallback descendant search.
    Container(ContainerError<E, N>),
    /// Unsigned container grammar failure.
    Property(properties::Error<E, N>),
    /// Original counter schema or actual selected-child verification refusal.
    Counter(Error<E, N>),
    /// Frame/result storage admission failed before growth.
    Resource {
        /// Original enclosing signature/property.
        node: N,
        /// Unchanged current execution refusal.
        cause: MemoryError,
    },
    /// Exact visitor error. No later sibling or descendant is visited.
    Visitor(VE),
}

/// Complete traversal result using original adapter causes and node identities.
pub type WalkResult<T, X, VE> = Result<T, WalkError<<X as Xml>::Error, VE, <X as Xml>::Id>>;

struct Frame<'a, 'xml, X: Xml, W: Work> {
    layout: Layout<X>,
    value: X::Id,
    children: Children<'a, 'xml, X, W>,
}

/// Visits every direct/nested enveloped countersignature in depth-first original
/// sibling order. Each child must have an actual successful `XMLDSig` receipt
/// covering its own parent's complete original `SignatureValue`. Plain `XMLDSig`
/// children are leaves; children with `XAdES` containers expose those original
/// containers to the visitor for their independent property/profile checks.
///
/// The walker does not recursively call itself, retain movable-frame borrows,
/// clone parent catalogues, reverify signatures or grant a child B level/trust.
/// O(depth) frames are held on accounted heap storage. A visitor result can own
/// admitted facts or original identities, but cannot borrow its temporary child
/// binding/layout. All results and frames are dropped on terminal refusal.
///
/// ```compile_fail
/// use structured_asn1::memory::{OwnedVec, Work};
/// use structured_xades::{binding::{Selected, SignatureXml}, counter, xml::Access};
/// fn escape<'a, X: SignatureXml, W: Work>(
///     access: &Access<'_, X, W>, root: &Selected<X>,
/// ) -> counter::WalkResult<OwnedVec<&'a counter::Binding<X>>, X, ()> {
///     counter::walk(access, root, |child, _| Ok(child))
/// }
/// ```
///
/// EN319132-1 §5.2.7.2 permits an enveloped `XMLDSig` counter; the B-LTA material
/// obligation in §6.3(aa) includes every incorporated counter, not just siblings.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn walk<X: SignatureXml, W: Work, R, VE>(
    access: &Access<'_, X, W>,
    root: &Selected<X>,
    mut visitor: impl FnMut(&Binding<X>, Option<&Layout<X>>) -> Result<R, VE>,
) -> WalkResult<OwnedVec<R>, X, VE> {
    let layout = root.containers();
    if access.snapshot() != layout.snapshot() {
        return Err(WalkError::Access(AccessError::Changed {
            node: layout.signature(),
        }));
    }
    let mut frames = access
        .query(layout.signature(), |_, _, work| Ok(work.vector()))
        .map_err(WalkError::Access)?;
    let mut results = access
        .query(layout.signature(), |_, _, work| Ok(work.vector()))
        .map_err(WalkError::Access)?;
    if let Some(frame) = frame(access, *layout)? {
        frames
            .try_push(frame)
            .map_err(|cause| WalkError::Resource {
                node: layout.signature(),
                cause,
            })?;
    }
    while let Some(current) = frames.last_mut() {
        let Some(next) = current.children.next() else {
            frames.pop();
            continue;
        };
        let node =
            next.map_err(|cause| WalkError::Counter(Error::Input(InputError::Child(cause))))?;
        if !named(access, node, XADES, "CounterSignature").map_err(WalkError::Counter)? {
            continue;
        }
        let original = member(access, current.layout.signature(), current.value, node)
            .map_err(WalkError::Counter)?;
        let checked = bind(access, original).map_err(WalkError::Counter)?;
        let child = checked.original().child();
        let nested = match container::locate(access, child) {
            Ok(layout) => Some(layout),
            // Only absence of direct qualifying properties makes a plain
            // XMLDSig leaf. Every other schema/resource/source error is terminal.
            Err(ContainerError::Missing {
                parent,
                local: "QualifyingProperties",
            }) if parent == child => None,
            Err(cause) => return Err(WalkError::Container(cause)),
        };
        let pending = nested
            .map(|layout| frame(access, layout))
            .transpose()?
            .flatten();
        let result = visitor(&checked, nested.as_ref()).map_err(WalkError::Visitor)?;
        // A visitor may retain owned data but cannot silently change the source
        // generation and still return a successful result or start another node.
        access
            .query(child, |_, _, _| Ok(()))
            .map_err(WalkError::Access)?;
        results
            .try_push(result)
            .map_err(|cause| WalkError::Resource { node, cause })?;
        if let Some(pending) = pending {
            frames
                .try_push(pending)
                .map_err(|cause| WalkError::Resource { node: child, cause })?;
        }
    }
    access
        .query(layout.signature(), |_, _, _| Ok(()))
        .map_err(WalkError::Access)?;
    Ok(results.into_owned())
}

fn frame<'a, 'xml, X: Xml, W: Work, VE>(
    access: &'a Access<'xml, X, W>,
    layout: Layout<X>,
) -> WalkResult<Option<Frame<'a, 'xml, X, W>>, X, VE> {
    let [parent, _] =
        unsigned::containers(access, layout.unsigned()).map_err(WalkError::Property)?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    let value = timestamp::singleton(access, layout.signature(), DS, "SignatureValue")
        .map_err(|cause| WalkError::Counter(Error::Input(cause)))?;
    Ok(Some(Frame {
        layout,
        value,
        children: access.children(parent),
    }))
}

// Membership in the direct unsigned cursor was already established by the
// walker. Share this field kernel with the independently selected read route.
pub(super) fn member<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    value: X::Id,
    node: X::Id,
) -> CounterResult<Original<X>, X> {
    if !named(access, node, XADES, "CounterSignature")? {
        return Err(Error::Input(InputError::Unexpected { node }));
    }
    let mut child = None;
    for next in access.children(node) {
        let next = next.map_err(|cause| Error::Input(InputError::Child(cause)))?;
        if !named(access, next, DS, "Signature")? {
            return Err(Error::Input(InputError::Unexpected { node: next }));
        }
        if child.is_some() {
            return Err(Error::Input(InputError::Duplicate { node: next }));
        }
        child = Some(next);
    }
    let child = child.ok_or(Error::Input(InputError::Missing {
        node,
        local: "Signature",
    }))?;
    Ok(Counter {
        snapshot: access.snapshot(),
        parent,
        value,
        node,
        child,
    })
}
