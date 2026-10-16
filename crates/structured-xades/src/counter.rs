//! Original enveloped countersignature selection and `XMLDSig` coverage binding.

use crate::binding::{self, Bound, SignatureXml};
use crate::container::DS;
use crate::timestamp::{self, InputError};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::Work;

mod walk;
pub use walk::{WalkError, WalkResult, walk};

/// Counter selection/binding refusal, preserving its original cause and role.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original container/source/resource cause.
    Input(InputError<E, N>),
    /// Actual child-signature or covering-reference refusal.
    Binding(binding::BindingError<E, N>),
}

/// Original enveloped counter and parent `SignatureValue` before child checking.
#[derive(Debug, Clone, Copy)]
pub struct Counter<N, D, G> {
    snapshot: Snapshot<D, G>,
    parent: N,
    value: N,
    node: N,
    child: N,
}

impl<N: Copy, D: Copy, G: Copy> Counter<N, D, G> {
    /// Original source identity and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original countersigned signature.
    #[must_use]
    pub fn parent(&self) -> N {
        self.parent
    }
    /// Exact original `SignatureValue` element, including its attributes/content.
    #[must_use]
    pub fn value(&self) -> N {
        self.value
    }
    /// Original `CounterSignature` property.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original enclosed `ds:Signature`, which may be plain `XMLDSig` or `XAdES`.
    #[must_use]
    pub fn child(&self) -> N {
        self.child
    }
}

/// Successful mathematical/coverage binding, not a child certificate/path or level.
#[derive(Debug, Clone, Copy)]
pub struct Checked<N, D, G> {
    original: Counter<N, D, G>,
    reference: N,
    ordinal: usize,
}

impl<N: Copy, D: Copy, G: Copy> Checked<N, D, G> {
    /// Original parent/child/source identities.
    #[must_use]
    pub fn original(&self) -> &Counter<N, D, G> {
        &self.original
    }
    /// Actual child `SignedInfo` reference covering the parent `SignatureValue`.
    #[must_use]
    pub fn reference(&self) -> N {
        self.reference
    }
    /// Original ordinal in the child's `SignedInfo`, not the parent's references.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
}

/// Counter using this XML owner's stable identity types.
pub type Original<X> = Counter<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// Original selection/check cause.
pub type CounterResult<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;
/// Successfully bound counter using this owner's identity types.
pub type Binding<X> = Checked<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Selects exactly one original enclosed Signature under a direct unsigned counter.
/// No child signature verification, certificate selection or recursive walk occurs.
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    node: X::Id,
) -> CounterResult<Original<X>, X> {
    let parent = timestamp::unsigned_parent(access, bound, node).map_err(Error::Input)?;
    let mut found = false;
    for child in access.children(parent) {
        if child.map_err(|cause| Error::Input(InputError::Child(cause)))? == node {
            found = true;
            break;
        }
    }
    if !found {
        return Err(Error::Input(InputError::Foreign { node }));
    }
    let parent = bound.containers().signature();
    let value = timestamp::singleton(access, parent, DS, "SignatureValue").map_err(Error::Input)?;
    walk::member(access, parent, value, node)
}

/// Consumes one original counter using the actual child's `XMLDSig` receipt.
///
/// The owner may expose a separate selected-child handle within the SAME original
/// verified-request session. This function does not reverify, reset operation
/// limits or substitute parent receipts for child evidence. EN319132-1 §5.2.7.2
/// requires the complete canonicalized parent `SignatureValue` element; plain
/// `XMLDSig` countersignatures do not require the baseline's two-reference minimum.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn bind<X: SignatureXml, W: Work>(
    child_access: &Access<'_, X, W>,
    original: Original<X>,
) -> CounterResult<Binding<X>, X> {
    if child_access.snapshot() != original.snapshot {
        return Err(Error::Input(InputError::Access(AccessError::Changed {
            node: original.child,
        })));
    }
    let (reference, ordinal) = binding::covering_reference(
        child_access,
        original.child,
        binding::Purpose::Counter(original.value),
    )
    .map_err(Error::Binding)?;
    Ok(Checked {
        original,
        reference,
        ordinal,
    })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> CounterResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(|cause| Error::Input(InputError::Access(cause)))
}
