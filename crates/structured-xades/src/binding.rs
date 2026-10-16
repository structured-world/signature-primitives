//! Selected-signature binding, separate from property validation and path trust.

use crate::container::{Containers, Layout};
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::Work;

/// Required Type of the `SignedInfo` reference protecting `SignedProperties`.
pub const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

/// `XMLDSig` outcome for this exact source generation and selected signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Complete `XMLDSig` processing and required reference checks succeeded.
    Valid,
    /// Completed processing rejected the signature or reference.
    Invalid,
    /// This signature or reference was not checked.
    Unchecked,
}

/// Conservative original-element coverage from the XML owner's transform engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Expanded names, attributes and element content are authenticated.
    ElementContent,
    /// Arbitrary transformed bytes do not prove complete original-element coverage.
    Transformed,
}

/// One callback-local verified `SignedInfo` reference from the selected signature.
#[derive(Debug, Clone, Copy)]
pub struct Reference<'a, N> {
    /// Original Reference node identity, distinct from its resolved target.
    pub node: N,
    /// Same-document original target, absent for external or unresolved resources.
    pub target: Option<N>,
    /// Original normalized Type attribute, not inferred from the target name.
    pub kind: Option<&'a str>,
    /// Completed reference digest outcome for this exact source generation.
    pub status: Status,
    /// Coverage certified by the actual transform chain.
    pub coverage: Coverage,
}

/// Resolution of the enveloped `QualifyingProperties` Target attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<N> {
    /// Empty non-fragment part and a bare-name fragment resolving to this node.
    LocalBareName(N),
    /// Required Target attribute is absent.
    Missing,
    /// Another URI form, external target or unresolved identifier.
    Other,
}

/// Read-only access to actual `XMLDSig` evidence, never an untrusted XML assertion.
///
/// The adapter checks original identity/generation and maps only the chosen
/// signature's evidence. It must not substitute another valid signature, a
/// Manifest reference or a URI string for authenticated original-node coverage.
/// Every data-dependent lookup is admitted through current Work and XML policy.
/// These queries do not repeat signature verification or perform implicit I/O.
pub trait SignatureXml: Xml {
    /// Returns the exact selected signature's completed `XMLDSig` outcome.
    /// Path trust, trusted lists and application acceptance are separate facts.
    fn signature_status<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        execution: &W,
    ) -> Result<Status, Self::Error>;

    /// Counts only the chosen signature's direct `SignedInfo` references.
    fn reference_count<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        execution: &W,
    ) -> Result<usize, Self::Error>;

    /// Inspects one original `SignedInfo` reference in ordinal order.
    fn reference<R, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        ordinal: usize,
        execution: &W,
        visitor: impl for<'view> FnOnce(Reference<'view, Self::Id>) -> R,
    ) -> Result<R, Self::Error>;

    /// Resolves Target using the XML owner's URI/ID kernel, without acquisition.
    /// URI syntax, namespace-independent attribute access and ID uniqueness are
    /// checked by the owner; resource/processing errors must not become Other.
    fn qualifying_target<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        qualifying: Self::Id,
        execution: &W,
    ) -> Result<Target<Self::Id>, Self::Error>;
}

/// Binding failed independently of a baseline property or path-trust decision.
#[derive(Debug)]
pub enum BindingError<E, N> {
    /// Original XML/resource/generation failure, never a signature mismatch.
    Access(AccessError<E, N>),
    /// The exact selected signature has no successful `XMLDSig` outcome.
    Signature {
        /// Original selected signature.
        node: N,
        /// Completed or unchecked outcome.
        status: Status,
    },
    /// Target does not identify the selected Signature by local bare-name URI.
    Target {
        /// Original `QualifyingProperties` container.
        node: N,
    },
    /// No authenticated reference protects the original `SignedProperties`.
    Missing {
        /// Original `SignedProperties`.
        node: N,
    },
    /// Matching target has wrong Type, digest outcome or incomplete coverage.
    Reference {
        /// Original Reference node.
        node: N,
    },
    /// Baseline signature has fewer than two `SignedInfo` references.
    References {
        /// Original Signature.
        node: N,
    },
}

/// Authenticated original `SignedProperties` for one selected signature.
///
/// This proves only `XMLDSig` binding. It does not certify property semantics,
/// signing-certificate identity, timestamps, attained baseline level or trust.
#[derive(Debug)]
pub struct Bound<N, D, G> {
    containers: Containers<N, D, G>,
    reference: N,
    ordinal: usize,
}

impl<N: Copy, D: Copy, G: Copy> Bound<N, D, G> {
    /// Original, generation-bound container identities.
    #[must_use]
    pub fn containers(&self) -> &Containers<N, D, G> {
        &self.containers
    }
    /// Authenticated original Reference, never another signature's reference.
    #[must_use]
    pub fn reference(&self) -> N {
        self.reference
    }
    /// Its original ordinal in the selected `SignedInfo`.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
}

/// A selected binding preserving the XML adapter's original identity types.
pub type Selected<X> = Bound<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// A binding result with the adapter's opaque original error and node provenance.
pub type BindingResult<T, X> = Result<T, BindingError<<X as Xml>::Error, <X as Xml>::Id>>;

#[derive(Clone, Copy)]
pub(crate) enum Purpose<N> {
    Properties(N),
    Counter(N),
}

pub(crate) fn covering_reference<X: SignatureXml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    purpose: Purpose<X::Id>,
) -> BindingResult<(X::Id, usize), X> {
    let status = access
        .query(signature, |xml, snapshot, work| {
            xml.signature_status(snapshot, signature, work)
        })
        .map_err(BindingError::Access)?;
    if status != Status::Valid {
        return Err(BindingError::Signature {
            node: signature,
            status,
        });
    }
    let count = access
        .query(signature, |xml, snapshot, work| {
            xml.reference_count(snapshot, signature, work)
        })
        .map_err(BindingError::Access)?;
    let (wanted, minimum) = match purpose {
        Purpose::Properties(target) => (target, 2),
        Purpose::Counter(target) => (target, 1),
    };
    if count < minimum {
        return Err(BindingError::References { node: signature });
    }
    let mut selected = None;
    let mut uncovered = None;
    for ordinal in 0..count {
        let (node, target, status, coverage, eligible) = access
            .query(signature, |xml, snapshot, work| {
                xml.reference(snapshot, signature, ordinal, work, |r| {
                    let eligible = match purpose {
                        Purpose::Properties(_) => match r.kind {
                            Some(kind) => access.equal(kind, SIGNED_PROPERTIES),
                            None => Ok(false),
                        },
                        // EN319132-1 §5.2.7.2 requires coverage of the original
                        // SignatureValue. It does not mandate a Type attribute for
                        // this enveloped form or turn it into SignedProperties.
                        // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
                        Purpose::Counter(_) => Ok(r.target == Some(wanted)),
                    };
                    (r.node, r.target, r.status, r.coverage, eligible)
                })
            })
            .map_err(BindingError::Access)?;
        let eligible = eligible
            .map_err(|cause| BindingError::Access(AccessError::Resource { node, cause }))?;
        if !eligible {
            continue;
        }
        if target != Some(wanted) || status != Status::Valid {
            return Err(BindingError::Reference { node });
        }
        if coverage != Coverage::ElementContent {
            uncovered = Some(node);
            continue;
        }
        if selected.is_none() {
            selected = Some((node, ordinal));
        }
    }
    if let Some(value) = selected {
        return Ok(value);
    }
    if let Some(node) = uncovered {
        return Err(BindingError::Reference { node });
    }
    Err(BindingError::Missing { node: wanted })
}

/// Verifies binding to the original selected signature before property execution.
pub fn bind<X: SignatureXml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &Layout<X>,
) -> BindingResult<Selected<X>, X> {
    check_target(access, layout)?;
    let (reference, ordinal) = covering_reference(
        access,
        layout.signature(),
        Purpose::Properties(layout.signed()),
    )?;
    Ok(Bound {
        containers: *layout,
        reference,
        ordinal,
    })
}

// EN319132-1 V1.3.1 4.3.1 applies to unsigned as well as signed qualifying
// properties. A checked counter does not associate an unrelated Target with
// itself. Share this source/URI guard without requiring a plain XMLDSig child
// to supply the root baseline header or a SignedProperties reference.
// https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
pub(crate) fn check_target<X: SignatureXml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &Layout<X>,
) -> BindingResult<(), X> {
    let signature = layout.signature();
    if access.snapshot() != layout.snapshot() {
        return Err(BindingError::Access(AccessError::Changed {
            node: signature,
        }));
    }
    // ETSI EN 319 132-1 V1.3.1 §§4.3.1/4.4.2 and §6.3 table 2.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    let target = access
        .query(layout.qualifying(), |xml, snapshot, work| {
            xml.qualifying_target(snapshot, layout.qualifying(), work)
        })
        .map_err(BindingError::Access)?;
    if target != Target::LocalBareName(signature) {
        return Err(BindingError::Target {
            node: layout.qualifying(),
        });
    }
    Ok(())
}
