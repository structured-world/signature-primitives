//! Actual countersignature signer association without requiring `XAdES` properties.

use super::CheckedPath;
use crate::certificate::{CertificateXml, KeyAssociation};
use crate::counter;
use crate::xml::{Access, AccessError, AccessResult, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// One actual child-signature receipt and its selected signer's checked path.
/// This establishes neither revocation nor incorporation of validation data.
/// A plain `XMLDSig` counter need not contain `SigningCertificateV2` to enter the
/// material census; original successful key evidence establishes its signer.
/// The scalar original-source receipt is copied without allocation so this
/// result can outlive a counter walk's temporary frame. Only the independently
/// checked path remains borrowed; no temporary XML view is retained.
pub struct CounterPath<'view, 'document, N, D, G> {
    counter: counter::Checked<N, D, G>,
    path: &'view CheckedPath<'document>,
}

impl<'view, 'document, N, D, G> CounterPath<'view, 'document, N, D, G> {
    /// Original actual child/parent `SignatureValue` coverage receipt.
    #[must_use]
    pub fn counter(&self) -> &counter::Checked<N, D, G> {
        &self.counter
    }

    /// Original checked path associated with the child's successful key.
    #[must_use]
    pub fn path(&self) -> &'view CheckedPath<'document> {
        self.path
    }
}

/// Completed key association, distinct from processing/resource failure.
pub enum CounterBinding<'view, 'document, N, D, G> {
    /// Actual successful child key agrees with this path's effective key.
    Bound(CounterPath<'view, 'document, N, D, G>),
    /// Original selected-key evidence establishes a different association.
    Differs,
    /// Evidence does not establish the necessary selected-key association.
    Unproven,
}

/// Counter/path association in this XML owner's original identity domain.
pub type CounterPathResult<'view, 'document, X> = AccessResult<
    CounterBinding<'view, 'document, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
>;

/// Complete original countersignature actors, never a successful subset.
/// Construction visits every original counter through the common iterative
/// walker. These paths still need their own status and material evaluation.
pub struct CounterPaths<'view, 'document, N, D, G> {
    snapshot: crate::xml::Snapshot<D, G>,
    signature: N,
    actors: OwnedVec<CounterActor<'view, 'document, N, D, G>>,
}

/// Actual counter signer plus its independently protected credential sources.
/// Plain counters and counters with no role property have no such catalogue.
/// A present role is authenticated and read without imposing the root's B level.
pub struct CounterActor<'view, 'document, N, D, G> {
    signer: CounterPath<'view, 'document, N, D, G>,
    containers: Option<crate::container::Containers<N, D, G>>,
    roles: Option<crate::role::Roles<N, D, G>>,
}

impl<'view, 'document, N, D, G> CounterActor<'view, 'document, N, D, G> {
    /// Actual child signer and its checked effective-key path.
    #[must_use]
    pub fn signer(&self) -> &CounterPath<'view, 'document, N, D, G> {
        &self.signer
    }
    /// Original protected role credentials, which still need their own handler.
    #[must_use]
    pub fn roles(&self) -> Option<&crate::role::Roles<N, D, G>> {
        self.roles.as_ref()
    }
    /// Original child qualifying-property layout, if this is an `XAdES`
    /// counter. This is not a child baseline claim. Plain `XMLDSig` has none.
    #[must_use]
    pub fn containers(&self) -> Option<&crate::container::Containers<N, D, G>> {
        self.containers.as_ref()
    }
}

impl<'view, 'document, N: Copy, D: Copy, G: Copy> CounterPaths<'view, 'document, N, D, G> {
    /// Original root source/generation under which all counters were visited.
    #[must_use]
    pub fn snapshot(&self) -> crate::xml::Snapshot<D, G> {
        self.snapshot
    }
    /// Root signature whose complete incorporated counters were checked.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Every original counter's bound signer path in depth-first source order.
    #[must_use]
    pub fn actors(&self) -> &[CounterActor<'view, 'document, N, D, G>] {
        &self.actors
    }
}

/// Actual path selection or source-bound key association could not complete.
#[derive(Debug)]
pub enum CounterSelectionError<PE, E, N> {
    /// A present child credential property lacks original whole-property binding.
    Binding(crate::binding::BindingError<E, N>),
    /// Original child role structure/source/resource refused before selection.
    Property(crate::properties::Error<E, N>),
    /// Caller path discovery/validation refused, retaining its own cause.
    Selection {
        /// Original child signature requiring a path.
        signature: N,
        /// Exact selection failure; never interpreted as no counter.
        cause: PE,
    },
    /// Current source/generation or operation refused before key association.
    Access(AccessError<E, N>),
    /// Completed selected-key evidence contradicts the supplied path.
    Differs {
        /// Original child signature, not the root's key.
        signature: N,
    },
    /// No original successful-key receipt establishes this path association.
    Unproven {
        /// Original child signature still requiring an associated path.
        signature: N,
    },
}

/// Complete counter-source traversal, preserving selection and XML causes.
pub type CounterPathsResult<'view, 'document, X, PE> = counter::WalkResult<
    CounterPaths<'view, 'document, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    CounterSelectionError<PE, <X as Xml>::Error, <X as Xml>::Id>,
>;

/// Bind a path for EVERY original incorporated counter, including plain
/// `XMLDSig` children, before constructing a complete counter-actor census.
/// The same iterative source walker, actual child coverage receipts and
/// selected-key association kernel serve independent and whole-root checks.
/// Path selection may use caller acquisition/trust policy, but must fund its
/// data-dependent work through the supplied current operation before execution.
/// Selection does not replay the original XML mathematical verification.
///
/// The callback cannot return references into its short-lived counter receipt.
/// Its output borrows an independently checked path. A late missing path,
/// mismatched/unproven key, XML failure or resource refusal drops all retained
/// counter results; external selector side effects cannot be rolled back.
pub fn bind_counters<'view, 'document, X: CertificateXml, W: Work, PE>(
    root: &crate::binding::Selected<X>,
    access: &Access<'_, X, W>,
    mut select: impl FnMut(&counter::Binding<X>, &W) -> Result<&'view CheckedPath<'document>, PE>,
) -> CounterPathsResult<'view, 'document, X, PE> {
    let actors = counter::walk(access, root, |counter, layout| {
        let signature = counter.original().child();
        let roles = match layout {
            Some(layout) => counter_roles(access, layout)?,
            None => None,
        };
        let path = access
            .query(signature, |_, _, work| Ok(select(counter, work)))
            .map_err(CounterSelectionError::Access)?
            .map_err(|cause| CounterSelectionError::Selection { signature, cause })?;
        match path
            .bind_counter(counter, access)
            .map_err(CounterSelectionError::Access)?
        {
            CounterBinding::Bound(signer) => Ok(CounterActor {
                signer,
                roles,
                containers: layout.copied(),
            }),
            CounterBinding::Differs => Err(CounterSelectionError::Differs { signature }),
            CounterBinding::Unproven => Err(CounterSelectionError::Unproven { signature }),
        }
    })?;
    Ok(CounterPaths {
        snapshot: access.snapshot(),
        signature: root.containers().signature(),
        actors,
    })
}

type RoleResult<X, PE> = Result<
    Option<crate::role::Catalogue<X>>,
    CounterSelectionError<PE, <X as Xml>::Error, <X as Xml>::Id>,
>;

fn counter_roles<X: CertificateXml, W: Work, PE>(
    access: &Access<'_, X, W>,
    layout: &crate::container::Layout<X>,
) -> RoleResult<X, PE> {
    let Some(node) =
        crate::role::locate(access, layout).map_err(CounterSelectionError::Property)?
    else {
        return Ok(None);
    };
    let bound = crate::binding::bind(access, layout).map_err(CounterSelectionError::Binding)?;
    crate::role::read_node(
        access,
        layout.snapshot(),
        bound.containers().signature(),
        node,
    )
    .map(Some)
    .map_err(CounterSelectionError::Property)
}

impl<'document> CheckedPath<'document> {
    /// Bind a checked child signature to its actual selected certificate/key.
    /// EN319132-1 §6.3(aa) includes incorporated countersignature actors in the
    /// material obligation, including plain `XMLDSig` counters (§5.2.7.2).
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    ///
    /// Uses the original successful XML-owner decision and this checked path's
    /// inherited parameters. It does not reverify, resolve a different candidate,
    /// fabricate certificate-reference properties or infer trust from `KeyInfo`.
    /// No catalogue allocation/copy is required. A foreign or stale source is
    /// terminal before owner dispatch; opaque original evidence may still prove
    /// the association, while absent evidence remains explicitly Unproven.
    ///
    /// # Panics
    /// Only if the private nonempty checked-path construction invariant fails.
    pub fn bind_counter<'view, X: CertificateXml, W: Work>(
        &'view self,
        counter: &counter::Binding<X>,
        access: &Access<'_, X, W>,
    ) -> CounterPathResult<'view, 'document, X> {
        let source = counter.original();
        if source.snapshot() != access.snapshot() {
            return Err(AccessError::Changed {
                node: source.child(),
            });
        }
        let target = self.members.last().expect("a checked path has a target");
        let association = access.query(source.child(), |xml, snapshot, work| {
            xml.key_association(
                snapshot,
                source.child(),
                target.certificate(),
                self.facts.key,
                work,
            )
        })?;
        Ok(match association {
            KeyAssociation::Same => CounterBinding::Bound(CounterPath {
                counter: *counter,
                path: self,
            }),
            KeyAssociation::Differs => CounterBinding::Differs,
            KeyAssociation::Unproven => CounterBinding::Unproven,
        })
    }
}
