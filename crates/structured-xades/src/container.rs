//! Original direct-incorporation containers of a selected XML signature.

use crate::xml::{Access, AccessError, ChildError, Name, Snapshot, Xml};
use structured_asn1::memory::Work;

/// `XMLDSig` namespace; the prefix used in the source is irrelevant.
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Namespace containing the qualifying-property containers.
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// Namespace specified by ETSI TS 101 903 V1.1.1 §5.
pub const XADES_111: &str = "http://uri.etsi.org/01903/v1.1.1#";
/// Namespace specified by ETSI TS 101 903 V1.2.2 §5.
pub const XADES_122: &str = "http://uri.etsi.org/01903/v1.2.2#";

/// Syntax found in the selected signature's original qualifying container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// EN 319 132-1.
    En319132,
    /// TS 103 171, with the 1.3.2 namespace and original certificate properties.
    Ts103171,
    /// TS 101 903 V1.1.1.
    Ts101903V111,
    /// TS 101 903 V1.2.2.
    Ts101903V122,
}

impl Syntax {
    /// Exact expanded-name namespace of the qualifying container.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::En319132 | Self::Ts103171 => XADES,
            Self::Ts101903V111 => XADES_111,
            Self::Ts101903V122 => XADES_122,
        }
    }
}

/// The caller's authorized set of original direct-incorporation syntaxes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Syntaxes {
    /// Accept the current EN syntax exclusively.
    #[default]
    En319132,
    /// Also accept the explicitly selected TS 101 903 V1.2.2 syntax.
    WithTs101903V122,
}

/// Original layout dispatches to the readers for its actual syntax.
pub enum Selected<X: Xml> {
    /// Current baseline property layout.
    En319132(Layout<X>),
    /// Legacy qualifying properties, with independent processing rules.
    Ts101903V122(crate::legacy::Layout<X>),
}

/// Why a selected signature's direct containers could not be located.
#[derive(Debug)]
pub enum ContainerError<E, N> {
    /// Original XML access or execution failure.
    Access(AccessError<E, N>),
    /// Element-only container traversal failed, with its original location.
    Child(ChildError<E, N>),
    /// An element has no role in the selected container's schema.
    Unexpected {
        /// Original element identity.
        node: N,
    },
    /// A required container is absent.
    Missing {
        /// Parent in whose direct child list the container was required.
        parent: N,
        /// Missing container's local name.
        local: &'static str,
    },
    /// More than one original container occupies the same schema role.
    Duplicate {
        /// Repeated container's original identity.
        node: N,
    },
    /// `SignedProperties` appears after `UnsignedProperties`.
    Order {
        /// Out-of-order original container.
        node: N,
    },
    /// A required property container has no element children.
    Empty {
        /// Original empty container.
        node: N,
    },
}

/// Original container identities, before reference coverage or property checks.
///
/// This is structural inspection, not authenticated signature evidence or an
/// attained baseline level. Construction is restricted to [`locate`]. Target,
/// `SignedProperties` reference coverage, property syntax and mathematical checks
/// are separate obligations; mere presence never proves them.
#[derive(Debug, Clone, Copy)]
pub struct Containers<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    object: N,
    qualifying: N,
    signed: N,
    unsigned: Option<N>,
    syntax: Syntax,
}

impl<N: Copy, D: Copy, G: Copy> Containers<N, D, G> {
    /// The exact original source under which these nodes were located.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// The selected original Signature, not another signature in the document.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// The single ds:Object holding the directly incorporated properties.
    #[must_use]
    pub fn object(&self) -> N {
        self.object
    }
    /// The original `QualifyingProperties` container.
    #[must_use]
    pub fn qualifying(&self) -> N {
        self.qualifying
    }
    /// The original `SignedProperties` container, before coverage verification.
    #[must_use]
    pub fn signed(&self) -> N {
        self.signed
    }
    /// The original optional `UnsignedProperties` container.
    #[must_use]
    pub fn unsigned(&self) -> Option<N> {
        self.unsigned
    }

    /// Syntax selected by the original qualifying element's expanded name.
    #[must_use]
    pub fn syntax(&self) -> Syntax {
        self.syntax
    }
}

/// Locates the direct containers under exactly the selected Signature.
///
/// Other ds:Object payloads may be mixed-content `XMLDSig` objects and are not
/// reinterpreted as `XAdES` property containers. No recursive descendant search
/// may substitute a nested or another signature's properties. All fan-out is
/// iterative and admitted in the current execution before access.
pub fn locate<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
) -> ContainerResult<Layout<X>, X> {
    locate_in(access, signature, None, Syntax::En319132)
}

/// Locates an original layout under the caller's expressly selected syntax set.
pub fn locate_with_syntax<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    allowed: Syntaxes,
) -> ContainerResult<Selected<X>, X> {
    let layout = locate_in(
        access,
        signature,
        (allowed == Syntaxes::WithTs101903V122).then_some(Syntax::Ts101903V122),
        Syntax::En319132,
    )?;
    Ok(match layout.syntax() {
        Syntax::En319132 => Selected::En319132(layout),
        Syntax::Ts101903V122 => Selected::Ts101903V122(crate::legacy::Layout::new(layout)),
        Syntax::Ts101903V111 | Syntax::Ts103171 => unreachable!("not selected by Syntaxes"),
    })
}

pub(crate) fn locate_historical<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    syntax: Syntax,
) -> ContainerResult<Layout<X>, X> {
    let layout = locate_in(access, signature, Some(syntax), syntax)?;
    if layout.syntax() == syntax {
        Ok(layout)
    } else {
        Err(ContainerError::Unexpected {
            node: layout.qualifying(),
        })
    }
}

fn locate_in<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    historical: Option<Syntax>,
    current: Syntax,
) -> ContainerResult<Layout<X>, X> {
    // EN 319 132-1 V1.3.1 §§4.4.1–4.4.2: direct incorporation within one Object,
    // at most one QualifyingProperties and all signed properties in one container.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    if !named(access, signature, DS, "Signature")? {
        return Err(ContainerError::Unexpected { node: signature });
    }
    let historical = historical.filter(|syntax| syntax.namespace() != XADES);
    let mut selected = None;
    for child in access.children(signature) {
        let object = child.map_err(ContainerError::Child)?;
        if !named(access, object, DS, "Object")? {
            continue;
        }
        // ds:Object is mixed content. Unlike property containers, arbitrary
        // character data and other application payloads are permitted here.
        let mut cursor = access.first_child(object).map_err(ContainerError::Access)?;
        while let Some(node) = cursor {
            // EN319132-1 §6.3 requires ONLY direct incorporation for all four
            // current baseline levels (note1 excludes QualifyingPropertiesReference).
            // A valid direct container cannot hide an indirect sibling in this
            // or another Object. Arbitrary nested application payload is not
            // searched or reinterpreted as a protocol property container.
            // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
            if named(access, node, XADES, "QualifyingPropertiesReference")?
                || (if let Some(historical) = historical {
                    named(
                        access,
                        node,
                        historical.namespace(),
                        "QualifyingPropertiesReference",
                    )?
                } else {
                    false
                })
            {
                return Err(ContainerError::Unexpected { node });
            }
            let syntax = qualifying_syntax(access, node, historical, current)?;
            if let Some(syntax) = syntax {
                if selected.is_some() {
                    return Err(ContainerError::Duplicate { node });
                }
                selected = Some((object, node, syntax));
            }
            cursor = access
                .next_sibling(object, node)
                .map_err(ContainerError::Access)?;
        }
    }
    let Some((object, qualifying, syntax)) = selected else {
        return Err(ContainerError::Missing {
            parent: signature,
            local: "QualifyingProperties",
        });
    };
    let mut signed = None;
    let mut unsigned = None;
    for child in access.children(qualifying) {
        let node = child.map_err(ContainerError::Child)?;
        if named(access, node, syntax.namespace(), "SignedProperties")? {
            if signed.is_some() {
                return Err(ContainerError::Duplicate { node });
            }
            if unsigned.is_some() {
                return Err(ContainerError::Order { node });
            }
            signed = Some(node);
        } else if named(access, node, syntax.namespace(), "UnsignedProperties")? {
            if unsigned.is_some() {
                return Err(ContainerError::Duplicate { node });
            }
            unsigned = Some(node);
        } else {
            return Err(ContainerError::Unexpected { node });
        }
    }
    let Some(signed) = signed else {
        return Err(ContainerError::Missing {
            parent: qualifying,
            local: "SignedProperties",
        });
    };
    if syntax == Syntax::En319132 {
        nonempty(access, signed)?;
        if let Some(unsigned) = unsigned {
            nonempty(access, unsigned)?;
        }
    }
    Ok(Containers {
        snapshot: access.snapshot(),
        signature,
        object,
        qualifying,
        signed,
        unsigned,
        syntax,
    })
}

/// Original container layout carrying the selected adapter's source identities.
pub type Layout<X> = Containers<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// A structural result retaining the original XML cause and node location.
pub type ContainerResult<T, X> = Result<T, ContainerError<<X as Xml>::Error, <X as Xml>::Id>>;

fn qualifying_syntax<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    historical: Option<Syntax>,
    current: Syntax,
) -> ContainerResult<Option<Syntax>, X> {
    const QUALIFYING: &str = "QualifyingProperties";
    if named(access, node, XADES, QUALIFYING)? {
        return Ok(Some(if current == Syntax::Ts103171 {
            current
        } else {
            Syntax::En319132
        }));
    }
    if let Some(syntax) = historical
        && named(access, node, syntax.namespace(), QUALIFYING)?
    {
        return Ok(Some(syntax));
    }
    if current != Syntax::En319132
        && (named(access, node, XADES_111, QUALIFYING)?
            || named(access, node, XADES_122, QUALIFYING)?
            || named(access, node, XADES_111, "QualifyingPropertiesReference")?
            || named(access, node, XADES_122, "QualifyingPropertiesReference")?)
    {
        return Err(ContainerError::Unexpected { node });
    }
    Ok(None)
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> ContainerResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(ContainerError::Access)
}

fn nonempty<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> ContainerResult<(), X> {
    // EN 319 132-1 §§4.3.2–4.3.3 forbid empty property containers.
    match access.children(node).next() {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => Err(ContainerError::Child(error)),
        None => Err(ContainerError::Empty { node }),
    }
}
