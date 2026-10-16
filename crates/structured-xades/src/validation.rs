//! Validation-data containers and non-authoritative timestamp association hints.

use crate::binding::Bound;
use crate::container::XADES;
use crate::material::{self, Catalogue};
use crate::properties;
use crate::timestamp::{self, InputError, XADES_141};
use crate::xml::{Access, Name, Snapshot, Xml};
use structured_asn1::memory::Work;

mod refs;
pub(crate) use refs::read as read_references;
mod ref_catalogue;
mod ref_digest;
pub use ref_catalogue::{
    MaterialDigest, ReferenceCatalogueResult, ReferenceDigests, ReferenceRow, ReferenceSearch,
    compare_reference_catalogues, compare_reference_catalogues_with_tokens,
};
mod ref_issuer;
mod ref_time;
pub use ref_time::{ReferenceTime, ReferenceTimeError, matches_reference_time};
mod ref_envelope;
mod ref_key;
mod ref_name;
mod ref_ocsp;
pub use ref_envelope::{
    OcspEnvelopeError, OcspEnvelopeReference, OcspEnvelopeResult, OcspReferenceInput,
    check_ocsp_envelope_reference,
};
pub use ref_issuer::with_reference_issuer_serial;
pub use ref_key::{
    ReferenceKeyResult, ResponderKeyError, matches_reference_key, with_responder_key,
};
pub use ref_name::{ReferenceNameError, matches_reference_name};
pub use ref_ocsp::{
    OcspReferenceError, OcspReferenceIdentity, OcspReferenceResult, check_ocsp_reference,
};
mod ref_credential_certificates;
mod ref_crl;
mod ref_crl_value;
mod ref_path;
mod ref_presence;
mod ref_roles;
mod ref_status_required;
pub use ref_credential_certificates::{
    CredentialCertificate, CredentialCertificateReferences, CredentialCertificateResult,
    CredentialCertificateRow, CredentialReferencePlace, check_credential_certificate_references,
};
mod ref_status_roles;
pub use ref_path::{
    RootPathReferenceResult, RootPathReferences, RootReferenceRow,
    check_root_certificate_references,
};
pub use ref_presence::{
    ReferencePresence, ReferencePresenceError, ReferencePresenceFailure, ReferencePresenceResult,
    ReferencePresenceRow, reference_presence,
};
pub use ref_roles::{
    CertificateRoleComparison, CertificateRoleError, CertificateRoleResult, CertificateRoleRow,
    CertificateRoles, check_certificate_reference_roles,
};
pub use ref_status_required::{CredentialStatusSource, PathStatusSource};
pub use ref_status_roles::{
    RevocationRoleResult, RevocationRoles, StatusRoleAgreement, StatusRoleComparison,
    StatusRoleRow, StatusSourceComparison, check_revocation_reference_roles,
};
mod ref_fields;
pub use ref_crl::{
    CrlReferenceError, CrlReferenceIdentity, CrlReferenceResult, check_crl_reference,
};
pub use ref_crl_value::{
    CrlValueError, CrlValueReference, CrlValueResult, check_crl_value_reference,
};
pub use ref_digest::{
    ReferenceDigest, ReferenceDigestError, ReferenceTarget, compare_reference_digest,
    compare_reference_target,
};
pub use ref_fields::{ReferenceFieldError, ReferenceFieldResult, check_reference_fields};
pub use refs::{
    ReferenceEntry, ReferenceField, ReferenceIdentifier, ReferenceKind, ReferenceProperty,
    ResponderIdentifier,
};

/// Validation-data container's actual schema role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Material usable for signatures anywhere within the selected `XAdES` signature.
    Any,
    /// Material intended to help validate electronic timestamps.
    Timestamp,
}

/// A hint is never proof that a certificate/status value belongs to a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint<N> {
    /// Immediate preceding specified timestamp container takes precedence over
    /// the URI attribute, including a URI pointing at another timestamp.
    Adjacent(N),
    /// No implicit preceding association. Any original URI still needs XML-owned
    /// resolution; a wrong hint does not make otherwise usable material invalid.
    Unresolved {
        /// Whether the original URI attribute exists, distinct from its value.
        uri_present: bool,
    },
}

/// Original structural/processing cause, separate from material authenticity.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original selected-container/source/resource cause.
    Input(InputError<E, N>),
    /// Original inner material catalogue cause; successful partial catalogues
    /// are not returned when a later child refuses.
    Property(properties::Error<E, N>),
    /// `AnyValidationData` forbids URI even though its base schema permits it.
    ForbiddenUri {
        /// Original `AnyValidationData` node.
        node: N,
    },
    /// `AnyValidationData` must contain certificate or revocation values, or both.
    Empty {
        /// Original empty material container.
        node: N,
    },
}

/// Original complete container, before PKI, path/status or level validation.
#[derive(Debug)]
pub struct Data<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    role: Role,
    hint: Option<Hint<N>>,
    certificates: Option<Catalogue<N, D, G>>,
    revocations: Option<Catalogue<N, D, G>>,
}

impl<N: Copy, D: Copy, G: Copy> Data<N, D, G> {
    /// Exact XML source generation carrying this material.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original selected signature, not an application trust decision.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original validation-data property.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Actual schema role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
    /// Original timestamp association hint; never an authentication receipt.
    #[must_use]
    pub fn hint(&self) -> Option<Hint<N>> {
        self.hint
    }
    /// Complete original certificate-value catalogue, if present.
    #[must_use]
    pub fn certificates(&self) -> Option<&Catalogue<N, D, G>> {
        self.certificates.as_ref()
    }
    /// Complete original revocation-value catalogue, if present.
    #[must_use]
    pub fn revocations(&self) -> Option<&Catalogue<N, D, G>> {
        self.revocations.as_ref()
    }
}

/// Reading in this XML owner's original identity types.
pub type Reading<X> = Data<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
/// Original XML/property refusal types.
pub type ValidationResult<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// Reads one direct unsigned validation-data container of the selected signature.
///
/// EN319132-1 V1.3.1 §§5.4.6/5.5.1 separate `AnyValidationData`'s prohibited URI
/// from `TimeStampValidationData`'s optional non-authoritative hint. For validation,
/// §5.5.1.2 gives immediate preceding timestamp association priority over the URI;
/// it does not require rejecting usable material merely for a wrong URI hint.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    node: X::Id,
) -> ValidationResult<Reading<X>, X> {
    let parent = timestamp::unsigned_parent(access, bound, node).map_err(Error::Input)?;
    let mut previous = None;
    let mut found = false;
    for child in access.children(parent) {
        let child = child.map_err(|cause| Error::Input(InputError::Child(cause)))?;
        if child == node {
            found = true;
            break;
        }
        previous = Some(child);
    }
    if !found {
        return Err(Error::Input(InputError::Foreign { node }));
    }
    read_at(access, bound.containers().signature(), node, previous)
}

// The caller already holds this exact node from the same original direct
// unsigned cursor. Counters reuse the field kernel without fabricating a root
// B-level binding or reinterpreting the optional URI as authentication.
pub(crate) fn read_at<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    node: X::Id,
    previous: Option<X::Id>,
) -> ValidationResult<Reading<X>, X> {
    let role = if named(access, node, XADES_141, "AnyValidationData")? {
        Role::Any
    } else if named(access, node, XADES_141, "TimeStampValidationData")? {
        Role::Timestamp
    } else {
        return Err(Error::Input(InputError::Unexpected { node }));
    };
    let uri_present = access
        .attribute(
            node,
            Name {
                namespace: "",
                local: "URI",
            },
            |value| value.is_some(),
        )
        .map_err(|cause| Error::Input(InputError::Access(cause)))?;
    if role == Role::Any && uri_present {
        return Err(Error::ForbiddenUri { node });
    }
    let mut hint = None;
    if role == Role::Timestamp {
        hint = Some(Hint::Unresolved { uri_present });
        if let Some(prior) = previous
            && (named(access, prior, XADES, "SignatureTimeStamp")?
                || named(access, prior, XADES_141, "ArchiveTimeStamp")?
                || named(access, prior, XADES_141, "SigAndRefsTimeStampV2")?
                || named(access, prior, XADES_141, "RefsOnlyTimeStampV2")?)
        {
            hint = Some(Hint::Adjacent(prior));
        }
    }
    let mut certificates = None;
    let mut revocations = None;
    for child in access.children(node) {
        let child = child.map_err(|cause| Error::Input(InputError::Child(cause)))?;
        if named(access, child, XADES, "CertificateValues")? {
            if certificates.is_some() {
                return Err(Error::Property(properties::Error::Duplicate {
                    node: child,
                }));
            }
            if revocations.is_some() {
                return Err(Error::Property(properties::Error::Order { node: child }));
            }
            certificates = Some(material::read(access, child).map_err(Error::Property)?);
        } else if named(access, child, XADES, "RevocationValues")? {
            if revocations.is_some() {
                return Err(Error::Property(properties::Error::Duplicate {
                    node: child,
                }));
            }
            revocations = Some(material::read(access, child).map_err(Error::Property)?);
        } else {
            return Err(Error::Input(InputError::Unexpected { node: child }));
        }
    }
    if role == Role::Any
        && certificates.as_ref().is_none_or(|c| c.entries().is_empty())
        && revocations.as_ref().is_none_or(|c| c.entries().is_empty())
    {
        return Err(Error::Empty { node });
    }
    Ok(Data {
        snapshot: access.snapshot(),
        signature,
        node,
        role,
        hint,
        certificates,
        revocations,
    })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> ValidationResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(|cause| Error::Input(InputError::Access(cause)))
}
