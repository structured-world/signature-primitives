//! Format-owned credential material under original whole/archive coverage.
//!
//! X.509 issuer paths do not describe every dependency of an attribute
//! certificate or signed assertion. The existing format authenticator's receipt
//! supplies those inputs; this module checks their original incorporation.

mod check;
mod scope;
mod selection;

pub use check::check;
pub use scope::Scope;

use crate::binary::Location;
use crate::credential::{Checked, Credential, ParticipantCredentials};
use crate::reference::VisitError;
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::material::{ArchiveError, ArtifactRef, IndexError};
use structured_ltv::timestamp::{ObligationError, TimestampScope};

/// One actual format dependency. Borrowed binary artifacts are queried during
/// the callback and cannot escape it; no DER copy or fingerprint substitutes.
#[derive(Clone, Copy)]
pub enum Need<'value, 'document, N, D, G> {
    /// Original known certificate, whole CRL or authenticated basic response.
    Known(ArtifactRef<'value, 'document>),
    /// Exact original OtherCertificate/OtherValue catalogue member. The format
    /// owner establishes its meaning and agreement before visiting this need.
    Open(Location<N, D, G>),
    /// A required format-specific value has no matching original open member.
    /// Discovery can be complete while incorporated material is missing.
    Missing,
}

/// Complete format dependency discovery and interpretation, independent of
/// finding an original incorporated copy. Resource failures are always Err.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// All actual dependencies were visited and their format semantics checked.
    Complete,
    /// This format handler cannot establish the required material semantics.
    Unsupported,
    /// Discovery/interpretation is still incomplete; an empty prefix is no proof.
    Unprocessed,
    /// Original required material is readable but not usable for this credential.
    Unusable,
    /// Original required material violates its selected format syntax.
    Malformed,
}

/// Same format owner as credential authentication, operating on its actual
/// retained receipt A, WITHOUT authenticating the credential again. It visits
/// every required input, including the attribute certificate's own status;
/// returning no inputs is Complete only if that format actually needs none.
/// `CertificateFree` is never an implicit implementation of this capability.
///
/// EN319132-1 V1.3.1 §§5.2.6/5.4.4/5.4.5/6.3(aa) leave concrete assertion and
/// other credential formats with their owners while requiring their validation
/// material. A X.509 issuer's status does not substitute for credential status.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub trait Provider<X: Xml, A> {
    /// Original format/processing/resource cause, not a negative completeness fact.
    type Error;

    /// Visit dependencies of THIS authenticated original credential once. Source
    /// decoding, semantic/status checks and every traversal/copy/allocation use
    /// the supplied current Access/Work before execution. Do not reparse XML,
    /// reverify the credential, acquire sources implicitly or drop a callback
    /// refusal. The common caller independently preserves that first refusal.
    fn visit<VE, W: Work>(
        &self,
        credential: &Checked<'_, '_, A, X::Id, X::Document, X::Generation>,
        open: &[super::Opaque<X::Id, X::Document, X::Generation>],
        access: &Access<'_, X, W>,
        visitor: impl for<'value, 'document> FnMut(
            Need<'value, 'document, X::Id, X::Document, X::Generation>,
        ) -> Result<(), VE>,
    ) -> Result<Completeness, VisitError<Self::Error, VE>>;
}

/// No incorporated copy, or only copies outside the selected earlier archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// No exact original incorporated artifact/open catalogue member exists.
    Absent,
    /// Exact copies exist, but this archive's original input covers none of them.
    Uncovered,
}

/// Original format dependency ordinal, without retaining callback-local DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Zero-based ordinal in this handler's complete dependency visitation.
    pub dependency: usize,
    /// Missing versus outside this original archive's coverage.
    pub cause: Missing,
}

/// One actual authenticated credential and all its original material findings.
pub struct Entry<N, D, G> {
    source: Credential<N, D, G>,
    completeness: Completeness,
    findings: OwnedVec<Finding>,
}

impl<N: Copy, D: Copy, G: Copy> Entry<N, D, G> {
    /// Original signed credential, not a selected issuer certificate.
    #[must_use]
    pub fn source(&self) -> Credential<N, D, G> {
        self.source
    }
    /// Original format interpretation, distinct from copy availability.
    #[must_use]
    pub fn completeness(&self) -> Completeness {
        self.completeness
    }
    /// Missing dependencies in original visitation order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

/// Every actual credential in the source-derived whole or earlier-archive scope.
/// Borrowing the authenticated catalogue preserves its original receipt identity;
/// retained findings own only admitted metadata, never temporary parsed values.
pub struct Report<'auth, 'path, 'document, A, N, D, G> {
    credentials: &'auth ParticipantCredentials<'path, 'document, A, N, D, G>,
    scope: TimestampScope<N, D, G>,
    entries: OwnedVec<Entry<N, D, G>>,
    complete: bool,
}

impl<'auth, 'path, 'document, A, N: Copy, D: Copy, G: Copy>
    Report<'auth, 'path, 'document, A, N, D, G>
{
    /// Same original independently authenticated credential census.
    #[must_use]
    pub fn credentials(&self) -> &'auth ParticipantCredentials<'path, 'document, A, N, D, G> {
        self.credentials
    }
    /// Exact original whole-signature or earlier-archive requirement scope.
    #[must_use]
    pub fn scope(&self) -> TimestampScope<N, D, G> {
        self.scope
    }
    /// Every original required credential once, including negative outcomes.
    #[must_use]
    pub fn entries(&self) -> &[Entry<N, D, G>] {
        &self.entries
    }
    /// Only format-specific material interpretation and incorporation. This
    /// does not replace X.509 path/status, timestamp or application trust checks.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.complete
    }
    /// Original source generation of the authenticated participant set.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.credentials.snapshot()
    }
}

/// Terminal source, scope, callback or resource failure. No successful partial
/// report is returned, and external handler side effects cannot be rolled back.
#[derive(Debug)]
pub enum Error<E, PE, N> {
    /// Foreign source, signature, incomplete counter census or archive binding.
    Foreign {
        /// Original enclosing node.
        node: N,
    },
    /// Original XML/current-operation/source refusal.
    Access(AccessError<E, N>),
    /// Original scope/membership query refusal.
    Obligation(ObligationError<N>),
    /// Original known artifact lookup refusal.
    Index(IndexError<N>),
    /// Original archive evidence/coverage/lookup refusal.
    Archive(ArchiveError<N>),
    /// Original credential format handler refused.
    Provider {
        /// Original credential payload.
        node: N,
        /// Unchanged processing/resource cause.
        cause: PE,
    },
    /// Admission failed before dependent traversal or report growth.
    Resource {
        /// Original selecting credential or enclosing root.
        node: N,
        /// Original memory/work refusal.
        cause: MemoryError,
    },
    /// The handler returned a visitor error without invoking/refusing its visitor.
    CallbackProtocol {
        /// Original credential payload.
        node: N,
    },
}

/// Original typed credential-material report or terminal refusal.
pub type CheckResult<'auth, 'path, 'document, X, A, PE> = Result<
    Report<
        'auth,
        'path,
        'document,
        A,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    Error<<X as Xml>::Error, PE, <X as Xml>::Id>,
>;

pub(super) type ProcessingResult<T, X, PE> =
    Result<T, Error<<X as Xml>::Error, PE, <X as Xml>::Id>>;
