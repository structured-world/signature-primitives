//! Complete source-derived independently authenticated credential census.

use crate::{
    Error,
    basic::SignerBinding,
    counters::Paths,
    prepare::Preparation,
    properties::{OpenRole, OpenValue, Properties},
    source::{DocumentId, Node, Original},
};
use structured_asn1::{
    Reader,
    memory::{OwnedVec, Work},
};
use structured_ltv::source::Snapshot;
use structured_ltv::{
    credential::Authentication,
    pki::{self, Authorities, CounterReceipts, CredentialGroup, CredentialReceipts},
};
use structured_pkix::Certificate;

/// Actual protected credential delivered to its selected format owner. The
/// private source/owner comes from the complete original property reading.
pub struct Context<'scope, 'model, 'document> {
    source: Original<'model, 'document>,
    signature: Node,
    value: OpenValue<'document>,
    signer: &'scope Certificate<'document>,
    operation: &'scope Reader<'document>,
}
impl<'m, 'd> Context<'_, 'm, 'd> {
    /// Original protected credential source and immutable document identity.
    #[must_use]
    pub fn source(&self) -> Original<'m, 'd> {
        self.source
    }
    /// Actual root/counter signature protecting this value.
    #[must_use]
    pub fn signature(&self) -> Node {
        self.signature
    }
    /// Actual independently bound signing certificate, not an arbitrary hint.
    #[must_use]
    pub fn signer(&self) -> &Certificate<'d> {
        self.signer
    }
    /// Original open type, explicit OPTIONAL absence, and source context.
    #[must_use]
    pub fn value(&self) -> OpenValue<'d> {
        self.value
    }
    /// Current operation; use the value's saved reader context for ASN.1
    /// inspection, preserving original source/depth and both work ceilings.
    #[must_use]
    pub fn operation(&self) -> &Reader<'d> {
        self.operation
    }
}

/// Actual credential-format authentication, without a parallel crypto engine.
///
/// EN319122-1 §5.2.6.1 leaves non-X.509 certificate/assertion formats to their
/// own specifications. Authenticate THIS original value and its binding to the
/// actual signer, returning the concrete format evidence and every actual
/// authority path/direct anchor or explicit certificate-free mechanism used.
/// Admit parsing, arithmetic, copies, output and retained evidence through the
/// current execution before work; preserve original resource/processing causes.
/// No network/file acquisition or asserted-role authorization occurs here.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub trait Provider<'path, 'document> {
    /// Actual retained format evidence, without Clone/Send/Sync bounds.
    type Evidence;
    /// Original provider/source/resource refusal, distinct from rejection.
    type Error;
    /// Authenticate one original independently signed credential exactly once.
    fn authenticate(
        &self,
        context: Context<'_, '_, 'document>,
    ) -> Result<Authentication<'path, 'document, Self::Evidence>, Self::Error>;
}

/// Completed credential answer retained even when no complete census exists.
pub enum Outcome<'path, 'document, E> {
    /// Concrete original authentication outcome (including negative answers).
    Authentication(Authentication<'path, 'document, E>),
    /// The open schema carries no payload; this cannot become authenticated.
    Absent,
    /// Empty Paths is incomplete handler evidence, not certificate-free.
    MissingAuthorities(E),
}
/// One original credential and its completed original-format answer.
pub struct Checked<'model, 'document, 'path, E> {
    source: Original<'model, 'document>,
    outcome: Outcome<'path, 'document, E>,
}
impl<'m, 'd, 'p, E> Checked<'m, 'd, 'p, E> {
    /// Exact original credential enclosure and protecting document.
    #[must_use]
    pub fn source(&self) -> Original<'m, 'd> {
        self.source
    }
    /// Actual format evidence or explicit negative outcome, without copying.
    #[must_use]
    pub fn outcome(&self) -> &Outcome<'p, 'd, E> {
        &self.outcome
    }
}

/// Complete original group, exposed as an LTV group only through [`Complete`].
pub struct Group<'model, 'document, 'path, E> {
    signature: Node,
    entries: OwnedVec<Checked<'model, 'document, 'path, E>>,
}
impl<'d, 'p, E> CredentialGroup<'p, 'd> for Group<'_, 'd, 'p, E> {
    type Id = Node;
    fn signature(&self) -> Node {
        self.signature
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
    fn credential(&self, ordinal: usize) -> pki::Credential<'p, 'd, Node> {
        let entry = &self.entries[ordinal];
        let Outcome::Authentication(Authentication::Authenticated { authorities, .. }) =
            &entry.outcome
        else {
            unreachable!("only complete groups are exposed as credential receipts");
        };
        pki::Credential {
            signature: self.signature,
            node: entry.source.node,
            authorities: *authorities,
        }
    }
}

/// Complete original root/counter results. A negative later credential does
/// not disappear behind the successful prefix, and no complete receipt exists.
pub struct Report<'model, 'document, 'path, E> {
    signature: Original<'model, 'document>,
    root: Group<'model, 'document, 'path, E>,
    counters: OwnedVec<Group<'model, 'document, 'path, E>>,
    complete: bool,
}
/// One original borrowed counter group, without copying retained evidence.
pub type CounterGroup<'view, 'm, 'd, 'p, E> = (Node, &'view [Checked<'m, 'd, 'p, E>]);
impl<'m, 'd, 'p, E> Report<'m, 'd, 'p, E> {
    /// Every original root credential, including absent/rejected/unsupported.
    #[must_use]
    pub fn root(&self) -> &[Checked<'m, 'd, 'p, E>] {
        &self.root.entries
    }
    /// Number of counter groups with original credentials.
    #[must_use]
    pub fn counters(&self) -> usize {
        self.counters.len()
    }
    /// One original counter group after current metadata admission. Absence is
    /// distinct from refusal; the caller cannot traverse attacker-sized groups
    /// through an infallible iterator that bypasses current Work.
    pub fn counter<W: Work>(
        &self,
        ordinal: usize,
        work: &W,
    ) -> Result<Option<CounterGroup<'_, 'm, 'd, 'p, E>>, structured_asn1::memory::MemoryError> {
        work.charge_work(1)?;
        Ok(self
            .counters
            .get(ordinal)
            .map(|group| (group.signature, &*group.entries)))
    }
    /// Complete actual authority-input census, only after ALL original values
    /// authenticated with nonempty/explicit authority facts.
    #[must_use]
    pub fn complete(&self) -> Option<Complete<'_, 'm, 'd, 'p, E>> {
        if self.complete {
            Some(Complete { report: self })
        } else {
            None
        }
    }
}

/// Borrowed full credential proof. Its construction cannot select a successful
/// subset or replace the original protecting signature.
pub struct Complete<'receipt, 'model, 'document, 'path, E> {
    pub(crate) report: &'receipt Report<'model, 'document, 'path, E>,
}
impl<'m, 'd, 'p, E> CredentialReceipts<'p, 'd> for Complete<'_, 'm, 'd, 'p, E> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    type Group = Group<'m, 'd, 'p, E>;
    fn snapshot(&self) -> Snapshot<DocumentId<'m, 'd>, ()> {
        self.report.signature.snapshot
    }
    fn signature(&self) -> Node {
        self.report.signature.node
    }
    fn root(&self) -> Option<&Self::Group> {
        if self.report.root.entries.is_empty() {
            None
        } else {
            Some(&self.report.root)
        }
    }
    fn counters(&self) -> usize {
        self.report.counters.len()
    }
    fn counter(&self, ordinal: usize) -> (Node, &Self::Group) {
        let group = &self.report.counters[ordinal];
        (group.signature, group)
    }
}

/// Processing refuses without returning a successful partial authentication.
#[derive(Debug)]
pub enum CheckError<E> {
    /// Source, original association or capacity/work refused before use.
    Processing(Error),
    /// Actual root/counter has no bound signing certificate for this operation.
    Unbound {
        /// Original protecting signer.
        signature: Node,
    },
    /// Original format/schema/placement findings prevent a complete protected
    /// credential census. The preparation retains every original cause; no
    /// format handler has been called and no successful empty set is issued.
    Nonconforming {
        /// Original selected root.
        signature: Node,
    },
    /// Original opaque format refusal and its physical enclosing credential.
    Provider {
        /// Original protected credential.
        node: Node,
        /// Unchanged provider/resource error.
        cause: E,
    },
}

/// Authenticate every actual root/counter non-claimed credential using the
/// existing format-owner contract. All original selections are checked before
/// authentication begins; a caller cannot supply only successful groups.
pub fn check<'m, 'd, 'p, E, P: Provider<'p, 'd, Evidence = E>>(
    prepared: &Preparation<'m, 'd>,
    signer: &SignerBinding<'_, 'm, 'd, 'p>,
    counters: &Paths<'_, 'm, 'd, 'p>,
    provider: &P,
    operation: &Reader<'d>,
) -> Result<Report<'m, 'd, 'p, E>, CheckError<P::Error>> {
    let processing = CheckError::Processing;
    prepared
        .document()
        .message()
        .require_session(operation, "cades.credentials")
        .map_err(|cause| processing(Error::Cms(cause)))?;
    let selected = prepared.document().locate(prepared.signer().span());
    operation
        .charge(1)
        .map_err(|cause| processing(Error::encoding(cause, "cades.credentials")))?;
    if !core::ptr::eq(prepared, signer.prepared())
        || selected.snapshot != counters.snapshot()
        || selected.node != counters.signature()
        || counters.len() != prepared.counters().len()
    {
        return Err(processing(Error::Foreign {
            at: selected.node.span().start,
        }));
    }
    if !signer.is_bound() {
        return Err(CheckError::Unbound {
            signature: selected.node,
        });
    }
    // Both value syntax and signed placement were established by the original
    // preparation. A partial open-value prefix or an unsigned role value must
    // never be promoted to a complete PROTECTED credential census.
    if !prepared.basic_format_requirements_met() {
        return Err(CheckError::Nonconforming {
            signature: selected.node,
        });
    }
    // Finish whole-source/counter membership preflight BEFORE the first handler.
    for (ordinal, expected) in prepared.counters().iter().enumerate() {
        operation
            .charge(1)
            .map_err(|cause| processing(Error::encoding(cause, "cades.credentials")))?;
        if counters.counter(ordinal).signature != expected.node() {
            return Err(processing(Error::Foreign {
                at: expected.node().span().start,
            }));
        }
    }
    let mut complete = true;
    let root = group(
        prepared,
        selected.node,
        prepared.properties(),
        signer.certificate(),
        provider,
        operation,
        &mut complete,
    )?;
    let work = operation.execution();
    let mut groups = work.vector();
    for (ordinal, counter) in prepared.counters().iter().enumerate() {
        operation
            .charge(1)
            .map_err(|cause| processing(Error::encoding(cause, "cades.credentials")))?;
        let Some(properties) = counter.properties() else {
            return Err(CheckError::Unbound {
                signature: counter.node(),
            });
        };
        let path = counters.counter(ordinal).path;
        let target = path.members().last().ok_or(CheckError::Unbound {
            signature: counter.node(),
        })?;
        let group = group(
            prepared,
            counter.node(),
            properties,
            target.certificate(),
            provider,
            operation,
            &mut complete,
        )?;
        if !group.entries.is_empty() {
            groups.try_push(group).map_err(|cause| {
                processing(Error::resource(
                    cause,
                    "cades.credentials",
                    counter.node().span().start,
                ))
            })?;
        }
    }
    Ok(Report {
        signature: selected,
        root,
        counters: groups.into_owned(),
        complete,
    })
}

fn group<'m, 'd, 'p, E, P: Provider<'p, 'd, Evidence = E>>(
    prepared: &Preparation<'m, 'd>,
    signature: Node,
    properties: &Properties<'d>,
    signer: &Certificate<'d>,
    provider: &P,
    operation: &Reader<'d>,
    complete: &mut bool,
) -> Result<Group<'m, 'd, 'p, E>, CheckError<P::Error>> {
    let work = operation.execution();
    let mut entries = work.vector();
    for value in properties.open_values() {
        work.charge_work(1).map_err(|cause| {
            CheckError::Processing(Error::resource(
                cause,
                "cades.credentials",
                signature.span().start,
            ))
        })?;
        if !matches!(
            value.role,
            OpenRole::AttributeCertificate
                | OpenRole::OtherAttributeCertificate
                | OpenRole::SignedAssertion
        ) {
            continue;
        }
        let source = prepared.document().locate(value.enclosure.span());
        let outcome = if value.value.is_none() {
            *complete = false;
            Outcome::Absent
        } else {
            match provider
                .authenticate(Context {
                    source,
                    signature,
                    value: *value,
                    signer,
                    operation,
                })
                .map_err(|cause| CheckError::Provider {
                    node: source.node,
                    cause,
                })? {
                Authentication::Authenticated {
                    evidence,
                    authorities: Authorities::Paths([]),
                } => {
                    *complete = false;
                    Outcome::MissingAuthorities(evidence)
                }
                Authentication::Unsupported => {
                    *complete = false;
                    Outcome::Authentication(Authentication::Unsupported)
                }
                Authentication::Rejected => {
                    *complete = false;
                    Outcome::Authentication(Authentication::Rejected)
                }
                authenticated @ Authentication::Authenticated { .. } => {
                    Outcome::Authentication(authenticated)
                }
            }
        };
        entries
            .try_push(Checked { source, outcome })
            .map_err(|cause| {
                CheckError::Processing(Error::resource(
                    cause,
                    "cades.credentials",
                    source.node.span().start,
                ))
            })?;
    }
    Ok(Group {
        signature,
        entries: entries.into_owned(),
    })
}
