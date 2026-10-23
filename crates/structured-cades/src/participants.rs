//! Complete actual actor census for whole-signature and archive scopes.

use crate::{
    Cades, ISSUER,
    basic::SignerBinding,
    counters::Paths,
    credential::Complete,
    source::{DocumentId, Node},
};
use structured_ltv::{
    pki::{self, ParticipantError, ParticipantRequirements},
    source::{Query, Source},
    timestamp::TimestampPaths,
};

/// Unavailable historical proofs remain distinct from source/census refusal.
#[derive(Debug)]
pub enum Error {
    /// Original shared actor-census refusal.
    Participants(ParticipantError<Node>),
    /// The complete authority set of this actual historical proof is unavailable.
    Preservation {
        /// Original preservation attribute.
        property: Node,
        /// Exact historical mechanism.
        kind: crate::preservation::Kind,
    },
    /// An actual parallel source could not supply a complete history census.
    /// The original cause remains in preparation's preservation findings.
    PreservationSource {
        /// Original unreadable source or malformed historical property.
        source: Node,
    },
}

/// Derive every actual signer/counter/credential/TSA authority from the SAME
/// sealed format receipts. The full original timestamp and counter census is
/// checked by the existing LTV kernel; successful subsets cannot enter here.
/// Use the returned census's `close_statuses` for the actual complete/delta
/// CRL and OCSP authority closure. No parsing or authentication is repeated.
pub fn participants<'view, 'path, 'm, 'd, E, Q>(
    signer: &'view SignerBinding<'_, 'm, 'd, 'path>,
    counters: &'view Paths<'_, 'm, 'd, 'path>,
    credentials: &'view Complete<'_, 'm, 'd, 'path, E>,
    timestamps: &'view TimestampPaths<'view, '_, 'd, Node, DocumentId<'m, 'd>, (), Cades>,
    query: &Q,
) -> Result<ParticipantRequirements<'view, 'd, Node, DocumentId<'m, 'd>, (), Cades>, Error>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    'path: 'view,
    'd: 'path,
{
    participants_in(signer, counters, credentials, timestamps, None, query)
}

/// Same complete actor census after a source-bound ERS/PoE closure. Every
/// actual contained TSA must STILL occur in the supplied `TimestampPaths`;
/// historical proofs cannot substitute a successful subset or erase actors.
pub fn participants_preserved<'view, 'path, 'm, 'd, E, Q>(
    signer: &'view SignerBinding<'_, 'm, 'd, 'path>,
    counters: &'view Paths<'_, 'm, 'd, 'path>,
    credentials: &'view Complete<'_, 'm, 'd, 'path, E>,
    timestamps: &'view TimestampPaths<'view, '_, 'd, Node, DocumentId<'m, 'd>, (), Cades>,
    preservation: &crate::evidence::Closure<'_, '_, 'm, 'd, '_>,
    query: &Q,
) -> Result<ParticipantRequirements<'view, 'd, Node, DocumentId<'m, 'd>, (), Cades>, Error>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    'path: 'view,
    'd: 'path,
{
    participants_in(
        signer,
        counters,
        credentials,
        timestamps,
        Some(preservation),
        query,
    )
}
fn participants_in<'view, 'path, 'm, 'd, E, Q>(
    signer: &'view SignerBinding<'_, 'm, 'd, 'path>,
    counters: &'view Paths<'_, 'm, 'd, 'path>,
    credentials: &'view Complete<'_, 'm, 'd, 'path, E>,
    timestamps: &'view TimestampPaths<'view, '_, 'd, Node, DocumentId<'m, 'd>, (), Cades>,
    preservation: Option<&crate::evidence::Closure<'_, '_, 'm, 'd, '_>>,
    query: &Q,
) -> Result<ParticipantRequirements<'view, 'd, Node, DocumentId<'m, 'd>, (), Cades>, Error>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    'path: 'view,
    'd: 'path,
{
    let prepared = signer.prepared();
    if let Some(proofs) = preservation
        && !core::ptr::eq(proofs.prepared(), prepared)
    {
        return Err(Error::Participants(ParticipantError::Foreign {
            signature: Node::of(prepared.signer().span()),
        }));
    }
    let selected = prepared.document().signer(prepared.signer()).map_err(|_| {
        Error::Participants(ParticipantError::Foreign {
            signature: Node::of(prepared.signer().span()),
        })
    })?;
    if prepared.document().snapshot() != query.snapshot() {
        return Err(Error::Participants(ParticipantError::Foreign {
            signature: selected.node,
        }));
    }
    query
        .admit(selected.node, 1)
        .map_err(|cause| Error::Participants(ParticipantError::Scope(cause)))?;
    for required in prepared.preservation() {
        query
            .admit(required.property, 1)
            .map_err(|cause| Error::Participants(ParticipantError::Scope(cause)))?;
        // Archives and reference timestamps have distinct format-selected
        // input checks. The SAME complete timestamp census below requires
        // their actual actors; ERS/PoE also requires its sealed input/history.
        if !required.kind.is_archive() && !required.kind.is_reference_timestamp() {
            if let Some(proofs) = preservation
                && required.kind.is_evidence()
                && proofs
                    .contains(required, query.execution())
                    .map_err(|cause| {
                        Error::Participants(ParticipantError::Resource {
                            node: required.property,
                            cause,
                        })
                    })?
            {
                continue;
            }

            return Err(Error::Preservation {
                property: required.property,
                kind: required.kind,
            });
        }
    }
    if !prepared.preservation().is_empty() {
        for finding in prepared.preservation_findings() {
            query
                .admit(finding.location.node, 1)
                .map_err(|cause| Error::Participants(ParticipantError::Scope(cause)))?;
            if finding.severity == crate::prepare::Severity::Required {
                return Err(Error::PreservationSource {
                    source: finding.location.node,
                });
            }
        }
    }
    pki::participants(ISSUER, signer, counters, credentials, timestamps, query)
        .map_err(Error::Participants)
}
