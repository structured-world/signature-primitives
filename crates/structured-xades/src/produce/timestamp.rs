//! Completed-response construction, distinct from an attained baseline grade.

use super::{Emit, Error, Work, Writer, XADES};
use crate::timestamp::XADES_141;

/// New unsigned timestamp property to append at the staged tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// Single-token `SignatureTimeStamp` for B-T.
    Signature,
    /// `ArchiveTimeStamp` in the v1.4.1 namespace for B-LTA or renewal.
    Archive,
}

/// Original token accepted by the request-bound common checker for the exact
/// proposed input. Only the augmentation operation constructs this association.
/// It is not trust, revocation chronology or a complete B-T/LTA assessment.
pub struct Timestamp<'a, D, G, N> {
    pub(super) snapshot: crate::xml::Snapshot<D, G>,
    pub(super) signature: N,
    pub(super) method: N,
    pub(super) kind: TimestampKind,
    pub(super) token: &'a structured_asn1::Element<'a>,
    pub(super) producer: structured_pkix::algorithm::Producer<'a>,
    pub(super) evidence: &'a structured_cms::timestamp::Evidence,
}
impl<D: Copy, G: Copy, N: Copy> Timestamp<'_, D, G, N> {
    /// Mathematical token/authority/input facts retained by the existing checker.
    #[must_use]
    pub fn evidence(&self) -> &structured_cms::timestamp::Evidence {
        self.evidence
    }
    /// Exact snapshot used to compute and check this token's input.
    #[must_use]
    pub fn snapshot(&self) -> crate::xml::Snapshot<D, G> {
        self.snapshot
    }
    /// Actual method node used for reference replay and canonicalization.
    #[must_use]
    pub fn method(&self) -> N {
        self.method
    }

    pub(super) fn write<B: Writer, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
        method: impl FnOnce(&mut B, &structured_asn1::memory::Execution<'_>) -> Result<(), B::Error>,
    ) -> Result<(), Error<B::Error>> {
        let scoped = self.producer.execution_in(work);
        let mut emit = Emit {
            writer,
            work: &scoped,
        };
        let (namespace, local) = match self.kind {
            TimestampKind::Signature => (XADES, "SignatureTimeStamp"),
            TimestampKind::Archive => (XADES_141, "ArchiveTimeStamp"),
        };
        emit.begin(namespace, local)?;
        // Method XML (including PrefixList) must be copied by its XML owner,
        // never reconstructed from only a URI or an invented ASN.1 identifier.
        scoped.charge_work(1).map_err(Error::Resource)?;
        method(emit.writer, &scoped).map_err(Error::Writer)?;
        emit.binary(XADES, "EncapsulatedTimeStamp", self.token.as_bytes())?;
        emit.end()
    }
}
