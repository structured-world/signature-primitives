//! Completed-response construction, distinct from an attained baseline grade.

use super::{Emit, Error, Transaction, Work, Writer, XADES};
use crate::timestamp::XADES_141;
use crate::xml::Name;

/// New unsigned timestamp property to append at the staged tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// Single-token `SignatureTimeStamp` for B-T.
    Signature,
    /// `ArchiveTimeStamp` in the v1.4.1 namespace for B-LTA or renewal.
    Archive,
}

/// XML-owned output specific to the explicit references of historical stamps.
pub trait HistoricalTimestampWriter: Transaction {
    /// Write the given URI attribute with a unique reference to the exact
    /// original `SignatureValue`. A missing or foreign XML ID is an owner error.
    fn signature_value_uri<W: Work>(
        &mut self,
        value: Self::Id,
        attribute: Name<'static>,
        work: &W,
    ) -> Result<(), Self::Error>;

    /// Write a single ds:Transform using this exact approved canonicalization
    /// method and its parameters from the same original staged snapshot.
    fn canonicalization_transform<W: Work>(
        &mut self,
        method: Self::Id,
        work: &W,
    ) -> Result<(), Self::Error>;
}

/// Original token accepted by the request-bound common checker for the exact
/// proposed input. Only the augmentation operation constructs this association.
/// It is not trust, revocation chronology or a complete B-T/LTA assessment.
pub struct Timestamp<'a, D, G, N> {
    pub(super) snapshot: crate::xml::Snapshot<D, G>,
    pub(super) signature: N,
    pub(super) method: N,
    pub(super) name: crate::xml::Name<'static>,
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
        self.write_in(XADES, writer, work, |emit| {
            method(emit.writer, emit.work).map_err(Error::Writer)
        })
    }

    pub(super) fn write_in<B: Writer, W: Work>(
        &self,
        token_namespace: &'static str,
        writer: &mut B,
        work: &W,
        prefix: impl FnOnce(
            &mut Emit<'_, B, structured_asn1::memory::Execution<'_>>,
        ) -> Result<(), Error<B::Error>>,
    ) -> Result<(), Error<B::Error>> {
        let scoped = self.producer.execution_in(work);
        let mut emit = Emit {
            writer,
            work: &scoped,
        };
        emit.begin(self.name.namespace, self.name.local)?;
        // Method XML (including PrefixList) must be copied by its XML owner,
        // never reconstructed from only a URI or an invented ASN.1 identifier.
        scoped.charge_work(1).map_err(Error::Resource)?;
        prefix(&mut emit)?;
        emit.binary(
            token_namespace,
            "EncapsulatedTimeStamp",
            self.token.as_bytes(),
        )?;
        emit.end()
    }
}

impl TimestampKind {
    pub(super) const fn name(self) -> crate::xml::Name<'static> {
        match self {
            Self::Signature => super::name(XADES, "SignatureTimeStamp"),
            Self::Archive => super::name(XADES_141, "ArchiveTimeStamp"),
        }
    }
}
