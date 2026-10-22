//! Original reference timestamp inputs, EN319122-1 V1.3.1 A.1.5.1–A.1.5.2.
//!
//! Attribute CONTENTS contain attrType and attrValues with their own headers;
//! the outer SEQUENCE header/EOC is excluded. BER is preserved, not replaced
//! by a DER re-encoding. Signature-and-references requires signature timestamps
//! under this edition: an external historical time-mark has no invented wire
//! representation here. These proofs authenticate the original REFERENCES,
//! not the certificates or revocation assertions to which they refer.
//! <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>

use super::{CheckError, CheckTime, Checked, Context};
use crate::{
    Cades, Error, ISSUER,
    prepare::{
        Preparation,
        encoding::{AttributeEncoding, SignerView},
    },
    preservation::Kind,
    source::{DocumentId, Node},
};
use core::convert::Infallible;
use structured_asn1::{
    Oid, Reader,
    memory::{Memory, OwnedMap, OwnedVec, Work},
};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{self as tsp, ComputedInput, ImprintContext, ImprintProof, InputFailure},
};
use structured_ltv::{
    material::Coverage, pki::CheckedPath, source::Source as _, timestamp::Purpose,
};
use structured_pkix::algorithm::digest::AsnDigest;

const FIELD: &str = "cades.references";

/// Actual required input object; absence is not an empty-byte fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// Every original signature-time-stamp Attribute, in its original order.
    SignatureTimestamp,
    /// The original complete-certificate-references Attribute.
    CertificateReferences,
    /// The original complete-revocation-references Attribute.
    RevocationReferences,
}
impl Component {
    fn oid(self) -> Oid<'static> {
        let bytes: &'static [u8] = match self {
            Self::SignatureTimestamp => &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 14],
            Self::CertificateReferences => &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21],
            Self::RevocationReferences => &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22],
        };
        Oid::from_bytes(bytes)
    }
}

/// Original selection refusal, before content/provider side effects.
#[derive(Debug)]
pub enum SelectionError {
    /// Original reader, capacity, work or source-processing cause.
    Processing(Error),
    /// Wrong source, owner, placement, purpose or token occurrence.
    WrongOccurrence,
    /// The selected edition requires this original component.
    Missing(Component),
    /// A unique references Attribute cannot be chosen from duplicates.
    Duplicate {
        /// Actual second attribute, without a fabricated input offset.
        property: Node,
    },
    /// A registered required/target Attribute does not hold exactly one value.
    Cardinality {
        /// Actual malformed attribute.
        property: Node,
    },
}
impl From<Error> for SelectionError {
    fn from(cause: Error) -> Self {
        Self::Processing(cause)
    }
}

/// Closed original recipe: only range descriptors are retained, never payload
/// copies or a caller-selected replacement digest. No detached input is used.
pub struct ReferenceInput<'input, 'model, 'document> {
    prepared: &'input Preparation<'model, 'document>,
    operation: &'input Reader<'document>,
    ordinal: usize,
    parts: OwnedVec<&'document [u8]>,
    covered: Option<OwnedMap<Node, bool>>,
}
impl<'s, 'm, 'd> ReferenceInput<'s, 'm, 'd> {
    /// Selects the actual unsigned owner and the exact registered token value.
    /// Current EN rules require both references Attributes, and additionally
    /// signature timestamps for .25. No genTime/order chronology is inferred.
    pub fn new(
        prepared: &'s Preparation<'m, 'd>,
        ordinal: usize,
        operation: &'s Reader<'d>,
    ) -> Result<Self, SelectionError> {
        prepared
            .document()
            .message()
            .require_session(operation, FIELD)
            .map_err(Error::Cms)?;
        let work = operation.execution();
        let refusal = |cause| {
            SelectionError::Processing(Error::resource(
                cause,
                FIELD,
                prepared.signer().span().start,
            ))
        };
        work.charge_work(1).map_err(refusal)?;
        let target = prepared
            .timestamps()
            .get(ordinal)
            .ok_or(SelectionError::WrongOccurrence)?;
        let kind = target
            .preservation_kind()
            .ok_or(SelectionError::WrongOccurrence)?;
        if !kind.is_reference_timestamp() || target.purpose() != Purpose::ValidationData {
            return Err(SelectionError::WrongOccurrence);
        }
        let value = target.value().ok_or(SelectionError::WrongOccurrence)?;
        let view = prepared.signer_encoding(target.owner(), operation)?;
        let mut placed = false;
        for index in 0..view.attributes() {
            work.charge_work(1).map_err(refusal)?;
            let attribute = view
                .attribute(index)
                .ok_or(SelectionError::WrongOccurrence)?;
            if Node::of(attribute.span) == target.property() {
                if attribute.single != Some(value.span()) {
                    return Err(SelectionError::Cardinality {
                        property: target.property(),
                    });
                }
                placed = true;
                break;
            }
        }
        if !placed {
            return Err(SelectionError::WrongOccurrence);
        }
        let plan = Plan::read(view, kind, target.property(), &work)?;
        let mut parts = work.vector();
        let mut covered = work.map();
        if kind == Kind::SignatureReferences {
            for piece in prepared.signature_of(target.owner(), operation)? {
                parts.try_push(piece.as_bytes()).map_err(refusal)?;
            }
        }
        plan.emit(&work, &mut parts, &mut covered)?;
        Ok(Self {
            prepared,
            operation,
            ordinal,
            parts: parts.into_owned(),
            covered: Some(covered.into_owned()),
        })
    }
}

// Discovery/validation owns only scalar metadata. No descriptor allocation
// begins until every mandatory component and cardinality is known. Retaining
// the two unique references also avoids three full catalogue scans on emission.
struct Plan<'v, 'd> {
    view: SignerView<'v, 'd>,
    signatures: bool,
    certificate: AttributeEncoding<'d>,
    revocation: AttributeEncoding<'d>,
    at: Node,
}
impl<'v, 'd> Plan<'v, 'd> {
    fn read(
        view: SignerView<'v, 'd>,
        kind: Kind,
        at: Node,
        work: &impl Work,
    ) -> Result<Self, SelectionError> {
        let mut certificate = None;
        let mut revocation = None;
        let signatures = kind == Kind::SignatureReferences;
        let mut signature_found = false;
        for index in 0..view.attributes() {
            work.charge_work(12)
                .map_err(|cause| Error::resource(cause, FIELD, at.span().start))?;
            let attribute = view
                .attribute(index)
                .ok_or(SelectionError::WrongOccurrence)?;
            let oid = attribute.kind.as_bytes();
            if oid.len() != 11 {
                continue;
            }
            if oid[..10] != [42, 134, 72, 134, 247, 13, 1, 9, 16, 2] {
                continue;
            }
            match oid[10] {
                14 if signatures => {
                    value(attribute)?;
                    signature_found = true;
                }
                21 => remember(&mut certificate, attribute)?,
                22 => remember(&mut revocation, attribute)?,
                _ => {}
            }
        }
        if signatures && !signature_found {
            return Err(SelectionError::Missing(Component::SignatureTimestamp));
        }
        Ok(Self {
            view,
            signatures,
            at,
            certificate: certificate
                .ok_or(SelectionError::Missing(Component::CertificateReferences))?,
            revocation: revocation
                .ok_or(SelectionError::Missing(Component::RevocationReferences))?,
        })
    }
    fn emit<W: Work>(
        &self,
        work: &W,
        parts: &mut OwnedVec<&'d [u8], W>,
        covered: &mut OwnedMap<Node, bool, W>,
    ) -> Result<(), SelectionError> {
        if self.signatures {
            // EN319122-1 table1 note6 permits several signature timestamps.
            // Source order (not genTime sorting) also matches DSS X1:
            // https://github.com/esig/dss/blob/9f3af8f2ca672b8948e0a3ee8687e53adf9f5c33/dss-cades/src/main/java/eu/europa/esig/dss/cades/validation/timestamp/CAdESTimestampMessageDigestBuilder.java
            for index in 0..self.view.attributes() {
                work.charge_work(12)
                    .map_err(|cause| Error::resource(cause, FIELD, self.at.span().start))?;
                let attribute = self
                    .view
                    .attribute(index)
                    .ok_or(SelectionError::WrongOccurrence)?;
                if attribute.kind == Component::SignatureTimestamp.oid() {
                    include(attribute, parts, covered)?;
                }
            }
        }
        include(self.certificate, parts, covered)?;
        include(self.revocation, parts, covered)
    }
}
fn value(attribute: AttributeEncoding<'_>) -> Result<structured_asn1::Span, SelectionError> {
    attribute.single.ok_or(SelectionError::Cardinality {
        property: Node::of(attribute.span),
    })
}
fn remember<'d>(
    slot: &mut Option<AttributeEncoding<'d>>,
    attribute: AttributeEncoding<'d>,
) -> Result<(), SelectionError> {
    if slot.is_some() {
        return Err(SelectionError::Duplicate {
            property: Node::of(attribute.span),
        });
    }
    value(attribute)?;
    *slot = Some(attribute);
    Ok(())
}
fn include<'d, W: Work>(
    attribute: AttributeEncoding<'d>,
    parts: &mut OwnedVec<&'d [u8], W>,
    covered: &mut OwnedMap<Node, bool, W>,
) -> Result<(), SelectionError> {
    let value = value(attribute)?;
    let refusal = |cause| Error::resource(cause, FIELD, attribute.span.start);
    parts.try_push(attribute.contents).map_err(refusal)?;
    // A.1.5.1/2 imprint attrType/attrValues TLVs, not the outer SEQUENCE.
    covered
        .try_insert(Node::of(attribute.span), false)
        .map_err(refusal)?;
    covered.try_insert(Node::of(value), true).map_err(refusal)?;
    Ok(())
}

impl<P, PE> ComputedInput<P, PE> for ReferenceInput<'_, '_, '_> {
    type Error = Infallible;
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        let mut state = context.start()?;
        for bytes in &self.parts {
            // Source and current-operation admission occurs before EVERY
            // descriptor/payload, including an empty signature fragment.
            state.write_from(bytes, self.operation)?;
        }
        let digest = state.finish()?;
        Ok(context.compare(&digest)?)
    }
}

/// Complete TSA facts plus exact reference-byte selection. This does not
/// assert that referenced artifacts match, are authenticated or are complete.
pub struct ReferenceChecked<'model, 'document, 'path> {
    timestamp: Checked<'model, 'document, 'path>,
    coverage: Coverage<Node, DocumentId<'model, 'document>, (), Memory, Cades>,
}
impl<'m, 'd> ReferenceChecked<'m, 'd, '_> {
    /// Original common CMS/ESS/key/path/time facts and optional sealed actor.
    pub fn timestamp(&self) -> &Checked<'m, 'd, '_> {
        &self.timestamp
    }
    /// Exact value coverage, usable only with this successful token actor.
    pub fn coverage(&self) -> &Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades> {
        &self.coverage
    }
}

impl<'m, 'd> Context<'_, 'm, 'd> {
    /// Runs the existing complete TSA pipeline with the sealed .25/.26 input.
    /// This is `ValidationData` purpose, never Archive or Signature purpose;
    /// successful legacy math cannot waive modern baseline conformance.
    #[expect(
        clippy::result_large_err,
        reason = "original profile causes remain unboxed"
    )]
    pub fn check_references<'a, 'p, P, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        input: &mut ReferenceInput<'_, 'm, 'd>,
        recognizes: impl FnMut(
            &tsp::TokenExtension<'_>,
            &structured_asn1::memory::Execution<'_>,
        ) -> Result<bool, RE>,
    ) -> Result<ReferenceChecked<'m, 'd, 'p>, CheckError<Infallible, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if self.ordinal != input.ordinal
            || !core::ptr::eq(self.prepared, input.prepared)
            || input.covered.is_none()
        {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        }
        let value = self
            .entry
            .value()
            .ok_or(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }))?;
        let timestamp = self.check_computed_profile(
            provider,
            path,
            certificate_parent,
            time,
            input,
            (
                recognizes,
                |_| Ok::<(), tsp::ProfileFailure<Infallible>>(()),
            ),
        )?;
        let coverage = Coverage::for_token(
            ISSUER,
            self.prepared.document().snapshot(),
            self.entry.owner(),
            self.entry.property(),
            Node::of(value.span()),
            Purpose::ValidationData,
            input
                .covered
                .take()
                .ok_or(CheckError::Selection(Error::Foreign {
                    at: self.entry.property().span().start,
                }))?,
        );
        Ok(ReferenceChecked {
            timestamp,
            coverage,
        })
    }
}
