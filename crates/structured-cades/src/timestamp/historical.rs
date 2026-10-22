//! Historical archive inputs, distinct from `ATSv3` and modern baseline status.
//!
//! RFC3126 §4.4.1, TS101733 V1.5.1 §6.4.1, and RFC5126 §6.4.1 select
//! DIFFERENT octets. The OID shared by the first two does not select an
//! edition. TS101733 V2.2.1 Annex K note 3 requires handling both unsigned
//! attribute framing interpretations for archiveTimestampV2.
//! <https://www.rfc-editor.org/rfc/rfc3126#section-4.4.1>
//! <https://www.rfc-editor.org/rfc/rfc5126#section-6.4.1>
//! <https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf>

use super::{ArchiveChecked, Checked};
use crate::{
    Cades, Error, ISSUER,
    prepare::{Preparation, encoding::SignerView},
    preservation::Kind,
    source::{DocumentId, Node},
};
use core::cell::Cell;
use structured_asn1::{
    Oid, Reader,
    length::DerLength,
    memory::{Memory, OwnedMap, OwnedVec, Work},
};
use structured_cms::{
    Octets,
    stream::Source,
    timestamp::{
        self as tsp, ComputedInput, ImprintAgreement, ImprintContext, ImprintProof, InputFailure,
    },
};
use structured_ltv::{
    material::Coverage,
    source::{Scope, Source as _},
    timestamp::{Purpose, Verified},
};
use structured_pkix::algorithm::digest::AsnDigest;

const FIELD: &str = "cades.historical";

mod selection;
mod snapshot;

/// Caller-established historical edition. Content never chooses a permissive
/// edition; both `ArchiveV1` editions deliberately have the same attribute OID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    /// Logical content, signed-attribute contents, signature contents and the
    /// listed unsigned attribute contents, in RFC3126 §4.4.1 order.
    Rfc3126,
    /// Whole `EncapsulatedContentInfo`, material fields, original signer fields
    /// and unsigned attributes. No detached-byte addition is specified.
    Ts101733V151,
    /// RFC5126 input, including actual detached bytes when eContent is absent,
    /// with BOTH Annex K unsigned-attribute framing alternatives.
    Rfc5126,
}
impl Edition {
    fn kind(self) -> Kind {
        match self {
            Self::Rfc3126 | Self::Ts101733V151 => Kind::ArchiveV1,
            Self::Rfc5126 => Kind::ArchiveV2,
        }
    }
}

/// Honest description of the unsigned field used by this input. A canonical
/// projection cannot recover a lost historical BER length/EOC spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Exact previous field bytes, including any indefinite wrapper/EOC.
    OriginalSnapshot,
    /// Newly generated minimal definite framing around original members.
    CanonicalDefiniteProjection,
}

/// Refusal before provider/source side effects; no implicit missing-input or
/// successful missing-preservation fallback is provided.
#[derive(Debug)]
pub enum SelectionError {
    /// Failure in the current source/operation.
    Processing(Error),
    /// Failure while consulting the explicitly supplied earlier source.
    PriorProcessing(Error),
    /// Exact common coverage/source refusal while admitting a later witness.
    Coverage(structured_ltv::material::CoverageError<Node>),
    /// Attribute OID and explicitly selected historical edition disagree.
    WrongEdition,
    /// Wrong source/owner/placement, repeated selection, or unreadable value.
    WrongOccurrence,
    /// RFC5126 requires actual detached input, but no source was supplied.
    MissingDetached,
    /// Original signed fields/material/previous unsigned attributes changed.
    PriorNotPreserved,
    /// The proposed previous input contains its own target token.
    SelfIncluded,
    /// Exclusion lacks a validated later proof covering this earlier token.
    UnprovenLater {
        /// Original excluded archive attribute, without invented coordinates.
        property: Node,
    },
    /// A separate preservation mechanism has no usable qualified processor.
    Unavailable {
        /// Original unsupported preservation property.
        property: Node,
    },
    /// Exact range/framing lengths cannot be represented.
    LengthOverflow,
}
impl From<Error> for SelectionError {
    fn from(cause: Error) -> Self {
        Self::Processing(cause)
    }
}

/// A validated later proof which actually covers the earlier token. A claimed
/// genTime or source order cannot manufacture this witness. The constructor
/// borrows the sealed common actor and its exact format-produced coverage.
pub struct Later<'view, 'model, 'document> {
    evidence: &'view Verified<Node, DocumentId<'model, 'document>, (), Cades>,
    coverage: &'view Coverage<Node, DocumentId<'model, 'document>, (), Memory, Cades>,
}
impl<'v, 'm, 'd> Later<'v, 'm, 'd> {
    /// Borrows an actual successful `ATSv3` receipt and its input coverage.
    pub fn modern(checked: &'v ArchiveChecked<'m, 'd, '_>) -> Option<Self> {
        Some(Self {
            evidence: checked.timestamp().actor()?.verified(),
            coverage: checked.coverage(),
        })
    }
    /// Borrows an actual successful historical archive receipt and coverage.
    pub fn historical(checked: &'v HistoricalChecked<'m, 'd, '_>) -> Option<Self> {
        Some(Self {
            evidence: checked.timestamp.actor()?.verified(),
            coverage: &checked.coverage,
        })
    }
    fn permits(
        &self,
        prepared: &Preparation<'m, 'd>,
        later: &crate::prepare::Timestamp<'d>,
        earlier: &crate::prepare::Timestamp<'d>,
        operation: &Reader<'d>,
    ) -> Result<bool, SelectionError> {
        operation
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let Some(value) = later.value() else {
            return Ok(false);
        };
        if self.evidence.token().node != Node::of(value.span()) {
            return Ok(false);
        }
        let source = prepared.document();
        let work = operation.execution();
        let query = Scope::new(source, source.snapshot(), &work);
        let node = earlier
            .value()
            .map_or(earlier.property(), |value| Node::of(value.span()));
        let selected = self
            .coverage
            .covers(self.evidence, node, &query)
            .map_err(SelectionError::Coverage)?;
        if selected {
            return Ok(true);
        }
        self.coverage
            .covers(self.evidence, earlier.property(), &query)
            .map_err(SelectionError::Coverage)
    }
}

/// Exact earlier source context, retained by borrowing the actual preparation
/// and producing reader. Capturing performs no reparse, re-encoding or payload
/// copy. Binding this to a later message is checked before starting a digest.
pub struct OriginalSnapshot<'view, 'model, 'document> {
    prepared: &'view Preparation<'model, 'document>,
    owner: Node,
    reader: &'view Reader<'document>,
    signer: SignerView<'view, 'document>,
}
impl<'v, 'm, 'd> OriginalSnapshot<'v, 'm, 'd> {
    /// Selects an actual root/counter in its own original parse session.
    pub fn capture(
        prepared: &'v Preparation<'m, 'd>,
        owner: Node,
        reader: &'v Reader<'d>,
    ) -> Result<Self, SelectionError> {
        let signer = prepared.signer_encoding(owner, reader)?;
        Ok(Self {
            prepared,
            owner,
            reader,
            signer,
        })
    }
}

#[derive(Clone, Copy)]
struct Header {
    bytes: [u8; 10],
    length: u8,
}
impl Header {
    fn new(tag: u8, length: u64) -> Self {
        let length = DerLength::new(length);
        let mut bytes = [0; 10];
        bytes[0] = tag;
        bytes[1..=length.as_bytes().len()].copy_from_slice(length.as_bytes());
        Self {
            bytes,
            length: 1 + u8::try_from(length.as_bytes().len())
                .expect("DER length uses at most nine octets"),
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}
enum Part<'a> {
    Current(&'a [u8]),
    Prior(&'a [u8]),
    Framing(Header),
}
impl Part<'_> {
    fn length(&self) -> usize {
        match self {
            Self::Current(bytes) | Self::Prior(bytes) => bytes.len(),
            Self::Framing(header) => header.bytes().len(),
        }
    }
}
enum Payload<'s, 'd, S> {
    Absent,
    Carried(&'s Octets<'d>),
    Detached(&'s mut S),
}

struct Carried<'s, 'd, E> {
    source: &'s Octets<'d>,
    error: core::marker::PhantomData<E>,
}
impl<E> Source for Carried<'_, '_, E> {
    type Error = StreamError<E>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl structured_cms::stream::Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        self.source
            .stream(receiver, work)
            .map_err(StreamError::Carried)
    }
}
struct Lift<'a, S>(&'a mut S);
impl<S: Source> Source for Lift<'_, S> {
    type Error = StreamError<S::Error>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl structured_cms::stream::Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        self.0.stream(receiver, work).map_err(StreamError::Source)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct ArchiveValue<'a> {
    generation: u8,
    bytes: &'a [u8],
}
impl structured_asn1::memory::HashWork for ArchiveValue<'_> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        (self.bytes.len() as u64)
            .checked_add(2)
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
    }
}

/// Prepared range recipe. Only descriptors/framing are owned; document bytes
/// remain original borrowed ranges. Detached acquisition happens once, after
/// all variant states have been admitted, with no complete-document buffer.
pub struct HistoricalInput<'input, 'model, 'document, S> {
    prepared: &'input Preparation<'model, 'document>,
    operation: &'input Reader<'document>,
    prior: Option<&'input Reader<'input>>,
    ordinal: usize,
    edition: Edition,
    framing: Framing,
    parts: OwnedVec<Part<'input>>,
    payload_at: usize,
    unsigned_at: usize,
    unsigned_header: Option<Header>,
    original_unsigned: Option<&'input [u8]>,
    payload: Payload<'input, 'document, S>,
    covered: Option<OwnedMap<Node, bool>>,
    matched: Cell<Option<Variant>>,
}

/// Actual matching interpretation, never guessed from the token's date/OID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// RFC3126's prescribed sequence of logical field/attribute contents.
    ListedContents,
    /// Complete original/projected unsigned field, including its framing.
    UnsignedField,
    /// Unsigned-field contents with its outer wrapper/EOC excluded.
    UnsignedContents,
}

/// Acquisition/format refusal during a computed imprint. Processing retains
/// its honest original cause; it is not a semantic digest disagreement.
#[derive(Debug)]
pub enum StreamError<E> {
    /// Opaque failure acquiring the actual detached bytes.
    Source(E),
    /// Original carried segment traversal or retained receiver refusal.
    Carried(structured_cms::octets::SourceError),
    /// Original range/metadata processing failure.
    Processing(Error),
}

impl<'s, 'm, 'd, S> HistoricalInput<'s, 'm, 'd, S> {
    /// Uses a genuine earlier unsigned field, including its original BER
    /// wrapper and EOC. Signed fields, global material fields and the complete
    /// previous attribute multiset are bound to this current owner FIRST.
    /// Neither a guessed date nor a synthetic previous encoding substitutes
    /// for the supplied source. All older archive values must still be present.
    pub fn from_snapshot<'old_model, 'old_document: 's>(
        prepared: &'s Preparation<'m, 'd>,
        ordinal: usize,
        edition: Edition,
        snapshot: &'s OriginalSnapshot<'_, 'old_model, 'old_document>,
        later: &[Later<'_, 'm, 'd>],
        operation: &'s Reader<'d>,
        detached: Option<&'s mut S>,
    ) -> Result<Self, SelectionError> {
        prepared
            .document()
            .message()
            .require_session(operation, FIELD)
            .map_err(Error::Cms)?;
        snapshot
            .prepared
            .document()
            .message()
            .require_session(snapshot.reader, FIELD)
            .map_err(|cause| SelectionError::PriorProcessing(Error::Cms(cause)))?;
        let target = prepared
            .timestamps()
            .get(ordinal)
            .ok_or(SelectionError::WrongOccurrence)?;
        let view = prepared.signer_encoding(target.owner(), operation)?;
        snapshot.boundaries(prepared, view, operation)?;
        snapshot.parent(prepared, target.owner(), operation)?;
        let mut attributes = snapshot.attributes(view, operation)?;
        let previous = snapshot.previous(prepared, target.owner(), ordinal, operation)?;
        Self::project(
            prepared, ordinal, edition, &previous, later, operation, detached,
        )?
        .restore(snapshot, view, &mut attributes)
    }
    /// Explicit final-message projection. `previous` contains exact prepared
    /// archive occurrence ordinals, not claimed times. Every excluded later
    /// archive must supply a validated coverage witness over this target.
    /// This spells NEW definite headers and never claims to recover lost BER.
    pub fn project(
        prepared: &'s Preparation<'m, 'd>,
        ordinal: usize,
        edition: Edition,
        previous: &[usize],
        later: &[Later<'_, 'm, 'd>],
        operation: &'s Reader<'d>,
        detached: Option<&'s mut S>,
    ) -> Result<Self, SelectionError> {
        prepared
            .document()
            .message()
            .require_session(operation, FIELD)
            .map_err(Error::Cms)?;
        operation
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let target = prepared
            .timestamps()
            .get(ordinal)
            .ok_or(SelectionError::WrongOccurrence)?;
        if target.preservation_kind() != Some(edition.kind()) {
            return Err(SelectionError::WrongEdition);
        }
        if target.value().is_none() {
            return Err(SelectionError::WrongOccurrence);
        }
        let view = prepared.signer_encoding(target.owner(), operation)?;
        let work = operation.execution();
        let resource = |cause| {
            SelectionError::Processing(Error::resource(
                cause,
                FIELD,
                target.property().span().start,
            ))
        };
        let mut placement = false;
        for index in 0..view.attributes() {
            work.charge_work(1).map_err(resource)?;
            if Node::of(
                view.attribute(index)
                    .ok_or(SelectionError::WrongOccurrence)?
                    .span,
            ) == target.property()
            {
                placement = true;
                break;
            }
        }
        if !placement {
            return Err(SelectionError::WrongOccurrence);
        }
        let chosen = selection::choose(prepared, ordinal, edition, previous, later, operation)?;
        let content = prepared.document().message().content().content();
        let payload = match (edition, content, detached) {
            (Edition::Rfc3126, Some(source), _) => Payload::Carried(source),
            (Edition::Rfc5126, None, Some(source)) => Payload::Detached(source),
            (Edition::Rfc5126, None, None) => return Err(SelectionError::MissingDetached),
            _ => Payload::Absent,
        };
        let mut parts = work.vector();
        let mut covered = work.map();
        let payload_at = selection::Output::new(&mut parts, &mut covered, &work, target.property())
            .prefix(prepared, view, target.owner(), edition, operation)?;
        let unsigned_at = parts.len();
        {
            let mut output =
                selection::Output::new(&mut parts, &mut covered, &work, target.property());
            output.unsigned(prepared, view, edition, &chosen)?;
            output.context(prepared, view, target.owner(), edition)?;
        }
        let mut unsigned_length = 0u64;
        for part in &parts[unsigned_at..] {
            work.charge_work(1).map_err(resource)?;
            unsigned_length = unsigned_length
                .checked_add(part.length() as u64)
                .ok_or(SelectionError::LengthOverflow)?;
        }
        Ok(Self {
            prepared,
            operation,
            prior: None,
            ordinal,
            edition,
            framing: Framing::CanonicalDefiniteProjection,
            parts: parts.into_owned(),
            payload_at,
            unsigned_at,
            unsigned_header: (unsigned_length != 0).then(|| Header::new(0xa1, unsigned_length)),
            original_unsigned: None,
            payload,
            covered: Some(covered.into_owned()),
            matched: Cell::new(None),
        })
    }
    /// Whether this input retained original or generated unsigned framing.
    pub fn framing(&self) -> Framing {
        self.framing
    }
    /// Last fully completed matching variant, or no matching computation.
    pub fn matched_variant(&self) -> Option<Variant> {
        self.matched.get()
    }
}

fn archive_kind(kind: Oid<'_>) -> Option<Kind> {
    match Kind::from_oid(kind) {
        Some(value) if value.is_archive() => Some(value),
        _ => None,
    }
}
fn category(kind: Oid<'_>) -> Option<usize> {
    for (index, last) in [14, 21, 22, 23, 24, 25, 26, 27].into_iter().enumerate() {
        if kind == Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, last]) {
            return Some(index);
        }
    }
    None
}

fn covered_container<W: Work>(
    view: SignerView<'_, '_>,
    node: Node,
    selected: &OwnedMap<Node, bool, W>,
    work: &impl Work,
) -> Result<bool, structured_asn1::memory::MemoryError> {
    // Parsed top-level attributes are disjoint and in original physical order.
    // Binary search avoids a counter-by-attribute cross-product. Selection is
    // consulted ONLY after whole-range containment, never by a prefix overlap.
    let span = node.span();
    let mut from = 0;
    let mut to = view.attributes();
    while from < to {
        work.charge_work(1)?;
        let middle = from + (to - from) / 2;
        let attribute = view.attribute(middle).expect("bounded original catalogue");
        if attribute.span.start <= span.start {
            from = middle + 1;
        } else {
            to = middle;
        }
    }
    if from == 0 {
        return Ok(false);
    }
    work.charge_work(1)?;
    let attribute = view
        .attribute(from - 1)
        .expect("preceding original attribute");
    if span.end() > attribute.span.end() {
        return Ok(false);
    }
    Ok(selected.get(&Node::of(attribute.span), work)? == Some(&true))
}

impl<P, PE, S: Source> ComputedInput<P, PE> for HistoricalInput<'_, '_, '_, S> {
    type Error = StreamError<S::Error>;
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        self.matched.set(None);
        let mut first = context.start()?;
        let mut second = if self.edition == Edition::Rfc5126 {
            Some(context.start()?)
        } else {
            None
        };
        for part in &self.parts[..self.payload_at] {
            emit(part, &mut first, self.operation, self.prior)?;
            if let Some(second) = &mut second {
                emit(part, second, self.operation, self.prior)?;
            }
        }
        match &mut self.payload {
            Payload::Absent => {}
            Payload::Carried(source) => {
                let mut source = Carried::<S::Error> {
                    source,
                    error: core::marker::PhantomData,
                };
                if let Some(second) = &mut second {
                    context.stream_from(&mut source, self.operation, &mut [&mut first, second])?;
                } else {
                    context.stream_from(&mut source, self.operation, &mut [&mut first])?;
                }
            }
            Payload::Detached(source) => {
                if let Some(second) = &mut second {
                    context.stream_from(
                        &mut Lift(*source),
                        self.operation,
                        &mut [&mut first, second],
                    )?;
                } else {
                    context.stream_from(&mut Lift(*source), self.operation, &mut [&mut first])?;
                }
            }
        }
        for part in &self.parts[self.payload_at..self.unsigned_at] {
            emit(part, &mut first, self.operation, self.prior)?;
            if let Some(second) = &mut second {
                emit(part, second, self.operation, self.prior)?;
            }
        }
        if self.edition != Edition::Rfc3126 {
            if let Some(bytes) = self.original_unsigned {
                first.write_from(
                    bytes,
                    self.prior
                        .expect("original unsigned belongs to captured source"),
                )?;
            } else if let Some(header) = &self.unsigned_header {
                first.write(header.bytes())?;
            }
        }
        for part in &self.parts[self.unsigned_at..] {
            if self.original_unsigned.is_some() && self.edition != Edition::Rfc3126 {
                if let Some(second) = &mut second {
                    emit(part, second, self.operation, self.prior)?;
                }
            } else {
                emit(part, &mut first, self.operation, self.prior)?;
                if let Some(second) = &mut second {
                    emit(part, second, self.operation, self.prior)?;
                }
            }
        }
        let first = first.finish()?;
        let second = match second {
            Some(state) => Some(state.finish()?),
            None => None,
        };
        let a = context.compare(&first)?;
        let b = match &second {
            Some(digest) => Some(context.compare(digest)?),
            None => None,
        };
        if a.agreement() == ImprintAgreement::Matches {
            self.matched.set(Some(if self.edition == Edition::Rfc3126 {
                Variant::ListedContents
            } else {
                Variant::UnsignedField
            }));
            Ok(a)
        } else if let Some(b) = b {
            if b.agreement() == ImprintAgreement::Matches {
                self.matched.set(Some(Variant::UnsignedContents));
            }
            Ok(b)
        } else {
            Ok(a)
        }
    }
}
fn emit<'c, 'r, 'd, P: AsnDigest<'d>, E>(
    part: &Part<'_>,
    state: &mut tsp::ImprintState<'c, 'r, 'd, P, E>,
    operation: &Reader<'_>,
    prior: Option<&Reader<'_>>,
) -> Result<(), structured_cms::stream::Refused> {
    match part {
        Part::Current(bytes) => state.write_from(bytes, operation),
        Part::Prior(bytes) => {
            state.write_from(bytes, prior.expect("prior descriptor has its source"))
        }
        Part::Framing(header) => state.write(header.bytes()),
    }
}

/// Complete common TSA result plus exact original-item coverage. This remains
/// separate from modern baseline-format conformance and application trust.
pub struct HistoricalChecked<'model, 'document, 'path> {
    timestamp: Checked<'model, 'document, 'path>,
    coverage: Coverage<Node, DocumentId<'model, 'document>, (), Memory, Cades>,
    framing: Framing,
    variant: Option<Variant>,
}
impl<'m, 'd, 'p> HistoricalChecked<'m, 'd, 'p> {
    /// Completed common signature/ESS/authority/time facts, including negatives.
    pub fn timestamp(&self) -> &Checked<'m, 'd, 'p> {
        &self.timestamp
    }
    /// Exact mathematical selection; use its own successful actor to bind it.
    pub fn coverage(&self) -> &Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades> {
        &self.coverage
    }
    /// Original versus explicitly projected unsigned-field framing.
    pub fn framing(&self) -> Framing {
        self.framing
    }
    /// Completed matching variant; absent on semantic disagreement.
    pub fn matched_variant(&self) -> Option<Variant> {
        self.variant
    }
    /// Derives every actually covered earlier TSA/counter from this archive's
    /// own successful actor. Its own TSA is excluded by exact token identity,
    /// not by an attribute identifier which might contain other older values.
    pub fn requirements(
        &self,
        prepared: &Preparation<'m, 'd>,
        operation: &Reader<'d>,
    ) -> Result<
        structured_ltv::timestamp::TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>,
        super::ArchiveScopeError,
    > {
        super::requirements::derive(&self.timestamp, &self.coverage, prepared, operation)
    }
}

impl<'m, 'd> super::Context<'_, 'm, 'd> {
    /// Performs the SAME complete common CMS/ESS/TSA/effective-key/path/time
    /// pipeline as an ordinary token, using this sealed historical recipe.
    /// Historical mathematical validity does not waive modern baseline rules.
    #[expect(
        clippy::result_large_err,
        reason = "original profile causes stay unboxed on refusal"
    )]
    pub fn check_historical<'a, 'p, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p structured_ltv::pki::CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &super::CheckTime<'_, 'd>,
        input: &mut HistoricalInput<'_, 'm, 'd, S>,
        recognizes: impl FnMut(
            &tsp::TokenExtension<'_>,
            &structured_asn1::memory::Execution<'_>,
        ) -> Result<bool, RE>,
    ) -> Result<HistoricalChecked<'m, 'd, 'p>, super::CheckError<StreamError<S::Error>, PE, RE>>
    where
        P: for<'scope> structured_cms::provider::SignatureProvider<'scope, Error = PE>,
    {
        if self.ordinal != input.ordinal
            || !core::ptr::eq(self.prepared, input.prepared)
            || input.covered.is_none()
        {
            return Err(super::CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        }
        let value = self
            .entry
            .value()
            .ok_or(super::CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }))?;
        let timestamp = self.check_computed_profile(
            provider,
            path,
            certificate_parent,
            time,
            input,
            (recognizes, |_| {
                Ok::<(), tsp::ProfileFailure<core::convert::Infallible>>(())
            }),
        )?;
        let coverage = Coverage::for_token(
            ISSUER,
            self.prepared.document().snapshot(),
            self.entry.owner(),
            self.entry.property(),
            Node::of(value.span()),
            Purpose::Archive,
            input
                .covered
                .take()
                .ok_or(super::CheckError::Selection(Error::Foreign {
                    at: self.entry.property().span().start,
                }))?,
        );
        Ok(HistoricalChecked {
            timestamp,
            coverage,
            framing: input.framing,
            variant: input.matched.get(),
        })
    }
}
