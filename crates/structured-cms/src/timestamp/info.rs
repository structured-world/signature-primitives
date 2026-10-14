//! `TSTInfo` schema views, original source fields and explicit recovery faults.

use super::{AccuracyReading, MessageImprint, TokenExtensions, TsaReading, record};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Integer, Oid, Reader, Span, Tag, universal};
use structured_pkix::temporal::Reading;

const FIELD: &str = "tstInfo";

/// Original integer spelling and the common decoder's minimal numeric view.
#[derive(Debug, Clone, Copy)]
pub struct IntegerField<'a> {
    element: Element<'a>,
    value: Integer<'a>,
}
impl<'a> IntegerField<'a> {
    fn read<W: Work>(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
        faults: &mut OwnedVec<Error, W>,
    ) -> Result<Self> {
        let (value, fault) = parent
            .integer_reading(element)
            .map_err(|error| Error::encoding(error, field))?
            .into_parts();
        if let Some(fault) = fault {
            record(faults, Error::encoding(fault, field))?;
        }
        Ok(Self {
            element: *element,
            value,
        })
    }
    /// Whole original INTEGER TLV; no minimal re-encoding is substituted.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }
    /// Shared minimal numeric view, still borrowing the original contents.
    #[must_use]
    pub fn value(self) -> Integer<'a> {
        self.value
    }
}

/// Required timestamp facts and optional values, independently of acceptance.
/// Original bytes are borrowed; diagnostics/catalogues own their accounted capacity.
#[derive(Debug)]
pub struct TokenInfo<'a> {
    policy: Oid<'a>,
    imprint: MessageImprint<'a>,
    serial: IntegerField<'a>,
    gen_time: Reading,
    accuracy: Option<AccuracyReading<'a>>,
    ordering: bool,
    nonce: Option<IntegerField<'a>>,
    tsa: Option<TsaReading<'a>>,
    extensions: Option<TokenExtensions<'a>>,
    faults: OwnedVec<Error>,
    span: Span,
}

impl<'a> TokenInfo<'a> {
    pub(super) fn read_carried(parent: &mut Reader<'a>) -> Result<Self> {
        let element = parent
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let info = Self::read(parent, &element)?;
        if parent.is_empty() {
            return Ok(info);
        }
        info.with_tail(parent)
    }

    fn with_tail(mut self, parent: &Reader<'_>) -> Result<Self> {
        let at = parent.offset();
        let work = parent.execution();
        // Recovery retains the uniquely bounded first TSTInfo and its source
        // map. RFC3161 §2.4.2 does not permit trailing content: this fault must
        // still prevent complete checking/evidence. It is inspection recovery,
        // not a second TSTInfo or silently consumed bytes.
        // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
        let mut faults = self.faults.with_execution(&work).map_err(|_| {
            Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                FIELD,
                at,
            ))
        })?;
        record(
            &mut faults,
            Error::schema(ErrorCode::TrailingData, FIELD, at),
        )?;
        self.faults = faults.into_owned();
        Ok(self)
    }

    /// Reads RFC3161 §2.4.2 fields under the original producing reader.
    ///
    /// A BER inspection reader retains DER/schema faults instead of repairing
    /// source bytes. This is not token acceptance: every nested fault remains
    /// visible and must be considered before successful proof extraction.
    /// INTEGER roles follow required/optional schema order; competing serial/
    /// nonce assignments refuse. Unknown bounded fields remain diagnostics.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let execution = parent.execution();
        let mut faults = execution.vector();
        distinguished(parent, element, &mut faults)?;
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let mut fields = Fields::default();
        // Only first successful schema fields require duplicate records: ten
        // fixed slots, never an unaccounted input-driven Vec of encodings.
        let mut seen: [Option<Element<'a>>; 10] = [None; 10];
        let mut last = None;
        while let Some(element) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))?
        {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, FIELD, element.span().start))?;
            let Some(slot) = fields.slot(&inside, &element)? else {
                if carries(element.tag()) {
                    if !same_duplicate(&inside, &fields, &seen, &element)? {
                        return Err(Error::schema(
                            ErrorCode::DuplicateField,
                            FIELD,
                            element.span().start,
                        ));
                    }
                    record(
                        &mut faults,
                        Error::schema(ErrorCode::DuplicateField, FIELD, element.span().start),
                    )?;
                } else {
                    record(
                        &mut faults,
                        Error::schema(ErrorCode::UnknownField, FIELD, element.span().start),
                    )?;
                }
                continue;
            };
            if (slot == Slot::Serial && fields.gen_time.is_some())
                || (slot == Slot::Nonce && (fields.serial_displaced || fields.gen_time.is_none()))
            {
                return Err(Error::schema(
                    ErrorCode::DuplicateField,
                    FIELD,
                    element.span().start,
                ));
            }
            if last.is_some_and(|last| slot < last) {
                record(
                    &mut faults,
                    Error::schema(ErrorCode::FieldOrder, FIELD, element.span().start),
                )?;
            }
            last = Some(last.map_or(slot, |last| last.max(slot)));
            fields.read(slot, &inside, &element, &mut faults)?;
            seen[slot as usize] = Some(element);
        }
        fields.finish(element.span(), faults.into_owned())
    }

    /// Original policy OID; acceptable policy selection belongs to the caller.
    #[must_use]
    pub fn policy(&self) -> Oid<'a> {
        self.policy
    }
    /// Original imprint fields, including explicit malformed algorithm syntax.
    #[must_use]
    pub fn imprint(&self) -> &MessageImprint<'a> {
        &self.imprint
    }
    /// Original serial; RFC3161 imposes no positivity or 160-bit maximum.
    #[must_use]
    pub fn serial(&self) -> IntegerField<'a> {
        self.serial
    }
    /// Shared UTC label/precision reading; supplied UTC facts remain independent.
    #[must_use]
    pub fn gen_time(&self) -> Reading {
        self.gen_time
    }
    /// Absent complete Accuracy differs from a present empty/invalid reading.
    #[must_use]
    pub fn accuracy(&self) -> Option<&AccuracyReading<'a>> {
        self.accuracy.as_ref()
    }
    /// Original ordering BOOLEAN, with FALSE only for its normative absent default.
    #[must_use]
    pub fn ordering(&self) -> bool {
        self.ordering
    }
    /// Original optional nonce, without a fixed width or sign policy.
    #[must_use]
    pub fn nonce(&self) -> Option<IntegerField<'a>> {
        self.nonce
    }
    /// Original explicit wrapper and common `GeneralName` reading or malformation.
    #[must_use]
    pub fn tsa(&self) -> Option<&TsaReading<'a>> {
        self.tsa.as_ref()
    }
    /// Original optional extension catalogue and its own recovery diagnostics.
    #[must_use]
    pub fn extensions(&self) -> Option<&TokenExtensions<'a>> {
        self.extensions.as_ref()
    }
    /// Root schema/DER faults; nested imprint/accuracy/extension faults stay there.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    /// Any retained root or nested conformance fault, without scanning collections.
    #[must_use]
    pub fn has_faults(&self) -> bool {
        !self.faults.is_empty()
            || !self.imprint.faults().is_empty()
            || self
                .accuracy
                .as_ref()
                .is_some_and(|reading| !reading.faults().is_empty())
            || self
                .extensions
                .as_ref()
                .is_some_and(|reading| !reading.faults().is_empty())
    }
    /// Whole original `TSTInfo` range, never reconstructed from scalar fields.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

fn same_duplicate(
    parent: &Reader<'_>,
    fields: &Fields<'_>,
    seen: &[Option<Element<'_>>; 10],
    element: &Element<'_>,
) -> Result<bool> {
    let execution = parent.execution();
    let refusal = |reason| Error::resource(reason, FIELD, element.span().start);
    if element.tag() == Tag::primitive(universal::OID)
        && let Some(policy) = fields.policy
    {
        // RFC3161 §2.4.2 requires one DER policy; duplicate recovery is our
        // inspection contract, not conformance. X.690 §8.1.3 length spelling
        // does not change the decoded OID. Shared decoding validates both.
        let other = parent
            .oid(element)
            .map_err(|error| Error::encoding(error, "tstInfo.policy"))?;
        execution.charge_work(1).map_err(refusal)?;
        if policy.as_bytes().len() != other.as_bytes().len() {
            return Ok(false);
        }
        execution
            .charge_work(policy.as_bytes().len() as u64)
            .map_err(refusal)?;
        return Ok(policy.as_bytes() == other.as_bytes());
    }
    // RFC3161 §2.4.2 orders the INTEGER roles. Here all three roles are
    // populated, so another INTEGER can only repeat nonce. Standard-silent
    // recovery must not rescue a conflicting nonce by matching version/serial.
    // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
    let applicable = if element.tag() == Tag::primitive(universal::INTEGER) {
        &seen[Slot::Nonce as usize..=Slot::Nonce as usize]
    } else {
        &seen[..]
    };
    for prior in applicable.iter().flatten() {
        execution.charge_work(1).map_err(refusal)?;
        if prior.as_bytes().len() != element.as_bytes().len() {
            continue;
        }
        execution
            .charge_work(element.as_bytes().len() as u64)
            .map_err(refusal)?;
        if prior.as_bytes() == element.as_bytes() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
enum Slot {
    Version,
    Policy,
    Imprint,
    Serial,
    GenTime,
    Accuracy,
    Ordering,
    Nonce,
    Tsa,
    Extensions,
}

#[derive(Default)]
struct Fields<'a> {
    version: bool,
    policy: Option<Oid<'a>>,
    imprint: Option<MessageImprint<'a>>,
    serial: Option<IntegerField<'a>>,
    serial_displaced: bool,
    gen_time: Option<Reading>,
    accuracy: Option<AccuracyReading<'a>>,
    ordering: Option<bool>,
    nonce: Option<IntegerField<'a>>,
    tsa: Option<TsaReading<'a>>,
    extensions: Option<TokenExtensions<'a>>,
}

impl<'a> Fields<'a> {
    fn slot(&self, parent: &Reader<'a>, element: &Element<'a>) -> Result<Option<Slot>> {
        let tag = element.tag();
        let slot = if tag == Tag::primitive(universal::INTEGER) {
            if !self.version {
                // RFC3161 §2.4.2 orders version before policy and imprint.
                // Recovery is not specified: once those anchors occurred,
                // this INTEGER also admits serial with missing version. Never
                // assign one of the competing readings merely by first slot.
                // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
                if self.policy.is_some() || self.imprint.is_some() || self.gen_time.is_some() {
                    return Err(Error::schema(
                        ErrorCode::DuplicateField,
                        FIELD,
                        element.span().start,
                    ));
                }
                Slot::Version
            } else if self.serial.is_none() {
                Slot::Serial
            } else if self.nonce.is_none() {
                Slot::Nonce
            } else {
                return Ok(None);
            }
        } else if tag == Tag::primitive(universal::OID) {
            Slot::Policy
        } else if tag == Tag::constructed(universal::SEQUENCE) {
            let mut probe = parent
                .enter(element)
                .map_err(|error| Error::encoding(error, FIELD))?;
            let first = probe
                .next_element()
                .map_err(|error| Error::encoding(error, FIELD))?;
            // A bare OID + hash has one malformed imprint reading; it must not
            // occupy Accuracy and erase required serial/genTime at finish.
            if first.is_some_and(|first| {
                first.tag() == Tag::constructed(universal::SEQUENCE)
                    || first.tag() == Tag::primitive(universal::OID)
            }) {
                Slot::Imprint
            } else {
                Slot::Accuracy
            }
        } else if tag == Tag::primitive(universal::GENERALIZED_TIME)
            || tag == Tag::constructed(universal::GENERALIZED_TIME)
        {
            Slot::GenTime
        } else if tag == Tag::primitive(universal::BOOLEAN) {
            Slot::Ordering
        } else if tag == Tag::context(true, 0) {
            Slot::Tsa
        } else if tag == Tag::context(true, 1) {
            Slot::Extensions
        } else {
            return Ok(None);
        };
        let found = match slot {
            Slot::Version => self.version,
            Slot::Policy => self.policy.is_some(),
            Slot::Imprint => self.imprint.is_some(),
            Slot::Serial => self.serial.is_some(),
            Slot::GenTime => self.gen_time.is_some(),
            Slot::Accuracy => self.accuracy.is_some(),
            Slot::Ordering => self.ordering.is_some(),
            Slot::Nonce => self.nonce.is_some(),
            Slot::Tsa => self.tsa.is_some(),
            Slot::Extensions => self.extensions.is_some(),
        };
        Ok(if found { None } else { Some(slot) })
    }

    fn read<W: Work>(
        &mut self,
        slot: Slot,
        parent: &Reader<'a>,
        element: &Element<'a>,
        faults: &mut OwnedVec<Error, W>,
    ) -> Result<()> {
        match slot {
            Slot::Version => {
                let version = IntegerField::read(parent, element, "tstInfo.version", faults)?;
                if version.value.as_u64() != Some(1) {
                    return Err(Error::schema(
                        ErrorCode::UnsupportedVersion,
                        "tstInfo.version",
                        element.span().start,
                    ));
                }
                self.version = true;
            }
            Slot::Policy => {
                self.policy = Some(
                    parent
                        .oid(element)
                        .map_err(|error| Error::encoding(error, "tstInfo.policy"))?,
                );
            }
            Slot::Imprint => self.imprint = Some(MessageImprint::read(parent, element)?),
            Slot::Serial => {
                let serial = IntegerField::read(parent, element, "tstInfo.serialNumber", faults)?;
                // RFC3161 §2.4.2 places serial after messageImprint. Before
                // that anchor, value 1 also admits a repeated version with
                // serial absent. Recovery must not select a competing reading.
                // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
                if self.imprint.is_none() && serial.value.as_u64() == Some(1) {
                    return Err(Error::schema(
                        ErrorCode::DuplicateField,
                        FIELD,
                        element.span().start,
                    ));
                }
                self.serial_displaced = self.imprint.is_none() || self.gen_time.is_some();
                self.serial = Some(serial);
            }
            Slot::GenTime => {
                self.gen_time = Some(
                    structured_pkix::temporal::read_generalized(parent, element, "tstInfo.genTime")
                        .map_err(Error::pkix)?,
                );
            }
            Slot::Accuracy => self.accuracy = Some(AccuracyReading::read(parent, element)?),
            Slot::Ordering => {
                let ordering = parent
                    .boolean(element)
                    .map_err(|error| Error::encoding(error, "tstInfo.ordering"))?;
                if !ordering {
                    record(
                        faults,
                        Error::schema(
                            ErrorCode::DefaultWritten,
                            "tstInfo.ordering",
                            element.span().start,
                        ),
                    )?;
                }
                self.ordering = Some(ordering);
            }
            Slot::Nonce => {
                self.nonce = Some(IntegerField::read(
                    parent,
                    element,
                    "tstInfo.nonce",
                    faults,
                )?);
            }
            Slot::Tsa => self.tsa = Some(TsaReading::read(parent, element, faults)?),
            Slot::Extensions => self.extensions = Some(TokenExtensions::read(parent, element)?),
        }
        Ok(())
    }

    fn finish(self, span: Span, faults: OwnedVec<Error>) -> Result<TokenInfo<'a>> {
        let missing = |field| Error::schema(ErrorCode::MissingField, field, span.start);
        if !self.version {
            return Err(missing("tstInfo.version"));
        }
        Ok(TokenInfo {
            policy: self.policy.ok_or_else(|| missing("tstInfo.policy"))?,
            imprint: self
                .imprint
                .ok_or_else(|| missing("tstInfo.messageImprint"))?,
            serial: self.serial.ok_or_else(|| missing("tstInfo.serialNumber"))?,
            gen_time: self.gen_time.ok_or_else(|| missing("tstInfo.genTime"))?,
            accuracy: self.accuracy,
            ordering: self.ordering.unwrap_or(false),
            nonce: self.nonce,
            tsa: self.tsa,
            extensions: self.extensions,
            faults,
            span,
        })
    }
}

fn carries(tag: Tag) -> bool {
    tag == Tag::primitive(universal::INTEGER)
        || tag == Tag::primitive(universal::OID)
        || tag == Tag::constructed(universal::SEQUENCE)
        || tag == Tag::primitive(universal::GENERALIZED_TIME)
        || tag == Tag::constructed(universal::GENERALIZED_TIME)
        || tag == Tag::primitive(universal::BOOLEAN)
        || tag == Tag::context(true, 0)
        || tag == Tag::context(true, 1)
}

fn distinguished<W: Work>(
    parent: &Reader<'_>,
    element: &Element<'_>,
    faults: &mut OwnedVec<Error, W>,
) -> Result<()> {
    let mut strict = parent
        .reread(element, Encoding::Der)
        .map_err(|error| Error::encoding(error, FIELD))?;
    let result = strict
        .expect(element.tag())
        .map_err(|error| Error::encoding(error, FIELD))
        .and_then(|again| {
            structured_pkix::der::conforms(&strict, &again, FIELD).map_err(Error::pkix)
        });
    match result {
        Ok(()) => Ok(()),
        Err(error) => record(faults, error),
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;
    use alloc::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount, MemoryError},
    };

    fn carried_bytes() -> [u8; 42] {
        [
            0x30, 37, 2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, b'a', b'b', 2, 1, 7,
            0x18, 15, b'2', b'0', b'2', b'6', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
            b'0', b'Z', 0xff, 0xfe, 0xfd,
        ]
    }

    #[test]
    fn tail_capacity_refusal_rolls_back_without_funding_a_successful_reading() {
        // Fill capacity only after schema reading, isolating the fault admission
        // from temporary DER-walk frames and proving refusal at the tail itself.
        let bytes = carried_bytes();
        let memory = Memory::new(Arc::new(MemoryAccount::new(65_536, 1_000_000)));
        let parser = Parser::ber(memory.clone());
        let mut parent = parser.read(&bytes, 70).unwrap();
        let element = parent
            .expect(Tag::constructed(universal::SEQUENCE))
            .unwrap();
        let info = TokenInfo::read(&parent, &element).unwrap();
        assert_eq!(info.faults().len(), 0);
        let mut held = memory.vector::<u8>();
        held.try_reserve_exact(memory.limit() - memory.used())
            .unwrap();
        assert_eq!(memory.used(), memory.limit());
        let error = info.with_tail(&parent).unwrap_err();
        assert!(error.is_terminal());
        assert_eq!(error.offset(), 109);
        assert_eq!(error.field(), "tstInfo");
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::from(MemoryError::LimitExceeded))
        );
        drop(error);
        drop(held);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn retained_tail_diagnostic_keeps_charge_after_original_parser_drops() {
        // Moving the independently owned catalogue preserves its allocation and
        // source location; releasing the parser is not a storage refund.
        let bytes = carried_bytes();
        let memory = Memory::new(Arc::new(MemoryAccount::new(65_536, 1_000_000)));
        let faults = {
            let parser = Parser::ber(memory.clone());
            let mut reader = parser.read(&bytes, 70).unwrap();
            let TokenInfo { faults, .. } = TokenInfo::read_carried(&mut reader).unwrap();
            faults
        };
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].code(), ErrorCode::TrailingData);
        assert_eq!(faults[0].offset(), 109);
        assert_eq!(faults[0].field(), "tstInfo");
        assert!(memory.used() >= core::mem::size_of::<Error>());
        drop(faults);
        assert_eq!(memory.used(), 0);
    }
}
