//! Accuracy schema over original integer views and independently owned faults.

use super::{Accuracy, record};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Integer, Reader, Span, Tag, universal};

const FIELD: &str = "tstInfo.accuracy";

/// The optional component selected by the RFC3161 Accuracy schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// Optional universal INTEGER seconds component.
    Seconds,
    /// Optional primitive IMPLICIT \[0\] milliseconds component.
    Millis,
    /// Optional primitive IMPLICIT \[1\] microseconds component.
    Micros,
}

impl Component {
    const fn index(self) -> usize {
        match self {
            Self::Seconds => 0,
            Self::Millis => 1,
            Self::Micros => 2,
        }
    }
}

/// Original wire spelling and the common INTEGER decoder's minimal suffix.
#[derive(Debug, Clone, Copy)]
pub struct ComponentReading<'a> {
    element: Element<'a>,
    value: Integer<'a>,
}
impl<'a> ComponentReading<'a> {
    /// Original whole TLV, distinguishing omitted fields from explicit zero.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }
    /// Numeric borrowed view, without another padding scan or a repaired copy.
    #[must_use]
    pub fn value(self) -> Integer<'a> {
        self.value
    }
}

/// Why the original component cannot be represented by a nonnegative u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviationReason {
    /// Original two's-complement INTEGER is below zero.
    Negative,
    /// Original nonnegative INTEGER exceeds the scalar representation.
    TooWide,
}

/// The unrepresentable component remains present, with its original location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviationError {
    /// Original component that could not be represented.
    pub component: Component,
    /// Whole original component TLV range.
    pub span: Span,
    /// No fallback value was substituted for this reason.
    pub reason: DeviationReason,
}

/// Readable scalar fields and conformance faults, without token acceptance.
///
/// Fixed component storage cannot grow with attacker-controlled field count.
/// Diagnostics retain their own capacity charge; callers must consider them
/// before accepting a token/proof. Unknown or out-of-order fields and readable
/// nonminimal INTEGERs remain faults. Numerically equal duplicates retain the
/// first original reading; conflicting numeric values refuse rather than selecting
/// a value. This recovery is an inspection contract, not specified by RFC3161.
#[derive(Debug)]
pub struct AccuracyReading<'a> {
    parts: [Option<ComponentReading<'a>>; 3],
    faults: OwnedVec<Error>,
    span: Span,
}

impl<'a> AccuracyReading<'a> {
    /// Reads SEQUENCE with optional seconds and primitive IMPLICIT \[0\]/\[1\].
    ///
    /// RFC3161 §2.4.2 gives millis/micros the range 1..999 and defaults each
    /// absent component to zero. Present empty Accuracy is zero, whereas an
    /// omitted entire Accuracy provides no bound. Readable out-of-range values
    /// are retained exactly with a fault, never clamped. Resource failures abort.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let execution = parent.execution();
        let mut faults = execution.vector();
        let mut parts: [Option<ComponentReading<'a>>; 3] = [None; 3];
        let mut last = None;
        while let Some(field) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))?
        {
            let at = field.span().start;
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, FIELD, at))?;
            let component = if field.tag() == Tag::primitive(universal::INTEGER) {
                Component::Seconds
            } else if field.tag() == Tag::context(false, 0) {
                Component::Millis
            } else if field.tag() == Tag::context(false, 1) {
                Component::Micros
            } else {
                record(
                    &mut faults,
                    Error::schema(ErrorCode::UnknownField, FIELD, at),
                )?;
                continue;
            };
            let index = component.index();
            if parts[index].is_none() {
                if last.is_some_and(|last| index < last) {
                    record(&mut faults, Error::schema(ErrorCode::FieldOrder, FIELD, at))?;
                }
                last = Some(last.map_or(index, |last| last.max(index)));
            }
            let (value, fault) = inside
                .integer_reading(&field)
                .map_err(|error| Error::encoding(error, FIELD))?
                .into_parts();
            if let Some(fault) = fault {
                record(&mut faults, Error::encoding(fault, FIELD))?;
            }
            let number = value.as_u64();
            if number.is_none()
                || (component != Component::Seconds
                    && !number.is_some_and(|number| (1..=999).contains(&number)))
            {
                record(
                    &mut faults,
                    Error::schema(ErrorCode::MalformedValue, FIELD, at),
                )?;
            }
            if let Some(earlier) = parts[index] {
                // RFC3161 §2.4.2 does not specify duplicate recovery. Our
                // inspection contract retains one numeric reading and every
                // fault, including X.690 §8.3.2 redundant-sign violations.
                // integer_reading already produced minimal borrowed suffixes;
                // compare them without a bounded numeric projection/sentinel.
                // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
                if earlier.value.as_bytes().len() != value.as_bytes().len() {
                    return Err(Error::schema(ErrorCode::DuplicateField, FIELD, at));
                }
                execution
                    .charge_work(value.as_bytes().len() as u64)
                    .map_err(|reason| Error::resource(reason, FIELD, at))?;
                if earlier.value.as_bytes() != value.as_bytes() {
                    return Err(Error::schema(ErrorCode::DuplicateField, FIELD, at));
                }
                record(
                    &mut faults,
                    Error::schema(ErrorCode::DuplicateField, FIELD, at),
                )?;
                continue;
            }
            parts[index] = Some(ComponentReading {
                element: field,
                value,
            });
        }
        Ok(Self {
            parts,
            faults: faults.into_owned(),
            span: element.span(),
        })
    }

    /// Original component, absent only when no such field was written.
    #[must_use]
    pub fn component(&self, component: Component) -> Option<ComponentReading<'a>> {
        self.parts[component.index()]
    }
    /// Original complete Accuracy encoding range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Original schema/conformance faults; accessing them performs no new scan.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    /// Move diagnostic storage without cloning paths or refunding live capacity.
    #[must_use]
    pub fn into_faults(self) -> OwnedVec<Error> {
        self.faults
    }

    /// Exact nonnegative deviation, independently of conformance acceptance.
    /// Negative/wide components are typed failures, never zero or `u64::MAX`.
    pub fn deviation(&self) -> core::result::Result<Accuracy, DeviationError> {
        let mut values = [0; 3];
        for component in [Component::Seconds, Component::Millis, Component::Micros] {
            let index = component.index();
            if let Some(part) = self.parts[index] {
                values[index] = part.value.as_u64().ok_or_else(|| DeviationError {
                    component,
                    span: part.element.span(),
                    reason: if part.value.is_negative() {
                        DeviationReason::Negative
                    } else {
                        DeviationReason::TooWide
                    },
                })?;
            }
        }
        Ok(Accuracy::new(values[0], values[1], values[2]))
    }
}
