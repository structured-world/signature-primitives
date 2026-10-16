//! Claimed signing-time schema/UTC qualification without timestamp evidence.

use super::Signed;
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::Work;

/// Narrow projection AFTER the XML owner checks the complete original XSD1.0
/// dateTime. Calendar/lexical parsing and arbitrary year/fraction support remain
/// in that same owner; this is not a second parser or a POSIX time conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateTimeFact {
    /// Absent/complex/invalid original simple content is not a dateTime value.
    Malformed,
    /// This source's schema interpretation has not been completed/supported.
    Unsupported,
    /// Complete original XSD1.0 value, with its actual optional timezone.
    Valid {
        /// Signed offset in minutes; None means genuinely unstated, never UTC.
        timezone_minutes: Option<i16>,
    },
}

/// XML-owned full XSD1.0 interpretation of original dateTime simple content.
pub trait DateTimeXml: Xml {
    /// Check THIS original node under the expected immutable source. Implementors
    /// reuse their actual scalar kernel and admit ALL scans/joined/collapsed
    /// capacity before work. A resource/processing refusal is Err, never an
    /// unsupported/malformed value. Do not extract only a timezone suffix, cap
    /// precision/year silently, default a zone, or substitute RFC3339/XSD1.1.
    /// Original lexical data remain accessible through the source/node owner;
    /// second60 validity is not proof of a real UTC leap event.
    fn date_time<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
    ) -> Result<DateTimeFact, Self::Error>;
}

/// Exact components supplied by the XML owner's complete XSD1.0 dateTime kernel.
/// Digits are original and arbitrary precision. This is a parsed lexical view,
/// not a finite UTC conversion or claim that a leap second actually occurred.
#[derive(Debug, Clone, Copy)]
pub struct CalendarValue<'view> {
    /// XSD1.0 sign: -0001 denotes 1 BCE; year zero is forbidden.
    pub negative_year: bool,
    /// Four or more original validated digits, without precision truncation.
    pub year_digits: &'view str,
    /// Gregorian month.
    pub month: u8,
    /// Day in the month.
    pub day: u8,
    /// Original hour, including end-of-day 24.
    pub hour: u8,
    /// Minute within the hour.
    pub minute: u8,
    /// Original whole seconds, possibly a leap-second label.
    pub second: u8,
    /// Complete fractional digits, preserving arbitrary precision and zeros.
    pub fraction_digits: Option<&'view str>,
    /// Original optional signed timezone offset, in minutes.
    pub timezone_minutes: Option<i16>,
}

/// Complete calendar interpretation without erasing unsupported/invalid data.
#[derive(Debug, Clone, Copy)]
pub enum CalendarFact<'view> {
    /// Absent, complex or malformed original content.
    Malformed,
    /// The original requested schema has not been interpreted.
    Unsupported,
    /// Complete original XSD1.0 interpretation.
    Value(CalendarValue<'view>),
}

/// Exact parsed components for format-owned equality with PKIX time labels.
/// Reuse the SAME scalar kernel as [`DateTimeXml`]; no second lexical parser,
/// normalized owned copy, finite year/fraction bound or schema discovery.
pub trait CalendarXml: DateTimeXml {
    /// Visit current-operation components once. Original identity, joining,
    /// lexical scans and temporary capacity are admitted before work. Returned
    /// values cannot borrow callback-local digits or joined source storage.
    fn with_calendar<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
        visitor: impl for<'view> FnOnce(CalendarFact<'view>) -> Result<R, VE>,
    ) -> Result<R, crate::reference::VisitError<Self::Error, VE>>;
}

/// Complete schema-qualified claimed time in original protected `SignedProperties`.
/// No timestamp, generation instant, historical truth, freshness or ordering is
/// established by a signer's claim. All original precision stays in the XML.
pub struct ClaimedTime<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    timezone_minutes: i16,
}

impl<N: Copy, D: Copy, G: Copy> ClaimedTime<N, D, G> {
    /// Original immutable document generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Selected signature protecting this exact claimed property.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original property; no calendar conversion or truncated value replaces it.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Actual explicit offset, not an inferred local timezone or canonical form.
    #[must_use]
    pub fn timezone_minutes(&self) -> i16 {
        self.timezone_minutes
    }
}

/// An incomplete/invalid signing-time claim does not supply a UTC default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedTimeFailure {
    /// Original content fails the complete owner-selected XSD1.0 contract.
    Malformed,
    /// Valid XSD dateTime but no zone establishes a claimed UTC value.
    TimezoneUnstated,
    /// Original scalar processing is unsupported/incomplete, not invalid syntax.
    Unsupported,
}

/// Qualified claim or explicit failed/incomplete original property.
pub enum ClaimedTimeBinding<N, D, G> {
    /// Original schema and explicit timezone were established.
    Bound(ClaimedTime<N, D, G>),
    /// No qualified claim; this cannot become successful baseline evidence.
    Unproven {
        /// Actual original property.
        node: N,
        /// Malformed/unstated/unsupported remain distinguishable.
        cause: ClaimedTimeFailure,
    },
}

/// Source/current-operation errors remain terminal and unchanged.
#[derive(Debug)]
pub enum ClaimedTimeError<E, N> {
    /// The original signed-property source differs from this operation.
    Foreign {
        /// Original property node.
        node: N,
    },
    /// Exact XML owner, resource or generation refusal.
    Access(AccessError<E, N>),
}

/// Result in this XML owner's source/error domain.
pub type ClaimedTimeResult<X> = Result<
    ClaimedTimeBinding<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    ClaimedTimeError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Check the mandatory ORIGINAL claimed `SigningTime` through the XML owner's
/// scalar kernel. EN319132-1 6.3(h) requires a claimed UTC time; XSD1.0 3.2.7
/// defines zoned values and permits explicit offsets. Canonical lexical Z is
/// not an additional format requirement. An absent timezone is not assumed UTC.
/// This deliberately never creates an Instant or validates a leap event.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
/// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime>
pub fn check_time<X: DateTimeXml, W: Work>(
    signed: &Signed<X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> ClaimedTimeResult<X> {
    let node = signed.signing_time();
    if signed.snapshot() != access.snapshot() {
        return Err(ClaimedTimeError::Foreign { node });
    }
    let fact = access
        .query(node, |xml, snapshot, work| {
            xml.date_time(snapshot, node, work)
        })
        .map_err(ClaimedTimeError::Access)?;
    let cause = match fact {
        DateTimeFact::Malformed => ClaimedTimeFailure::Malformed,
        DateTimeFact::Unsupported => ClaimedTimeFailure::Unsupported,
        DateTimeFact::Valid {
            timezone_minutes: None,
        } => ClaimedTimeFailure::TimezoneUnstated,
        DateTimeFact::Valid {
            timezone_minutes: Some(timezone_minutes),
        } => {
            return Ok(ClaimedTimeBinding::Bound(ClaimedTime {
                snapshot: signed.snapshot(),
                signature: signed.signature(),
                node,
                timezone_minutes,
            }));
        }
    };
    Ok(ClaimedTimeBinding::Unproven { node, cause })
}
