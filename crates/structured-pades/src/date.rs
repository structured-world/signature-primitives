//! PDF calendar labels with explicit precision and original timezone spelling.

use crate::error::{Error, ErrorKind, Syntax};
use crate::model::admit;
use crate::source::Location;
use structured_asn1::memory::Work;
use structured_pkix::{temporal::Instant, time::Calendar};

/// Exact readable PDF date semantics, without a freshness or occurrence proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    calendar: Calendar,
    offset: i16,
    components: u8,
    explicit_zone: bool,
    instant: Instant,
}

impl Date {
    /// Original calendar components, with only schema-prescribed defaults.
    #[must_use]
    pub fn calendar(self) -> Calendar {
        self.calendar
    }
    /// Original signed local-time offset in minutes.
    #[must_use]
    pub fn offset_minutes(self) -> i16 {
        self.offset
    }
    /// Count of explicitly written year/month/day/hour/minute/second fields.
    #[must_use]
    pub fn components(self) -> u8 {
        self.components
    }
    /// Whether the input explicitly wrote Z or a signed timezone.
    #[must_use]
    pub fn has_explicit_zone(self) -> bool {
        self.explicit_zone
    }
    /// The resulting UTC label, without an authenticated clock assertion.
    #[must_use]
    pub fn instant(self) -> Instant {
        self.instant
    }

    /// Reads ISO32000-1 §7.9.4, including D:, calendar bounds, ordered optional
    /// fields, apostrophe placement and its prescribed GMT default. Numeric
    /// defaults and calendar arithmetic are independent of application policy.
    /// <https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf>
    pub fn read(bytes: &[u8], location: Location, work: &impl Work) -> crate::Result<Self> {
        admit(work, location, bytes.len() as u64 + 1)?;
        let malformed = || Error {
            kind: ErrorKind::Syntax(Syntax::String),
            location,
        };
        if !bytes.starts_with(b"D:") || bytes.len() < 6 || bytes.len() > 22 {
            return Err(malformed());
        }
        let mut at = 2;
        let mut year = 0_i64;
        for _ in 0..4 {
            let byte = bytes[at];
            if !byte.is_ascii_digit() {
                return Err(malformed());
            }
            year = year * 10 + i64::from(byte - b'0');
            at += 1;
        }
        let mut values = [1, 1, 0, 0, 0];
        let mut components = 1_u8;
        for value in &mut values {
            if at == bytes.len() || !bytes[at].is_ascii_digit() {
                break;
            }
            if at + 2 > bytes.len() || !bytes[at + 1].is_ascii_digit() {
                return Err(malformed());
            }
            *value = (bytes[at] - b'0') * 10 + bytes[at + 1] - b'0';
            components += 1;
            at += 2;
        }
        let explicit_zone = at != bytes.len();
        let mut offset = 0_i16;
        if explicit_zone {
            if components != 6 {
                return Err(malformed());
            }
            let sign = bytes[at];
            at += 1;
            match sign {
                b'Z' => {}
                b'+' | b'-' => {
                    let mut hours = 0_u8;
                    let mut minutes = 0_u8;
                    if at != bytes.len() {
                        hours = pair(bytes, &mut at).ok_or_else(malformed)?;
                        if at != bytes.len() {
                            if bytes[at] != b'\'' {
                                return Err(malformed());
                            }
                            at += 1;
                            if at != bytes.len() {
                                minutes = pair(bytes, &mut at).ok_or_else(malformed)?;
                            }
                        }
                    }
                    if hours > 23 || minutes > 59 {
                        return Err(malformed());
                    }
                    offset = i16::from(hours) * 60 + i16::from(minutes);
                    if sign == b'-' {
                        offset = -offset;
                    }
                }
                _ => return Err(malformed()),
            }
        }
        if at != bytes.len() || values[4] > 59 {
            return Err(malformed());
        }
        let calendar = Calendar {
            year,
            month: values[0],
            day: values[1],
            hour: values[2],
            minute: values[3],
            second: values[4],
            nanos: 0,
        };
        let instant = calendar
            .instant_at_minutes(offset, work)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?
            .ok_or_else(malformed)?;
        Ok(Self {
            calendar,
            offset,
            components,
            explicit_zone,
            instant,
        })
    }
}

fn pair(bytes: &[u8], at: &mut usize) -> Option<u8> {
    if bytes.len() - *at < 2 {
        return None;
    }
    let first = bytes[*at];
    let second = bytes[*at + 1];
    if !first.is_ascii_digit() || !second.is_ascii_digit() {
        return None;
    }
    *at += 2;
    Some((first - b'0') * 10 + second - b'0')
}
