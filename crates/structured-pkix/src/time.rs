//! The two ways a certificate writes a moment, read into one.
//!
//! Both preserve UTC labels, including an inserted second. The form is kept because it is
//! part of what the certificate says: the profile requires the two-digit form
//! through 2049 and the four-digit form afterwards, and a report that has to
//! explain a certificate cannot explain what it did not keep.
//!
//! Only the fixed-width form with seconds and `Z` is accepted. The wider
//! encodings the base standard allows, an offset from local time, minutes
//! without seconds, a fractional part, all let one moment be written several
//! ways, and here they would let two documents disagree about when a
//! certificate expired while both claiming to be the same certificate.

use crate::error::{Error, ErrorCode, Result};
use crate::temporal::Instant;
use core::fmt;
use structured_asn1::{Element, Tag, universal};

/// Which form a time was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Two digits of year, which the profile requires through 2049.
    Utc,
    /// Four digits of year, which the profile requires from 2050.
    Generalized,
}

/// A moment, and how the certificate wrote it.
///
/// Two times are equal when they name the same moment. The form is what the
/// certificate used to say it, not part of which moment it is.
#[derive(Debug, Clone, Copy)]
pub struct Time {
    instant: Instant,
    form: Form,
}

/// The moment `99991231235959Z` names, which the profile uses to say that a
/// certificate has no well defined expiry rather than that it expires then.
pub const NO_WELL_DEFINED_EXPIRY: i64 = 253_402_300_799;

impl Time {
    /// POSIX label, negative before the epoch. For an inserted second this
    /// is the preceding ordinary second's label. Use [`Self::instant`] for
    /// comparisons and [`crate::temporal::LeapTable`] for elapsed arithmetic.
    #[must_use]
    pub fn seconds(self) -> i64 {
        self.instant.seconds()
    }

    /// The lossless UTC label; parsing does not authenticate its occurrence.
    #[must_use]
    pub fn instant(self) -> Instant {
        self.instant
    }

    /// Whether the encoded time labels an inserted second.
    #[must_use]
    pub fn is_leap_second(self) -> bool {
        self.instant.is_leap_second()
    }

    /// Which form the certificate wrote this in.
    #[must_use]
    pub fn form(self) -> Form {
        self.form
    }

    /// Whether this is the moment the profile uses to mean that no expiry was
    /// defined. What that means for a verdict is a policy question, and this
    /// only reports that the certificate said it.
    #[must_use]
    pub fn is_no_well_defined_expiry(self) -> bool {
        self.seconds() == NO_WELL_DEFINED_EXPIRY && !self.is_leap_second()
    }
}

impl PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.instant == other.instant
    }
}

impl Eq for Time {}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.instant.cmp(&other.instant)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day, hour, minute, ordinary) = civil_from_seconds(self.seconds());
        let second = if self.is_leap_second() { 60 } else { ordinary };
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )
    }
}

/// Reads an element that a schema says is a time.
///
/// The tag chooses the form, so a field declared as a choice between the two is
/// read by handing whichever element was found to this.
pub(crate) fn read(element: &Element<'_>, field: &'static str) -> Result<Time> {
    read_as(element, field, Fraction::Absent)
}

/// Whether a fractional-seconds element may close the value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fraction {
    /// The profile writes a certificate's validity dates without one
    /// (RFC 5280 4.1.2.5.2), and this reader answers with one moment, which
    /// a fraction would not change.
    Absent,
    /// The encoding writes one where there is one to write, with no trailing
    /// zeros and none at all where it stands for zero (X.690 11.7.3). A
    /// value preserved inside somebody else's payload is written under that
    /// rule and not under the profile's narrower one.
    Written,
}

/// Reads a time under whichever of the two rules the caller is asking about.
pub(crate) fn read_as(
    element: &Element<'_>,
    field: &'static str,
    fraction: Fraction,
) -> Result<Time> {
    let fail = |code| Error::new(code, field, element.span().start);

    let form = if element.tag() == Tag::primitive(universal::UTC_TIME) {
        Form::Utc
    } else if element.tag() == Tag::primitive(universal::GENERALIZED_TIME) {
        Form::Generalized
    } else {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    };

    let contents = element.contents();
    let (year, rest) = match form {
        Form::Utc => {
            let (digits, rest) =
                split(contents, 2).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
            let two = number(digits).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
            // The profile's pivot: a two-digit year is read into the window
            // 1950 to 2049, so a certificate written in 1998 does not become
            // one written in 2098.
            (if two >= 50 { 1900 + two } else { 2000 + two }, rest)
        }
        Form::Generalized => {
            // Any year, including one the profile tells issuers to write as a
            // UTCTime instead. That rule binds the issuer: "CAs conforming to
            // this profile MUST always encode certificate validity dates
            // through the year 2049 as UTCTime". The sentence after it binds
            // this reader the other way: "Conforming applications MUST be
            // able to process validity dates that are encoded in either
            // UTCTime or GeneralizedTime" (RFC 5280 4.1.2.5). A date written
            // in the wrong form still names one moment, unambiguously, and
            // refusing to read it would leave a person holding a document
            // this product declined to explain over its issuer's spelling.
            let (digits, rest) =
                split(contents, 4).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
            let four = number(digits).ok_or_else(|| fail(ErrorCode::MalformedTime))?;
            (four, rest)
        }
    };

    let ([month, day, hour, minute, second], tail) =
        fields_of(rest).ok_or_else(|| fail(ErrorCode::MalformedTime))?;

    // A fraction closes the value where one is written at all: only the wider
    // form has one, and only where the caller is reading under the encoding's
    // rule rather than the profile's.
    let closed = match tail.split_first() {
        Some((b'.', digits)) if fraction == Fraction::Written && form == Form::Generalized => {
            // At least one digit, no trailing zero, and the Z after them.
            matches!(digits.split_last(), Some((b'Z', fraction)) if !fraction.is_empty()
                && fraction.iter().all(u8::is_ascii_digit)
                && fraction.last() != Some(&b'0'))
        }
        _ => tail == b"Z",
    };
    if !closed {
        return Err(fail(ErrorCode::MalformedTime));
    }

    if form == Form::Generalized {
        // X.680 (2021) §46.3 incorporates ISO 8601 time-of-day notation,
        // including inserted-second labels. X.690 §11.7 restricts spelling,
        // not UTC occurrence. After the spelling checks above, use the same
        // calendar/label semantics as the temporal reader; a LeapTable alone
        // can establish occurrence. UTCTime has its own 00..59 grammar below.
        // https://www.itu.int/rec/T-REC-X.680-202102-I/en
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        let instant = crate::temporal::generalized(element, field)?.start();
        return Ok(Time { instant, form });
    }

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(fail(ErrorCode::TimeOutOfRange));
    }
    // X.680 (2021) §47.3(b)(2): "ss is seconds (00 to 59)" for UTCTime.
    // https://www.itu.int/rec/T-REC-X.680-202102-I/en
    if hour > 23 || minute > 59 || second > 59 {
        return Err(fail(ErrorCode::TimeOutOfRange));
    }

    // Every field is bounded by the checks above and the year by its digit
    // count, so the seconds count is at most the year 9999 in seconds and
    // nothing here can overflow.
    let days = days_from_civil(i64::from(year), month, day);
    let seconds =
        days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);

    let instant = Instant::new(seconds, 0).ok_or_else(|| fail(ErrorCode::TimeOutOfRange))?;
    Ok(Time { instant, form })
}

/// Splits off `count` bytes, which must all be digits.
pub(super) fn split(contents: &[u8], count: usize) -> Option<(&[u8], &[u8])> {
    let (digits, rest) = contents.split_at_checked(count)?;
    digits
        .iter()
        .all(u8::is_ascii_digit)
        .then_some((digits, rest))
}

/// Reads a run of digits already known to be digits.
pub(super) fn number(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
    })
}

/// Where a year falls in the four-hundred-year cycle the calendar repeats
/// on, which is what every question about its length answers to.
///
/// The Gregorian calendar comes back to the same shape every four hundred
/// years: the leap rule is stated in fours, hundreds and four hundreds, and
/// four hundred years hold a whole number of weeks. So a year of any width
/// is answered by its last four digits, which is what makes a year too wide
/// for a counter no less readable than a short one. The sign turns the count
/// the other way round the cycle.
fn in_cycle(digits: &str, negative: bool) -> u32 {
    let counted = digits.as_bytes().iter().fold(0u32, |cycle, digit| {
        (cycle * 10 + u32::from(digit - b'0')) % 400
    });
    if negative {
        (400 - counted) % 400
    } else {
        counted
    }
}

/// How many weeks a year is written in: fifty-two, and fifty-three where the
/// year is the long one.
///
/// A year is long where it begins on a Thursday, and where it is a leap year
/// beginning on a Wednesday (ISO 8601 4.1.4, which the week components of
/// X.680 Table 7 are written in). Both are said by the day the first of
/// January falls on, which is what the count below is: the days from the
/// start of the calendar to that year, over seven.
fn weeks_in_year(year: u32) -> u32 {
    let opens = |year: u32| (year + year / 4 - year / 100 + year / 400) % 7;
    // The second reading needs the year before, which the first year of the
    // calendar does not have; it opens the calendar rather than continuing
    // one, so only the first reading applies to it.
    let long = opens(year) == 4 || year.checked_sub(1).is_some_and(|before| opens(before) == 3);
    if long { 53 } else { 52 }
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

pub(super) fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from the epoch to a date, by the shift-the-year-to-March method: with
/// March first, the four-year, hundred-year and four-hundred-year corrections
/// all land at the end of the year and the leap day needs no special case.
///
/// Every value is bounded by the calendar checks above, so ordinary arithmetic
/// cannot overflow here.
pub(super) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let month = i64::from(month);
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    // 719468 is the number of days from the epoch back to the start of the era
    // this counts from.
    era * 146_097 + day_of_era - 719_468
}

/// The inverse, for rendering. Bounded the same way.
pub(super) fn civil_from_seconds(seconds: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = seconds.div_euclid(86_400);
    let within = seconds.rem_euclid(86_400);

    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };

    (
        if month <= 2 { year + 1 } else { year },
        month,
        day,
        within / 3_600,
        within / 60 % 60,
        within % 60,
    )
}

/// Which of the types defined in X.680 38.4 a value claims to be, for the
/// four whose notation is settled enough to hold it to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defined {
    /// `DATE`, a year, a month and a day.
    Date,
    /// `TIME-OF-DAY`, an hour, a minute and a second.
    TimeOfDay,
    /// `DATE-TIME`, the two of them.
    DateTime,
    /// `DURATION`, a length of time rather than a moment.
    Duration,
    /// `TIME` itself, whose notation is the whole of the interchange format
    /// and is read here only as the characters it is written from.
    Any,
}

/// Whether the contents of one of the newer time types are the notation that
/// type writes.
///
/// The contents are the value notation in UTF-8, with the characters X.690
/// 8.26 names removed: the hyphens of a date, the colons of a time, the T
/// between them, the P before a duration. What is left is what this reads.
/// A value that is not the notation is not a value of the type, and one
/// preserved for somebody else must not claim a type it does not have.
pub(crate) fn defined_fits(kind: Defined, contents: &[u8]) -> bool {
    match kind {
        Defined::Date => date_fits(contents),
        Defined::TimeOfDay => time_of_day_fits(contents),
        Defined::DateTime => contents
            .split_at_checked(8)
            .is_some_and(|(date, time)| date_fits(date) && time_of_day_fits(time)),
        Defined::Duration => duration_fits(contents),
        Defined::Any => core::str::from_utf8(contents).is_ok_and(any_fits),
    }
}

/// The unrestricted type, whose notation is the whole of what the property
/// settings can choose: a point in time, a duration, an interval of the two,
/// and any of those repeated (X.680 Table 7).
///
/// Written in the extended formats, which keep their separators, and X.690
/// 8.26.1.2 takes only the quotation marks off, so what arrives here is the
/// notation as the table writes it.
fn any_fits(text: &str) -> bool {
    // Recurrence opens the value: R, how many times if it is not unlimited,
    // and then the interval it repeats.
    let interval = match text.strip_prefix('R') {
        Some(after) => {
            let count = after.bytes().take_while(u8::is_ascii_digit).count();
            let (repeats, tail) = after.split_at(count);
            if repeats.starts_with('0') && repeats.len() > 1 {
                return false;
            }
            let Some(rest) = tail.strip_prefix('/') else {
                return false;
            };
            rest
        }
        None => text,
    };
    match interval.split_once('/') {
        // An interval is a start point and an end point, a start point and a
        // duration, or a duration and an end point (Table 7, "Time
        // interval"). Two durations name no interval: nothing says when.
        Some((start, end)) => match (part_fits(start), part_fits(end)) {
            (Some(starts), Some(ends)) => !(starts == Part::Duration && ends == Part::Duration),
            _ => false,
        },
        None => part_fits(interval).is_some(),
    }
}

/// Which of the two an end of an interval, or a value standing alone, is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Point,
    Duration,
}

/// Whether one end of a value is a point in time or a length of one.
fn part_fits(text: &str) -> Option<Part> {
    if let Some(duration) = text.strip_prefix('P') {
        return duration_fits(duration.as_bytes()).then_some(Part::Duration);
    }
    point_fits(text).then_some(Part::Point)
}

/// Whether text is a point in time: a date, a time of day, or both with the
/// T between them, and the zone the value is read in if it carries one.
fn point_fits(text: &str) -> bool {
    match text.split_once('T') {
        Some((date, time)) => date_part_fits(date) && zoned_time_fits(time),
        // The hours component of a time standing alone is written without
        // the T (Table 7, "Hours component" with Basic=Time), so what is
        // left is one or the other.
        None => date_part_fits(text) || zoned_time_fits(text),
    }
}

/// Whether text is a time of day and, where it carries one, the zone it is
/// read in: the UTC designator, or the difference from it (Table 7, the last
/// two rows). The zone follows the time and nothing else, so it is looked
/// for here rather than at the end of the whole point.
fn zoned_time_fits(text: &str) -> bool {
    let stated = match text.strip_suffix('Z') {
        Some(rest) => rest,
        None => match text.rfind(['+', '-']) {
            Some(at) if difference_fits(&text[at..]) => &text[..at],
            _ => text,
        },
    };
    time_part_fits(stated)
}

/// Whether text is the difference from UTC: a sign, hours, and minutes where
/// the difference is not a whole number of hours.
fn difference_fits(text: &str) -> bool {
    let Some(rest) = text.strip_prefix(['+', '-']) else {
        return false;
    };
    match rest.split_once(':') {
        Some((hours, minutes)) => {
            two_digits(hours).is_some_and(|hours| hours <= 23)
                && two_digits(minutes).is_some_and(|minutes| minutes <= 59)
        }
        None => two_digits(rest).is_some_and(|hours| hours <= 23),
    }
}

/// Whether text is a date in the extended format: a year, and then a month
/// and a day, a week and a day of it, or a day of the year (Table 7, the
/// year, month, week and day components).
fn date_part_fits(text: &str) -> bool {
    let signed = text.starts_with(['+', '-']);
    let rest = if signed { &text[1..] } else { text };
    let mut parts = rest.split('-');
    let Some(year) = parts.next() else {
        return false;
    };
    // Four digits, or more where the settings ask for a wider year.
    if year.len() < 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some(next) = parts.next() else {
        return parts.next().is_none();
    };
    // How far the days and the weeks of this year run is the year's to say,
    // and a year of any width says it: the calendar repeats every four
    // hundred years, so where in that cycle the year falls is the whole of
    // the answer.
    let counted = in_cycle(year, signed);
    if let Some(week) = next.strip_prefix('W') {
        // A week, and then which day of it, one digit through seven.
        let last = weeks_in_year(counted);
        let weeks = two_digits(week).is_some_and(|week| (1..=last).contains(&week));
        return weeks
            && match parts.next() {
                Some(day) => {
                    day.len() == 1
                        && day.bytes().all(|byte| (b'1'..=b'7').contains(&byte))
                        && parts.next().is_none()
                }
                None => true,
            };
    }
    if next.len() == 3 {
        // The day of the year, which stands in for the month and the day,
        // and runs to the length of that year.
        let last = if is_leap(counted) { 366 } else { 365 };
        return next.bytes().all(|byte| byte.is_ascii_digit())
            && number(next.as_bytes()).is_some_and(|day| (1..=last).contains(&day))
            && parts.next().is_none();
    }
    let Some(month) = two_digits(next).filter(|month| (1..=12).contains(month)) else {
        return false;
    };
    match parts.next() {
        Some(day) => {
            let Some(day) = two_digits(day) else {
                return false;
            };
            // The calendar decides the last day of the month, and the year
            // decides February.
            let last = days_in_month(counted, month);
            day >= 1 && day <= last && parts.next().is_none()
        }
        None => true,
    }
}

/// Whether text is a time of day in the extended format: hours, and then
/// minutes and seconds, the last component present carrying a fraction where
/// the value is written to that accuracy (Table 7).
fn time_part_fits(text: &str) -> bool {
    let mut parts = text.split(':');
    let bounds = [23u32, 59, 60];
    let mut carried = None;
    let mut counted = 0usize;
    let mut ending = false;
    for (piece, most) in parts.by_ref().zip(bounds) {
        let (digits, fraction) = match piece.split_once(['.', ',']) {
            Some((digits, fraction)) => (digits, Some(fraction)),
            None => (piece, None),
        };
        let Some(value) = two_digits(digits) else {
            return false;
        };
        // A fraction says how accurately the value is written, so the
        // component carrying one is the last (ISO 8601, 4.2.2.4).
        if let Some(fraction) = fraction {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            carried = Some(counted);
        }
        counted += 1;
        if carried.is_some_and(|at| at + 1 != counted) {
            return false;
        }
        // Midnight at the end of a day is the twenty-fourth hour, which is
        // the one value past the bounds (Table 7, "Hours component"). It
        // names one instant rather than an hour a value can sit inside, so
        // what follows it is zero and nothing carries a fraction: a
        // fraction of that hour, or of a component after it, is a moment
        // past the end of the day.
        if ending && fraction.is_some() {
            return false;
        }
        if counted == 1 && value == 24 {
            ending = true;
            if fraction.is_some() {
                return false;
            }
            continue;
        }
        if value > most || (ending && value != 0) {
            return false;
        }
    }
    counted > 0 && parts.next().is_none()
}

/// Two digits read as a number, which is how every component but the year
/// and the day of the year is written.
fn two_digits(text: &str) -> Option<u32> {
    (text.len() == 2 && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| number(text.as_bytes()))?
}

/// Eight digits naming a day of the calendar (`Date=YMD Year=Basic`).
fn date_fits(contents: &[u8]) -> bool {
    let Some((year, rest)) = split(contents, 4) else {
        return false;
    };
    let Some(([month, day], [])) = fields_of(rest) else {
        return false;
    };
    let Some(year) = number(year) else {
        return false;
    };
    (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month)
}

/// Six digits naming a time of day (`Time=HMS`).
fn time_of_day_fits(contents: &[u8]) -> bool {
    let Some(([hour, minute, second], [])) = fields_of(contents) else {
        return false;
    };
    // Midnight is written at either end of the day, so the hour reaches
    // twenty-four where the rest of the value is zero (X.680 38.4.2), and
    // the second reaches sixty because the interchange format writes a leap
    // second that way.
    let midnight = hour == 24 && minute == 0 && second == 0;
    (hour <= 23 || midnight) && minute <= 59 && second <= 60
}

/// A duration, as X.690 8.26.5 leaves it: the notation without its leading P,
/// so a count and its designator for each component that is present, largest
/// first, with the time components after a T.
fn duration_fits(contents: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(contents) else {
        return false;
    };
    // The week form stands alone: it is one of the three alternatives and
    // does not mix with the others (X.680 38.3.6.1).
    if text.ends_with('W') {
        return components_fit(text, b"W").is_some_and(|weeks| weeks.any);
    }
    let (date, time) = match text.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (text, None),
    };
    // A T with nothing after it names no component.
    if time.is_some_and(str::is_empty) {
        return false;
    }
    let Some(dated) = components_fit(date, b"YMD") else {
        return false;
    };
    // A fraction ends the duration, so a date part that carries one may not
    // be followed by a time part either (X.680 38.3.6.13).
    if dated.fractional && time.is_some() {
        return false;
    }
    let Some(timed) = time.map_or(Some(Components::NONE), |time| components_fit(time, b"HMS"))
    else {
        return false;
    };
    // Something has to be there: a duration of no components is no length of
    // time.
    dated.any || timed.any
}

/// What a run of designations turned out to be.
#[derive(Clone, Copy)]
struct Components {
    /// Whether there were any at all, which is a form the caller decides
    /// about rather than a malformation on its own.
    any: bool,
    /// Whether the last one carried a fraction, which closes the duration.
    fractional: bool,
}

impl Components {
    const NONE: Self = Self {
        any: false,
        fractional: false,
    };
}

/// Whether a run is designations in the order given, each designator used at
/// most once: a count, an optional fraction, and the letter naming the
/// component (X.680 38.3.6.2 to 38.3.6.13). `None` says the run is not
/// designations at all.
fn components_fit(text: &str, order: &[u8]) -> Option<Components> {
    let mut rest = text.as_bytes();
    let mut left = order;
    let mut seen = Components::NONE;
    while !rest.is_empty() {
        // The count opens with a zero only where it is the single digit zero
        // (38.3.6.11), so the accuracy a value is written to is written one
        // way.
        let count = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if count == 0 || (rest[0] == b'0' && count > 1) {
            return None;
        }
        let after = &rest[count..];
        let (after, fractional) = match after.split_first() {
            Some((b'.' | b',', tail)) => {
                let digits = tail.iter().take_while(|byte| byte.is_ascii_digit()).count();
                if digits == 0 {
                    return None;
                }
                (&tail[digits..], true)
            }
            _ => (after, false),
        };
        let (designator, tail) = after.split_first()?;
        let at = left.iter().position(|kind| kind == designator)?;
        left = &left[at + 1..];
        // "If a designation contains a fractional part, there shall be no
        // following designation" (38.3.6.13): the fraction says how
        // accurately the duration is written, and a component after it
        // would say something more accurate again.
        if seen.fractional {
            return None;
        }
        seen = Components {
            any: true,
            fractional,
        };
        rest = tail;
    }
    Some(seen)
}

/// The two-digit fields at the front of a value, and whatever follows them
/// for the caller to hold to its own rule.
pub(super) fn fields_of<const N: usize>(contents: &[u8]) -> Option<([u32; N], &[u8])> {
    let mut values = [0u32; N];
    let mut rest = contents;
    for value in &mut values {
        let (digits, tail) = split(rest, 2)?;
        *value = number(digits)?;
        rest = tail;
    }
    Some((values, rest))
}

#[cfg(test)]
mod tests;
