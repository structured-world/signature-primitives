//! XSD1.0 calendar value arithmetic, distinct from UTC elapsed-time arithmetic.

use structured_asn1::memory::{MemoryError, Work};

/// Bounded calendar components in XML Schema Datatypes 1.0 year numbering.
/// Year -1 denotes 1 BCE; zero is not a valid label. This is a value-space
/// bridge for already decoded fields, not an XML lexical parser. Arbitrary
/// precision lexical years/fractions remain with the caller's schema reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xsd10Label {
    /// Signed XSD1.0 year, excluding zero.
    pub year: i64,
    /// Month, one through twelve.
    pub month: u8,
    /// Day within the XSD1.0 month.
    pub day: u8,
    /// Original hour, including end-of-day twenty-four.
    pub hour: u8,
    /// Minute, zero through fifty-nine.
    pub minute: u8,
    /// Second, including sixty before value normalization.
    pub second: u8,
    /// Exact representable fractional nanoseconds.
    pub nanos: u32,
}

impl Xsd10Label {
    /// Normalize a label with an explicit timezone to the XSD1.0 UTC value.
    /// Returns None for invalid fields or a result outside this bounded year
    /// representation. Work refusal remains an error, never a malformed label.
    ///
    /// XSD1.0 §3.2.7.3 and Appendix E normalize second sixty by carrying to the
    /// next minute even at timezone zero. Appendix E's month length uses the
    /// literal signed year, not XSD1.1/astronomical year numbering. No leap table,
    /// occurrence proof or implicit timezone is inferred by this operation.
    /// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-order>
    /// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#adding-durations-to-dateTimes>
    ///
    /// # Panics
    /// Only if the private bounded calendar component invariants are violated.
    pub fn at_utc<W: Work>(
        mut self,
        timezone_minutes: i16,
        execution: &W,
    ) -> Result<Option<Self>, MemoryError> {
        // Fixed fields and at most one day boundary for the permitted fourteen
        // hour offset, including hour24/second60. No attacker-driven loop.
        execution.charge_work(128)?;
        if self.year == 0
            || !(1..=12).contains(&self.month)
            || self.day == 0
            || self.day > self.month_days()
            || self.hour > 24
            || self.minute > 59
            || self.second > 60
            || self.nanos >= 1_000_000_000
            || !(-840..=840).contains(&timezone_minutes)
        {
            return Ok(None);
        }
        if self.hour == 24 && (self.minute != 0 || self.second != 0 || self.nanos != 0) {
            return Ok(None);
        }
        let seconds =
            i32::from(self.hour) * 3600 + i32::from(self.minute) * 60 + i32::from(self.second)
                - i32::from(timezone_minutes) * 60;
        let carry = seconds.div_euclid(86_400);
        let seconds = seconds.rem_euclid(86_400);
        self.hour = u8::try_from(seconds / 3600).expect("bounded hour");
        self.minute = u8::try_from(seconds / 60 % 60).expect("bounded minute");
        self.second = u8::try_from(seconds % 60).expect("bounded second");
        if carry < 0 {
            if self.day > 1 {
                self.day -= 1;
            } else {
                if self.month > 1 {
                    self.month -= 1;
                } else {
                    self.month = 12;
                    let Some(year) = self.year.checked_sub(1) else {
                        return Ok(None);
                    };
                    self.year = if year == 0 { -1 } else { year };
                }
                self.day = self.month_days();
            }
        } else if carry > 0 {
            if self.day < self.month_days() {
                self.day += 1;
            } else {
                self.day = 1;
                if self.month < 12 {
                    self.month += 1;
                } else {
                    self.month = 1;
                    let Some(year) = self.year.checked_add(1) else {
                        return Ok(None);
                    };
                    self.year = if year == 0 { 1 } else { year };
                }
            }
        }
        Ok(Some(self))
    }

    fn month_days(self) -> u8 {
        // The existing Gregorian month kernel needs only the 400-year residue.
        // This preserves Appendix E's signed-year modulus without narrowing a
        // whole negative/wide year or introducing another month-length table.
        let year = u32::try_from(self.year.rem_euclid(400)).expect("year residue");
        u8::try_from(super::days_in_month(year, u32::from(self.month))).expect("month length")
    }
}
