//! Explicit recovery of numeric value without repairing the received encoding.

use super::{Element, ScopedReader};
use crate::{Error, ErrorCode, Integer, Limit, Result, value};

/// An INTEGER's original contents, numeric view and encoding diagnostic.
///
/// The original bytes are never rewritten. `value()` borrows a minimal suffix
/// of those bytes so its numeric conversions inspect at most eight significant
/// octets. A nonminimal source is still malformed BER/DER (X.690 §8.3.2).
/// Only the diagnostic path owns storage, retaining its account until drop.
#[derive(Debug)]
pub struct IntegerReading<'a> {
    original: &'a [u8],
    value: Integer<'a>,
    fault: Option<Error>,
}

impl<'a> IntegerReading<'a> {
    /// Original two's-complement contents, including redundant sign octets.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.original
    }

    /// Borrowed minimal numeric view; obtaining it performs no padding scan.
    #[must_use]
    pub fn value(&self) -> Integer<'a> {
        self.value
    }

    /// Original located minimality violation; `None` means minimal contents.
    #[must_use]
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }

    /// Move the numeric view and diagnostic without copying their storage.
    ///
    /// Retain `as_bytes()` or the original element separately when wire
    /// identity is needed. The minimal view is not a replacement signed value.
    #[must_use]
    pub fn into_parts(self) -> (Integer<'a>, Option<Error>) {
        (self.value, self.fault)
    }
}

impl<'a: 'operation, 'operation> ScopedReader<'a, 'operation> {
    /// Recover the unique numeric value while retaining nonminimal spelling.
    ///
    /// Unlike [`Self::integer`], this explicit diagnostic operation reads
    /// redundant sign octets. It does not declare them conforming: X.690
    /// §§8.3.1–8.3.3 requires primitive, nonempty, minimal two's complement
    /// already under BER. Schema layers decide how to retain the fault.
    /// <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
    ///
    /// Use the Reader which produced `element`. Like the strict reader, this
    /// supports primitive IMPLICIT tagging and leaves tag selection to the
    /// schema. Original offsets, depth and cumulative local work are retained;
    /// future work and diagnostic storage use the current execution account.
    /// Payload bytes remain borrowed. Padding is scanned once, before any
    /// bounded numeric conversion requested on the returned view.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, ErrorCode};
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// let parser = Parser::der(memory);
    /// let mut reader = parser.read(&[2, 2, 0, 1], 400)?;
    /// let element = reader.next_element()?.unwrap();
    /// let reading = reader.integer_reading(&element)?;
    /// assert_eq!(reading.as_bytes(), &[0, 1]);
    /// let (value, fault) = reading.into_parts();
    /// assert_eq!(value.as_u64(), Some(1));
    /// let fault = fault.unwrap();
    /// assert_eq!(fault.code(), ErrorCode::IntegerNotMinimal);
    /// assert_eq!(fault.offset(), 400);
    /// # Ok::<(), structured_asn1::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Empty and constructed contents remain errors. Work is admitted before
    /// scanning; failure to retain the fault path is a resource refusal, never
    /// a successful reading without its diagnostic.
    pub fn integer_reading(&self, element: &Element<'a>) -> Result<IntegerReading<'a>> {
        self.primitive(element)?;
        // Fixed minimality/sign inspection, including the canonical fast path.
        self.budget()
            .work_in(3, self.memory())
            .map_err(|limit| self.fail_under(ErrorCode::LimitExceeded(limit), element))?;
        let original = element.contents();
        match value::integer(original) {
            Ok(value) => Ok(IntegerReading {
                original,
                value,
                fault: None,
            }),
            Err(ErrorCode::IntegerNotMinimal) => {
                // At most two byte inspections per removed sign octet, plus
                // the final predicate. Overflow refuses before any traversal.
                let work = u64::try_from(original.len())
                    .ok()
                    .and_then(|n| n.checked_mul(2))
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| {
                        self.fail_under(ErrorCode::LimitExceeded(Limit::Work), element)
                    })?;
                self.budget()
                    .work_in(work, self.memory())
                    .map_err(|limit| self.fail_under(ErrorCode::LimitExceeded(limit), element))?;
                let value = value::recovered_integer(original);
                let fault = self.fail_under(ErrorCode::IntegerNotMinimal, element);
                if fault.is_resource() {
                    return Err(fault);
                }
                Ok(IntegerReading {
                    original,
                    value,
                    fault: Some(fault),
                })
            }
            Err(code) => Err(self.fail_under(code, element)),
        }
    }
}
