//! Accounted dotted-decimal parsing with validated immutable OID storage.

use super::Oid;
use crate::error::{Error, ErrorCode, Path, Result};
use crate::memory::{Memory, MemoryError, OwnedVec};

/// An independently owned object identifier with retained capacity accounting.
///
/// Its immutable storage is validated at construction. Borrowing its OID view
/// does not rescan the encoded arcs; callers admit subsequent comparisons or
/// traversal in the execution domain of the current operation.
#[derive(Debug)]
pub struct OwnedOid {
    bytes: OwnedVec<u8>,
}

impl OwnedOid {
    /// Parses strict dotted-decimal numericOID text into owned encoded arcs.
    ///
    /// Uses RFC4512 §1.4's decimal-component grammar (at least two components,
    /// no padded decimal component) and ASN.1's first/second arc restrictions.
    /// Arc width is unrestricted by machine integers. Work, scratch, copying
    /// and capacity are admitted before execution; the result keeps its charge.
    ///
    /// # Errors
    /// Returns `MalformedOid` at the offending text offset, or a distinct
    /// resource error before unfunded conversion/allocation.
    pub fn parse(text: &str, execution: &Memory) -> Result<Self> {
        let work = (text.len() as u64)
            .checked_mul(4)
            .and_then(|work| work.checked_add(1))
            .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, 0))?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, 0))?;
        let root = validate(text)?;
        let mut bytes = execution.vector();
        let mut groups = execution.vector();
        let mut offset = 2;
        for (position, component) in text.split('.').enumerate() {
            if position == 0 {
                continue;
            }
            groups.clear();
            groups
                .try_push(0u8)
                .map_err(|reason| Error::resource(reason, offset))?;
            for digit in component.bytes() {
                multiply(&mut groups, digit - b'0', execution, offset)?;
            }
            if position == 1 {
                add_root(&mut groups, root * 40, execution, offset)?;
            }
            execution
                .charge_work(groups.len() as u64)
                .map_err(|reason| Error::resource(reason, offset))?;
            for at in (0..groups.len()).rev() {
                let byte = if at == 0 {
                    groups[at]
                } else {
                    groups[at] | 0x80
                };
                bytes
                    .try_push(byte)
                    .map_err(|reason| Error::resource(reason, offset))?;
            }
            offset += component.len() as u64 + 1;
        }
        Ok(Self { bytes })
    }

    /// Copies an already validated identifier into the supplied storage domain.
    /// The original encoding and source remain unchanged on resource refusal.
    pub fn from_oid(value: Oid<'_>, execution: &Memory) -> core::result::Result<Self, MemoryError> {
        let mut bytes = execution.vector();
        bytes.try_extend_from_slice(value.as_bytes())?;
        Ok(Self { bytes })
    }

    /// A constant-time borrowed view of the validated immutable encoding.
    #[must_use]
    pub fn as_oid(&self) -> Oid<'_> {
        Oid(&self.bytes)
    }
}

fn malformed(offset: usize) -> Error {
    Error::new(ErrorCode::MalformedOid, offset as u64, Path::default())
}

fn validate(text: &str) -> Result<u8> {
    // RFC4512 §1.4 supplies the lexical rule; X.690 §8.19.4 packs the
    // first two ASN.1 arcs as 40*root + second, with second<40 for root<2.
    // https://www.rfc-editor.org/rfc/rfc4512.html#section-1.4
    let mut offset = 0;
    let mut count = 0;
    let mut root = 0;
    for component in text.split('.') {
        let bytes = component.as_bytes();
        if bytes.is_empty() {
            return Err(malformed(offset));
        }
        if bytes.len() > 1 && bytes[0] == b'0' {
            return Err(malformed(offset));
        }
        for (at, byte) in bytes.iter().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(malformed(offset + at));
            }
        }
        if count == 0 {
            if bytes.len() != 1 || bytes[0] > b'2' {
                return Err(malformed(offset));
            }
            root = bytes[0] - b'0';
        } else if count == 1
            && root < 2
            && (bytes.len() > 2 || (bytes.len() == 2 && bytes > &b"39"[..]))
        {
            return Err(malformed(offset));
        }
        count += 1;
        offset += bytes.len() + 1;
    }
    if count < 2 {
        return Err(malformed(text.len()));
    }
    Ok(root)
}

fn admit(groups: &OwnedVec<u8>, execution: &Memory, offset: u64) -> Result<()> {
    let work = (groups.len() as u64)
        .checked_mul(3)
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, offset))?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, offset))
}

fn multiply(groups: &mut OwnedVec<u8>, digit: u8, execution: &Memory, offset: u64) -> Result<()> {
    admit(groups, execution, offset)?;
    let mut carry = u16::from(digit);
    for group in &mut **groups {
        let current = u16::from(*group) * 10 + carry;
        *group = u8::try_from(current & 0x7f).expect("seven-bit group");
        carry = current >> 7;
    }
    while carry != 0 {
        groups
            .try_push(u8::try_from(carry & 0x7f).expect("seven-bit carry"))
            .map_err(|reason| Error::resource(reason, offset))?;
        carry >>= 7;
    }
    Ok(())
}

fn add_root(groups: &mut OwnedVec<u8>, root: u8, execution: &Memory, offset: u64) -> Result<()> {
    admit(groups, execution, offset)?;
    let mut carry = u16::from(root);
    for group in &mut **groups {
        if carry == 0 {
            break;
        }
        let current = u16::from(*group) + carry;
        *group = u8::try_from(current & 0x7f).expect("seven-bit group");
        carry = current >> 7;
    }
    if carry != 0 {
        groups
            .try_push(u8::try_from(carry).expect("one-bit carry"))
            .map_err(|reason| Error::resource(reason, offset))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryAccount;
    use alloc::sync::Arc;

    fn memory(storage: usize, work: usize) -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(storage, work)))
    }

    #[test]
    fn owned_decimal_oids_preserve_arbitrary_width_and_joint_root() {
        // Values exceed u128 and force decimal multiplication into base128;
        // the packed root offset must be added before encoding and undone by text.
        for text in [
            "0.0",
            "1.39",
            "2.0",
            "2.18446744073709551616",
            "1.2.10889035741470030830827987437816582766593",
        ] {
            let execution = memory(4096, 1_000_000);
            let value = OwnedOid::parse(text, &execution).unwrap();
            let rendered = value.as_oid().text(&execution).unwrap();
            assert_eq!(rendered.as_str(&execution).unwrap(), text);
            drop(rendered);
            assert_eq!(execution.used(), value.bytes.capacity());
            drop(value);
            assert_eq!(execution.used(), 0);
        }
    }

    #[test]
    fn decimal_oid_syntax_refusal_has_no_retained_allocation() {
        // Grammar/root failures are detected before constructing buffers;
        // the original text offset remains available without allocation.
        for (text, offset) in [
            ("", 0),
            ("1", 1),
            ("1.", 2),
            ("3.1", 0),
            ("1.40", 2),
            ("0.100", 2),
            ("2.01", 2),
            ("2.1..3", 4),
            ("2.1x", 3),
            (" 2.1", 0),
        ] {
            let execution = memory(0, 1024);
            let error = OwnedOid::parse(text, &execution).unwrap_err();
            assert_eq!(error.code(), ErrorCode::MalformedOid);
            assert_eq!(error.offset(), offset);
            assert_eq!(execution.used(), 0);
        }
    }

    #[test]
    fn owned_oid_refusal_releases_partial_conversion_and_copy_storage() {
        // Work refusal during a wide-arc multiply releases both output and
        // reusable scratch; a funded source survives rejected deep copies.
        let execution = memory(4096, 350);
        let error =
            OwnedOid::parse("2.1844674407370955161618446744073709551616", &execution).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded(crate::Limit::Work));
        assert_eq!(execution.used(), 0);
        let storage = memory(128, 10_000);
        let original = OwnedOid::parse("1.2.840.113549", &storage).unwrap();
        let used = storage.used();
        let refused = memory(0, 1000);
        assert_eq!(
            OwnedOid::from_oid(original.as_oid(), &refused).unwrap_err(),
            MemoryError::LimitExceeded
        );
        assert_eq!(refused.used(), 0);
        assert_eq!(storage.used(), used);
        assert_eq!(
            original.as_oid(),
            Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d])
        );
    }
}
