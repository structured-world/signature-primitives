//! Original EOF records, without guessing an appended ZIP's base offset.

#[cfg(test)]
mod tests;

use super::super::framing::{Cursor, u16_at, u32_at, u64_at};
use crate::error::{Error, Syntax, Unsupported, resource, syntax};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::{RangeSource, Window},
};

pub(super) struct Directory {
    pub(super) range: Span,
    pub(super) comment: Span,
    pub(super) count: u64,
}

pub(super) async fn candidates<S: RangeSource, W: Work>(
    window: &mut Window<'_, S>,
    work: &W,
) -> Result<OwnedVec<u64, W>, Error<S::Error>> {
    let length = window.stamp().length;
    let minimum = length - length.min(65_557);
    let mut end = length;
    let mut suffix = [0_u8; 3];
    let mut suffix_len = 0;
    let mut found = work.vector();
    while end > minimum {
        let bytes = window.chunk_before(end, minimum).await?;
        let range = Span {
            start: end - bytes.len() as u64,
            length: bytes.len() as u64,
        };
        work.charge_work(bytes.len() as u64 * 4 + 1)
            .map_err(|cause| resource(range, cause))?;
        scan_chunk(bytes, &suffix[..suffix_len], |at| {
            found
                .try_push(range.start + at as u64)
                .map_err(|cause| resource(range, cause))
        })?;
        let mut next = [0_u8; 3];
        let count = bytes.len().min(3);
        next[..count].copy_from_slice(&bytes[..count]);
        let extra = suffix_len.min(3 - count);
        next[count..count + extra].copy_from_slice(&suffix[..extra]);
        suffix = next;
        suffix_len = count + extra;
        end = range.start;
    }
    Ok(found)
}

fn scan_chunk<E>(
    bytes: &[u8],
    suffix: &[u8],
    mut record: impl FnMut(usize) -> Result<(), E>,
) -> Result<(), E> {
    const REST: &[u8; 3] = b"K\x05\x06";
    // On x86_64, word setup costs more than scanning an empty archive's
    // 22-byte footer directly. Use the same byte scan as the leading fragment.
    let split = if cfg!(target_arch = "x86_64") && bytes.len() < 32 {
        bytes.len()
    } else {
        bytes.len() % 8
    };
    let (head, full) = bytes.split_at(split);
    debug_assert!(suffix.len() <= 3);
    let trailing = match *suffix {
        [a, b, c] => [0, a, b, c],
        [a, b] => [0, a, b, 0],
        [a] => [0, a, 0, 0],
        _ => [0; 4],
    };
    let mut next = u64::from(u32::from_be_bytes(trailing));
    for (index, group) in full.as_chunks::<8>().0.iter().enumerate().rev() {
        // Compare four overlapping byte lanes, using the following word's
        // first three octets where a marker crosses the chunk boundary.
        let word = u64::from_be_bytes(*group);
        let different = (word ^ u64::from_be_bytes([b'P'; 8]))
            | (((word << 8) | (next >> 16)) ^ u64::from_be_bytes([b'K'; 8]))
            | (((word << 16) | (next >> 8)) ^ u64::from_be_bytes([5; 8]))
            | (((word << 24) | next) ^ u64::from_be_bytes([6; 8]));
        next = word >> 40;
        // Isolate exact zero lanes without cross-lane carries.
        let lows = 0x7f7f_7f7f_7f7f_7f7f;
        let mut matches = !(((different & lows) + lows) | different | lows);
        while matches != 0 {
            let offset = 7 - matches.trailing_zeros() as usize / 8;
            record(head.len() + index * 8 + offset)?;
            matches &= matches - 1;
        }
    }
    for (at, &byte) in head.iter().enumerate().rev() {
        if byte != b'P' {
            continue;
        }
        let rest = &bytes[at + 1..];
        if rest.starts_with(REST)
            || (REST.starts_with(rest) && suffix.starts_with(&REST[rest.len()..]))
        {
            record(at)?;
        }
    }
    Ok(())
}

pub(super) async fn read<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    at: u64,
) -> Result<Directory, Error<S::Error>> {
    cursor.at = at;
    let fixed = cursor.fixed::<22>().await?;
    let range = Span {
        start: at,
        length: 22,
    };
    if u32_at(&fixed, 0) != 0x0605_4b50 || u64::from(u16_at(&fixed, 20)) != cursor.end - cursor.at {
        return Err(syntax(range, Syntax::End));
    }
    let comment = Span {
        start: cursor.at,
        length: cursor.end - cursor.at,
    };
    if u16_at(&fixed, 4) != 0 || u16_at(&fixed, 6) != 0 {
        return Err(Error::Unsupported {
            range,
            kind: Unsupported::Volumes,
        });
    }
    let count = u16_at(&fixed, 10);
    let size = u32_at(&fixed, 12);
    let offset = u32_at(&fixed, 16);
    let needs64 = count == u16::MAX || size == u32::MAX || offset == u32::MAX;
    if at >= 20 {
        cursor.at = at - 20;
        let locator = cursor.fixed::<20>().await?;
        if u32_at(&locator, 0) == 0x0706_4b50 {
            return zip64(cursor, &locator, &fixed, at - 20, comment).await;
        }
    }
    if needs64 || u16_at(&fixed, 8) != count {
        return Err(syntax(range, Syntax::Directory));
    }
    let range = bounded(u64::from(offset), u64::from(size), at)?;
    Ok(Directory {
        range,
        comment,
        count: u64::from(count),
    })
}

async fn zip64<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    locator: &[u8; 20],
    classic: &[u8; 22],
    locator_at: u64,
    comment: Span,
) -> Result<Directory, Error<S::Error>> {
    let location = Span {
        start: locator_at,
        length: 20,
    };
    if u32_at(locator, 4) != 0 || u32_at(locator, 16) != 1 {
        return Err(Error::Unsupported {
            range: location,
            kind: Unsupported::Volumes,
        });
    }
    let at = u64_at(locator, 8);
    // The minimum ZIP64 record precedes the locator (APPNOTE §4.3.14).
    // Establish that enclosure before its fixed-size acquisition/copy.
    bounded(at, 56, locator_at)?;
    cursor.at = at;
    let record = cursor.fixed::<56>().await?;
    let range = Span {
        start: at,
        length: 56,
    };
    if u32_at(&record, 0) != 0x0606_4b50 || u64_at(&record, 4) < 44 {
        return Err(syntax(range, Syntax::Directory));
    }
    let size = u64_at(&record, 4)
        .checked_add(12)
        .ok_or_else(|| syntax(range, Syntax::Bounds))?;
    let whole = bounded(at, size, locator_at)?;
    if whole.end() != locator_at {
        return Err(syntax(whole, Syntax::Directory));
    }
    let needed = u16_at(&record, 14);
    if needed > 45 {
        return Err(Error::Unsupported {
            range,
            kind: Unsupported::DirectoryVersion(needed),
        });
    }
    if u32_at(&record, 16) != 0 || u32_at(&record, 20) != 0 {
        return Err(Error::Unsupported {
            range,
            kind: Unsupported::Volumes,
        });
    }
    let count = u64_at(&record, 32);
    if u64_at(&record, 24) != count {
        return Err(syntax(range, Syntax::Directory));
    }
    let size = u64_at(&record, 40);
    let offset = u64_at(&record, 48);
    for value in [8, 10] {
        let declared = u16_at(classic, value);
        if declared != u16::MAX && u64::from(declared) != count {
            return Err(syntax(range, Syntax::Directory));
        }
    }
    for (field, actual) in [(12, size), (16, offset)] {
        let declared = u32_at(classic, field);
        if declared != u32::MAX && u64::from(declared) != actual {
            return Err(syntax(range, Syntax::Directory));
        }
    }
    // APPNOTE6.3.3 §4.3.14.3: each extensible V1 item has a 2+4 byte header.
    while cursor.at < whole.end() {
        let header = cursor.fixed::<6>().await?;
        let length = u64::from(u32_at(&header, 2));
        if cursor.at > whole.end() || length > whole.end() - cursor.at {
            return Err(syntax(whole, Syntax::Directory));
        }
        cursor.skip(length)?;
    }
    Ok(Directory {
        range: bounded(offset, size, at)?,
        comment,
        count,
    })
}

fn bounded<E>(start: u64, length: u64, end: u64) -> Result<Span, Error<E>> {
    let range = Span { start, length };
    if start > end || length > end - start {
        return Err(syntax(range, Syntax::Bounds));
    }
    Ok(range)
}
