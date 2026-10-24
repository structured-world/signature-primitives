//! Original extra fields, with ZIP64's sentinel-dependent field order.

#[cfg(test)]
mod tests;

use super::super::Entry;
use super::super::framing::{Cursor, u16_at, u32_at, u64_at};
use crate::error::{Error, Syntax, Unsupported, syntax};
use structured_asn1::{Span, range::RangeSource};

pub(super) async fn central<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    entry: &mut Entry,
) -> Result<(), Error<S::Error>> {
    let saved = (cursor.at, cursor.end);
    cursor.at = entry.extra.start;
    cursor.end = entry.extra.end();
    let needs64 = entry.decoded == u64::from(u32::MAX)
        || entry.compressed == u64::from(u32::MAX)
        || entry.local == u64::from(u32::MAX)
        || entry.disk == u32::from(u16::MAX);
    while cursor.at < cursor.end {
        let header = cursor.fixed::<4>().await?;
        let span = cursor.skip(u64::from(u16_at(&header, 2)))?;
        match u16_at(&header, 0) {
            0x0001 => {
                if entry.zip64 {
                    return Err(syntax(entry.extra, Syntax::Directory));
                }
                entry.zip64 = true;
                let resume = cursor.at;
                cursor.at = span.start;
                cursor.end = span.end();
                // APPNOTE6.3.3 §4.5.3: only sentinel-valued fields occur,
                // in decoded/compressed/local/disk order, never a guessed tuple.
                if entry.decoded == u64::from(u32::MAX) {
                    entry.decoded = u64_at(&cursor.fixed::<8>().await?, 0);
                }
                if entry.compressed == u64::from(u32::MAX) {
                    entry.compressed = u64_at(&cursor.fixed::<8>().await?, 0);
                }
                if entry.local == u64::from(u32::MAX) {
                    entry.local = u64_at(&cursor.fixed::<8>().await?, 0);
                }
                if entry.disk == u32::from(u16::MAX) {
                    entry.disk = u32_at(&cursor.fixed::<4>().await?, 0);
                }
                if cursor.at != cursor.end {
                    return Err(syntax(span, Syntax::Directory));
                }
                cursor.at = resume;
                cursor.end = entry.extra.end();
            }
            0x7075 => {
                if entry.unicode.is_some() {
                    return Err(syntax(span, Syntax::Directory));
                }
                entry.unicode = Some(span);
            }
            _ => {}
        }
    }
    if needs64 && !entry.zip64 {
        return Err(syntax(entry.extra, Syntax::Directory));
    }
    if entry.disk != 0 {
        return Err(Error::Unsupported {
            range: entry.central,
            kind: Unsupported::Volumes,
        });
    }
    (cursor.at, cursor.end) = saved;
    Ok(())
}

pub(super) struct Local {
    pub(super) decoded: u64,
    pub(super) compressed: u64,
    pub(super) zip64: bool,
    pub(super) unicode: Option<Span>,
}

pub(super) async fn local<S: RangeSource>(
    cursor: &mut Cursor<'_, S>,
    span: Span,
    decoded: u32,
    compressed: u32,
) -> Result<Local, Error<S::Error>> {
    let end = cursor.end;
    cursor.at = span.start;
    cursor.end = span.end();
    let mut result = Local {
        decoded: u64::from(decoded),
        compressed: u64::from(compressed),
        zip64: false,
        unicode: None,
    };
    while cursor.at < cursor.end {
        let header = cursor.fixed::<4>().await?;
        let field = cursor.skip(u64::from(u16_at(&header, 2)))?;
        match u16_at(&header, 0) {
            0x0001 => {
                // APPNOTE6.3.3 §4.5.3 permits fields only for corresponding
                // sentinels and requires BOTH sizes in a local ZIP64 record.
                // https://pkware.cachefly.net/webdocs/APPNOTE.TXT
                if result.zip64
                    || field.length != 16
                    || decoded != u32::MAX
                    || compressed != u32::MAX
                {
                    return Err(syntax(field, Syntax::Local));
                }
                result.zip64 = true;
                let resume = cursor.at;
                cursor.at = field.start;
                let values = cursor.fixed::<16>().await?;
                result.decoded = u64_at(&values, 0);
                result.compressed = u64_at(&values, 8);
                cursor.at = resume;
            }
            0x7075 => {
                if result.unicode.is_some() {
                    return Err(syntax(field, Syntax::Local));
                }
                result.unicode = Some(field);
            }
            _ => {}
        }
    }
    if (decoded == u32::MAX || compressed == u32::MAX) && !result.zip64 {
        return Err(syntax(span, Syntax::Local));
    }
    cursor.end = end;
    Ok(result)
}
