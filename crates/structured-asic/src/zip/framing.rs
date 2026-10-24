//! Small fixed ZIP fields over the shared bounded source window.

use crate::error::{Error, Syntax, resource, syntax};
use structured_asn1::{
    Span,
    memory::Work,
    range::{RangeSource, Window},
};

pub(super) struct Cursor<'q, S: RangeSource> {
    pub(super) window: Window<'q, S>,
    pub(super) at: u64,
    pub(super) end: u64,
}
impl<S: RangeSource> Cursor<'_, S> {
    pub(super) async fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error<S::Error>> {
        let result = fixed_at(&mut self.window, self.at, self.end).await?;
        self.at += N as u64;
        Ok(result)
    }
    pub(super) fn skip(&mut self, length: u64) -> Result<Span, Error<S::Error>> {
        let range = Span {
            start: self.at,
            length,
        };
        if self.at > self.end || length > self.end - self.at {
            return Err(syntax(range, Syntax::Bounds));
        }
        self.at += length;
        Ok(range)
    }
}

pub(super) async fn fixed_at<const N: usize, S: RangeSource>(
    window: &mut Window<'_, S>,
    offset: u64,
    end: u64,
) -> Result<[u8; N], Error<S::Error>> {
    let range = Span {
        start: offset,
        length: N as u64,
    };
    if offset > end || N as u64 > end - offset {
        return Err(syntax(range, Syntax::Bounds));
    }
    window
        .execution()
        .charge_work(N as u64)
        .map_err(|cause| resource(range, cause))?;
    let mut result = [0; N];
    let mut written = 0;
    while written < N {
        let bytes = window.chunk_at(offset + written as u64, end).await?;
        let count = bytes.len().min(N - written);
        result[written..written + count].copy_from_slice(&bytes[..count]);
        written += count;
    }
    Ok(result)
}

pub(super) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("fixed field bounds"))
}
pub(super) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed field bounds"))
}
pub(super) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed field bounds"))
}
