//! Independent ZIP framing fixtures, not a second production encoder.

use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::sync::Arc;
use structured_asn1::{
    memory::{Memory, MemoryAccount, Work},
    range::{RangeSource, ReadError, Stamp},
    source::Snapshot,
};

pub fn finish<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..1_000_000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
    }
    panic!("bounded in-memory fixture did not complete");
}

pub fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(4 * 1024 * 1024, 100_000_000)))
}

/// Each read really suspends; arbitrary positive short reads remain legal.
pub struct Input {
    pub bytes: Vec<u8>,
    pub maximum: usize,
    pub calls: Cell<usize>,
    pub largest: Cell<usize>,
    pub generation: Cell<u64>,
}
impl Input {
    pub fn new(bytes: Vec<u8>, maximum: usize) -> Self {
        Self {
            bytes,
            maximum,
            calls: Cell::new(0),
            largest: Cell::new(0),
            generation: Cell::new(1),
        }
    }
}
impl RangeSource for Input {
    type Document = usize;
    type Generation = u64;
    type Error = core::convert::Infallible;
    fn stamp(&self) -> Stamp<usize, u64> {
        Stamp {
            snapshot: Snapshot {
                document: core::ptr::from_ref(self).addr(),
                generation: self.generation.get(),
            },
            length: self.bytes.len() as u64,
        }
    }
    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> Result<usize, ReadError<Self::Error>> {
        let mut pending = true;
        core::future::poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        self.calls.set(self.calls.get() + 1);
        self.largest.set(self.largest.get().max(output.len()));
        let input = self
            .bytes
            .get(usize::try_from(offset).unwrap()..)
            .unwrap_or_default();
        let count = input.len().min(output.len()).min(self.maximum);
        output[..count].copy_from_slice(&input[..count]);
        Ok(count)
    }
}

#[derive(Clone, Copy)]
pub enum Descriptor {
    None,
    Unsigned,
    Signed,
}
pub struct File<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub comment: &'a [u8],
    pub deflate: bool,
    pub zip64: bool,
    pub descriptor: Descriptor,
    pub flags: u16,
    pub crc: Option<u32>,
}
impl<'a> File<'a> {
    pub fn stored(name: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            comment: b"",
            deflate: false,
            zip64: false,
            descriptor: Descriptor::None,
            flags: 0x800,
            crc: None,
        }
    }
}
pub struct Built {
    pub bytes: Vec<u8>,
    pub central: Vec<usize>,
    pub local: Vec<usize>,
    pub data: Vec<usize>,
    pub end: usize,
}
fn u16le(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn u32le(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn u64le(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
pub fn set32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

// RFC1951 §3.2.4 stored blocks deliberately avoid the production inflater's
// encoder implementation, including its choices of block sizes and EOF.
fn deflate(input: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if input.is_empty() {
        bytes.extend_from_slice(&[1, 0, 0, 255, 255]);
    }
    for (index, chunk) in input.chunks(32768).enumerate() {
        bytes.push(u8::from((index + 1) * 32768 >= input.len()));
        let length = u16::try_from(chunk.len()).unwrap();
        u16le(&mut bytes, length);
        u16le(&mut bytes, !length);
        bytes.extend_from_slice(chunk);
    }
    bytes
}

/// APPNOTE6.3.3 §4.3 records are written literally, with optional ZIP64 and
/// both descriptor spellings. All offsets are returned for precise mutations.
#[expect(
    clippy::too_many_lines,
    reason = "independent ZIP oracle writes local, central and ZIP64 records in one ordered fixture transaction"
)]
pub fn zip(files: &[File<'_>]) -> Built {
    let mut result = Built {
        bytes: Vec::new(),
        central: Vec::new(),
        local: Vec::new(),
        data: Vec::new(),
        end: 0,
    };
    let mut encoded = Vec::new();
    for file in files {
        let content = if file.deflate {
            deflate(file.data)
        } else {
            file.data.to_vec()
        };
        let crc = file.crc.unwrap_or_else(|| crc32fast::hash(file.data));
        let descriptor = !matches!(file.descriptor, Descriptor::None);
        let flags = file.flags | if descriptor { 8 } else { 0 };
        let size = u32::try_from(file.data.len()).unwrap();
        let compressed = u32::try_from(content.len()).unwrap();
        result.local.push(result.bytes.len());
        let bytes = &mut result.bytes;
        u32le(bytes, 0x0403_4b50);
        u16le(bytes, if file.zip64 { 45 } else { 20 });
        u16le(bytes, flags);
        u16le(bytes, if file.deflate { 8 } else { 0 });
        u16le(bytes, 0);
        u16le(bytes, 0x5c21);
        u32le(bytes, if descriptor { 0 } else { crc });
        u32le(
            bytes,
            if file.zip64 {
                u32::MAX
            } else if descriptor {
                0
            } else {
                compressed
            },
        );
        u32le(
            bytes,
            if file.zip64 {
                u32::MAX
            } else if descriptor {
                0
            } else {
                size
            },
        );
        u16le(bytes, u16::try_from(file.name.len()).unwrap());
        u16le(bytes, if file.zip64 { 20 } else { 0 });
        bytes.extend_from_slice(file.name);
        if file.zip64 {
            u16le(bytes, 1);
            u16le(bytes, 16);
            u64le(bytes, u64::from(size));
            u64le(bytes, u64::from(compressed));
        }
        result.data.push(bytes.len());
        bytes.extend_from_slice(&content);
        if descriptor {
            if matches!(file.descriptor, Descriptor::Signed) {
                u32le(bytes, 0x0807_4b50);
            }
            u32le(bytes, crc);
            if file.zip64 {
                u64le(bytes, u64::from(compressed));
                u64le(bytes, u64::from(size));
            } else {
                u32le(bytes, compressed);
                u32le(bytes, size);
            }
        }
        encoded.push((compressed, size, crc, flags));
    }
    let start = result.bytes.len();
    for (index, file) in files.iter().enumerate() {
        let (compressed, size, crc, flags) = encoded[index];
        result.central.push(result.bytes.len());
        let bytes = &mut result.bytes;
        u32le(bytes, 0x0201_4b50);
        u16le(bytes, 45);
        u16le(bytes, if file.zip64 { 45 } else { 20 });
        u16le(bytes, flags);
        u16le(bytes, if file.deflate { 8 } else { 0 });
        u16le(bytes, 0);
        u16le(bytes, 0x5c21);
        u32le(bytes, crc);
        u32le(bytes, if file.zip64 { u32::MAX } else { compressed });
        u32le(bytes, if file.zip64 { u32::MAX } else { size });
        u16le(bytes, u16::try_from(file.name.len()).unwrap());
        u16le(bytes, if file.zip64 { 20 } else { 0 });
        u16le(bytes, u16::try_from(file.comment.len()).unwrap());
        u16le(bytes, 0);
        u16le(bytes, 0);
        u32le(bytes, 0);
        u32le(bytes, u32::try_from(result.local[index]).unwrap());
        bytes.extend_from_slice(file.name);
        if file.zip64 {
            u16le(bytes, 1);
            u16le(bytes, 16);
            u64le(bytes, u64::from(size));
            u64le(bytes, u64::from(compressed));
        }
        bytes.extend_from_slice(file.comment);
    }
    let length = result.bytes.len() - start;
    let zip64 = files.iter().any(|file| file.zip64);
    let bytes = &mut result.bytes;
    if zip64 {
        let end64 = bytes.len();
        u32le(bytes, 0x0606_4b50);
        u64le(bytes, 44);
        u16le(bytes, 45);
        u16le(bytes, 45);
        u32le(bytes, 0);
        u32le(bytes, 0);
        u64le(bytes, files.len() as u64);
        u64le(bytes, files.len() as u64);
        u64le(bytes, length as u64);
        u64le(bytes, start as u64);
        u32le(bytes, 0x0706_4b50);
        u32le(bytes, 0);
        u64le(bytes, end64 as u64);
        u32le(bytes, 1);
    }
    result.end = bytes.len();
    u32le(bytes, 0x0605_4b50);
    u16le(bytes, 0);
    u16le(bytes, 0);
    let count = if zip64 {
        u16::MAX
    } else {
        u16::try_from(files.len()).unwrap()
    };
    u16le(bytes, count);
    u16le(bytes, count);
    u32le(
        bytes,
        if zip64 {
            u32::MAX
        } else {
            u32::try_from(length).unwrap()
        },
    );
    u32le(
        bytes,
        if zip64 {
            u32::MAX
        } else {
            u32::try_from(start).unwrap()
        },
    );
    u16le(bytes, 0);
    result
}
