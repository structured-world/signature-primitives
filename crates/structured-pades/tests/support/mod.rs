//! Trusted small PDF writers shared by source/permission integration tests.

extern crate std;
use self::std::io::Write;
use alloc::vec::Vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the slice fixture performs no suspended acquisition"),
    }
}

pub struct Pdf {
    pub bytes: Vec<u8>,
    xref: usize,
    size: usize,
    free: alloc::collections::BTreeSet<usize>,
}
impl Pdf {
    pub fn new(objects: &[(usize, &[u8])]) -> Self {
        let size = objects
            .iter()
            .map(|value| value.0)
            .max()
            .expect("fixture root")
            + 1;
        let mut bytes = b"%PDF-1.7\n".to_vec();
        let mut offsets = alloc::vec![0; size];
        for &(number, body) in objects {
            offsets[number] = bytes.len();
            writeln!(bytes, "{number} 0 obj").unwrap();
            bytes.extend_from_slice(body);
            writeln!(bytes, "\nendobj").unwrap();
        }
        let xref = bytes.len();
        writeln!(bytes, "xref\n0 {size}\n0000000000 65535 f ").unwrap();
        for offset in &offsets[1..] {
            assert!(*offset > 0, "base fixture object numbers are contiguous");
            writeln!(bytes, "{offset:010} 00000 n ").unwrap();
        }
        writeln!(
            bytes,
            "trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
        )
        .unwrap();
        Self {
            bytes,
            xref,
            size,
            free: alloc::collections::BTreeSet::new(),
        }
    }
    pub fn append(&mut self, objects: &[(usize, &[u8])]) {
        let old_size = self.size;
        let mut offsets = Vec::new();
        for &(number, body) in objects {
            self.size = self.size.max(number + 1);
            offsets.push((number, self.bytes.len()));
            writeln!(self.bytes, "{number} 0 obj").unwrap();
            self.bytes.extend_from_slice(body);
            writeln!(self.bytes, "\nendobj").unwrap();
        }
        for number in old_size..self.size {
            self.free.insert(number);
        }
        for &(number, _) in objects {
            self.free.remove(&number);
        }
        let xref = self.bytes.len();
        writeln!(self.bytes, "xref").unwrap();
        for (number, offset) in offsets {
            writeln!(self.bytes, "{number} 1\n{offset:010} 00000 n ").unwrap();
        }
        let mut free = self.free.iter().peekable();
        writeln!(
            self.bytes,
            "0 1\n{:010} 65535 f ",
            free.peek().map_or(0, |&&number| number)
        )
        .unwrap();
        while let Some(&number) = free.next() {
            writeln!(
                self.bytes,
                "{number} 1\n{:010} 00000 f ",
                free.peek().map_or(0, |&&number| number)
            )
            .unwrap();
        }
        writeln!(
            self.bytes,
            "trailer\n<< /Size {} /Root 1 0 R /Prev {} >>\nstartxref\n{xref}\n%%EOF",
            self.size, self.xref
        )
        .unwrap();
        self.xref = xref;
    }
}
