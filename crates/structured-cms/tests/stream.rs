//! Sticky refusal and one-pass public streaming behavior.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_cms::stream::{self, Receiver, Sink, Source, StreamError};

struct Input {
    calls: usize,
    partial: bool,
}
impl Source for Input {
    type Error = &'static str;
    fn stream<W: Work>(&mut self, receiver: &mut impl Receiver, _: &W) -> Result<(), Self::Error> {
        self.calls += 1;
        // Deliberately ignore a refusal to exercise the driver's sticky guard.
        let _ = receiver.write(b"a");
        let _ = receiver.write(b"b");
        if self.partial {
            Err("incomplete")
        } else {
            Ok(())
        }
    }
}

struct Output {
    calls: usize,
    fail: bool,
}
impl Sink for Output {
    type Error = &'static str;
    fn write<W: Work>(&mut self, _: &[u8], _: &W) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.fail {
            Err("provider failure")
        } else {
            Ok(())
        }
    }
}

#[test]
fn ignored_callback_refusal_is_sticky_and_keeps_original_cause() {
    // A source cannot turn callback refusal into successful complete payload.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
    let mut source = Input {
        calls: 0,
        partial: false,
    };
    let mut sink = Output {
        calls: 0,
        fail: true,
    };
    assert!(matches!(
        stream::run(&mut source, &mut sink, &memory, "content", 400),
        Err(StreamError::Callback("provider failure"))
    ));
    assert_eq!(source.calls, 1);
    assert_eq!(sink.calls, 1);
}

#[test]
fn incomplete_payload_never_reports_success_after_a_processed_prefix() {
    // EOF failure remains acquisition failure, independently of valid prefix processing.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
    let mut source = Input {
        calls: 0,
        partial: true,
    };
    let mut sink = Output {
        calls: 0,
        fail: false,
    };
    assert!(matches!(
        stream::run(&mut source, &mut sink, &memory, "content", 400),
        Err(StreamError::Source("incomplete"))
    ));
    assert_eq!(source.calls, 1);
    assert_eq!(sink.calls, 2);
}

#[test]
fn unfunded_dispatch_does_not_call_source_or_sink() {
    // Input-derived acquisition must not begin after common admission refuses.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let mut source = Input {
        calls: 0,
        partial: false,
    };
    let mut sink = Output {
        calls: 0,
        fail: false,
    };
    let error = stream::run(&mut source, &mut sink, &memory, "content", 400).unwrap_err();
    assert!(
        matches!(error, StreamError::Processing(error) if error.is_resource() && error.offset() == 400)
    );
    assert_eq!(source.calls, 0);
    assert_eq!(sink.calls, 0);
}

#[test]
fn parsed_octets_feed_original_payload_once_in_the_current_domain() {
    // The real parsed source is wired to the stream driver; BER wrapper bytes
    // never reach processing and deferred work does not debit the old account.
    use structured_asn1::Parser;
    use structured_cms::Octets;
    struct Collected {
        bytes: [u8; 16],
        length: usize,
        calls: usize,
    }
    impl Sink for Collected {
        type Error = structured_asn1::memory::MemoryError;
        fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
            execution.charge_work(bytes.len() as u64)?;
            self.bytes[self.length..self.length + bytes.len()].copy_from_slice(bytes);
            self.length += bytes.len();
            self.calls += 1;
            Ok(())
        }
    }
    let old = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let parser = Parser::ber(old.clone());
    let encoded = [0x24, 6, 4, 1, b'a', 4, 1, b'b'];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let content = Octets::read(&reader, &element, "content").unwrap();
    let before = old.work_used();
    let mut source = &content;
    let mut sink = Collected {
        bytes: [0; 16],
        length: 0,
        calls: 0,
    };
    stream::run(&mut source, &mut sink, &current, "content", 400).unwrap();
    assert_eq!(&sink.bytes[..sink.length], b"ab");
    assert_eq!(sink.calls, 2);
    assert_eq!(old.work_used(), before);
    assert_eq!(current.used(), 0);
    assert_eq!(current.work_used(), 7);
}
