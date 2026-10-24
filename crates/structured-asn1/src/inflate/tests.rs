use super::*;
use crate::memory::{Memory, MemoryAccount};
use crate::{Encoding, Limits, Parser};
use alloc::{sync::Arc, vec::Vec};

fn parser() -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000_000,
            ..Limits::default()
        },
        Memory::new(Arc::new(MemoryAccount::new(256 * 1024, 10_000_000))),
    )
}

#[test]
fn raw_and_zlib_share_exact_bounded_decoder_and_release_storage() {
    // ZIP and PDF differ only in their declared compression envelope. The
    // same core returns borrowed output and consumes the complete envelope.
    let raw = b"\x01\x05\x00\xfa\xffhello";
    let zlib = b"\x78\x01\x01\x05\x00\xfa\xffhello\x06\x2c\x02\x15";
    for (envelope, input) in [
        (Envelope::Raw, raw.as_slice()),
        (Envelope::Zlib, zlib.as_slice()),
    ] {
        let parser = parser();
        let work = parser.execution_in(parser.memory());
        let mut decoder = Inflater::new(envelope, &work).unwrap();
        let mut at = 0;
        let mut output = Vec::new();
        loop {
            let next = decoder.step(&input[at..], false, usize::MAX).unwrap();
            at += next.consumed;
            output.extend_from_slice(next.output);
            if next.progress == Progress::Done {
                break;
            }
        }
        assert_eq!(at, input.len());
        assert_eq!(output, b"hello");
        assert!(matches!(decoder.step(&[], false, 1), Err(Error::State)));
        assert!(parser.memory().used() > DICTIONARY);
        drop(decoder);
        assert_eq!(parser.memory().used(), 0);
    }
}

#[test]
fn long_stored_block_crosses_input_and_dictionary_windows_without_loss() {
    // A single DEFLATE block may exceed both caller chunk size and the 32 KiB
    // dictionary. Every byte remains in order, without a whole-output owner.
    let parser = parser();
    let work = parser.execution_in(parser.memory());
    let mut input = Vec::from([1_u8, 0xff, 0xff, 0, 0]);
    input.extend((0..65535_u32).map(|index| index.to_le_bytes()[0]));
    let mut decoder = Inflater::new(Envelope::Raw, &work).unwrap();
    let mut at = 0;
    let mut produced = 0_u32;
    loop {
        let next = decoder.step(&input[at..], false, usize::MAX).unwrap();
        assert!(next.consumed <= CHUNK);
        assert!(next.output.len() <= CHUNK);
        at += next.consumed;
        for byte in next.output {
            assert_eq!(*byte, produced.to_le_bytes()[0]);
            produced += 1;
        }
        if next.progress == Progress::Done {
            break;
        }
    }
    assert_eq!(at, input.len());
    assert_eq!(produced, 65535);
}

#[test]
fn output_exhaustion_and_truncation_remain_distinct_terminal_failures() {
    // Exhausted output is a format resource limit, not malformed DEFLATE.
    // Neither refusal can be retried into success on the same decoder.
    let parser = parser();
    let work = parser.execution_in(parser.memory());
    let mut decoder = Inflater::new(Envelope::Raw, &work).unwrap();
    assert!(matches!(
        decoder.step(b"\x01\x01\x00\xfe\xffx", false, 0),
        Err(Error::OutputLimit)
    ));
    assert!(matches!(decoder.step(&[], false, 99), Err(Error::State)));
    drop(decoder);
    let mut decoder = Inflater::new(Envelope::Raw, &work).unwrap();
    assert!(matches!(
        decoder.step(b"\x01\x02\x00\xfd\xffx", false, 99),
        Err(Error::Malformed { produced: 1 })
    ));
    assert!(matches!(decoder.step(b"y", false, 99), Err(Error::State)));
}

#[test]
fn bad_zlib_checksum_reports_discarded_output_for_aggregate_accounting() {
    // A failed envelope still performed decoding. The format must bill these
    // bytes without exposing them as successfully decoded output.
    let parser = parser();
    let work = parser.execution_in(parser.memory());
    let mut decoder = Inflater::new(Envelope::Zlib, &work).unwrap();
    assert!(matches!(
        decoder.step(
            b"\x78\x01\x01\x05\x00\xfa\xffhello\x06\x2c\x02\x16",
            false,
            99
        ),
        Err(Error::Malformed { produced: 5 })
    ));
    assert!(matches!(decoder.step(&[], false, 99), Err(Error::State)));
}

#[test]
fn captured_execution_refuses_before_block_work_and_releases_both_allocations() {
    // Decoder steps use the original captured execution, with no argument
    // allowing a wider account to replace it after construction.
    let parser = parser();
    let work = parser.execution_in(parser.memory());
    let mut decoder = Inflater::new(Envelope::Raw, &work).unwrap();
    work.charge_work(work.work_remaining() as u64).unwrap();
    assert!(matches!(
        decoder.step(b"\x03\x00", false, 99),
        Err(Error::Resource(MemoryError::WorkExceeded))
    ));
    assert!(matches!(decoder.step(&[], false, 99), Err(Error::State)));
    drop(decoder);
    assert_eq!(parser.memory().used(), 0);
}
