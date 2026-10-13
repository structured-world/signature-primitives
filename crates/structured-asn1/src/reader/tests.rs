use super::Parser;
use crate::error::{ErrorCode, Limit};
use crate::length::Encoding;
use crate::limits::Limits;
use crate::tag::{Tag, universal};

/// SEQUENCE { INTEGER 1, INTEGER 2 }
const TWO_INTEGERS: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];

#[test]
fn execution_rebinding_keeps_old_storage_and_charges_new_descendants() {
    // A retained path remains owned by A. Reading, entering, copying and
    // error reporting after rebinding must use B without moving A's charge.
    let original = crate::test_memory();
    let execution = crate::test_memory();
    let parser = Parser::der(original.clone());
    let bytes = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
    let mut root = parser.read(&bytes, 401).unwrap();
    let outer = root.next_element().unwrap().unwrap();
    let inside = root.enter(&outer).unwrap();
    let held = original.used();
    let before = original.work_used();
    let mut inside = inside.with_execution(&execution);
    assert_eq!(original.used(), held);
    let inner = inside.next_element().unwrap().unwrap();
    let mut child = inside.enter(&inner).unwrap();
    let copy = child.try_clone().unwrap();
    let reread = inside.reread(&inner, Encoding::Der).unwrap();
    assert!(child.memory().same_account(&execution));
    assert!(copy.memory().same_account(&execution));
    assert!(reread.memory().same_account(&execution));
    assert_eq!(child.read_integer().unwrap().as_u64(), Some(1));
    assert_eq!(original.work_used(), before);
    assert_eq!(original.used(), held);
    assert!(execution.used() > 0);
    drop((child, copy, reread));
    assert_eq!(execution.used(), 0);
    drop(inside);
    assert_eq!(original.used(), 0);
}

#[test]
fn execution_rebinding_preserves_session_work_ceiling() {
    // A new aggregate domain cannot reset the parser session's cumulative
    // local ceiling. Failure keeps the original document offset.
    let original = crate::test_memory();
    let execution = crate::test_memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            // Two header octets plus the retained root path's 17 work units.
            max_work: 19,
            ..Limits::default()
        },
        original.clone(),
    );
    let mut reader = parser.read(&TWO_INTEGERS, 402).unwrap();
    let sequence = reader.next_element().unwrap().unwrap();
    let inside = reader.enter(&sequence).unwrap();
    let before = original.work_used();
    let mut inside = inside.with_execution(&execution);
    let error = inside.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
    assert_eq!(error.offset(), 404);
    // A paid the original header and retained path. The exhausted local
    // ceiling also refuses diagnostic copying before allocating in B.
    assert_eq!(original.work_used(), before);
    assert_eq!(execution.used(), 0);
    assert_eq!(
        error.path().unavailable(),
        Some(crate::memory::MemoryError::WorkExceeded)
    );
}

#[test]
fn lazy_nested_read_and_ber_scratch_use_the_selected_execution_domain() {
    // Lazy creation must select B before any deferred scan. A zero-work B
    // rejects DER at its original offset; BER scratch cannot allocate in A
    // when B permits work but no storage.
    use crate::memory::{Memory, MemoryAccount};
    let original = crate::test_memory();
    let parser = Parser::ber(original.clone());
    let no_work = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
    let mut lazy = parser
        .read_nested_in(&TWO_INTEGERS, 501, Encoding::Der, 3, &no_work)
        .unwrap();
    assert_eq!(lazy.depth(), 4);
    let error = lazy.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
    assert_eq!(error.offset(), 501);
    assert_eq!(original.work_used(), 0);

    let no_storage = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 1000)));
    let bytes = [0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0];
    let mut lazy = parser
        .read_nested_in(&bytes, 502, Encoding::Ber, 1, &no_storage)
        .unwrap();
    let error = lazy.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Memory));
    assert_eq!(original.used(), 0);
    assert_eq!(original.work_used(), 0);
    assert_eq!(no_storage.used(), 0);
    assert!(no_storage.work_used() > 0);
}

#[test]
fn malformed_headers_cannot_run_before_work_admission() {
    // A malformed first byte used to return before the late header charge,
    // letting repeated failing reads execute outside a zero work allowance.
    let memory = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(0, 0),
    ));
    let parser = Parser::der(memory);
    let mut reader = parser.read(&[0x20, 0], 42).unwrap();
    let error = reader.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
    assert_eq!(error.offset(), 42);
}

#[test]
fn separate_parsers_share_cumulative_work() {
    // Sequential parser construction must not replenish the operation allowance.
    let memory = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(0, 4),
    ));
    for _ in 0..2 {
        let parser = Parser::der(memory.clone());
        parser.read(&[0x05, 0], 0).unwrap().next_element().unwrap();
    }
    let parser = Parser::der(memory.clone());
    let error = parser
        .read(&[0x05, 0], 51)
        .unwrap()
        .next_element()
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
    assert_eq!(error.offset(), 51);
    assert_eq!(memory.work_used(), 4);
}

#[test]
fn reader_copy_is_fallible_and_preserves_original_storage() {
    // Retaining a second nested reader must reserve its own path, rather than
    // let Clone allocate outside the operation ceiling.
    let memory = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(16, 1024),
    ));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&TWO_INTEGERS, 51).unwrap();
    let sequence = reader.next_element().unwrap().unwrap();
    let mut inside = reader.enter(&sequence).unwrap();
    assert_eq!(memory.used(), 16);
    let error = inside.try_clone().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Memory));
    assert_eq!(error.offset(), 53);
    assert_eq!(
        error.path().unavailable(),
        Some(crate::memory::MemoryError::LimitExceeded)
    );
    assert!(!error.path().is_root());
    assert_eq!(memory.used(), 16);
    assert_eq!(inside.next_element().unwrap().unwrap().contents(), &[1]);
    drop(inside);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retained_diagnostic_path_outlives_the_parser() {
    // Owning an error after parsing finishes must retain its path's allocation
    // charge until the error itself is dropped.
    let memory = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(16, 1024),
    ));
    let error = {
        let parser = Parser::der(memory.clone());
        let mut reader = parser.read(&[0x05, 0], 51).unwrap();
        reader.read_integer().unwrap_err()
    };
    assert_eq!(error.code(), ErrorCode::UnexpectedTag);
    assert_eq!(error.path().indices(), &[0]);
    assert_eq!(memory.used(), 16);
    drop(error);
    assert_eq!(memory.used(), 0);
}

#[test]
fn ber_scan_refuses_stack_growth_before_allocation() {
    // Indefinite scanning uses an explicit charged stack. A zero storage
    // allowance cannot be bypassed by deeply nested BER containers.
    let memory = crate::memory::Memory::new(alloc::sync::Arc::new(
        crate::memory::MemoryAccount::new(0, 1024),
    ));
    let parser = Parser::ber(memory.clone());
    let mut reader = parser
        .read(&[0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0], 51)
        .unwrap();
    let error = reader.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Memory));
    assert_eq!(error.offset(), 53);
    assert_eq!(memory.used(), 0);
    assert_eq!(
        error.path().unavailable(),
        Some(crate::memory::MemoryError::LimitExceeded)
    );
}

#[test]
fn reads_a_sequence_and_its_members() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();

    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    assert!(reader.is_empty());

    let mut inside = reader.enter(&sequence).unwrap();
    let first = inside.expect(Tag::primitive(universal::INTEGER)).unwrap();
    let second = inside.expect(Tag::primitive(universal::INTEGER)).unwrap();

    assert_eq!(first.contents(), &[0x01]);
    assert_eq!(second.contents(), &[0x02]);
    assert!(inside.is_empty());
    assert_eq!(second.index(), 1);
}

#[test]
fn spans_locate_the_bytes_a_signature_would_cover() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    // The whole element, header included: what a signature over the encoded
    // element covers.
    assert_eq!(sequence.span().start, 0);
    assert_eq!(sequence.span().length, 8);
    assert_eq!(sequence.span().end(), 8);

    // The contents alone.
    assert_eq!(sequence.contents_span().start, 2);
    assert_eq!(sequence.contents_span().length, 6);

    let mut inside = reader.enter(&sequence).unwrap();
    let second = {
        let _ = inside.next_element().unwrap();
        inside.next_element().unwrap().unwrap()
    };
    assert_eq!(second.span().start, 5);
    assert_eq!(second.contents_span().start, 7);
}

#[test]
fn a_base_offset_makes_spans_refer_to_the_whole_document() {
    // The parser is handed a window that starts 1000 bytes into a document.
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 1000).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    assert_eq!(sequence.span().start, 1000);
    assert_eq!(sequence.contents_span().start, 1002);
}

#[test]
fn contents_borrow_from_the_document_rather_than_copying_it() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    // The same bytes, not a copy of them: reading a large document must not
    // make the reader hold a second one.
    assert!(core::ptr::eq(
        sequence.contents().as_ptr(),
        TWO_INTEGERS[2..].as_ptr()
    ));
}

#[test]
fn entering_a_primitive_is_refused() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();
    let integer = inside.next_element().unwrap().unwrap();

    // An integer's contents are a value. Reading them as elements is how a
    // parser is talked into finding structure nobody encoded.
    assert_eq!(
        inside.enter(&integer).unwrap_err().code(),
        ErrorCode::WrongConstruction
    );
}

#[test]
fn an_element_longer_than_its_container_is_refused() {
    // SEQUENCE says six bytes of contents but only three follow.
    let input = [0x30, 0x06, 0x02, 0x01, 0x01];
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::UnexpectedEnd
    );
}

#[test]
fn an_unknown_tag_is_skipped_within_its_declared_length() {
    // SEQUENCE { [7] "junk", INTEGER 1 }: the schema layer does not know [7]
    // and steps over it without losing its place.
    let input = [
        0x30, 0x09, 0x87, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x02, 0x01, 0x01,
    ];
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();

    assert!(inside.skip().unwrap());
    let integer = inside.expect(Tag::primitive(universal::INTEGER)).unwrap();
    assert_eq!(integer.contents(), &[0x01]);
    assert!(inside.is_empty());
}

#[test]
fn expecting_the_wrong_tag_says_so() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    assert_eq!(
        reader
            .expect(Tag::primitive(universal::INTEGER))
            .unwrap_err()
            .code(),
        ErrorCode::UnexpectedTag
    );
}

#[test]
fn indefinite_length_is_read_in_ber() {
    // SEQUENCE (indefinite) { INTEGER 1 } EOC
    let input = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    assert!(sequence.is_indefinite());
    assert_eq!(sequence.contents(), &[0x02, 0x01, 0x01]);
    // The whole element includes the two end-of-contents bytes.
    assert_eq!(sequence.span().length, 7);
    assert!(reader.is_empty());

    let mut inside = reader.enter(&sequence).unwrap();
    assert_eq!(
        inside
            .expect(Tag::primitive(universal::INTEGER))
            .unwrap()
            .contents(),
        &[0x01]
    );
}

#[test]
fn nested_indefinite_lengths_close_in_order() {
    // SEQUENCE (indef) { SEQUENCE (indef) { INTEGER 1 } EOC } EOC
    let input = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    let outer = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    assert_eq!(outer.span().length, 11);

    let mut middle = reader.enter(&outer).unwrap();
    let inner = middle
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    assert_eq!(inner.contents(), &[0x02, 0x01, 0x01]);
}

#[test]
fn an_indefinite_length_that_never_ends_is_refused() {
    let input = [0x30, 0x80, 0x02, 0x01, 0x01];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::UnterminatedContents
    );
}

#[test]
fn an_indefinite_primitive_is_refused() {
    // Only constructed elements may use the indefinite form.
    let input = [0x04, 0x80, 0x00, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::WrongConstruction
    );
}

#[test]
fn end_of_contents_closing_nothing_is_refused() {
    let input = [0x00, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::MalformedEndOfContents
    );
}

#[test]
fn end_of_contents_carrying_a_length_is_refused() {
    // 0x00 0x01 0xff claims one content byte, which end-of-contents never has.
    let input = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x01, 0xff];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::MalformedEndOfContents
    );
}

/// Bytes wrapped in an octet string are read one level below the reader the
/// octet string was found in, so the depth ceiling bounds the document and
/// not each wrapping of it.
#[test]
fn a_nested_reader_counts_from_the_level_it_was_found_at() {
    // OCTET STRING { SEQUENCE { INTEGER 1, INTEGER 2 } }, inside a SEQUENCE.
    let mut wrapped = alloc::vec![0x30, 0x0c, 0x04, 0x0a];
    wrapped.extend_from_slice(&[0x30, 0x08]);
    wrapped.extend_from_slice(&TWO_INTEGERS);
    wrapped[1] = u8::try_from(wrapped.len() - 2).expect("short");
    wrapped[3] = u8::try_from(wrapped.len() - 4).expect("short");

    let at = |max_depth: u32| {
        let parser = alloc::boxed::Box::leak(alloc::boxed::Box::new(Parser::new(
            Encoding::Der,
            Limits {
                max_depth,
                ..Limits::default()
            },
            crate::test_memory(),
        )));
        let mut top = parser.read(&wrapped, 0)?;
        let outer = top.expect(Tag::constructed(universal::SEQUENCE))?;
        let mut inside = top.enter(&outer)?;
        let octets = inside.expect(Tag::primitive(universal::OCTET_STRING))?;
        assert_eq!(inside.depth(), 1);
        let mut value = parser.read_nested(
            octets.contents(),
            octets.contents_span().start,
            Encoding::Der,
            inside.depth(),
        )?;
        assert_eq!(value.depth(), 2);
        let sequence = value.expect(Tag::constructed(universal::SEQUENCE))?;
        let mut deepest = value.enter(&sequence)?;
        let _ = deepest.expect(Tag::constructed(universal::SEQUENCE))?;
        Ok::<u32, crate::Error>(deepest.depth())
    };

    assert_eq!(at(3).expect("three levels are the whole of it"), 3);
    let error = at(2).expect_err("the wrapping is a level too");
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
    let error = at(1).expect_err("the wrapped value starts below the octet string");
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
}

#[test]
fn depth_beyond_the_budget_is_a_limit_not_a_malformed_document() {
    let limits = Limits {
        max_depth: 1,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    let inside = reader.enter(&sequence).unwrap();
    let integer = {
        let mut inside = inside;
        inside.next_element().unwrap().unwrap()
    };
    let _ = integer;

    // One level is allowed; the document is fine, this run simply stops.
    let deeper = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, deeper, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let error = reader.enter(&sequence).unwrap_err();

    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
    assert!(error.is_limit());
}

#[test]
fn element_count_beyond_the_budget_is_a_limit() {
    let limits = Limits {
        max_elements: 1,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();

    let error = inside.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Elements));
}

#[test]
fn the_budget_is_shared_by_readers_entered_from_one_another() {
    // Three elements exist in total. A budget of two must stop at the third
    // even though the third is the first element of its own container: a
    // per-container budget would bound nothing.
    let limits = Limits {
        max_elements: 2,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();

    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();
    inside.next_element().unwrap().unwrap();

    assert_eq!(
        inside.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::Elements)
    );
}

#[test]
fn a_declared_length_beyond_the_budget_is_refused_before_it_is_trusted() {
    let limits = Limits {
        max_element_length: 2,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();

    let error = reader.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::ElementLength));
}

#[test]
fn work_beyond_the_budget_is_a_limit() {
    let limits = Limits {
        max_work: 1,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();

    let error = reader.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
}

#[test]
fn deep_nesting_is_refused_rather_than_ending_the_process() {
    // Ten thousand nested indefinite-length sequences, none of them closed.
    // A recursive scanner would run out of stack here; this must answer.
    let mut input = alloc::vec::Vec::new();
    for _ in 0..10_000 {
        input.push(0x30);
        input.push(0x80);
    }

    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    let error = reader.next_element().unwrap_err();

    assert!(error.is_limit() || error.code() == ErrorCode::UnterminatedContents);
}

#[test]
fn the_error_path_names_the_container_the_trouble_was_in() {
    // SEQUENCE { SEQUENCE { <truncated> } }
    let input = [0x30, 0x04, 0x30, 0x02, 0x02, 0x05];
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    let outer = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut middle = reader.enter(&outer).unwrap();
    let inner = middle
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut innermost = middle.enter(&inner).unwrap();

    let error = innermost.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedEnd);
    assert_eq!(error.path().indices(), &[0, 0]);
}

/// Whatever the bytes are, reading them must end: with elements, or with an
/// error, never with a panic and never without returning.
///
/// A deeper generative harness with a corpus belongs to the fuzzing work; this
/// is the smoke test that runs on every commit, so it stays exhaustive over the
/// short inputs where header handling lives and pseudo-random beyond that.
fn parse_to_exhaustion(input: &[u8], encoding: Encoding) {
    let parser = Parser::new(encoding, Limits::default(), crate::test_memory());
    let mut reader = parser.read(input, 0).unwrap();

    // More rounds than any of these inputs can hold elements. Reaching the end
    // of this loop means the reader stopped consuming, which is the hang this
    // test exists to catch.
    for _ in 0..(input.len() + 2) {
        match reader.next_element() {
            Ok(Some(element)) => {
                assert!(element.span().length > 0, "an element of no bytes");
                assert!(
                    element.span().end() <= input.len() as u64,
                    "element runs past the input it came from"
                );
                assert!(
                    element.contents().len() as u64 <= element.span().length,
                    "contents larger than the element holding them"
                );
            }
            Ok(None) => {
                assert!(reader.is_empty());
                return;
            }
            Err(_) => return,
        }
    }

    panic!("reader neither finished nor failed");
}

/// A fixed sequence of bytes from a fixed seed, so a failure here is
/// reproducible from the test name alone rather than only on the machine that
/// happened to see it.
fn byte_source(seed: u64) -> impl FnMut() -> u8 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        u8::try_from(state & 0xff).expect("masked to one byte")
    }
}

#[test]
fn every_short_input_is_read_or_refused() {
    // Exhaustive over two bytes: every tag byte against every length byte,
    // which is where the header rules live.
    for first in u8::MIN..=u8::MAX {
        for second in u8::MIN..=u8::MAX {
            let input = [first, second];
            parse_to_exhaustion(&input, Encoding::Der);
            parse_to_exhaustion(&input, Encoding::Ber);
        }
    }
}

#[test]
fn pseudo_random_inputs_are_read_or_refused() {
    let mut next = byte_source(0x2545_f491_4f6c_dd1d);

    let mut input = alloc::vec::Vec::new();
    for round in 0..2_000 {
        input.clear();
        let length = (round % 64) + 1;
        for _ in 0..length {
            input.push(next());
        }
        parse_to_exhaustion(&input, Encoding::Der);
        parse_to_exhaustion(&input, Encoding::Ber);
    }
}

#[test]
fn structured_random_inputs_are_read_or_refused() {
    // Bytes drawn from the alphabet that actually appears in encodings, so the
    // generator spends its time inside plausible structure rather than on
    // headers that are refused at the first byte.
    const ALPHABET: [u8; 12] = [
        0x30, 0x31, 0x02, 0x04, 0x06, 0x80, 0x81, 0x00, 0x01, 0x02, 0x7f, 0xa0,
    ];

    let mut next = byte_source(0x9e37_79b9_7f4a_7c15);

    let mut input = alloc::vec::Vec::new();
    for round in 0..2_000 {
        input.clear();
        let length = (round % 48) + 2;
        for _ in 0..length {
            input.push(ALPHABET[usize::from(next()) % ALPHABET.len()]);
        }
        parse_to_exhaustion(&input, Encoding::Der);
        parse_to_exhaustion(&input, Encoding::Ber);
    }
}

#[test]
fn end_of_contents_in_the_long_form_is_refused() {
    // 00 81 00 is a zero length written the long way. Accepting it as the
    // marker would end the element one byte early and leave the third byte to
    // be read as the start of another element. X.690 spells the marker one way.
    let input = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x81, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::MalformedEndOfContents
    );
}

#[test]
fn an_indefinite_container_is_held_to_the_element_length_budget() {
    // Its children are each small; the container is not. A budget that only
    // looked at declared lengths would never see this one, because an
    // indefinite element does not declare one.
    let mut input = alloc::vec![0x30, 0x80];
    for _ in 0..20 {
        input.extend_from_slice(&[0x02, 0x01, 0x01]);
    }
    input.extend_from_slice(&[0x00, 0x00]);

    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_element_length: 8,
            ..Limits::default()
        },
        crate::test_memory(),
    );
    let mut reader = parser.read(&input, 0).unwrap();

    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::ElementLength)
    );
}

#[test]
fn an_element_is_charged_to_the_count_once_not_once_per_pass() {
    // One element exists: an empty indefinite SEQUENCE. Finding its end reads
    // the end-of-contents marker, which is not an element and must not be
    // charged as one, and the scan must not charge for what reading will
    // charge for again.
    let input = [0x30, 0x80, 0x00, 0x00];
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_elements: 1,
            ..Limits::default()
        },
        crate::test_memory(),
    );
    let mut reader = parser.read(&input, 0).unwrap();

    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    assert_eq!(sequence.contents(), &[] as &[u8]);
}

#[test]
fn a_fault_inside_nested_indefinite_contents_names_where_it_is() {
    // SEQUENCE (indef) { SEQUENCE (indef) { <malformed tag> } }
    let input = [0x30, 0x80, 0x30, 0x80, 0x1f, 0x80, 0x02];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    let error = reader.next_element().unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedTag);
    // The malformed tag sits inside the first element of the first element,
    // and saying it is at the root points a reader at the wrong place.
    assert_eq!(error.path().indices(), &[0, 0]);
}

#[test]
fn a_depth_refusal_names_the_element_that_could_not_be_entered() {
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        crate::test_memory(),
    );
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    let error = reader.enter(&sequence).unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
    // The element whose contents could not be entered, not its container.
    assert_eq!(error.path().indices(), &[0]);
}

#[test]
fn a_constructed_universal_zero_is_not_read_as_an_element() {
    let input = [0x20, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();

    assert_eq!(
        reader.next_element().unwrap_err().code(),
        ErrorCode::MalformedTag
    );
}

#[test]
fn a_window_whose_end_would_not_fit_an_offset_is_refused() {
    // Saturating instead would answer later questions with an offset that is
    // not where anything is: every span and every error would name a position
    // the document does not have, and the reader would look like it worked.
    let parser = Parser::der(crate::test_memory());
    let error = parser.read(&TWO_INTEGERS, u64::MAX - 2).unwrap_err();

    assert_eq!(error.code(), ErrorCode::OffsetTooLarge);
}

#[test]
fn a_window_that_ends_exactly_at_the_last_offset_is_allowed() {
    let parser = Parser::der(crate::test_memory());
    let base = u64::MAX - TWO_INTEGERS.len() as u64;

    let reader = parser.read(&TWO_INTEGERS, base).unwrap();
    assert_eq!(reader.offset(), base);
}

#[test]
fn an_unexpected_tag_names_the_element_that_carried_it() {
    // SEQUENCE { INTEGER 1, INTEGER 2 }, asked for a SET as the second child.
    // The fault is the second child, not the sequence holding it, and a
    // diagnostic that names the parent sends a reader to the wrong field.
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();

    inside.expect(Tag::primitive(universal::INTEGER)).unwrap();
    let error = inside.expect(Tag::constructed(universal::SET)).unwrap_err();

    assert_eq!(error.code(), ErrorCode::UnexpectedTag);
    assert_eq!(error.path().indices(), &[0, 1]);
}

#[test]
fn a_value_that_cannot_be_read_is_named_where_it_sits() {
    // SEQUENCE { INTEGER 1, INTEGER 0x00 0x01 }, the second written a byte
    // longer than the value needs.
    let document = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01];
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&document, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let mut inside = reader.enter(&sequence).unwrap();

    inside.read_integer().unwrap();
    let error = inside.read_integer().unwrap_err();

    assert_eq!(error.code(), ErrorCode::IntegerNotMinimal);
    assert_eq!(error.path().indices(), &[0, 1]);
    assert_eq!(error.offset(), 5);
}

#[test]
fn a_value_read_from_a_constructed_element_is_refused() {
    // A bit string segmented the way BER allows, which is a second spelling of
    // one value and is not read here even when BER is what was asked for.
    let document = [0x23, 0x04, 0x03, 0x02, 0x00, 0xff];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&document, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();

    let error = reader.bit_string(&element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::WrongConstruction);
    assert_eq!(error.path().indices(), &[0]);
}

#[test]
fn implicit_tagging_does_not_stop_a_value_from_being_read() {
    // [0] IMPLICIT INTEGER 5, as a schema writes a field whose tag its
    // position gives it. The tag is the caller's business; the encoding of the
    // value is not.
    let document = [0x80, 0x01, 0x05];
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&document, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();

    assert_eq!(reader.integer(&element).unwrap().as_u64(), Some(5));
}

#[test]
fn an_element_hands_back_the_bytes_it_arrived_as() {
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&TWO_INTEGERS, 0).unwrap();
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();

    // Header included: the range a signature over the encoded element covers,
    // and what the span says it is.
    assert_eq!(sequence.as_bytes(), &TWO_INTEGERS[..]);
    assert_eq!(sequence.as_bytes().len() as u64, sequence.span().length);

    let mut inside = reader.enter(&sequence).unwrap();
    let first = inside.next_element().unwrap().unwrap();
    assert_eq!(first.as_bytes(), &[0x02, 0x01, 0x01]);
}

#[test]
fn an_indefinite_element_carries_the_marker_that_closed_it() {
    // SEQUENCE (indefinite) { INTEGER 1 }, which ends with the two zero bytes.
    let document = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
    let parser = Parser::ber(crate::test_memory());
    let mut reader = parser.read(&document, 0).unwrap();
    let sequence = reader.next_element().unwrap().unwrap();

    assert_eq!(sequence.as_bytes(), &document[..]);
    assert_eq!(sequence.contents(), &[0x02, 0x01, 0x01]);
}

#[test]
fn an_oid_scan_is_charged_to_the_work_budget() {
    // A single element passes the element and header charges, but its
    // contents are scanned arc by arc: a caller bounding work must see that
    // scan on the same meter, or one long identifier costs unmetered time.
    let mut input = alloc::vec::Vec::from([0x06u8, 0x82, 0x01, 0x00]);
    input.push(0x2a);
    input.extend(core::iter::repeat_n(0x01u8, 255));

    let limits = Limits {
        max_work: 64,
        ..Limits::default()
    };
    let parser = Parser::new(Encoding::Der, limits, crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = reader.oid(&element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));

    // Under a budget that fits, the same identifier reads.
    let parser = Parser::der(crate::test_memory());
    let mut reader = parser.read(&input, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    assert!(reader.oid(&element).is_ok());
}
