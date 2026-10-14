//! Carried-content source coordinates, lifetime and admission boundaries.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser, Span};
use structured_cms::content_source::{ContentError, Coordinates};
use structured_cms::{ErrorCode, Octets};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)))
}

#[test]
fn primitive_reader_borrows_original_bytes_and_physical_positions() {
    // A single range must avoid joining and preserve the physical base/depth.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [4, 3, 2, 1, 7];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "content").unwrap();
    let held = memory.used();
    let value = octets
        .with_nested_reader(&parent, Encoding::Ber, "content", |reader, map| {
            assert_eq!(map.coordinates(), Coordinates::Original);
            assert_eq!(reader.depth(), 1);
            let value = reader.next_element().unwrap().unwrap();
            assert_eq!(value.as_bytes().as_ptr(), bytes[2..].as_ptr());
            assert_eq!(
                value.span(),
                Span {
                    start: 402,
                    length: 3
                }
            );
            assert_eq!(map.project_offset(405, &reader.execution()).unwrap(), 405);
            assert_eq!(memory.used(), held);
            Ok::<_, ()>(value.contents()[0])
        })
        .unwrap();
    assert_eq!(value, 7);
    assert_eq!(memory.used(), held);
}

#[test]
fn joined_error_retains_disjoint_map_after_source_and_parser_drop() {
    // An inner logical error must remain projectable without temporary bytes,
    // including the header gap, the fragment boundary and physical EOF.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 7, 4, 1, 2, 4, 2, 1, 7];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "content").unwrap();
    let failure = octets
        .with_nested_reader(&parent, Encoding::Ber, "content", |reader, map| {
            assert_eq!(map.coordinates(), Coordinates::Logical);
            let value = reader.next_element().unwrap().unwrap();
            assert_eq!(
                value.span(),
                Span {
                    start: 0,
                    length: 3
                }
            );
            Err::<(), _>(value.span())
        })
        .unwrap_err();
    drop(octets);
    drop(parent);
    drop(parser);
    let ContentError::Callback { source, context } = failure else {
        panic!("callback cause lost")
    };
    assert_eq!(
        source,
        Span {
            start: 0,
            length: 3
        }
    );
    assert_eq!(
        context.carrier(),
        Span {
            start: 400,
            length: 9
        }
    );
    assert_eq!(context.project_offset(0, &memory).unwrap(), 404);
    assert_eq!(context.project_offset(1, &memory).unwrap(), 407);
    assert_eq!(context.project_offset(3, &memory).unwrap(), 409);
    let physical = context.project_span(source, &memory).unwrap();
    assert_eq!(
        &*physical,
        &[
            Span {
                start: 404,
                length: 1
            },
            Span {
                start: 407,
                length: 2
            }
        ]
    );
    assert!(memory.used() > 0);
    drop(physical);
    drop(context);
    assert_eq!(memory.used(), 0);
}

#[test]
fn empty_fragments_and_empty_constructed_value_have_real_eof_positions() {
    // Zero joined bytes must retain header-aware EOF and pay empty fan-out.
    for (bytes, eof) in [(&[0x24, 4, 4, 0, 4, 0][..], 406), (&[0x24, 0][..], 402)] {
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut parent = parser.read(bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let octets = Octets::read(&parent, &element, "content").unwrap();
        octets
            .with_nested_reader(&parent, Encoding::Ber, "content", |reader, context| {
                assert!(reader.next_element().unwrap().is_none());
                assert_eq!(context.project_offset(0, &reader.execution()).unwrap(), eof);
                let point = context
                    .project_span(
                        Span {
                            start: 0,
                            length: 0,
                        },
                        &reader.execution(),
                    )
                    .unwrap();
                assert_eq!(
                    &*point,
                    &[Span {
                        start: eof,
                        length: 0
                    }]
                );
                Ok::<_, ()>(())
            })
            .unwrap();
    }
}

#[test]
fn invalid_projection_is_terminal_and_does_not_allocate_or_scan() {
    // Caller offsets are validated before traversal; overflow is not syntax.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 6, 4, 1, 1, 4, 1, 2];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "content").unwrap();
    octets
        .with_nested_reader(&parent, Encoding::Ber, "content", |reader, map| {
            let held = memory.used();
            let work = memory.work_used();
            for span in [
                Span {
                    start: 3,
                    length: 0,
                },
                Span {
                    start: u64::MAX,
                    length: 1,
                },
            ] {
                let error = map.project_span(span, &reader.execution()).unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidLocation);
                assert!(error.is_terminal());
                assert_eq!(error.offset(), 400);
            }
            assert_eq!(memory.used(), held);
            assert_eq!(memory.work_used(), work);
            Ok::<_, ()>(())
        })
        .unwrap();
}

#[test]
fn foreign_session_and_inherited_depth_refuse_before_callback() {
    // Equal accounts cannot replace session ceilings; nesting is not reset.
    let memory = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory.clone(),
    );
    let foreign = Parser::ber(memory.clone());
    let bytes = [4, 3, 2, 1, 7];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "content").unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let held = memory.used();
    let work = memory.work_used();
    let refusal = octets
        .with_nested_reader(&other, Encoding::Ber, "content", |_, _| -> Result<(), ()> {
            panic!("foreign callback")
        })
        .unwrap_err();
    assert!(matches!(refusal, ContentError::Processing(error) if error.is_terminal()));
    assert_eq!(memory.used(), held);
    assert_eq!(memory.work_used(), work);
    let refusal = octets
        .with_nested_reader(
            &parent,
            Encoding::Ber,
            "content",
            |_, _| -> Result<(), ()> { panic!("depth callback") },
        )
        .unwrap_err();
    assert!(
        matches!(refusal, ContentError::Decoding { source, context } if source.is_resource() && context.coordinates() == Coordinates::Original)
    );
    assert_eq!(memory.used(), held);
}

#[test]
fn joined_timestamp_decodes_in_scope_and_retains_only_explicit_owned_output() {
    // Exercise the actual TSTInfo reader over a split inner encoding. Nothing
    // borrowing the join may escape; an admitted serial copy survives all views.
    use structured_asn1::memory::Work;
    use structured_cms::timestamp::TokenInfo;
    let mut inner = vec![
        0x30, 0, 2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, b'a', b'b', 2, 1, 7, 0x18, 15,
    ];
    inner.extend_from_slice(b"20260101000000Z");
    inner[1] = u8::try_from(inner.len() - 2).unwrap();
    let mut bytes = vec![0x24, u8::try_from(inner.len() + 4).unwrap(), 4, 7];
    bytes.extend_from_slice(&inner[..7]);
    bytes.extend([4, u8::try_from(inner.len() - 7).unwrap()]);
    bytes.extend_from_slice(&inner[7..]);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "tstInfo").unwrap();
    let (serial, generation) = octets
        .with_nested_reader(&parent, Encoding::Ber, "tstInfo", |reader, map| {
            let element = reader.next_element().unwrap().unwrap();
            let info = TokenInfo::read(reader, &element).unwrap();
            assert!(!info.has_faults());
            assert_eq!(map.coordinates(), Coordinates::Logical);
            let mut serial = reader.execution().vector();
            serial
                .try_extend_from_slice(info.serial().element().contents())
                .unwrap();
            Ok::<_, ()>((serial.into_owned(), info.gen_time()))
        })
        .unwrap();
    drop(octets);
    drop(parent);
    drop(parser);
    assert_eq!(&*serial, &[7]);
    assert_eq!(generation.start().seconds(), 1_767_225_600);
    assert_eq!(memory.used(), 1);
    drop(serial);
    assert_eq!(memory.used(), 0);
}

#[test]
fn projection_refusal_preserves_original_cause_and_retained_source_map() {
    // Refusing a later query does not overwrite the opaque callback failure or
    // release mapping capacity while that independently retained context lives.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 6, 4, 1, 1, 4, 1, 2];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let octets = Octets::read(&parent, &element, "content").unwrap();
    let error = octets
        .with_nested_reader(&parent, Encoding::Ber, "content", |_, _| {
            Err::<(), _>("provider refused")
        })
        .unwrap_err();
    let ContentError::Callback { source, context } = error else {
        panic!("callback cause lost")
    };
    let held = memory.used();
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    let error = context.project_offset(1, &memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(source, "provider refused");
    assert_eq!(memory.used(), held);
    assert_eq!(context.coordinates(), Coordinates::Logical);
    assert_eq!(
        context.carrier(),
        Span {
            start: 400,
            length: 8
        }
    );
}

#[test]
fn nested_borrowed_piece_composes_disjoint_physical_source_without_parent_map() {
    // A primitive inner OCTET STRING is contiguous in the outer temporary join
    // but its INTEGER payload crosses original wire fragments. Flatten that
    // provenance before returning the inner error; retain neither outer join/map.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 9, 4, 3, 4, 3, 2, 4, 2, 1, 7];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let outer = Octets::read(&parent, &element, "outer").unwrap();
    let inner = outer
        .with_nested_reader(&parent, Encoding::Ber, "outer", |reader, origin| {
            let element = reader.next_element().unwrap().unwrap();
            let content = Octets::read(reader, &element, "inner").unwrap();
            assert!(content.as_one().is_some());
            let error = content.with_nested_reader_mapped(
                reader,
                origin,
                Encoding::Ber,
                "inner",
                |reader, map| {
                    assert_eq!(map.coordinates(), Coordinates::Logical);
                    assert_eq!(reader.depth(), 2);
                    let element = reader.next_element().unwrap().unwrap();
                    assert_eq!(element.contents(), &[7]);
                    Err::<(), _>(element.span())
                },
            );
            Ok::<_, ()>(error)
        })
        .unwrap()
        .unwrap_err();
    drop(outer);
    drop(parent);
    drop(parser);
    let ContentError::Callback { source, context } = inner else {
        panic!("nested source context lost")
    };
    assert_eq!(
        source,
        Span {
            start: 0,
            length: 3
        }
    );
    assert_eq!(
        context.carrier(),
        Span {
            start: 404,
            length: 7
        }
    );
    assert_eq!(context.project_offset(0, &memory).unwrap(), 406);
    assert_eq!(context.project_offset(1, &memory).unwrap(), 409);
    assert_eq!(context.project_offset(3, &memory).unwrap(), 411);
    let ranges = context.project_span(source, &memory).unwrap();
    assert_eq!(
        &*ranges,
        &[
            Span {
                start: 406,
                length: 1
            },
            Span {
                start: 409,
                length: 2
            }
        ]
    );
    drop(ranges);
    drop(context);
    assert_eq!(memory.used(), 0);
}

#[test]
fn mapped_child_of_original_reader_keeps_physical_coordinates_and_no_join() {
    // An existing physical parent map must not force an unnecessary buffer or
    // turn known physical offsets into a new logical namespace.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let bytes = [4, 5, 4, 3, 2, 1, 7];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let outer = Octets::read(&parent, &element, "outer").unwrap();
    let held = memory.used();
    outer
        .with_nested_reader(&parent, Encoding::Ber, "outer", |reader, origin| {
            let element = reader.next_element().unwrap().unwrap();
            let content = Octets::read(reader, &element, "inner").unwrap();
            content
                .with_nested_reader_mapped(
                    reader,
                    origin,
                    Encoding::Ber,
                    "inner",
                    |reader, context| {
                        let integer = reader.next_element().unwrap().unwrap();
                        assert_eq!(context.coordinates(), Coordinates::Original);
                        assert_eq!(integer.as_bytes().as_ptr(), bytes[4..].as_ptr());
                        assert_eq!(
                            integer.span(),
                            Span {
                                start: 404,
                                length: 3
                            }
                        );
                        assert_eq!(
                            context.project_offset(404, &reader.execution()).unwrap(),
                            404
                        );
                        assert_eq!(memory.used(), held);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(memory.used(), held);
}
