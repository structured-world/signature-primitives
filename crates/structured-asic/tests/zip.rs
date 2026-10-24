//! Public original-range ZIP framing, payload and resource regressions.

mod support;

#[path = "layout/cases.rs"]
mod layout_cases;

#[path = "xml/cases.rs"]
mod xml_cases;

#[cfg(feature = "interop-tests")]
#[path = "interop/python.rs"]
mod python_interop;

use std::sync::Arc;
use structured_asic::{
    Limits, Session,
    error::{Error, Limit},
    zip::{Archive, FaultKind, Integrity, ReadFailure},
};
use structured_asn1::{
    memory::{Memory, MemoryAccount, MemoryError},
    range::InputError,
};
use support::{Descriptor, File, Input, finish, memory, set32, zip};

#[test]
fn stored_deflated_zip64_and_all_descriptors_survive_short_async_reads() {
    // The independent literal encoder covers all local/central size and
    // descriptor spellings, including multi-block raw DEFLATE and empty input.
    let large = (0..70_001)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect::<Vec<_>>();
    for maximum in [7, 4096] {
        for zip64 in [false, true] {
            for descriptor in [Descriptor::None, Descriptor::Unsigned, Descriptor::Signed] {
                for deflate in [false, true] {
                    let mut file = File::stored(b"document.bin", &large);
                    file.zip64 = zip64;
                    file.descriptor = descriptor;
                    file.deflate = deflate;
                    let mut empty = File::stored(b"empty", b"");
                    empty.deflate = deflate;
                    let input = Input::new(zip(&[file, empty]).bytes, maximum);
                    let work = memory();
                    let session = Session::new(Limits::default(), work.clone());
                    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
                    assert_eq!(archive.len(), 2);
                    let faults = archive
                        .faults(&work)
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        faults.is_empty(),
                        "ZIP64={zip64}, deflate={deflate}: {faults:?}"
                    );
                    let member = archive.member(0, &work).unwrap().unwrap();
                    let used = work.used();
                    let bytes = finish(member.read_bytes(&work)).unwrap();
                    assert_eq!(bytes.as_ref(), large);
                    assert!(work.used() >= used + large.len());
                    drop(bytes);
                    assert_eq!(work.used(), used);
                    let empty = archive.member(1, &work).unwrap().unwrap();
                    assert!(finish(empty.read_bytes(&work)).unwrap().is_empty());
                    assert!(input.largest.get() <= 4096);
                    drop(archive);
                    assert_eq!(work.used(), 0);
                }
            }
        }
    }
}

#[test]
fn duplicate_invalid_and_distinct_case_names_remain_original_occurrences() {
    // Lookup must never choose one duplicate, fold case or erase a rejected
    // original path. Invalid UTF-8 is retained for inspection, not repaired.
    let files = [
        File::stored(b"data", b"first"),
        File::stored(b"data", b"second"),
        File::stored(b"Data", b"third"),
        File::stored(b"../data", b"fourth"),
        File::stored(b"/data", b"fifth"),
        File::stored(b"bad\xff", b"sixth"),
    ];
    let input = Input::new(zip(&files).bytes, 13);
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    assert_eq!(archive.len(), files.len());
    let names = archive.find(b"data", &work).unwrap();
    assert_eq!(names.len(), 2);
    let mut originals = Vec::new();
    for index in 0..names.len() {
        let member = names.member(index, &work).unwrap().unwrap();
        originals.push(member.id().ordinal());
    }
    originals.sort_unstable();
    assert_eq!(originals, [0, 1]);
    for (index, file) in files.iter().enumerate() {
        let member = archive.member(index, &work).unwrap().unwrap();
        assert_eq!(member.name(), file.name);
        assert_eq!(
            archive.find(file.name, &work).unwrap().len(),
            if index < 2 { 2 } else { 1 }
        );
    }
    let faults = archive
        .faults(&work)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        faults
            .iter()
            .filter(|f| f.kind == FaultKind::DuplicateName)
            .count(),
        2
    );
    assert!(
        faults
            .iter()
            .any(|f| f.member == Some(4) && f.kind == FaultKind::Name)
    );
    assert!(
        faults
            .iter()
            .any(|f| f.member == Some(5) && f.kind == FaultKind::Utf8)
    );
    assert!(
        !faults
            .iter()
            .any(|f| f.member == Some(3) && f.kind == FaultKind::Name)
    );
}

#[test]
fn crc_descriptor_marker_and_late_integrity_failure_do_not_return_partial_bytes() {
    // An unsigned descriptor may begin with the optional signature's numeric
    // value. Directory framing must retain it; the actual CRC then fails.
    for descriptor in [Descriptor::None, Descriptor::Unsigned, Descriptor::Signed] {
        let mut file = File::stored(b"data", b"complete original bytes");
        file.descriptor = descriptor;
        file.crc = Some(0x0807_4b50);
        let input = Input::new(zip(&[file]).bytes, 5);
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let member = archive.member(0, &work).unwrap().unwrap();
        assert!(archive.faults(&work).unwrap().next().is_none());
        let used = work.used();
        assert!(matches!(
            finish(member.read_bytes(&work)),
            Err(ReadFailure::Integrity {
                kind: Integrity::Crc,
                ..
            })
        ));
        assert_eq!(work.used(), used);
    }
}

#[test]
fn overlaps_and_wrong_local_names_preserve_negative_member_census() {
    // Two directory occurrences cannot claim one physical local record, even
    // if every name, size and CRC otherwise agrees exactly.
    let mut built = zip(&[
        File::stored(b"data", b"same"),
        File::stored(b"data", b"same"),
    ]);
    set32(&mut built.bytes, built.central[1] + 42, 0);
    let input = Input::new(built.bytes, 31);
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    assert_eq!(archive.len(), 2);
    let faults = archive
        .faults(&work)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        faults
            .iter()
            .filter(|f| f.kind == FaultKind::Overlap)
            .count(),
        2
    );
    for index in 0..2 {
        let member = archive.member(index, &work).unwrap().unwrap();
        assert!(matches!(
            finish(member.read_bytes(&work)),
            Err(ReadFailure::Integrity {
                kind: Integrity::Framing,
                ..
            })
        ));
    }
    let mut built = zip(&[File::stored(b"data", b"same")]);
    built.bytes[built.local[0] + 30] = b'D';
    let input = Input::new(built.bytes, 31);
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    assert!(
        archive
            .faults(&work)
            .unwrap()
            .any(|f| f.unwrap().kind == FaultKind::LocalMismatch)
    );
    assert_eq!(archive.member(0, &work).unwrap().unwrap().name(), b"data");
}

#[test]
fn repeated_queries_preserve_current_origin_and_cumulative_decode_refusal() {
    // A previously paid directory does not credit a new query. Decode output
    // remains cumulative even after the first retained buffer is released.
    let input = Input::new(zip(&[File::stored(b"data", b"12345")]).bytes, 31);
    let work = memory();
    let limits = Limits {
        max_decoded: 5,
        ..Limits::default()
    };
    let session = Session::new(limits, work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let member = archive.member(0, &work).unwrap().unwrap();
    let used = work.used();
    assert_eq!(finish(member.read_bytes(&work)).unwrap().as_ref(), b"12345");
    assert_eq!(work.used(), used);
    assert!(matches!(
        finish(member.read_bytes(&work)),
        Err(ReadFailure::Processing {
            cause: Error::Limit {
                kind: Limit::Decoded,
                ..
            },
            ..
        })
    ));
    let zero = Memory::new(Arc::new(MemoryAccount::new(1024, 0)));
    let calls = input.calls.get();
    assert!(matches!(
        archive.find(b"data", &zero),
        Err(Error::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(input.calls.get(), calls);
    input.generation.set(2);
    assert!(matches!(
        archive.member(0, &work),
        Err(Error::Input(InputError::Changed { .. }))
    ));
}

#[test]
fn empty_directory_and_zero_capacity_fail_without_leaking_scratch() {
    // Empty ZIP is structurally valid but cannot fabricate an ASiC signature.
    // A capacity failure during directory acquisition releases all partial state.
    let input = Input::new(zip(&[]).bytes, 1);
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    assert!(archive.is_empty());
    drop(archive);
    assert_eq!(work.used(), 0);
    let zero = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let session = Session::new(Limits::default(), zero.clone());
    assert!(finish(Archive::read(&input, &session, &zero)).is_err());
    assert_eq!(zero.used(), 0);
}

#[test]
fn iso_profile_requires_utf8_flag_for_non_ascii_comments_as_well_as_names() {
    // APPNOTE6.3.3 Appendix D applies bit11 to both name and comment. Valid
    // UTF-8 alone cannot make a non-ASCII, unflagged comment ISO21320 conforming.
    let mut file = File::stored(b"data", b"value");
    file.flags = 0;
    file.comment = "caf\u{e9}".as_bytes();
    let input = Input::new(zip(&[file]).bytes, 3);
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let faults = archive
        .faults(&work)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        faults
            .iter()
            .any(|f| f.member == Some(0) && f.kind == FaultKind::IsoProfile)
    );
    assert!(!faults.iter().any(|f| f.kind == FaultKind::Utf8));
}
