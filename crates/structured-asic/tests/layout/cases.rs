use super::support::{File, Input, finish, memory, zip};
use std::sync::Arc;
use structured_asic::zip::{Archive, Integrity, ReadFailure};
use structured_asic::{
    Limits, Session,
    layout::{Census, Form, Inspection, Principal, Requirement, Rules},
    media,
};
use structured_asn1::memory::{Memory, MemoryAccount};

#[test]
fn general_baseline_and_additional_file_layouts_do_not_collapse_into_one_rule_set() {
    // A readable general S container may carry auxiliary application metadata.
    // Part1's S baseline disallows it; Part2 does not define this signature route.
    let input = Input::new(
        zip(&[
            File::stored(b"document.bin", b"payload"),
            File::stored(b"META-INF/signature.p7s", b"not a CMS signature"),
            File::stored(b"META-INF/certificate.cer", b"auxiliary"),
        ])
        .bytes,
        11,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let census = Census::read(&archive, &work).unwrap();
    let form = Form::Simple(Principal::Cades);
    let general = Inspection::read(&census, form, Rules::General, &work).unwrap();
    assert_eq!(general.required_layout(), Some(true));
    let baseline = Inspection::read(&census, form, Rules::BaselinePart1, &work).unwrap();
    assert_eq!(baseline.required_layout(), Some(false));
    assert!(
        baseline
            .issues(&work)
            .any(|v| v.unwrap().requirement == Requirement::BaselineSimpleExtra)
    );
    let additional = Inspection::read(&census, form, Rules::AdditionalPart2, &work).unwrap();
    assert_eq!(additional.required_layout(), None);
    // No layout fact is a successful signature: the original carried content
    // remains malformed under the one actual CMS parser.
    let member = archive.member(1, &work).unwrap().unwrap();
    let content = finish(member.content(&work)).unwrap();
    assert!(content.read(&work).is_err());
}

#[test]
fn e_xades_baseline_requires_original_manifest_and_never_becomes_part2() {
    // General E-XAdES permits optional ODF metadata; Part1 baseline requires
    // exactly one manifest.xml. Another rule set must not silently fill it in.
    for present in [false, true] {
        let mut files = vec![
            File::stored(b"nested/document.bin", b"payload"),
            File::stored(b"META-INF/signatures-1.xml", b"original XML"),
        ];
        if present {
            files.push(File::stored(
                b"META-INF/manifest.xml",
                b"original ODF manifest",
            ));
        }
        let input = Input::new(zip(&files).bytes, 17);
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let census = Census::read(&archive, &work).unwrap();
        let general =
            Inspection::read(&census, Form::ExtendedXades, Rules::General, &work).unwrap();
        assert_eq!(general.required_layout(), Some(true));
        let baseline =
            Inspection::read(&census, Form::ExtendedXades, Rules::BaselinePart1, &work).unwrap();
        assert_eq!(baseline.required_layout(), Some(present));
        let additional =
            Inspection::read(&census, Form::ExtendedXades, Rules::AdditionalPart2, &work).unwrap();
        assert_eq!(additional.required_layout(), None);
    }
}

#[test]
fn additional_time_assertion_layout_retains_archive_renewal_files() {
    // Part2 §4.2.1 explicitly permits ArchiveManifest/associated timestamp
    // files. Applying Part1's signature-baseline extra-file ban would erase LTA.
    let input = Input::new(
        zip(&[
            File::stored(b"document.bin", b"payload"),
            File::stored(b"META-INF/timestamp.tst", b"initial"),
            File::stored(b"META-INF/ASiCArchiveManifest-1.xml", b"archive"),
            File::stored(b"META-INF/timestamp-2.tst", b"renewal"),
        ])
        .bytes,
        19,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let census = Census::read(&archive, &work).unwrap();
    let additional = Inspection::read(
        &census,
        Form::Simple(Principal::Timestamp),
        Rules::AdditionalPart2,
        &work,
    )
    .unwrap();
    assert_eq!(additional.required_layout(), Some(true));
    let baseline = Inspection::read(
        &census,
        Form::Simple(Principal::Timestamp),
        Rules::BaselinePart1,
        &work,
    )
    .unwrap();
    assert_eq!(baseline.required_layout(), None);
}

#[test]
fn renamed_archive_manifest_pattern_includes_the_normative_arbitrary_prefix() {
    // Annex A.7(2a) permits *ASiCArchiveManifest*.xml, not only a prefix at
    // position zero. Case-insensitive reserved detection must not rename it.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/old-ASiCArchiveManifest-1.xml", b"previous"),
            File::stored(b"META-INF/OLD-ASICARCHIVEMANIFEST-1.xml", b"reserved"),
        ])
        .bytes,
        13,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let census = Census::read(&archive, &work).unwrap();
    assert_eq!(
        census.occurrence(0, &work).unwrap().unwrap().1,
        structured_asic::layout::Role::ArchiveManifest
    );
    assert_eq!(
        census.occurrence(1, &work).unwrap().unwrap().1,
        structured_asic::layout::Role::Reserved
    );
}

#[test]
fn absent_or_exhausted_mimetype_traversal_is_empty_even_under_zero_work() {
    // An empty optional traversal performs no item access, dispatch or work.
    // Exhaustion must not manufacture a processing failure after the last item.
    for present in [false, true] {
        let files = if present {
            vec![File::stored(b"mimetype", b"text/plain")]
        } else {
            Vec::new()
        };
        let input = Input::new(zip(&files).bytes, 31);
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let census = Census::read(&archive, &work).unwrap();
        let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        if present {
            let one = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
            let mut headers = census.mimetypes(&one);
            assert!(headers.next().unwrap().is_ok());
            assert!(headers.next().is_none());
            let mut refused = census.mimetypes(&zero);
            assert!(refused.next().unwrap().is_err());
            assert!(refused.next().is_none());
        } else {
            assert!(census.mimetypes(&zero).next().is_none());
        }
    }
}

#[test]
fn media_is_streamed_without_a_whole_value_buffer_and_requires_complete_crc() {
    // The complete MIME member exceeds available capacity. A second joined
    // value or replay buffer cannot fit; only the existing range window is live.
    let value = format!(
        "APPLICATION/vnd.etsi.asic-e+zip; name=\"{}\"",
        "x".repeat(100_000)
    );
    let input = Input::new(
        zip(&[File::stored(b"mimetype", value.as_bytes())]).bytes,
        37,
    );
    let work = Memory::new(Arc::new(MemoryAccount::new(64 * 1024, 100_000_000)));
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let member = archive.member(0, &work).unwrap().unwrap();
    let used = work.used();
    let media = finish(member.read_media(&work)).unwrap();
    assert_eq!(media.kind(), media::Type::Extended);
    assert_eq!(media.member(), member.id());
    assert_eq!(work.used(), used);
    let mut corrupt = File::stored(b"mimetype", b"application/vnd.etsi.asic-s+zip");
    corrupt.crc = Some(7);
    let input = Input::new(zip(&[corrupt]).bytes, 3);
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let member = archive.member(0, &work).unwrap().unwrap();
    assert!(matches!(
        finish(member.read_media(&work)),
        Err(ReadFailure::Integrity {
            kind: Integrity::Crc,
            ..
        })
    ));
}

#[test]
fn media_parameters_and_original_type_alternatives_are_not_rejected_by_substring_rules() {
    // RFC2045 comparison concerns the actual essence, not a substring inside
    // a comment/parameter; a different original-container media type stays distinct.
    for (value, expected) in [
        (
            "application/vnd.etsi.asic-s+zip; charset=utf-8",
            media::Type::Simple,
        ),
        (
            "application/vnd.oasis.opendocument.text",
            media::Type::Other,
        ),
        (
            "text/plain; name=\"application/vnd.etsi.asic-e+zip\"",
            media::Type::Other,
        ),
        (
            "application/vnd.etsi.asic-e+zip;broken",
            media::Type::Malformed,
        ),
        ("", media::Type::Malformed),
    ] {
        let input = Input::new(zip(&[File::stored(b"mimetype", value.as_bytes())]).bytes, 3);
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let member = archive.member(0, &work).unwrap().unwrap();
        assert_eq!(finish(member.read_media(&work)).unwrap().kind(), expected);
    }
}
