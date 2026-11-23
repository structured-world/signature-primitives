use super::support::{File, Input, finish, memory, set32, zip};
use core::{cell::Cell, task::Poll};
use std::sync::Arc;
use structured_asic::{
    Session,
    probe::{self, Acquisition, Error, Finding, Format, Limits, Namespace, Report},
};
use structured_asn1::{
    Span,
    memory::{Memory, MemoryAccount, Work},
    range::{InputError, RangeSource, ReadError, Stamp},
    source::Snapshot,
};

fn inspect(bytes: &[u8]) -> Report<usize, u64> {
    let input = Input::new(bytes.to_vec(), 17);
    let work = memory();
    let session = Session::new(structured_asic::Limits::default(), work.clone());
    let report = finish(probe::read(&input, &session, &work, Limits::default())).unwrap();
    assert_eq!(report.stamp(), input.stamp());
    assert_eq!(report.ranges().len(), input.calls.get());
    assert!(input.largest.get() <= 4096);
    report
}

fn has<D: Copy, G: Copy>(report: &Report<D, G>, format: Format, finding: Finding) -> bool {
    report
        .candidates()
        .iter()
        .any(|candidate| candidate.format == format && candidate.finding == finding)
}

#[test]
fn image_candidates_use_structural_headers_and_keep_truncation_explicit() {
    // Evidence covers complete bounded headers and never requires image decode.
    let mut png = *b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR\0\0\0\x01\0\0\0\x01\x08\x02\0\0\0\0\0\0\0";
    let mut bmp = vec![0; 54];
    bmp[..2].copy_from_slice(b"BM");
    bmp[2] = 54;
    bmp[10] = 54;
    bmp[14] = 40;
    let fixtures: &[(Format, &[u8])] = &[
        (Format::Png, &png),
        (Format::Jpeg, b"\xff\xd8\xff\xdb\x00\x02"),
        (Format::Gif87a, b"GIF87a\x01\0\x01\0\0\0\0"),
        (Format::Gif89a, b"GIF89a\x01\0\x01\0\0\0\0"),
        (Format::TiffLittleEndian, b"II*\0\x08\0\0\0\0\0"),
        (Format::TiffBigEndian, b"MM\0*\0\0\0\x08\0\0"),
        (
            Format::WebP,
            b"RIFF\x16\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ),
        (Format::Bmp, &bmp),
    ];
    for &(format, image) in fixtures {
        let report = inspect(image);
        assert!(
            has(&report, format, Finding::Framing),
            "{format:?}: {report:?}"
        );
        assert!(
            has(
                &inspect(&image[..image.len() - 1]),
                format,
                Finding::Incomplete
            ),
            "{format:?}"
        );
    }
    png[12] = b'X';
    assert!(has(&inspect(&png), Format::Png, Finding::Conflicting));
    assert!(has(
        &inspect(b"II+\0"),
        Format::TiffLittleEndian,
        Finding::Unsupported
    ));
    assert_eq!(inspect(b"plain text").candidates(), []);
}

#[test]
fn cms_uses_the_signed_data_oid_and_pdf_uses_its_original_xref() {
    // A generic DER SEQUENCE has no CMS evidence.
    assert_eq!(inspect(b"\x30\x03\x02\x01\x01").candidates(), []);
    let cms = b"\x30\x12\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02\xa0\x05\x30\x03\x02\x01\x01";
    assert!(has(&inspect(cms), Format::CmsSignedData, Finding::Framing));
    assert!(has(
        &inspect(&cms[..13]),
        Format::CmsSignedData,
        Finding::Incomplete
    ));
    let pdf =
        b"%PDF-1.7\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n9\n%%EOF\n";
    assert!(has(&inspect(pdf), Format::Pdf, Finding::Framing));
    assert!(has(
        &inspect(b"%PDF-1.7\n"),
        Format::Pdf,
        Finding::Incomplete
    ));
    assert!(has(
        &inspect(b"%PDF-2.0\n"),
        Format::Pdf,
        Finding::Unsupported
    ));
}

#[test]
fn xml_prefix_separates_namespace_evidence_and_opaque_dtds() {
    // DOCTYPE can add defaults even when the root opening tag has been read.
    let known = inspect(
        b"<?xml\tversion='1.0'?> <!--a--> <?x y?> <!DOCTYPE p:r><p:r xmlns:p='urn:known'/>",
    );
    assert!(has(&known, Format::Xml, Finding::Framing));
    assert!(
        matches!(known.root_namespace(), Some(Namespace::Uri(uri)) if uri.as_str() == "urn:known")
    );
    let internal = b"<!DOCTYPE r [<!ATTLIST r xmlns CDATA 'urn:default'>]><r/>";
    let external = b"<!DOCTYPE p:r SYSTEM 'outside.dtd'><p:r xmlns:p='urn:written'/>";
    for original in [internal.as_slice(), external.as_slice()] {
        let report = inspect(original);
        assert!(has(&report, Format::Xml, Finding::Framing));
        assert!(matches!(report.root_namespace(), Some(Namespace::Unknown)));
    }
    assert!(has(
        &inspect(b"<!-- unterminated"),
        Format::Xml,
        Finding::Incomplete
    ));
    assert!(has(
        &inspect(b"\xef\xbb\xbf<?xml version='1.0' encoding='UTF-16'?><r/>"),
        Format::Xml,
        Finding::Conflicting
    ));
    assert!(has(
        &inspect(b"\x4c\x6f\xa7\x94"),
        Format::Xml,
        Finding::Unsupported
    ));
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(
        "<r xmlns='urn:wide'/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let report = inspect(&utf16);
    assert!(
        matches!(report.root_namespace(), Some(Namespace::Uri(uri)) if uri.as_str() == "urn:wide")
    );
    assert_eq!(
        report.candidates()[0].range,
        Span {
            start: 0,
            length: utf16.len() as u64
        }
    );
}

#[test]
fn xref_stream_type_comes_from_the_outer_pdf_dictionary() {
    // Dictionary entry ordering and intervening PDF objects do not affect Type.
    for dictionary in [
        "<< /Type /XRef /DecodeParms << /Columns 4 >> /Length 0 >>",
        "<< /DecodeParms << /Columns 4 >> /Type /XRef /Length 0 >>",
        "<< /DecodeParms [ << /Columns 4 >> ] /Note ( >> /Type /Other ) /Type /XRef >>",
        "<< /Link 6 0 R /Note <3e3e> /Ty#70e /X#52ef >>",
    ] {
        let pdf = format!(
            "%PDF-1.7\n1 0 obj\n{dictionary}\nstream\nendstream\nendobj\nstartxref\n9\n%%EOF\n"
        );
        assert!(
            has(&inspect(pdf.as_bytes()), Format::Pdf, Finding::Framing),
            "{dictionary}"
        );
    }
    for dictionary in [
        "<< /Parameters << /Type /XRef >> /Type /Other >>",
        "<< /Note ( /Type /XRef ) /Type /Other >>",
        "<< /Other /Type /XRef /Other >>",
        "<< /Type /XRef /Type /Other >>",
    ] {
        let pdf = format!(
            "%PDF-1.7\n1 0 obj\n{dictionary}\nstream\nendstream\nendobj\nstartxref\n9\n%%EOF\n"
        );
        assert!(
            has(&inspect(pdf.as_bytes()), Format::Pdf, Finding::Incomplete),
            "{dictionary}"
        );
    }
}

#[test]
fn actual_zip_markers_distinguish_asic_odf_and_ooxml() {
    // ASiC mimetype is validated as payload and corroborated by a signature role.
    for (format, mime) in [
        (Format::AsicS, b"application/vnd.etsi.asic-s+zip"),
        (Format::AsicE, b"application/vnd.etsi.asic-e+zip"),
    ] {
        let files = [
            File::stored(b"mimetype", mime),
            File::stored(b"data", b"payload"),
            File::stored(b"META-INF/signatures.xml", b"<Signature/>"),
        ];
        let report = inspect(&zip(&files).bytes);
        assert!(has(&report, Format::Zip, Finding::Framing));
        assert!(has(&report, format, Finding::Framing));
        assert!(!report.is_ambiguous());
    }
    let odf = b"<m:manifest xmlns:m='urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'><m:file-entry m:full-path='/' m:media-type='application/vnd.oasis.opendocument.text'/></m:manifest>";
    let document = zip(&[File::stored(b"META-INF/manifest.xml", odf)]);
    assert!(has(
        &inspect(&document.bytes),
        Format::Odf,
        Finding::Framing
    ));
    let conflicting = zip(&[
        File::stored(
            b"mimetype",
            b"application/vnd.oasis.opendocument.spreadsheet",
        ),
        File::stored(b"META-INF/manifest.xml", odf),
    ]);
    assert!(has(
        &inspect(&conflicting.bytes),
        Format::Odf,
        Finding::Conflicting
    ));

    let opened = office("", false);
    assert!(has(&opened, Format::Ooxml, Finding::Framing), "{opened:?}");
    assert!(has(
        &office(" TargetMode='External'", false),
        Format::Ooxml,
        Finding::Unsupported
    ));
    assert!(has(&office("", true), Format::Ooxml, Finding::Incomplete));
    let raw = zip(&[File::stored(b"plain", b"entry")]);
    let generic = inspect(&raw.bytes);
    assert_eq!(
        generic
            .candidates()
            .iter()
            .map(|item| item.format)
            .collect::<Vec<_>>(),
        [Format::Zip]
    );
}

fn office(mode: &str, missing: bool) -> Report<usize, u64> {
    office_with_target(mode, missing, "word/document.xml")
}

#[test]
fn office_relationship_resolves_dot_segments_against_the_package_root() {
    // The ZIP name and its content-type override use the resolved part name.
    for target in [
        "word/../word/document.xml",
        "./word/./document.xml",
        "/other/sub/../../word/document.xml",
        "../word/document.xml",
    ] {
        assert!(
            has(
                &office_with_target("", false, target),
                Format::Ooxml,
                Finding::Framing
            ),
            "{target}"
        );
    }
    assert!(has(
        &office_with_target(" TargetMode='External'", false, "word/../word/document.xml"),
        Format::Ooxml,
        Finding::Unsupported
    ));
    assert!(has(
        &office_with_target("", false, "word%2Fdocument.xml"),
        Format::Ooxml,
        Finding::Conflicting
    ));
    assert!(has(
        &office_with_part(
            "",
            false,
            "tmp/../word/sample%20file.xml",
            "word/sample%20file.xml"
        ),
        Format::Ooxml,
        Finding::Framing
    ));
}

fn office_with_target(mode: &str, missing: bool, target: &str) -> Report<usize, u64> {
    office_with_part(mode, missing, target, "word/document.xml")
}

fn office_with_part(mode: &str, missing: bool, target: &str, part: &str) -> Report<usize, u64> {
    let relationships = format!(
        "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'><Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='{target}'{mode}/></Relationships>"
    );
    let types = format!(
        "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Override PartName='/{part}' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/></Types>"
    );
    let records = [
        File::stored(b"_rels/.rels", relationships.as_bytes()),
        File::stored(b"[Content_Types].xml", types.as_bytes()),
        File::stored(part.as_bytes(), b"<document/>"),
    ];
    let count = if missing { 2 } else { 3 };
    inspect(&zip(&records[..count]).bytes)
}

#[test]
fn independent_formats_and_duplicate_package_markers_remain_visible() {
    // A GIF header and a ZIP directory at EOF coexist in the same source.
    let mut original = b"GIF89a\x01\0\x01\0\0\0\0".to_vec();
    let mut empty = zip(&[]);
    set32(
        &mut empty.bytes,
        empty.end + 16,
        u32::try_from(original.len()).unwrap(),
    );
    original.extend(empty.bytes);
    let report = inspect(&original);
    assert!(has(&report, Format::Zip, Finding::Framing), "{report:?}");
    assert!(has(&report, Format::Gif89a, Finding::Framing));
    assert!(report.is_ambiguous());
    let partial = inspect(&original[..original.len() - 18]);
    assert!(has(&partial, Format::Zip, Finding::Incomplete));
    let duplicated = zip(&[
        File::stored(b"[Content_Types].xml", b"first"),
        File::stored(b"[Content_Types].xml", b"second"),
    ]);
    let result = inspect(&duplicated.bytes);
    assert_eq!(
        result
            .candidates()
            .iter()
            .filter(|item| { item.format == Format::Ooxml && item.finding == Finding::Ambiguous })
            .count(),
        2
    );
}

#[test]
fn requested_byte_read_and_storage_refusals_stay_terminal() {
    // A refused request must not reach the underlying source or become unknown.
    let source = Input::new(b"unrecognized artifact".to_vec(), 2);
    let work = memory();
    let session = Session::new(structured_asic::Limits::default(), work.clone());
    let bytes = Limits {
        bytes: 5,
        ..Limits::default()
    };
    assert!(matches!(
        finish(probe::read(&source, &session, &work, bytes)),
        Err(Error::Input(InputError::Cause {
            cause: Acquisition::Bytes,
            ..
        }))
    ));
    assert_eq!(source.calls.get(), 0);
    let reads = Limits {
        reads: 1,
        ..Limits::default()
    };
    assert!(matches!(
        finish(probe::read(&source, &session, &work, reads)),
        Err(Error::Input(InputError::Cause {
            cause: Acquisition::Reads,
            ..
        }))
    ));
    assert_eq!(source.calls.get(), 1);
    assert_eq!(work.used(), 0);
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let session = Session::new(structured_asic::Limits::default(), empty.clone());
    assert!(matches!(
        finish(probe::read(&source, &session, &empty, Limits::default())),
        Err(Error::Input(InputError::Resource { .. }) | Error::Resource { .. })
    ));
    assert_eq!(source.calls.get(), 1);
    let spent = Memory::new(Arc::new(MemoryAccount::new(100_000, 0)));
    let session = Session::new(structured_asic::Limits::default(), memory());
    assert!(matches!(
        finish(probe::read(&source, &session, &spent, Limits::default())),
        Err(Error::Input(InputError::Resource { .. }) | Error::Resource { .. })
    ));
    assert_eq!(source.calls.get(), 1);
}

struct Virtual {
    generation: Cell<u64>,
    changes: bool,
    requested: Cell<u64>,
}

impl RangeSource for Virtual {
    type Document = u8;
    type Generation = u64;
    type Error = ();

    fn stamp(&self) -> Stamp<u8, u64> {
        Stamp {
            snapshot: Snapshot {
                document: 42,
                generation: self.generation.get(),
            },
            length: 1 << 42,
        }
    }

    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        out: &'q mut [u8],
        _: &'q W,
    ) -> Result<usize, ReadError<()>> {
        let mut first = true;
        core::future::poll_fn(|task| {
            if core::mem::take(&mut first) {
                task.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        assert!(out.len() <= 4096);
        self.requested.set(self.requested.get() + out.len() as u64);
        out.fill(0);
        if offset == 0 {
            out[..9].copy_from_slice(b"%PDF-2.0\n");
        }
        if self.changes {
            self.generation.set(2);
        }
        Ok(out.len())
    }
}

#[test]
fn an_async_terabyte_source_stays_bounded_and_cannot_change_generation() {
    // Large virtual input exercises real awaits, the bounded suffix and provenance.
    for changes in [false, true] {
        let source = Virtual {
            generation: Cell::new(1),
            changes,
            requested: Cell::new(0),
        };
        let work = memory();
        let session = Session::new(structured_asic::Limits::default(), work.clone());
        let result = finish(probe::read(&source, &session, &work, Limits::default()));
        if changes {
            assert!(matches!(
                result,
                Err(Error::Input(InputError::Changed { .. }))
            ));
            assert_eq!(source.requested.get(), 4096);
        } else {
            let report = result.unwrap();
            assert!(has(&report, Format::Pdf, Finding::Unsupported));
            assert_eq!(report.stamp().length, 1 << 42);
            assert!(source.requested.get() <= 4096 + 65_557);
        }
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn malformed_and_truncated_corpus_never_emits_an_out_of_source_span() {
    // Exhaust all prefixes of representative framing and mutate bytes at each
    // position, exercising the public path and its short-read acquisition.
    let archive = zip(&[File::stored(b"regular", b"payload")]);
    let corpus: &[&[u8]] = &[
        b"<?xml version='1.0'?><!--x--><a:r xmlns:a='urn:x'/>",
        b"<!DOCTYPE r [<!-- ]> --> <!ATTLIST r xmlns CDATA 'urn:x'>]><r/>",
        b"%PDF-1.7\nxref\n0 1\nstartxref\n9\n%%EOF\n",
        b"\x30\x12\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02\xa0\x05\x30\x03\x02\x01\x01",
        b"RIFF\x16\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0",
        &archive.bytes,
    ];
    let check = |bytes: &[u8]| {
        let report = inspect(bytes);
        let length = bytes.len() as u64;
        assert!(
            report
                .ranges()
                .iter()
                .chain(report.candidates().iter().map(|item| &item.range))
                .all(|span| span.start <= length && span.length <= length - span.start),
            "length {length}, source {bytes:02x?}, report {report:?}"
        );
    };
    for &input in corpus {
        check(input);
        for end in 0..input.len() {
            check(&input[..end]);
        }
        let mut mutation = input.to_vec();
        for (index, &original) in input.iter().enumerate() {
            for byte in [0, 0xff, original ^ 0x80] {
                mutation[index] = byte;
                check(&mutation);
            }
            mutation[index] = original;
        }
    }
}
