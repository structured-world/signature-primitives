//! Historical DSS/VRI inspection through the actual original-range reader.

extern crate alloc;

use std::{io::Write, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::source::Snapshot;
use structured_pades::{Limits, Session, document::Document, range::Slice};
mod support;
use support::ready;

fn compressed_vri(corrupt_last: bool) -> (Vec<u8>, u64) {
    const VRI: &str = "<< /Type /VRI /TU (D:20260101000000Z) >> ";
    const COUNT: usize = 8;
    const STREAM: usize = 5;
    const XREF: usize = STREAM + 1 + COUNT;
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = [0; STREAM + 1];
    for (number, value) in [
        (1, "<< /Type /Catalog /Pages 2 0 R /DSS 4 0 R >>"),
        (2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
    ] {
        offsets[number] = pdf.len();
        writeln!(pdf, "{number} 0 obj\n{value}\nendobj").unwrap();
    }
    offsets[4] = pdf.len();
    write!(pdf, "4 0 obj\n<< /Type /DSS /VRI <<").unwrap();
    let mut directory = Vec::new();
    for ordinal in 0..COUNT {
        let number = STREAM + 1 + ordinal;
        write!(pdf, " /{number:040X} {number} 0 R").unwrap();
        write!(directory, "{number} {} ", ordinal * VRI.len()).unwrap();
    }
    pdf.extend_from_slice(b" >> >>\nendobj\n");
    offsets[STREAM] = pdf.len();
    let first = directory.len();
    for ordinal in 0..COUNT {
        let value = VRI.replace("20260101", &format!("202601{:02}", ordinal + 1));
        directory.extend_from_slice(value.as_bytes());
    }
    writeln!(
        pdf,
        "{STREAM} 0 obj\n<< /Type /ObjStm /N {COUNT} /First {first} /Length {} >>\nstream",
        directory.len()
    )
    .unwrap();
    pdf.extend_from_slice(&directory);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = pdf.len();
    let size = XREF + 1;
    let crossref_length = size * 7;
    writeln!(pdf, "{XREF} 0 obj\n<< /Type /XRef /Root 1 0 R /Size {size} /W [1 4 2] /Length {crossref_length} >>\nstream").unwrap();
    pdf.extend_from_slice(&[0, 0, 0, 0, 0, 255, 255]);
    for offset in offsets.into_iter().skip(1) {
        pdf.push(1);
        pdf.extend_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());
        pdf.extend_from_slice(&[0, 0]);
    }
    for ordinal in 0..COUNT {
        pdf.push(2);
        pdf.extend_from_slice(&u32::try_from(STREAM).unwrap().to_be_bytes());
        let slot = if corrupt_last && ordinal + 1 == COUNT {
            ordinal - 1
        } else {
            ordinal
        };
        pdf.extend_from_slice(&u16::try_from(slot).unwrap().to_be_bytes());
    }
    pdf.push(1);
    pdf.extend_from_slice(&u32::try_from(xref).unwrap().to_be_bytes());
    pdf.extend_from_slice(&[0, 0]);
    writeln!(pdf, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF").unwrap();
    (
        pdf,
        u64::try_from(directory.len() + crossref_length).unwrap(),
    )
}

#[test]
fn compressed_vri_reuses_the_original_decoded_stream() {
    // The allowance covers the cross-reference stream and exactly one object
    // stream. Every VRI still parses its own string from decoded coordinates.
    let (pdf, max_decoded) = compressed_vri(false);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(
        Limits {
            max_decoded,
            ..Limits::default()
        },
        memory.clone(),
    );
    let source = Slice::new(
        &pdf,
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let document = ready(Document::read(&source, &session, &memory)).unwrap();
    let validation = ready(document.validation(0, &memory)).unwrap();
    assert_eq!(validation.vri().len(), 8);
    for (ordinal, entry) in validation.vri().iter().enumerate() {
        assert_eq!(
            usize::from(entry.update_time().unwrap().calendar().day),
            ordinal + 1
        );
    }
}

#[test]
fn cached_vri_directory_never_accepts_a_different_member() {
    // The last xref entry reuses its predecessor's slot. The warm lookup
    // must still reject the member identity without reinflating the stream.
    use structured_pades::error::{ErrorKind, ReadFailure, Syntax};
    let (pdf, max_decoded) = compressed_vri(true);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(
        Limits {
            max_decoded,
            ..Limits::default()
        },
        memory.clone(),
    );
    let source = Slice::new(
        &pdf,
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let document = ready(Document::read(&source, &session, &memory)).unwrap();
    let Err(ReadFailure::Format(error)) = ready(document.validation(0, &memory)) else {
        panic!("must reject a different original member");
    };
    assert!(matches!(error.kind, ErrorKind::Syntax(Syntax::Object)));
}

#[test]
fn terminal_material_refusal_retains_the_actual_stream_enclosure() {
    // A terminal inner refusal must identify the actual material body, not
    // the catalog's unrelated location or an invented physical DER offset.
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
    ]);
    pdf.append(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /DSS 4 0 R >>"),
        (4, b"<< /Certs [5 0 R] >>"),
        (5, b"<< /Length 2 >>\nstream\n\x30\x00\nendstream"),
    ]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(Limits::default(), memory.clone());
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let work = session.execution();
    let document = ready(Document::read(&source, &session, &work)).unwrap();
    let validation = ready(document.validation(1, &work)).unwrap();
    let limited = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        memory,
    );
    let operation = limited.execution_in(limited.memory());
    let Err(error) = validation.parse(&operation) else {
        panic!("exhausted current work")
    };
    assert_eq!(error.location, validation.items()[0].location());
    assert!(error.cause.is_terminal());
}

fn with_vri(entries: &str) -> Vec<u8> {
    with_vri_type("/DSS", entries)
}

fn with_vri_type(dss_type: &str, entries: &str) -> Vec<u8> {
    // Trusted fixture writer. Every offset is derived from the actual output;
    // the second root/DSS belongs to a real incremental update, not a tail
    // presented as if it were part of the original signed revision.
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = [0; 4];
    for (number, value) in [
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
    ] {
        offsets[number] = bytes.len();
        writeln!(bytes, "{number} 0 obj\n{value}\nendobj").unwrap();
    }
    let previous = bytes.len();
    write!(bytes, "xref\n0 4\n0000000000 65535 f \n").unwrap();
    for offset in &offsets[1..] {
        writeln!(bytes, "{offset:010} 00000 n ").unwrap();
    }
    writeln!(
        bytes,
        "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{previous}\n%%EOF"
    )
    .unwrap();
    let root = bytes.len();
    writeln!(
        bytes,
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /DSS 4 0 R >>\nendobj"
    )
    .unwrap();
    let dss = bytes.len();
    writeln!(bytes, "4 0 obj\n<< /Type {dss_type} /VRI << /0000000000000000000000000000000000000000 << {entries} >> >> >>\nendobj").unwrap();
    let xref = bytes.len();
    writeln!(bytes, "xref\n1 1\n{root:010} 00000 n \n4 1\n{dss:010} 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R /Prev {previous} >>\nstartxref\n{xref}\n%%EOF").unwrap();
    bytes
}

#[test]
fn written_dss_and_vri_type_names_cannot_be_ignored() {
    // EN319142-1 §§5.4.2.2–5.4.2.3 make Type optional, but constrain it
    // when present. PDF null dictionary values remain equivalent to absence.
    for (dss, vri, valid) in [
        ("/DSS", "/Type /VRI", true),
        ("null", "/Type null", true),
        ("/VRI", "", false),
        ("(DSS)", "", false),
        ("/DSS", "/Type /DSS", false),
        ("/DSS", "/Type (VRI)", false),
    ] {
        let bytes = with_vri_type(dss, vri);
        let source = Slice::new(
            &bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(
            Limits::default(),
            Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24))),
        );
        let work = session.execution();
        let document = ready(Document::read(&source, &session, &work)).unwrap();
        let result = ready(document.validation(1, &work));
        assert_eq!(result.is_ok(), valid, "DSS={dss}, VRI={vri}");
        if !valid {
            assert!(
                matches!(result, Err(structured_pades::error::ReadFailure::Format(error))
            if matches!(error.kind, structured_pades::ErrorKind::Syntax(structured_pades::error::Syntax::Dictionary)))
            );
        }
    }
}

#[test]
fn optional_material_references_keep_pdf_null_equivalence() {
    // ISO32000-1 §7.3.9 applies after indirect resolution too. Missing or null
    // optional arrays are absent; an explicitly empty VRI array is different.
    for null_dss in [false, true] {
        let mut pdf = support::Pdf::new(&[
            (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
            (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
            (
                3,
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Resources << >> >>",
            ),
        ]);
        let dss = if null_dss {
            b"null".as_slice()
        } else {
            b"<< /Type /DSS /Certs 5 0 R /CRLs 6 0 R /OCSPs 7 0 R /VRI << /0000000000000000000000000000000000000000 << /Cert 5 0 R /CRL 6 0 R /OCSP 7 0 R /TU 8 0 R /TS 5 0 R >> >> >>"
        };
        pdf.append(&[
            (1, b"<< /Type /Catalog /Pages 2 0 R /DSS 4 0 R >>"),
            (4, dss),
            (5, b"null"),
            (7, b"5 0 R"),
            (8, b"(D:20260101000000Z)"),
        ]);
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(
            Limits::default(),
            Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24))),
        );
        let work = session.execution();
        let document = ready(Document::read(&source, &session, &work)).unwrap();
        let value = ready(document.validation(1, &work)).unwrap();
        assert_eq!(value.is_present(), !null_dss);
        assert!(value.items().is_empty());
        if !null_dss {
            assert_eq!(value.vri().len(), 1);
            assert_eq!(value.vri()[0].certificates(), []);
            assert_eq!(value.vri()[0].crls(), []);
            assert_eq!(value.vri()[0].ocsp(), []);
            assert!(value.vri()[0].update_time().is_some());
            assert!(value.vri()[0].timestamp().is_none());
        }
    }
}

#[test]
fn vri_without_tu_or_ts_remains_inspectable_for_a_subsequent_document_timestamp() {
    // EN319142-1 §5.4.2.3(c) permits a subsequent document timestamp as the
    // third generation-time method. Reading this VRI cannot demand TU xor TS;
    // the later timestamp's actual coverage/check is a separate obligation.
    let bytes = with_vri("");
    let source = Slice::new(
        &bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = ready(Document::read(&source, &session, &work)).unwrap();
    assert_eq!(document.revisions(), 2);
    let before = ready(document.validation(0, &work)).unwrap();
    assert!(!before.is_present());
    assert!(before.vri().is_empty());
    let after = ready(document.validation(1, &work)).unwrap();
    assert!(after.is_present());
    assert_eq!(after.vri().len(), 1);
    assert_eq!(after.vri()[0].name(), &[b'0'; 40]);
    assert!(after.vri()[0].update_time().is_none());
    assert!(after.vri()[0].timestamp().is_none());
    assert!(matches!(
        after.vri()[0].generation_time(),
        structured_pades::material::GenerationTime::DocumentTimestampRequired
    ));
}

#[test]
fn vri_only_material_is_not_reported_as_incorporated_in_the_dss() {
    // EN319142-1 §5.4.2.3(b) requires every VRI validation value in the
    // corresponding DSS array too. Keep the readable value and the failure.
    let mut bytes = with_vri("/Cert [5 0 R]");
    let previous = String::from_utf8_lossy(&bytes)
        .rsplit("startxref\n")
        .next()
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let object = bytes.len();
    writeln!(
        bytes,
        "5 0 obj\n<< /Length 2 >>\nstream\n00\nendstream\nendobj"
    )
    .unwrap();
    let xref = bytes.len();
    writeln!(bytes, "xref\n5 1\n{object:010} 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R /Prev {previous} >>\nstartxref\n{xref}\n%%EOF").unwrap();
    let source = Slice::new(
        &bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = ready(Document::read(&source, &session, &work)).unwrap();
    let value = ready(document.validation(2, &work)).unwrap();
    assert_eq!(value.vri()[0].certificates().len(), 1);
    assert!(!value.vri()[0].all_material_in_dss());
}
