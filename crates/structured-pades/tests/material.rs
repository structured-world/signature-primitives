//! Historical DSS/VRI inspection through the actual original-range reader.

extern crate alloc;

use std::{io::Write, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::source::Snapshot;
use structured_pades::{Limits, Session, document::Document, range::Slice};
mod support;
use support::ready;

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
