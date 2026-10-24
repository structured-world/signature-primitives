use super::*;
use crate::test_support as support;
use crate::{Limits, Session, range::Slice};
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::source::Snapshot;

fn field_update(extra: &[u8]) -> support::Pdf {
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Annots [5 0 R] >>",
        ),
        (4, b"<< /Fields [5 0 R] >>"),
        (
            5,
            b"<< /FT /Tx /T (a) /V (old) /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /P 3 0 R >>",
        ),
    ]);
    pdf.append(&[(
        5,
        b"<< /FT /Tx /T (a) /V (new) /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /P 3 0 R >>",
    )]);
    if !extra.is_empty() {
        pdf.append(&[(3, extra)]);
    }
    pdf
}

#[test]
fn form_fill_uses_field_edges_without_recursing_through_widget_page_backlinks() {
    // Table254 permits filling under P=2, but not P=1. A widget's P backlink
    // must not make the changed value look like an unrelated page change.
    let pdf = field_update(&[]);
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let old = support::ready(document.graph(0, &work)).unwrap();
    let new = support::ready(document.graph(1, &work)).unwrap();
    let old = support::ready(document.fields(&old, &work)).unwrap();
    let new = support::ready(document.fields(&new, &work)).unwrap();
    assert_eq!(
        support::ready(document.classify_changes(&old, &new, Permission::FormFill, &work)).unwrap(),
        Outcome::Permitted
    );
    assert_eq!(
        support::ready(document.classify_changes(&old, &new, Permission::NoChanges, &work))
            .unwrap(),
        Outcome::Forbidden
    );
}

#[test]
fn form_fill_cannot_hide_a_simultaneous_page_geometry_change() {
    // A permitted field value cannot exempt a page reached through another
    // graph edge. P=3 permits annotations, not changing the page's MediaBox.
    let pdf = field_update(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 2 2] /Annots [5 0 R] >>");
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let old = support::ready(document.graph(0, &work)).unwrap();
    let new = support::ready(document.graph(2, &work)).unwrap();
    let old = support::ready(document.fields(&old, &work)).unwrap();
    let new = support::ready(document.fields(&new, &work)).unwrap();
    assert_eq!(
        support::ready(document.classify_changes(&old, &new, Permission::Annotations, &work))
            .unwrap(),
        Outcome::Forbidden
    );
}

#[test]
fn a_named_original_page_template_can_be_instantiated_but_not_substituted() {
    // Table254 permits actual template instantiation under P=2/3, not an
    // arbitrary new page merely labelled with TemplateInstantiated (Table30).
    for changed in [false, true] {
        let mut pdf = support::Pdf::new(&[
            (1, b"<< /Type /Catalog /Pages 2 0 R /Names << /Templates << /Names [(Invoice) 4 0 R] >> >> >>"),
            (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
            (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
            (4, b"<< /Type /Template /MediaBox [0 0 1 1] >>"),
        ]);
        let page = if changed {
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 2 2] /TemplateInstantiated /Invoice >>"
                .as_slice()
        } else {
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /TemplateInstantiated /Invoice >>"
        };
        pdf.append(&[
            (2, b"<< /Type /Pages /Count 2 /Kids [3 0 R 5 0 R] >>"),
            (5, page),
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
            Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26))),
        );
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let old = support::ready(document.graph(0, &work)).unwrap();
        let new = support::ready(document.graph(1, &work)).unwrap();
        let old = support::ready(document.fields(&old, &work)).unwrap();
        let new = support::ready(document.fields(&new, &work)).unwrap();
        assert_eq!(
            support::ready(document.classify_changes(&old, &new, Permission::FormFill, &work))
                .unwrap(),
            if changed {
                Outcome::Forbidden
            } else {
                Outcome::Permitted
            }
        );
        assert_eq!(
            support::ready(document.classify_changes(&old, &new, Permission::NoChanges, &work))
                .unwrap(),
            Outcome::Forbidden
        );
    }
}

#[test]
fn instantiated_widgets_keep_prototype_metadata_and_may_receive_new_field_names() {
    // Template instantiation copies widgets and may rename their fields. It
    // cannot use that exception to change unrelated field actions or geometry.
    for changed in [false, true] {
        let mut pdf = support::Pdf::new(&[
            (1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R /Names << /Templates << /Names [(Invoice) 4 0 R] >> >> >>"),
            (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
            (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
            (4, b"<< /Type /Template /MediaBox [0 0 1 1] /Annots [5 0 R] >>"),
            (5, b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (User) /V (default) /Rect [0 0 1 1] /P 4 0 R >>"),
            (6, b"<< /Fields [5 0 R] >>"),
        ]);
        let field = if changed {
            b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (CopiedUser) /V (filled) /Rect [0 0 2 2] /P 7 0 R >>".as_slice()
        } else {
            b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (CopiedUser) /V (filled) /Rect [0 0 1 1] /P 7 0 R >>"
        };
        pdf.append(&[(2, b"<< /Type /Pages /Count 2 /Kids [3 0 R 7 0 R] >>"),
            (6, b"<< /Fields [5 0 R 8 0 R] >>"),
            (7, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /TemplateInstantiated /Invoice /Annots [8 0 R] >>"), (8, field)]);
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(
            Limits::default(),
            Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26))),
        );
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let old = support::ready(document.graph(0, &work)).unwrap();
        let new = support::ready(document.graph(1, &work)).unwrap();
        let old = support::ready(document.fields(&old, &work)).unwrap();
        let new = support::ready(document.fields(&new, &work)).unwrap();
        assert_eq!(
            support::ready(document.classify_changes(&old, &new, Permission::FormFill, &work))
                .unwrap(),
            if changed {
                Outcome::Forbidden
            } else {
                Outcome::Permitted
            }
        );
    }
}

#[test]
fn filling_a_field_with_a_separate_widget_does_not_change_its_parent_binding() {
    // A pure widget's Parent is a field identity, not a protected deep copy
    // of the field value. Filling that same field is permitted under P=2.
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Annots [6 0 R] >>",
        ),
        (4, b"<< /Fields [5 0 R] >>"),
        (5, b"<< /FT /Tx /T (User) /V (old) /Kids [6 0 R] >>"),
        (
            6,
            b"<< /Type /Annot /Subtype /Widget /Parent 5 0 R /P 3 0 R /Rect [0 0 1 1] >>",
        ),
    ]);
    pdf.append(&[(5, b"<< /FT /Tx /T (User) /V (new) /Kids [6 0 R] >>")]);
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let session = Session::new(
        Limits::default(),
        Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26))),
    );
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let old = support::ready(document.graph(0, &work)).unwrap();
    let new = support::ready(document.graph(1, &work)).unwrap();
    let old = support::ready(document.fields(&old, &work)).unwrap();
    let new = support::ready(document.fields(&new, &work)).unwrap();
    assert_eq!(
        support::ready(document.classify_changes(&old, &new, Permission::FormFill, &work)).unwrap(),
        Outcome::Permitted
    );
    assert_eq!(
        support::ready(document.classify_changes(&old, &new, Permission::NoChanges, &work))
            .unwrap(),
        Outcome::Forbidden
    );
}
