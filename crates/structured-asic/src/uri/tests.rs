use super::*;
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

#[test]
fn metadata_root_relative_lookup_needs_no_allocation_or_copy() {
    // Most manifest references need no joining or percent decoding. A zero
    // capacity account proves this path borrows the existing lexical view.
    let work = memory(0, 10_000);
    let uri = "document.xml";
    let Target::Member {
        name: MemberName::Borrowed(name),
        part: Part::Whole,
    } = resolve(b"META-INF/ASiCManifest.xml", uri, &work).unwrap()
    else {
        panic!("borrowed member");
    };
    assert!(core::ptr::eq(name, uri.as_bytes()));
    assert_eq!(work.used(), 0);
    assert!(work.work_used() > 0);
    let Target::Member {
        name: MemberName::Borrowed(name),
        ..
    } = resolve(b"META-INF/ASiCManifest.xml", "/document.xml", &work).unwrap()
    else {
        panic!("root member");
    };
    assert_eq!(name, b"document.xml");
}

#[test]
fn only_iri_components_are_decoded_once_and_plus_is_preserved() {
    // The base is an original ZIP filename, not a URI. Its literal '%' must
    // survive while the reference's escaped bytes are decoded exactly once.
    let work = memory(4096, 10_000);
    let target = resolve(
        b"directory%20name/manifest.xml",
        "file+name%2520.txt",
        &work,
    )
    .unwrap();
    let Target::Member {
        name,
        part: Part::Whole,
    } = &target
    else {
        panic!("member");
    };
    assert_eq!(name.as_ref(), b"directory%20name/file+name%20.txt");
    assert!(work.used() >= name.as_ref().len());
    drop(target);
    assert_eq!(work.used(), 0);
}

#[test]
fn navigation_cannot_escape_package_and_components_do_not_become_coverage() {
    // Metadata uses the package root. Query/fragment presence remains a
    // separate fact and cannot silently become a whole-member digest request.
    let work = memory(4096, 10_000);
    for uri in [
        "../outside",
        "https://example.invalid/file",
        "//example.invalid/file",
    ] {
        assert!(matches!(
            resolve(b"META-INF/signatures.xml", uri, &work).unwrap(),
            Target::Negative(Negative::Outside)
        ));
    }
    assert!(matches!(
        resolve(b"META-INF/signatures.xml", "#id", &work).unwrap(),
        Target::SameDocument(Part::Fragment)
    ));
    assert!(matches!(
        resolve(b"META-INF/manifest.xml", "document.xml?#", &work).unwrap(),
        Target::Member {
            part: Part::QueryAndFragment,
            ..
        }
    ));
    let Target::Member { name, .. } = resolve(b"a/b/manifest.xml", "../object.bin", &work).unwrap()
    else {
        panic!("relative member");
    };
    assert_eq!(name.as_ref(), b"a/object.bin");
}

#[test]
fn zero_work_and_failed_decoding_never_return_a_partial_name() {
    // Even borrowed/empty fast paths must fund current work. Failed percent
    // decoding releases the partial joined allocation and retains no prefix.
    let empty = memory(4096, 0);
    assert!(matches!(
        resolve(b"", "", &empty),
        Err(MemoryError::WorkExceeded)
    ));
    let work = memory(4096, 10_000);
    for uri in ["part%", "part%Q0", "part%FF"] {
        assert!(matches!(
            resolve(b"a/manifest.xml", uri, &work).unwrap(),
            Target::Negative(_)
        ));
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn malformed_opaque_components_are_not_fabricated_as_valid_uris() {
    // Splitting before decoding is necessary, but does not excuse malformed
    // percent triplets in an otherwise opaque query or fragment component.
    let work = memory(0, 10_000);
    for uri in ["#bad%", "document.xml?bad%G0", "document.xml#bad%0"] {
        assert!(
            matches!(
                resolve(b"META-INF/signatures.xml", uri, &work).unwrap(),
                Target::Negative(Negative::Malformed)
            ),
            "{uri}"
        );
    }
}
