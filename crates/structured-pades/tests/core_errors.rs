//! PDF errors retain their core Error contract in alloc-only builds.
#![no_std]

use core::error::Error;
use structured_asn1::memory::MemoryError;
use structured_pades::{
    Error as PdfError, ErrorKind,
    source::{Location, Source},
};

#[test]
fn pdf_error_preserves_resource_and_original_location() {
    // Enabling error interoperation cannot change PDF terminal classification.
    let error = PdfError {
        kind: ErrorKind::Resource(MemoryError::WorkExceeded),
        location: Location::new(Source::File, 73, 2).unwrap(),
    };
    let erased: &dyn Error = &error;
    assert!(core::ptr::eq(erased.downcast_ref().unwrap(), &error));
    assert!(erased.source().is_none());
    assert!(error.is_terminal());
    assert_eq!(error.location.span().start, 73);
}
