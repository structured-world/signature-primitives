//! Error interoperability without enabling the library's std feature.
#![no_std]

use core::error::Error;
use structured_asn1::memory::MemoryError;

#[test]
fn core_errors_preserve_resource_identity_and_location() {
    // Alloc-only callers can retain typed causes without allocation or std.
    let cause = MemoryError::WorkExceeded;
    let error = structured_asn1::Error::resource(cause, 73);
    let erased: &dyn Error = &error;
    assert!(core::ptr::eq(erased.downcast_ref().unwrap(), &error));
    assert_eq!(error.offset(), 73);
    assert!(error.is_resource());
    assert!(erased.source().is_none());
    let erased: &dyn Error = &cause;
    assert_eq!(erased.downcast_ref::<MemoryError>(), Some(&cause));
    assert!(erased.source().is_none());
}
