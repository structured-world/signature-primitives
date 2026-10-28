//! All existing public error chains work in alloc-only consumers.
#![no_std]

use core::error::Error;
use structured_asn1::memory::MemoryError;
use structured_pkix::{Error as Processing, error::CallbackError, hybrid::CheckError};
use structured_pkix::{ocsp::SignatureError, path::BuildError};

fn processing() -> Processing {
    Processing::resource(MemoryError::WorkExceeded, "certificate", 73)
}

fn same_source<E: Error, T: Error + 'static>(outer: &E, inner: &T) {
    let found = outer.source().unwrap().downcast_ref::<T>().unwrap();
    assert!(core::ptr::eq(found, inner));
}

#[test]
fn leaf_errors_keep_original_classification() {
    // Adding the core trait must not alter resource or nonce diagnostics.
    let error = processing();
    let erased: &dyn Error = &error;
    assert!(core::ptr::eq(
        erased.downcast_ref().unwrap(),
        core::ptr::from_ref(&error)
    ));
    assert!(erased.source().is_none());
    assert!(error.is_resource());
    assert_eq!(error.offset(), 73);
    let nonce = structured_pkix::ocsp::RequestNonce::from_sent(&[]).unwrap_err();
    let erased: &dyn Error = &nonce;
    assert!(core::ptr::eq(
        erased.downcast_ref().unwrap(),
        core::ptr::from_ref(&nonce)
    ));
    assert!(erased.source().is_none());
    assert_eq!(nonce.length, 0);
}

#[test]
fn callback_errors_expose_each_original_source() {
    // Both processing and injected causes remain the actual borrowed fields.
    let error: CallbackError<MemoryError> = CallbackError::Processing(processing());
    if let CallbackError::Processing(inner) = &error {
        same_source(&error, inner);
    }
    let error = CallbackError::Callback(MemoryError::OutOfMemory);
    if let CallbackError::Callback(inner) = &error {
        same_source(&error, inner);
    }
}

#[test]
fn path_errors_expose_all_three_sources() {
    // Verifier and recognizer failures cannot be erased into processing errors.
    let errors: [BuildError<MemoryError, MemoryError>; 3] = [
        BuildError::Processing(processing()),
        BuildError::Verification(MemoryError::OutOfMemory),
        BuildError::Recognition(MemoryError::CapacityOverflow),
    ];
    for error in &errors {
        match error {
            BuildError::Processing(inner) => same_source(error, inner),
            BuildError::Verification(inner) | BuildError::Recognition(inner) => {
                same_source(error, inner);
            }
        }
    }
}

#[test]
fn ocsp_errors_expose_all_three_sources() {
    // Digest and signature provider errors retain independent typed causes.
    let errors: [SignatureError<MemoryError, MemoryError>; 3] = [
        SignatureError::Processing(processing()),
        SignatureError::Verification(MemoryError::OutOfMemory),
        SignatureError::Digest(MemoryError::CapacityOverflow),
    ];
    for error in &errors {
        match error {
            SignatureError::Processing(inner) => same_source(error, inner),
            SignatureError::Verification(inner) | SignatureError::Digest(inner) => {
                same_source(error, inner);
            }
        }
    }
}

#[test]
fn hybrid_errors_expose_all_three_sources() {
    // Native and alternative provider failures stay independently observable.
    let errors: [CheckError<MemoryError, MemoryError>; 3] = [
        CheckError::Processing(processing()),
        CheckError::Native(MemoryError::OutOfMemory),
        CheckError::Alternative(MemoryError::CapacityOverflow),
    ];
    for error in &errors {
        match error {
            CheckError::Processing(inner) => same_source(error, inner),
            CheckError::Native(inner) | CheckError::Alternative(inner) => same_source(error, inner),
        }
    }
}
