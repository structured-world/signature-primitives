//! CMS processing and directory causes are available without std.
#![no_std]
extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount, MemoryError},
};
use structured_cms::{ContentInfo, directory};

#[test]
fn processing_chain_retains_original_asn1_error() {
    // A real parser failure remains downcastable with its original location.
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    let parser = Parser::der(memory);
    let mut reader = parser.read(&[5, 0], 73).unwrap();
    let error = ContentInfo::read(&mut reader).unwrap_err();
    let source = error.source().unwrap();
    let original = error.encoding_source().unwrap();
    assert!(core::ptr::eq(source.downcast_ref().unwrap(), original));
    assert_eq!(original.offset(), 73);
    let directory = directory::Error::Processing(error);
    assert!(directory.source().unwrap().is::<structured_cms::Error>());
    assert_eq!(
        directory
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<structured_asn1::Error>()
            .unwrap()
            .offset(),
        73
    );
}

#[test]
fn directory_resource_chain_preserves_actual_cause() {
    // Source-free budget refusal remains a resource cause, not a schema fault.
    let error = directory::Error::Resource(MemoryError::WorkExceeded);
    let directory::Error::Resource(inner) = &error else {
        unreachable!()
    };
    assert!(core::ptr::eq(
        error.source().unwrap().downcast_ref().unwrap(),
        inner
    ));
}
