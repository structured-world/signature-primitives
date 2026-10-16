//! Standalone ESS issuer hints retain original views and diagnostic ownership.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{ErrorCode, ess::IssuerSerialReading};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn standalone_issuer_serial_borrows_original_der() {
    // XAdES embeds IssuerSerial directly, not an artificial SigningCertificate.
    // The same kernel must preserve original names, serial and source offsets.
    let bytes = [
        0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, b'a',
        2, 1, 7,
    ];
    let account = memory();
    let parser = Parser::der(account.clone());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let reading = IssuerSerialReading::read(&parent, &element, "xades.issuerSerialV2").unwrap();
    assert!(reading.faults().is_empty());
    assert_eq!(reading.value().serial().as_bytes(), &bytes[22..]);
    assert_eq!(
        reading.value().serial().as_bytes().as_ptr(),
        bytes[22..].as_ptr()
    );
    assert_eq!(reading.value().names_element().span().start, 702);
    assert_eq!(reading.value().names_element().as_bytes(), &bytes[2..20]);
    assert_eq!(reading.value().names().len(), 1);
    assert_eq!(reading.value().span().start, 700);
    drop(reading);
    assert_eq!(account.used(), 0);
}

#[test]
fn standalone_issuer_serial_keeps_fault_storage_after_parser_drop() {
    // Empty GeneralNames has a readable hint but cannot assert an issuer. Its
    // original fault remains independently owned after the borrowed view drops.
    let bytes = [0x30, 5, 0x30, 0, 2, 1, 7];
    let account = memory();
    let faults = {
        let parser = Parser::der(account.clone());
        let mut parent = parser.read(&bytes, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let reading = IssuerSerialReading::read(&parent, &element, "xades.issuerSerialV2").unwrap();
        assert_eq!(reading.value().serial().as_u64(), Some(7));
        let (_, faults) = reading.into_parts();
        faults
    };
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].code(), ErrorCode::AttributeSyntax);
    assert_eq!(faults[0].offset(), 702);
    assert_eq!(faults[0].field(), "xades.issuerSerialV2");
    assert!(account.used() > 0);
    drop(faults);
    assert_eq!(account.used(), 0);
}

#[test]
fn standalone_issuer_serial_retains_all_original_faults() {
    // A trailing value cannot hide the empty-issuer fault or erase the serial.
    // The diagnostic wrapper preserves the existing kernel's source order.
    let bytes = [0x30, 7, 0x30, 0, 2, 1, 7, 5, 0];
    let account = memory();
    let parser = Parser::der(account.clone());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let reading = IssuerSerialReading::read(&parent, &element, "xades.issuerSerialV2").unwrap();
    assert_eq!(reading.value().serial().as_bytes(), &bytes[6..7]);
    assert_eq!(reading.faults().len(), 2);
    assert_eq!(reading.faults()[0].code(), ErrorCode::TrailingData);
    assert_eq!(reading.faults()[0].offset(), 707);
    assert_eq!(reading.faults()[1].code(), ErrorCode::AttributeSyntax);
    assert_eq!(reading.faults()[1].offset(), 702);
    drop(reading);
    assert_eq!(account.used(), 0);
}

#[test]
fn standalone_issuer_serial_refuses_unfunded_reading() {
    // Missing storage cannot turn malformed input into a reading without its
    // required diagnostics; all partial path/result capacity must roll back.
    let bytes = [0x30, 5, 0x30, 0, 2, 1, 7];
    let account = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let parser = Parser::der(account.clone());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = IssuerSerialReading::read(&parent, &element, "xades.issuerSerialV2").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 702);
    assert_eq!(account.used(), 0);
}
