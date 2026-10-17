//! Invalid empty outer sets remain inspectable, never valid binding facts.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::{
    ErrorCode,
    attribute::{Attributes, Placement},
    binding::{self, Scope},
    signer::SignerInfo,
};

fn signer_bytes(signed: bool, unsigned: bool) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42];
    if signed {
        fields.extend([0xa0, 0]);
    }
    fields.extend([0x30, 3, 6, 1, 43, 4, 1, 8]);
    if unsigned {
        fields.extend([0xa1, 0]);
    }
    let mut bytes = vec![0x30, u8::try_from(fields.len()).unwrap()];
    bytes.extend(fields);
    bytes
}

#[test]
fn empty_written_sets_retain_original_signer_and_refuse_binding() {
    // RFC5652 §5.3 requires nonempty sets. Inspection retains presence and
    // original bytes; neither signed nor unsigned emptiness grants validity.
    for (signed, unsigned) in [(true, false), (false, true), (true, true)] {
        let bytes = signer_bytes(signed, unsigned);
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let parser = Parser::ber(memory.clone());
        let mut reader = parser.read(&bytes, 700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&reader, &element).expect("inspect empty set");
        assert_eq!(signer.as_bytes(), bytes);
        assert_eq!(signer.signature().as_one(), Some(&[8][..]));
        assert_eq!(
            signer.faults().len(),
            usize::from(signed) + usize::from(unsigned)
        );
        assert_eq!(signer.signed_attributes().is_some(), signed);
        assert_eq!(signer.unsigned_attributes().is_some(), unsigned);
        if let Some(attrs) = signer.signed_attributes() {
            assert!(attrs.items().is_empty());
            assert_eq!(attrs.element().span().start, 713);
            assert_eq!(attrs.signed_bytes().unwrap(), [&[0x31][..], &[0][..]]);
            assert_eq!(
                attrs.signed_bytes().unwrap()[1].as_ptr(),
                bytes[14..].as_ptr()
            );
        }
        for fault in signer.faults() {
            assert_eq!(fault.code(), ErrorCode::EmptyAttributes);
            let index = usize::try_from(fault.offset() - 700).unwrap();
            assert_eq!(
                &bytes[index..index + 2],
                if fault.field() == "signerInfo.signedAttrs" {
                    &[0xa0, 0]
                } else {
                    &[0xa1, 0]
                }
            );
        }
        let error = binding::inspect(&signer, &reader, Scope::Content(structured_cms::oid::DATA))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::EmptyAttributes);
        assert_eq!(error.offset(), if signed { 713 } else { 721 });
        assert!(!error.is_resource());
        assert!(memory.used() > 0);
        drop(reader);
        assert_eq!(
            signer.faults().len(),
            usize::from(signed) + usize::from(unsigned)
        );
        drop(signer);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn strict_reader_refuses_while_inspection_retains_only_bounded_empty_sets() {
    // Recovery adds only the outer SIZE violation. It cannot bypass signed
    // DER, accept a wrong member tag or manufacture missing length/content.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    for (tag, placement) in [(0xa0, Placement::Signed), (0xa1, Placement::Unsigned)] {
        let bytes = [tag, 0];
        let mut reader = parser.read(&bytes, 900).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert_eq!(
            Attributes::read(&reader, &element, placement)
                .unwrap_err()
                .code(),
            ErrorCode::EmptyAttributes
        );
        let reading = Attributes::read_inspection(&reader, &element, placement).unwrap();
        assert!(reading.items().is_empty());
        let fault = reading.fault().unwrap();
        assert_eq!(fault.code(), ErrorCode::EmptyAttributes);
        assert_eq!(fault.offset(), 900);
        assert_eq!(reading.element().as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(memory.used(), 0);
    }
    for bytes in [
        &[0xa0, 0x81, 0][..],
        &[0xa0, 2, 5, 0][..],
        &[0xa0, 2, 0x30, 1][..],
    ] {
        let mut reader = parser.read(bytes, 900).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let error = Attributes::read_inspection(&reader, &element, Placement::Signed).unwrap_err();
        assert_ne!(error.code(), ErrorCode::EmptyAttributes);
        assert!(!error.is_resource());
        drop(error);
        drop(reader);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn retained_empty_set_diagnostics_obey_exact_work_and_capacity() {
    // Empty sets still allocate retained diagnostics. Exhausting current local
    // work, aggregate work or storage must refuse and release partial output.
    let bytes = signer_bytes(true, true);
    let read = |capacity, local, aggregate| {
        let memory = Memory::new(Arc::new(MemoryAccount::new(capacity, aggregate)));
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut reader = parser.read(&bytes, 700).unwrap();
        let result = reader.next_element().map_err(|_| ()).and_then(|element| {
            let result = SignerInfo::read(&reader, &element.unwrap());
            match result {
                Ok(value) => {
                    assert_eq!(value.faults().len(), 2);
                    Ok(())
                }
                Err(error) => {
                    assert!(error.is_resource());
                    assert!((700..bytes.len() as u64 + 700).contains(&error.offset()));
                    Err(())
                }
            }
        });
        assert_eq!(memory.used(), 0);
        (result.is_ok(), memory.work_used())
    };
    let (success, cost) = read(65536, 65536, 65536);
    assert!(success);
    let mut lower = 0;
    let mut upper = 65536;
    while lower < upper {
        let mid = lower + (upper - lower) / 2;
        if read(mid, 65536, 65536).0 {
            upper = mid;
        } else {
            lower = mid + 1;
        }
    }
    assert!(lower > 0);
    assert!(read(lower, cost as u64, cost).0);
    assert!(!read(lower - 1, cost as u64, cost).0);
    assert!(!read(lower, cost as u64 - 1, cost).0);
    assert!(!read(lower, cost as u64, cost - 1).0);
    assert!(!read(0, cost as u64, cost).0);
}
