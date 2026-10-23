//! Independently spelled DER expectations for original BER archive inputs.
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
struct Output(Vec<u8>);
impl Receiver for Output {
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), Refused> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(DerLength::new(value.len() as u64).as_bytes());
    bytes.extend_from_slice(value);
    bytes
}
fn projected(bytes: &[u8]) -> Vec<u8> {
    let parser = Parser::ber(memory());
    let mut parent = parser.read(bytes, 300).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let work = parent.execution();
    let projection = Projection::new(&parent, element, &Rules::new(&work)).unwrap();
    let mut output = Output(Vec::new());
    projection.write(&mut output, &work).unwrap();
    output.0
}
#[test]
fn constructed_bits_share_padding_validation_and_clear_only_final_unused_bits() {
    // X.690 §§8.6.4/11.2: nested fragments concatenate; only FINAL padding
    // remains, and DER clears those unused bits. There is no payload join.
    let encoded = [0x23, 0x80, 3, 2, 0, 0xaa, 0x23, 4, 3, 2, 3, 0xff, 0, 0];
    assert_eq!(projected(&encoded), [3, 3, 3, 0xaa, 0xf8]);
}
#[test]
fn pss_default_fields_use_the_original_shared_schema_in_der_projection() {
    // X.690 §11.5 applies INSIDE a valid BER AlgorithmIdentifier too.
    // Keeping explicit salt20/trailer1 would hash a non-DER prior sequence.
    let parameters = tlv(
        0x30,
        &[tlv(0xa2, &[2, 1, 20]), tlv(0xa3, &[2, 1, 1])].concat(),
    );
    let oid = tlv(6, structured_pkix::oid::RSASSA_PSS.as_bytes());
    let algorithm = tlv(0x30, &[oid.clone(), parameters].concat());
    let bytes = tlv(
        0x30,
        &[
            vec![2, 1, 3],
            vec![0x80, 1, 1],
            tlv(0x30, &tlv(6, crate::oid::SHA256.as_bytes())),
            algorithm,
            vec![4, 1, 7],
        ]
        .concat(),
    );
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 300).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = crate::signer::SignerInfo::read(&parent, &element).unwrap();
    assert!(signer.faults().is_empty());
    let work = parent.execution();
    let source = signer.fields_source().reader_in(&work).unwrap();
    let mut fields = signer.fields().signature_der(&source).unwrap();
    let mut output = Output(Vec::new());
    fields.stream(&mut output, &work).unwrap();
    assert_eq!(
        output.0,
        [tlv(0x30, &[oid, vec![0x30, 0]].concat()), vec![4, 1, 7]].concat()
    );
}
#[test]
fn sorted_projection_keeps_empty_string_fragments_and_duplicate_values() {
    // Empty original fragments must not terminate a lexicographic stream.
    // Both equal values survive SET sorting; true uses DER's ff content.
    let a = tlv(0x24, &[vec![4, 0], tlv(4, b"a")].concat());
    let b = tlv(0x24, &[tlv(4, b"a"), vec![4, 0]].concat());
    let encoded = tlv(0x31, &[b, vec![1, 1, 1], a].concat());
    assert_eq!(
        projected(&encoded),
        [0x31, 9, 1, 1, 255, 4, 1, b'a', 4, 1, b'a']
    );
}
