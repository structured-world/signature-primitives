//! `PoE` metadata order and archived TSA order share exact decimal UTC facts.
use std::{cmp::Ordering, sync::Arc};
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::temporal::{self, CompareError, ExactReading, LeapTable};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128); // fixed small, independent wire fixtures
    let mut value = vec![tag, u8::try_from(contents.len()).unwrap()];
    value.extend_from_slice(contents);
    value
}
fn read(bytes: &[u8], work: &Memory) -> ExactReading {
    let parser = Parser::ber(work.clone());
    let mut source = parser.read(bytes, 700).unwrap();
    let element = source.next_element().unwrap().unwrap();
    let plain = temporal::read_generalized(&source, &element, "date").unwrap();
    let exact = temporal::read_generalized_exact(&source, &element, "date").unwrap();
    assert_eq!(plain, exact.reading());
    exact // no parser/input borrow may escape this helper
}

#[test]
fn minute_hour_offset_and_constructed_fractions_share_the_same_exact_value() {
    // Nanosecond floors alone would collapse these pairs and lose their
    // actual order. Shorter components and BER fragments must share the parser.
    let work = memory();
    let table = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let second = read(&tlv(24, b"20000101000000.0000000006Z"), &work);
    let minute = read(&tlv(24, b"200001010000,00000000001Z"), &work);
    let offset = read(&tlv(24, b"20000101010000.0000000006000+0100"), &work);
    let mut fragments = tlv(4, b"20000101");
    fragments.extend_from_slice(&tlv(4, b"000000.0000000006Z"));
    let constructed = read(&tlv(0x38, &fragments), &work);
    for same in [&minute, &offset, &constructed] {
        assert_eq!(
            second.compare(same, &table, &work).unwrap(),
            Ordering::Equal
        );
    }
    let hour = read(&tlv(24, b"2000010100.000000000001Z"), &work);
    let equivalent = read(&tlv(24, b"20000101000000.0000000036Z"), &work);
    assert_eq!(
        hour.compare(&equivalent, &table, &work).unwrap(),
        Ordering::Equal
    );
    assert_eq!(
        second.compare(&hour, &table, &work).unwrap(),
        Ordering::Less
    );
    assert!(work.used() > 0);
    drop((second, minute, offset, constructed, hour, equivalent));
    assert_eq!(work.used(), 0);
}

#[test]
fn retained_precision_copy_and_comparison_refuse_current_work_before_scanning() {
    // A retained fractional owner survives parser drop, but neither copying
    // nor UTC/decimal comparison may bypass a newly exhausted operation.
    let work = memory();
    let a = read(&tlv(24, b"20000101000000.0000000001Z"), &work);
    let b = read(&tlv(24, b"20000101000000.0000000002Z"), &work);
    let table = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    assert_eq!(a.compare(&b, &table, &work).unwrap(), Ordering::Less);
    let copy = a.try_copy_in(&work, "date", 700).unwrap();
    let capacity = work.used();
    work.charge_work(work.work_remaining() as u64).unwrap();
    assert!(a.try_copy_in(&work, "date", 700).unwrap_err().is_resource());
    assert!(matches!(
        a.compare(&b, &table, &work),
        Err(CompareError::Resource(_))
    ));
    assert_eq!(work.used(), capacity);
    drop((a, b, copy));
    assert_eq!(work.used(), 0);
}
