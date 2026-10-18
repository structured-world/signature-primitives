use super::*;
use alloc::sync::Arc;
use core::{
    cell::Cell,
    hash::{Hash, Hasher},
};
use structured_asn1::memory::{Memory, MemoryAccount};

#[derive(Clone, Copy, Debug)]
struct CountedId<'a>(&'a Cell<usize>, u8);

impl PartialEq for CountedId<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.set(self.0.get() + 1);
        self.1 == other.1
    }
}
impl Eq for CountedId<'_> {}
impl Hash for CountedId<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.1.hash(state);
    }
}
impl HashWork for CountedId<'_> {
    fn hash_work(&self) -> core::result::Result<u64, MemoryError> {
        Ok(64)
    }
}

#[test]
fn evidence_identity_admits_each_comparison_before_equality() {
    // Data-dependent Id equality must not execute under a zero/short
    // current query budget, even though its retained map is already funded.
    let calls = Cell::new(0);
    let id = CountedId(&calls, 1);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1000)));
    let snapshot = Snapshot {
        document: 1u8,
        generation: 1u8,
    };
    let coverage = Coverage::new((), snapshot, id, id, Purpose::Archive, memory.map());
    for (budget, expected_calls) in [(0, 0), (127, 0), (128, 1), (255, 1)] {
        calls.set(0);
        let current = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
        assert!(matches!(
            coverage.require_identity(snapshot, id, id, Purpose::Archive, id, &current),
            Err(CoverageError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            })
        ));
        assert_eq!(calls.get(), expected_calls);
    }
    calls.set(0);
    let exact = Memory::new(Arc::new(MemoryAccount::new(0, 256)));
    coverage
        .require_identity(snapshot, id, id, Purpose::Archive, id, &exact)
        .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(exact.charge_work(1), Err(MemoryError::WorkExceeded));
    assert_eq!(exact.used(), 0);
}
