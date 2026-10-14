//! Callback-local work admission for already retained storage.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_asn1::{Encoding, Limits, Parser};

#[test]
fn spare_capacity_copy_refuses_before_mutation_and_moves_the_keeper() {
    // A retained buffer must obey the callback's local ceiling even when
    // copying needs no allocation. Transfers themselves perform no work.
    let account = Arc::new(MemoryAccount::new(1024, 4096));
    let memory = Memory::new(account.clone());
    let mut values = memory.vector::<u8>();
    values.try_reserve_exact(16).unwrap();
    values.try_extend_from_slice(b"a").unwrap();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = parser.read(&[], 0).unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let charge = memory.used();
    let handles = Arc::strong_count(&account);
    let work = memory.work_used();
    let mut scoped = values.with_execution(&reader.execution()).unwrap();
    assert_eq!(Arc::strong_count(&account), handles);
    assert_eq!(memory.work_used(), work);
    assert_eq!(
        scoped.try_extend_from_slice(b"bc"),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(&*scoped, b"a");
    assert_eq!(scoped.as_ptr(), pointer);
    assert_eq!(scoped.capacity(), capacity);
    assert_eq!(memory.used(), charge);
    let values = scoped.into_owned();
    assert_eq!(Arc::strong_count(&account), handles);
    drop(reader);
    drop(parser);
    assert_eq!(&*values, b"a");
    assert_eq!(values.as_ptr(), pointer);
    drop(values);
    assert_eq!(memory.used(), 0);
}

#[test]
fn different_account_returns_original_without_admission() {
    // Storage cannot silently migrate to the execution account. A rejected
    // transfer returns every original ownership and capacity invariant.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 4096)));
    let other = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let mut values = memory.vector::<u8>();
    values.try_extend_from_slice(b"abc").unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let charge = memory.used();
    let work = memory.work_used();
    let values = values.with_execution(&other).unwrap_err();
    assert_eq!(&*values, b"abc");
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values.capacity(), capacity);
    assert_eq!(memory.used(), charge);
    assert_eq!(memory.work_used(), work);
    assert_eq!(other.work_used(), 0);
    assert_eq!(other.used(), 0);
}

#[test]
fn refused_growth_preserves_storage_and_generic_callback_can_restore_it() {
    // The callback carries no retained Work borrow. It restores the owned
    // buffer even on failure, without weakening the original local ceiling.
    fn append<W: structured_asn1::memory::Work>(
        state: &mut Option<structured_asn1::memory::OwnedVec<u8>>,
        work: &W,
    ) -> Result<(), MemoryError> {
        let original = state.take().unwrap();
        let mut scoped = match original.with_execution(work) {
            Ok(scoped) => scoped,
            Err(original) => {
                *state = Some(original);
                panic!("fixture accounts must match");
            }
        };
        let result = scoped.try_extend_from_slice(b"bc");
        *state = Some(scoped.into_owned());
        result
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(1, 4096)));
    let mut values = memory.vector::<u8>();
    values.try_extend_from_slice(b"a").unwrap();
    let pointer = values.as_ptr();
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 0).unwrap();
    let mut state = Some(values);
    assert_eq!(
        append(&mut state, &reader.execution()),
        Err(MemoryError::LimitExceeded)
    );
    let values = state.unwrap();
    assert_eq!(&*values, b"a");
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values.capacity(), 1);
    assert_eq!(memory.used(), 1);
    drop(values);
    assert_eq!(memory.used(), 0);
}

#[test]
fn aligned_drop_values_and_zero_sized_values_move_without_dropping() {
    // Raw-part transfer must preserve alignment, spare capacity and exactly
    // once destruction, including Vec's nonallocated zero-sized layout.
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug)]
    #[repr(align(64))]
    struct Aligned(Arc<AtomicUsize>);
    impl Drop for Aligned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[derive(Debug)]
    struct Zst;
    impl Drop for Zst {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 0).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut values = memory.vector();
    values.try_reserve_exact(4).unwrap();
    values.try_push(Aligned(drops.clone())).unwrap();
    let pointer = values.as_ptr();
    let scoped = values.with_execution(&reader.execution()).unwrap();
    assert_eq!(scoped.as_ptr(), pointer);
    assert_eq!(scoped.capacity(), 4);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let values = scoped.into_owned();
    drop(values);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(memory.used(), 0);
    let mut zst = memory.vector();
    zst.try_push(Zst).unwrap();
    let pointer = zst.as_ptr();
    let zst = zst
        .with_execution(&reader.execution())
        .unwrap()
        .into_owned();
    assert_eq!(zst.as_ptr(), pointer);
    assert_eq!(zst.capacity(), usize::MAX);
    assert_eq!(DROPS.load(Ordering::Relaxed), 0);
    drop(zst);
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(memory.used(), 0);
}
