//! Public table hashing contracts, including core-only construction.

use core::hash::{BuildHasher, Hash, Hasher};
use std::{cell::RefCell, collections::BTreeSet, hash::RandomState, rc::Rc};
use structured_asn1::hash::SeededState;

#[test]
fn equal_keys_and_clones_keep_the_same_table_configuration() {
    // Repeated lookups and clones must retain the original table's hash seed.
    let state = SeededState::new(17, RandomState::new());
    for key in [(7_u64, "subject"), (9, "issuer")] {
        assert_eq!(state.hash_one(key), state.hash_one(key));
        assert_eq!(state.hash_one(key), state.clone().hash_one(key));
    }
    assert_ne!(state.hash_one(("a", "bc")), state.hash_one(("ab", "c")));
    assert_ne!(state.hash_one((7, "x")), state.hash_one((8, "x")));
    assert_ne!(state.hash_one(("x", 7)), state.hash_one(("x", 8)));
    let mut map = std::collections::HashMap::with_hasher(state);
    map.insert((7_u64, "subject"), 42);
    assert_eq!(map.get(&(7, "subject")), Some(&42));
}

#[test]
fn low_and_control_bits_spread_for_strided_identities() {
    // Deterministic seeds make distribution regressions reproducible, including
    // seeds which degenerate a naive multiply-by-seed implementation.
    for seed in [0, 1, 17, u64::MAX, 0x1234_5678_9abc_def0] {
        let state = SeededState::new(seed, RandomState::new());
        for stride in [1_u64, 1 << 8, 1 << 16, 1 << 32] {
            let hashes: Vec<_> = (0..4096).map(|key| state.hash_one(key * stride)).collect();
            let buckets: BTreeSet<_> = hashes.iter().map(|hash| hash & 4095).collect();
            let controls: BTreeSet<_> = hashes.iter().map(|hash| hash >> 57).collect();
            assert!(
                buckets.len() > 2400,
                "seed {seed}, stride {stride}: {}",
                buckets.len()
            );
            assert_eq!(controls.len(), 128, "seed {seed}, stride {stride}");
        }
    }
}

#[derive(Clone, Default)]
struct Trace(Rc<RefCell<Vec<Event>>>);

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Build,
    Bytes(Vec<u8>),
    Word(&'static str, u128),
}

impl BuildHasher for Trace {
    type Hasher = Self;
    fn build_hasher(&self) -> Self {
        self.0.borrow_mut().push(Event::Build);
        self.clone()
    }
}

macro_rules! trace_integer {
    ($method:ident($value:ident: $ty:ty) => $mapped:expr) => {
        fn $method(&mut self, $value: $ty) {
            self.0
                .borrow_mut()
                .push(Event::Word(stringify!($method), $mapped));
        }
    };
}

impl Hasher for Trace {
    fn write(&mut self, bytes: &[u8]) {
        self.0.borrow_mut().push(Event::Bytes(bytes.to_vec()));
    }
    fn finish(&self) -> u64 {
        123
    }
    trace_integer!(write_u8(x: u8) => u128::from(x));
    trace_integer!(write_u16(x: u16) => u128::from(x));
    trace_integer!(write_u32(x: u32) => u128::from(x));
    trace_integer!(write_u64(x: u64) => u128::from(x));
    trace_integer!(write_u128(x: u128) => x);
    trace_integer!(write_usize(x: usize) => x as u128);
    trace_integer!(write_i8(x: i8) => u128::from(x.cast_unsigned()));
    trace_integer!(write_i16(x: i16) => u128::from(x.cast_unsigned()));
    trace_integer!(write_i32(x: i32) => u128::from(x.cast_unsigned()));
    trace_integer!(write_i64(x: i64) => u128::from(x.cast_unsigned()));
    trace_integer!(write_i128(x: i128) => x.cast_unsigned());
    trace_integer!(write_isize(x: isize) => x.cast_unsigned() as u128);
}

#[test]
fn every_integer_width_stays_off_the_byte_path() {
    // No byte engine may be constructed for integer-only keys, including signed
    // and 128-bit words whose default Hasher implementations would write bytes.
    let trace = Trace::default();
    let state = SeededState::new(0, trace.clone());
    let mut hasher = state.build_hasher();
    hasher.write_u8(u8::MAX);
    hasher.write_u16(u16::MAX);
    hasher.write_u32(u32::MAX);
    hasher.write_u64(u64::MAX);
    hasher.write_u128(u128::MAX);
    hasher.write_usize(usize::MAX);
    hasher.write_i8(i8::MIN);
    hasher.write_i16(i16::MIN);
    hasher.write_i32(i32::MIN);
    hasher.write_i64(i64::MIN);
    hasher.write_i128(i128::MIN);
    hasher.write_isize(isize::MIN);
    let first = hasher.finish();
    assert_eq!(hasher.finish(), first);
    assert!(trace.0.borrow().is_empty());
    hasher.write_u64(19);
    assert_ne!(hasher.finish(), first);
    assert!(trace.0.borrow().is_empty());
}

#[test]
fn first_bytes_prefix_integer_state_then_preserve_all_typed_writes() {
    // The byte engine starts exactly once. Integer fields before the transition
    // must not disappear, and those after it must not be mixed out of order.
    let trace = Trace::default();
    let mut hasher = SeededState::new(17, trace.clone()).build_hasher();
    hasher.write_u64(7);
    hasher.write_i128(-1);
    let prefix = hasher.finish();
    hasher.write(b"x");
    hasher.write_u8(1);
    hasher.write_u16(2);
    hasher.write_u32(3);
    hasher.write_u64(4);
    hasher.write_u128(5);
    hasher.write_usize(6);
    hasher.write_i8(-1);
    hasher.write_i16(-2);
    hasher.write_i32(-3);
    hasher.write_i64(-4);
    hasher.write_i128(-5);
    hasher.write_isize(-6);
    hasher.write(b"");
    assert_eq!(hasher.finish(), 123);
    assert_eq!(hasher.finish(), 123);
    assert_eq!(
        *trace.0.borrow(),
        vec![
            Event::Build,
            Event::Word("write_u64", u128::from(prefix)),
            Event::Bytes(b"x".to_vec()),
            Event::Word("write_u8", 1),
            Event::Word("write_u16", 2),
            Event::Word("write_u32", 3),
            Event::Word("write_u64", 4),
            Event::Word("write_u128", 5),
            Event::Word("write_usize", 6),
            Event::Word("write_i8", u128::from((-1_i8).cast_unsigned())),
            Event::Word("write_i16", u128::from((-2_i16).cast_unsigned())),
            Event::Word("write_i32", u128::from((-3_i32).cast_unsigned())),
            Event::Word("write_i64", u128::from((-4_i64).cast_unsigned())),
            Event::Word("write_i128", (-5_i128).cast_unsigned()),
            Event::Word("write_isize", (-6_isize).cast_unsigned() as u128),
            Event::Bytes(vec![]),
        ]
    );
}

#[test]
fn full_width_integer_values_reach_the_selected_mixer() {
    // Detect truncation and accidental signed-to-byte fallback against the
    // selected upstream integer core, not just the byte engine's event log.
    let state = SeededState::new(17, Trace::default());
    macro_rules! compare {
        ($method:ident($value:expr) => $integer:ident($mapped:expr)) => {{
            let mut actual = state.build_hasher();
            actual.$method($value);
            let mut reference = foldhash::quality::FixedState::with_seed(17).build_hasher();
            reference.$integer($mapped);
            assert_eq!(actual.finish(), reference.finish(), stringify!($method));
        }};
    }
    compare!(write_u8(u8::MAX) => write_u8(u8::MAX));
    compare!(write_u16(u16::MAX) => write_u16(u16::MAX));
    compare!(write_u32(u32::MAX) => write_u32(u32::MAX));
    compare!(write_u64(u64::MAX) => write_u64(u64::MAX));
    compare!(write_u128(1 << 127) => write_u128(1 << 127));
    compare!(write_usize(usize::MAX) => write_usize(usize::MAX));
    compare!(write_i8(i8::MIN) => write_u8(i8::MIN.cast_unsigned()));
    compare!(write_i16(i16::MIN) => write_u16(i16::MIN.cast_unsigned()));
    compare!(write_i32(i32::MIN) => write_u32(i32::MIN.cast_unsigned()));
    compare!(write_i64(i64::MIN) => write_u64(i64::MIN.cast_unsigned()));
    compare!(write_i128(i128::MIN) => write_u128(i128::MIN.cast_unsigned()));
    compare!(write_isize(isize::MIN) => write_usize(isize::MIN.cast_unsigned()));
}

#[test]
fn finish_does_not_consume_either_mode() {
    // Hashing may continue after finish, including a transition after an empty
    // byte write. The resulting stream must match uninterrupted hashing.
    let state = SeededState::new(5, RandomState::new());
    let mut observed = state.build_hasher();
    let mut uninterrupted = state.build_hasher();
    for value in [0_u64, u64::MAX] {
        value.hash(&mut observed);
        value.hash(&mut uninterrupted);
        assert_eq!(observed.finish(), observed.finish());
    }
    for bytes in [b"".as_slice(), b"left", b"right"] {
        observed.write(bytes);
        uninterrupted.write(bytes);
        assert_eq!(observed.finish(), uninterrupted.finish());
        observed.write_i64(-9);
        uninterrupted.write_i64(-9);
    }
    assert_eq!(observed.finish(), uninterrupted.finish());
}

#[cfg(feature = "std")]
#[test]
fn standard_tables_are_independently_seeded() {
    // Fresh table construction must reseed both integer and byte paths; cloning
    // an existing builder deliberately preserves both instead.
    use structured_asn1::hash::RandomState;
    let first = RandomState::default();
    let second = RandomState::default();
    assert_ne!(first.hash_one(1_u64), second.hash_one(1_u64));
    assert_ne!(first.hash_one("subject"), second.hash_one("subject"));
}
