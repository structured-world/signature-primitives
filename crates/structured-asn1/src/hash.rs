//! Seeded table hashing with an integer fast path and a keyed byte path.
//!
//! [`SeededState`] uses foldhash's quality integer mixer until the first byte
//! write. That write starts the injected byte hasher, prefixes the accumulated
//! integer hash, and routes every subsequent write into the same byte stream.
//! Neither hashing nor calling `finish` changes the table's seed.
//!
//! # Security and resources
//!
//! This is non-cryptographic table hashing, not a signature digest or a promise
//! of resistance to adaptive seed recovery. It targets independently seeded
//! tables whose hash values and timing do not expose a seed-recovery oracle.
//! A hostile document can choose strings and strided integer identities; the
//! table's secret seed must come from a trusted caller, never that document.
//! For stronger adversarial guarantees, use a keyed byte hasher for every input.
//!
//! The integer path has fixed storage and bounded work per word. Byte hashing
//! is linear in the supplied bytes, subject to the injected implementation.
//! This module does not allocate itself; cloning/building the injected builder
//! and its hashing behavior remain that implementation's responsibility.
//! Callers must admit input work and table storage before invoking infallible
//! [`Hash`](core::hash::Hash) APIs. Existing accounted collections are unchanged.
//!
//! Hashes are not stable across platforms or versions. Implementations of
//! `Hash` must supply their own prefix-free field boundaries, as required by
//! <https://doc.rust-lang.org/core/hash/trait.Hash.html#prefix-collisions>.
//! Adjacent raw byte writes are not automatically length-prefixed.

use core::hash::{BuildHasher, Hasher};
use foldhash::quality::{FixedState, FoldHasher};

/// A per-table integer seed and an independently keyed byte builder.
///
/// Cloning preserves the same hashing configuration; it does not reseed a table.
/// Each built hasher clones `B` so it can start the byte path lazily without
/// borrowing the table. With the standard builder, this only copies seed words.
/// `B::clone` must preserve its hashing configuration.
#[derive(Clone)]
pub struct SeededState<B> {
    integers: FixedState,
    bytes: B,
}

impl<B> SeededState<B> {
    /// Constructs a table builder without obtaining entropy or allocating.
    ///
    /// `integer_seed` must be independently unpredictable for each hostile-input
    /// table, and `bytes` must be appropriately keyed. Fixed public seeds are
    /// useful for tests but do not provide collision-attack protection.
    #[must_use]
    pub const fn new(integer_seed: u64, bytes: B) -> Self {
        Self {
            integers: FixedState::with_seed(integer_seed),
            bytes,
        }
    }
}

impl<B: BuildHasher + Clone> BuildHasher for SeededState<B> {
    type Hasher = SeededHasher<B>;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        SeededHasher {
            integers: self.integers.build_hasher(),
            builder: self.bytes.clone(),
            bytes: None,
        }
    }
}

/// A seeded table builder using the standard library's keyed byte hasher.
///
/// [`Default`] creates a fresh standard random state and derives a separate
/// integer seed through its keyed hash. No fixed or unkeyed fallback is used.
///
/// ```
/// # #[cfg(feature = "std")] {
/// use std::collections::HashMap;
/// use structured_asn1::hash::RandomState;
/// let mut index = HashMap::with_hasher(RandomState::default());
/// index.insert((7_u64, "subject"), 42);
/// assert_eq!(index.get(&(7, "subject")), Some(&42));
/// # }
/// ```
#[cfg(feature = "std")]
pub type RandomState = SeededState<std::hash::RandomState>;

#[cfg(feature = "std")]
impl Default for RandomState {
    fn default() -> Self {
        let bytes = std::hash::RandomState::new();
        let seed = bytes.hash_one(0x6861_7368_7365_6564_u64);
        Self::new(seed, bytes)
    }
}

/// The hasher produced by [`SeededState`].
///
/// Integer writes never construct the byte hasher until a byte write occurs.
/// After that transition, typed writes retain the byte hasher's own semantics.
pub struct SeededHasher<B: BuildHasher> {
    integers: FoldHasher<'static>,
    builder: B,
    bytes: Option<B::Hasher>,
}

macro_rules! integer_write {
    ($method:ident($value:ident: $ty:ty) => $integer:ident($mapped:expr)) => {
        #[inline]
        fn $method(&mut self, $value: $ty) {
            match &mut self.bytes {
                Some(bytes) => bytes.$method($value),
                None => self.integers.$integer($mapped),
            }
        }
    };
}

impl<B: BuildHasher> Hasher for SeededHasher<B> {
    #[inline]
    fn write(&mut self, input: &[u8]) {
        let (builder, integers) = (&self.builder, &self.integers);
        self.bytes
            .get_or_insert_with(|| {
                let mut bytes = builder.build_hasher();
                bytes.write_u64(integers.finish());
                bytes
            })
            .write(input);
    }

    integer_write!(write_u8(value: u8) => write_u8(value));
    integer_write!(write_u16(value: u16) => write_u16(value));
    integer_write!(write_u32(value: u32) => write_u32(value));
    integer_write!(write_u64(value: u64) => write_u64(value));
    integer_write!(write_u128(value: u128) => write_u128(value));
    integer_write!(write_usize(value: usize) => write_usize(value));
    integer_write!(write_i8(value: i8) => write_u8(value.cast_unsigned()));
    integer_write!(write_i16(value: i16) => write_u16(value.cast_unsigned()));
    integer_write!(write_i32(value: i32) => write_u32(value.cast_unsigned()));
    integer_write!(write_i64(value: i64) => write_u64(value.cast_unsigned()));
    integer_write!(write_i128(value: i128) => write_u128(value.cast_unsigned()));
    integer_write!(write_isize(value: isize) => write_usize(value.cast_unsigned()));

    // Expose the mode to the caller so integer-only keys eliminate byte state.
    #[inline(always)]
    fn finish(&self) -> u64 {
        match &self.bytes {
            Some(bytes) => bytes.finish(),
            None => self.integers.finish(),
        }
    }
}
