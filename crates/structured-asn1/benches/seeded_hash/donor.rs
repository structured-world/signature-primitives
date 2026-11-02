//! Benchmark-only reference for the original complete integer/byte state machine.
//! Source: <https://github.com/structured-world/xml-sec/blob/4ec184d9a4878eeff5f23167c4e791936ee872ac/src/collections.rs>.

use core::hash::{BuildHasher, Hasher};

#[derive(Clone)]
pub struct State {
    strings: std::hash::RandomState,
    seed: u64,
}

impl State {
    pub fn new(seed: u64, strings: std::hash::RandomState) -> Self {
        Self { strings, seed }
    }
}

impl BuildHasher for State {
    type Hasher = Words;

    #[inline]
    fn build_hasher(&self) -> Words {
        Words {
            state: self.seed,
            seed: self.seed,
            keys: self.strings.clone(),
            strings: None,
        }
    }
}

pub struct Words {
    state: u64,
    seed: u64,
    keys: std::hash::RandomState,
    strings: Option<std::hash::DefaultHasher>,
}

#[inline]
fn halves(word: u128) -> (u64, u64) {
    let low = u64::try_from(word & u128::from(u64::MAX)).expect("masked to 64 bits");
    let high = u64::try_from(word >> 64).expect("shifted to 64 bits");
    (low, high)
}

#[inline]
fn folded_multiply(left: u64, right: u64) -> u64 {
    let (low, high) = halves(u128::from(left) * u128::from(right));
    low ^ high
}

impl Hasher for Words {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (keys, state) = (&self.keys, self.state);
        self.strings
            .get_or_insert_with(|| {
                let mut strings = keys.build_hasher();
                strings.write_u64(state);
                strings
            })
            .write(bytes);
    }

    #[inline]
    fn write_u8(&mut self, word: u8) {
        self.write_u64(u64::from(word));
    }
    #[inline]
    fn write_u16(&mut self, word: u16) {
        self.write_u64(u64::from(word));
    }
    #[inline]
    fn write_u32(&mut self, word: u32) {
        self.write_u64(u64::from(word));
    }
    #[inline]
    fn write_u64(&mut self, word: u64) {
        match &mut self.strings {
            None => self.state = folded_multiply(self.state ^ word, self.seed),
            Some(strings) => strings.write_u64(word),
        }
    }
    #[inline]
    fn write_u128(&mut self, word: u128) {
        let (low, high) = halves(word);
        self.write_u64(low);
        self.write_u64(high);
    }
    #[inline]
    fn write_usize(&mut self, word: usize) {
        self.write_u64(word as u64);
    }
    #[inline]
    fn write_i8(&mut self, word: i8) {
        self.write_u8(word.cast_unsigned());
    }
    #[inline]
    fn write_i16(&mut self, word: i16) {
        self.write_u16(word.cast_unsigned());
    }
    #[inline]
    fn write_i32(&mut self, word: i32) {
        self.write_u32(word.cast_unsigned());
    }
    #[inline]
    fn write_i64(&mut self, word: i64) {
        self.write_u64(word.cast_unsigned());
    }
    #[inline]
    fn write_i128(&mut self, word: i128) {
        self.write_u128(word.cast_unsigned());
    }
    #[inline]
    fn write_isize(&mut self, word: isize) {
        self.write_usize(word.cast_unsigned());
    }

    #[inline]
    fn finish(&self) -> u64 {
        let state = match &self.strings {
            Some(strings) => strings.finish(),
            None => self.state,
        };
        folded_multiply(state, self.seed.rotate_left(32) | 1)
    }
}
