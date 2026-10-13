//! NFKC using allocation-free Unicode table APIs and accounted buffers.

use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};

/// UAX #15 §§1.3, 3: fully decompose, stably order each combining sequence,
/// then canonically compose unblocked pairs (including adjacent Hangul Jamo).
/// <https://www.unicode.org/reports/tr15/#Description_Norm>
pub(super) fn nfkc<W: Work>(
    memory: &W,
    mut characters: impl Iterator<Item = char>,
) -> Result<OwnedVec<char, W>, MemoryError> {
    let mut output = memory.vector();
    let mut pending = memory.vector();
    let mut state = Composition::default();
    loop {
        memory.charge_work(1)?;
        let Some(character) = characters.next() else {
            break;
        };
        // The dependency exposes fully decomposed static tables, not a
        // recursive allocating iterator. A scalar's bounded table lookup
        // and emission loop are one operation; each emitted character's
        // class lookup, storage and subsequent processing are admitted below.
        memory.charge_work(1)?;
        let mut failure = None;
        decompose_compatible(character, |character| {
            if failure.is_some() {
                return;
            }
            let result = (|| {
                memory.charge_work(1)?;
                let class = canonical_combining_class(character);
                if class == 0 {
                    flush(memory, &mut pending, &mut output, &mut state)?;
                    state.push(memory, &mut output, character, class)
                } else {
                    // Original position makes an unstable allocation-free
                    // sort preserve the required order of equal classes.
                    pending.try_push((class, pending.len(), character))
                }
            })();
            if let Err(reason) = result {
                failure = Some(reason);
            }
        });
        if let Some(reason) = failure {
            return Err(reason);
        }
    }
    flush(memory, &mut pending, &mut output, &mut state)?;
    Ok(output)
}

fn flush<W: Work>(
    memory: &W,
    pending: &mut OwnedVec<(u8, usize, char), W>,
    output: &mut OwnedVec<char, W>,
    state: &mut Composition,
) -> Result<(), MemoryError> {
    pending
        .try_sort_unstable_by(|left, right| {
            Ok::<_, MemoryError>((left.0, left.1).cmp(&(right.0, right.1)))
        })
        .map_err(MemoryError::from)?;
    for &(class, _, character) in &*pending {
        state.push(memory, output, character, class)?;
    }
    pending.clear();
    Ok(())
}

#[derive(Default)]
struct Composition {
    starter: Option<usize>,
    last_class: u8,
}

impl Composition {
    fn push<W: Work>(
        &mut self,
        memory: &W,
        output: &mut OwnedVec<char, W>,
        character: char,
        class: u8,
    ) -> Result<(), MemoryError> {
        memory.charge_work(1)?;
        if let Some(starter) = self.starter
            && (self.last_class == 0 || self.last_class < class)
        {
            memory.charge_work(1)?;
            if let Some(composed) = compose(output[starter], character) {
                output[starter] = composed;
                return Ok(());
            }
        }
        let index = output.len();
        output.try_push(character)?;
        if class == 0 {
            self.starter = Some(index);
        }
        self.last_class = class;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::nfkc;
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    use unicode_normalization::UnicodeNormalization;

    #[test]
    fn accounted_nfkc_matches_the_reference_at_composition_boundaries() {
        // Ordering must be stable for equal classes, blocking must preserve
        // uncomposed marks, and Hangul composition crosses starter boundaries.
        let memory = crate::fixtures::memory();
        for text in [
            "",
            "ASCII",
            "\u{fb03}\u{2121}\u{fdfa}",
            "\u{ac01}\u{1100}\u{1161}\u{11a8}",
            "A\u{0315}\u{0300}\u{0327}",
            "A\u{0301}\u{0300}",
            "\u{0301}\u{0327}A",
            "\u{0958}\u{0344}\u{0340}",
            "A\u{030a}\u{0301}",
        ] {
            let expected: alloc::vec::Vec<char> = text.nfkc().collect();
            let actual = nfkc(&memory, text.chars()).unwrap();
            assert_eq!(&*actual, expected, "{text:?}");
        }
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn all_single_scalar_decompositions_match_the_reference() {
        // Exercise every table entry, compatibility expansion and Hangul
        // syllable without importing a fixture corpus into the public crate.
        let memory = crate::fixtures::memory();
        for scalar in 0..=0x0010_ffff {
            let Some(character) = char::from_u32(scalar) else {
                continue;
            };
            let expected: alloc::vec::Vec<char> = core::iter::once(character).nfkc().collect();
            let actual = nfkc(&memory, core::iter::once(character)).unwrap();
            assert_eq!(&*actual, expected, "U+{scalar:04X}");
        }
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn normalization_refuses_storage_and_releases_partial_buffers() {
        // A combining run must not escape the shared allocation boundary;
        // refusal drops every partially built buffer and preserves the cause.
        let memory = Memory::new(Arc::new(MemoryAccount::new(16, 1024)));
        assert_eq!(
            nfkc(&memory, "A\u{0301}".chars()),
            Err(MemoryError::LimitExceeded)
        );
        assert_eq!(memory.used(), 0);
    }
}
