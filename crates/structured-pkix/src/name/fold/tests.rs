use super::{Fold, TABLE, of};
use alloc::string::String;

/// The published mapping this module's table was derived from, so that a
/// slip in writing it out is caught here rather than in a name that quietly
/// stops matching.
const CASE_FOLDING: &str = include_str!("../../test-data/CaseFolding.txt");

/// The fold this crate applies, as the characters it produces.
fn folded(c: char) -> String {
    match of(c) {
        Fold::Mapped(mapped) => String::from(mapped),
        Fold::One(one) => String::from(one),
        Fold::Lowercase => c.to_lowercase().collect(),
    }
}

#[test]
fn every_published_full_fold_is_the_fold_applied() {
    // Statuses C and F together are the full case folding: the common folds
    // and the ones that produce more than one character. T is the Turkish
    // tailoring, which the profile does not ask for, and S is the simple
    // alternative to F, which is the one this fold is not.
    let mut checked = 0usize;
    for line in CASE_FOLDING.lines() {
        let Some(body) = line.split('#').next() else {
            continue;
        };
        let fields: [&str; 3] = {
            let mut parts = body.split(';').map(str::trim);
            match (parts.next(), parts.next(), parts.next()) {
                (Some(a), Some(b), Some(c)) if !a.is_empty() => [a, b, c],
                _ => continue,
            }
        };
        if !matches!(fields[1], "C" | "F") {
            continue;
        }
        let from = char::from_u32(u32::from_str_radix(fields[0], 16).unwrap()).unwrap();
        let to: String = fields[2]
            .split_whitespace()
            .map(|point| char::from_u32(u32::from_str_radix(point, 16).unwrap()).unwrap())
            .collect();
        assert_eq!(folded(from), to, "{from:?} ({:04X})", u32::from(from));
        checked += 1;
    }
    // The file is parsed, not merely opened: a reading that silently matched
    // nothing would pass every assertion above.
    assert!(checked > 1_000, "{checked}");
}

#[test]
fn a_character_the_file_does_not_fold_folds_to_itself() {
    // The other half of the same file. A character with no C or F entry has
    // no case folding, so the fold is the character, and the lowercase
    // mapping this falls back to is not always that: Cherokee writes its
    // capitals as the folded form, so lowering one moves it while folding
    // it does not. A fold that moves a character the profile leaves alone
    // makes two names equal that the profile does not.
    let mut folds: alloc::collections::BTreeSet<char> = alloc::collections::BTreeSet::new();
    for line in CASE_FOLDING.lines() {
        let Some(body) = line.split('#').next() else {
            continue;
        };
        let mut parts = body.split(';').map(str::trim);
        let (Some(point), Some(status)) = (parts.next(), parts.next()) else {
            continue;
        };
        if point.is_empty() || !matches!(status, "C" | "F") {
            continue;
        }
        folds.insert(char::from_u32(u32::from_str_radix(point, 16).unwrap()).unwrap());
    }

    let mut checked = 0usize;
    for point in 0..=0x10_FFFFu32 {
        let Some(c) = char::from_u32(point) else {
            continue;
        };
        if folds.contains(&c) {
            continue;
        }
        assert_eq!(folded(c), String::from(c), "{c:?} ({point:04X})");
        checked += 1;
    }
    assert!(checked > 1_000_000, "{checked}");
}

#[test]
fn the_table_is_searchable_and_earns_its_entries() {
    // Binary search is only an answer over a sorted list without repeats.
    assert!(
        TABLE.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "the table is not sorted"
    );
    // An entry that agreed with the lowercase mapping would be a wrong one
    // copied from the wrong column, and nothing else would notice.
    for &(from, to) in &TABLE {
        let lowered: String = from.to_lowercase().collect();
        assert_ne!(lowered, to, "{from:?}");
    }
}

#[test]
fn a_letter_whose_fold_changes_its_length_folds() {
    // The cases a name comparison actually meets.
    assert_eq!(folded('ß'), "ss");
    assert_eq!(folded('ẞ'), "ss");
    assert_eq!(folded('ς'), "σ");
    assert_eq!(folded('ﬁ'), "fi");
    // Cherokee, where the fold is arithmetic: both ends of both stretches.
    assert_eq!(folded('\u{13F8}'), "\u{13F0}");
    assert_eq!(folded('\u{13FD}'), "\u{13F5}");
    assert_eq!(folded('\u{AB70}'), "\u{13A0}");
    assert_eq!(folded('\u{ABBF}'), "\u{13EF}");
    // Their neighbours are outside it and fold by the ordinary rule.
    assert_eq!(folded('\u{13F7}'), "\u{13F7}");
    assert_eq!(folded('\u{13FE}'), "\u{13FE}");
    // A letter with no fold of its own is itself, in either script.
    assert_eq!(folded('и'), "и");
    assert_eq!(folded('И'), "и");
}
