use super::{RANGES, in_unicode_3_2};

/// Table A.1 as RFC 3454 prints it, so that the table written out beside
/// this file is checked against the source it came from and not against
/// itself.
const TABLE: &str = include_str!("../../test-data/rfc3454-a1.txt");

/// One line of the table: a code point, or two with a hyphen between them.
fn range(line: &str) -> Option<(u32, u32)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (first, last) = line.split_once('-').unwrap_or((line, line));
    Some((
        u32::from_str_radix(first, 16).unwrap(),
        u32::from_str_radix(last, 16).unwrap(),
    ))
}

#[test]
fn every_published_unassigned_range_is_the_range_refused() {
    let published: alloc::vec::Vec<(u32, u32)> = TABLE.lines().filter_map(range).collect();
    assert_eq!(published.len(), RANGES.len());
    assert_eq!(published, RANGES.to_vec());
}

#[test]
fn the_table_is_ascending_and_apart() {
    // The search over it is a binary one, which is only an answer if the
    // ranges rise and never touch.
    for pair in RANGES.windows(2) {
        let [(first, last), (next, _)] = [pair[0], pair[1]];
        assert!(first <= last, "{first:04X} runs backwards");
        assert!(last < next, "{last:04X} meets {next:04X}");
    }
}

#[test]
fn the_edges_of_a_range_are_inside_it() {
    // Both ends and the point before each are the cases an off-by-one in the
    // search would get wrong.
    for &(first, last) in &RANGES {
        for point in [first, last] {
            let c = char::from_u32(point).expect("the table lists no surrogate");
            assert!(in_unicode_3_2(c), "{point:04X}");
        }
        let below = first - 1;
        if let Some(before) = char::from_u32(below) {
            let touching = RANGES.iter().any(|&(a, b)| a <= below && below <= b);
            assert_eq!(in_unicode_3_2(before), touching, "{below:04X}");
        }
    }
}

#[test]
fn the_characters_this_crate_folds_onto_are_answered() {
    // The case that made the step matter: the Cherokee small letters were
    // added in Unicode 8.0 and fold onto letters that were in 3.2, so the
    // preparation must refuse the newer ones and keep the older ones.
    assert!(in_unicode_3_2('\u{AB70}'));
    assert!(in_unicode_3_2('\u{13F8}'));
    assert!(!in_unicode_3_2('\u{13A0}'));

    // And the ordinary letters a name is written from are not touched.
    for c in ['A', 'z', '0', 'Ї', 'ß', 'あ', '\u{05D0}'] {
        assert!(!in_unicode_3_2(c), "{c}");
    }
}
