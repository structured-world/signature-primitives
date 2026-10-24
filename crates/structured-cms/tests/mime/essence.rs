use super::work;
use structured_asn1::memory::MemoryError;
use structured_cms::mime::{Essences, Syntax};

const PAIRS: [(&str, &str); 2] = [
    ("application", "vnd.etsi.asic-s+zip"),
    ("application", "vnd.etsi.asic-e+zip"),
];

#[test]
fn one_shared_grammar_matches_case_comments_parameters_and_every_partition() {
    // Type/subtype comparison ignores case/CFWS but never parameter syntax.
    // Every split also proves that no borrowed input or joined buffer is kept.
    for (value, expected) in [
        ("application/vnd.etsi.asic-s+zip", [true, false]),
        (
            "(outer(inner)) APPLICATION (x) / VND.ETSI.ASIC-E+ZIP ; name=\"a;b\"",
            [false, true],
        ),
        (
            "application/vnd.etsi.asic-e+zip; charset=\"\"",
            [false, true],
        ),
        ("application/vnd.etsi.asic-e+zip-more", [false, false]),
        (
            "text/plain; value=\"application/vnd.etsi.asic-e+zip\"",
            [false, false],
        ),
        ("application/vnd.etsi.asic-e+zip; broken", [false, false]),
        ("appli(comment)cation/vnd.etsi.asic-e+zip", [false, false]),
        (
            "application/vnd.etsi.asic-e+zip; charset=\"unterminated",
            [false, false],
        ),
    ] {
        for split in 0..=value.len() {
            let work = work(100_000);
            let mut grammar = Syntax::<false>::new();
            let mut matches = Essences::<2>::new(PAIRS);
            for fragment in [&value.as_bytes()[..split], &value.as_bytes()[split..]] {
                assert_eq!(
                    grammar.feed(fragment, &work).unwrap(),
                    matches.feed(fragment, &work).unwrap()
                );
            }
            assert_eq!(
                matches.complete(),
                grammar.complete(),
                "{value}, split={split}"
            );
            assert_eq!(matches.matches(0), Some(expected[0]), "{value}");
            assert_eq!(matches.matches(1), Some(expected[1]), "{value}");
            assert_eq!(matches.matches(2), None);
            assert_eq!(work.used(), 0);
        }
    }
}

#[test]
fn refusal_precedes_grammar_and_comparison_state_and_invalidity_is_sticky() {
    // A failed current query cannot consume a suffix or complete a known pair.
    let mut matches = Essences::<2>::new(PAIRS);
    matches.feed("application/", &work(100_000)).unwrap();
    assert_eq!(
        matches.feed("vnd.etsi.asic-e+zip", &work(0)),
        Err(MemoryError::WorkExceeded)
    );
    assert!(!matches.complete());
    matches.feed("vnd.etsi.asic-e+zip", &work(100_000)).unwrap();
    assert_eq!(matches.matches(1), Some(true));
    assert!(!matches.feed("?", &work(100_000)).unwrap());
    assert!(
        !matches
            .feed("application/vnd.etsi.asic-e+zip", &work(100_000))
            .unwrap()
    );
    assert_eq!(matches.matches(1), Some(false));
}
