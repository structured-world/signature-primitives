//! Bound delta ordering reuses validated numbers and funds every producer.

use super::*;
use core::cmp::Ordering;
use structured_asn1::memory::Work;
use structured_pkix::crl::{BoundDelta, DeltaBinding};

fn with_deltas(
    numbers: [&[u8]; 2],
    shared: bool,
    visit: impl FnOnce([BoundDelta<'_, '_, '_>; 2], [&Parser; 2], &Memory),
) {
    let execution = memory(256 * 1024, 1_000_000);
    let common = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer = structured_pkix::Certificate::read(&common, &issuer_bytes, 100).unwrap();
    let base_bytes = crl(&tbs(Some(1), &crl_metadata(Some(&[0]), None, false)));
    let base = CertificateList::read(&common, &base_bytes, 500).unwrap();
    let base = authenticated(&base, &issuer, &execution);
    let limits = Limits {
        max_work: 100_000,
        max_elements: 128,
        ..Limits::default()
    };
    let left_parser = Parser::new(Encoding::Der, limits, memory(64 * 1024, 1_000_000));
    let right_parser = Parser::new(Encoding::Der, limits, memory(64 * 1024, 1_000_000));
    let parsers = [
        &left_parser,
        if shared { &left_parser } else { &right_parser },
    ];
    let bytes = numbers.map(|number| {
        crl(&tbs(
            Some(1),
            &crl_metadata(Some(number), Some(&[0]), false),
        ))
    });
    let left = CertificateList::read(parsers[0], &bytes[0], 1000).unwrap();
    let right = CertificateList::read(parsers[1], &bytes[1], 2000).unwrap();
    let left = authenticated(&left, &issuer, &execution);
    let right = authenticated(&right, &issuer, &execution);
    let DeltaBinding::Bound(left) = base.bind_delta(&left, &execution).unwrap() else {
        panic!("left fixture must bind")
    };
    let DeltaBinding::Bound(right) = base.bind_delta(&right, &execution).unwrap() else {
        panic!("right fixture must bind")
    };
    visit([left, right], parsers, &execution);
}

#[test]
fn delta_number_order_is_numeric_without_machine_width_narrowing() {
    // DER sign padding and large common prefixes must not change numeric order.
    // Reverse and equal comparisons also exercise independent borrowed sources.
    let wide = [1; 20];
    let mut later = wide;
    later[19] = 2;
    for (left, right) in [
        (&[1][..], &[2][..]),
        (&[0x7f][..], &[0, 0x80][..]),
        (&[0, 0xff][..], &[1, 0][..]),
        (
            &[0x7f; 19][..],
            &[
                0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ][..],
        ),
        (&wide[..], &later[..]),
    ] {
        with_deltas([left, right], false, |[left, right], _, _| {
            let current = memory(0, 1000);
            assert_eq!(
                left.compare_delta_number(right, &current).unwrap(),
                Ordering::Less
            );
            assert_eq!(
                right.compare_delta_number(left, &current).unwrap(),
                Ordering::Greater
            );
            assert_eq!(
                left.compare_delta_number(left, &current).unwrap(),
                Ordering::Equal
            );
            assert_eq!(current.used(), 0);
        });
    }
    with_deltas([&[0, 0x80], &[0, 0x80]], false, |[left, right], _, _| {
        assert_eq!(
            left.compare_delta_number(right, &memory(0, 100)).unwrap(),
            Ordering::Equal
        );
    });
}

#[test]
fn delta_number_comparison_keeps_each_producing_ceiling() {
    // A new, generous current account must not reset either spent CRL parser.
    for exhausted in 0..2 {
        with_deltas([&[1], &[2]], false, |[left, right], parsers, execution| {
            let source = parsers[exhausted].execution_in(execution);
            source
                .charge_work(u64::try_from(source.work_remaining()).unwrap())
                .unwrap();
            let current = memory(0, 1000);
            let other = parsers[1 - exhausted]
                .execution_in(&current)
                .work_remaining();
            let error = left.compare_delta_number(right, &current).unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.field(), "certificateList.deltaNumberOrder");
            assert_eq!(error.offset(), left.delta().crl().span().start);
            assert_eq!(current.work_used(), 0);
            assert_eq!(
                parsers[1 - exhausted]
                    .execution_in(&current)
                    .work_remaining(),
                other
            );
        });
    }
}

#[test]
fn delta_number_comparison_keeps_both_current_ceilings() {
    // Current Work can already carry root and foreign ceilings. Adding the two
    // delta producers must preserve both, including a refusal before any bill.
    for exhausted in 0..2 {
        with_deltas([&[1], &[2]], false, |[left, right], parsers, _| {
            let current = memory(0, 1000);
            let owners: [Parser; 2] = core::array::from_fn(|index| {
                Parser::new(
                    Encoding::Der,
                    Limits {
                        max_work: if index == exhausted { 0 } else { 100 },
                        ..Limits::default()
                    },
                    current.clone(),
                )
            });
            let root = owners[0].execution_in(&current);
            let query = root.execution_for(&owners[1]);
            let before = parsers.map(|source| source.execution_in(&current).work_remaining());
            assert!(
                left.compare_delta_number(right, &query)
                    .unwrap_err()
                    .is_resource()
            );
            assert_eq!(current.work_used(), 0);
            assert_eq!(
                parsers.map(|source| source.execution_in(&current).work_remaining()),
                before
            );
        });
    }
    with_deltas([&[1], &[2]], false, |[left, right], _, _| {
        assert!(
            left.compare_delta_number(right, &memory(0, 0))
                .unwrap_err()
                .is_resource()
        );
    });
}

#[test]
fn delta_number_comparison_funds_four_distinct_ceilings_together() {
    // A funded operation consumes both existing current ceilings and both CRL
    // producers once. Repeating it cannot reset even an equal-number query.
    with_deltas([&[1], &[2]], false, |[left, right], sources, _| {
        let current = memory(0, 1000);
        let owners: [Parser; 2] = core::array::from_fn(|_| {
            Parser::new(
                Encoding::Der,
                Limits {
                    max_work: 6,
                    max_elements: 0,
                    ..Limits::default()
                },
                current.clone(),
            )
        });
        let root = owners[0].execution_in(&current);
        let query = root.execution_for(&owners[1]);
        let before = sources.map(|source| source.execution_in(&current).work_remaining());
        assert_eq!(
            left.compare_delta_number(right, &query).unwrap(),
            Ordering::Less
        );
        assert_eq!(
            right.compare_delta_number(left, &query).unwrap(),
            Ordering::Greater
        );
        for (index, source) in sources.into_iter().enumerate() {
            assert_eq!(
                source.execution_in(&current).work_remaining(),
                before[index] - 6
            );
        }
        for owner in &owners {
            assert_eq!(owner.execution_in(&current).work_remaining(), 0);
        }
        assert!(
            left.compare_delta_number(left, &query)
                .unwrap_err()
                .is_resource()
        );
        assert_eq!(current.work_used(), 6);
    });
}

#[test]
fn delta_number_comparison_bills_once_and_never_reparses() {
    // Zero remaining element allowance still permits comparison of the bound
    // INTEGERs. Distinct/aliased sources and repeat calls each pay exactly once.
    for shared in [false, true] {
        with_deltas([&[1], &[2]], shared, |[left, right], parsers, _| {
            for source in parsers {
                for attempt in 0..=128 {
                    let mut reader = source.read(&[2, 1, 0], 0).unwrap();
                    if let Err(error) = reader.read_integer() {
                        assert_eq!(
                            error.code(),
                            structured_asn1::ErrorCode::LimitExceeded(
                                structured_asn1::Limit::Elements
                            )
                        );
                        break;
                    }
                    assert!(attempt < 128, "element ceiling must be exhausted");
                }
            }
            let current = memory(0, 1000);
            let origin_bills = parsers.map(|source| source.memory().work_used());
            let before = parsers.map(|source| source.execution_in(&current).work_remaining());
            let root = parsers[0].execution_in(&current);
            let query = root.execution_for(parsers[1]);
            for expected in [3, 6] {
                assert_eq!(
                    left.compare_delta_number(right, &query).unwrap(),
                    Ordering::Less
                );
                assert_eq!(current.work_used(), expected);
                for (index, source) in parsers.iter().enumerate() {
                    assert_eq!(
                        source.execution_in(&current).work_remaining(),
                        before[index] - expected
                    );
                    assert_eq!(source.memory().work_used(), origin_bills[index]);
                }
            }
        });
    }
}
