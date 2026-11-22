//! Judging one piece of material against a set of constraints.

use super::*;

fn at(seconds: i64) -> Instant {
    Instant::new(seconds, 0).unwrap()
}

const END: i64 = 1_000;

const HASHES: [HashRule; 2] = [
    HashRule {
        hash: Hash::Sha1,
        until: Some(match Instant::new(END, 0) {
            Some(end) => end,
            None => unreachable!(),
        }),
    },
    HashRule {
        hash: Hash::Sha256,
        until: None,
    },
];

const SCHEMES: [SchemeRule; 2] = [
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 1024,
        min_subgroup_bits: 0,
        until: Some(match Instant::new(END, 0) {
            Some(end) => end,
            None => unreachable!(),
        }),
    },
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 3000,
        min_subgroup_bits: 0,
        until: None,
    },
];

const CONSTRAINTS: Constraints<'static> = Constraints {
    hashes: &HASHES,
    schemes: &SCHEMES,
    suites: &[SuiteRule {
        family: Family::RsaPkcs1,
        hashes: &[Hash::Sha1, Hash::Sha256],
    }],
    rsa_exponent_bits: Some(Bits { min: 17, max: 256 }),
};

/// Missing suite data denies a composite signature, while a hash-only
/// object or standalone key is judged only by the components it uses.
#[test]
fn suites_are_explicit_and_apply_only_to_composite_material() {
    let constraints = Constraints {
        suites: &[],
        ..CONSTRAINTS
    };
    assert_eq!(
        constraints.assess(rsa(4096), at(0), None),
        Err(Unmet {
            mechanism: Mechanism::Suite {
                hash: Hash::Sha256,
                scheme: key(4096)
            },
            until: None,
            proven_after: false,
        })
    );
    for material in [
        Material {
            hash: Some(Hash::Sha256),
            scheme: None,
        },
        Material {
            hash: None,
            scheme: Some(key(4096)),
        },
    ] {
        assert_eq!(constraints.assess(material, at(0), None), Ok(()));
    }
    let unmet = constraints
        .assess(rsa(4096), at(1), Some(at(0)))
        .unwrap_err();
    assert!(unmet.proven_after);
}

/// An RSA key of `bits` with the exponent 65537.
const fn key(bits: u32) -> Scheme {
    Scheme {
        family: Family::RsaPkcs1,
        bits,
        exponent_bits: Some(17),
        subgroup_bits: None,
    }
}

fn rsa(bits: u32) -> Material {
    Material {
        hash: Some(Hash::Sha256),
        scheme: Some(key(bits)),
    }
}

/// Material that existed before the end meets the constraint, at the end
/// it no longer does: the end is the first moment a mechanism is not
/// considered secure.
#[test]
fn the_end_is_the_first_moment_not_considered_secure() {
    assert_eq!(CONSTRAINTS.assess(rsa(2048), at(END - 1), None), Ok(()));
    assert_eq!(
        CONSTRAINTS.assess(rsa(2048), at(END), None),
        Err(Unmet {
            mechanism: Mechanism::Scheme(key(2048)),
            until: Some(at(END)),
            proven_after: false,
        })
    );
}

/// A key takes the rule of the largest size it reaches: 4096 bits is under
/// the open-ended 3000-bit rule, 2999 under the 1024-bit one, and a key
/// below every listed size was never considered secure.
#[test]
fn a_key_takes_the_rule_of_the_largest_size_it_reaches() {
    assert_eq!(CONSTRAINTS.assess(rsa(4096), at(END * 10), None), Ok(()));
    assert_eq!(CONSTRAINTS.assess(rsa(3000), at(END * 10), None), Ok(()));
    assert!(CONSTRAINTS.assess(rsa(2999), at(END * 10), None).is_err());
    assert_eq!(
        CONSTRAINTS.assess(rsa(512), at(0), None),
        Err(Unmet {
            mechanism: Mechanism::Scheme(key(512)),
            until: None,
            proven_after: false,
        })
    );
}

/// A mechanism the constraints do not name is not reliable, with no known
/// end, rather than passed over; any proven moment of its production is a
/// moment it was not reliable.
#[test]
fn a_mechanism_without_a_rule_is_not_reliable() {
    let pss = Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            family: Family::RsaPss,
            ..key(4096)
        }),
    };
    assert_eq!(
        CONSTRAINTS.assess(pss, at(0), None).unwrap_err().until,
        None
    );
    let md5 = Material {
        hash: Some(Hash::Md5),
        scheme: None,
    };
    let unmet = CONSTRAINTS.assess(md5, at(0), None).unwrap_err();
    assert_eq!(unmet.mechanism, Mechanism::Hash(Hash::Md5));
    assert!(!unmet.proven_after);
    assert!(
        CONSTRAINTS
            .assess(md5, at(5), Some(at(0)))
            .unwrap_err()
            .proven_after
    );
}

/// Proof the material was made at or after the end turns the missing proof
/// of existence into a proven shortfall; proof of a moment before the end
/// does not.
#[test]
fn proof_of_production_after_the_end_is_kept() {
    let sha1 = Material {
        hash: Some(Hash::Sha1),
        scheme: None,
    };
    assert!(
        CONSTRAINTS
            .assess(sha1, at(END + 5), Some(at(END)))
            .unwrap_err()
            .proven_after
    );
    assert!(
        !CONSTRAINTS
            .assess(sha1, at(END + 5), Some(at(END - 1)))
            .unwrap_err()
            .proven_after
    );
}

/// Of two shortfalls the hash's is reported, and a material that uses
/// neither a separate hash nor a sized scheme meets every constraint.
#[test]
fn the_hash_is_judged_before_the_scheme() {
    let both = Material {
        hash: Some(Hash::Sha1),
        scheme: Some(key(2048)),
    };
    assert_eq!(
        CONSTRAINTS
            .assess(both, at(END), None)
            .unwrap_err()
            .mechanism,
        Mechanism::Hash(Hash::Sha1)
    );
    let bare = Material {
        hash: None,
        scheme: None,
    };
    assert_eq!(CONSTRAINTS.assess(bare, at(i64::MAX), None), Ok(()));
}

/// TS 119 312 V2.1.1 clause 6.2.2.1 asks 2^16 < e < 2^256: an exponent of
/// 3, of more than 256 bits, or one not supplied fails whatever the
/// modulus; 65537 and a 256-bit exponent pass. Other families carry none.
#[test]
fn an_rsa_exponent_outside_the_range_is_not_reliable() {
    let with = |exponent_bits| Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            exponent_bits,
            ..key(4096)
        }),
    };
    for bits in [Some(2), Some(16), Some(257), None] {
        let unmet = CONSTRAINTS
            .assess(with(bits), at(0), None)
            .expect_err("the exponent is outside the range");
        assert_eq!(
            unmet.mechanism,
            Mechanism::Exponent(Scheme {
                exponent_bits: bits,
                ..key(4096)
            })
        );
        assert_eq!(unmet.until, None);
    }
    for bits in [17, 256] {
        assert_eq!(CONSTRAINTS.assess(with(Some(bits)), at(0), None), Ok(()));
    }
    let ecdsa = Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            family: Family::Ecdsa,
            bits: 256,
            exponent_bits: None,
            subgroup_bits: None,
        }),
    };
    let curves = Constraints {
        suites: &[SuiteRule {
            family: Family::Ecdsa,
            hashes: &[Hash::Sha256],
        }],
        schemes: &[SchemeRule {
            family: Family::Ecdsa,
            min_bits: 256,
            min_subgroup_bits: 0,
            until: None,
        }],
        ..CONSTRAINTS
    };
    assert_eq!(curves.assess(ecdsa, at(0), None), Ok(()));
}

/// Custom policies may have multiple q tiers for one p minimum. Choose the
/// strongest reached q independently of table order, retaining its own end.
#[test]
fn dsa_rules_with_equal_p_choose_the_strongest_reached_q() {
    let legacy = SchemeRule {
        family: Family::Dsa,
        min_bits: 3000,
        min_subgroup_bits: 200,
        until: Some(at(END)),
    };
    let strong = SchemeRule {
        min_subgroup_bits: 250,
        until: None,
        ..legacy
    };
    for rules in [[legacy, strong], [strong, legacy]] {
        let constraints = Constraints {
            schemes: &rules,
            suites: &[SuiteRule {
                family: Family::Dsa,
                hashes: &[Hash::Sha256],
            }],
            ..CONSTRAINTS
        };
        let material = |subgroup_bits| Material {
            hash: Some(Hash::Sha256),
            scheme: Some(Scheme {
                family: Family::Dsa,
                bits: 3072,
                exponent_bits: None,
                subgroup_bits,
            }),
        };
        for bits in [200, 249] {
            assert_eq!(
                constraints
                    .assess(material(Some(bits)), at(END), None)
                    .unwrap_err()
                    .until,
                Some(at(END))
            );
        }
        assert_eq!(
            constraints.assess(material(Some(250)), at(END), None),
            Ok(())
        );
        for bits in [None, Some(199)] {
            assert_eq!(
                constraints
                    .assess(material(bits), at(0), None)
                    .unwrap_err()
                    .until,
                None
            );
        }
    }
}
