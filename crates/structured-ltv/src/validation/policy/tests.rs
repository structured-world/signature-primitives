//! The explicitly named catalogue's dates against their normative clauses.

use super::*;
use crate::validation::crypto::{Material, Scheme};

/// The start of the UTC day `date`, `YYYY-MM-DD`.
fn day_of(year: i64, month: i64, date: i64) -> Instant {
    // Days from civil (Howard Hinnant's algorithm), for a test-only oracle
    // independent of the constants under test.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + date - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Instant::new((era * 146_097 + doe - 719_468) * 86_400, 0).unwrap()
}

/// A key of `family` and `bits`; RSA ones with the exponent 65537.
fn rsa(family: Family, bits: u32) -> Material {
    Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            family,
            bits,
            exponent_bits: matches!(family, Family::RsaPkcs1 | Family::RsaPss).then_some(17),
            subgroup_bits: None,
        }),
    }
}

fn holds(material: Material, at: Instant) -> bool {
    ETSI_TS_119_312_V2_1_1.assess(material, at, None).is_ok()
}

/// DSA facts carry both independent security parameters; the hash is
/// separate so historical subgroup coverage is not hidden by a hash cutoff.
fn dsa(bits: u32, subgroup_bits: Option<u32>) -> Material {
    Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            family: Family::Dsa,
            bits,
            exponent_bits: None,
            subgroup_bits,
        }),
    }
}

/// TS 119 312 V2.1.1 8.4 Table 7 requires both p and q. A large p cannot
/// promote a weak or unknown q into the open-ended tier.
#[test]
fn dsa_strength_requires_both_dimensions() {
    for subgroup in [None, Some(159), Some(160), Some(199), Some(200), Some(249)] {
        assert!(!holds(dsa(3072, subgroup), day_of(2027, 1, 1)));
    }
    assert!(holds(dsa(3072, Some(250)), day_of(2100, 1, 1)));
    assert!(!holds(dsa(2999, Some(250)), day_of(2027, 1, 1)));
    assert!(!holds(dsa(1899, Some(250)), day_of(2026, 1, 1)));
}

/// Table 7's legacy tier requires q >= 200 and stops at the end of 2026;
/// a stronger p with q=160 retains only its historical, discontinued tier.
#[test]
fn dsa_subgroup_tiers_keep_their_own_end_dates() {
    assert!(!holds(dsa(3072, Some(199)), day_of(2026, 12, 31)));
    assert!(holds(dsa(1900, Some(200)), day_of(2026, 12, 31)));
    assert!(!holds(dsa(1900, Some(200)), day_of(2027, 1, 1)));
    assert!(holds(dsa(3072, Some(249)), day_of(2026, 12, 31)));
    assert!(holds(dsa(1024, Some(160)), day_of(2015, 11, 30)));
    assert!(!holds(dsa(1024, Some(160)), day_of(2015, 12, 1)));
}

/// RSA 2048 holds through 31 December 2026 and not on 1 January 2027:
/// TS 119 312 V2.1.1 clause 8.4 Table 6, L[2026] read by clause 3.4, rather
/// than the 2026-04-01 of the informative Annex C file or the 2026-01-01 of
/// Table D.2.
#[test]
fn rsa_under_3000_bits_ends_with_2026() {
    let last = day_of(2026, 12, 31);
    let next = day_of(2027, 1, 1);
    for family in [Family::RsaPkcs1, Family::RsaPss] {
        assert!(holds(rsa(family, 2048), day_of(2026, 4, 1)));
        assert!(holds(rsa(family, 2048), last));
        assert!(!holds(rsa(family, 2048), next));
    }
}

/// PKCS#1 v1.5 at 3000 bits and above is classified L and ends with 2034;
/// PSS at that size has no end (Tables 4 and 6).
#[test]
fn rsa_from_3000_bits_ends_by_padding() {
    assert!(holds(rsa(Family::RsaPkcs1, 4096), day_of(2034, 12, 31)));
    assert!(!holds(rsa(Family::RsaPkcs1, 4096), day_of(2035, 1, 1)));
    assert!(holds(rsa(Family::RsaPss, 3072), day_of(2100, 1, 1)));
}

/// TS 119 312 V2.1.1 7.3 Table 4 permits SHA3 with PSS, DSA and ECDSA,
/// but not PKCS#1 v1.5. Independently suitable components are insufficient.
#[test]
fn the_default_policy_rejects_unlisted_signature_suites() {
    for hash in [Hash::Sha3_256, Hash::Sha3_384, Hash::Sha3_512] {
        let mut material = rsa(Family::RsaPkcs1, 3072);
        material.hash = Some(hash);
        assert!(!holds(material, day_of(2026, 10, 23)));
        material.scheme.as_mut().unwrap().family = Family::RsaPss;
        assert!(holds(material, day_of(2026, 10, 23)));
    }
}

/// A table oracle for every represented hash/family pair at the current
/// policy date, preventing another accidental Cartesian-product acceptance.
#[test]
fn the_default_suite_matrix_matches_table_4() {
    for family in [
        Family::RsaPkcs1,
        Family::RsaPss,
        Family::Dsa,
        Family::Ecdsa,
        Family::Other,
    ] {
        for hash in [
            Hash::Md5,
            Hash::Sha1,
            Hash::Sha224,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha512,
            Hash::Sha3_256,
            Hash::Sha3_384,
            Hash::Sha3_512,
            Hash::Ripemd160,
            Hash::Whirlpool,
            Hash::Other,
        ] {
            let expected = match family {
                Family::RsaPkcs1 => matches!(
                    hash,
                    Hash::Sha224 | Hash::Sha256 | Hash::Sha384 | Hash::Sha512
                ),
                Family::RsaPss | Family::Dsa | Family::Ecdsa => matches!(
                    hash,
                    Hash::Sha256
                        | Hash::Sha384
                        | Hash::Sha512
                        | Hash::Sha3_256
                        | Hash::Sha3_384
                        | Hash::Sha3_512
                ),
                Family::Other => false,
            };
            let mut material = rsa(family, if family == Family::Ecdsa { 256 } else { 3072 });
            material.hash = Some(hash);
            if family == Family::Dsa {
                material.scheme.as_mut().unwrap().subgroup_bits = Some(256);
            }
            assert_eq!(
                holds(material, day_of(2026, 10, 23)),
                expected,
                "{family:?}/{hash:?}"
            );
        }
    }
}

/// Adding current suites must not turn a known historical SHA-1 signature
/// into an unlisted pair, or allow one at its Table D.1 cutoff.
#[test]
fn historical_sha1_suites_keep_the_hash_cutoff() {
    for family in [Family::RsaPkcs1, Family::RsaPss, Family::Dsa, Family::Ecdsa] {
        let mut material = rsa(family, if family == Family::Ecdsa { 256 } else { 3072 });
        material.hash = Some(Hash::Sha1);
        if family == Family::Dsa {
            material.scheme.as_mut().unwrap().subgroup_bits = Some(256);
        }
        assert!(holds(material, day_of(2012, 7, 31)), "{family:?}");
        assert!(!holds(material, day_of(2012, 8, 1)), "{family:?}");
    }
}

/// Discontinued sizes follow Table D.2: RSA 1024 and 1536 before
/// 2019-10-01, ECDSA 224 before 2021-10-01, DSA 1024 before 2015-12-01, and
/// RSA under 786 bits was never listed.
#[test]
fn discontinued_sizes_follow_table_d2() {
    assert!(holds(rsa(Family::RsaPkcs1, 1024), day_of(2019, 9, 30)));
    assert!(!holds(rsa(Family::RsaPkcs1, 1024), day_of(2019, 10, 1)));
    assert!(!holds(rsa(Family::RsaPkcs1, 1536), day_of(2019, 10, 1)));
    assert!(!holds(rsa(Family::RsaPkcs1, 512), day_of(2000, 1, 1)));
    assert!(holds(rsa(Family::Ecdsa, 224), day_of(2021, 9, 30)));
    assert!(!holds(rsa(Family::Ecdsa, 224), day_of(2021, 10, 1)));
    assert!(holds(rsa(Family::Ecdsa, 256), day_of(2100, 1, 1)));
    assert!(!holds(dsa(1024, Some(160)), day_of(2015, 12, 1)));
}

/// SHA-1 before 2012-08-01 (Table D.1), SHA-224 through 2028 (Table 1,
/// L[2028]), SHA-256 and SHA3 with no end, MD5 never.
#[test]
fn hash_functions_follow_tables_1_and_d1() {
    let hash = |hash| Material {
        hash: Some(hash),
        scheme: None,
    };
    assert!(holds(hash(Hash::Sha1), day_of(2012, 7, 31)));
    assert!(!holds(hash(Hash::Sha1), day_of(2012, 8, 1)));
    assert!(holds(hash(Hash::Sha224), day_of(2028, 12, 31)));
    assert!(!holds(hash(Hash::Sha224), day_of(2029, 1, 1)));
    assert!(holds(hash(Hash::Sha256), day_of(2100, 1, 1)));
    assert!(holds(hash(Hash::Sha3_512), day_of(2100, 1, 1)));
    assert!(!holds(hash(Hash::Md5), day_of(1995, 1, 1)));
}

/// An RSA exponent of 3 is refused even under a listed modulus and hash
/// (clause 6.2.2.1). Element requirements remain a separate input.
#[test]
fn the_default_policy_constrains_the_rsa_exponent_and_no_element() {
    let mut weak = rsa(Family::RsaPkcs1, 4096);
    if let Some(scheme) = weak.scheme.as_mut() {
        scheme.exponent_bits = Some(2);
    }
    assert!(!holds(weak, day_of(2026, 10, 19)));
}

/// A set of elements holds what was added, and names the first required
/// element that is missing, in declaration order.
#[test]
fn an_element_set_names_the_first_missing_element() {
    let required = Elements::NONE
        .with(Element::ClaimedSigningTime)
        .with(Element::SigningCertificate);
    assert!(required.contains(Element::SigningCertificate));
    assert!(!required.contains(Element::ContentType));
    assert_eq!(
        required.first_missing(Elements::NONE),
        Some(Element::SigningCertificate)
    );
    assert_eq!(
        required.first_missing(Elements::NONE.with(Element::SigningCertificate)),
        Some(Element::ClaimedSigningTime)
    );
    assert_eq!(required.first_missing(required), None);
}

/// Explicit requirements hold exactly the selected constraints.
#[test]
fn a_scheme_replaces_the_default_constraints() {
    const ONLY_SHA512: [HashRule; 1] = [HashRule {
        hash: Hash::Sha512,
        until: None,
    }];
    let requirements = Requirements {
        crypto: Constraints {
            hashes: &ONLY_SHA512,
            schemes: &[],
            suites: &[],
            rsa_exponent_bits: None,
        },
        elements: Elements::NONE,
        timestamp_delay: None,
    };
    let sha256 = Material {
        hash: Some(Hash::Sha256),
        scheme: None,
    };
    let now = day_of(2026, 10, 19);
    assert!(requirements.crypto.assess(sha256, now, None).is_err());
    assert!(ETSI_TS_119_312_V2_1_1.assess(sha256, now, None).is_ok());
}
