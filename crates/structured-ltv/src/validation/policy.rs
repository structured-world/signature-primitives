//! Caller-selected requirements and an explicit cryptographic constraint catalogue.
//!
//! Catalogue source: ETSI TS 119 312 V2.1.1:
//! <https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf>.

use super::crypto::{Bits, Constraints, Family, Hash, HashRule, SchemeRule, SuiteRule};
use core::time::Duration;
use structured_pkix::temporal::Instant;

/// A signature element a policy can require (EN 319 102-1 V1.4.1 5.1.4.4
/// and the attributes of 4.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    /// A signed reference to, or copy of, the signing certificate (4.2.5.2).
    SigningCertificate,
    /// A signature policy identifier (4.2.5.3).
    SignaturePolicy,
    /// The data content type (4.2.5.5).
    ContentType,
    /// A commitment type indication (4.2.5.6).
    CommitmentType,
    /// The claimed signing time (4.2.5.8).
    ClaimedSigningTime,
    /// The claimed signer location (4.2.5.9).
    SignerLocation,
    /// Signer attributes (4.2.5.10).
    SignerAttributes,
    /// A timestamp over the signed data, covered by the signature.
    ContentTimestamp,
}

impl Element {
    /// Every element, in declaration order.
    pub const ALL: [Element; 8] = [
        Element::SigningCertificate,
        Element::SignaturePolicy,
        Element::ContentType,
        Element::CommitmentType,
        Element::ClaimedSigningTime,
        Element::SignerLocation,
        Element::SignerAttributes,
        Element::ContentTimestamp,
    ];

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// A set of signature elements: those a policy requires, or those a
/// signature carries in a form that passed its own checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Elements(u16);

impl Elements {
    /// The empty set.
    pub const NONE: Elements = Elements(0);

    /// This set with `element` added.
    #[must_use]
    pub const fn with(self, element: Element) -> Self {
        Elements(self.0 | element.bit())
    }

    /// Whether `element` is in the set.
    #[must_use]
    pub const fn contains(self, element: Element) -> bool {
        self.0 & element.bit() != 0
    }

    /// Required elements without a passing supplied result.
    #[must_use]
    pub const fn missing_from(self, present: Elements) -> Elements {
        Elements(self.0 & !present.0)
    }

    /// The first element of `self` missing from `present`, in declaration
    /// order.
    #[must_use]
    pub fn first_missing(self, present: Elements) -> Option<Element> {
        Element::ALL
            .into_iter()
            .find(|element| self.contains(*element) && !present.contains(*element))
    }
}

/// Requirements already selected by the caller for one validation.
/// Policy selection and its identity for reporting belong to the caller.
///
/// ```
/// use structured_ltv::validation::{Requirements, Elements, Element, ETSI_TS_119_312_V2_1_1};
/// let requirements = Requirements {
///     crypto: ETSI_TS_119_312_V2_1_1,
///     elements: Elements::NONE.with(Element::SigningCertificate),
///     timestamp_delay: None,
/// };
/// assert!(requirements.elements.contains(Element::SigningCertificate));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirements<'a> {
    /// The complete cryptographic constraints to apply.
    pub crypto: Constraints<'a>,
    /// The signature elements a signature has to carry (5.1.4.4).
    pub elements: Elements,
    /// Optional maximum delay after the claimed signing time for a signature
    /// timestamp (EN 319 102-1 V1.4.1 5.5.4 step 5). Equality fails.
    pub timestamp_delay: Option<Duration>,
}

/// The start of a UTC day, as POSIX seconds.
const fn day(seconds: i64) -> Instant {
    match Instant::new(seconds, 0) {
        Some(instant) => instant,
        None => panic!("whole seconds always form an instant"),
    }
}

// The first moment each mechanism stops being considered secure. TS 119 312
// writes an end as the last day it holds ("L[yyyy]": up to 31.12.yyyy,
// clause 3.4) or as "< date" (Annex D), so the moment here is the start of
// the day after the last one.
const AUG_2010: Option<Instant> = Some(day(1_280_620_800));
const AUG_2012: Option<Instant> = Some(day(1_343_779_200));
const AUG_2014: Option<Instant> = Some(day(1_406_851_200));
const DEC_2015: Option<Instant> = Some(day(1_448_928_000));
const OCT_2019: Option<Instant> = Some(day(1_569_888_000));
const DEC_2020: Option<Instant> = Some(day(1_606_780_800));
const OCT_2021: Option<Instant> = Some(day(1_633_046_400));
const JAN_2027: Option<Instant> = Some(day(1_798_761_600));
const JAN_2029: Option<Instant> = Some(day(1_861_920_000));
const JAN_2035: Option<Instant> = Some(day(2_051_222_400));

/// Hash functions, ETSI TS 119 312 V2.1.1 Table 1 and Table D.1.
///
/// SHA-224 follows Table 1 (L[2028]); Table D.1 suggests 2026-01-01, but it
/// is informative and the normative table is the one followed. MD5 is not
/// listed by this edition and so is never considered secure.
const HASHES: [HashRule; 10] = [
    HashRule {
        hash: Hash::Sha1,
        until: AUG_2012,
    },
    HashRule {
        hash: Hash::Ripemd160,
        until: AUG_2014,
    },
    HashRule {
        hash: Hash::Whirlpool,
        until: DEC_2020,
    },
    HashRule {
        hash: Hash::Sha224,
        until: JAN_2029,
    },
    HashRule {
        hash: Hash::Sha256,
        until: None,
    },
    HashRule {
        hash: Hash::Sha384,
        until: None,
    },
    HashRule {
        hash: Hash::Sha512,
        until: None,
    },
    HashRule {
        hash: Hash::Sha3_256,
        until: None,
    },
    HashRule {
        hash: Hash::Sha3_384,
        until: None,
    },
    HashRule {
        hash: Hash::Sha3_512,
        until: None,
    },
];

/// Signature schemes by key size, ETSI TS 119 312 V2.1.1 Tables 4, 6, 7 and
/// D.2.
///
/// RSA keys of 1900 to 3000 bits end with 2026 (clause 8.4 Table 6, L[2026]).
/// The informative Annex C file says 2026-04-01 and Table D.2 says
/// 2026-01-01; the normative table is the one followed. PKCS#1 v1.5 at 3000
/// bits and above is classified L, up to 31.12.2034 (clause 3.4, Table 4).
/// PSS, DSA with p >= 3000 and q >= 250 (8.4 Table 7), and ECDSA at 256
/// bits and above are recommended with no end. DSA's discontinued 1024-bit
/// tier retains q >= 160 (TS 102 176-1 V2.0.0 6.1.2.2 and Table D.2 here).
const SCHEMES: [SchemeRule; 19] = [
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 786,
        min_subgroup_bits: 0,
        until: AUG_2010,
    },
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 1024,
        min_subgroup_bits: 0,
        until: OCT_2019,
    },
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 1536,
        min_subgroup_bits: 0,
        until: OCT_2019,
    },
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 1900,
        min_subgroup_bits: 0,
        until: JAN_2027,
    },
    SchemeRule {
        family: Family::RsaPkcs1,
        min_bits: 3000,
        min_subgroup_bits: 0,
        until: JAN_2035,
    },
    SchemeRule {
        family: Family::RsaPss,
        min_bits: 786,
        min_subgroup_bits: 0,
        until: AUG_2010,
    },
    SchemeRule {
        family: Family::RsaPss,
        min_bits: 1024,
        min_subgroup_bits: 0,
        until: OCT_2019,
    },
    SchemeRule {
        family: Family::RsaPss,
        min_bits: 1536,
        min_subgroup_bits: 0,
        until: OCT_2019,
    },
    SchemeRule {
        family: Family::RsaPss,
        min_bits: 1900,
        min_subgroup_bits: 0,
        until: JAN_2027,
    },
    SchemeRule {
        family: Family::RsaPss,
        min_bits: 3000,
        min_subgroup_bits: 0,
        until: None,
    },
    SchemeRule {
        family: Family::Dsa,
        min_bits: 1024,
        min_subgroup_bits: 160,
        until: DEC_2015,
    },
    SchemeRule {
        family: Family::Dsa,
        min_bits: 1900,
        min_subgroup_bits: 200,
        until: JAN_2027,
    },
    SchemeRule {
        family: Family::Dsa,
        min_bits: 3000,
        min_subgroup_bits: 250,
        until: None,
    },
    SchemeRule {
        family: Family::Ecdsa,
        min_bits: 160,
        min_subgroup_bits: 0,
        until: AUG_2012,
    },
    SchemeRule {
        family: Family::Ecdsa,
        min_bits: 163,
        min_subgroup_bits: 0,
        until: AUG_2012,
    },
    SchemeRule {
        family: Family::Ecdsa,
        min_bits: 224,
        min_subgroup_bits: 0,
        until: OCT_2021,
    },
    SchemeRule {
        family: Family::Ecdsa,
        min_bits: 256,
        min_subgroup_bits: 0,
        until: None,
    },
    // Clauses 6.2.2.4 and 7.3 Table 4: EdDSA variants are fixed and
    // recommended; their intrinsic hashes are not separate suite inputs.
    SchemeRule {
        family: Family::Ed25519,
        min_bits: 0,
        min_subgroup_bits: 0,
        until: None,
    },
    SchemeRule {
        family: Family::Ed448,
        min_bits: 0,
        min_subgroup_bits: 0,
        until: None,
    },
];

// TS 119 312 V2.1.1 7.3 Table 4, for the families represented by Material.
// SHA-1 is retained only for historical assessment, with the discontinued
// function's end in Table D.1 enforced by HASHES. Its signature bindings are
// RFC 3279 2.2.1/2.2.2/2.2.3 and RFC 4055 3.1. Other standalone hash rules
// do not implicitly authorize a signature suite absent from this list.
const SUITES: [SuiteRule<'static>; 7] = [
    SuiteRule {
        family: Family::RsaPkcs1,
        key_bits: None,
        hashes: &[
            Hash::Sha1,
            Hash::Sha224,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha512,
        ],
    },
    SuiteRule {
        family: Family::RsaPss,
        key_bits: None,
        hashes: &[
            Hash::Sha1,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha512,
            Hash::Sha3_256,
            Hash::Sha3_384,
            Hash::Sha3_512,
        ],
    },
    SuiteRule {
        family: Family::Dsa,
        key_bits: None,
        hashes: &[
            Hash::Sha1,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha512,
            Hash::Sha3_256,
            Hash::Sha3_384,
            Hash::Sha3_512,
        ],
    },
    SuiteRule {
        family: Family::Ecdsa,
        key_bits: None,
        hashes: &[Hash::Sha1],
    },
    // TS 119 312 V2.1.1 clause 7.3 requires matching hash output and
    // curve key sizes for its recommended ECDSA combinations.
    SuiteRule {
        family: Family::Ecdsa,
        key_bits: Some(Bits { min: 256, max: 256 }),
        hashes: &[Hash::Sha256, Hash::Sha3_256],
    },
    SuiteRule {
        family: Family::Ecdsa,
        key_bits: Some(Bits { min: 384, max: 384 }),
        hashes: &[Hash::Sha384, Hash::Sha3_384],
    },
    SuiteRule {
        family: Family::Ecdsa,
        key_bits: Some(Bits { min: 512, max: 512 }),
        hashes: &[Hash::Sha512, Hash::Sha3_512],
    },
];

/// Named cryptographic constraints from ETSI TS 119 312 V2.1.1
/// (2026-06), as ETSI EN 319 102-1 V1.4.1 5.1.4.3 points to through
/// TS 119 172-1 Table A.2 row p.
/// Covers the mechanisms represented by this module. The evaluator never
/// selects the catalogue implicitly.
pub const ETSI_TS_119_312_V2_1_1: Constraints<'static> = Constraints {
    hashes: &HASHES,
    schemes: &SCHEMES,
    suites: &SUITES,
    // Clause 6.2.2.1: an odd exponent with 2^16 < e < 2^256.
    rsa_exponent_bits: Some(Bits { min: 17, max: 256 }),
};

#[cfg(test)]
mod tests;
