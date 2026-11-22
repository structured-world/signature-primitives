//! Cryptographic constraints: until when each mechanism and key size is
//! considered secure, and what that says about one piece of material
//! (ETSI EN 319 102-1 V1.4.1 5.1.4.3 and 5.2.8.4.1).

use structured_pkix::temporal::Instant;

/// A hash function as a policy names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hash {
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// RIPEMD-160.
    Ripemd160,
    /// WHIRLPOOL.
    Whirlpool,
    /// One the caller could identify but no variant above names.
    Other,
}

/// A signature algorithm family or fixed-parameter signature variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// RSA under PKCS#1 v1.5.
    RsaPkcs1,
    /// RSA under PSS.
    RsaPss,
    /// DSA, sized by its prime p and subgroup order q.
    Dsa,
    /// ECDSA, sized by its curve's order.
    Ecdsa,
    /// Pure Ed25519 (RFC 8032), with its intrinsic SHA-512.
    Ed25519,
    /// Pure Ed448 (RFC 8032) with empty context and intrinsic SHAKE256.
    Ed448,
    /// One the caller could identify but no variant above names.
    Other,
}

/// A signature scheme and the size of the key it was used with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scheme {
    /// The algorithm family.
    pub family: Family,
    /// The key size in bits: the modulus for RSA, p for DSA, the curve for
    /// ECDSA. Use a zero minimum in the rule for a fixed-parameter variant
    /// whose acceptance is based on identity alone.
    pub bits: u32,
    /// For RSA, the bit length of the public exponent, which the registry
    /// only accepts odd. `None` for other families, and for an RSA key whose
    /// exponent was not supplied, which no exponent rule can then accept.
    pub exponent_bits: Option<u32>,
    /// For DSA, the bit length of the subgroup order q. `None` for other
    /// families or when q was not supplied, which no DSA rule can accept.
    pub subgroup_bits: Option<u32>,
}

/// An inclusive range of bit lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bits {
    /// The shortest accepted.
    pub min: u32,
    /// The longest accepted.
    pub max: u32,
}

/// What produced one signed object: its hash and its signature scheme.
/// Either is absent where the object does not use one separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Material {
    /// The separately selected hash, if any. Leave this unset for pure
    /// Ed25519 and Ed448; their intrinsic hash is part of the scheme identity.
    pub hash: Option<Hash>,
    /// The scheme the signature value was made with.
    pub scheme: Option<Scheme>,
}

/// How long one hash function is considered secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashRule {
    /// The function.
    pub hash: Hash,
    /// The first moment it is no longer considered secure, or `None` for no
    /// known end.
    pub until: Option<Instant>,
}

/// How long one family at one key size and above is considered secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemeRule {
    /// The family.
    pub family: Family,
    /// The smallest key size the rule covers. A key takes the rule with the
    /// largest minimum it reaches in both dimensions, comparing this minimum
    /// first and then the subgroup minimum. Below every rule, it is never secure.
    pub min_bits: u32,
    /// For DSA, the smallest subgroup order q the rule covers. Other
    /// families do not use this dimension and set it to zero.
    pub min_subgroup_bits: u32,
    /// The first moment it is no longer considered secure, or `None` for no
    /// known end.
    pub until: Option<Instant>,
}

/// Hash functions permitted with one signature family. Component timelines
/// and key parameters are still checked separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteRule<'a> {
    /// The signature family.
    pub family: Family,
    /// Inclusive key size range, or `None` to rely on the scheme rules alone.
    pub key_bits: Option<Bits>,
    /// Its permitted message hash functions. An empty list permits none.
    pub hashes: &'a [Hash],
}

/// One set of cryptographic constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraints<'a> {
    /// One rule per hash function. A function without one is not reliable.
    pub hashes: &'a [HashRule],
    /// Rules per family and key size. A family without one is not reliable.
    pub schemes: &'a [SchemeRule],
    /// Permitted hash/family combinations, when both are present in the
    /// material. No matching combination means it is not permitted, even
    /// when each component independently meets its constraints.
    pub suites: &'a [SuiteRule<'a>],
    /// The bit lengths an RSA public exponent may have, or `None` for no
    /// requirement. An odd exponent of 17 to 256 bits is exactly
    /// 2^16 < e < 2^256.
    pub rsa_exponent_bits: Option<Bits>,
}

/// The mechanism a constraint was not met for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    /// The hash function.
    Hash(Hash),
    /// The scheme at its key size.
    Scheme(Scheme),
    /// The scheme's RSA public exponent.
    Exponent(Scheme),
    /// The combination of a message hash and signature scheme.
    Suite {
        /// The message hash.
        hash: Hash,
        /// The signature scheme, retaining its key parameters.
        scheme: Scheme,
    },
}

/// Why one piece of material does not meet the constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmet {
    /// What fell short.
    pub mechanism: Mechanism,
    /// Until when it was considered secure, where the policy knows it. `None`
    /// is a mechanism or key size the policy never considered secure.
    pub until: Option<Instant>,
    /// Whether the material is proven made when the mechanism was no longer
    /// considered secure: made after a moment at or past `until`, or made at
    /// any proven moment for a mechanism never considered secure. For a
    /// signature's own material this is `CRYPTO_CONSTRAINTS_FAILURE` rather
    /// than its `_NO_POE` form (EN 319 102-1 V1.4.1 5.3.4 step 6).
    pub proven_after: bool,
}

impl Constraints<'_> {
    /// Whether material that existed by `existed_by`, and was made after
    /// `made_after` where that is proven, meets these constraints.
    ///
    /// The hash is checked before the scheme, so of two shortfalls the one
    /// reported is the hash's. Their combination is checked last. A
    /// constraint is met when the material existed
    /// before the mechanism stopped being considered secure (5.2.8.4.1, and
    /// 5.5.4 steps 4c and 8 with best-signature-time as `existed_by`).
    pub(super) fn assess(
        &self,
        material: Material,
        existed_by: Instant,
        made_after: Option<Instant>,
    ) -> Result<(), Unmet> {
        self.resolve(material, Some(existed_by), made_after)
            .map(|_| ())
    }

    /// Resolve the common mechanism rules without applying a validation date.
    pub(super) fn sunset(&self, material: Material) -> Result<Option<Instant>, Unmet> {
        self.resolve(material, None, None)
    }

    fn resolve(
        &self,
        material: Material,
        existed_by: Option<Instant>,
        made_after: Option<Instant>,
    ) -> Result<Option<Instant>, Unmet> {
        self.resolve_with(material, existed_by, made_after, Err)
    }

    pub(super) fn inspect(
        &self,
        material: Material,
        existed_by: Instant,
        made_after: Option<Instant>,
        mut visit: impl FnMut(Unmet),
    ) {
        // This visitor always continues, so resolution cannot terminate.
        match self.resolve_with(material, Some(existed_by), made_after, |unmet| {
            visit(unmet);
            Ok(())
        }) {
            Ok(_) => {}
            Err(unmet) => visit(unmet),
        }
    }

    fn resolve_with(
        &self,
        material: Material,
        existed_by: Option<Instant>,
        made_after: Option<Instant>,
        mut finding: impl FnMut(Unmet) -> Result<(), Unmet>,
    ) -> Result<Option<Instant>, Unmet> {
        let mut sunset = None;
        if let Some(hash) = material.hash {
            let mechanism = Mechanism::Hash(hash);
            if let Some(rule) = self.hashes.iter().find(|rule| rule.hash == hash) {
                if let Err(unmet) = check(mechanism, rule.until, existed_by, made_after) {
                    finding(unmet)?;
                }
                sunset = rule.until;
            } else {
                finding(Unmet::unlisted(mechanism, made_after))?;
            }
        }
        if let Some(scheme) = material.scheme {
            let mechanism = Mechanism::Scheme(scheme);
            let mut selected: Option<&SchemeRule> = None;
            for candidate in self.schemes {
                if candidate.family != scheme.family || candidate.min_bits > scheme.bits {
                    continue;
                }
                // TS 119 312 V2.1.1 8.4 Table 7: DSA strength depends on
                // both p and q. A stronger p cannot replace an unknown or
                // insufficient q; only a tier reached by both may be used.
                if scheme.family == Family::Dsa {
                    let Some(bits) = scheme.subgroup_bits else {
                        continue;
                    };
                    if bits < candidate.min_subgroup_bits {
                        continue;
                    }
                }
                if let Some(current) = selected {
                    if current.min_bits > candidate.min_bits {
                        continue;
                    }
                    if current.min_bits == candidate.min_bits
                        && scheme.family == Family::Dsa
                        && current.min_subgroup_bits > candidate.min_subgroup_bits
                    {
                        continue;
                    }
                }
                selected = Some(candidate);
            }
            if selected.is_none() {
                finding(Unmet::unlisted(mechanism, made_after))?;
            }
            // TS 119 312 V2.1.1 clause 6.2.2.1: 2^16 < e < 2^256.
            if let (Family::RsaPkcs1 | Family::RsaPss, Some(range)) =
                (scheme.family, self.rsa_exponent_bits)
                && !scheme
                    .exponent_bits
                    .is_some_and(|bits| range.min <= bits && bits <= range.max)
            {
                finding(Unmet::unlisted(Mechanism::Exponent(scheme), made_after))?;
            }
            if let Some(rule) = selected {
                if let Err(unmet) = check(mechanism, rule.until, existed_by, made_after) {
                    finding(unmet)?;
                }
                if let Some(end) = rule.until {
                    sunset = Some(sunset.map_or(end, |previous| previous.min(end)));
                }
            }
        }
        if let (Some(hash), Some(scheme)) = (material.hash, material.scheme) {
            // TS 119 312 V2.1.1 7.2 and 7.3: only predefined suites, not
            // the Cartesian product of independently suitable components.
            for rule in self.suites {
                if rule.family != scheme.family {
                    continue;
                }
                if let Some(bits) = rule.key_bits
                    && (scheme.bits < bits.min || scheme.bits > bits.max)
                {
                    continue;
                }
                for permitted in rule.hashes {
                    if *permitted == hash {
                        return Ok(sunset);
                    }
                }
            }
            finding(Unmet::unlisted(
                Mechanism::Suite { hash, scheme },
                made_after,
            ))?;
        }
        Ok(sunset)
    }
}

impl Unmet {
    /// A mechanism, key size or exponent the constraints never considered
    /// secure: any proven moment of production is a moment it was not.
    const fn unlisted(mechanism: Mechanism, made_after: Option<Instant>) -> Self {
        Self {
            mechanism,
            until: None,
            proven_after: made_after.is_some(),
        }
    }
}

fn check(
    mechanism: Mechanism,
    until: Option<Instant>,
    existed_by: Option<Instant>,
    made_after: Option<Instant>,
) -> Result<(), Unmet> {
    let Some(end) = until else {
        return Ok(());
    };
    if existed_by.is_none_or(|at| at < end) {
        return Ok(());
    }
    Err(Unmet {
        mechanism,
        until,
        // Made strictly after a moment at or past the end: produced when the
        // mechanism was no longer considered secure.
        proven_after: made_after.is_some_and(|after| after >= end),
    })
}

#[cfg(test)]
mod tests;
