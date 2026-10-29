//! Source-aware adapters for the existing common work and digest contracts.

use crate::{
    Error,
    domain::{Domain, Explicit},
    gost::{DEFAULT_DKE, Dke},
    hash::{self, Hash},
    validation::{Factor, ValidationError},
};
use core::{cmp::Ordering, convert::Infallible, fmt};
use structured_asn1::{
    digest::{Digest, Resolution},
    memory::{MemoryError, Work},
};
use structured_pkix::{
    PublicKeyInfo,
    algorithm::{
        Producer,
        digest::Algorithm,
        dstu4145::{self, Curve, Parameters, Profile},
    },
};

/// Processing, backend and original entropy failures with physical input offsets.
#[derive(Debug)]
pub enum Failure<E = Infallible> {
    /// Original shared parser/resource failure.
    Encoding(structured_pkix::Error),
    /// Refusal before the corresponding backend work.
    Resource {
        /// Original resource class.
        reason: MemoryError,
        /// Original enclosing value location.
        at: u64,
    },
    /// Backend input/capability failure, independent of mathematical mismatch.
    Backend {
        /// Backend classification.
        reason: Error,
        /// Original enclosing value location.
        at: u64,
    },
    /// Caller-supplied entropy failure, without classification loss.
    Entropy {
        /// Original caller entropy failure.
        source: E,
        /// Explicit parameter source location.
        at: u64,
    },
}

impl<E: fmt::Display> fmt::Display for Failure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(f),
            Self::Resource { reason, at } => write!(f, "{reason} at {at}"),
            Self::Backend { reason, at } => write!(f, "{reason} at {at}"),
            Self::Entropy { source, at } => write!(f, "{source} at {at}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Failure<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(match self {
            Self::Encoding(error) => error,
            Self::Resource { reason, .. } => reason,
            Self::Backend { reason, .. } => reason,
            Self::Entropy { source, .. } => source,
        })
    }
}

/// An immutable actual DKE associated with its original parameter source.
#[derive(Debug, Clone, Copy)]
pub struct DkeBinding<'a> {
    dke: &'a Dke,
    origin: Producer<'a>,
    at: u64,
}

impl<'a> DkeBinding<'a> {
    /// Binds a prepared table only after comparing its full effective DKE
    /// against original parameters. Omitted DKE uses the profile's number one.
    pub fn new<W: Work>(
        parameters: Parameters<'a>,
        dke: &'a Dke,
        current: &W,
    ) -> Result<Self, Failure> {
        let at = parameters.element().span().start;
        let execution = parameters.execution_in(current);
        execution
            .charge_work(65)
            .map_err(|reason| Failure::Resource { reason, at })?;
        let written = parameters
            .dke()
            .map_or(&DEFAULT_DKE[..], |element| element.contents());
        if written != dke.packed() {
            return Err(Failure::Backend {
                reason: Error::InvalidDke,
                at,
            });
        }
        Ok(Self {
            dke,
            origin: parameters.execution_origin(),
            at,
        })
    }
}

/// Prepares the written/default DKE under the producing and current ceilings.
/// The returned table is inline. Bind it to the source before deferred hashing.
pub fn prepare_dke<W: Work>(parameters: Parameters<'_>, current: &W) -> Result<Dke, Failure> {
    let at = parameters.element().span().start;
    parameters
        .execution_in(current)
        .charge_work(64 + 128 + 4 * 256)
        .map_err(|reason| Failure::Resource { reason, at })?;
    let bytes = parameters
        .dke()
        .map_or(&DEFAULT_DKE[..], |element| element.contents());
    let packed: &[u8; 64] = bytes.try_into().map_err(|_| Failure::Backend {
        reason: Error::InvalidDke,
        at,
    })?;
    Dke::new(packed).map_err(|reason| Failure::Backend { reason, at })
}

/// Full hash identity with the parameter origin needed by deferred execution.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    hash: Hash<'a>,
    origin: Option<Producer<'a>>,
    at: u64,
}

impl<'a> Identity<'a> {
    /// Explicitly trusted caller setup, without an encoded parameter source.
    /// Parsed untrusted GOST parameters use [`Self::gost`] instead.
    pub fn trusted(hash: Hash<'a>) -> Result<Self, Error> {
        hash.width()?;
        Ok(Self {
            hash,
            origin: None,
            at: 0,
        })
    }

    /// Uses an actual source-bound DKE, without copying its prepared tables.
    #[must_use]
    pub const fn gost(binding: DkeBinding<'a>) -> Self {
        Self {
            hash: Hash::Gost34311(binding.dke),
            origin: Some(binding.origin),
            at: binding.at,
        }
    }

    /// Fixed width of the validated selected hash identity.
    #[must_use]
    pub fn width(self) -> usize {
        self.hash.output_width()
    }

    /// The exact selected backend hash, without a new algorithm resolution.
    #[must_use]
    pub const fn hash(self) -> Hash<'a> {
        self.hash
    }

    fn charge<W: Work>(self, work: &W, cost: u64) -> Result<(), Failure> {
        let result = match self.origin {
            Some(origin) => origin.charge_work_in(work, cost),
            None => work.charge_work(cost),
        };
        result.map_err(|reason| Failure::Resource {
            reason,
            at: self.at,
        })
    }
}

/// Source-aware state for one admitted stream, preserving its parameter origin.
pub struct HashState<'a> {
    identity: Identity<'a>,
    state: hash::State<'a>,
}

/// Primitive digest execution adapter. Compose it inside the selected provider;
/// it is not a new provider registry or XML security dispatcher.
#[derive(Debug, Clone, Copy)]
pub struct Hashes;

impl<'a> Digest<'a> for Hashes {
    type Identity = Identity<'a>;
    type State = HashState<'a>;
    type Output = hash::Output;
    type Error = Failure;

    fn width(&self, identity: &Self::Identity) -> Option<usize> {
        Some(identity.width())
    }
    fn compare<W: Work>(
        &self,
        left: &Self::Identity,
        right: &Self::Identity,
        work: &W,
    ) -> Result<Ordering, Failure> {
        let cost = match (left.hash, right.hash) {
            (Hash::Gost34311(a), Hash::Gost34311(b)) if !core::ptr::eq(a, b) => 65,
            _ => 1,
        };
        // Admit both original identities and the current root in one bill.
        // Rebinding twice would replace a source; separate bills double-charge.
        match (left.origin, right.origin) {
            (Some(a), Some(b)) => {
                a.charge_work_with(b, work, cost)
                    .map_err(|reason| Failure::Resource {
                        reason,
                        at: right.at,
                    })?;
            }
            (None, Some(_)) => right.charge(work, cost)?,
            _ => left.charge(work, cost)?,
        }
        Ok(left.hash.compare(right.hash))
    }
    fn start<W: Work>(
        &'a self,
        identity: &Self::Identity,
        work: &W,
    ) -> Result<Resolution<Self::State>, Failure> {
        identity.charge(work, 512)?;
        let state = hash::State::new(identity.hash).map_err(|reason| Failure::Backend {
            reason,
            at: identity.at,
        })?;
        Ok(Resolution::Supported(HashState {
            identity: *identity,
            state,
        }))
    }
    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Failure> {
        let cost = match state.state.update_work(bytes.len()) {
            Ok(cost) => cost,
            Err(reason) => {
                state.identity.charge(work, 1)?;
                return Err(Failure::Backend {
                    reason,
                    at: state.identity.at,
                });
            }
        };
        state.identity.charge(work, cost)?;
        state
            .state
            .update(bytes)
            .map_err(|reason| Failure::Backend {
                reason,
                at: state.identity.at,
            })
    }
    fn finish<W: Work>(&self, state: Self::State, work: &W) -> Result<Self::Output, Failure> {
        state.identity.charge(work, state.state.finalize_work())?;
        Ok(state.state.finalize())
    }
    fn matches<W: Work>(
        &self,
        identity: &Self::Identity,
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        identity.charge(work, 1)?;
        if output.as_ref().len() != expected.len() {
            return Ok(false);
        }
        identity.charge(work, expected.len() as u64)?;
        Ok(output.as_ref() == expected)
    }
}

/// Prepared key carrying the original source ceiling for later verification.
#[derive(Debug)]
pub struct Key<'a> {
    public: crate::domain::PublicKey,
    profile: Profile,
    source: Producer<'a>,
    at: u64,
    dke: DkeBinding<'a>,
    verification_cost: u64,
}

impl<'a> Key<'a> {
    /// Prepares a named or canonical explicit SPKI under its original scope.
    /// Custom-domain validation evidence is a separate explicit capability.
    pub fn prepare<W: Work>(
        info: PublicKeyInfo<'a>,
        dke: &'a Dke,
        work: &W,
    ) -> Result<Self, Failure> {
        Self::prepare_using(info, dke, work, 0, |input| {
            Domain::explicit(input).map_err(ValidationError::Input)
        })
    }

    /// Validates custom explicit parameters with caller evidence and entropy.
    /// The complete bounded validation cost is admitted before either is used.
    pub fn prepare_with_evidence<W: Work, R: rand_core::TryCryptoRng>(
        info: PublicKeyInfo<'a>,
        dke: &'a Dke,
        work: &W,
        factors: &[Factor<'_>],
        random: &mut R,
    ) -> Result<Self, Failure<R::Error>> {
        info.algorithm()
            .execution_origin()
            .charge_work_in(work, 1)
            .map_err(|reason| Failure::Resource {
                reason,
                at: info.algorithm().offset(),
            })?;
        if factors.len() > crate::MAX_DEGREE {
            return Err(Failure::Backend {
                reason: Error::UnsupportedDomain,
                at: info.algorithm().offset(),
            });
        }
        // At most512-bit exponents/integers,50 primality rounds,128 bounded
        // samples and one field exponent per factor, including32-bit targets.
        let extra =
            (factors.len() as u64 + 1) * (50 * 512 * 2048 + 2 * 509 * 25_000 + 50 * 128 * 64);
        Self::prepare_using(info, dke, work, extra, |input| {
            Domain::explicit_with_evidence(input, factors, random)
        })
    }

    fn prepare_using<W: Work, E>(
        info: PublicKeyInfo<'a>,
        dke: &'a Dke,
        work: &W,
        extra: u64,
        domain_of: impl FnOnce(Explicit<'_>) -> Result<Domain, ValidationError<E>>,
    ) -> Result<Self, Failure<E>> {
        let parsed = structured_pkix::key::dstu4145::read(info, work).map_err(Failure::Encoding)?;
        info.algorithm()
            .execution_origin()
            .charge_work_in(work, 1)
            .map_err(|reason| Failure::Resource {
                reason,
                at: info.algorithm().offset(),
            })?;
        let profile = parsed.profile();
        let parameters = parsed.parameters().ok_or(Failure::Backend {
            reason: Error::UnsupportedDomain,
            at: info.algorithm().offset(),
        })?;
        let at = parameters.element().span().start;
        let degree = parameters.curve().degree().ok_or(Failure::Backend {
            reason: Error::UnsupportedDomain,
            at,
        })?;
        if !(163..=509).contains(&degree) || degree.is_multiple_of(2) {
            return Err(Failure::Backend {
                reason: Error::UnsupportedDomain,
                at,
            });
        }
        let execution = parsed.execution_in(work);
        let field_cost = field_cost(degree, &parameters.curve());
        let cost = match parameters.curve() {
            Curve::Named(_) => curve_cost(degree, 20, field_cost),
            Curve::Explicit(_) => curve_cost(degree, 40, field_cost) + extra,
        };
        execution
            .charge_work(cost)
            .map_err(|reason| Failure::Resource { reason, at })?;
        let dke = DkeBinding::new(parameters, dke, &execution).map_err(widen)?;
        let domain = match parameters.curve() {
            Curve::Named(named) => {
                let (basis, m) = named.known().ok_or(Failure::Backend {
                    reason: Error::UnsupportedDomain,
                    at,
                })?;
                if basis != profile.basis() {
                    return Err(Failure::Backend {
                        reason: Error::InvalidDomain,
                        at,
                    });
                }
                Domain::named(basis, m as usize).map_err(ValidationError::Input)
            }
            Curve::Explicit(explicit) => {
                domain_of(explicit_input(&explicit, profile).map_err(widen)?)
            }
        }
        .map_err(|error| match error {
            ValidationError::Input(reason) => Failure::Backend { reason, at },
            ValidationError::Entropy(source) => Failure::Entropy { source, at },
        })?;
        let key = domain
            .public_key(parsed.point().as_bytes(), profile.byte_order())
            .map_err(|reason| Failure::Backend {
                reason,
                at: parsed.point().offset(),
            })?;
        Ok(Self {
            public: key,
            profile,
            source: info.algorithm().execution_origin(),
            at,
            dke,
            verification_cost: curve_cost(degree, 32, field_cost),
        })
    }

    /// Resolves the signature digest using this actual key's effective DKE.
    /// Key OID hash bits do not restrict a later signature's digest.
    pub fn digest_identity<W: Work>(
        &self,
        signature: Profile,
        work: &W,
    ) -> Result<Identity<'a>, Failure> {
        self.source
            .charge_work_in(work, 1)
            .map_err(|reason| Failure::Resource {
                reason,
                at: self.at,
            })?;
        if signature.basis() != self.profile.basis() {
            return Err(Failure::Backend {
                reason: Error::UnsupportedDomain,
                at: self.at,
            });
        }
        self.identity_of(signature.digest())?
            .ok_or(Failure::Backend {
                reason: Error::UnsupportedDomain,
                at: self.at,
            })
    }

    /// Resolves an already decoded digest declaration for this actual key.
    /// This is the key-bound signature operation, not an ESS/TSP default.
    pub fn resolve_digest<W: Work>(
        &self,
        algorithm: Algorithm,
        work: &W,
    ) -> Result<Resolution<Identity<'a>>, Failure> {
        self.source
            .charge_work_in(work, 1)
            .map_err(|reason| Failure::Resource {
                reason,
                at: self.at,
            })?;
        Ok(match self.identity_of(algorithm)? {
            Some(identity) => Resolution::Supported(identity),
            None => Resolution::Unsupported,
        })
    }

    fn identity_of(&self, algorithm: Algorithm) -> Result<Option<Identity<'a>>, Failure> {
        let mut identity = match algorithm {
            Algorithm::Gost34311 => Ok(Identity::gost(self.dke)),
            Algorithm::Kupyna256 => Identity::trusted(Hash::Kupyna(32)),
            Algorithm::Kupyna384 => Identity::trusted(Hash::Kupyna(48)),
            Algorithm::Kupyna512 => Identity::trusted(Hash::Kupyna(64)),
            _ => return Ok(None),
        };
        // Kupyna also retains the original key-context selection, although
        // its digest has no DKE parameter.
        if let Ok(ref mut value) = identity {
            value.origin = Some(self.source);
            value.at = self.at;
        }
        identity.map(Some).map_err(|reason| Failure::Backend {
            reason,
            at: self.at,
        })
    }

    /// Verifies an exact prehash under the complete previously selected identity.
    /// Source/current refusal precedes all field arithmetic.
    pub fn verify_prehash<W: Work>(
        &self,
        profile: Profile,
        identity: Identity<'a>,
        hash: &[u8],
        signature: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        self.verify_using(profile, identity, hash, signature, None, work)
    }

    /// Verifies an original certificate/CRL signature with strict carried
    /// OCTET framing. Key, signature and every current ceiling admit the one
    /// complete mathematical operation before it executes.
    pub fn verify_signature_value<W: Work>(
        &self,
        profile: Profile,
        identity: Identity<'a>,
        hash: &[u8],
        signature: structured_pkix::signature::SignatureValue<'a>,
        work: &W,
    ) -> Result<bool, Failure> {
        let bits = u32::try_from(self.public.order_bits()).map_err(|_| Failure::Backend {
            reason: Error::UnsupportedDomain,
            at: self.at,
        })?;
        let framed = signature
            .dstu4145_in(work, profile.byte_order(), bits)
            .map_err(Failure::Encoding)?;
        self.verify_using(
            profile,
            identity,
            hash,
            framed.element().contents(),
            Some(signature.execution_origin()),
            work,
        )
    }

    fn verify_using<W: Work>(
        &self,
        profile: Profile,
        identity: Identity<'a>,
        hash: &[u8],
        signature: &[u8],
        origin: Option<Producer<'a>>,
        work: &W,
    ) -> Result<bool, Failure> {
        let expected = self.digest_identity(profile, work)?;
        if Hashes.compare(&expected, &identity, work)? != Ordering::Equal
            || hash.len() != identity.width()
        {
            return Err(Failure::Backend {
                reason: Error::InvalidEncoding,
                at: self.at,
            });
        }
        let cost = self.verification_cost;
        let admitted = match origin {
            Some(origin) => self.source.charge_work_with(origin, work, cost),
            None => self.source.charge_work_in(work, cost),
        };
        admitted.map_err(|reason| Failure::Resource {
            reason,
            at: self.at,
        })?;
        self.public
            .verify_prehash(hash, signature, profile.byte_order())
            .map_err(|reason| Failure::Backend {
                reason,
                at: self.at,
            })
    }
}

fn explicit_input<'a>(
    value: &dstu4145::ExplicitCurve<'a>,
    profile: Profile,
) -> Result<Explicit<'a>, Failure> {
    let a = match value.a().value().as_u64() {
        Some(0) => false,
        Some(1) => true,
        _ => {
            return Err(Failure::Backend {
                reason: Error::InvalidDomain,
                at: value.a().span().start,
            });
        }
    };
    Ok(Explicit {
        degree: value.degree_value(),
        reduction: value.reduction(),
        a,
        b: value.b().as_bytes(),
        order: value.order().value().as_bytes(),
        base_point: value.base_point().as_bytes(),
        byte_order: profile.byte_order(),
    })
}

fn widen<E>(failure: Failure) -> Failure<E> {
    match failure {
        Failure::Encoding(error) => Failure::Encoding(error),
        Failure::Resource { reason, at } => Failure::Resource { reason, at },
        Failure::Backend { reason, at } => Failure::Backend { reason, at },
        Failure::Entropy { source: never, .. } => match never {},
    }
}

fn field_cost(degree: u32, curve: &Curve<'_>) -> u64 {
    // At most8 limbs. Includes both ONB products, all reduction alternatives,
    // normal-basis conversions, inversion chains and the ladder's recovery.
    let degree = u64::from(degree);
    let words = (degree + 1).div_ceil(64);
    let mut reduction = 2 * degree;
    if let Curve::Explicit(value) = curve {
        let top = match value.reduction() {
            dstu4145::Reduction::Trinomial(k) => Some(k),
            dstu4145::Reduction::Pentanomial { l, .. } => Some(l),
            dstu4145::Reduction::OptimalNormal => None,
        };
        if let Some(top) = top
            && u64::from(top) > degree - 64
        {
            reduction = 32 * degree;
        }
    }
    32 * words * words + 256 * words + reduction + 128
}

fn curve_cost(degree: u32, factor: u64, field_cost: u64) -> u64 {
    (factor * u64::from(degree) + 128) * field_cost
}
