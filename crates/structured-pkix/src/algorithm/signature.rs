//! Original signature algorithm structure, without provider or policy selection.
//!
//! Recognizes SHA-family RSA PKCS#1 v1.5, RFC3279/5758 DSA, ECDSA,
//! RSASSA-PSS, pure Ed25519/Ed448 and RFC9881 ML-DSA. It does not infer a scheme from a key,
//! signature size or separately written CMS digest. Unknown OIDs, including
//! legacy OIW aliases, MD2/MD5, additional DSA profiles and other PQ, remain unknown.

use super::{AlgorithmIdentifier, digest, ml_dsa, pss};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;

/// A recognized signature structure, not backend support or authorization.
///
/// Fixed digests are implied by the signature OID; no encoded digest identifier
/// is fabricated. The caller keeps the original signature identifier for
/// provenance, provider dispatch and unsupported-algorithm diagnostics.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Algorithm<'a, 'parameters> {
    /// RSA PKCS#1 v1.5 with the indicated digest.
    RsaPkcs1v15(digest::Algorithm),
    /// Original PSS parameters, without narrowing integers or choosing a backend.
    RsaPss(&'parameters pss::Parameters<'a>),
    /// DSA with SHA-1, SHA-224 or SHA-256.
    Dsa(digest::Algorithm),
    /// ECDSA with the indicated digest.
    Ecdsa(digest::Algorithm),
    /// Pure Ed25519: not Ed25519ph or Ed25519ctx.
    Ed25519,
    /// Pure Ed448: not Ed448ph.
    Ed448,
    /// Pure ML-DSA; certificate/CRL verification requires an empty context.
    /// This does not authorize HashML-DSA or imply a finalized-message digest.
    MlDsa(ml_dsa::ParameterSet),
}

#[derive(Clone, Copy)]
enum Parameters {
    Absent,
    Null,
    NullOrAbsent,
}

/// Visits a retained signature structure under original and current work.
///
/// RSA SHA-224/256/384/512 accepts absent or primitive NULL on reception
/// (RFC4055 §5). Recognized RSA SHA-1, SHA-512/224, SHA-512/256 and SHA3 require
/// NULL (RFC3279 §2.2.1, RFC8017 A.2.4, RFC9688 §3.1). DSA SHA-1/224/256,
/// ECDSA SHA-1/SHA-2/SHA3 and pure Ed25519/Ed448 require absent parameters
/// (RFC3279 §2.2, RFC5758 §3, RFC9688 §3.2, RFC8410 §6). BER NULL spellings are
/// validated by the original reader; bytes are never compared to fabricated DER.
/// ML-DSA-44/65/87 also require absent parameters (RFC9881 §2); the PKIX
/// provider must use pure mode and an empty context (RFC9881 §3).
///
/// PSS signature parameters must be present (RFC4055 §3.1), unlike optional
/// key restrictions. The existing strict PSS kernel preserves independent
/// message/MGF hashes, wide salt/trailer fields and original ranges/depth;
/// DER written DEFAULTs remain errors. Use [`pss::inspect`] for readable PSS
/// diagnostics. Backend support, PSS compatibility, key strength, policy and
/// signature math remain separate. A known structure does not promise that
/// its provider implements it or accepts its parameters.
///
/// Visits `None` for identifiers outside the module's documented recognized
/// set. Both original parser and current operation ceilings apply before any
/// OID scan; a fresh account cannot reset source limits. Fixed cases allocate
/// nothing and need no cursor. PSS fields are borrowed only for the visit,
/// keeping the enum small without allocating a wrapper. The returned `R` may
/// borrow original document bytes, or explicitly copy PSS fields, but cannot
/// keep a reference to the temporary PSS descriptor. The visitor's result,
/// including a caller-specific `Result`, is returned unchanged inside the
/// outer processing result. The visitor is not called on a processing error.
///
/// # Errors
/// Located missing/invalid parameters or strict PSS errors; terminal resource
/// errors remain distinct from unknown algorithms and malformed parameters.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::algorithm::{self, digest, signature};
/// let source = Parser::der(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
/// // ecdsa-with-SHA256, with parameters absent.
/// let bytes = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
/// let mut reader = source.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let identifier = algorithm::read(&reader, &element, "signatureAlgorithm")?;
/// let current = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
/// let recognized = signature::with_algorithm(identifier, &current, |algorithm|
///     matches!(algorithm, Some(signature::Algorithm::Ecdsa(digest::Algorithm::Sha256))))?;
/// assert!(recognized);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
/// A reference to the temporary PSS descriptor cannot escape:
/// ```compile_fail
/// use structured_pkix::algorithm::{AlgorithmIdentifier, pss, signature};
/// use structured_asn1::memory::Memory;
/// fn escape<'a>(id: AlgorithmIdentifier<'a>, work: &Memory)
///     -> structured_pkix::Result<&'a pss::Parameters<'a>> {
///     signature::with_algorithm(id, work, |algorithm| match algorithm {
///         Some(signature::Algorithm::RsaPss(parameters)) => parameters,
///         _ => panic!("PSS expected"),
///     })
/// }
/// ```
pub fn with_algorithm<'a, W: Work, R>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &W,
    visitor: impl for<'parameters> FnOnce(Option<Algorithm<'a, 'parameters>>) -> R,
) -> Result<R> {
    use digest::Algorithm as Hash;
    let bytes = identifier.algorithm().as_bytes();
    identifier
        .query_in(execution)
        .charge_work(bytes.len() as u64 + 1)
        .map_err(|reason| Error::resource(reason, identifier.field, identifier.offset()))?;
    let (algorithm, parameters) = match bytes {
        // RFC8017 A.2.4 assigns distinct signature OIDs, not digest OIDs.
        // https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, last] => {
            let (hash, parameters) = match last {
                5 => (Hash::Sha1, Parameters::Null),
                11 => (Hash::Sha256, Parameters::NullOrAbsent),
                12 => (Hash::Sha384, Parameters::NullOrAbsent),
                13 => (Hash::Sha512, Parameters::NullOrAbsent),
                14 => (Hash::Sha224, Parameters::NullOrAbsent),
                15 => (Hash::Sha512_224, Parameters::Null),
                16 => (Hash::Sha512_256, Parameters::Null),
                10 => {
                    let value = pss::read_known(identifier, execution)?.ok_or_else(|| {
                        Error::new(
                            ErrorCode::MissingField,
                            identifier.field,
                            identifier.offset(),
                        )
                    })?;
                    return Ok(visitor(Some(Algorithm::RsaPss(&value))));
                }
                _ => return Ok(visitor(None)),
            };
            (Algorithm::RsaPkcs1v15(hash), parameters)
        }
        [0x2a, 0x86, 0x48, 0xce, 0x38, 4, 3] => (Algorithm::Dsa(Hash::Sha1), Parameters::Absent),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 1] => (Algorithm::Ecdsa(Hash::Sha1), Parameters::Absent),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, last] => {
            let hash = match last {
                1 => Hash::Sha224,
                2 => Hash::Sha256,
                3 => Hash::Sha384,
                4 => Hash::Sha512,
                _ => return Ok(visitor(None)),
            };
            (Algorithm::Ecdsa(hash), Parameters::Absent)
        }
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, last] => {
            // SHA3 digest and signature parameter rules differ by role.
            // https://www.rfc-editor.org/rfc/rfc9688#section-3
            match last {
                1 => (Algorithm::Dsa(Hash::Sha224), Parameters::Absent),
                2 => (Algorithm::Dsa(Hash::Sha256), Parameters::Absent),
                9..=16 => {
                    let hash = match last {
                        9 | 13 => Hash::Sha3_224,
                        10 | 14 => Hash::Sha3_256,
                        11 | 15 => Hash::Sha3_384,
                        _ => Hash::Sha3_512,
                    };
                    if *last <= 12 {
                        (Algorithm::Ecdsa(hash), Parameters::Absent)
                    } else {
                        (Algorithm::RsaPkcs1v15(hash), Parameters::Null)
                    }
                }
                _ => {
                    // The prefix was already paid and matched. Share the final
                    // arc and parameter kernel without another OID scan.
                    if let Some(set) = ml_dsa::from_arc(*last) {
                        ml_dsa::require_absent(identifier)?;
                        return Ok(visitor(Some(Algorithm::MlDsa(set))));
                    }
                    return Ok(visitor(None));
                }
            }
        }
        [0x2b, 0x65, 112] => (Algorithm::Ed25519, Parameters::Absent),
        [0x2b, 0x65, 113] => (Algorithm::Ed448, Parameters::Absent),
        _ => return Ok(visitor(None)),
    };
    check_parameters(identifier, parameters)?;
    Ok(visitor(Some(algorithm)))
}

fn check_parameters(identifier: AlgorithmIdentifier<'_>, parameters: Parameters) -> Result<()> {
    let present = identifier.parameters_nested();
    let valid = match parameters {
        // NULL is present, not an absent DSA/ECDSA or pure EdDSA parameter.
        // https://www.rfc-editor.org/rfc/rfc5758#section-3
        // https://www.rfc-editor.org/rfc/rfc8410#section-6
        Parameters::Absent => present.is_none(),
        // Signature AlgorithmIdentifier, not SHA3 digest AlgorithmIdentifier.
        // https://www.rfc-editor.org/rfc/rfc9688#section-3.1
        Parameters::Null => identifier.has_null_parameter(),
        // RFC4055 §5 explicitly requires both forms on reception.
        // https://www.rfc-editor.org/rfc/rfc4055#section-5
        Parameters::NullOrAbsent => present.is_none() || identifier.has_null_parameter(),
    };
    if !valid {
        let at = present.map_or(identifier.offset(), super::Nested::offset);
        let code = if present.is_some() {
            ErrorCode::MalformedValue
        } else {
            ErrorCode::MissingField
        };
        return Err(Error::new(code, identifier.field, at));
    }
    Ok(())
}
