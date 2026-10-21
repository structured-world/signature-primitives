//! `CAdES` attribute rules of ETSI EN 319 122-1 V1.3.1 §§5.2-5.5 that narrow
//! the generic CMS and ESS schemas.
//!
//! The generic readers accept what RFC 5652 and RFC 5035 accept; this module
//! reports where a `CAdES` signature uses that freedom against the profile:
//! an attribute in the wrong set, a single-valued attribute with another value
//! count, a content-describing attribute inside a countersignature, ESS
//! `policies` and an implied signature policy. Which attributes a level
//! requires, and every verdict, stay with the caller.

use crate::attribute::Attributes;
use crate::ess::SigningAttributes;
use crate::signer::SignerInfo;
use crate::{Error, ErrorCode, Result, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Oid, Reader, Tag, universal};

/// The `SignerInfo` being checked, since rules differ by where it sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A signer of the root `SignedData`.
    Signature,
    /// A `SignerInfo` carried in a countersignature attribute (§5.2.7).
    Countersignature,
    /// The signer of the time-stamp token in an `archive-time-stamp-v3`
    /// (§5.5.3), the only one that carries an `ats-hash-index-v3` (§5.5.2).
    ArchiveTimestamp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Set {
    Signed,
    Unsigned,
    // Allowed in neither top-level set, only nested in another attribute.
    Neither,
}

// Which signers may carry the attribute at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signers {
    Any,
    NotCountersignature,
    ArchiveTimestampOnly,
}

impl Signers {
    fn admit(self, role: Role) -> bool {
        match self {
            Self::Any => true,
            Self::NotCountersignature => role != Role::Countersignature,
            Self::ArchiveTimestampOnly => role == Role::ArchiveTimestamp,
        }
    }
}

struct Rule {
    kind: Oid<'static>,
    set: Set,
    single: bool,
    unique: bool,
    signers: Signers,
    field: &'static str,
}

const fn rule(kind: Oid<'static>, set: Set, single: bool, field: &'static str) -> Rule {
    Rule {
        kind,
        set,
        single,
        unique: false,
        signers: Signers::Any,
        field,
    }
}

// An attribute type defined in ESS: "A signerInfo MUST NOT include multiple
// instances of any of the attribute types defined in ESS", each with "a single
// instance of AttributeValue" (RFC 2634 §1.3.4).
const fn ess(kind: Oid<'static>, field: &'static str) -> Rule {
    Rule {
        unique: true,
        ..rule(kind, Set::Signed, true, field)
    }
}

// The placement ("is/shall be a signed/unsigned attribute") and the value
// count ("shall contain exactly one component of AttributeValue type") of each
// §5.2-5.5 attribute. Rules the CMS and ESS readers already apply (content
// type, message digest, signing time, algorithm protection, signing
// certificates) are not repeated here.
const RULES: [Rule; 14] = [
    // §5.2.3
    rule(
        oid::COMMITMENT_TYPE_INDICATION,
        Set::Signed,
        true,
        "commitmentTypeIndication",
    ),
    // §5.2.4.1: ESS, signed, and not within a countersignature.
    Rule {
        signers: Signers::NotCountersignature,
        ..ess(oid::CONTENT_HINTS, "contentHints")
    },
    // §5.2.4.2: signed, one value, and not within a countersignature.
    Rule {
        signers: Signers::NotCountersignature,
        ..rule(oid::MIME_TYPE, Set::Signed, true, "mimeType")
    },
    // §5.2.5
    rule(oid::SIGNER_LOCATION, Set::Signed, true, "signerLocation"),
    // §5.2.6.1
    rule(
        oid::SIGNER_ATTRIBUTES_V2,
        Set::Signed,
        true,
        "signerAttributesV2",
    ),
    // §5.2.6.2: only in signer-attributes-v2 claimedAttributes; "It shall
    // not be used anywhere else."
    rule(
        oid::CLAIMED_SAML_ASSERTION,
        Set::Neither,
        false,
        "claimedSamlAssertion",
    ),
    // §5.2.8
    rule(
        oid::CONTENT_TIMESTAMP,
        Set::Signed,
        true,
        "contentTimeStamp",
    ),
    // §5.2.9.1
    rule(
        oid::SIGNATURE_POLICY_IDENTIFIER,
        Set::Signed,
        true,
        "signaturePolicyIdentifier",
    ),
    // §5.2.10
    rule(
        oid::SIGNATURE_POLICY_STORE,
        Set::Unsigned,
        true,
        "signaturePolicyStore",
    ),
    // §5.2.11: ESS.
    ess(oid::CONTENT_REFERENCE, "contentReference"),
    // §5.2.12: ESS.
    ess(oid::CONTENT_IDENTIFIER, "contentIdentifier"),
    // §5.3
    rule(
        oid::SIGNATURE_TIMESTAMP,
        Set::Unsigned,
        true,
        "signatureTimeStamp",
    ),
    // §5.5.2: an unsigned attribute of the archive time-stamp token's signer;
    // §5.5.3: the token carries "a single ats-hash-index-v3 attribute".
    Rule {
        unique: true,
        signers: Signers::ArchiveTimestampOnly,
        ..rule(
            oid::ATS_HASH_INDEX_V3,
            Set::Unsigned,
            true,
            "atsHashIndexV3",
        )
    },
    // §5.5.3(3) archives a SignedData.signerInfos item. Its nested counters
    // are protected through the indexed unsigned values (§5.5.2 note6,
    // §5.5.3 note4), not selected as another root of the archive input.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    Rule {
        signers: Signers::NotCountersignature,
        ..rule(
            oid::ARCHIVE_TIMESTAMP_V3,
            Set::Unsigned,
            true,
            "archiveTimeStampV3",
        )
    },
];

/// Reports every `CAdES` profile violation of one `SignerInfo`, in rule order,
/// with original locations.
///
/// The signer's own ESS signing-certificate attributes are read here, so the
/// `policies` field §§5.2.2.2-5.2.2.3 forbid is always judged on this signer,
/// never on attributes read from another. An attribute this crate does not read is
/// judged only by its placement, value count and, for the ESS content
/// attributes, a repeated instance (RFC 2634 §1.3.4), plus the
/// `signaturePolicyImplied` choice that §5.2.9.1 forbids. An empty result is
/// not a level or validity verdict.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::Parser;
/// use structured_asn1::memory::{Memory, MemoryAccount};
/// use structured_cms::cades::{Role, profile_faults};
/// use structured_cms::{ErrorCode, SignedData, oid};
///
/// fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
///     [&[tag, contents.len() as u8][..], contents].concat()
/// }
/// // One signer whose signed attributes hold a mime-type, which §5.2.4.2
/// // forbids only within a countersignature.
/// let mime = tlv(0x30, &[tlv(6, oid::MIME_TYPE.as_bytes()), tlv(0x31, &tlv(12, b"text/plain"))].concat());
/// let signer = [
///     &[2, 1, 3, 0x80, 1, 7][..],
///     &tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
///     &tlv(0xa0, &mime),
///     &tlv(0x30, &tlv(6, &[0x2b, 0x65, 0x70])),
///     &tlv(4, &[8]),
/// ]
/// .concat();
/// let inside = [
///     &[2, 1, 3, 0x31, 0][..],
///     &tlv(0x30, &tlv(6, oid::DATA.as_bytes())),
///     &tlv(0x31, &tlv(0x30, &signer)),
/// ]
/// .concat();
/// let message = tlv(0x30, &[tlv(6, oid::SIGNED_DATA.as_bytes()), tlv(0xa0, &tlv(0x30, &inside))].concat());
///
/// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
/// let value = SignedData::read(&parser, &message, 0).unwrap();
/// let query = parser.read(&[], 0).unwrap();
/// let info = &value.signers()[0];
/// assert!(profile_faults(info, Role::Signature, &query).unwrap().is_empty());
/// let faults = profile_faults(info, Role::Countersignature, &query).unwrap();
/// assert_eq!(faults[0].code(), ErrorCode::AttributePlacement);
/// ```
///
/// # Errors
///
/// A foreign reader, signing-certificate attributes the ESS reader refuses
/// ([`SigningAttributes::read`]), or a spent work or memory ceiling; never a
/// violation.
pub fn profile_faults<'a>(
    signer: &SignerInfo<'a>,
    role: Role,
    parent: &Reader<'a>,
) -> Result<OwnedVec<Error>> {
    Ok(profile(signer, role, parent)?.faults)
}

/// One original ESS reading and its CAdES-specific profile findings. Keeping
/// the reading lets a baseline layer bind the certificate without parsing the
/// same signed attribute a second time in that operation.
#[derive(Debug)]
pub struct Profile<'a> {
    signing: SigningAttributes<'a>,
    faults: OwnedVec<Error>,
}

impl<'a> Profile<'a> {
    /// Original ESS signer/path restrictions, independently of hash agreement.
    #[must_use]
    pub fn signing(&self) -> &SigningAttributes<'a> {
        &self.signing
    }

    /// `CAdES` placement/cardinality/profile violations from the same pass.
    /// ESS reading diagnostics remain on [`Self::signing`].
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
}

/// Runs the same profile kernel as [`profile_faults`], retaining the already
/// parsed ESS reading for subsequent baseline certificate binding. No result
/// here supplies a baseline level, mathematical agreement or trust.
pub fn profile<'a>(
    signer: &SignerInfo<'a>,
    role: Role,
    parent: &Reader<'a>,
) -> Result<Profile<'a>> {
    // The producing parser's ceilings fund every scan below.
    signer.require_session(parent, "signerInfo")?;
    let signing = SigningAttributes::read(signer, parent)?;
    let faults = findings_from_reading(signer, role, &signing, parent)?;
    Ok(Profile { signing, faults })
}

/// Inspects the same profile while retaining nonterminal ESS selection/schema
/// failures as located findings. A conflicting version has no selected binding;
/// it cannot silently become the first assertion or an empty successful set.
/// Source/resource refusal still returns an error without a successful prefix.
/// This permits a format layer to inventory later timestamps and counters even
/// when the original signer's ESS fields are nonconforming.
pub fn inspect_profile<'a>(
    signer: &SignerInfo<'a>,
    role: Role,
    parent: &Reader<'a>,
) -> Result<Profile<'a>> {
    signer.require_session(parent, "signerInfo")?;
    let signing = SigningAttributes::inspect(signer, parent)?;
    let faults = findings_from_reading(signer, role, &signing, parent)?;
    Ok(Profile { signing, faults })
}

/// Applies the same profile kernel to the SAME already parsed ESS reading.
/// Source identity is checked before traversal; no ESS value is reparsed and
/// no signature, certificate binding or application trust is established.
pub fn findings_from_reading(
    signer: &SignerInfo<'_>,
    role: Role,
    signing: &SigningAttributes<'_>,
    parent: &Reader<'_>,
) -> Result<OwnedVec<Error>> {
    signing.require_signer(signer, parent)?;
    let execution = parent.execution();
    let mut faults = execution.vector();
    for rule in &RULES {
        let protected = signer.signed_attributes();
        let unprotected = signer.unsigned_attributes();
        let (allowed, forbidden) = match rule.set {
            Set::Signed => (protected, [unprotected, None]),
            Set::Unsigned => (unprotected, [protected, None]),
            Set::Neither => (None, [protected, unprotected]),
        };
        for set in forbidden.into_iter().flatten() {
            report(set, rule, parent, &mut faults, |_, _| {
                Some(ErrorCode::AttributePlacement)
            })?;
        }
        let Some(set) = allowed else {
            continue;
        };
        report(set, rule, parent, &mut faults, |attribute, instance| {
            if !rule.signers.admit(role) {
                Some(ErrorCode::AttributePlacement)
            } else if rule.unique && instance > 0 {
                Some(ErrorCode::DuplicateAttribute)
            } else if rule.single && attribute.values().len() != 1 {
                Some(ErrorCode::AttributeCardinality)
            } else {
                None
            }
        })?;
    }
    // §5.2.9.1: SignaturePolicyIdentifier ::= CHOICE { signaturePolicyId
    // SignaturePolicyId, signaturePolicyImplied NULL }; the NULL choice shall
    // not be used.
    if let Some(signed) = signer.signed_attributes() {
        for result in signed.all_in(oid::SIGNATURE_POLICY_IDENTIFIER, parent) {
            for value in result?.values() {
                // Each value inspected is paid before its tag is read.
                execution.charge_work(1).map_err(|reason| {
                    Error::resource(reason, "signaturePolicyIdentifier", value.span().start)
                })?;
                if value.tag() == Tag::primitive(universal::NULL) {
                    push(
                        &mut faults,
                        Error::schema(
                            ErrorCode::AttributeSyntax,
                            "signaturePolicyIdentifier.signaturePolicyImplied",
                            value.span().start,
                        ),
                    )?;
                }
            }
        }
    }
    // §§5.2.2.2-5.2.2.3: "The policies field shall not be used."
    for (certificate, field) in [
        (signing.v1(), "signingCertificate.policies"),
        (signing.v2(), "signingCertificateV2.policies"),
    ] {
        if let Some(policies) = certificate.and_then(|value| value.policies()) {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, field, policies.span().start))?;
            push(
                &mut faults,
                Error::schema(ErrorCode::AttributeSyntax, field, policies.span().start),
            )?;
        }
    }
    Ok(faults.into_owned())
}

fn report<W: Work>(
    set: &Attributes<'_>,
    rule: &Rule,
    parent: &Reader<'_>,
    faults: &mut OwnedVec<Error, W>,
    judge: impl Fn(&crate::attribute::Attribute<'_>, usize) -> Option<ErrorCode>,
) -> Result<()> {
    for (instance, result) in set.all_in(rule.kind, parent).enumerate() {
        let attribute = result?;
        if let Some(code) = judge(attribute, instance) {
            push(
                faults,
                Error::schema(code, rule.field, attribute.span().start),
            )?;
        }
    }
    Ok(())
}

fn push<W: Work>(faults: &mut OwnedVec<Error, W>, fault: Error) -> Result<()> {
    let field = fault.field();
    let at = fault.offset();
    faults
        .try_push(fault)
        .map_err(|reason| Error::resource(reason, field, at))
}
