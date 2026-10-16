//! Pinned `XAdES` attribute declarations; no second child grammar or XML engine.

use super::{Context, Declaration, Rule};
use crate::{container::XADES, timestamp::XADES_141, xml::Name};

// EN319132-1 V1.3.1 Annex C defines the declarations below.
// https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd
// https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v141.xsd
pub(super) fn declaration(name: Name<'_>, parent: Context) -> Option<Declaration> {
    if name.namespace == XADES {
        v132(name.local, parent)
    } else if name.namespace == XADES_141 {
        v141(name.local, parent)
    } else {
        None
    }
}

fn v132(local: &str, parent: Context) -> Option<Declaration> {
    let mut descend = true;
    let mut context = Context::Ordinary;
    let rule = match local {
        "QualifyingProperties" => Rule::Target,
        "Include" => {
            descend = false;
            Rule::Include
        }
        "DataObjectFormat" => Rule::Format,
        "Identifier" => {
            descend = false;
            Rule::Identifier
        }
        "Cert" | "CRLIdentifier" | "OCSPIdentifier" => Rule::Uri,
        "ReferenceInfo" => Rule::IdUri,
        "QualifyingPropertiesReference" => Rule::RequiredUri,
        "CertifiedRole" if matches!(parent, Context::CertifiedV2) => Rule::None,
        "CertifiedRolesV2" => {
            context = Context::CertifiedV2;
            Rule::None
        }
        "EncapsulatedPKIData"
        | "EncapsulatedTimeStamp"
        | "EncapsulatedX509Certificate"
        | "EncapsulatedCRLValue"
        | "EncapsulatedOCSPValue"
        | "X509AttributeCertificate"
        | "CertifiedRole" => {
            descend = false;
            Rule::Encoding
        }
        "SignedProperties"
        | "UnsignedProperties"
        | "SignedSignatureProperties"
        | "SignedDataObjectProperties"
        | "UnsignedSignatureProperties"
        | "UnsignedDataObjectProperties"
        | "CounterSignature"
        | "XAdESTimeStamp"
        | "OtherTimeStamp"
        | "AllDataObjectsTimeStamp"
        | "IndividualDataObjectsTimeStamp"
        | "SignatureTimeStamp"
        | "SigAndRefsTimeStamp"
        | "RefsOnlyTimeStamp"
        | "ArchiveTimeStamp"
        | "CompleteCertificateRefs"
        | "CompleteRevocationRefs"
        | "AttributeCertificateRefs"
        | "AttributeRevocationRefs"
        | "CertificateValues"
        | "RevocationValues"
        | "AttrAuthoritiesCertValues"
        | "AttributeRevocationValues" => Rule::Id,
        "Any"
        | "OtherCertificate"
        | "OtherValue"
        | "OtherRef"
        | "ClaimedRole"
        | "SignedAssertion"
        | "OtherAttributeCertificate"
        | "UnsignedDataObjectProperty"
        | "XMLTimeStamp"
        | "SigPolicyQualifier"
        | "CommitmentTypeQualifier"
        | "SignaturePolicyImplied"
        | "AllSignedDataObjects" => {
            descend = false;
            Rule::Open
        }
        _ if plain(local) => Rule::None,
        _ => return None,
    };
    if local == "SigningCertificateV2" {
        context = Context::CertV2;
    }
    Some(Declaration {
        rule,
        descend,
        context,
        schema_type: super::types::declared(
            Name {
                namespace: XADES,
                local,
            },
            parent,
        )?,
    })
}

fn plain(local: &str) -> bool {
    matches!(
        local,
        "ObjectIdentifier"
            | "Description"
            | "DocumentationReferences"
            | "DocumentationReference"
            | "SigningTime"
            | "SigningCertificate"
            | "SigningCertificateV2"
            | "CertRefs"
            | "CertDigest"
            | "IssuerSerialV2"
            | "IssuerSerial"
            | "SignaturePolicyIdentifier"
            | "SignaturePolicyId"
            | "SigPolicyId"
            | "SigPolicyHash"
            | "SigPolicyQualifiers"
            | "SPURI"
            | "SPUserNotice"
            | "NoticeRef"
            | "Organization"
            | "NoticeNumbers"
            | "int"
            | "ExplicitText"
            | "MimeType"
            | "Encoding"
            | "CommitmentTypeIndication"
            | "CommitmentTypeId"
            | "ObjectReference"
            | "CommitmentTypeQualifiers"
            | "SignatureProductionPlace"
            | "SignatureProductionPlaceV2"
            | "City"
            | "StreetAddress"
            | "StateOrProvince"
            | "PostalCode"
            | "CountryName"
            | "SignerRole"
            | "SignerRoleV2"
            | "ClaimedRoles"
            | "CertifiedRoles"
            | "SignedAssertions"
            | "CRLRefs"
            | "CRLRef"
            | "DigestAlgAndValue"
            | "Issuer"
            | "IssueTime"
            | "Number"
            | "OCSPRefs"
            | "OCSPRef"
            | "ResponderID"
            | "ByName"
            | "ByKey"
            | "ProducedAt"
            | "OtherRefs"
            | "CRLValues"
            | "OCSPValues"
            | "OtherValues"
    )
}

fn v141(local: &str, parent: Context) -> Option<Declaration> {
    let mut context = Context::Ordinary;
    let rule = match local {
        "TimeStampValidationData" => Rule::IdUri,
        "AnyValidationData"
        | "SignaturePolicyStore"
        | "RenewedDigestsV2"
        | "ArchiveTimeStamp"
        | "CompleteCertificateRefsV2"
        | "AttributeCertificateRefsV2"
        | "SigAndRefsTimeStampV2"
        | "RefsOnlyTimeStampV2" => Rule::Id,
        "RenewedDigests" => {
            context = Context::Renewed;
            Rule::Id
        }
        // The global legacy element extends DigestValue with required Order;
        // RenewedDigestsV2's identically named local child is a pair wrapper.
        "RecomputedDigestValue" if matches!(parent, Context::Renewed) => Rule::Order,
        "SPDocSpecification"
        | "SignaturePolicyDocument"
        | "SigPolDocLocalURI"
        | "RecomputedDigestValue"
        | "NewSDODigestValue"
        | "OriginalRefDigest"
        | "CertRefs" => Rule::None,
        _ => return None,
    };
    if local == "CertRefs" {
        context = Context::CertV2;
    }
    Some(Declaration {
        rule,
        descend: true,
        context,
        schema_type: super::types::declared(
            Name {
                namespace: XADES_141,
                local,
            },
            parent,
        )?,
    })
}
