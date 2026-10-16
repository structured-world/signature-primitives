//! Pinned Annex C declared type names, including contextual local declarations.

use super::Context;
use crate::{
    container::{DS, XADES},
    timestamp::XADES_141,
    xml::Name,
};

const XSD: &str = "http://www.w3.org/2001/XMLSchema";

// EN319132-1 V1.3.1 Annex C publisher schemas. These are declaration names,
// not an inference from allowed attributes or a replacement XML/XSD parser.
// https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd
// https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v141.xsd
pub(super) fn declared(name: Name<'_>, parent: Context) -> Option<Name<'static>> {
    let (namespace, local) = if name.namespace == XADES {
        v132(name.local, parent)?
    } else if name.namespace == XADES_141 {
        match name.local {
            "AnyValidationData" | "TimeStampValidationData" => (XADES_141, "ValidationDataType"),
            "SignaturePolicyStore" => (XADES_141, "SignaturePolicyStoreType"),
            "SignaturePolicyDocument" => (XSD, "base64Binary"),
            "SigPolDocLocalURI" => (XSD, "anyURI"),
            "SPDocSpecification" => (XADES, "ObjectIdentifierType"),
            "RenewedDigests" => (XADES_141, "RenewedDigestsType"),
            "RenewedDigestsV2" => (XADES_141, "RenewedDigestsV2Type"),
            "RecomputedDigestValue" if matches!(parent, Context::Renewed) => {
                (XADES_141, "RecomputedDigestValueType")
            }
            "RecomputedDigestValue" => (XADES_141, "RecomputedDigestValueV2Type"),
            "NewSDODigestValue" | "OriginalRefDigest" => (DS, "DigestValueType"),
            "ArchiveTimeStamp" | "RefsOnlyTimeStampV2" | "SigAndRefsTimeStampV2" => {
                (XADES, "XAdESTimeStampType")
            }
            "AttributeCertificateRefsV2" | "CompleteCertificateRefsV2" => {
                (XADES_141, "CompleteCertificateRefsTypeV2")
            }
            "CertRefs" => (XADES, "CertIDListV2Type"),
            _ => return None,
        }
    } else {
        return None;
    };
    Some(Name { namespace, local })
}

fn v132(local: &str, parent: Context) -> Option<(&'static str, &'static str)> {
    let kind = match local {
        "Description" | "ByName" | "City" | "CountryName" | "ExplicitText" | "Issuer"
        | "MimeType" | "Organization" | "PostalCode" | "StateOrProvince" | "StreetAddress" => {
            return Some((XSD, "string"));
        }
        "DocumentationReference" | "Encoding" | "ObjectReference" | "SPURI" => {
            return Some((XSD, "anyURI"));
        }
        "IssueTime" | "ProducedAt" | "SigningTime" => return Some((XSD, "dateTime")),
        "ByKey" | "IssuerSerialV2" => return Some((XSD, "base64Binary")),
        "AllSignedDataObjects" | "SignaturePolicyImplied" => return Some((XSD, "anyType")),
        "Number" | "int" => return Some((XSD, "integer")),
        "IssuerSerial" => return Some((DS, "X509IssuerSerialType")),
        "Any"
        | "ClaimedRole"
        | "CommitmentTypeQualifier"
        | "OtherAttributeCertificate"
        | "OtherCertificate"
        | "OtherRef"
        | "OtherValue"
        | "SigPolicyQualifier"
        | "SignedAssertion"
        | "UnsignedDataObjectProperty"
        | "XMLTimeStamp" => "AnyType",
        "CommitmentTypeId" | "ObjectIdentifier" | "SigPolicyId" => "ObjectIdentifierType",
        "Identifier" => "IdentifierType",
        "DocumentationReferences" => "DocumentationReferencesType",
        "CertifiedRole" if matches!(parent, Context::CertifiedV2) => "CertifiedRoleTypeV2",
        "CertifiedRole"
        | "EncapsulatedCRLValue"
        | "EncapsulatedOCSPValue"
        | "EncapsulatedPKIData"
        | "EncapsulatedTimeStamp"
        | "EncapsulatedX509Certificate"
        | "X509AttributeCertificate" => "EncapsulatedPKIDataType",
        "Include" => "IncludeType",
        "ReferenceInfo" => "ReferenceInfoType",
        "AllDataObjectsTimeStamp"
        | "ArchiveTimeStamp"
        | "IndividualDataObjectsTimeStamp"
        | "RefsOnlyTimeStamp"
        | "SigAndRefsTimeStamp"
        | "SignatureTimeStamp"
        | "XAdESTimeStamp" => "XAdESTimeStampType",
        "OtherTimeStamp" => "OtherTimeStampType",
        "QualifyingProperties" => "QualifyingPropertiesType",
        "SignedProperties" => "SignedPropertiesType",
        "UnsignedProperties" => "UnsignedPropertiesType",
        "SignedSignatureProperties" => "SignedSignaturePropertiesType",
        "SignedDataObjectProperties" => "SignedDataObjectPropertiesType",
        "UnsignedSignatureProperties" => "UnsignedSignaturePropertiesType",
        "UnsignedDataObjectProperties" => "UnsignedDataObjectPropertiesType",
        "QualifyingPropertiesReference" => "QualifyingPropertiesReferenceType",
        "SigningCertificate" | "CertRefs" => "CertIDListType",
        "SigningCertificateV2" => "CertIDListV2Type",
        "Cert" if matches!(parent, Context::CertV2) => "CertIDTypeV2",
        "Cert" => "CertIDType",
        "CertDigest" | "DigestAlgAndValue" | "SigPolicyHash" => "DigestAlgAndValueType",
        "SignaturePolicyIdentifier" => "SignaturePolicyIdentifierType",
        "SignaturePolicyId" => "SignaturePolicyIdType",
        "SigPolicyQualifiers" => "SigPolicyQualifiersListType",
        "SPUserNotice" => "SPUserNoticeType",
        "NoticeRef" => "NoticeReferenceType",
        "NoticeNumbers" => "IntegerListType",
        "CounterSignature" => "CounterSignatureType",
        "DataObjectFormat" => "DataObjectFormatType",
        "CommitmentTypeIndication" => "CommitmentTypeIndicationType",
        "CommitmentTypeQualifiers" => "CommitmentTypeQualifiersListType",
        "SignatureProductionPlace" => "SignatureProductionPlaceType",
        "SignatureProductionPlaceV2" => "SignatureProductionPlaceV2Type",
        "SignerRole" => "SignerRoleType",
        "ClaimedRoles" => "ClaimedRolesListType",
        "CertifiedRoles" => "CertifiedRolesListType",
        "SignerRoleV2" => "SignerRoleV2Type",
        "CertifiedRolesV2" => "CertifiedRolesListTypeV2",
        "SignedAssertions" => "SignedAssertionsListType",
        "AttributeCertificateRefs" | "CompleteCertificateRefs" => "CompleteCertificateRefsType",
        "AttributeRevocationRefs" | "CompleteRevocationRefs" => "CompleteRevocationRefsType",
        "CRLRefs" => "CRLRefsType",
        "OCSPRefs" => "OCSPRefsType",
        "OtherRefs" => "OtherCertStatusRefsType",
        "CRLRef" => "CRLRefType",
        "CRLIdentifier" => "CRLIdentifierType",
        "OCSPRef" => "OCSPRefType",
        "OCSPIdentifier" => "OCSPIdentifierType",
        "ResponderID" => "ResponderIDType",
        "AttrAuthoritiesCertValues" | "CertificateValues" => "CertificateValuesType",
        "AttributeRevocationValues" | "RevocationValues" => "RevocationValuesType",
        "CRLValues" => "CRLValuesType",
        "OCSPValues" => "OCSPValuesType",
        "OtherValues" => "OtherCertStatusValuesType",
        _ => return None,
    };
    Some((XADES, kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_declarations_retain_actual_parent_type_context() {
        // Annex C has three repeated local names with different types. A
        // type override must never borrow its admissibility from a namesake.
        for (namespace, local, context, expected_namespace, expected_local) in [
            (XADES, "Cert", Context::Ordinary, XADES, "CertIDType"),
            (XADES, "Cert", Context::CertV2, XADES, "CertIDTypeV2"),
            (
                XADES,
                "CertifiedRole",
                Context::Ordinary,
                XADES,
                "EncapsulatedPKIDataType",
            ),
            (
                XADES,
                "CertifiedRole",
                Context::CertifiedV2,
                XADES,
                "CertifiedRoleTypeV2",
            ),
            (
                XADES_141,
                "RecomputedDigestValue",
                Context::Renewed,
                XADES_141,
                "RecomputedDigestValueType",
            ),
            (
                XADES_141,
                "RecomputedDigestValue",
                Context::Ordinary,
                XADES_141,
                "RecomputedDigestValueV2Type",
            ),
            (
                XADES_141,
                "ArchiveTimeStamp",
                Context::Ordinary,
                XADES,
                "XAdESTimeStampType",
            ),
            (
                XADES,
                "AllSignedDataObjects",
                Context::Ordinary,
                XSD,
                "anyType",
            ),
        ] {
            assert_eq!(
                declared(Name { namespace, local }, context),
                Some(Name {
                    namespace: expected_namespace,
                    local: expected_local
                })
            );
        }
    }
}
