//! Original timestamp signing syntax, before certificate/provider selection.

use super::{Finding, Rule, Severity, Timestamp, finding};
use crate::{Error, Result, source::Document};
use structured_asn1::{
    Reader, Span,
    digest::Resolution,
    memory::{OwnedVec, Work},
};
use structured_cms::{
    ErrorCode, binding,
    ess::SigningAttributes,
    oid,
    provider::{DigestAlgorithm, ImpliedDigest},
    timestamp::Token,
};
use structured_pkix::{AlgorithmIdentifier, algorithm::digest as algorithms};

pub(super) enum InspectionError {
    Reader(Error),
    Physical(Error),
}
impl InspectionError {
    pub(super) fn into_source(self) -> Error {
        match self {
            Self::Reader(source) | Self::Physical(source) => source,
        }
    }
}

pub(super) fn read<'m, 'd>(
    document: &Document<'m, 'd>,
    entry: &Timestamp<'d>,
    token: &Token<'d>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<SigningAttributes<'d>> {
    let signing = SigningAttributes::inspect(token.signer(), parent)?;
    parent
        .charge(1)
        .map_err(|cause| Error::encoding(cause, "cades.timestamp.ess"))?;
    // RFC3161 §2.4.2, updated by RFC5816 §2.2.1, requires a readable signed
    // TSA certificate identifier even when no certificate has been selected.
    // This is presence/syntax, not a hash, issuer or trust assertion.
    // https://www.rfc-editor.org/rfc/rfc5816#section-2.2.1
    if signing.v1().is_none() && signing.v2().is_none() {
        schema(
            document,
            token.signer().span(),
            ErrorCode::MissingField,
            "timeStampToken.signingCertificate",
            parent,
            findings,
        )?;
    }
    certificate_identifiers(document, &signing, parent, findings)?;
    let declared = match binding::inspect(
        token.signer(),
        parent,
        binding::Scope::Content(oid::TST_INFO),
    ) {
        Ok(binding::Binding::Attributes { digest, .. }) => Some(digest.len()),
        Ok(binding::Binding::Direct) => None,
        Err(cause) => {
            if cause.is_terminal() {
                return Err(cause.into());
            }
            schema(
                document,
                Span {
                    start: cause.offset(),
                    length: 0,
                },
                cause.code(),
                cause.field(),
                parent,
                findings,
            )?;
            None
        }
    };
    if let Some(algorithm) = token.signer().digest_algorithm().identifier() {
        digest(
            document,
            entry.property.span(),
            &algorithm,
            declared,
            "signerInfo.signedAttrs.messageDigest",
            parent,
            findings,
        )
        .map_err(InspectionError::into_source)?;
    }
    Ok(signing)
}

fn certificate_identifiers<'m, 'd>(
    document: &Document<'m, 'd>,
    signing: &SigningAttributes<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<()> {
    for cause in signing.faults() {
        schema(
            document,
            Span {
                start: cause.offset(),
                length: 0,
            },
            cause.code(),
            cause.field(),
            parent,
            findings,
        )?;
    }
    for attribute in [signing.v1(), signing.v2()].into_iter().flatten() {
        for cause in attribute.faults() {
            schema(
                document,
                Span {
                    start: cause.offset(),
                    length: 0,
                },
                cause.code(),
                cause.field(),
                parent,
                findings,
            )?;
        }
        for identifier in attribute.identifiers() {
            parent
                .charge(1)
                .map_err(|cause| Error::encoding(cause, "cades.timestamp.ess"))?;
            let span = identifier.element().span();
            let field = "timeStampToken.signingCertificate.certHash";
            match identifier.digest_algorithm() {
                DigestAlgorithm::Written(algorithm) => {
                    digest(
                        document,
                        span,
                        &algorithm,
                        Some(identifier.hashed().len()),
                        field,
                        parent,
                        findings,
                    )
                    .map_err(InspectionError::into_source)?;
                }
                DigestAlgorithm::Implied { algorithm, .. } => {
                    let width = match algorithm {
                        ImpliedDigest::EssSha1 => 20,
                        ImpliedDigest::EssV2Sha256 => 32,
                    };
                    if identifier.hashed().len() != width {
                        schema(
                            document,
                            span,
                            ErrorCode::DigestWidth,
                            field,
                            parent,
                            findings,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn schema<'m, 'd>(
    document: &Document<'m, 'd>,
    span: Span,
    code: ErrorCode,
    field: &'static str,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<()> {
    parent
        .charge(1)
        .map_err(|cause| Error::encoding(cause, field))?;
    finding(
        document,
        span,
        Severity::Required,
        Rule::Schema { code, field },
        findings,
    )
}

pub(super) fn digest<'m, 'd>(
    document: &Document<'m, 'd>,
    span: Span,
    algorithm: &AlgorithmIdentifier<'_>,
    expected: Option<usize>,
    field: &'static str,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> core::result::Result<Resolution<algorithms::Algorithm>, InspectionError> {
    let md5 = structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
    parent
        .charge(
            1 + algorithm
                .algorithm()
                .as_bytes()
                .len()
                .min(md5.as_bytes().len()) as u64,
        )
        .map_err(|cause| InspectionError::Reader(Error::encoding(cause, field)))?;
    // EN319122-1 §6.2.1 is format-wide, including optional TSA/ESS inputs.
    if algorithm.algorithm() == md5 {
        finding(document, span, Severity::Required, Rule::Md5, findings)
            .map_err(InspectionError::Physical)?;
    }
    let identity = algorithms::algorithm(algorithm, &parent.execution())
        .map_err(|cause| InspectionError::Reader(Error::Pkix(cause)))?;
    match identity {
        Resolution::Supported(identity)
            if expected.is_some_and(|length| length != identity.width()) =>
        {
            schema(
                document,
                span,
                ErrorCode::DigestWidth,
                field,
                parent,
                findings,
            )
            .map_err(InspectionError::Physical)?;
        }
        Resolution::Malformed => schema(
            document,
            span,
            ErrorCode::AlgorithmSyntax,
            field,
            parent,
            findings,
        )
        .map_err(InspectionError::Physical)?,
        // Unknown mechanisms remain a capability question for the selected
        // provider. Width never manufactures a digest identity or default.
        _ => {}
    }
    Ok(identity)
}
