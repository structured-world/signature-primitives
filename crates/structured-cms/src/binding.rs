//! Signed content binding and algorithm protection before cryptographic callbacks.

use crate::attribute::{Attribute, Attributes};
use crate::signer::SignerInfo;
use crate::{Error, ErrorCode, Octets, Result, oid};
use structured_asn1::memory::Work;
use structured_asn1::{Oid, Reader, Span, Tag, universal};
use structured_pkix::AlgorithmIdentifier;

/// Result of comparing a declared imprint with complete typed digest bytes.
#[derive(Debug)]
pub enum DigestBinding {
    /// Admitted bytes agree under the selected provider's comparison contract.
    Matches,
    /// Admitted, correctly sized bytes differ.
    Differs,
    /// The declared value has an impossible width; no comparison callback ran.
    Malformed(Error),
}

/// Execution failure distinct from a malformed imprint or byte mismatch.
#[derive(Debug)]
pub enum BindError<E> {
    /// Common admission failed at the declared value's original location.
    Processing(Error),
    /// Original comparison callback failure, including backend resource errors.
    Callback(E),
    /// A completed output conflicts with the selected identity's fixed width.
    OutputWidth {
        /// Width promised by the full resolved identity.
        expected: usize,
        /// Actual completed output size.
        actual: usize,
    },
}

/// Checks actual output width before comparing a declared digest.
///
/// This applies even when `digest_width` is None. `field`/`span` identify the
/// original declaration, not the output or a synthesized DER element. Provider
/// instance identity is checked before work or callback. The borrowed provider
/// retained by the finalized output cannot be replaced or moved while in use.
/// The callback
/// receives bytes already finalized; no resolver, hashing or copy is performed.
pub fn matches_digest<'a, P: crate::provider::DigestProvider<'a>, W: Work>(
    provider: &P,
    digest: crate::provider::Prehash<'_, '_, P, P::Identity>,
    expected: &[u8],
    execution: &W,
    field: &'static str,
    span: Span,
) -> core::result::Result<DigestBinding, BindError<P::Error>> {
    crate::provider::require_instance(provider, field, span.start)
        .map_err(BindError::Processing)?;
    if !digest.from_provider(provider) {
        return Err(BindError::Processing(Error::schema(
            ErrorCode::ProviderMismatch,
            field,
            span.start,
        )));
    }
    execution
        .charge_work(1)
        .map_err(|reason| BindError::Processing(Error::resource(reason, field, span.start)))?;
    let actual = digest.as_bytes().len();
    if let Some(width) = provider.digest_width(digest.identity())
        && width != actual
    {
        return Err(BindError::OutputWidth {
            expected: width,
            actual,
        });
    }
    if expected.len() != actual {
        return Ok(DigestBinding::Malformed(Error::schema(
            ErrorCode::DigestWidth,
            field,
            span.start,
        )));
    }
    if provider
        .matches_digest(digest, expected, execution)
        .map_err(BindError::Callback)?
    {
        Ok(DigestBinding::Matches)
    } else {
        Ok(DigestBinding::Differs)
    }
}

/// The enclosing protocol selects what this signer covers.
#[derive(Debug, Clone, Copy)]
pub enum Scope<'a> {
    /// Normal `SignedData` content type, from its enclosing content-info.
    Content(Oid<'a>),
    /// A countersignature covers the parent signature octets, not message content.
    CounterSignature,
}

/// Original identifiers covered by `CMSAlgorithmProtection` (RFC6211 §2).
#[derive(Debug, Clone, Copy)]
pub struct Protection<'a> {
    digest: AlgorithmIdentifier<'a>,
    signature: AlgorithmIdentifier<'a>,
}

impl<'a> Protection<'a> {
    /// Original protected digest identifier; defaults need selected-provider resolution.
    #[must_use]
    pub fn digest(&self) -> AlgorithmIdentifier<'a> {
        self.digest
    }
    /// Original protected signature identifier, retaining its IMPLICIT `[1]` tag.
    #[must_use]
    pub fn signature(&self) -> AlgorithmIdentifier<'a> {
        self.signature
    }
}

/// Content bytes are signed directly or bound through original signed attributes.
#[derive(Debug)]
pub enum Binding<'a> {
    /// The signature input is the logical content (or parent signature) itself.
    Direct,
    /// Signed attributes bind the content digest; signature input is their original SET spelling.
    Attributes {
        /// Original expected digest octets; no algorithm is inferred from length.
        digest: &'a [u8],
        /// Original digest value's source range for subsequent comparison failures.
        digest_span: Span,
        /// Original algorithm protection, when present. Semantic comparison remains mandatory.
        protection: Option<Protection<'a>>,
    },
}

/// Checks content/type placement and singleton syntax before provider dispatch or payload I/O.
///
/// RFC5652 §§5.3, 11.1–11.4 requires content-type/message-digest for ordinary
/// signed attributes, forbids content-type in countersignatures, and requires
/// attributes for non-id-data. RFC6211 §2 requires one signed protection value
/// and the signature alternative in `SignedData`. This returns binding facts,
/// not a signature/trust verdict; protected identities still need the provider.
/// <https://www.rfc-editor.org/rfc/rfc5652#section-11>
/// <https://www.rfc-editor.org/rfc/rfc6211#section-2>
pub fn inspect<'a>(
    signer: &SignerInfo<'a>,
    parent: &Reader<'a>,
    scope: Scope<'a>,
) -> Result<Binding<'a>> {
    signer.require_session(parent, "signerInfo")?;
    // RFC5652 §5.3 requires both written attribute sets to be nonempty.
    // Inspection can retain this unique malformed shape, but even unsigned
    // emptiness must refuse before any provider resolution or payload access.
    // https://www.rfc-editor.org/rfc/rfc5652#section-5.3
    for attributes in [signer.signed_attributes(), signer.unsigned_attributes()]
        .into_iter()
        .flatten()
    {
        if let Some(fault) = attributes.fault() {
            return Err(fault);
        }
    }
    check_placements(signer, parent)?;
    let Some(attributes) = signer.signed_attributes() else {
        if let Scope::Content(kind) = scope {
            parent
                .execution()
                .charge_work(kind.as_bytes().len() as u64)
                .map_err(|reason| {
                    Error::resource(reason, "signerInfo.signedAttrs", signer.span().start)
                })?;
            if kind != oid::DATA {
                return Err(Error::schema(
                    ErrorCode::MissingField,
                    "signerInfo.signedAttrs",
                    signer.span().start,
                ));
            }
        }
        return Ok(Binding::Direct);
    };
    let content_type = attributes.unique_in(oid::CONTENT_TYPE, parent)?;
    match scope {
        Scope::CounterSignature => {
            if let Some(attribute) = content_type {
                return Err(Error::schema(
                    ErrorCode::AttributePlacement,
                    "signerInfo.signedAttrs.contentType",
                    attribute.span().start,
                ));
            }
        }
        Scope::Content(expected) => {
            let attribute = content_type.ok_or_else(|| {
                Error::schema(
                    ErrorCode::MissingField,
                    "signerInfo.signedAttrs.contentType",
                    attributes.element().span().start,
                )
            })?;
            attribute.single("signerInfo.signedAttrs.contentType")?;
            let mut reader = value_reader(attribute, parent, "signerInfo.signedAttrs.contentType")?;
            let declared = reader
                .read_oid()
                .map_err(|error| Error::encoding(error, "signerInfo.signedAttrs.contentType"))?;
            parent
                .execution()
                .charge_work(declared.as_bytes().len() as u64)
                .map_err(|reason| {
                    Error::resource(
                        reason,
                        "signerInfo.signedAttrs.contentType",
                        attribute.span().start,
                    )
                })?;
            if declared != expected {
                return Err(Error::schema(
                    ErrorCode::ContentTypeMismatch,
                    "signerInfo.signedAttrs.contentType",
                    attribute.span().start,
                ));
            }
        }
    }
    let attribute = attributes
        .unique_in(oid::MESSAGE_DIGEST, parent)?
        .ok_or_else(|| {
            Error::schema(
                ErrorCode::MissingField,
                "signerInfo.signedAttrs.messageDigest",
                attributes.element().span().start,
            )
        })?;
    attribute.single("signerInfo.signedAttrs.messageDigest")?;
    let mut reader = value_reader(attribute, parent, "signerInfo.signedAttrs.messageDigest")?;
    let element = crate::signer::required(&mut reader, "signerInfo.signedAttrs.messageDigest")?;
    let digest = Octets::read(&reader, &element, "signerInfo.signedAttrs.messageDigest")?;
    // Signed values have already been held to DER; OCTET STRING therefore has
    // exactly one primitive range. Borrow that range instead of retaining a
    // redundant segmented representation in every verification plan.
    let digest = digest.as_one().ok_or_else(|| {
        Error::schema(
            ErrorCode::UnexpectedTag,
            "signerInfo.signedAttrs.messageDigest",
            element.span().start,
        )
    })?;
    check_signing_time(attributes, parent)?;
    let protection = read_protection(attributes, parent)?;
    Ok(Binding::Attributes {
        digest,
        digest_span: element.span(),
        protection,
    })
}

fn check_placements(signer: &SignerInfo<'_>, parent: &Reader<'_>) -> Result<()> {
    if let Some(unsigned) = signer.unsigned_attributes() {
        // RFC5652 §§11.1–11.3 and RFC6211 §2 define these as signed attributes.
        // https://www.rfc-editor.org/rfc/rfc5652#section-11
        for kind in [
            oid::CONTENT_TYPE,
            oid::MESSAGE_DIGEST,
            oid::SIGNING_TIME,
            oid::ALGORITHM_PROTECTION,
        ] {
            if let Some(result) = unsigned.all_in(kind, parent).next() {
                let attribute = result?;
                return Err(Error::schema(
                    ErrorCode::AttributePlacement,
                    "signerInfo.unsignedAttrs",
                    attribute.span().start,
                ));
            }
        }
    }
    if let Some(signed) = signer.signed_attributes()
        && let Some(result) = signed.all_in(oid::COUNTERSIGNATURE, parent).next()
    {
        let attribute = result?;
        return Err(Error::schema(
            ErrorCode::AttributePlacement,
            "signerInfo.signedAttrs.counterSignature",
            attribute.span().start,
        ));
    }
    Ok(())
}

fn check_signing_time(attributes: &Attributes<'_>, parent: &Reader<'_>) -> Result<()> {
    const FIELD: &str = "signerInfo.signedAttrs.signingTime";
    let Some(attribute) = attributes.unique_in(oid::SIGNING_TIME, parent)? else {
        return Ok(());
    };
    let value = attribute.single(FIELD)?;
    parent
        .execution()
        .charge_work(9)
        .map_err(|reason| Error::resource(reason, FIELD, value.span().start))?;
    // General DER time validation already uses the shared calendar core. CMS
    // adds its own selected encoding contract: UTC for 1950..2049, generalized
    // otherwise, and no fractional seconds (RFC5652 §11.3).
    // https://www.rfc-editor.org/rfc/rfc5652#section-11.3
    let valid = if value.tag() == Tag::primitive(universal::UTC_TIME) {
        value.contents().len() == 13
    } else if value.tag() == Tag::primitive(universal::GENERALIZED_TIME) {
        value.contents().len() == 15
            && !(value.contents()[..4] >= b"1950"[..] && value.contents()[..4] <= b"2049"[..])
    } else {
        false
    };
    if !valid {
        return Err(Error::schema(
            ErrorCode::AttributeSyntax,
            FIELD,
            value.span().start,
        ));
    }
    Ok(())
}

fn value_reader<'a, 'query>(
    attribute: &Attribute<'a>,
    parent: &Reader<'query>,
    field: &'static str,
) -> Result<Reader<'query>>
where
    'a: 'query,
{
    attribute.value_reader_in(0, parent, field)?.ok_or_else(|| {
        Error::schema(
            ErrorCode::AttributeCardinality,
            field,
            attribute.span().start,
        )
    })
}

fn read_protection<'a>(
    attributes: &Attributes<'a>,
    parent: &Reader<'a>,
) -> Result<Option<Protection<'a>>> {
    const FIELD: &str = "signerInfo.signedAttrs.cmsAlgorithmProtection";
    let Some(attribute) = attributes.unique_in(oid::ALGORITHM_PROTECTION, parent)? else {
        return Ok(None);
    };
    attribute.single(FIELD)?;
    let mut reader = value_reader(attribute, parent, FIELD)?;
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .map_err(|error| Error::encoding(error, FIELD))?;
    let mut inside = reader
        .enter(&element)
        .map_err(|error| Error::encoding(error, FIELD))?;
    let digest = crate::signer::required(&mut inside, FIELD)?;
    let digest = structured_pkix::algorithm::read(&inside, &digest, FIELD).map_err(Error::pkix)?;
    let signature = crate::signer::required(&mut inside, FIELD)?;
    let signature = structured_pkix::algorithm::read_implicit(&inside, &signature, 1, FIELD)
        .map_err(Error::pkix)?;
    if !inside.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            FIELD,
            inside.offset(),
        ));
    }
    Ok(Some(Protection { digest, signature }))
}
