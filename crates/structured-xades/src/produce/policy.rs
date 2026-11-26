//! Explicit and implied signature policy construction, including storage.

use super::qualifying::fragment;
use super::{DS, Datatype, Emit, Error, FragmentSlot, Identifier, PropertyWriter, Work, XADES};
use crate::timestamp::XADES_141;

const SPECIFICATION_TRANSFORM: &str =
    "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

/// The exact selected policy-document processing plan.
pub enum PolicyTransform<'a, F> {
    /// Hash the original policy document bytes.
    None,
    /// Transform the original bytes with this XML-owned ds:Transforms plan.
    /// The ETSI specification transform has its dedicated typed variant.
    Xml(&'a F),
    /// Compute the digest as specified by an explicit technical specification.
    InSpecification(Identifier<'a>),
}

/// An exact XML-owner transformation and digest operation for a policy property.
pub trait PolicyWriter: PropertyWriter {
    /// Finished output of the selected policy digest method.
    type Digest: AsRef<[u8]>;

    /// Compute the digest of this supplied policy document under this same
    /// transform plan. The owner validates all algorithm parameters, accounts
    /// for processing, and serializes the same XML plan through `fragment()`.
    /// An unavailable technical specification must produce the owner's typed
    /// refusal. The None route must use the original supplied document bytes.
    fn policy_digest<W: Work>(
        &self,
        document: &[u8],
        method: &str,
        transform: &PolicyTransform<'_, Self::Fragment>,
        work: &W,
    ) -> Result<Self::Digest, Self::Error>;

    /// Check that this explicit policy is the actual staged or original
    /// signed policy of the selected signature. Match the version, document
    /// and digest plan under current Work, preserving source or policy errors.
    fn matches_policy<W: Work>(
        &self,
        policy: &ExplicitPolicy<'_, Self::Fragment>,
        work: &W,
    ) -> Result<bool, Self::Error>;
}

/// Original lexical policy notice reference and arbitrary-width numbers.
pub struct NoticeReference<'a> {
    /// Organization that maintains the referenced notices.
    pub organization: &'a str,
    /// XSD integer values identifying notices, in order.
    pub numbers: &'a [&'a str],
}

/// Information displayed to the relying party as a policy qualifier.
pub struct UserNotice<'a> {
    /// Optional reference to published notices.
    pub reference: Option<NoticeReference<'a>>,
    /// Optional notice text.
    pub text: Option<&'a str>,
}

/// Additional policy information in source order.
pub enum PolicyQualifier<'a, F> {
    /// An address for obtaining the policy.
    Uri(&'a str),
    /// An explicit text or reference to a notice.
    Notice(UserNotice<'a>),
    /// A technical specification for the document format.
    DocumentSpecification(Identifier<'a>),
    /// XML-owned extension contents of one `SigPolicyQualifier`.
    Other(F),
}

/// One explicit policy version, its actual document and hash plan.
pub struct ExplicitPolicy<'a, F> {
    /// Exact policy version identifier.
    pub identifier: Identifier<'a>,
    /// Original bytes given to the policy digest operation.
    pub document: &'a [u8],
    /// Selected ds:DigestMethod algorithm URI, written exactly as supplied.
    pub digest_method: &'a str,
    /// Exact transform plan, shared between execution and emission.
    pub transform: PolicyTransform<'a, F>,
    /// Additional qualifiers. `InSpecification` emits its own specification,
    /// so its effective identifier cannot be omitted or substituted.
    pub qualifiers: &'a [PolicyQualifier<'a, F>],
}

/// Signed `SignaturePolicyIdentifier` choice.
pub enum SignaturePolicy<'a, F> {
    /// The signature's policy is implied by application context.
    Implied,
    /// The signature names and binds a version of the supplied policy document.
    Explicit(ExplicitPolicy<'a, F>),
}

impl<F> SignaturePolicy<'_, F> {
    /// Emit into `SignedSignatureProperties`. EN 319 132-1 §5.2.9 binds the
    /// digest to the original document after the indicated transforms.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: PolicyWriter<Fragment = F>, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        let Self::Explicit(policy) = self else {
            let mut emit = Emit { writer, work };
            emit.begin(XADES, "SignaturePolicyIdentifier")?;
            emit.begin(XADES, "SignaturePolicyImplied")?;
            emit.end()?;
            return emit.end();
        };
        if policy.identifier.uri.is_empty() || policy.digest_method.is_empty() {
            return Err(Error::Value("signaturePolicyId.required"));
        }
        if let PolicyTransform::InSpecification(spec) = policy.transform {
            require_specification(spec)?;
        }
        for qualifier in policy.qualifiers {
            work.charge_work(1).map_err(Error::Resource)?;
            if let PolicyQualifier::DocumentSpecification(specification) = qualifier {
                require_specification(*specification)?;
            }
        }
        work.charge_work(1).map_err(Error::Resource)?;
        let digest = writer
            .policy_digest(
                policy.document,
                policy.digest_method,
                &policy.transform,
                work,
            )
            .map_err(Error::Writer)?;
        if digest.as_ref().is_empty() {
            return Err(Error::Value("signaturePolicyId.digest"));
        }
        let mut emit = Emit { writer, work };
        emit.begin(XADES, "SignaturePolicyIdentifier")?;
        emit.begin(XADES, "SignaturePolicyId")?;
        policy.identifier.write(XADES, "SigPolicyId", &mut emit)?;
        match policy.transform {
            PolicyTransform::None => {}
            PolicyTransform::Xml(value) => {
                fragment(&mut emit, FragmentSlot::PolicyTransforms, value)?;
            }
            PolicyTransform::InSpecification(_) => {
                emit.begin(DS, "Transforms")?;
                emit.begin(DS, "Transform")?;
                emit.attribute("Algorithm", SPECIFICATION_TRANSFORM)?;
                emit.end()?;
                emit.end()?;
            }
        }
        emit.begin(XADES, "SigPolicyHash")?;
        emit.digest(policy.digest_method, digest.as_ref())?;
        emit.end()?;
        qualifiers(&mut emit, policy)?;
        emit.end()?;
        emit.end()
    }
}

/// How the unsigned policy store makes the same policy document available.
pub enum PolicyDocument<'a> {
    /// Embed the exact original bytes of the explicit signed policy.
    Embedded,
    /// Reference a local store holding that policy document.
    LocalUri(&'a str),
}

/// Required document specification and retrieval form of `SignaturePolicyStore`.
pub struct PolicyStore<'a> {
    /// Technical specification for the syntax of the document.
    pub specification: Identifier<'a>,
    /// Embedded bytes or a local URI.
    pub document: PolicyDocument<'a>,
}

impl<F> ExplicitPolicy<'_, F> {
    /// Write the store for this explicit policy into `UnsignedSignatureProperties`.
    /// The writer checks the policy against the selected signature before
    /// any output. Embedded bytes come from the exact explicit-policy input.
    ///
    /// EN 319 132-1 §5.2.10 and §6.3(m) require an explicit signed policy
    /// and an unsigned store in the 1.4.1 namespace.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write_store<B: PolicyWriter<Fragment = F>, W: Work>(
        &self,
        store: &PolicyStore<'_>,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        require_specification(store.specification)?;
        work.charge_work(1).map_err(Error::Resource)?;
        if !writer.matches_policy(self, work).map_err(Error::Writer)? {
            return Err(Error::Foreign);
        }
        let mut emit = Emit { writer, work };
        emit.begin(XADES_141, "SignaturePolicyStore")?;
        store
            .specification
            .write(XADES_141, "SPDocSpecification", &mut emit)?;
        match store.document {
            PolicyDocument::Embedded => {
                emit.binary(XADES_141, "SignaturePolicyDocument", self.document)?;
            }
            PolicyDocument::LocalUri(uri) => {
                emit.scalar(XADES_141, "SigPolDocLocalURI", uri, Datatype::AnyUri)?;
            }
        }
        emit.end()
    }
}

fn require_specification<E>(specification: Identifier<'_>) -> Result<(), Error<E>> {
    // EN 319 132-1 §5.2.9.2 uses an unqualified URI or an OIDAsURN.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    if specification.uri.is_empty()
        || specification.qualifier == Some(crate::identifier::Qualifier::Uri)
    {
        return Err(Error::Value("signaturePolicy.specification"));
    }
    Ok(())
}

fn qualifiers<B: PropertyWriter<Fragment = F>, F, W: Work>(
    emit: &mut Emit<'_, B, W>,
    policy: &ExplicitPolicy<'_, F>,
) -> Result<(), Error<B::Error>> {
    let specification = match policy.transform {
        PolicyTransform::InSpecification(specification) => Some(specification),
        _ => None,
    };
    if specification.is_none() && policy.qualifiers.is_empty() {
        return Ok(());
    }
    emit.begin(XADES, "SigPolicyQualifiers")?;
    if let Some(spec) = specification {
        emit.begin(XADES, "SigPolicyQualifier")?;
        spec.write(XADES_141, "SPDocSpecification", emit)?;
        emit.end()?;
    }
    for qualifier in policy.qualifiers {
        emit.begin(XADES, "SigPolicyQualifier")?;
        match qualifier {
            PolicyQualifier::Uri(uri) => emit.scalar(XADES, "SPURI", uri, Datatype::AnyUri)?,
            PolicyQualifier::Notice(notice) => user_notice(emit, notice)?,
            PolicyQualifier::DocumentSpecification(spec) => {
                spec.write(XADES_141, "SPDocSpecification", emit)?;
            }
            PolicyQualifier::Other(value) => fragment(emit, FragmentSlot::AnyContent, value)?,
        }
        emit.end()?;
    }
    emit.end()
}

fn user_notice<B: PropertyWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    notice: &UserNotice<'_>,
) -> Result<(), Error<B::Error>> {
    emit.begin(XADES, "SPUserNotice")?;
    if let Some(reference) = &notice.reference {
        emit.begin(XADES, "NoticeRef")?;
        emit.text(XADES, "Organization", reference.organization)?;
        emit.begin(XADES, "NoticeNumbers")?;
        for number in reference.numbers {
            emit.begin(XADES, "int")?;
            emit.work.charge_work(1).map_err(Error::Resource)?;
            emit.writer
                .integer(number, emit.work)
                .map_err(Error::Writer)?;
            emit.end()?;
        }
        emit.end()?;
        emit.end()?;
    }
    if let Some(text) = notice.text {
        emit.text(XADES, "ExplicitText", text)?;
    }
    emit.end()
}
