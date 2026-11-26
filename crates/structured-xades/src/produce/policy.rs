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

/// An explicit policy whose digest was obtained outside this operation.
pub struct SuppliedPolicy<'a, F> {
    /// Exact policy version identifier.
    pub identifier: Identifier<'a>,
    /// The digest method URI written in the signature.
    pub digest_method: &'a str,
    /// Finished digest for this policy version and declared transformation.
    pub digest: &'a [u8],
    /// Exact transform declaration associated with the supplied digest.
    pub transform: PolicyTransform<'a, F>,
    /// Ordered policy qualifiers.
    pub qualifiers: &'a [PolicyQualifier<'a, F>],
}

impl<F> SuppliedPolicy<'_, F> {
    /// Write the explicit signed declaration using the supplied digest.
    /// The resolver checks the exact method with the caller's selected
    /// provider and policy and returns its fixed output width. This path
    /// does not acquire the document or issue an unsigned policy store.
    ///
    /// EN 319 132-1 §§5.2.9–5.2.10 define the declaration and policy store
    /// independently.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: PropertyWriter<Fragment = F>, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
        resolve_width: impl FnOnce(&str, &W) -> Result<usize, B::Error>,
    ) -> Result<(), Error<B::Error>> {
        require_declaration(
            self.identifier,
            self.digest_method,
            &self.transform,
            self.qualifiers,
            work,
        )?;
        if self.digest.is_empty() {
            return Err(Error::Value("signaturePolicyId.digest"));
        }
        work.charge_work(1).map_err(Error::Resource)?;
        let width = resolve_width(self.digest_method, work).map_err(Error::Writer)?;
        if width != self.digest.len() {
            return Err(Error::Value("signaturePolicyId.digestWidth"));
        }
        emit_explicit(
            writer,
            work,
            self.identifier,
            self.digest_method,
            self.digest,
            &self.transform,
            self.qualifiers,
        )
    }
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
        require_declaration(
            policy.identifier,
            policy.digest_method,
            &policy.transform,
            policy.qualifiers,
            work,
        )?;
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
        emit_explicit(
            writer,
            work,
            policy.identifier,
            policy.digest_method,
            digest.as_ref(),
            &policy.transform,
            policy.qualifiers,
        )
    }
}

fn require_declaration<E, F, W: Work>(
    identifier: Identifier<'_>,
    method: &str,
    transform: &PolicyTransform<'_, F>,
    qualifiers: &[PolicyQualifier<'_, F>],
    work: &W,
) -> Result<(), Error<E>> {
    if identifier.uri.is_empty() || method.is_empty() {
        return Err(Error::Value("signaturePolicyId.required"));
    }
    if let PolicyTransform::InSpecification(spec) = transform {
        require_specification(*spec)?;
    }
    for qualifier in qualifiers {
        work.charge_work(1).map_err(Error::Resource)?;
        if let PolicyQualifier::DocumentSpecification(specification) = qualifier {
            require_specification(*specification)?;
        }
    }
    Ok(())
}

fn emit_explicit<B: PropertyWriter, W: Work>(
    writer: &mut B,
    work: &W,
    identifier: Identifier<'_>,
    method: &str,
    digest: &[u8],
    transform: &PolicyTransform<'_, B::Fragment>,
    qualifiers: &[PolicyQualifier<'_, B::Fragment>],
) -> Result<(), Error<B::Error>> {
    let mut emit = Emit { writer, work };
    emit.begin(XADES, "SignaturePolicyIdentifier")?;
    emit.begin(XADES, "SignaturePolicyId")?;
    identifier.write(XADES, "SigPolicyId", &mut emit)?;
    let specification = match transform {
        PolicyTransform::None => None,
        PolicyTransform::Xml(value) => {
            fragment(&mut emit, FragmentSlot::PolicyTransforms, value)?;
            None
        }
        PolicyTransform::InSpecification(spec) => {
            emit.begin(DS, "Transforms")?;
            emit.begin(DS, "Transform")?;
            emit.attribute("Algorithm", SPECIFICATION_TRANSFORM)?;
            emit.end()?;
            emit.end()?;
            Some(*spec)
        }
    };
    emit.begin(XADES, "SigPolicyHash")?;
    emit.digest(method, digest)?;
    emit.end()?;
    emit_qualifiers(&mut emit, specification, qualifiers)?;
    emit.end()?;
    emit.end()
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

fn emit_qualifiers<B: PropertyWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    specification: Option<Identifier<'_>>,
    qualifiers: &[PolicyQualifier<'_, B::Fragment>],
) -> Result<(), Error<B::Error>> {
    if specification.is_none() && qualifiers.is_empty() {
        return Ok(());
    }
    emit.begin(XADES, "SigPolicyQualifiers")?;
    if let Some(spec) = specification {
        emit.begin(XADES, "SigPolicyQualifier")?;
        spec.write(XADES_141, "SPDocSpecification", emit)?;
        emit.end()?;
    }
    for qualifier in qualifiers {
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
