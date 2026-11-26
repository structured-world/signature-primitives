//! Original DER inputs for the ETSI ASN.1 signature-policy digest.

use crate::{
    Error, ErrorCode, Result,
    binding::{self, BindError, DigestBinding},
    digest::{DigestError, DigestOutput, PassError, SingleDigest},
    stream::RangesError,
};
use structured_asn1::{
    Class, Element, Encoding, Oid, ScopedReader, Span, Tag, digest::Resolution, memory::Work,
    universal,
};
use structured_pkix::{
    AlgorithmIdentifier,
    algorithm::digest::{self, Algorithm, AsnDigest},
};

const FIELD: &str = "signaturePolicy";
const ALGORITHM: &str = "signaturePolicy.signPolicyHashAlg";
const INFO: &str = "signaturePolicy.signPolicyInfo";
const HASH: &str = "signaturePolicy.signPolicyHash";

/// A signature-policy digest envelope under ETSI TR 102 272 V1.1.1 §6.1.
///
/// This selects the policy identifier and original digest input. The policy's
/// application rules and the authority to select or trust it belong to the
/// caller. See <https://www.etsi.org/deliver/etsi_tr/102200_102299/102272/01.01.01_60/tr_102272v010101p.pdf>.
#[derive(Debug, Clone, Copy)]
pub struct Asn1Policy<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    identifier: Oid<'a>,
    covered: &'a [u8],
    stored: Option<Element<'a>>,
}

impl<'a> Asn1Policy<'a> {
    /// Read one complete digest envelope under the actual producing reader.
    /// Nested policy rules are kept as original DER for digesting. The DER
    /// rule also applies when an outer format accepts BER.
    pub fn read(parent: &mut ScopedReader<'a, '_>) -> Result<Self> {
        let root = sequence(parent, FIELD)?;
        end(parent, FIELD)?;
        if parent.encoding() == Encoding::Der {
            return Self::read_der(parent, &root);
        }
        let mut der = parent
            .reread(&root, Encoding::Der)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let root = sequence(&mut der, FIELD)?;
        Self::read_der(&der, &root)
    }

    fn read_der(parent: &ScopedReader<'a, '_>, root: &Element<'a>) -> Result<Self> {
        let mut inside = parent
            .enter(root)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let written = sequence(&mut inside, ALGORITHM)?;
        let algorithm =
            structured_pkix::algorithm::read(&inside, &written, ALGORITHM).map_err(Error::pkix)?;
        let info = sequence(&mut inside, INFO)?;
        let stored = if inside.is_empty() {
            None
        } else {
            Some(expect(
                &mut inside,
                Tag::primitive(universal::OCTET_STRING),
                HASH,
            )?)
        };
        end(&inside, FIELD)?;
        let identifier = policy_identifier(&inside, &info)?;
        structured_pkix::der::conforms(&inside, &info, INFO).map_err(Error::pkix)?;
        // Both protected TLVs are adjacent. The optional hash is the only
        // field outside their range after the enclosing header.
        let contents = root.contents();
        let end = contents.len() - stored.map_or(0, |value| value.as_bytes().len());
        Ok(Self {
            algorithm,
            identifier,
            covered: &contents[..end],
            stored,
        })
    }

    /// Original version OID from the policy information.
    #[must_use]
    pub fn identifier(self) -> Oid<'a> {
        self.identifier
    }

    /// Original hash algorithm, including the written parameters and offset.
    #[must_use]
    pub fn algorithm(self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }

    /// Contiguous original DER TLVs of the algorithm and policy information.
    /// The enclosing SEQUENCE header and optional stored hash are excluded.
    #[must_use]
    pub fn covered_bytes(self) -> &'a [u8] {
        self.covered
    }

    /// Optional original stored digest octets, including their source span.
    #[must_use]
    pub fn stored_digest(self) -> Option<(&'a [u8], Span)> {
        self.stored
            .map(|value| (value.contents(), value.contents_span()))
    }

    /// Compute the policy digest using the selected provider, after requiring
    /// agreement with the digest method selected by the enclosing signature.
    /// Check the optional stored digest from the same output and return that
    /// output without an additional hash, allocation or re-encoding.
    pub fn digest<'p, P: AsnDigest<'p>, W: Work>(
        &self,
        provider: &'p P,
        selected: Algorithm,
        work: &W,
    ) -> DigestResult<'p, P> {
        let scoped = self.algorithm.execution_origin().execution_in(work);
        let written = match digest::algorithm(&self.algorithm, &scoped)
            .map_err(|cause| PolicyDigestError::Processing(Error::pkix(cause)))?
        {
            Resolution::Supported(written) => written,
            Resolution::Unsupported => return Err(PolicyDigestError::Unsupported),
            Resolution::Malformed => {
                return Err(PolicyDigestError::Processing(Error::schema(
                    ErrorCode::AlgorithmSyntax,
                    ALGORITHM,
                    self.algorithm.offset(),
                )));
            }
        };
        if selected != written {
            return Err(PolicyDigestError::AlgorithmMismatch { selected, written });
        }
        let width = written.width();
        let stored = self.stored_digest();
        if let Some((expected, span)) = stored
            && expected.len() != width
        {
            return Err(PolicyDigestError::Processing(Error::schema(
                ErrorCode::DigestWidth,
                HASH,
                span.start,
            )));
        }
        let identity = provider
            .identity(written)
            .ok_or(PolicyDigestError::Unsupported)?;
        let pass = SingleDigest::prepare(
            provider,
            identity,
            &scoped,
            ALGORITHM,
            self.algorithm.offset(),
        )
        .map_err(PolicyDigestError::Prepare)?;
        let output = pass
            .run(&mut [self.covered], &scoped)
            .map_err(PolicyDigestError::Digest)?;
        let actual = output.as_bytes().len();
        if actual != width {
            return Err(PolicyDigestError::OutputWidth {
                expected: width,
                actual,
            });
        }
        if let Some((expected, span)) = stored {
            match binding::matches_digest(
                provider,
                output.finished(),
                expected,
                &scoped,
                HASH,
                span,
            )
            .map_err(PolicyDigestError::Bind)?
            {
                DigestBinding::Matches => {}
                DigestBinding::Differs => {
                    return Err(PolicyDigestError::StoredDigestMismatch(span));
                }
                DigestBinding::Malformed(cause) => {
                    return Err(PolicyDigestError::Processing(cause));
                }
            }
        }
        Ok(output)
    }
}

/// A computed policy digest with the selected provider's original output type.
pub type DigestResult<'p, P> = core::result::Result<
    DigestOutput<'p, P>,
    PolicyDigestError<<P as structured_asn1::digest::Digest<'p>>::Error>,
>;

/// Why computing or checking a policy digest could not succeed.
#[derive(Debug)]
#[non_exhaustive]
pub enum PolicyDigestError<E> {
    /// Original schema or resource refusal.
    Processing(Error),
    /// The written algorithm or its selected provider is unavailable.
    Unsupported,
    /// The enclosing signature and the policy document use different digests.
    AlgorithmMismatch {
        /// Method selected by the enclosing signature.
        selected: Algorithm,
        /// Method written in the policy document.
        written: Algorithm,
    },
    /// The optional stored digest differs from the recomputed output.
    StoredDigestMismatch(Span),
    /// Digest preparation refusal.
    Prepare(DigestError<E>),
    /// The provider output does not have the width of the written method.
    OutputWidth {
        /// Width required by the method.
        expected: usize,
        /// Width returned by the provider.
        actual: usize,
    },
    /// Original callback, source or processing error while hashing.
    Digest(PassError<RangesError, E>),
    /// Original error during comparison with the stored digest.
    Bind(BindError<E>),
}

fn policy_identifier<'a>(parent: &ScopedReader<'a, '_>, info: &Element<'a>) -> Result<Oid<'a>> {
    let mut fields = parent
        .enter(info)
        .map_err(|cause| Error::encoding(cause, INFO))?;
    let identifier = fields
        .read_oid()
        .map_err(|cause| Error::encoding(cause, INFO))?;
    expect(
        &mut fields,
        Tag::primitive(universal::GENERALIZED_TIME),
        INFO,
    )?;
    sequence(&mut fields, INFO)?;
    // DirectoryString alternatives of the X.509 type selected by §6.1.
    let application = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, INFO))?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, INFO, info.span().end()))?;
    let tag = application.tag();
    if tag.class() != Class::Universal
        || tag.is_constructed()
        || !matches!(
            tag.number(),
            Some(universal::UTF8_STRING | universal::PRINTABLE_STRING | 20 | 28 | 30)
        )
    {
        return Err(Error::schema(
            ErrorCode::UnexpectedTag,
            INFO,
            application.span().start,
        ));
    }
    sequence(&mut fields, INFO)?;
    if !fields.is_empty() {
        sequence(&mut fields, INFO)?;
    }
    end(&fields, INFO)?;
    Ok(identifier)
}

fn expect<'a>(
    reader: &mut ScopedReader<'a, '_>,
    tag: Tag,
    field: &'static str,
) -> Result<Element<'a>> {
    reader
        .expect(tag)
        .map_err(|cause| Error::encoding(cause, field))
}

fn sequence<'a>(reader: &mut ScopedReader<'a, '_>, field: &'static str) -> Result<Element<'a>> {
    expect(reader, Tag::constructed(universal::SEQUENCE), field)
}

fn end(reader: &ScopedReader<'_, '_>, field: &'static str) -> Result<()> {
    if !reader.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            reader.offset(),
        ));
    }
    Ok(())
}
