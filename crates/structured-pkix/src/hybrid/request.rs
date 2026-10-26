//! DER PKCS#10 with independent native and alternative proofs of possession.
//! Alternative attributes follow Bouncy Castle's single-valued convention;
//! RFC2986 defines the surrounding structure, not this hybrid extension profile.
//! <https://www.rfc-editor.org/rfc/rfc2986#section-4>

use super::components::{self, Component, Components};
use super::{
    ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE, AlternativeVerifier, CheckError, FIELD, Prepared,
    SUBJECT_ALT_PUBLIC_KEY_INFO, Signatures, alternative, preimage, required,
};
use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::Located;
use crate::path::{Verify, WorkingKey};
use crate::signature::SignatureValue;
use crate::{Error, ErrorCode, Name, PublicKeyInfo, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, Span, Tag, universal};

mod attributes;

/// Original attribute identity and complete encoding. Values remain borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'a> {
    kind: Oid<'a>,
    element: Element<'a>,
    values: Element<'a>,
}
impl<'a> Attribute<'a> {
    /// Attribute type from the original DER.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }
    /// Original complete Attribute TLV, not its enclosing IMPLICIT SET.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }
    /// Original SET OF values, whose DER and order have been checked.
    #[must_use]
    pub fn values(self) -> Element<'a> {
        self.values
    }
}

/// A request whose native signature and original attribute catalogue are readable.
/// Alternative faults/absence remain in `components`, without erasing native facts.
#[derive(Debug)]
pub struct Request<'a> {
    element: Element<'a>,
    cri: Element<'a>,
    attributes_element: Element<'a>,
    subject: Name<'a>,
    key: PublicKeyInfo<'a>,
    algorithm: AlgorithmIdentifier<'a>,
    signature: SignatureValue<'a>,
    attributes: OwnedVec<Attribute<'a>>,
    components: Components<'a>,
    parser: &'a Parser,
    depth: u32,
}
impl<'a> Request<'a> {
    /// Read a complete original DER request under the supplied parser limits.
    pub fn read(parser: &'a Parser, bytes: &'a [u8], base: u64) -> Result<Self> {
        let mut reader = parser.read(bytes, base).field(FIELD)?;
        let element = required(&mut reader, Tag::constructed(universal::SEQUENCE))?;
        components::end(&reader)?;
        Self::read_element(&reader, &element)
    }
    /// Read an embedded request, preserving its real source, depth and budget.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut strict = parent.reread(element, Encoding::Der).field(FIELD)?;
        let element = required(&mut strict, Tag::constructed(universal::SEQUENCE))?;
        crate::der::conforms(&strict, &element, FIELD)?;
        let mut inside = strict.enter(&element).field(FIELD)?;
        let cri = required(&mut inside, Tag::constructed(universal::SEQUENCE))?;
        let mut fields = inside.enter(&cri).field(FIELD)?;
        let version = required(&mut fields, Tag::primitive(universal::INTEGER))?;
        fields.charge(9).field(FIELD)?;
        if fields.integer(&version).field(FIELD)?.as_u64() != Some(0) {
            return Err(Error::new(
                ErrorCode::UnsupportedVersion,
                FIELD,
                version.span().start,
            ));
        }
        let name = required(&mut fields, Tag::constructed(universal::SEQUENCE))?;
        let subject = crate::name::read(&fields, &name, FIELD)?;
        let key = required(&mut fields, Tag::constructed(universal::SEQUENCE))?;
        let key = PublicKeyInfo::read_element(&fields, &key, FIELD)?;
        let attributes_element = required(&mut fields, Tag::context(true, 0))?;
        components::end(&fields)?;
        let (attributes, components) = attributes::read(&fields, &attributes_element)?;
        let identifier = required(&mut inside, Tag::constructed(universal::SEQUENCE))?;
        let algorithm = algorithm::read(&inside, &identifier, FIELD)?;
        let signature = SignatureValue::read(&mut inside, FIELD)?;
        components::end(&inside)?;
        Ok(Self {
            element,
            cri,
            attributes_element,
            subject,
            key,
            algorithm,
            signature,
            attributes,
            components,
            parser: inside.parser(),
            depth: inside.depth(),
        })
    }
    /// Original whole request location.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }
    /// Original complete request DER.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }
    /// Exact native proof input, including the alternative-value attribute.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.cri.as_bytes()
    }
    /// Original requested subject, without application identity policy.
    #[must_use]
    pub fn subject(&self) -> &Name<'a> {
        &self.subject
    }
    /// Original native key used for the native proof of possession.
    #[must_use]
    pub fn public_key(&self) -> PublicKeyInfo<'a> {
        self.key
    }
    /// All original attributes, with no product-specific allowlist or normalization.
    /// This raw catalogue borrow performs no traversal; callers fund their scans.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attributes
    }
    /// Independent alternative components, including located faults and absence.
    #[must_use]
    pub fn components(&self) -> &Components<'a> {
        &self.components
    }
    /// Strict preparation: all three single-valued attributes must be readable.
    pub fn prepare<W: Work>(&self, work: &W) -> Result<Prepared<'a>> {
        self.algorithm
            .query_in(work)
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, self.span().start))?;
        super::validate_key(self.components.key.require()?, work)?;
        let (algorithm, signature, remove) = self.components.signature_fields()?;
        let reader = work
            .read_scoped_source(
                self.parser,
                self.element.as_bytes(),
                self.element.span().start,
                Encoding::Der,
                self.depth - 1,
            )
            .field(FIELD)?;
        let preimage = preimage::request(&reader, self.cri, self.attributes_element, remove)?;
        Ok(Prepared {
            algorithm,
            signature,
            preimage,
        })
    }
    /// Evaluate both proofs independently; a two-key enrollment caller requires Both.
    pub fn check<W: Work, N: Verify<W>, A: AlternativeVerifier<W>>(
        &self,
        native: &N,
        verifier: &A,
        work: &W,
    ) -> core::result::Result<Signatures, CheckError<N::Error, A::Error>> {
        self.algorithm
            .query_in(work)
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, self.span().start))?;
        let native = native
            .verify(
                &self.algorithm,
                WorkingKey::standing(self.key),
                self.signed_bytes(),
                self.signature,
                work,
            )
            .map_err(CheckError::Native)?;
        let alternative = match self.components.key.require() {
            Ok(key) => alternative(self.prepare(work), key, verifier, work),
            Err(error) if super::terminal(&error) => return Err(CheckError::Processing(error)),
            Err(error) => {
                return Ok(Signatures {
                    native,
                    alternative: super::Alternative::Nonconforming(super::Fault::of(&error)),
                });
            }
        }
        .map_err(|e| match e {
            crate::error::CallbackError::Processing(e) => CheckError::Processing(e),
            crate::error::CallbackError::Callback(e) => CheckError::Alternative(e),
        })?;
        Ok(Signatures {
            native,
            alternative,
        })
    }
}
fn single<'a, 'q>(
    reader: &structured_asn1::ScopedReader<'a, 'q>,
    set: &Element<'a>,
) -> Result<(structured_asn1::ScopedReader<'a, 'q>, Element<'a>)> {
    let mut values = reader.enter(set).field(FIELD)?;
    let value = components::one(&mut values)?;
    Ok((values, value))
}
