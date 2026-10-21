//! Original Attribute Certificate v2 structure (RFC5755 §4.1 / Appendix B).
//!
//! This reader supplies signature inputs and inspection facts, not a complete
//! RFC5755 profile or authorization verdict. In particular, issuer forms and
//! holder combinations outside §4.2's profile, negative/long serials, reversed
//! validity and unknown critical extensions remain inspectable. Holder binding,
//! algorithm agreement/acceptance, signature math, AA trust, targeting and
//! revocation require separate checks (§5). No public-key certificate is made
//! from an attribute certificate, and no opaque attribute is trusted here.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.1>

use crate::attribute::Attribute;
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, SortError, Work};
use structured_asn1::{
    BitString, Element, Integer, Oid, Parser, Reader, ScopedReader, Tag, universal,
};
use structured_pkix::general_name::{self, GeneralName};
use structured_pkix::signature::SignatureValue;
use structured_pkix::{AlgorithmIdentifier, Extensions, Time};

const FIELD: &str = "attributeCertificate";
const INFO: &str = "attributeCertificate.acinfo";

pub mod target;
fn sequence() -> Tag {
    Tag::constructed(universal::SEQUENCE)
}

/// Certificate identity, without looking up or authenticating a certificate.
#[derive(Debug)]
pub struct IssuerSerial<'a> {
    /// Original issuer names, nonempty but not restricted to directoryName here.
    pub issuer: OwnedVec<GeneralName<'a>>,
    /// Original serial, including a readable negative or unusually wide number.
    pub serial: Integer<'a>,
    /// Optional original unique identifier, including unused-bit information.
    pub issuer_uid: Option<BitString<'a>>,
}

/// Object selected by an explicitly written object-digest type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestedObject {
    /// A `SubjectPublicKeyInfo`, including effective parameters (§7.3).
    PublicKey,
    /// An entire public-key certificate (§7.3).
    PublicKeyCertificate,
    /// ASN.1's third alternative, forbidden by the RFC5755 profile.
    Other,
}

/// Written digest assertion. It neither hashes nor binds an object.
#[derive(Debug)]
pub struct ObjectDigestInfo<'a> {
    /// Object selected by the original ENUMERATED value.
    pub object_type: DigestedObject,
    /// Original optional type identifier; profile consistency is separate.
    pub other_type: Option<Oid<'a>>,
    /// Original digest algorithm with its parameter provenance.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Original digest bits; width and padding acceptance belong to the resolver.
    pub digest: BitString<'a>,
}

/// All independently written Holder alternatives, without choosing an identity.
/// RFC5755 §4.2.2 recommends only one; ASN.1 permits combinations and absence.
#[derive(Debug)]
pub struct Holder<'a> {
    /// `[0] IMPLICIT IssuerSerial`.
    pub base_certificate: Option<IssuerSerial<'a>>,
    /// `[1] IMPLICIT GeneralNames`.
    pub entity_names: Option<OwnedVec<GeneralName<'a>>>,
    /// `[2] IMPLICIT ObjectDigestInfo`.
    pub object_digest: Option<ObjectDigestInfo<'a>>,
}

/// Original issuer fields, without imposing the profile's issuerName-only restriction.
#[derive(Debug)]
pub struct Issuer<'a> {
    /// Which original ASN.1 CHOICE was written.
    pub form: IssuerForm,
    /// Original `GeneralNames`; always present for V1, optional for V2.
    pub names: Option<OwnedVec<GeneralName<'a>>>,
    /// Optional `[0] IMPLICIT IssuerSerial`, absent for V1.
    pub base_certificate: Option<IssuerSerial<'a>>,
    /// Optional `[1] IMPLICIT ObjectDigestInfo`, absent for V1.
    pub object_digest: Option<ObjectDigestInfo<'a>>,
}

/// The encoded issuer CHOICE. V1 remains inspectable, not profile-conforming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerForm {
    /// Legacy `GeneralNames`, excluded by RFC5755 §4.2.3's profile.
    V1,
    /// `[0] IMPLICIT V2Form`.
    V2,
}

/// Signed v2 information, retaining original attributes and extension readers.
#[derive(Debug)]
pub struct Information<'a> {
    /// All original holder alternatives.
    pub holder: Holder<'a>,
    /// Original issuer form; not an authenticated AA.
    pub issuer: Issuer<'a>,
    /// Signed algorithm identifier, without provider resolution.
    pub signature: AlgorithmIdentifier<'a>,
    /// Original serial number, not truncated to a machine integer.
    pub serial: Integer<'a>,
    /// Inclusive lower validity label; no implicit clock comparison is made.
    pub not_before: Time,
    /// Inclusive upper validity label; a reversed interval stays inspectable.
    pub not_after: Time,
    /// Original attributes in source order, with nonempty values and unique OIDs.
    pub attributes: OwnedVec<Attribute<'a>>,
    /// Optional original issuer unique identifier.
    pub issuer_uid: Option<BitString<'a>>,
    /// Optional generic catalogue. PKC extension recognition is not AC acceptance.
    pub extensions: Option<Extensions<'a>>,
}

/// A v2 attribute certificate's structure and exact original signature inputs.
#[derive(Debug)]
pub struct AttributeCertificate<'a> {
    parser: &'a Parser,
    information: Information<'a>,
    algorithm: AlgorithmIdentifier<'a>,
    signature: SignatureValue<'a>,
    signed: Element<'a>,
    element: Element<'a>,
}

impl<'a> AttributeCertificate<'a> {
    /// Reads a standalone universal SEQUENCE, with no trailing document bytes.
    /// The producing reader selects BER or DER; signing requires the original
    /// DER `acinfo`, which this entry checks regardless of the outer encoding.
    pub fn read(parent: &mut Reader<'a>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let value = Self::read_element(parent, &element)?;
        end(parent, FIELD)?;
        Ok(value)
    }

    /// Reads one original universal SEQUENCE in its producing context.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        tag(element, sequence(), FIELD)?;
        Self::fields(parent, element)
    }

    /// Reads CMS's `[2] IMPLICIT AttributeCertificateV2`, without retagging.
    /// Supply the original certificate-set member context, for example from
    /// [`crate::SignedData::certificate_choice_reader_in`].
    pub fn read_implicit(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        tag(element, Tag::context(true, 2), FIELD)?;
        Self::fields(parent, element)
    }

    fn fields(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = parent
            .enter(element)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let signed = required(&mut inside, INFO)?;
        tag(&signed, sequence(), INFO)?;
        // X.509 signatures use the DER encoding of acinfo (RFC5755 §4.1).
        // Rereading the original element checks its header too, with the same
        // depth and execution, rather than normalizing an untrusted encoding.
        let mut der = inside
            .reread(&signed, structured_asn1::Encoding::Der)
            .map_err(|e| Error::encoding(e, INFO))?;
        let signed_der = required(&mut der, INFO)?;
        let information = information(&der, &signed_der)?;
        let encoded_algorithm = required(&mut inside, "attributeCertificate.signatureAlgorithm")?;
        let algorithm = algorithm(
            &inside,
            &encoded_algorithm,
            "attributeCertificate.signatureAlgorithm",
        )?;
        let signature = SignatureValue::read(&mut inside, "attributeCertificate.signatureValue")
            .map_err(Error::pkix)?;
        end(&inside, FIELD)?;
        Ok(Self {
            parser: parent.parser(),
            information,
            algorithm,
            signature,
            signed,
            element: *element,
        })
    }

    /// Parsed signed fields. Their readability is not a profile/trust verdict.
    #[must_use]
    pub fn information(&self) -> &Information<'a> {
        &self.information
    }

    /// Decodes the optional original recipient-targeting extension under the
    /// current operation. `None` means no targeting restriction (RFC5755 §4.3.2);
    /// a present empty set is returned as such and matches no recipient.
    /// Readability alone does not authenticate the AC or its asserted targets.
    pub fn target_information<W: Work>(
        &self,
        work: &W,
    ) -> Result<Option<target::TargetInformation<'a>>> {
        let execution = work.execution_for(self.parser);
        execution
            .charge_work(1)
            .map_err(|e| Error::resource(e, target::FIELD, self.element.span().start))?;
        let Some(extensions) = &self.information.extensions else {
            return Ok(None);
        };
        extensions
            .get(target::IDENTIFIER, &execution)
            .map_err(Error::pkix)?
            .map(|extension| target::TargetInformation::read(extension, &execution))
            .transpose()
    }

    /// Exact whole original acinfo TLV, not a re-encoding of the parsed fields.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed.as_bytes()
    }

    /// Original source range of the signed information.
    #[must_use]
    pub fn signed_element(&self) -> Element<'a> {
        self.signed
    }

    /// Outer algorithm, to be checked against the signed algorithm by the provider.
    #[must_use]
    pub fn signature_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }

    /// Original signature bits and deferred payload context.
    #[must_use]
    pub fn signature_value(&self) -> SignatureValue<'a> {
        self.signature
    }

    /// Entire original certificate, retaining an IMPLICIT tag when present.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
}

fn information<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Information<'a>> {
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, INFO))?;
    let version = integer(&mut inside, "attributeCertificate.version")?;
    if version.as_u64() != Some(1) {
        return Err(Error::schema(
            ErrorCode::UnsupportedVersion,
            "attributeCertificate.version",
            element.contents_span().start,
        ));
    }
    let holder_element = required(&mut inside, "attributeCertificate.holder")?;
    tag(&holder_element, sequence(), "attributeCertificate.holder")?;
    let holder = holder(&inside, &holder_element)?;
    let issuer_element = required(&mut inside, "attributeCertificate.issuer")?;
    let issuer = match issuer_element.tag() {
        t if t == sequence() => Issuer {
            form: IssuerForm::V1,
            names: Some(names(
                &inside,
                &issuer_element,
                "attributeCertificate.issuer",
            )?),
            base_certificate: None,
            object_digest: None,
        },
        t if t == Tag::context(true, 0) => v2_form(&inside, &issuer_element)?,
        _ => {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                "attributeCertificate.issuer",
                issuer_element.span().start,
            ));
        }
    };
    let signature_element = required(&mut inside, "attributeCertificate.acinfo.signature")?;
    let signature = algorithm(
        &inside,
        &signature_element,
        "attributeCertificate.acinfo.signature",
    )?;
    let serial = integer(&mut inside, "attributeCertificate.serialNumber")?;
    let validity = required(&mut inside, "attributeCertificate.validity")?;
    tag(&validity, sequence(), "attributeCertificate.validity")?;
    let mut times = inside
        .enter(&validity)
        .map_err(|e| Error::encoding(e, "attributeCertificate.validity"))?;
    let not_before = time(&mut times, "attributeCertificate.notBeforeTime")?;
    let not_after = time(&mut times, "attributeCertificate.notAfterTime")?;
    end(&times, "attributeCertificate.validity")?;
    let attribute_element = required(&mut inside, "attributeCertificate.attributes")?;
    let attributes = attributes(&inside, &attribute_element)?;
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, INFO))?;
    let issuer_uid = optional_bits(
        &mut inside,
        &mut next,
        "attributeCertificate.issuerUniqueID",
    )?;
    let extensions = match next {
        Some(value) => {
            tag(&value, sequence(), "attributeCertificate.extensions")?;
            Some(
                Extensions::read_element(&inside, &value, "attributeCertificate.extensions")
                    .map_err(Error::pkix)?,
            )
        }
        None => None,
    };
    end(&inside, INFO)?;
    Ok(Information {
        holder,
        issuer,
        signature,
        serial,
        not_before,
        not_after,
        attributes,
        issuer_uid,
        extensions,
    })
}

fn holder<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Holder<'a>> {
    let field = "attributeCertificate.holder";
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, field))?;
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?;
    let base_certificate = optional(&mut inside, &mut next, Tag::context(true, 0), field)?
        .map(|e| issuer_serial(&inside, &e, field))
        .transpose()?;
    let entity_names = optional(&mut inside, &mut next, Tag::context(true, 1), field)?
        .map(|e| names(&inside, &e, field))
        .transpose()?;
    let object_digest = optional(&mut inside, &mut next, Tag::context(true, 2), field)?
        .map(|e| object_digest(&inside, &e, field))
        .transpose()?;
    no_pending(next, field)?;
    Ok(Holder {
        base_certificate,
        entity_names,
        object_digest,
    })
}

fn v2_form<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Issuer<'a>> {
    let field = "attributeCertificate.issuer";
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, field))?;
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?;
    let names = optional(&mut inside, &mut next, sequence(), field)?
        .map(|e| names(&inside, &e, field))
        .transpose()?;
    let base_certificate = optional(&mut inside, &mut next, Tag::context(true, 0), field)?
        .map(|e| issuer_serial(&inside, &e, field))
        .transpose()?;
    let object_digest = optional(&mut inside, &mut next, Tag::context(true, 1), field)?
        .map(|e| object_digest(&inside, &e, field))
        .transpose()?;
    no_pending(next, field)?;
    Ok(Issuer {
        form: IssuerForm::V2,
        names,
        base_certificate,
        object_digest,
    })
}

fn issuer_serial<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<IssuerSerial<'a>> {
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, field))?;
    let name_element = required(&mut inside, field)?;
    tag(&name_element, sequence(), field)?;
    let issuer = names(&inside, &name_element, field)?;
    let serial = integer(&mut inside, field)?;
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?;
    let issuer_uid = optional_bits(&mut inside, &mut next, field)?;
    no_pending(next, field)?;
    Ok(IssuerSerial {
        issuer,
        serial,
        issuer_uid,
    })
}

fn object_digest<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<ObjectDigestInfo<'a>> {
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, field))?;
    let object = required(&mut inside, field)?;
    tag(&object, Tag::primitive(10), field)?; // X.690 §8.4: ENUMERATED has INTEGER contents.
    let number = inside
        .integer(&object)
        .map_err(|e| Error::encoding(e, field))?;
    let object_type = match number.as_u64() {
        Some(0) => DigestedObject::PublicKey,
        Some(1) => DigestedObject::PublicKeyCertificate,
        Some(2) => DigestedObject::Other,
        _ => {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                field,
                object.span().start,
            ));
        }
    };
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?;
    let other_type = optional(
        &mut inside,
        &mut next,
        Tag::primitive(universal::OID),
        field,
    )?
    .map(|e| inside.oid(&e).map_err(|e| Error::encoding(e, field)))
    .transpose()?;
    let algorithm_element =
        next.ok_or_else(|| Error::schema(ErrorCode::MissingField, field, inside.offset()))?;
    let algorithm = algorithm(&inside, &algorithm_element, field)?;
    let digest_element = required(&mut inside, field)?;
    tag(
        &digest_element,
        Tag::primitive(universal::BIT_STRING),
        field,
    )?;
    let digest = inside
        .bit_string(&digest_element)
        .map_err(|e| Error::encoding(e, field))?;
    end(&inside, field)?;
    Ok(ObjectDigestInfo {
        object_type,
        other_type,
        algorithm,
        digest,
    })
}

fn names<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<OwnedVec<GeneralName<'a>>> {
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, field))?;
    let execution = parent.execution();
    let mut names = execution.vector();
    while let Some(value) = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?
    {
        names
            .try_reserve(1)
            .map_err(|e| Error::resource(e, field, value.span().start))?;
        names
            .try_push(general_name::read(&inside, &value, field).map_err(Error::pkix)?)
            .map_err(|e| Error::resource(e, field, value.span().start))?;
    }
    if names.is_empty() {
        return Err(Error::schema(
            ErrorCode::MissingField,
            field,
            element.contents_span().start,
        ));
    }
    Ok(names.into_owned())
}

fn attributes<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<OwnedVec<Attribute<'a>>> {
    const FIELD: &str = "attributeCertificate.attributes";
    tag(element, sequence(), FIELD)?;
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let execution = parent.execution();
    let mut attributes = execution.vector();
    let mut order = execution.vector();
    while let Some(value) = inside
        .next_element()
        .map_err(|e| Error::encoding(e, FIELD))?
    {
        attributes
            .try_reserve(1)
            .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
        let attribute = Attribute::read(&inside, &value, FIELD)?;
        if attribute.values().is_empty() {
            return Err(Error::schema(
                ErrorCode::AttributeCardinality,
                FIELD,
                value.span().start,
            ));
        }
        order
            .try_push((attribute.kind(), attribute.span().start))
            .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
        attributes
            .try_push(attribute)
            .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
    }
    if attributes.is_empty() {
        return Err(Error::schema(
            ErrorCode::EmptyAttributes,
            FIELD,
            element.span().start,
        ));
    }
    // RFC5755 §4.2.7 forbids duplicate types but permits multiple values.
    // Sort only a paid index: the original attribute order/bytes never change.
    let refusal = |e| Error::resource(e, FIELD, element.span().start);
    order
        .try_sort_unstable_by(|(left, _), (right, _)| {
            execution.charge_work(left.as_bytes().len().min(right.as_bytes().len()) as u64)?;
            Ok::<_, structured_asn1::memory::MemoryError>(left.as_bytes().cmp(right.as_bytes()))
        })
        .map_err(|e| match e {
            SortError::Resource(e) | SortError::Comparison(e) => refusal(e),
        })?;
    for pair in order.windows(2) {
        execution
            .charge_work(pair[0].0.as_bytes().len().min(pair[1].0.as_bytes().len()) as u64 + 1)
            .map_err(refusal)?;
        if pair[0].0 == pair[1].0 {
            return Err(Error::schema(
                ErrorCode::DuplicateAttribute,
                FIELD,
                pair[1].1,
            ));
        }
    }
    Ok(attributes.into_owned())
}

fn integer<'a>(parent: &mut ScopedReader<'a, '_>, field: &'static str) -> Result<Integer<'a>> {
    let value = parent
        .expect(Tag::primitive(universal::INTEGER))
        .map_err(|e| Error::encoding(e, field))?;
    parent
        .integer(&value)
        .map_err(|e| Error::encoding(e, field))
}

fn time(parent: &mut Reader<'_>, field: &'static str) -> Result<Time> {
    let value = parent
        .expect(Tag::primitive(universal::GENERALIZED_TIME))
        .map_err(|e| Error::encoding(e, field))?;
    Time::read(parent, &value, field).map_err(Error::pkix)
}

fn algorithm<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    structured_pkix::algorithm::read(parent, element, field).map_err(Error::pkix)
}

fn optional<'a>(
    parent: &mut ScopedReader<'a, '_>,
    next: &mut Option<Element<'a>>,
    expected: Tag,
    field: &'static str,
) -> Result<Option<Element<'a>>> {
    if next.as_ref().is_some_and(|e| e.tag() == expected) {
        let selected = next.take();
        *next = parent
            .next_element()
            .map_err(|e| Error::encoding(e, field))?;
        Ok(selected)
    } else {
        Ok(None)
    }
}

fn optional_bits<'a>(
    parent: &mut ScopedReader<'a, '_>,
    next: &mut Option<Element<'a>>,
    field: &'static str,
) -> Result<Option<BitString<'a>>> {
    optional(parent, next, Tag::primitive(universal::BIT_STRING), field)?
        .map(|e| parent.bit_string(&e).map_err(|e| Error::encoding(e, field)))
        .transpose()
}

fn no_pending(next: Option<Element<'_>>, field: &'static str) -> Result<()> {
    match next {
        Some(value) => Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            value.span().start,
        )),
        None => Ok(()),
    }
}

fn tag(element: &Element<'_>, expected: Tag, field: &'static str) -> Result<()> {
    if element.tag() == expected {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            element.span().start,
        ))
    }
}

fn end(parent: &ScopedReader<'_, '_>, field: &'static str) -> Result<()> {
    if parent.is_empty() {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            parent.offset(),
        ))
    }
}
