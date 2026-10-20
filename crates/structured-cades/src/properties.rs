//! Original optional property values. Open credential/policy semantics stay
//! explicit obligations; reading an ASN.1 envelope never authenticates them.

use crate::{Error, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Oid, Reader, Tag, universal};
use structured_cms::{ErrorCode, Octets, attribute::Attribute, oid, signer::SignerInfo};
use structured_pkix::algorithm::{self, AlgorithmIdentifier};

/// Complete original value diagnostic. Processing refusals are never retained
/// here as malformed syntax: they terminate before a partial report escapes.
#[derive(Debug)]
pub struct Fault {
    /// Original attribute type whose value failed.
    pub attribute: Oid<'static>,
    /// Field used by the format's single schema reader.
    pub field: &'static str,
    /// Original shared/schema error, including its source coordinates.
    pub cause: Error,
}

/// Open-format original input requiring its actual format owner. This is not
/// an authenticated credential or a caller-writable positive baseline fact.
#[derive(Debug, Clone, Copy)]
pub struct OpenValue<'a> {
    /// Outer format service that owns this value.
    pub role: OpenRole,
    /// Original type, when the open schema carries an identifier.
    pub kind: Option<Oid<'a>>,
    /// Whole original open pair/attribute, including an absent OPTIONAL value.
    pub enclosure: Element<'a>,
    /// Original payload context, or explicit absence. The enclosing pair is
    /// never substituted for a missing open value.
    pub value: Option<crate::source::Value<'a>>,
}

/// Distinct services cannot substitute for each other during composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRole {
    /// Claimed (unauthenticated) signer attribute.
    Claimed,
    /// X.509 attribute certificate with its own authority/material requirements.
    AttributeCertificate,
    /// An independently specified non-X.509 attribute certificate.
    OtherAttributeCertificate,
    /// An independently authenticated assertion (including signed SAML).
    SignedAssertion,
    /// A commitment qualifier whose semantics its OID defines.
    CommitmentQualifier,
    /// A signature-policy qualifier whose semantics its OID defines.
    PolicyQualifier,
}

/// Original signature-policy identifier and declared document digest. The
/// signature-policy document's technical specification determines the hashing
/// input; an all-zero digest means UNKNOWN, never the empty document's digest.
pub struct Policy<'a> {
    /// Original signature policy OID.
    pub identifier: Oid<'a>,
    /// Original written digest mechanism and parameter provenance.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Original declared digest, including constructed BER fragments.
    pub hash: Octets<'a>,
    /// Normative zero-hash marker, independent of output width (§5.2.9.1).
    pub hash_unknown: bool,
}

/// Original policy store, without filesystem/network discovery or acquisition.
pub struct Store<'a> {
    /// Original technical specification choice (OID or `IA5String` URI).
    pub specification: Element<'a>,
    /// Original embedded document or explicit caller-resolved local URI.
    pub document: crate::source::Value<'a>,
}

/// One complete original signer's optional property reading. Unknown open
/// values stay visible, and a failing value does not hide later occurrences.
pub struct Properties<'a> {
    faults: OwnedVec<Fault>,
    open: OwnedVec<OpenValue<'a>>,
    policy: Option<Policy<'a>>,
    store: Option<Store<'a>>,
}

impl<'a> Properties<'a> {
    /// Read each recognized value under its original attribute reader. Existing
    /// CMS placement/cardinality and signed-DER checks remain the CMS kernel's
    /// responsibility; this adds the value schemas from EN319122-1 Annex D.
    pub fn read(signer: &SignerInfo<'a>, parent: &Reader<'a>) -> Result<Self> {
        signer.require_session(parent, "cades.properties")?;
        let work = parent.execution();
        let mut policy = None;
        let mut store = None;
        let mut faults = work.vector();
        let mut open = work.vector();
        for set in [signer.signed_attributes(), signer.unsigned_attributes()]
            .into_iter()
            .flatten()
        {
            for attribute in set.items() {
                // Fixed registered identifiers are at most twelve octets; a
                // different width is rejected by OID equality before scanning.
                parent
                    .charge(11 * (1 + attribute.kind().as_bytes().len().min(12) as u64))
                    .map_err(|cause| Error::encoding(cause, "cades.properties"))?;
                let Some((kind, field)) = known(attribute.kind()) else {
                    continue;
                };
                let reading = read_value(
                    attribute,
                    kind,
                    field,
                    parent,
                    &mut open,
                    &mut policy,
                    &mut store,
                );
                if let Err(cause) = reading {
                    if cause.is_terminal() {
                        return Err(cause);
                    }
                    let at = cause.offset();
                    faults
                        .try_push(Fault {
                            attribute: kind,
                            field,
                            cause,
                        })
                        .map_err(|cause| Error::resource(cause, field, at))?;
                }
            }
        }
        Ok(Self {
            faults: faults.into_owned(),
            open: open.into_owned(),
            policy,
            store,
        })
    }
    /// Every located value-schema failure, retaining its original cause.
    #[must_use]
    pub fn faults(&self) -> &[Fault] {
        &self.faults
    }
    /// All original open semantic inputs, not only successfully bound ones.
    #[must_use]
    pub fn open_values(&self) -> &[OpenValue<'a>] {
        &self.open
    }
    /// Parsed written policy; no hash comparison or policy acceptance implied.
    #[must_use]
    pub fn policy(&self) -> Option<&Policy<'a>> {
        self.policy.as_ref()
    }
    /// Parsed original store; no file or URI is accessed by reading it.
    #[must_use]
    pub fn store(&self) -> Option<&Store<'a>> {
        self.store.as_ref()
    }
}

fn known(kind: Oid<'_>) -> Option<(Oid<'static>, &'static str)> {
    for (expected, field) in [
        (oid::COMMITMENT_TYPE_INDICATION, "commitmentTypeIndication"),
        (oid::MIME_TYPE, "mimeType"),
        (oid::CONTENT_HINTS, "contentHints"),
        (oid::CONTENT_IDENTIFIER, "contentIdentifier"),
        (oid::CONTENT_REFERENCE, "contentReference"),
        (oid::SIGNER_LOCATION, "signerLocation"),
        (oid::SIGNER_ATTRIBUTES_V2, "signerAttributesV2"),
        (
            oid::SIGNATURE_POLICY_IDENTIFIER,
            "signaturePolicyIdentifier",
        ),
        (oid::SIGNATURE_POLICY_STORE, "signaturePolicyStore"),
        (oid::SIGNATURE_TIMESTAMP, "signatureTimeStamp"),
        (oid::COUNTERSIGNATURE, "countersignature"),
    ] {
        if kind == expected {
            return Some((expected, field));
        }
    }
    None
}

fn read_value<'a, W: Work>(
    attribute: &Attribute<'a>,
    kind: Oid<'static>,
    field: &'static str,
    parent: &Reader<'a>,
    open: &mut OwnedVec<OpenValue<'a>, W>,
    policy: &mut Option<Policy<'a>>,
    store: &mut Option<Store<'a>>,
) -> Result<()> {
    if kind == oid::COUNTERSIGNATURE {
        return if attribute.values().is_empty() {
            Err(syntax(field, attribute.span().start))
        } else {
            Ok(())
        };
    }
    if kind == oid::SIGNATURE_TIMESTAMP {
        // §5.3 fixes the WHOLE attribute to DER, independently of its envelope.
        // Reuse the shared DER walker, with the original header reread as DER.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
        let mut der = parent
            .reread(attribute.element(), structured_asn1::Encoding::Der)
            .map_err(|cause| Error::encoding(cause, field))?;
        let element = der
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|cause| Error::encoding(cause, field))?;
        return structured_pkix::der::conforms(&der, &element, field).map_err(Error::Pkix);
    }
    if attribute.values().len() != 1 {
        return Err(syntax(field, attribute.span().start));
    }
    let mut reader = attribute
        .value_reader_in(0, parent, field)?
        .ok_or_else(|| syntax(field, attribute.span().start))?;
    let value = reader
        .next_element()
        .map_err(|cause| Error::encoding(cause, field))?
        .ok_or_else(|| syntax(field, reader.offset()))?;
    if !reader.is_empty() {
        return Err(syntax(field, reader.offset()));
    }
    if kind == oid::MIME_TYPE {
        require_tag(&value, Tag::primitive(universal::UTF8_STRING), field)?;
        structured_pkix::der::conforms(&reader, &value, field).map_err(Error::Pkix)?;
        let mut mime = structured_cms::mime::Syntax::<false>::new();
        mime.feed(value.contents(), &reader.execution())
            .map_err(|cause| Error::resource(cause, field, value.span().start))?;
        return if mime.complete() {
            Ok(())
        } else {
            Err(syntax(field, value.span().start))
        };
    }
    if kind == oid::CONTENT_IDENTIFIER {
        Octets::read(&reader, &value, field)?;
        return Ok(());
    }
    let inside = sequence(&reader, &value, field)?;
    read_sequence(inside, kind, field, open, policy, store)
}

fn read_sequence<'a, W: Work>(
    mut inside: Reader<'a>,
    kind: Oid<'static>,
    field: &'static str,
    open: &mut OwnedVec<OpenValue<'a>, W>,
    policy: &mut Option<Policy<'a>>,
    store: &mut Option<Store<'a>>,
) -> Result<()> {
    if kind == oid::CONTENT_HINTS {
        let first = next(&mut inside, field)?;
        if first.tag() == Tag::primitive(universal::UTF8_STRING) {
            string(&inside, &first, field)?;
            inside
                .read_oid()
                .map_err(|cause| Error::encoding(cause, field))?;
        } else {
            inside
                .oid(&first)
                .map_err(|cause| Error::encoding(cause, field))?;
        }
    } else if kind == oid::CONTENT_REFERENCE {
        inside
            .read_oid()
            .map_err(|cause| Error::encoding(cause, field))?;
        for _ in 0..2 {
            let part = next(&mut inside, field)?;
            Octets::read(&inside, &part, field)?;
        }
    } else if kind == oid::COMMITMENT_TYPE_INDICATION {
        inside
            .read_oid()
            .map_err(|cause| Error::encoding(cause, field))?;
        if let Some(qualifiers) = inside
            .next_element()
            .map_err(|cause| Error::encoding(cause, field))?
        {
            let mut values = sequence(&inside, &qualifiers, field)?;
            if values.is_empty() {
                return Err(syntax(field, qualifiers.span().start));
            }
            while let Some(value) = values
                .next_element()
                .map_err(|cause| Error::encoding(cause, field))?
            {
                open_pair(&values, &value, OpenRole::CommitmentQualifier, field, open)?;
            }
        }
    } else if kind == oid::SIGNER_LOCATION {
        location(&mut inside, field)?;
    } else if kind == oid::SIGNER_ATTRIBUTES_V2 {
        attributes(&mut inside, field, open)?;
    } else if kind == oid::SIGNATURE_POLICY_IDENTIFIER {
        let identifier = inside
            .read_oid()
            .map_err(|cause| Error::encoding(cause, field))?;
        let hash_value = next(&mut inside, field)?;
        let mut hash_fields = sequence(&inside, &hash_value, field)?;
        let id = next(&mut hash_fields, field)?;
        let algorithm = algorithm::read(&hash_fields, &id, field).map_err(Error::Pkix)?;
        let hash_value = next(&mut hash_fields, field)?;
        let hash = Octets::read(&hash_fields, &hash_value, field)?;
        end(&hash_fields, field)?;
        let mut hash_unknown = true;
        for piece in hash.pieces() {
            inside
                .charge(1 + piece.as_bytes().len() as u64)
                .map_err(|cause| Error::encoding(cause, field))?;
            if piece.as_bytes().iter().any(|byte| *byte != 0) {
                hash_unknown = false;
            }
        }
        if let Some(qualifiers) = inside
            .next_element()
            .map_err(|cause| Error::encoding(cause, field))?
        {
            let mut values = sequence(&inside, &qualifiers, field)?;
            if values.is_empty() {
                return Err(syntax(field, qualifiers.span().start));
            }
            while let Some(value) = values
                .next_element()
                .map_err(|cause| Error::encoding(cause, field))?
            {
                open_pair(&values, &value, OpenRole::PolicyQualifier, field, open)?;
            }
        }
        *policy = Some(Policy {
            identifier,
            algorithm,
            hash,
            hash_unknown,
        });
    } else if kind == oid::SIGNATURE_POLICY_STORE {
        let specification = next(&mut inside, field)?;
        spec(&inside, &specification, field)?;
        let document = next(&mut inside, field)?;
        if document.tag().number() == Some(universal::OCTET_STRING) {
            Octets::read(&inside, &document, field)?;
        } else {
            Octets::read_ia5(&inside, &document, field)?;
        }
        *store = Some(Store {
            specification,
            document: crate::source::Value::of(&inside, document, field),
        });
    }
    end(&inside, field)
}

fn location(reader: &mut Reader<'_>, field: &'static str) -> Result<()> {
    // Annex D uses EXPLICIT TAGS, even though the containing CMS is BER.
    // At least one field and postalAddress SIZE(1..6) are format constraints.
    let mut previous = None;
    while let Some(value) = reader
        .next_element()
        .map_err(|cause| Error::encoding(cause, field))?
    {
        let Some(number) = value.tag().number() else {
            return Err(syntax(field, value.span().start));
        };
        if number > 2
            || value.tag() != Tag::context(true, number)
            || previous.is_some_and(|p| number <= p)
        {
            return Err(syntax(field, value.span().start));
        }
        previous = Some(number);
        let mut explicit = reader
            .enter(&value)
            .map_err(|cause| Error::encoding(cause, field))?;
        let part = next(&mut explicit, field)?;
        end(&explicit, field)?;
        if number < 2 {
            directory_string(&explicit, &part, field)?;
        } else {
            let mut lines = sequence(&explicit, &part, field)?;
            let mut count = 0;
            while let Some(line) = lines
                .next_element()
                .map_err(|cause| Error::encoding(cause, field))?
            {
                count += 1;
                if count > 6 {
                    return Err(syntax(field, line.span().start));
                }
                directory_string(&lines, &line, field)?;
            }
            if count == 0 {
                return Err(syntax(field, part.span().start));
            }
        }
    }
    if previous.is_none() {
        return Err(syntax(field, reader.offset()));
    }
    Ok(())
}

fn attributes<'a, W: Work>(
    reader: &mut Reader<'a>,
    field: &'static str,
    open: &mut OwnedVec<OpenValue<'a>, W>,
) -> Result<()> {
    let mut previous = None;
    while let Some(value) = reader
        .next_element()
        .map_err(|cause| Error::encoding(cause, field))?
    {
        let Some(number) = value.tag().number() else {
            return Err(syntax(field, value.span().start));
        };
        if number > 2
            || value.tag() != Tag::context(true, number)
            || previous.is_some_and(|p| number <= p)
        {
            return Err(syntax(field, value.span().start));
        }
        previous = Some(number);
        let mut explicit = reader
            .enter(&value)
            .map_err(|cause| Error::encoding(cause, field))?;
        let part = next(&mut explicit, field)?;
        end(&explicit, field)?;
        let mut entries = sequence(&explicit, &part, field)?;
        // §5.2.6.1 requires nonempty certified and assertion sequences.
        if number != 0 && entries.is_empty() {
            return Err(syntax(field, part.span().start));
        }
        while let Some(entry) = entries
            .next_element()
            .map_err(|cause| Error::encoding(cause, field))?
        {
            if number == 0 {
                let claimed = Attribute::read(&entries, &entry, field)?;
                push(
                    open,
                    OpenValue {
                        role: OpenRole::Claimed,
                        kind: Some(claimed.kind()),
                        enclosure: entry,
                        value: Some(crate::source::Value::of(&entries, entry, field)),
                    },
                    field,
                )?;
            } else if number == 1 {
                let choice = entry.tag();
                if choice != Tag::context(true, 0) && choice != Tag::context(true, 1) {
                    return Err(syntax(field, entry.span().start));
                }
                let mut explicit = entries
                    .enter(&entry)
                    .map_err(|cause| Error::encoding(cause, field))?;
                let certificate = next(&mut explicit, field)?;
                end(&explicit, field)?;
                if choice.number() == Some(0) {
                    require_tag(&certificate, Tag::constructed(universal::SEQUENCE), field)?;
                    push(
                        open,
                        OpenValue {
                            role: OpenRole::AttributeCertificate,
                            kind: None,
                            enclosure: certificate,
                            value: Some(crate::source::Value::of(&explicit, certificate, field)),
                        },
                        field,
                    )?;
                } else {
                    open_pair(
                        &explicit,
                        &certificate,
                        OpenRole::OtherAttributeCertificate,
                        field,
                        open,
                    )?;
                }
            } else {
                open_pair(&entries, &entry, OpenRole::SignedAssertion, field, open)?;
            }
        }
    }
    if previous.is_none() {
        return Err(syntax(field, reader.offset()));
    }
    Ok(())
}

fn open_pair<'a, W: Work>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    role: OpenRole,
    field: &'static str,
    open: &mut OwnedVec<OpenValue<'a>, W>,
) -> Result<()> {
    let mut pair = sequence(parent, element, field)?;
    let kind = pair
        .read_oid()
        .map_err(|cause| Error::encoding(cause, field))?;
    let value = pair
        .next_element()
        .map_err(|cause| Error::encoding(cause, field))?;
    end(&pair, field)?;
    if role == OpenRole::PolicyQualifier {
        let uri = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 5, 1]);
        let notice = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 5, 2]);
        let specification = Oid::from_bytes(&[4, 0, 0x81, 0x95, 0x32, 2, 1]);
        parent
            .charge(3 * (1 + kind.as_bytes().len() as u64))
            .map_err(|cause| Error::encoding(cause, field))?;
        if kind == uri || kind == notice || kind == specification {
            let part = value.ok_or_else(|| syntax(field, element.span().start))?;
            if kind == uri {
                uri_value(&pair, &part, field)?;
            } else if kind == specification {
                spec(&pair, &part, field)?;
            } else if !structured_pkix::policy::signature_notice_understood(&pair, &part)
                .map_err(Error::Pkix)?
            {
                return Err(syntax(field, part.span().start));
            }
        }
    }
    push(
        open,
        OpenValue {
            role,
            kind: Some(kind),
            enclosure: *element,
            value: value.map(|value| crate::source::Value::of(&pair, value, field)),
        },
        field,
    )
}

fn push<'a, W: Work>(
    out: &mut OwnedVec<OpenValue<'a>, W>,
    value: OpenValue<'a>,
    field: &'static str,
) -> Result<()> {
    let at = value.enclosure.span().start;
    out.try_push(value)
        .map_err(|cause| Error::resource(cause, field, at))
}

fn directory_string(parent: &Reader<'_>, value: &Element<'_>, field: &'static str) -> Result<()> {
    if ![12, 19, 20, 28, 30]
        .into_iter()
        .any(|number| value.tag() == Tag::primitive(number))
    {
        return Err(syntax(field, value.span().start));
    }
    string(parent, value, field)
}

fn string<'a>(parent: &Reader<'a>, value: &Element<'a>, field: &'static str) -> Result<()> {
    if value.contents().is_empty() {
        return Err(syntax(field, value.span().start));
    }
    structured_pkix::der::conforms(parent, value, field).map_err(Error::Pkix)
}

fn spec<'a>(parent: &Reader<'a>, value: &Element<'a>, field: &'static str) -> Result<()> {
    if value.tag() == Tag::primitive(universal::OID) {
        parent
            .oid(value)
            .map_err(|cause| Error::encoding(cause, field))?;
    } else {
        uri_value(parent, value, field)?;
    }
    Ok(())
}

fn uri_value<'a>(parent: &Reader<'a>, value: &Element<'a>, field: &'static str) -> Result<()> {
    let octets = Octets::read_ia5(parent, value, field)?;
    let work = parent.execution();
    let joined;
    let bytes = if let Some(one) = octets.as_one() {
        one
    } else {
        joined = octets.copy_in(parent, field, value.span().start)?;
        &joined
    };
    work.charge_work(1 + bytes.len() as u64)
        .map_err(|cause| Error::resource(cause, field, value.span().start))?;
    let text = core::str::from_utf8(bytes).map_err(|_| syntax(field, value.span().start))?;
    if !structured_pkix::general_name::uri_syntax(text, &work)
        .map_err(|cause| Error::resource(cause, field, value.span().start))?
    {
        return Err(syntax(field, value.span().start));
    }
    Ok(())
}

fn sequence<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    field: &'static str,
) -> Result<Reader<'a>> {
    require_tag(value, Tag::constructed(universal::SEQUENCE), field)?;
    parent
        .enter(value)
        .map_err(|cause| Error::encoding(cause, field))
}
fn next<'a>(reader: &mut Reader<'a>, field: &'static str) -> Result<Element<'a>> {
    reader
        .next_element()
        .map_err(|cause| Error::encoding(cause, field))?
        .ok_or_else(|| syntax(field, reader.offset()))
}
fn end(reader: &Reader<'_>, field: &'static str) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(syntax(field, reader.offset()))
    }
}
fn require_tag(value: &Element<'_>, tag: Tag, field: &'static str) -> Result<()> {
    if value.tag() == tag {
        Ok(())
    } else {
        Err(syntax(field, value.span().start))
    }
}
fn syntax(field: &'static str, at: u64) -> Error {
    Error::Syntax {
        code: ErrorCode::AttributeSyntax,
        field,
        at,
    }
}
