//! `CAdES` `archive-time-stamp-v3` and its `ats-hash-index-v3` (ETSI EN 319 122-1
//! V1.3.1 §5.5).
//!
//! An `archive-time-stamp-v3` is an unsigned attribute of a signer whose value
//! is a time-stamp token. That token's own signer carries one
//! `ats-hash-index-v3`: the hashes of the root `SignedData` certificates,
//! revocation values and the signer's unsigned attribute values the
//! time-stamp protects. The token's message imprint covers the content type,
//! the content hash, the signer's signed fields and that index.
//!
//! [`token_reader`] yields the token of the attribute, [`HashIndex::of_token`]
//! reads its index, [`check_index`] matches the index entries against the
//! original elements, and [`imprint_input`] gives the ranges the token's
//! imprint is checked over. Which archive time-stamps a level requires, and
//! trust, stay with the caller.

use crate::attribute::Attribute;
use crate::digest::DigestError;
use crate::signed::{CertificateChoice, SignedData};
use crate::signer::{SignerInfo, required};
use crate::timestamp::Token;
use crate::{Error, ErrorCode, Result, oid};
use core::cmp::Ordering;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{OwnedVec, SortError, Work};
use structured_asn1::{Element, Encoding, Reader, Span, Tag, universal};
use structured_pkix::AlgorithmIdentifier;
use structured_pkix::algorithm::digest::{self as asn_digest, AsnDigest};

/// One `ATSHashIndexV3` value (EN 319 122-1 §5.5.2), in its original DER.
#[derive(Debug)]
pub struct HashIndex<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    certificates: OwnedVec<&'a [u8]>,
    revocations: OwnedVec<&'a [u8]>,
    attribute_values: OwnedVec<&'a [u8]>,
    element: Element<'a>,
}

impl<'a> HashIndex<'a> {
    /// Reads the single `ats-hash-index-v3` of an archive time-stamp token.
    ///
    /// EN 319 122-1 §5.5.3 requires exactly one such attribute in the token's
    /// unsigned attributes, and §5.5.2 exactly one value, with the whole
    /// attribute DER encoded.
    ///
    /// # Errors
    ///
    /// A missing or repeated attribute, a value count other than one, an
    /// attribute that is not DER, a value that is not an `ATSHashIndexV3`, a
    /// foreign reader, or a spent work ceiling.
    pub fn of_token(token: &Token<'a>, parent: &Reader<'a>) -> Result<Self> {
        const FIELD: &str = "archiveTimeStampV3.atsHashIndexV3";
        let signer = token.signer();
        // The token's parser funds the search below, not another session's.
        signer.require_session(parent, FIELD)?;
        let Some(unsigned) = signer.unsigned_attributes() else {
            return Err(Error::schema(
                ErrorCode::MissingField,
                FIELD,
                signer.span().start,
            ));
        };
        let attribute = unsigned
            .unique_in(oid::ATS_HASH_INDEX_V3, parent)?
            .ok_or_else(|| {
                Error::schema(
                    ErrorCode::MissingField,
                    FIELD,
                    unsigned.element().span().start,
                )
            })?;
        attribute.single(FIELD)?;
        // The value keeps its original nesting depth here, so its contents are
        // read under the depth ceiling that applies where they are written.
        let mut reader = attribute
            .value_reader_in(0, parent, FIELD)?
            .ok_or_else(|| Error::schema(ErrorCode::MissingField, FIELD, attribute.span().start))?;
        let value = required(&mut reader, FIELD)?;
        // §5.5.2 "The ats-hash-index-v3 attribute shall be DER encoded": the
        // Attribute SEQUENCE, attrType and attrValues SET headers are checked
        // here without descending into the value; `read` checks the value.
        let mut strict = parent
            .reread(attribute.element(), Encoding::Der)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let whole = strict
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let mut fields = strict
            .enter(&whole)
            .map_err(|error| Error::encoding(error, FIELD))?;
        fields
            .expect(Tag::primitive(universal::OID))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let set = fields
            .expect(Tag::constructed(universal::SET))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let mut values = fields
            .enter(&set)
            .map_err(|error| Error::encoding(error, FIELD))?;
        required(&mut values, FIELD)?;
        Self::read(&reader, &value)
    }
}

/// A reader over the one time-stamp token of an `archive-time-stamp-v3`
/// attribute, for [`Token::read_from`].
///
/// EN 319 122-1 §5.5.3 gives the attribute exactly one `AttributeValue`.
///
/// # Errors
///
/// An attribute of another type, a value count other than one, a foreign
/// reader, or a spent work ceiling.
pub fn token_reader<'q, 'a: 'q>(
    attribute: &Attribute<'a>,
    parent: &Reader<'q>,
) -> Result<Reader<'q>> {
    const FIELD: &str = "archiveTimeStampV3";
    if attribute.kind() != oid::ARCHIVE_TIMESTAMP_V3 {
        return Err(Error::schema(
            ErrorCode::AttributeSyntax,
            FIELD,
            attribute.span().start,
        ));
    }
    attribute.single(FIELD)?;
    attribute
        .value_reader_in(0, parent, FIELD)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, FIELD, attribute.span().start))
}

impl<'a> HashIndex<'a> {
    /// Reads one `ATSHashIndexV3` value, rereading it under DER (§5.5.2).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::Parser;
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// use structured_cms::archive::HashIndex;
    ///
    /// // SHA-256, one certificate hash, no revocation or attribute hashes.
    /// let mut index = vec![0x30, 53, 0x30, 11, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
    /// index.extend([0x30, 34, 4, 32]);
    /// index.extend([7; 32]);
    /// index.extend([0x30, 0, 0x30, 0]);
    /// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
    /// let mut reader = parser.read(&index, 0).unwrap();
    /// let value = reader.next_element().unwrap().unwrap();
    /// let read = HashIndex::read(&reader, &value).unwrap();
    /// assert_eq!(read.certificates(), &[&[7; 32][..]]);
    /// assert!(read.revocations().is_empty() && read.attribute_values().is_empty());
    /// assert_eq!(read.as_bytes(), index.as_slice());
    /// ```
    ///
    /// # Errors
    ///
    /// A value that is not DER, not the four-field sequence, or whose index
    /// entries are not OCTET STRINGs; a spent work ceiling.
    pub fn read(parent: &Reader<'a>, value: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "atsHashIndexV3";
        let mut strict = parent
            .reread(value, Encoding::Der)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let element = strict
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let mut inside = strict
            .enter(&element)
            .map_err(|error| Error::encoding(error, FIELD))?;
        // Annex D gives hashIndAlgorithm no DEFAULT: it is always written.
        let algorithm_element = required(&mut inside, "atsHashIndexV3.hashIndAlgorithm")?;
        let algorithm = structured_pkix::algorithm::read(
            &inside,
            &algorithm_element,
            "atsHashIndexV3.hashIndAlgorithm",
        )
        .map_err(Error::pkix)?;
        let certificates = hashes(&mut inside, "atsHashIndexV3.certificatesHashIndex")?;
        let revocations = hashes(&mut inside, "atsHashIndexV3.crlsHashIndex")?;
        let attribute_values = hashes(&mut inside, "atsHashIndexV3.unsignedAttrValuesHashIndex")?;
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
                inside.offset(),
            ));
        }
        Ok(Self {
            algorithm,
            certificates,
            revocations,
            attribute_values,
            element,
        })
    }

    /// The algorithm every index entry and the message imprint are hashed with.
    #[must_use]
    pub fn algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.algorithm
    }
    /// `certificatesHashIndex` entries, in their written order.
    #[must_use]
    pub fn certificates(&self) -> &[&'a [u8]] {
        &self.certificates
    }
    /// `crlsHashIndex` entries, in their written order.
    #[must_use]
    pub fn revocations(&self) -> &[&'a [u8]] {
        &self.revocations
    }
    /// `unsignedAttrValuesHashIndex` entries, in their written order.
    #[must_use]
    pub fn attribute_values(&self) -> &[&'a [u8]] {
        &self.attribute_values
    }
    /// The original `ATSHashIndexV3` encoding, the last part of the imprint input.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }
    /// The original range of the index value.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }
}

fn hashes<'a>(inside: &mut Reader<'a>, field: &'static str) -> Result<OwnedVec<&'a [u8]>> {
    let list = required(inside, field)?;
    if list.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            list.span().start,
        ));
    }
    let mut members = inside
        .enter(&list)
        .map_err(|error| Error::encoding(error, field))?;
    let mut entries = inside.execution().vector();
    while let Some(entry) = members
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
    {
        if entry.tag() != Tag::primitive(universal::OCTET_STRING) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                field,
                entry.span().start,
            ));
        }
        entries
            .try_push(entry.contents())
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
    }
    Ok(entries.into_owned())
}

/// Which list of the index an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexList {
    /// `certificatesHashIndex`.
    Certificates,
    /// `crlsHashIndex`.
    Revocations,
    /// `unsignedAttrValuesHashIndex`.
    AttributeValues,
}

/// An index entry that matches no original element, which makes the whole
/// `ats-hash-index-v3` invalid (EN 319 122-1 §5.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmatched {
    /// The list holding the entry.
    pub list: IndexList,
    /// The entry's position in that list.
    pub ordinal: usize,
}

/// One unsigned attribute value of the archived signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeValue {
    /// Position of the attribute in the signer's unsigned attributes.
    pub attribute: usize,
    /// Position of the value in that attribute's values.
    pub value: usize,
}

/// What an `ats-hash-index-v3` protects in the root `SignedData` and signer.
///
/// An element without an entry is not an error: it was added after the
/// time-stamp, or is not protected by it. Only an entry without an element
/// invalidates the index (§5.5.2).
#[derive(Debug)]
pub struct IndexCoverage {
    certificates: OwnedVec<bool>,
    revocations: OwnedVec<bool>,
    attribute_values: OwnedVec<(AttributeValue, bool)>,
    unmatched: OwnedVec<Unmatched>,
}

impl IndexCoverage {
    /// Every index entry matches an original element.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.unmatched.is_empty()
    }
    /// Entries that match no element, in list and written order.
    #[must_use]
    pub fn unmatched(&self) -> &[Unmatched] {
        &self.unmatched
    }
    /// Whether each certificate choice, in original order, has an entry.
    #[must_use]
    pub fn certificates(&self) -> &[bool] {
        &self.certificates
    }
    /// Whether each revocation choice, in original order, has an entry.
    #[must_use]
    pub fn revocations(&self) -> &[bool] {
        &self.revocations
    }
    /// Every unsigned attribute value of the signer, in original order, and
    /// whether it has an entry.
    #[must_use]
    pub fn attribute_values(&self) -> &[(AttributeValue, bool)] {
        &self.attribute_values
    }
}

/// Result of matching an index, or the provider's answer that it cannot hash
/// with the index algorithm.
pub type CoverageResult<E> = core::result::Result<Resolution<IndexCoverage>, DigestError<E>>;

/// Matches every entry of `index` against the original elements it may name.
///
/// Each certificate and revocation choice of the root `message` is hashed over
/// its whole original encoding, and each unsigned attribute value of `signer`
/// over its `attrType` encoding followed by the value's encoding (§5.5.2).
/// Nothing is re-encoded: an entry computed over another encoding of the same
/// value does not match, and an `OtherCertificateFormat`, which §5.5.2 has its
/// producer write in DER, is hashed as written. Only the root `SignedData`
/// fields count; an element carried elsewhere, such as in a revocation-values
/// attribute, names no entry. The index algorithm is resolved through
/// `provider`; an algorithm it does not know or that is malformed is answered
/// as such, before anything is hashed.
///
/// # Errors
///
/// A zero-sized provider, a message or index from another parser than
/// `parent`'s, a `signer` that is not one of `message`'s, a spent work ceiling,
/// a provider failure, or a provider output whose width contradicts its
/// identity.
pub fn check_index<'a, P: AsnDigest<'a>>(
    index: &HashIndex<'_>,
    message: &SignedData<'_>,
    signer: &SignerInfo<'_>,
    provider: &'a P,
    parent: &Reader<'_>,
) -> CoverageResult<P::Error> {
    let execution = parent.execution();
    let at = index.span().start;
    let field = "atsHashIndexV3";
    let refusal = |reason| DigestError::Processing(Error::resource(reason, field, at));
    admit(index, message, signer, provider, parent).map_err(DigestError::Processing)?;
    let identity = match asn_digest::resolve(provider, index.algorithm(), &execution)
        .map_err(|error| DigestError::Processing(Error::pkix(error)))?
    {
        Resolution::Supported(identity) => identity,
        Resolution::Unsupported => return Ok(Resolution::Unsupported),
        Resolution::Malformed => return Ok(Resolution::Malformed),
    };
    let hasher = Hasher {
        provider,
        identity: &identity,
        field,
        at,
    };

    let certificate_hashes = hasher.hash_each(
        message
            .certificate_choices()
            .iter()
            .map(|choice| match choice {
                CertificateChoice::X509(ordinal) => message.certificates()[*ordinal].as_bytes(),
                CertificateChoice::Extended(element)
                | CertificateChoice::AttributeV1(element)
                | CertificateChoice::AttributeV2(element)
                | CertificateChoice::Other(element) => element.as_bytes(),
            }),
        &execution,
    )?;
    let revocation_hashes = hasher.hash_each(
        message
            .revocations()
            .iter()
            .map(|revocation| revocation.as_bytes()),
        &execution,
    )?;

    let attributes = signer
        .unsigned_attributes()
        .map_or(&[][..], |set| set.items());
    let mut value_hashes = execution.vector();
    let mut values = execution.vector();
    for (attribute_ordinal, attribute) in attributes.iter().enumerate() {
        for (value_ordinal, value) in attribute.values().iter().enumerate() {
            value_hashes.try_reserve(1).map_err(refusal)?;
            values.try_reserve(1).map_err(refusal)?;
            let hash = hasher.hash(&[attribute.kind_encoding(), value.as_bytes()], &execution)?;
            value_hashes.try_push(hash).map_err(refusal)?;
            values
                .try_push((
                    AttributeValue {
                        attribute: attribute_ordinal,
                        value: value_ordinal,
                    },
                    false,
                ))
                .map_err(refusal)?;
        }
    }

    let mut unmatched = execution.vector();
    let certificates = mark(
        &hasher,
        &certificate_hashes,
        index.certificates(),
        IndexList::Certificates,
        &mut unmatched,
        &execution,
        refusal,
    )?;
    let revocations = mark(
        &hasher,
        &revocation_hashes,
        index.revocations(),
        IndexList::Revocations,
        &mut unmatched,
        &execution,
        refusal,
    )?;
    let covered = mark(
        &hasher,
        &value_hashes,
        index.attribute_values(),
        IndexList::AttributeValues,
        &mut unmatched,
        &execution,
        refusal,
    )?;
    for (entry, flag) in values.iter_mut().zip(covered.iter()) {
        entry.1 = *flag;
    }
    Ok(Resolution::Supported(IndexCoverage {
        certificates,
        revocations,
        attribute_values: values.into_owned(),
        unmatched: unmatched.into_owned(),
    }))
}

// Refuses before any work: a zero-sized provider has no instance identity,
// only the producing parser's ceilings may fund the hashes and comparisons,
// and the archived signer is one of the root message's own (§5.5.1).
fn admit<P>(
    index: &HashIndex<'_>,
    message: &SignedData<'_>,
    signer: &SignerInfo<'_>,
    provider: &P,
    parent: &Reader<'_>,
) -> Result<()> {
    const FIELD: &str = "atsHashIndexV3";
    let at = index.span().start;
    crate::provider::require_instance(provider, FIELD, at)?;
    message.require_session(parent, FIELD)?;
    message.require_signer(signer, FIELD)?;
    if !index.algorithm().same_session(parent) {
        return Err(Error::pkix(structured_pkix::Error::new(
            structured_pkix::ErrorCode::ForeignReader,
            FIELD,
            at,
        )));
    }
    Ok(())
}

struct Hasher<'p, 'a, P: Digest<'a>> {
    provider: &'a P,
    identity: &'p P::Identity,
    field: &'static str,
    at: u64,
}

impl<'a, P: Digest<'a>> Hasher<'_, 'a, P> {
    fn hash<W: Work>(
        &self,
        parts: &[&[u8]],
        execution: &W,
    ) -> core::result::Result<P::Output, DigestError<P::Error>> {
        execution.charge_work(1).map_err(|reason| {
            DigestError::Processing(Error::resource(reason, self.field, self.at))
        })?;
        let mut state = match self
            .provider
            .start(self.identity, execution)
            .map_err(DigestError::Callback)?
        {
            Resolution::Supported(state) => state,
            Resolution::Unsupported | Resolution::Malformed => {
                return Err(DigestError::Unstreamable);
            }
        };
        for part in parts {
            self.provider
                .update(&mut state, part, execution)
                .map_err(DigestError::Callback)?;
        }
        let output = self
            .provider
            .finish(state, execution)
            .map_err(DigestError::Callback)?;
        if let Some(expected) = self.provider.width(self.identity) {
            let actual = output.as_ref().len();
            if actual != expected {
                return Err(DigestError::OutputWidth { expected, actual });
            }
        }
        Ok(output)
    }

    // One hash per whole encoding, in order, with exact storage up front.
    fn hash_each<'e, W: Work>(
        &self,
        encodings: impl ExactSizeIterator<Item = &'e [u8]>,
        execution: &W,
    ) -> core::result::Result<OwnedVec<P::Output, W>, DigestError<P::Error>> {
        let refusal =
            |reason| DigestError::Processing(Error::resource(reason, self.field, self.at));
        let mut outputs = execution.vector();
        outputs
            .try_reserve_exact(encodings.len())
            .map_err(refusal)?;
        for encoding in encodings {
            outputs
                .try_push(self.hash(&[encoding], execution)?)
                .map_err(refusal)?;
        }
        Ok(outputs)
    }

    fn matches<W: Work>(
        &self,
        output: &P::Output,
        entry: &[u8],
        execution: &W,
    ) -> core::result::Result<bool, DigestError<P::Error>> {
        self.provider
            .matches(self.identity, output, entry, execution)
            .map_err(DigestError::Callback)
    }
}

// Sorts the element hashes once and finds, by binary search, the one hash each
// entry could equal; the provider's own comparison then judges that pair, so
// each entry costs one provider comparison and log n byte comparisons. Equal
// hashes name equal encodings and are all marked.
fn mark<'a, P: Digest<'a>>(
    digest: &Hasher<'_, 'a, P>,
    hashes: &[P::Output],
    entries: &[&[u8]],
    list: IndexList,
    unmatched: &mut OwnedVec<Unmatched, structured_asn1::memory::Execution<'_>>,
    execution: &impl Work,
    refusal: impl Fn(structured_asn1::memory::MemoryError) -> DigestError<P::Error> + Copy,
) -> core::result::Result<OwnedVec<bool>, DigestError<P::Error>> {
    let mut order = execution.vector();
    order.try_reserve_exact(hashes.len()).map_err(refusal)?;
    for ordinal in 0..hashes.len() {
        order.try_push(ordinal).map_err(refusal)?;
    }
    order
        .try_sort_unstable_by(|left, right| {
            compare(hashes[*left].as_ref(), hashes[*right].as_ref(), execution)
        })
        .map_err(|error| match error {
            SortError::Resource(reason) | SortError::Comparison(reason) => refusal(reason),
        })?;
    let mut covered = execution.vector();
    covered.try_reserve_exact(hashes.len()).map_err(refusal)?;
    for _ in 0..hashes.len() {
        covered.try_push(false).map_err(refusal)?;
    }
    for (ordinal, entry) in entries.iter().enumerate() {
        let first = lower_bound(&order, hashes, entry, execution).map_err(refusal)?;
        let matched = match order.get(first) {
            Some(&candidate) => digest.matches(&hashes[candidate], entry, execution)?,
            None => false,
        };
        if matched {
            let candidate = hashes[order[first]].as_ref();
            let mut position = first;
            while position < order.len()
                && compare(hashes[order[position]].as_ref(), candidate, execution)
                    .map_err(refusal)?
                    == Ordering::Equal
            {
                covered[order[position]] = true;
                position += 1;
            }
        } else {
            unmatched.try_reserve(1).map_err(refusal)?;
            unmatched
                .try_push(Unmatched { list, ordinal })
                .map_err(refusal)?;
        }
    }
    Ok(covered.into_owned())
}

fn lower_bound<O: AsRef<[u8]>>(
    order: &[usize],
    hashes: &[O],
    entry: &[u8],
    execution: &impl Work,
) -> core::result::Result<usize, structured_asn1::memory::MemoryError> {
    let mut from = 0;
    let mut to = order.len();
    while from < to {
        let middle = from + (to - from) / 2;
        if compare(hashes[order[middle]].as_ref(), entry, execution)? == Ordering::Less {
            from = middle + 1;
        } else {
            to = middle;
        }
    }
    Ok(from)
}

fn compare(
    left: &[u8],
    right: &[u8],
    execution: &impl Work,
) -> core::result::Result<Ordering, structured_asn1::memory::MemoryError> {
    execution.charge_work(left.len().min(right.len()) as u64 + 1)?;
    Ok(left.cmp(right))
}

/// The message-imprint input of an `archive-time-stamp-v3` (EN 319 122-1
/// §5.5.3), as original ranges in their required order: the content type
/// encoding, `content_hash`, the signer's `version` through `signature`
/// encodings, and the `ATSHashIndexV3` encoding.
///
/// `content_hash` is the hash of the signed content, computed as for the
/// `message-digest` attribute but with the time-stamp's imprint algorithm; for
/// detached content the caller supplies it. The returned ranges are a
/// [`crate::stream::Source`] for the token's
/// [`crate::timestamp::MessageImprint::check_content`].
///
/// # Errors
///
/// A `signer` that is not one of `message`'s own signers.
pub fn imprint_input<'s>(
    message: &SignedData<'s>,
    signer: &SignerInfo<'s>,
    index: &HashIndex<'s>,
    content_hash: &'s [u8],
) -> Result<[&'s [u8]; 4]> {
    message.require_signer(signer, "archiveTimeStampV3")?;
    Ok([
        message.content().kind_encoding(),
        content_hash,
        signer.signed_fields(),
        index.as_bytes(),
    ])
}

/// Whether the index algorithm is the time-stamp's imprint algorithm, as
/// §5.5.2 requires. Both are compared as resolved standard digests; an
/// algorithm either side does not name as one is answered as such.
///
/// # Errors
///
/// A spent work ceiling.
pub fn same_algorithm<W: Work>(
    index: &HashIndex<'_>,
    imprint: &AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Resolution<bool>> {
    let left = asn_digest::algorithm(index.algorithm(), execution).map_err(Error::pkix)?;
    let right = asn_digest::algorithm(imprint, execution).map_err(Error::pkix)?;
    Ok(match (left, right) {
        (Resolution::Supported(left), Resolution::Supported(right)) => {
            Resolution::Supported(left == right)
        }
        (Resolution::Malformed, _) | (_, Resolution::Malformed) => Resolution::Malformed,
        _ => Resolution::Unsupported,
    })
}
