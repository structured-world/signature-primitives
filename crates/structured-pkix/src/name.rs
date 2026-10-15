//! Distinguished names, kept as they were encoded.
//!
//! A name has two jobs here and they pull in opposite directions. One is
//! identity: an issuer name in one certificate has to be recognized as the
//! subject name of another, or no path is ever built. The other is
//! explanation: somebody has to read who this is.
//!
//! They are kept apart. Identity is the bytes, and the comparison below is the
//! profile's rule over the encoded values. Explanation is [`Attribute::text`],
//! which decodes for a person to read and is never what two names are compared
//! on. A parser that folded the two would let a name that renders identically
//! stand in for the one it imitates.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::oid;
#[cfg(test)]
use alloc::vec::Vec;
use structured_asn1::memory::{Memory, OwnedString, OwnedVec, Work};
use structured_asn1::{Class, Element, Oid, Reader, Tag, universal};
use unicode_bidi::BidiClass;

mod fold;
mod normalize;
mod prepared;
mod render;
pub(crate) mod segments;
mod selector;
pub use selector::Selector;
pub(crate) use selector::attribute_type_syntax_fits;
pub(crate) use selector::syntax_fits as dn_syntax_fits;
mod unassigned;

/// A distinguished name, as the sequence of parts the certificate holds.
#[derive(Debug)]
pub struct Name<'a> {
    der: &'a [u8],
    parts: OwnedVec<RelativeName<'a>>,
    offset: u64,
    field: &'static str,
}

/// One part of a name: usually one attribute, occasionally several that are
/// unordered among themselves.
#[derive(Debug)]
pub struct RelativeName<'a> {
    attributes: OwnedVec<Attribute<'a>>,
}

/// One attribute of a name: what kind of thing it is, and the value.
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'a> {
    kind: Oid<'a>,
    value: AttributeValue<'a>,
}

/// The value of an attribute, as it was encoded.
#[derive(Debug, Clone, Copy)]
pub struct AttributeValue<'a> {
    tag: Tag,
    contents: &'a [u8],
    der: &'a [u8],
    offset: u64,
    // Original container depth for deferred constructed-string preparation.
    depth: u32,
}

/// Which string encoding a value was written in, where it is a string at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Encoding {
    /// `UTF8String`.
    Utf8,
    /// `PrintableString`, a restricted set of ASCII.
    Printable,
    /// `IA5String`, ASCII.
    Ia5,
    /// `VisibleString`, printable ASCII.
    Visible,
    /// `NumericString`, digits and spaces.
    Numeric,
    /// `TeletexString`, from before the others, and read here as an
    /// approximation.
    Teletex,
    /// `BMPString`, sixteen bits a character.
    Bmp,
    /// `UniversalString`, thirty-two bits a character.
    Universal,
    /// Not a string type this crate reads as text.
    Other,
}

impl<'a> Name<'a> {
    /// The name exactly as it was encoded, which is what identity is.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.der
    }

    /// The parts, outermost first, as the certificate wrote them.
    #[must_use]
    pub fn parts(&self) -> &[RelativeName<'a>] {
        &self.parts
    }

    /// Whether the name has no parts at all, which a certificate is allowed to
    /// do when the subject is named somewhere else instead.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Copies descriptors into the current domain; document bytes remain borrowed.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded copying or allocation.
    pub fn try_copy(&self, execution: &Memory) -> Result<Self> {
        let mut parts = execution.vector();
        for part in &self.parts {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, self.field, self.offset))?;
            parts
                .try_push(part.try_copy(execution)?)
                .map_err(|reason| Error::resource(reason, self.field, self.offset))?;
        }
        Ok(Self {
            der: self.der,
            parts,
            offset: self.offset,
            field: self.field,
        })
    }

    /// Every attribute, in the order the name holds them.
    /// The caller admits its own traversal of this borrowed view.
    pub fn attributes(&self) -> impl Iterator<Item = &Attribute<'a>> {
        self.parts.iter().flat_map(RelativeName::attributes)
    }

    /// The attributes of one kind, in order. Several is not an error: a name
    /// can carry more than one organizational unit, and which one matters is
    /// not this layer's decision.
    /// Each search step is admitted in the current execution domain. A refusal
    /// is yielded once, after which repeated `next()` calls do no further work.
    /// Returned references borrow the name, independently of the budget borrow.
    pub fn attributes_of<'n, 'q, W: structured_asn1::memory::Work>(
        &'n self,
        kind: Oid<'q>,
        execution: &'q W,
    ) -> impl Iterator<Item = Result<&'n Attribute<'a>>> + 'q
    where
        'n: 'q,
    {
        let mut attributes = self.attributes();
        let mut failed = false;
        core::iter::from_fn(move || {
            if failed {
                return None;
            }
            for attribute in attributes.by_ref() {
                let work = 1 + attribute.kind.as_bytes().len().max(kind.as_bytes().len()) as u64;
                if let Err(reason) = execution.charge_work(work) {
                    failed = true;
                    return Some(Err(self.resource(reason)));
                }
                if attribute.kind == kind {
                    return Some(Ok(attribute));
                }
            }
            None
        })
    }

    /// The first attribute of one kind.
    pub fn attribute<W: structured_asn1::memory::Work>(
        &self,
        kind: Oid<'_>,
        execution: &W,
    ) -> Result<Option<&Attribute<'a>>> {
        self.attributes_of(kind, execution).next().transpose()
    }

    /// The common name, which describes the subject and does not identify it.
    pub fn common_name<W: structured_asn1::memory::Work>(
        &self,
        execution: &W,
    ) -> Result<Option<&Attribute<'a>>> {
        self.attribute(oid::COMMON_NAME, execution)
    }

    /// The organization identifier, which is how a legal entity is identified
    /// rather than described, and is the attribute an attribution decision may
    /// rest on where the common name is not.
    pub fn organization_identifier<W: structured_asn1::memory::Work>(
        &self,
        execution: &W,
    ) -> Result<Option<&Attribute<'a>>> {
        self.attribute(oid::ORGANIZATION_IDENTIFIER, execution)
    }

    /// Whether two names are the same name, by the profile's rule: the same
    /// parts in the same order, each holding the same attributes, with strings
    /// compared under their declared equality rule.
    ///
    /// Directory strings are compared after the preparation the profile requires
    /// (RFC 5280 7.1, over RFC 4518): the characters that carry no meaning
    /// are dropped, case is folded in full, the value is normalized to form
    /// KC, and runs of space count as one between words and none at the
    /// edges. Unsupported types and nonconforming stored values retain their
    /// encoded identity; that preservation does not validate an LDAP assertion.
    /// Valid supported values use the schema's size bounds and the current
    /// work/storage budget, independently of display truncation.
    /// IA5 emailAddress and domainComponent values instead use their exact
    /// ASCII case-insensitive rules without whitespace compression; the DN
    /// emailAddress rule covers the whole value, unlike rfc822Name mailboxes.
    /// Pseudonym uses caseExactMatch (RFC2985 §5.2.9): the same preparation
    /// and insignificant-space handling, with case preserved.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded comparison work.
    pub fn matches<W: structured_asn1::memory::Work>(
        &self,
        other: &Name<'_>,
        execution: &W,
    ) -> Result<bool> {
        self.matches_with(other, execution, None)
    }

    /// Compares retained names under the current query reader's execution.
    ///
    /// Names may come from independently parsed certificates. Their storage
    /// stays on its original account; normalization/comparison scratch and
    /// deferred string decoding use the query's local and aggregate ceilings.
    /// This is a comparison, not permission to reparse a foreign certificate.
    pub fn matches_in(&self, other: &Name<'_>, parent: &Reader<'_>) -> Result<bool> {
        self.matches_with(other, &parent.execution(), Some(parent))
    }

    pub(crate) fn matches_with<W: structured_asn1::memory::Work>(
        &self,
        other: &Name<'_>,
        execution: &W,
        parent: Option<&Reader<'_>>,
    ) -> Result<bool> {
        if self.parts.len() != other.parts.len() {
            return Ok(false);
        }
        // Identical original encodings have the same retained wire identity.
        // This fast path does not validate a nonconforming stored value.
        if self.der.len() == other.der.len() {
            execution
                .charge_work(self.der.len() as u64)
                .map_err(|reason| self.resource(reason))?;
            if self.der == other.der {
                return Ok(true);
            }
        }
        Ok(self.order_with(other, execution, parent)? == core::cmp::Ordering::Equal)
    }

    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn field(&self) -> &'static str {
        self.field
    }

    pub(crate) fn resource(&self, reason: structured_asn1::memory::MemoryError) -> Error {
        Error::resource(reason, self.field, self.offset)
    }

    /// A total order over names that calls two of them equal exactly when
    /// [`Name::matches`] does.
    ///
    /// It exists so that a set of names can be searched rather than walked. A
    /// caller holding many certificates and asking which one a name belongs to
    /// otherwise compares against every one of them, and comparing names is
    /// where the profile's folding lives; ordering them once turns that into a
    /// search. Answering the same question two ways is only safe because this
    /// is the same comparison: it is built from the ordering the multiset
    /// matching already uses, not from a second reading of what identity is.
    ///
    /// Preparation and comparison use the current execution domain. Unicode
    /// scratch storage is released when this comparison returns.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded preparation or comparison.
    pub fn order<W: structured_asn1::memory::Work>(
        &self,
        other: &Name<'_>,
        execution: &W,
    ) -> Result<core::cmp::Ordering> {
        self.order_with(other, execution, None)
    }

    fn order_with<W: structured_asn1::memory::Work>(
        &self,
        other: &Name<'_>,
        execution: &W,
        parent: Option<&Reader<'_>>,
    ) -> Result<core::cmp::Ordering> {
        let order = self.parts.len().cmp(&other.parts.len());
        if order != core::cmp::Ordering::Equal {
            return Ok(order);
        }
        // Stop at the first distinguishing RDN: unrelated tail values must
        // not pay for normalization or scratch storage that cannot affect order.
        for (left, right) in self.parts.iter().zip(&other.parts) {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, self.field, self.offset))?;
            let order = prepared::compare_parts_in(left, right, execution, parent)?;
            if order != core::cmp::Ordering::Equal {
                return Ok(order);
            }
        }
        Ok(core::cmp::Ordering::Equal)
    }

    /// Prepares this name once for repeated comparisons.
    ///
    /// Encoded values remain borrowed. Sorted descriptors and any Unicode
    /// canonical text retain their storage charge until this result is dropped.
    /// Comparisons subsequently use the execution domain passed to them.
    ///
    /// # Errors
    /// Returns a located resource error if preparation cannot be financed.
    pub fn ordered<W: structured_asn1::memory::Work>(
        &self,
        execution: &W,
    ) -> Result<Ordered<'a, W>> {
        Ok(Ordered {
            prepared: prepared::PreparedName::of(&self.parts, execution)?,
            offset: self.offset,
        })
    }

    /// Prepares a cache inside the current producing operation's work ceilings.
    ///
    /// Original document values and their retained nesting depths remain intact.
    /// Deferred BER strings use the supplied reader's session/account instead
    /// of a new Parser. Cache storage retains its current account; its work
    /// owner borrows the operation independently of the document's lifetime.
    /// This is the same semantic order as [`Name::ordered`], with scoped funding.
    pub fn ordered_in<'p>(
        &self,
        parent: &'p Reader<'_>,
    ) -> Result<Ordered<'a, structured_asn1::memory::Execution<'p>>> {
        Ok(Ordered {
            prepared: prepared::PreparedName::of_in(
                &self.parts,
                &parent.execution(),
                Some(parent),
            )?,
            offset: self.offset,
        })
    }

    /// Whether this name sits below another one: the parts of the other, in
    /// order, from the top down, and anything at all after them.
    ///
    /// This is the containment a name-constraint subtree asks about, where
    /// the base "specifies a subtree of the X.500 directory tree" and a name
    /// is within it when it begins with the base (RFC 5280 4.2.1.10). A base
    /// of no parts is the root of the tree and holds every name. Parts are
    /// compared by the rule identity uses, so a name sits below itself.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded prefix preparation.
    pub fn starts_with<W: structured_asn1::memory::Work>(
        &self,
        base: &Name<'_>,
        execution: &W,
    ) -> Result<bool> {
        if base.parts.len() > self.parts.len() {
            return Ok(false);
        }
        for (left, right) in self.parts.iter().zip(&base.parts) {
            execution
                .charge_work(1)
                .map_err(|reason| self.resource(reason))?;
            let order = prepared::compare_parts(left, right, execution)?;
            if order != core::cmp::Ordering::Equal {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A prepared name with independently accounted descriptors and canonical text.
///
/// Encoded values borrow the source document. Storage charges survive the
/// parser; every comparison is paid by its explicit current execution domain.
#[derive(Debug)]
pub struct Ordered<'a, W: structured_asn1::memory::Work = Memory> {
    prepared: prepared::PreparedName<'a, W>,
    offset: u64,
}

impl<W: structured_asn1::memory::Work> Ordered<'_, W> {
    /// The same order [`Name::order`] gives, using already prepared values.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded comparison work.
    pub fn order<V: structured_asn1::memory::Work, E: structured_asn1::memory::Work>(
        &self,
        other: &Ordered<'_, V>,
        execution: &E,
    ) -> Result<core::cmp::Ordering> {
        self.prepared
            .order(&other.prepared, execution)
            .map_err(|reason| Error::resource(reason, "name", self.offset))
    }
}

/// Match virtual names without inventing an encoding for the appended RDN.
/// CRL distribution names append relative fragments to their own issuer bases.
/// The existing prepared-part core owns all attribute and SET semantics.
pub(crate) fn matches_composed<const ENCODED: bool>(
    left: &Name<'_>,
    left_suffix: Option<&RelativeName<'_>>,
    right: &Name<'_>,
    right_suffix: Option<&RelativeName<'_>>,
    execution: &impl structured_asn1::memory::Work,
) -> Result<bool> {
    if left_suffix.is_none() && right_suffix.is_none() {
        if ENCODED {
            return encoded_bytes_match(left.der, right.der, left, execution);
        }
        return left.matches(right, execution);
    }
    if ENCODED && let (Some(left_part), Some(right_part)) = (left_suffix, right_suffix) {
        // The original DP fields encode the relative RDN, not their issuer
        // bases. RFC5280 §5.2.5 fixes that RDN encoding; §6.3.3(b)(1) retains
        // ordinary issuer-name equality for the separately encoded bases.
        if !left.matches(right, execution)? {
            return Ok(false);
        }
        return encoded_parts_match(left_part, right_part, left, execution);
    }
    let left_len = left
        .parts
        .len()
        .checked_add(usize::from(left_suffix.is_some()))
        .ok_or_else(|| left.resource(structured_asn1::memory::MemoryError::WorkExceeded))?;
    let right_len = right
        .parts
        .len()
        .checked_add(usize::from(right_suffix.is_some()))
        .ok_or_else(|| right.resource(structured_asn1::memory::MemoryError::WorkExceeded))?;
    if left_len != right_len {
        return Ok(false);
    }
    for index in 0..left_len {
        execution
            .charge_work(1)
            .map_err(|reason| left.resource(reason))?;
        let left_part = if index < left.parts.len() {
            &left.parts[index]
        } else {
            left_suffix.expect("suffix was counted")
        };
        let right_part = if index < right.parts.len() {
            &right.parts[index]
        } else {
            right_suffix.expect("suffix was counted")
        };
        let matches = if ENCODED {
            encoded_parts_match(left_part, right_part, left, execution)?
        } else {
            prepared::compare_parts(left_part, right_part, execution)? == core::cmp::Ordering::Equal
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

fn encoded_bytes_match(
    left: &[u8],
    right: &[u8],
    source: &Name<'_>,
    execution: &impl structured_asn1::memory::Work,
) -> Result<bool> {
    let work = u64::try_from(left.len().max(right.len()))
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| source.resource(structured_asn1::memory::MemoryError::WorkExceeded))?;
    execution
        .charge_work(work)
        .map_err(|reason| source.resource(reason))?;
    Ok(left == right)
}

fn encoded_parts_match(
    left: &RelativeName<'_>,
    right: &RelativeName<'_>,
    source: &Name<'_>,
    execution: &impl structured_asn1::memory::Work,
) -> Result<bool> {
    if left.attributes.len() != right.attributes.len() {
        return Ok(false);
    }
    // Original DER SET order and canonical tag/length encoding make exact OID
    // plus complete value TLVs sufficient for exact RDN encoding, without an
    // encode/reparse bridge. No attribute preparation or reordering occurs.
    for (left, right) in left.attributes.iter().zip(right.attributes.iter()) {
        execution
            .charge_work(1)
            .map_err(|reason| source.resource(reason))?;
        if !encoded_bytes_match(
            left.kind.as_bytes(),
            right.kind.as_bytes(),
            source,
            execution,
        )? || !encoded_bytes_match(left.value.der, right.value.der, source, execution)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

impl<'a> RelativeName<'a> {
    /// The attributes of this part.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attributes
    }

    /// Copies borrowed descriptors into independently accounted storage.
    ///
    /// # Errors
    /// Returns a located resource error before unfunded copying or allocation.
    pub fn try_copy(&self, execution: &Memory) -> Result<Self> {
        let mut attributes = execution.vector();
        attributes
            .try_extend_from_slice(&self.attributes)
            .map_err(|reason| {
                Error::resource(reason, "name.relative", self.attributes[0].value.offset)
            })?;
        Ok(Self { attributes })
    }

    /// Whether two parts hold the same attributes. They are a set, so order
    /// within a part is not part of what they say, and the correspondence is
    /// one to one: a part written with a duplicate does not match a part
    /// without one.
    ///
    /// Both sides are ordered by a total order that agrees with attribute
    /// equality, then compared in step. Ordering is streamed: nothing is
    /// materialized, so a part holding a value the element limit permits, up
    /// to four gibibytes, costs a list of references and not a copy of the
    /// value. The alternative, one canonical key per attribute, is a copy the
    /// size of the name; scanning one list per attribute of the other is work
    /// proportional to the square of a count the parse budget never sees.
    #[must_use]
    #[cfg(test)]
    fn matches(&self, other: &RelativeName<'_>) -> bool {
        if self.attributes.len() != other.attributes.len() {
            return false;
        }
        // One attribute is the common case, and it needs no ordering at all.
        if let ([left], [right]) = (&self.attributes[..], &other.attributes[..]) {
            return left.matches(right);
        }
        let mut ours: Vec<&Attribute<'a>> = self.attributes.iter().collect();
        let mut theirs: Vec<&Attribute<'_>> = other.attributes.iter().collect();
        ours.sort_unstable_by(|left, right| left.order(right));
        theirs.sort_unstable_by(|left, right| left.order(right));
        ours.iter()
            .zip(&theirs)
            .all(|(left, right)| left.matches(right))
    }

    /// A total order over parts that calls two of them equal exactly when
    /// [`RelativeName::matches`] does, built the same way: both sides ordered
    /// by the attribute order, then compared in step.
    #[cfg(test)]
    fn order(&self, other: &RelativeName<'_>) -> core::cmp::Ordering {
        self.attributes
            .len()
            .cmp(&other.attributes.len())
            .then_with(|| {
                if let ([left], [right]) = (&self.attributes[..], &other.attributes[..]) {
                    return left.order(right);
                }
                let mut ours: Vec<&Attribute<'a>> = self.attributes.iter().collect();
                let mut theirs: Vec<&Attribute<'_>> = other.attributes.iter().collect();
                ours.sort_unstable_by(|left, right| left.order(right));
                theirs.sort_unstable_by(|left, right| left.order(right));
                ours.iter()
                    .zip(&theirs)
                    .map(|(left, right)| left.order(right))
                    .find(|ordering| ordering.is_ne())
                    .unwrap_or(core::cmp::Ordering::Equal)
            })
    }
}

/// The value syntax of an attribute type this crate names, or `None` for a
/// kind it does not.
fn syntax_of(kind: Oid<'_>) -> Option<Syntax> {
    // The X.520 attributes whose value is a DirectoryString.
    const DIRECTORY: &[Oid<'static>] = &[
        oid::COMMON_NAME,
        oid::SURNAME,
        oid::LOCALITY,
        oid::STATE_OR_PROVINCE,
        oid::STREET_ADDRESS,
        oid::ORGANIZATION,
        oid::ORGANIZATIONAL_UNIT,
        oid::TITLE,
        oid::GIVEN_NAME,
        oid::INITIALS,
        oid::GENERATION_QUALIFIER,
        oid::PSEUDONYM,
        oid::ORGANIZATION_IDENTIFIER,
        oid::USER_ID,
    ];
    if DIRECTORY.contains(&kind) {
        Some(Syntax::Directory)
    } else if kind == oid::COUNTRY || kind == oid::SERIAL_NUMBER || kind == oid::DN_QUALIFIER {
        // X.520 gives these a PrintableString.
        Some(Syntax::Printable)
    } else if kind == oid::EMAIL_ADDRESS || kind == oid::DOMAIN_COMPONENT {
        // And these an IA5String.
        Some(Syntax::Ia5)
    } else {
        None
    }
}

/// The value syntaxes the named attribute types take.
#[derive(Clone, Copy)]
enum Syntax {
    /// The `DirectoryString` choice of X.520.
    Directory,
    /// A `PrintableString`.
    Printable,
    /// An `IA5String`.
    Ia5,
}

impl Syntax {
    fn permits(self, encoding: Encoding) -> bool {
        match self {
            Self::Directory => matches!(
                encoding,
                Encoding::Utf8
                    | Encoding::Printable
                    | Encoding::Teletex
                    | Encoding::Bmp
                    | Encoding::Universal
            ),
            Self::Printable => encoding == Encoding::Printable,
            Self::Ia5 => encoding == Encoding::Ia5,
        }
    }
}

/// Whether an attribute type's schema permits folding a value in one string
/// encoding. A value outside its type's choices takes part in identity as
/// bytes only: text folded out of an encoding the type does not have would
/// let a malformed value match a genuine one it never equals. And a kind
/// this crate does not name may define case-sensitive equality, so folding
/// under a rule the type may not have would match names that differ: its
/// values too equal themselves and nothing else.
fn permits(kind: Oid<'_>, encoding: Encoding) -> bool {
    syntax_of(kind).is_some_and(|syntax| syntax.permits(encoding))
}

/// The size an attribute kind's schema puts on its value, in characters:
/// the country is exactly two, and the rest follow the upper bounds of
/// RFC 5280 appendix A. A kind the appendix does not bound stays unbounded.
fn size_bounds(kind: Oid<'_>) -> (usize, usize) {
    if kind == oid::COUNTRY {
        (2, 2)
    } else if kind == oid::COMMON_NAME
        || kind == oid::ORGANIZATION
        || kind == oid::ORGANIZATIONAL_UNIT
        || kind == oid::TITLE
        || kind == oid::SERIAL_NUMBER
    {
        (1, 64)
    } else if kind == oid::LOCALITY || kind == oid::STATE_OR_PROVINCE {
        (1, 128)
    } else if kind == oid::EMAIL_ADDRESS {
        (1, 255)
    } else if kind == oid::PSEUDONYM {
        (1, 128)
    } else if kind == oid::STREET_ADDRESS {
        // ub-street-address (X.520).
        (1, 128)
    } else if kind == oid::SURNAME
        || kind == oid::GIVEN_NAME
        || kind == oid::INITIALS
        || kind == oid::GENERATION_QUALIFIER
    {
        // The name components share ub-name, 32768.
        (1, 32768)
    } else {
        (1, usize::MAX)
    }
}

/// Whether an attribute of a kind this crate names is written inside that
/// kind's syntax: the encoding is one its type permits, the value decodes
/// under it, and the decoded text fits the size the schema gives the kind.
/// An unknown kind answers yes, having no schema here to hold it to; where
/// an identity must have been read entirely, this is the question each
/// attribute is asked.
pub(crate) fn well_formed(attribute: &Attribute<'_>) -> bool {
    inside_syntax(attribute, Asking::Shape, |_| true)
}

/// Schema validation of retained string bytes, admitted before scanning.
pub(crate) fn well_formed_in(
    attribute: &Attribute<'_>,
    parent: &Reader<'_>,
    field: &'static str,
) -> Result<bool> {
    let work = (attribute.kind.as_bytes().len() as u64)
        .checked_mul(64)
        .and_then(|kinds| {
            (attribute.value.contents.len() as u64)
                .checked_mul(2)
                .and_then(|contents| kinds.checked_add(contents))
        })
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                attribute.value.offset,
            )
        })?;
    parent.charge(work).field(field)?;
    let value = attribute.value;
    if value.tag.is_constructed()
        && value.tag.class() == Class::Universal
        && value.tag.number().is_some_and(segmented_universal_type)
        && value.tag.number() != Some(universal::BIT_STRING)
        && syntax_of(attribute.kind).is_some()
    {
        // X.690 §8.23: the BER restricted-string spelling has OCTET STRING
        // fragments. Validate the joined logical value under the same schema
        // rather than treating its constructed tag as unsupported text.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        debug_assert!(value.depth > 0);
        let mut reader = parent
            .parser()
            .read_nested_query_in(
                parent,
                value.der,
                value.offset,
                structured_asn1::Encoding::Ber,
                value.depth - 1,
            )
            .field(field)?;
        let element = reader
            .next_element()
            .field(field)?
            .expect("retained complete attribute value");
        let execution = parent.execution();
        let mut contents = execution.vector();
        segments::walk_in(
            &reader,
            &element,
            field,
            false,
            Some(&mut contents),
            &execution,
        )?;
        parent
            .charge((contents.len() as u64).checked_mul(2).ok_or_else(|| {
                Error::resource(
                    structured_asn1::memory::MemoryError::WorkExceeded,
                    field,
                    value.offset,
                )
            })?)
            .field(field)?;
        return Ok(well_formed(&Attribute {
            kind: attribute.kind,
            value: AttributeValue {
                tag: Tag::primitive(value.tag.number().expect("universal string")),
                contents: &contents,
                ..value
            },
        }));
    }
    Ok(well_formed(attribute))
}

/// Display text may truncate at this bound. Identity preparation instead uses
/// the schema bound and the operation's admitted work/storage: RFC5280 §7.1
/// requires `StringPrep` for valid `UTF8String`/`PrintableString` values.
/// A display limit must never silently substitute binary equality.
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-7.1>
const DISPLAY_CEILING: usize = 32_768;

/// Whether the preparation can run on a value at all.
///
/// Unsupported encodings, malformed stored values and prohibited code points
/// retain only their encoded identity. That preservation does not validate
/// an LDAP assertion. Valid values have no display-derived preparation limit.
#[cfg(test)]
fn preparable(attribute: &Attribute<'_>) -> bool {
    if !inside_syntax(attribute, Asking::Folding, |c| !prohibited(c)) {
        return false;
    }
    // The direction step reads the value the normalizing step leaves, which
    // is the order the profile puts them in (RFC 4518 2, steps 3 then 5).
    // The order decides the answer: a compatibility form can expand into
    // letters of a direction the character it replaces did not have, U+2121
    // into TEL, so a value read before normalizing can look right-to-left
    // and be mixed once prepared. The walk is bounded by the step above,
    // which already held the value to the size its schema gives it.
    let mut direction = Direction::default();
    for c in normalized(attribute.value.decoded_chars()) {
        direction.see(c);
    }
    direction.settled()
}

/// The direction step of the preparation (RFC 4518 2.5, over RFC 3454 6),
/// read as the value is scanned.
///
/// A value holding a right-to-left letter may hold no left-to-right one, and
/// must begin and end with a right-to-left one. Failing either leaves the
/// value unprepared, which here means compared as bytes.
///
/// The edges are decided on the characters that are still there when the
/// preparation ends. The step that drops the spaces at the edges is part of
/// the same preparation and comes after this one, so holding a value to an
/// edge its own preparation deletes would refuse it over its spacing rather
/// than over its direction.
///
/// The steps before this one decide what it sees, so it reads the value as
/// they leave it: mapped and normalized. The mapping sends a set of
/// characters to nothing, and the direction marks are among them: a value is
/// written right to left because of its letters, not because it carries a
/// mark saying so, and counting a mark the preparation deletes would refuse
/// a name over a character that is not there by the time anything compares
/// it. Normalizing matters here too, and in the other direction: a
/// compatibility form can expand into letters that carry a direction the
/// character it replaces did not have, U+2121 into TEL, so a value read
/// before that step can look settled and be mixed after it.
#[derive(Default)]
struct Direction {
    /// The first character that is not a space, and whether it is
    /// right-to-left.
    first: Option<bool>,
    /// The same for the last one seen so far.
    last: bool,
    any_right: bool,
    any_left: bool,
}

impl Direction {
    fn see(&mut self, c: char) {
        if mapped_to_nothing(c) || c.is_whitespace() {
            return;
        }
        let class = unicode_bidi::bidi_class(c);
        let right = matches!(class, BidiClass::R | BidiClass::AL);
        if self.first.is_none() {
            self.first = Some(right);
        }
        self.last = right;
        self.any_right |= right;
        self.any_left |= class == BidiClass::L;
    }

    fn settled(&self) -> bool {
        !self.any_right || (!self.any_left && self.first == Some(true) && self.last)
    }
}

/// Whether the profile prohibits a code point (RFC 4518 2.4).
///
/// Private use, the non-characters, and the replacement character a decoder
/// writes when it could not read something: nobody agrees what any of them
/// says, so nothing downstream can be defined over them. None of the three
/// is touched by the mapping or the normalization, so asking about them
/// before those steps is asking about the same characters they ask about.
/// Surrogates are prohibited too and cannot arrive: nothing here produces
/// one, because a character is a scalar value.
///
/// The step also prohibits the deprecated code points and the ones that
/// change display properties, and none of those can reach it. The mapping
/// sends the display controls to nothing two steps earlier, and the
/// normalization takes the two deprecated tone marks to the ordinary marks
/// they are equivalent to. Testing for them here would refuse a value the
/// profile prepares, which is a name that stops matching itself.
///
/// The step's table of code points unassigned in Unicode 3.2 is applied,
/// which costs the folded comparison for a character assigned since. That is
/// the direction to lose in. The preparation is defined over one repertoire,
/// and every step after this one is a table this crate reaches at its
/// current version: a character the profile never saw carries a case folding
/// and a compatibility decomposition today, so folding one makes two names
/// equal by a rule the profile does not contain. Refusing it leaves the two
/// compared as bytes, which reports a path as unproven; folding it can
/// report an issuer as a subject it is not.
fn prohibited(c: char) -> bool {
    let point = u32::from(c);
    unassigned::in_unicode_3_2(c)
        || matches!(c,
        // Private use (RFC 3454 C.3).
        '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}'
        // The non-characters of the arabic presentation forms (C.4).
        | '\u{fdd0}'..='\u{fdef}'
        // The replacement character.
        | '\u{fffd}')
        // The last two code points of every plane, which are the rest of C.4.
        || point & 0xfffe == 0xfffe
}

/// Which of the two questions about a value is being asked.
///
/// They differ where a value can be kept without being read. A value whose
/// shape its schema names is not refused, and it is what the two callers of
/// this share; whether the preparation can then run on it is a narrower
/// question, and answering no to it costs a folded comparison rather than a
/// certificate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asking {
    /// Whether the value is written inside its kind's syntax at all. A no
    /// here refuses the value where an identity must have been read whole.
    Shape,
    /// Whether the preparation the comparison runs can run on this value.
    /// A no here leaves it compared as bytes.
    Folding,
}

/// The shared reading of an attribute against its kind's schema, with a
/// further test on each character the caller supplies.
fn inside_syntax(
    attribute: &Attribute<'_>,
    asking: Asking,
    mut keep: impl FnMut(char) -> bool,
) -> bool {
    match syntax_of(attribute.kind) {
        Some(syntax) => {
            let (least, schema) = size_bounds(attribute.kind);
            let most = schema;
            // The ceiling is checked on the encoded bytes first: no encoding
            // here spends fewer than one byte per character or more than
            // four, so a value whose bytes exceed four times the character
            // bound can never fit it. The saturation is deliberate: an
            // unbounded kind saturates the ceiling to the type's maximum,
            // and the streaming scan below still touches it one character
            // at a time without materializing a copy the size of the value.
            if attribute.value.contents().len() > most.saturating_mul(4) {
                return false;
            }
            if !syntax.permits(attribute.value.encoding()) {
                return false;
            }
            // TeletexString is T.61, and its repertoire is a negotiation this
            // crate does not implement: the bytes being there and inside the
            // size the schema gives the kind is what is checkable. Asking it
            // to decode as anything would call a legacy value malformed, and
            // where a name must be written inside its syntax that refuses a
            // certificate over an encoding the schema names. It is counted
            // in bytes here and not folded at all, which is the other half
            // of the same answer: a value nobody has agreed how to read
            // takes part in identity as its bytes.
            if attribute.value.encoding() == Encoding::Teletex && asking == Asking::Shape {
                return (least..=most).contains(&attribute.value.contents().len());
            }
            let country = attribute.kind == oid::COUNTRY;
            attribute
                .value
                // The country is a two-letter ISO 3166 code: digits and
                // punctuation fit the printable repertoire and the size
                // without naming any country. Case is left to folding.
                .validated_count(|c| (!country || c.is_ascii_alphabetic()) && keep(c))
                .is_some_and(|count| (least..=most).contains(&count))
        }
        None => true,
    }
}

/// Whether the preparation this comparison runs sends a character to nothing.
///
/// The Map step of the string preparation the profile requires (RFC 5280 7.1,
/// which requires RFC 4518) sends soft hyphen, the grapheme joiner, the
/// variation selectors, the object replacement character, the zero width
/// space and "all other control code (e.g., Cc) points or code points with a
/// control function (e.g., Cf)" to nothing. The list below is the one that
/// section writes out. What it does NOT contain is tab, line feed, vertical
/// tab, form feed, carriage return and next line: those are mapped to SPACE,
/// which is why the whitespace fold beside this covers them.
fn mapped_to_nothing(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{1806}'
            | '\u{034f}'
            | '\u{180b}'..='\u{180d}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{fffc}'
            | '\u{0000}'..='\u{0008}'
            | '\u{000e}'..='\u{001f}'
            | '\u{007f}'..='\u{0084}'
            | '\u{0086}'..='\u{009f}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206a}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// Streams the canonical form of a character stream: the preparation's steps
/// in the order it gives them, each one an adapter over the one before, so
/// that no step ever holds the value.
///
/// Map (RFC 4518 2.2), then Normalize (2.3), then the insignificant space
/// handling (2.6.1). The order is the profile's and it is not free to
/// change: normalization can produce a space of its own, out of a character
/// whose compatibility form begins with one, and a space it produces has to
/// reach the step that decides which spaces count.
///
/// The mapping runs on both sides of the normalization, which is what makes
/// it the profile's mapping rather than a case fold. The table the profile
/// names is B.2 of RFC 3454, a fold that carries the compatibility mappings
/// with it: `2102; 0063; Additional folding` takes the double-struck
/// capital C straight to a lowercase c. This crate's fold is the published
/// case folding, which leaves that character alone, and the normalization
/// after it produces a capital. Folding what the normalization produces
/// arrives where the profile's table does, and costs a second walk of a
/// stream already bounded.
///
/// What bounds the work is upstream of here: only an attribute type this
/// crate names is folded at all, and only inside the size its schema gives
/// it, so the longest stream this sees is a few tens of thousands of
/// characters rather than a document's worth.
#[cfg(test)]
type Canonical<I> = Spaced<Mapped<Recomposed<Mapped<I>>>>;

/// What the normalization step hands on, named so the pipeline above reads
/// as the steps it is.
#[cfg(test)]
type Recomposed<I> = unicode_normalization::Recompositions<I>;

/// Assembles the pipeline over one decoded value.
#[cfg(test)]
fn canonical<I: Iterator<Item = char>>(inner: I) -> Canonical<I> {
    Spaced::over(Mapped::over(normalized(inner)))
}

/// The value as the two steps before the direction one leave it: mapped
/// (RFC 4518 2.2), then normalized to form KC (2.3).
///
/// The steps that read a value rather than produce one, Prohibit and the
/// direction check, come after these two (2.4 and 2.5), so this is the
/// stream they are defined over.
#[cfg(test)]
fn normalized<I: Iterator<Item = char>>(inner: I) -> Recomposed<Mapped<I>> {
    use unicode_normalization::UnicodeNormalization;
    Mapped::over(inner).nfkc()
}

/// The Map step: what the preparation sends to nothing is dropped, what it
/// sends to SPACE becomes one, and case is folded. One held expansion is the
/// whole state.
///
/// The characters mapped to a space are exactly the ones RFC 4518 names: tab,
/// line feed, vertical tab, form feed, carriage return and next line, plus
/// the separator code points, which is what `is_whitespace` names.
struct Mapped<I, const FOLD_CASE: bool = true> {
    inner: I,
    /// What one folded character expands to, which is at most a few.
    folded: Option<Folded>,
}

/// The tail of one character's fold, after its first character has been
/// handed out.
enum Folded {
    Mapped(core::str::Chars<'static>),
    Lowered(core::char::ToLowercase),
}

impl Iterator for Folded {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        match self {
            Self::Mapped(rest) => rest.next(),
            Self::Lowered(rest) => rest.next(),
        }
    }
}

impl<I: Iterator<Item = char>, const FOLD_CASE: bool> Mapped<I, FOLD_CASE> {
    fn over(inner: I) -> Self {
        Self {
            inner,
            folded: None,
        }
    }

    /// Folds one character's case and hands back its first output, keeping
    /// the rest for the next call.
    ///
    /// The fold is the one the preparation names (RFC 4518 2.2 folds case by
    /// the table of RFC 3454 B.2): a letter may fold to a different letter
    /// or to more than one, and an issuer written in one case is the same
    /// name as the subject written in another. See [`fold`] for what the map
    /// is and what it still leaves out.
    fn fold(&mut self, c: char) -> Option<char> {
        match fold::of(c) {
            fold::Fold::Mapped(mapped) => {
                let mut rest = mapped.chars();
                let first = rest.next();
                self.folded = Some(Folded::Mapped(rest));
                first
            }
            fold::Fold::One(one) => {
                self.folded = None;
                Some(one)
            }
            fold::Fold::Lowercase => {
                let mut lowered = c.to_lowercase();
                let first = lowered.next();
                self.folded = Some(Folded::Lowered(lowered));
                first
            }
        }
    }
}

impl<I: Iterator<Item = char>, const FOLD_CASE: bool> Iterator for Mapped<I, FOLD_CASE> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(rest) = self.folded.as_mut()
            && let Some(c) = rest.next()
        {
            return Some(c);
        }
        self.folded = None;
        for c in self.inner.by_ref() {
            // Mapped to nothing, so it takes no part in what the value says
            // and does not separate words either.
            if mapped_to_nothing(c) {
                continue;
            }
            if c.is_whitespace() {
                return Some(' ');
            }
            return if FOLD_CASE { self.fold(c) } else { Some(c) };
        }
        None
    }
}

/// The insignificant space handling: a run of spaces between words counts as
/// one and the runs at either end count as none.
///
/// The profile writes the same rule as padding rather than trimming, one
/// space at each end and two between words (RFC 4518 2.6.1), which is what
/// makes a substring assertion's edges line up. For deciding whether two
/// whole values are equal the two forms put exactly the same values
/// together, and this one holds one character of state instead of emitting
/// an edge the value does not have.
struct Spaced<I> {
    inner: I,
    held: Option<char>,
    gap: bool,
    started: bool,
}

impl<I: Iterator<Item = char>> Spaced<I> {
    fn over(inner: I) -> Self {
        Self {
            inner,
            held: None,
            gap: false,
            started: false,
        }
    }
}

impl<I: Iterator<Item = char>> Iterator for Spaced<I> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(c) = self.held.take() {
            return Some(c);
        }
        for c in self.inner.by_ref() {
            if c == ' ' {
                // A gap counts only between words: a leading run has no word
                // before it, and a trailing run meets the end instead.
                self.gap = self.started;
                continue;
            }
            self.started = true;
            if self.gap {
                self.gap = false;
                self.held = Some(c);
                return Some(' ');
            }
            return Some(c);
        }
        None
    }
}

impl<'a> Attribute<'a> {
    /// What kind of attribute this is.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }

    /// The value, as encoded.
    #[must_use]
    pub fn value(self) -> AttributeValue<'a> {
        self.value
    }

    /// The value as text for a person to read, where it is text at all.
    ///
    /// For display. Never for deciding that two names are the same one: see
    /// [`Name::matches`].
    ///
    /// # Errors
    /// Returns a located resource error if the execution or storage budget is spent.
    pub fn text(self, execution: &Memory) -> Result<Option<OwnedString>> {
        self.value.text(execution)
    }

    #[cfg(test)]
    fn matches(self, other: &Attribute<'_>) -> bool {
        if self.kind != other.kind {
            return false;
        }
        if self.value.der == other.value.der {
            return true;
        }
        // Both are strings the type permits and that decode: the profile
        // compares what they say, ignoring case and the width of the gaps.
        // Streamed, so two long differently encoded values cost no copy.
        // Anything else is compared as it was encoded, because this layer has
        // no rule for what it means, and such bytes only ever equal
        // themselves.
        match (self.folding_chars(), other.folding_chars()) {
            (Some(left), Some(right)) => canonical(left).eq(canonical(right)),
            _ => false,
        }
    }

    /// A total order over attributes that calls two of them equal exactly
    /// when [`Attribute::matches`] does, so ordering both sides of a part and
    /// walking them in step answers the multiset question.
    ///
    /// Kind first, then whether the value folds, then the values themselves:
    /// folded ones by their canonical characters, the rest by their bytes. A
    /// value that folds can never share its encoding with one that does not,
    /// the two questions being asked of the same kind and bytes, so no pair
    /// this separates is a pair `matches` would join.
    #[cfg(test)]
    fn order(&self, other: &Attribute<'_>) -> core::cmp::Ordering {
        self.kind
            .as_bytes()
            .cmp(other.kind.as_bytes())
            .then_with(|| match (self.folding_chars(), other.folding_chars()) {
                (Some(left), Some(right)) => canonical(left).cmp(canonical(right)),
                (None, None) => self.value.der.cmp(other.value.der),
                (Some(_), None) => core::cmp::Ordering::Less,
                (None, Some(_)) => core::cmp::Ordering::Greater,
            })
    }

    /// Whether this value takes part in the preparation the profile describes,
    /// or is compared only as the bytes it was written in.
    ///
    /// A caller explaining why a name did not match needs the same answer this
    /// comparison uses, not a guess at it: a value can be excluded for its
    /// encoding, for a code point the type prohibits, or for failing the
    /// direction step, and only one of those is visible from the outside.
    ///
    /// # Errors
    /// Returns a located resource error if preparation cannot be financed.
    pub fn folds(self, execution: &Memory) -> Result<bool> {
        prepared::folds(self, execution)
    }

    /// The decoded characters of a value that takes part in folding: the
    /// type's schema permits the encoding it was written in, and it sits
    /// inside the schema's size bounds. A known attribute outside them is not
    /// a value the schema names, and folding one would let a malformed issuer
    /// match a genuine subject; it stays byte-only equality.
    #[cfg(test)]
    fn folding_chars(self) -> Option<DecodedChars<'a>> {
        (permits(self.kind, self.value.encoding()) && preparable(&self))
            .then(|| self.value.decoded_chars())
    }
}

impl<'a> AttributeValue<'a> {
    /// The value exactly as it was encoded, tag included.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.der
    }

    /// The contents, without the tag and length.
    #[must_use]
    pub fn contents(self) -> &'a [u8] {
        self.contents
    }

    /// Which string encoding this was written in.
    #[must_use]
    pub fn encoding(self) -> Encoding {
        if self.tag.class() != Class::Universal || self.tag.is_constructed() {
            return Encoding::Other;
        }
        match self.tag.number() {
            Some(universal::UTF8_STRING) => Encoding::Utf8,
            Some(universal::PRINTABLE_STRING) => Encoding::Printable,
            Some(universal::IA5_STRING) => Encoding::Ia5,
            Some(NUMERIC_STRING) => Encoding::Numeric,
            Some(TELETEX_STRING) => Encoding::Teletex,
            Some(VISIBLE_STRING) => Encoding::Visible,
            Some(BMP_STRING) => Encoding::Bmp,
            Some(UNIVERSAL_STRING) => Encoding::Universal,
            _ => Encoding::Other,
        }
    }

    /// The value as text for a person to read, where it is text at all.
    ///
    /// Bounded, because this is the public reading path and a value may be
    /// as wide as the element limit permits while several attribute types
    /// have no ceiling in the schema. What is shown is as much of the value
    /// as the widest name component the profile names, and a mark saying the
    /// rest is there. Identity is the bytes and is never this.
    ///
    /// The returned string retains its storage charge independently of the parser.
    /// # Errors
    /// Returns a located resource error before unfunded decoding or allocation.
    pub fn text(self, execution: &Memory) -> Result<Option<OwnedString>> {
        let fail = |reason| Error::resource(reason, "name.attribute", self.offset);
        let width = match self.encoding() {
            Encoding::Other => return Ok(None),
            Encoding::Bmp => Some(2),
            Encoding::Universal => Some(4),
            _ => None,
        };
        // UTF-8 validation and subsequent decoding each visit the input at most
        // once. Admit both before entering either scan.
        execution
            .charge_work((self.contents.len() as u64) * 2)
            .map_err(fail)?;
        match width {
            Some(width) => {
                if !self.contents.len().is_multiple_of(width) {
                    return Ok(None);
                }
                let bound = ((DISPLAY_CEILING + 1) * width).min(self.contents.len());
                display_text(wide_chars(&self.contents[..bound], width), execution).map_err(fail)
            }
            // Every remaining type is a subset of ASCII by its definition, and
            // an issuer writing outside it has written something. Where those
            // bytes are UTF-8 they are read as UTF-8, which is what the issuer
            // meant; where they are not, they are read as one byte a
            // character. Both are approximations for a person to read, and
            // neither is what two names are compared on.
            None => match core::str::from_utf8(self.contents) {
                Ok(text) => display_text(text.chars().map(Some), execution).map_err(fail),
                Err(_) => display_text(
                    self.contents.iter().map(|byte| Some(char::from(*byte))),
                    execution,
                )
                .map_err(fail),
            },
        }
    }

    /// Streams the value's characters through its declared alphabet and
    /// `keep`, counting them, without materializing the text: a value can be
    /// as long as the element limit permits, and validating one must not
    /// allocate a copy its size. `None` is a value that does not decode or a
    /// character either test refuses.
    fn validated_count(self, mut keep: impl FnMut(char) -> bool) -> Option<usize> {
        let encoding = self.encoding();
        let mut count = 0usize;
        match encoding {
            Encoding::Other => return None,
            Encoding::Bmp | Encoding::Universal => {
                let width = if encoding == Encoding::Bmp { 2 } else { 4 };
                if !self.contents.len().is_multiple_of(width) {
                    return None;
                }
                for c in wide_chars(self.contents, width) {
                    if !keep(c?) {
                        return None;
                    }
                    count += 1;
                }
            }
            _ => {
                let text = core::str::from_utf8(self.contents).ok()?;
                for c in text.chars() {
                    if !in_alphabet(encoding, c) || !keep(c) {
                        return None;
                    }
                    count += 1;
                }
            }
        }
        Some(count)
    }

    /// The decoded characters of a value [`preparable`] has already
    /// validated: total and allocation free, for folding without a copy.
    fn decoded_chars(self) -> DecodedChars<'a> {
        match self.encoding() {
            Encoding::Bmp => DecodedChars::Wide {
                contents: self.contents,
                width: 2,
            },
            Encoding::Universal => DecodedChars::Wide {
                contents: self.contents,
                width: 4,
            },
            _ => DecodedChars::Narrow(
                core::str::from_utf8(self.contents)
                    .expect("the value was decoded before this iterator was built")
                    .chars(),
            ),
        }
    }
}

/// Whether a character sits inside the alphabet a narrow string type
/// declares. IA5 is ASCII by definition. The teletex repertoire is a
/// negotiation this crate does not implement; its invariant subset is ASCII,
/// and only that subset takes part in matching.
fn in_alphabet(encoding: Encoding, c: char) -> bool {
    match encoding {
        Encoding::Printable => is_printable_string(c),
        Encoding::Numeric => c.is_ascii_digit() || c == ' ',
        Encoding::Visible => matches!(c, '\x20'..='\x7e'),
        Encoding::Ia5 | Encoding::Teletex => c.is_ascii(),
        _ => true,
    }
}

/// The decoded characters of a wide string, one unit at a time: a unit that
/// is not a character, a surrogate included, is `None` (X.680, 41.16 puts
/// `BMPString` in the basic plane, and `char::from_u32` refuses surrogates).
fn wide_chars(contents: &[u8], width: usize) -> impl Iterator<Item = Option<char>> + '_ {
    contents.chunks_exact(width).map(|chunk| {
        char::from_u32(
            chunk
                .iter()
                .fold(0u32, |value, byte| (value << 8) | u32::from(*byte)),
        )
    })
}

/// The characters of an already validated value, streamed without an
/// allocation.
enum DecodedChars<'a> {
    Narrow(core::str::Chars<'a>),
    Wide { contents: &'a [u8], width: usize },
}

impl Iterator for DecodedChars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        match self {
            Self::Narrow(chars) => chars.next(),
            Self::Wide { contents, width } => {
                if contents.len() < *width {
                    return None;
                }
                let (unit, rest) = contents.split_at(*width);
                *contents = rest;
                // A substitute character here would make two values that do
                // not decode compare equal, which is the forged match this
                // module exists to prevent.
                Some(
                    char::from_u32(
                        unit.iter()
                            .fold(0u32, |value, byte| (value << 8) | u32::from(*byte)),
                    )
                    .expect("the value was decoded before this iterator was built"),
                )
            }
        }
    }
}

/// Tag numbers X.680 gives the types this crate reads past the ones
/// `sig-asn1` names, which are the ones nothing below the schema needs.
const REAL: u32 = 9;
const ENUMERATED: u32 = 10;
const RELATIVE_OID: u32 = 13;
const NUMERIC_STRING: u32 = 18;
const TELETEX_STRING: u32 = 20;
const VISIBLE_STRING: u32 = 26;
const UNIVERSAL_STRING: u32 = 28;
const BMP_STRING: u32 = 30;
const EXTERNAL: u32 = 8;
const EMBEDDED_PDV: u32 = 11;
const OBJECT_DESCRIPTOR: u32 = 7;
const TIME: u32 = 14;
const DATE: u32 = 31;
const TIME_OF_DAY: u32 = 32;
const DATE_TIME: u32 = 33;
const DURATION: u32 = 34;
const OID_IRI: u32 = 35;
const RELATIVE_OID_IRI: u32 = 36;

/// Whether contents are the value notation of an identifier written as a
/// resource name: the arcs in UTF-8, no arc empty and none carrying white
/// space, the object form opening with the separator and the relative one
/// not (X.680 34.3 and 35.3, X.690 8.21.2 and 8.22.2).
///
/// What an arc may say beyond that is a registry's business, so nothing here
/// reads one: this is the shape of the value, which is what deciding it is a
/// value of the type asks for.
fn iri_fits(contents: &[u8], rooted: bool) -> bool {
    let Ok(text) = core::str::from_utf8(contents) else {
        return false;
    };
    let arcs = match text.strip_prefix('/') {
        Some(rest) if rooted => rest,
        None if !rooted => text,
        _ => return false,
    };
    !arcs.is_empty() && arcs.split('/').all(arc_fits)
}

/// Whether one arc is a Unicode label: either the digits of an arc's own
/// number, or a name written from the characters X.660 7.5.2 lists.
///
/// The number opens with a zero only where it is that one digit (7.3). The
/// name holds at least one character that is not a digit, which is what
/// tells the two apart (7.5.1), carries no hyphen at either end and no pair
/// of them in the third and fourth places, where a normalized form would
/// read them as a prefix (7.5.4).
///
/// What is not applied is 7.5.3, which excludes the positions ISO/IEC 10646
/// marks as not to be used: that marking is not stable across editions, and
/// the clause's own note tells a reader to be tolerant of it. Everything
/// else here is the label as the standard writes it.
fn arc_fits(arc: &str) -> bool {
    if arc.is_empty() {
        return false;
    }
    if arc.bytes().all(|byte| byte.is_ascii_digit()) {
        return arc == "0" || !arc.starts_with('0');
    }
    if arc.starts_with('-') || arc.ends_with('-') {
        return false;
    }
    let hyphenated = arc
        .chars()
        .nth(2)
        .zip(arc.chars().nth(3))
        .is_some_and(|(third, fourth)| third == '-' && fourth == '-');
    !hyphenated && arc.chars().all(label_character)
}

/// Whether a character is one a Unicode label is written from (X.660 7.5.2).
fn label_character(c: char) -> bool {
    matches!(c, '-' | '.' | '_' | '~' | '0'..='9' | 'A'..='Z' | 'a'..='z')
        || matches!(u32::from(c),
            0xa0..=0xdffe
            | 0xf900..=0xfdcf
            | 0xfdf0..=0xffef
            | 0x1_0000..=0x1_fffd
            | 0x2_0000..=0x2_fffd
            | 0x3_0000..=0x3_fffd
            | 0x4_0000..=0x4_fffd
            | 0x5_0000..=0x5_fffd
            | 0x6_0000..=0x6_fffd
            | 0x7_0000..=0x7_fffd
            | 0x8_0000..=0x8_fffd
            | 0x9_0000..=0x9_fffd
            | 0xa_0000..=0xa_fffd
            | 0xb_0000..=0xb_fffd
            | 0xc_0000..=0xc_fffd
            | 0xd_0000..=0xd_fffd
            | 0xe_1000..=0xe_fffd)
}

/// Whether a universal type is one DER writes constructed, so finding it that
/// way is the type rather than a second spelling of a primitive one.
///
/// The containers, and the three types whose definition is an associated
/// sequence: external and instance-of under tag 8 (X.690 8.16.1, 8.18.1),
/// embedded-pdv under 11 (8.17.1), and the unrestricted character string
/// under 29 (8.24.1). Everything else universal is primitive here (10.2).
pub(crate) fn constructed_universal_type(number: u32) -> bool {
    matches!(
        number,
        universal::SEQUENCE | universal::SET | 8 | 11 | CHARACTER_STRING
    )
}

/// `CHARACTER STRING`, the unrestricted one, which this crate names itself
/// because nothing below the schema needs it.
const CHARACTER_STRING: u32 = 29;

/// Whether the members of one of the three types whose encoding is a
/// sequence defined for it are the components that definition names.
///
/// The external type is a sequence of three optional members, an identifier,
/// a reference and a descriptor, and then the encoding it carries, which is
/// one of three choices and is not optional (X.690 8.18.1). The embedded-pdv
/// type and the unrestricted character string are the same shape as each
/// other: how the value is identified, then the value, both required and
/// tagged in order, with the descriptor between them absent by the
/// definition's own constraint (X.680 36.5 and 44.5).
///
/// What each member says is somebody else's business, and nothing here reads
/// one. This is the shape, which is what deciding it is a value of the type
/// asks for. The walk that follows holds each member to its own rules.
fn associated_sequence_fits<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    number: u32,
) -> Result<bool> {
    let mut inside = parent.enter(element).field(field)?;
    if number == EXTERNAL {
        // The optional members come in this order and each appears once.
        let mut left: &[u32] = &[universal::OID, universal::INTEGER, OBJECT_DESCRIPTOR];
        while let Some(member) = inside.next_element().field(field)? {
            let tag = member.tag();
            if tag.class() == Class::ContextSpecific {
                // The encoding closes the sequence, and each of its three
                // ways says what its contents are: one whole value carried
                // inside the tag, a value in octets, which any bytes are, or
                // a value in bits, which opens with the count of the unused
                // ones.
                let carried = match tag.number() {
                    Some(0) => {
                        let mut held = inside.enter(&member).field(field)?;
                        held.next_element().field(field)?.is_some() && held.is_empty()
                    }
                    Some(1) => segments::implicit(&inside, &member, field, false)?,
                    Some(2) => segments::implicit(&inside, &member, field, true)?,
                    _ => false,
                };
                return Ok(carried && inside.is_empty());
            }
            let Some(at) = tag
                .number()
                .filter(|_| tag.class() == Class::Universal)
                .and_then(|number| left.iter().position(|kind| *kind == number))
            else {
                return Ok(false);
            };
            left = &left[at + 1..];
        }
        // Nothing carried, which is the one member the definition requires.
        return Ok(false);
    }

    // How the value is identified: a choice, so its member wears an explicit
    // tag over whichever of the six alternatives was written.
    let Some(identification) = inside.next_element().field(field)? else {
        return Ok(false);
    };
    if identification.tag() != Tag::context(true, 0) {
        return Ok(false);
    }
    let mut chosen = inside.enter(&identification).field(field)?;
    let Some(alternative) = chosen.next_element().field(field)? else {
        return Ok(false);
    };
    if alternative.tag().class() != Class::ContextSpecific
        || !chosen.is_empty()
        || !identification_fits(&chosen, &alternative, field)?
    {
        return Ok(false);
    }
    // Then the value itself, which is the third component of the definition
    // and keeps that number whether or not the second one is written. It is
    // an octet string under its tag, and the distinguished rules write a
    // string in one piece (X.690 10.2), so the segmented form is a second
    // spelling of it there. The basic rules have both, and a document read
    // under them keeps what it was written with.
    let Some(value) = inside.next_element().field(field)? else {
        return Ok(false);
    };
    Ok(value.tag().class() == Class::ContextSpecific
        && value.tag().number() == Some(2)
        && segments::implicit(&inside, &value, field, false)?
        && inside.is_empty())
}

/// Whether a member read as the type it is, with a spent budget kept as
/// what it is.
///
/// A value that is not the type is an answer about the document, and this
/// says no. A budget that ran out is this run giving up, and it says
/// nothing about the document, so it travels on rather than being folded
/// into the no beside it: a report must not blame a certificate for a
/// device that stopped.
fn reads<T>(outcome: structured_asn1::Result<T>, field: &'static str) -> Result<bool> {
    match outcome.field(field) {
        Ok(_) => Ok(true),
        Err(error) if error.is_resource() => Err(error),
        Err(_) => Ok(false),
    }
}

/// Whether one alternative of the identification choice is the type that
/// alternative is (X.680 36.5, and 44.5 for the same choice again).
///
/// The alternatives are tagged over their types rather than beside them, so
/// what arrives is the type's contents under a context tag, and the contents
/// are the type's: the pair of identifiers, one identifier, a context named
/// by a number, that number with an identifier beside it, the transfer
/// syntax as an identifier, and the fixed alternative, which is nothing at
/// all. A tag with the wrong contents under it is the same defect as a
/// container with the wrong members, one level down.
fn identification_fits<'a>(
    parent: &Reader<'a>,
    alternative: &Element<'a>,
    field: &'static str,
) -> Result<bool> {
    /// The two members of the alternatives that hold a pair, as the types
    /// they are: the syntaxes are two identifiers, the negotiation is a
    /// context and the syntax to encode it in.
    fn pair<'a>(
        parent: &Reader<'a>,
        alternative: &Element<'a>,
        field: &'static str,
        numbered: bool,
    ) -> Result<bool> {
        let mut inside = parent.enter(alternative).field(field)?;
        let (Some(first), Some(second)) = (
            inside.next_element().field(field)?,
            inside.next_element().field(field)?,
        ) else {
            return Ok(false);
        };
        let opens = if numbered {
            reads(inside.integer(&first), field)?
        } else {
            reads(inside.oid(&first), field)?
        };
        Ok(opens
            && first.tag() == Tag::context(false, 0)
            && second.tag() == Tag::context(false, 1)
            && reads(inside.oid(&second), field)?
            && inside.is_empty())
    }

    let constructed = alternative.tag().is_constructed();
    Ok(match alternative.tag().number() {
        Some(0) => constructed && pair(parent, alternative, field, false)?,
        Some(1 | 4) => reads(parent.oid(alternative), field)?,
        Some(2) => reads(parent.integer(alternative), field)?,
        Some(3) => constructed && pair(parent, alternative, field, true)?,
        // The fixed alternative is a null, which says what it says by being
        // there and carries nothing.
        Some(5) => !constructed && alternative.contents().is_empty(),
        _ => false,
    })
}

/// Whether a universal number belongs to a type at all.
///
/// Table 1 of X.680 assigns them. Zero is kept by the encoding rules,
/// fifteen is reserved for future editions, and thirty-seven and up are
/// reserved for addenda: nothing between the standard's covers gives any of
/// them a meaning, so bytes wearing one are a value of no type.
fn assigned_universal_type(number: u32) -> bool {
    !matches!(number, 0 | 15) && number <= RELATIVE_OID_IRI
}

/// Whether a restricted string's contents are held to the alphabet its type
/// names.
///
/// The two answers are the two things a preserved value goes on to do. A
/// value handed to a scheme that clears a critical extension has to be a
/// value of the type it claims, or the extension is cleared on something
/// that is not one. A value that takes part in a name is kept as written:
/// refusing it would block a certificate over a spelling, and the profile
/// names binary comparison as a sufficient matching rule (RFC 5280 7.1), so
/// a malformed value still has an identity and is still shown to a person.
/// It is only withheld from folding, which is defined over values the schema
/// names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strings {
    Checked,
    AsWritten,
}

/// Reads every element under one, holding each to the rules the encoding
/// names even where nothing here interprets the value.
///
/// The places that preserve an opaque value share this: an attribute of a
/// name, the value of an other-name, the information of a qualified
/// statement, an algorithm's parameter and the value of a policy qualifier.
/// Each is handed to somebody who decides an identity, names the service that
/// issued the certificate, or clears a critical extension on the strength of
/// it, so what is preserved has to be the encoding the document claims, all
/// the way down. Checking the outer tag
/// alone leaves the same second spelling of a value one level lower, where it
/// arrives at the same reader by the same route.
pub(crate) fn walk_der<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    strings: Strings,
) -> Result<()> {
    if !check_der(parent, element, field, strings)? {
        return Ok(());
    }
    // The descent keeps its own stack rather than the machine's. Depth is
    // the reader's to bound and a caller may raise that bound, so spending a
    // machine stack frame per element would turn a limit into a crash for
    // whoever raised it. On this stack the same input is the refusal the
    // limit describes.
    let mut open = parent.execution().vector::<Open<'a>>();
    open.try_push(Open::of(parent.enter(element).field(field)?, element.tag()))
        .map_err(|reason| Error::resource(reason, field, element.span().start))?;
    while let Some(level) = open.last_mut() {
        let Some(child) = level.reader.next_element().field(field)? else {
            open.pop();
            continue;
        };
        // The members of a set appear in ascending order of their encodings
        // (X.690 11.6), and a set's components in the tag order 10.3 names,
        // which the same comparison decides because a tag leads its own
        // encoding. Deciding it walks up to the longer member, so that
        // length is charged before the walk: a caller bounding work sees
        // this on the same meter the reads use.
        if level.ordered
            && let Some(previous) = level.previous
        {
            level
                .reader
                .charge(previous.len().max(child.as_bytes().len()) as u64)
                .field(field)?;
            if !der_set_ordered(previous, child.as_bytes()) {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    field,
                    child.span().start,
                ));
            }
        }
        level.previous = Some(child.as_bytes());

        let inside = &open
            .last()
            .expect("the reader the child was read from")
            .reader;
        if check_der(inside, &child, field, strings)? {
            let entered = inside.enter(&child).field(field)?;
            let tag = child.tag();
            open.try_push(Open::of(entered, tag))
                .map_err(|reason| Error::resource(reason, field, child.span().start))?;
        }
    }
    Ok(())
}

/// One container the walk is inside, and what deciding its members needs.
struct Open<'a> {
    reader: Reader<'a>,
    /// Whether this container's members are ordered by their encodings,
    /// which is the case for a set and for nothing else.
    ordered: bool,
    /// The member read before this one, for that comparison.
    previous: Option<&'a [u8]>,
}

impl<'a> Open<'a> {
    fn of(reader: Reader<'a>, tag: Tag) -> Self {
        let ordered = reader.encoding().is_der()
            && tag.class() == Class::Universal
            && tag.number() == Some(universal::SET);
        Self {
            reader,
            ordered,
            previous: None,
        }
    }
}

/// Holds one element to the rules its tag names, and says whether it has
/// children the caller still has to walk.
fn check_der<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    strings: Strings,
) -> Result<bool> {
    let fail = |code| Error::new(code, field, element.span().start);
    let tag = element.tag();
    // The construction rule runs both ways, and only one of the two is
    // about DER. A string written constructed is a second spelling of one
    // value, which the distinguished rules forbid (X.690 10.2). A container
    // written primitive is not the type at all: a sequence and a set are
    // constructed by definition (8.9.1, 8.11.1), as are the three types
    // whose definition is an associated sequence (8.17.1, 8.18.1, 8.24.1),
    // and that holds in either encoding.
    if tag.class() == Class::Universal {
        // Before the form, the number itself. Table 1 of X.680 assigns the
        // universal numbers, and three ranges belong to no type: zero, which
        // the encoding rules keep for themselves, fifteen, and everything
        // from thirty-seven up. Bytes wearing one of those claim a type the
        // standard has not defined, in either encoding, so preserving them
        // would hand a scheme a value of nothing.
        if !tag.number().is_some_and(assigned_universal_type) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        // A number this reader does not name is not one of the containers,
        // and universal numbers that wide are not assigned at all.
        let container = tag.number().is_some_and(constructed_universal_type);
        let wrong = if tag.is_constructed() {
            !container
                && (parent.encoding().is_der()
                    || !tag.number().is_some_and(segmented_universal_type))
        } else {
            container
        };
        if wrong {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        if tag.is_constructed() && tag.number().is_some_and(segmented_universal_type) {
            segments::validate(parent, element, field, strings)?;
            return Ok(false);
        }
        // Three of the containers are not containers of anything: their
        // encoding is the encoding of a sequence defined for them, whose
        // components are the type. A tag with the wrong members under it
        // wears the type without being a value of it.
        if let Some(number @ (EXTERNAL | EMBEDDED_PDV | CHARACTER_STRING)) = tag.number()
            && !associated_sequence_fits(parent, element, field, number)?
        {
            return Err(fail(ErrorCode::MalformedValue));
        }
    }
    if !tag.is_constructed() {
        // The types whose contents the encoding settles: an integer written
        // a byte longer than it needs, a boolean spelled with a byte other
        // than the two DER allows, a bit string whose padding carries data.
        // Nothing here means anything by the value; what is checked is that
        // it is written the one way DER writes it.
        if tag.class() == Class::Universal {
            match tag.number() {
                Some(universal::INTEGER) => parent.integer(element).field(field).map(|_| ())?,
                Some(universal::BIT_STRING) => {
                    parent.bit_string(element).field(field).map(|_| ())?;
                }
                Some(universal::BOOLEAN) => parent.boolean(element).field(field).map(|_| ())?,
                Some(universal::NULL) => parent.null(element).field(field)?,
                Some(universal::OID) => parent.oid(element).field(field).map(|_| ())?,
                // An enumerated value is encoded as the integer it is
                // associated with (X.690 8.4), so the integer's rules are
                // its rules.
                Some(ENUMERATED) => parent.integer(element).field(field).map(|_| ())?,
                // A real's octets are settled to the last one (8.5), and the
                // distinguished rules settle them further (11.3). Nothing
                // here reads the number.
                Some(REAL) => parent.real(element).field(field)?,
                // A relative identifier's sub-identifiers are written the
                // way an identifier's are: in the fewest octets, so none
                // begins with 0x80, and the last of each series closes it
                // (X.690 8.20.2). That is what the identifier reader checks,
                // the joint first arc aside, which a relative one does not
                // have.
                Some(RELATIVE_OID) => parent.oid(element).field(field).map(|_| ())?,
                // Under the encoding's rule and not the profile's: a
                // certificate's validity dates are written without a
                // fraction because the profile says so (RFC 5280 4.1.2.5.2),
                // and a value preserved inside somebody else's payload is
                // not a validity date.
                Some(universal::UTC_TIME | universal::GENERALIZED_TIME) => {
                    // A fraction is held to digits by walking it, and it is
                    // as long as the element permits: the length goes on the
                    // shared meter first, as it does for the identifier and
                    // the strings below.
                    useful_time_fits(parent, element, field)?;
                }
                // The newer time types, whose contents are the value notation
                // with the characters X.690 8.26 names taken out. What each
                // one writes is settled by its property settings (X.680
                // 38.4), so a value that is not that notation is not a value
                // of the type, whatever the tag says.
                Some(kind @ (TIME | DATE | TIME_OF_DAY | DATE_TIME | DURATION)) => {
                    parent
                        .charge(element.contents().len() as u64)
                        .field(field)?;
                    let defined = match kind {
                        DATE => crate::time::Defined::Date,
                        TIME_OF_DAY => crate::time::Defined::TimeOfDay,
                        DATE_TIME => crate::time::Defined::DateTime,
                        DURATION => crate::time::Defined::Duration,
                        _ => crate::time::Defined::Any,
                    };
                    if !crate::time::defined_fits(defined, element.contents()) {
                        return Err(fail(ErrorCode::MalformedValue));
                    }
                }
                // The two identifiers written as resource names: their
                // contents are the arcs in UTF-8 with no white space between
                // the lexical items (X.690 8.21.2, 8.22.2), the object form
                // beginning at the root and the relative one not (X.680 34.3
                // and 35.3).
                Some(kind @ (OID_IRI | RELATIVE_OID_IRI)) => {
                    parent
                        .charge(element.contents().len() as u64)
                        .field(field)?;
                    if !iri_fits(element.contents(), kind == OID_IRI) {
                        return Err(fail(ErrorCode::MalformedValue));
                    }
                }
                // A restricted string's contents are settled by its type as
                // much as an integer's are by DER: bytes outside the type's
                // alphabet, a width that is not whole, or a unit that is not
                // a character wear the tag without being a value of it
                // (X.680 41). The scan streams and counts rather than
                // decoding into a copy, so a value the element limit permits
                // costs its length and not its size in memory.
                _ if strings == Strings::Checked => {
                    // The scan walks every character, and a preserved value
                    // has no ceiling of its own: the length is charged to
                    // the shared work budget first, so a caller who bounded
                    // the work gets the bound here as everywhere else.
                    parent
                        .charge(element.contents().len() as u64)
                        .field(field)?;
                    let value = AttributeValue {
                        tag,
                        contents: element.contents(),
                        der: element.as_bytes(),
                        offset: element.span().start,
                        depth: parent.depth(),
                    };
                    // TeletexString is left out of this, as it is left out
                    // of the shape question a name asks: its repertoire is
                    // T.61, a negotiation this crate does not implement, so
                    // the bytes being there is what is checkable. What the
                    // alphabet below says about it is the approximation
                    // this crate reads it as for display, and holding a
                    // preserved value to that would refuse a legacy value
                    // the schema names.
                    let settled = !matches!(value.encoding(), Encoding::Other | Encoding::Teletex);
                    if settled && value.validated_count(|_| true).is_none() {
                        return Err(fail(ErrorCode::MalformedValue));
                    }
                }
                // What is left is what the encoding does not settle, and it
                // is left on purpose. The graphic and general strings and
                // the object descriptor carry a repertoire that is
                // negotiated rather than fixed (X.680 41, and the same
                // reasoning as the teletex string a name may hold). The
                // types that write a time as characters, and the two that
                // write an identifier as an internationalized resource
                // name, are settled by a syntax rather than by the octets,
                // and none of them has a reader here because no schema this
                // product parses names one; checking them would mean
                // writing a parser whose only caller is this check.
                _ => (),
            }
        }
        return Ok(false);
    }
    Ok(true)
}

fn useful_time_fits(parent: &Reader<'_>, element: &Element<'_>, field: &'static str) -> Result<()> {
    let generalized = element.tag().number() == Some(universal::GENERALIZED_TIME);
    let bytes = element.contents();
    if parent.encoding().is_der() {
        parent.charge(bytes.len() as u64).field(field)?;
        if generalized {
            crate::temporal::admit_generalized(parent, element, field)?;
        }
        crate::time::read_as(element, field, crate::time::Fraction::Written)?;
    } else {
        let work = (bytes.len() as u64).checked_mul(3).ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                element.span().start,
            )
        })?;
        parent.charge(work).field(field)?;
        if !crate::time::ber_fits(bytes, generalized) {
            return Err(Error::new(
                ErrorCode::MalformedTime,
                field,
                element.span().start,
            ));
        }
    }
    Ok(())
}

/// BER permits segmentation only for bit/octet strings and the restricted
/// character strings, including the useful time types implicitly based on
/// `VisibleString`. It does not change primitive-only scalar encodings.
/// X.690 §§8.6, 8.7, 8.23; X.680 §§46.3, 47.3, 48.3.
/// <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
fn segmented_universal_type(number: u32) -> bool {
    matches!(number, 3 | 4 | 7 | 12 | 18..=28 | 30)
}

/// Whether the bytes stay inside the `IA5String` alphabet, the 128-character
/// IRV (X.680, 41.4): a byte above 0x7f wears the tag but is not the type.
pub(crate) fn is_ia5(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii)
}

/// Whether the bytes stay inside the `NumericString` alphabet, digits and
/// space (X.680, 41.2).
pub(crate) fn is_numeric(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte.is_ascii_digit() || byte == b' ')
}

/// Whether the bytes stay inside the closed `PrintableString` alphabet of
/// X.680, 41.4.
pub(crate) fn is_printable(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte.is_ascii() && is_printable_string(char::from(byte)))
}

/// Whether a character belongs to the `PrintableString` alphabet, which X.680
/// closes over letters, digits, space and a short list of punctuation.
pub(crate) fn is_printable_string(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
        )
}

/// Whether two adjacent members of a set are in the order DER requires:
/// ascending as octet strings, the shorter compared as if padded at its end
/// with zeroes. Equal members are permitted, which is how a genuine duplicate
/// is encoded.
pub(crate) fn der_set_ordered(previous: &[u8], next: &[u8]) -> bool {
    let length = previous.len().max(next.len());
    for position in 0..length {
        let left = previous.get(position).copied().unwrap_or(0);
        let right = next.get(position).copied().unwrap_or(0);
        if left != right {
            return left < right;
        }
    }
    true
}

/// Decodes a string of characters `width` bytes each.
/// Counts the characters of a wide string without building one: the size
/// constraint on such a value is in characters, and answering it is all a
/// gate needs. `None` is a value that does not decode.
pub(crate) fn wide_char_count(contents: &[u8], width: usize) -> Option<usize> {
    if !contents.len().is_multiple_of(width) {
        return None;
    }
    let mut count = 0usize;
    for character in wide_chars(contents, width) {
        character?;
        count += 1;
    }
    Some(count)
}

/// The same reading, stopped one character past the bound a report shows.
///
/// A unit that is not a character still refuses the whole value, as it does
/// when the value is read entire; the difference is only that the units past
/// the bound are not looked at, because they are not going to be shown.
fn display_text(
    mut characters: impl Iterator<Item = Option<char>>,
    execution: &Memory,
) -> core::result::Result<Option<OwnedString>, structured_asn1::memory::MemoryError> {
    let mut text = execution.string();
    for index in 0..=DISPLAY_CEILING {
        execution.charge_work(1)?;
        let Some(character) = characters.next() else {
            break;
        };
        let Some(character) = character else {
            return Ok(None);
        };
        if index == DISPLAY_CEILING {
            text.try_push('…')?;
            break;
        }
        text.try_push(character)?;
    }
    Ok(Some(text))
}

/// Reads a name from an element a schema said is one.
///
/// It is public for the same reason as [`crate::algorithm::read`]: a signed
/// message names a signer by the issuer name of its certificate, and comparing
/// that against a certificate requires both to have been read by the same
/// rules. A second reader would be a second answer to which encodings of a
/// name are the same name.
/// Catalogue allocation and copying use the producing reader's local work
/// ceiling and current aggregate account. A successful result retains its
/// capacity charge until it is dropped; the borrowed input lifetime is unchanged.
///
/// # Errors
///
/// Reports encoding faults or resource refusals with the original field and
/// source position.
pub fn read<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<Name<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut sequence = parent.enter(element).field(field)?;
    let mut parts = parent.execution().vector();

    while let Some(part) = sequence.next_element().field(field)? {
        if part.tag() != Tag::constructed(universal::SET) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                field,
                part.span().start,
            ));
        }
        parts
            .try_push(read_relative(&sequence, &part, field)?)
            .map_err(|reason| Error::resource(reason, field, part.span().start))?;
    }

    Ok(Name {
        der: element.as_bytes(),
        parts: parts.into_owned(),
        offset: element.span().start,
        field,
    })
}

/// Reads one part of a name, which a distribution point carries on its own.
///
/// The tag belongs to the caller: here it is the set the schema names, and in
/// a distribution point it is the number that position gives it.
pub(crate) fn read_relative<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<RelativeName<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    let mut inside = parent.enter(element).field(field)?;
    let mut attributes = parent.execution().vector();
    let mut previous: Option<&[u8]> = None;
    while let Some(pair) = inside.next_element().field(field)? {
        // DER orders the members of a set by their encodings, ascending, and
        // the comparison of names deliberately ignores order. Without this
        // check an unsorted part would match a correctly sorted one, and a
        // malformed issuer could take part in a path. The comparison walks
        // up to the longer encoding, so that length is charged to the
        // shared work budget before the walk: a caller bounding work sees
        // two huge common-prefix members on the same meter the reads use.
        if inside.encoding().is_der()
            && let Some(previous) = previous
            && {
                inside
                    .charge(previous.len().max(pair.as_bytes().len()) as u64)
                    .field(field)?;
                !der_set_ordered(previous, pair.as_bytes())
            }
        {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                field,
                pair.span().start,
            ));
        }
        previous = Some(pair.as_bytes());
        attributes
            .try_push(read_attribute(&inside, &pair, field)?)
            .map_err(|reason| Error::resource(reason, field, pair.span().start))?;
    }

    // A part with nothing in it names nothing, and two names that differ only
    // by one of these would compare as different names.
    if attributes.is_empty() {
        return Err(fail(ErrorCode::EmptySequence));
    }

    Ok(RelativeName {
        attributes: attributes.into_owned(),
    })
}

fn read_attribute<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<Attribute<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut pair = parent.enter(element).field(field)?;
    let kind = pair.read_oid().field(field)?;
    let value = pair
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;

    // Even an unknown kind's opaque value must be DER before it is
    // preserved: what is kept here is compared against the same attribute in
    // another certificate, and a second spelling of one value would be a
    // different name for the same holder.
    walk_der(&pair, &value, field, Strings::AsWritten)?;

    if !pair.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    Ok(Attribute {
        kind,
        value: AttributeValue {
            tag: value.tag(),
            contents: value.contents(),
            der: value.as_bytes(),
            offset: value.span().start,
            depth: pair.depth(),
        },
    })
}

#[cfg(test)]
mod tests;
