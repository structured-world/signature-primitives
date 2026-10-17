//! Original CMS attribute values and the exact retagged signed range.

use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{Execution, Memory, OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, Span, Tag, universal};

/// The schema placement of an attribute set, not deployment policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// `[0] IMPLICIT SignedAttributes`, required to be DER.
    Signed,
    /// `[1] IMPLICIT UnsignedAttributes`, permitted to use BER.
    Unsigned,
}

impl Placement {
    fn field(self) -> &'static str {
        match self {
            Self::Signed => "signerInfo.signedAttrs",
            Self::Unsigned => "signerInfo.unsignedAttrs",
        }
    }
    fn tag(self) -> Tag {
        Tag::context(
            true,
            match self {
                Self::Signed => 0,
                Self::Unsigned => 1,
            },
        )
    }
}

/// One original attribute, preserving all values without interpreting unknown syntax.
#[derive(Debug)]
pub struct Attribute<'a> {
    kind: Oid<'a>,
    values: OwnedVec<Element<'a>>,
    element: Element<'a>,
    parser: &'a Parser,
    depth: u32,
    encoding: Encoding,
}

impl<'a> Attribute<'a> {
    fn read(parent: &Reader<'a>, element: &Element<'a>, field: &'static str) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                field,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, field))?;
        let kind = inside
            .read_oid()
            .map_err(|error| Error::encoding(error, field))?;
        let set = inside
            .expect(Tag::constructed(universal::SET))
            .map_err(|error| Error::encoding(error, field))?;
        let mut members = inside
            .enter(&set)
            .map_err(|error| Error::encoding(error, field))?;
        let execution = parent.execution();
        let mut values = execution.vector();
        let mut previous = None;
        // RFC5652 §§5.3/12.1: attrValues is SET OF AttributeValue without SIZE.
        // The nonempty bound belongs to SignedAttributes/UnsignedAttributes,
        // not this inner set. Registered attribute rules impose their own
        // cardinality in binding/counter/ESS processing; unknown syntax cannot
        // inherit a blanket lower bound from the outer collection.
        // https://www.rfc-editor.org/rfc/rfc5652#section-5.3
        while let Some(value) = members
            .next_element()
            .map_err(|error| Error::encoding(error, field))?
        {
            if members.encoding().is_der() {
                structured_pkix::der::conforms(&members, &value, field).map_err(Error::pkix)?;
                if let Some(earlier) = previous
                    && !structured_pkix::der::set_ordered(&members, earlier, &value, field)
                        .map_err(Error::pkix)?
                {
                    return Err(Error::schema(
                        ErrorCode::AttributeOrder,
                        field,
                        value.span().start,
                    ));
                }
                previous = Some(value.as_bytes());
            }
            values
                .try_push(value)
                .map_err(|reason| Error::resource(reason, field, value.span().start))?;
        }
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                field,
                inside.offset(),
            ));
        }
        Ok(Self {
            kind,
            values: values.into_owned(),
            element: *element,
            parser: members.parser(),
            depth: members.depth(),
            encoding: members.encoding(),
        })
    }

    /// The original attribute identifier.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }

    /// Every original value, including unknown or generically empty value sets.
    #[must_use]
    pub fn values(&self) -> &[Element<'a>] {
        &self.values
    }

    /// The original attribute source range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }

    /// The original encoded attribute without normalization.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }

    /// Opens one original value in the current account and inherited parser depth.
    ///
    /// The index selects this attribute's catalogue, so a foreign element cannot
    /// be rebound to its provenance. No serialized bridge or replacement parser
    /// is used. Missing indices are absence; resource refusal remains an error.
    pub fn value_reader(
        &self,
        index: usize,
        execution: &Memory,
        field: &'static str,
    ) -> Result<Option<Reader<'a>>> {
        let Some(value) = self.selected_value(index, execution, field)? else {
            return Ok(None);
        };
        debug_assert!(self.depth > 0);
        self.parser
            .read_nested_in(
                value.as_bytes(),
                value.span().start,
                self.encoding,
                self.depth - 1,
                execution,
            )
            .map(Some)
            .map_err(|error| Error::encoding(error, field))
    }

    /// Opens one original value with producing local and current aggregate work.
    /// A foreign parser session refuses before lookup/allocation; it cannot
    /// silently replace the current producing ceiling with this value's old one.
    pub fn value_reader_in<'query>(
        &self,
        index: usize,
        parent: &Reader<'query>,
        field: &'static str,
    ) -> Result<Option<Reader<'query>>>
    where
        'a: 'query,
    {
        if !core::ptr::eq(self.parser, parent.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                field,
                self.element.span().start,
            )));
        }
        let Some(value) = self.selected_value(index, &parent.execution(), field)? else {
            return Ok(None);
        };
        debug_assert!(self.depth > 0);
        self.parser
            .read_nested_query_in(
                parent,
                value.as_bytes(),
                value.span().start,
                self.encoding,
                self.depth - 1,
            )
            .map(Some)
            .map_err(|error| Error::encoding(error, field))
    }

    fn selected_value<W: Work>(
        &self,
        index: usize,
        execution: &W,
        field: &'static str,
    ) -> Result<Option<Element<'a>>> {
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, self.element.span().start))?;
        Ok(self.values.get(index).copied())
    }

    /// Requires a singleton for attribute types whose specific schema demands it.
    pub fn single(&self, field: &'static str) -> Result<&Element<'a>> {
        match &*self.values {
            [value] => Ok(value),
            _ => Err(Error::schema(
                ErrorCode::AttributeCardinality,
                field,
                self.element.span().start,
            )),
        }
    }
}

/// An original attribute set with independently retained catalogue storage.
#[derive(Debug)]
pub struct Attributes<'a> {
    items: OwnedVec<Attribute<'a>>,
    element: Element<'a>,
    placement: Placement,
}

impl<'a> Attributes<'a> {
    /// Reads nonempty attributes in their trusted schema placement.
    ///
    /// RFC5652 §5.3 requires nonempty Signed/UnsignedAttributes. Signed sets
    /// are reread under DER through the same parser, not repaired or re-encoded.
    /// Generic attributes preserve unknown instances; per-type cardinality and
    /// placement checks are separate (§§11.1–11.4, RFC6211 §2).
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-5.3>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>, placement: Placement) -> Result<Self> {
        let reading = Self::read_inspection(parent, element, placement)?;
        if let Some(fault) = reading.fault() {
            return Err(fault);
        }
        Ok(reading)
    }

    /// Reads original attributes while retaining a uniquely bounded empty set.
    ///
    /// An empty outer set violates RFC5652 §5.3 and is exposed by [`Self::fault`].
    /// This inspection recovery does not relax signed DER, member syntax or
    /// binding requirements. It preserves presence rather than treating an
    /// invalid written set as absent.
    pub fn read_inspection(
        parent: &Reader<'a>,
        element: &Element<'a>,
        placement: Placement,
    ) -> Result<Self> {
        if element.tag() != placement.tag() {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                placement.field(),
                element.span().start,
            ));
        }
        if placement == Placement::Signed {
            let mut strict = parent
                .reread(element, Encoding::Der)
                .map_err(|error| Error::encoding(error, placement.field()))?;
            let original = strict
                .expect(placement.tag())
                .map_err(|error| Error::encoding(error, placement.field()))?;
            Self::read_set(&strict, &original, placement)
        } else {
            Self::read_set(parent, element, placement)
        }
    }

    fn read_set(parent: &Reader<'a>, element: &Element<'a>, placement: Placement) -> Result<Self> {
        let field = placement.field();
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, field))?;
        let execution = parent.execution();
        let mut items = execution.vector();
        let mut previous = None;
        while let Some(member) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, field))?
        {
            if inside.encoding().is_der() {
                if let Some(earlier) = previous
                    && !structured_pkix::der::set_ordered(&inside, earlier, &member, field)
                        .map_err(Error::pkix)?
                {
                    return Err(Error::schema(
                        ErrorCode::AttributeOrder,
                        field,
                        member.span().start,
                    ));
                }
                previous = Some(member.as_bytes());
            }
            let attribute = Attribute::read(&inside, &member, field)?;
            items
                .try_push(attribute)
                .map_err(|reason| Error::resource(reason, field, member.span().start))?;
        }
        Ok(Self {
            items: items.into_owned(),
            element: *element,
            placement,
        })
    }

    /// The located nonempty-bound violation, without allocating diagnostics.
    ///
    /// Original signed bytes remain available for inspection; this fault must
    /// be refused before preparing a cryptographic operation.
    #[must_use]
    pub fn fault(&self) -> Option<Error> {
        if self.items.is_empty() {
            return Some(Error::schema(
                ErrorCode::EmptyAttributes,
                self.placement.field(),
                self.element.span().start,
            ));
        }
        None
    }

    /// The original attribute catalogue in encoded order.
    #[must_use]
    pub fn items(&self) -> &[Attribute<'a>] {
        &self.items
    }

    /// The exact range and placement supplied by the schema.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }

    /// Searches every instance with the current retained-query account.
    ///
    /// Lookup errors are yielded once, then iteration stops. Absence is returned
    /// only after the whole admitted search, including its terminal step.
    pub fn all<'s>(&'s self, kind: Oid<'s>, execution: &Memory) -> Matching<'s, 'a> {
        Matching {
            attributes: self,
            kind,
            execution: execution.clone(),
            next: 0,
            stopped: false,
        }
    }

    /// Searches through the producing reader's local and aggregate ceilings.
    pub fn all_in<'s>(
        &'s self,
        kind: Oid<'s>,
        parent: &'s Reader<'_>,
    ) -> Matching<'s, 'a, Execution<'s>> {
        Matching {
            attributes: self,
            kind,
            execution: parent.execution(),
            next: 0,
            stopped: false,
        }
    }

    /// Requires at most one instance for a specifically singleton attribute type.
    ///
    /// Unknown generic types must use [`Self::all_in`] instead: RFC5652 §5.3
    /// does not forbid every repeated attribute identifier.
    pub fn unique_in<'s>(
        &'s self,
        kind: Oid<'s>,
        parent: &'s Reader<'_>,
    ) -> Result<Option<&'s Attribute<'a>>> {
        let mut found = None;
        for result in self.all_in(kind, parent) {
            let attribute = result?;
            if found.is_some() {
                return Err(Error::schema(
                    ErrorCode::AttributeCardinality,
                    self.placement.field(),
                    attribute.span().start,
                ));
            }
            found = Some(attribute);
        }
        Ok(found)
    }

    /// Original signed octets with only the implicit identifier replaced by SET.
    ///
    /// RFC5652 §5.4 requires the SET OF identifier, preserving original DER
    /// length/content. Unsigned sets have no such signed range.
    #[must_use]
    pub fn signed_bytes(&self) -> Option<[&'a [u8]; 2]> {
        if self.placement != Placement::Signed {
            return None;
        }
        Some([&[0x31], &self.element.as_bytes()[1..]])
    }
}

/// Accounted matching instances, with one terminal resource refusal.
pub struct Matching<'s, 'a, W: Work = Memory> {
    attributes: &'s Attributes<'a>,
    kind: Oid<'s>,
    execution: W,
    next: usize,
    stopped: bool,
}

impl<'s, 'a, W: Work> Iterator for Matching<'s, 'a, W> {
    type Item = Result<&'s Attribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.attributes.next_matching(
            self.kind,
            &self.execution,
            &mut self.next,
            &mut self.stopped,
        )
    }
}

impl<'a> Attributes<'a> {
    pub(crate) fn next_matching<'s>(
        &'s self,
        kind: Oid<'_>,
        execution: &impl Work,
        next: &mut usize,
        stopped: &mut bool,
    ) -> Option<Result<&'s Attribute<'a>>> {
        if *stopped {
            return None;
        }
        let field = self.placement.field();
        loop {
            if let Err(reason) = execution.charge_work(1) {
                *stopped = true;
                let at = self
                    .items
                    .get(*next)
                    .map_or(self.element.span().start, |attribute| {
                        attribute.span().start
                    });
                return Some(Err(Error::resource(reason, field, at)));
            }
            let Some(attribute) = self.items.get(*next) else {
                *stopped = true;
                return None;
            };
            *next += 1;
            if attribute.kind.as_bytes().len() != kind.as_bytes().len() {
                continue;
            }
            if let Err(reason) = execution.charge_work(attribute.kind.as_bytes().len() as u64) {
                *stopped = true;
                return Some(Err(Error::resource(reason, field, attribute.span().start)));
            }
            if attribute.kind == kind {
                return Some(Ok(attribute));
            }
        }
    }
}

impl<W: Work> core::iter::FusedIterator for Matching<'_, '_, W> {}
