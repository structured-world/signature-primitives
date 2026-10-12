//! What a certificate may certify below itself.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::general_name::{self, GeneralName};
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{Tag, universal};

/// A count of certificates a constraint names.
///
/// The fields counted here are `INTEGER (0..MAX)` (RFC 5280 4.2.1.9, 4.2.1.11
/// and 4.2.1.14), so a count wider than any path that could be built is inside
/// the schema. It is kept as what it is, a bound nothing reaches, rather than
/// refused as malformed or folded into a number the certificate never wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateCount {
    /// The count the certificate names.
    Certificates(u32),
    /// A count past what a path could hold, which therefore never binds.
    BeyondAnyPath,
}

impl CertificateCount {
    /// The count where a path could reach it, and `None` where nothing can.
    #[must_use]
    pub fn certificates(self) -> Option<u32> {
        match self {
            Self::Certificates(count) => Some(count),
            Self::BeyondAnyPath => None,
        }
    }

    /// Whether the count is zero, which is the only value some fields permit.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self == Self::Certificates(0)
    }
}

/// Whether this is a certification authority, and how far below it a path may
/// go.
#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    authority: bool,
    path_length: Option<CertificateCount>,
}

impl BasicConstraints {
    /// Whether the certificate may sign other certificates.
    #[must_use]
    pub fn is_authority(self) -> bool {
        self.authority
    }

    /// How many certificates may sit between this one and the one at the end
    /// of the path, where the certificate says.
    ///
    /// Written without the flag above it constrains nothing, and is kept as
    /// what the certificate said rather than dropped.
    #[must_use]
    pub fn path_length(self) -> Option<CertificateCount> {
        self.path_length
    }

    /// Reads the value of a basic constraints extension.
    pub fn read(extension: &Extension<'_>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.basicConstraints";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;

        // Absent means not an authority, which is what a certificate issued to
        // a person leaves it at.
        let mut authority = false;
        let mut path_length = None;

        let mut next = inside.next_element().field(FIELD)?;
        if let Some(flag) = next
            && flag.tag() == Tag::primitive(universal::BOOLEAN)
        {
            authority = inside.boolean(&flag).field(FIELD)?;
            // X.690 11.5: DER omits a component equal to its default, and the
            // flag defaults to false. Writing it out is a second spelling of
            // the absent flag.
            if !authority && inside.encoding().is_der() {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    FIELD,
                    flag.span().start,
                ));
            }
            next = inside.next_element().field(FIELD)?;
        }

        if let Some(length) = next {
            if length.tag() != Tag::primitive(universal::INTEGER) {
                return Err(fail(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
            // The path length must not be present unless the authority flag
            // is asserted (RFC 5280 4.2.1.9): without it, the value
            // constrains a path below a certificate that says it heads none.
            if !authority {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    FIELD,
                    length.span().start,
                ));
            }
            path_length = Some(read_count(&inside, &length, FIELD)?);
        }

        if !inside.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        Ok(Self {
            authority,
            path_length,
        })
    }
}

/// The name space a certification authority may certify within.
#[derive(Debug)]
pub struct NameConstraints<'a> {
    permitted: OwnedVec<Subtree<'a>>,
    excluded: OwnedVec<Subtree<'a>>,
}

/// One region of the name space, as a name every name in it sits under. The
/// region starts at its base: the profile requires the minimum distance to
/// be zero and the maximum to be absent, and a subtree written otherwise is
/// refused when it is read.
#[derive(Debug)]
pub struct Subtree<'a> {
    base: GeneralName<'a>,
}

impl<'a> Subtree<'a> {
    /// The name the region is described by.
    #[must_use]
    pub fn base(&self) -> &GeneralName<'a> {
        &self.base
    }
}

impl<'a> NameConstraints<'a> {
    /// The regions names below this certificate must sit in.
    #[must_use]
    pub fn permitted(&self) -> &[Subtree<'a>] {
        &self.permitted
    }

    /// The regions they must not.
    #[must_use]
    pub fn excluded(&self) -> &[Subtree<'a>] {
        &self.excluded
    }

    /// Reads the value of a name constraints extension.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.nameConstraints";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let mut constraints = Self {
            permitted: inside.memory().vector(),
            excluded: inside.memory().vector(),
        };

        // The schema fixes the order: permitted, then excluded. A tag at or
        // below the last one read is a repeat or a field written backwards,
        // and neither is this schema.
        let mut last_number = None;
        while let Some(field) = inside.next_element().field(FIELD)? {
            let tag = extension::context_of(field.tag());
            let subtrees = match tag {
                Some((0, true)) if last_number.is_none() => &mut constraints.permitted,
                Some((1, true)) if last_number < Some(1) => &mut constraints.excluded,
                _ => {
                    return Err(Error::new(
                        ErrorCode::UnexpectedField,
                        FIELD,
                        field.span().start,
                    ));
                }
            };
            last_number = tag.map(|(number, _)| number);

            let mut list = inside.enter(&field).field(FIELD)?;
            while let Some(entry) = list.next_element().field(FIELD)? {
                subtrees
                    .try_push(read_subtree(&list, &entry, FIELD)?)
                    .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
            }
            if subtrees.is_empty() {
                return Err(Error::new(
                    ErrorCode::EmptySequence,
                    FIELD,
                    field.span().start,
                ));
            }
        }

        // A constraint that permits nothing and excludes nothing constrains
        // nothing, while being marked critical to say it must be obeyed.
        if constraints.permitted.is_empty() && constraints.excluded.is_empty() {
            return Err(fail(ErrorCode::MalformedValue));
        }
        Ok(constraints)
    }
}

/// Limits on how policies are processed below this certificate.
#[derive(Debug, Clone, Copy)]
pub struct PolicyConstraints {
    require_explicit_policy: Option<CertificateCount>,
    inhibit_policy_mapping: Option<CertificateCount>,
}

impl PolicyConstraints {
    /// After how many certificates a path must name a policy.
    #[must_use]
    pub fn require_explicit_policy(self) -> Option<CertificateCount> {
        self.require_explicit_policy
    }

    /// After how many certificates policy mappings stop being honoured.
    #[must_use]
    pub fn inhibit_policy_mapping(self) -> Option<CertificateCount> {
        self.inhibit_policy_mapping
    }

    /// Reads the value of a policy constraints extension.
    pub fn read(extension: &Extension<'_>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.policyConstraints";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let mut constraints = Self {
            require_explicit_policy: None,
            inhibit_policy_mapping: None,
        };

        // Fixed order here too: a tag at or below the last one read is not
        // this schema.
        let mut last_number = None;
        while let Some(field) = inside.next_element().field(FIELD)? {
            let tag = extension::context_of(field.tag());
            match tag {
                Some((0, false)) if last_number.is_none() => {
                    constraints.require_explicit_policy = Some(read_count(&inside, &field, FIELD)?);
                }
                Some((1, false)) if last_number < Some(1) => {
                    constraints.inhibit_policy_mapping = Some(read_count(&inside, &field, FIELD)?);
                }
                _ => {
                    return Err(Error::new(
                        ErrorCode::UnexpectedField,
                        FIELD,
                        field.span().start,
                    ));
                }
            }
            last_number = tag.map(|(number, _)| number);
        }

        // Neither field written is an extension that says nothing.
        if constraints.require_explicit_policy.is_none()
            && constraints.inhibit_policy_mapping.is_none()
        {
            return Err(fail(ErrorCode::MalformedValue));
        }
        Ok(constraints)
    }
}

/// After how many certificates the identifier standing for any policy stops
/// being accepted.
#[derive(Debug, Clone, Copy)]
pub struct InhibitAnyPolicy {
    skip: CertificateCount,
}

impl InhibitAnyPolicy {
    /// How many certificates it survives.
    #[must_use]
    pub fn skip(self) -> CertificateCount {
        self.skip
    }

    /// Reads the value of an inhibit-any-policy extension.
    pub fn read(extension: &Extension<'_>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.inhibitAnyPolicy";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut reader = extension.reader(execution).field(FIELD)?;
        let element = reader
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| fail(ErrorCode::MissingField))?;
        if element.tag() != Tag::primitive(universal::INTEGER) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        let skip = read_count(&reader, &element, FIELD)?;
        if !reader.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        Ok(Self { skip })
    }
}

fn read_subtree<'a>(
    parent: &structured_asn1::Reader<'a>,
    element: &structured_asn1::Element<'a>,
    field: &'static str,
) -> Result<Subtree<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut inside = parent.enter(element).field(field)?;
    let base_element = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let base = general_name::read_as(
        &inside,
        &base_element,
        field,
        general_name::AddressForm::WithMask,
    )?;

    // The profile requires the minimum to be zero and the maximum to be
    // absent (RFC 5280 4.2.1.10): either written otherwise asks for a
    // reading this profile does not define. Zero spelled out is refused
    // under DER as a second spelling of the absent default (X.690 11.5) and
    // read under BER, which carries no such rule.
    let mut last_number = None;
    while let Some(distance) = inside.next_element().field(field)? {
        let tag = extension::context_of(distance.tag());
        match tag {
            Some((0, false)) if last_number.is_none() => {
                let count = read_count(&inside, &distance, field)?;
                if !count.is_zero() || inside.encoding().is_der() {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        field,
                        distance.span().start,
                    ));
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    field,
                    distance.span().start,
                ));
            }
        }
        last_number = tag.map(|(number, _)| number);
    }

    Ok(Subtree { base })
}

/// Reads a count of certificates, which is never negative.
fn read_count(
    parent: &structured_asn1::Reader<'_>,
    element: &structured_asn1::Element<'_>,
    field: &'static str,
) -> Result<CertificateCount> {
    let value = parent.integer(element).field(field)?;
    // Below zero is outside the schema, which bounds every one of these
    // fields at zero (RFC 5280 4.2.1.9, 4.2.1.11, 4.2.1.14).
    if value.is_negative() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            element.span().start,
        ));
    }
    // Above the type is still inside the schema, whose upper bound is MAX:
    // the count is understood, and what it says is that nothing reaches it.
    Ok(value.as_u32().map_or(
        CertificateCount::BeyondAnyPath,
        CertificateCount::Certificates,
    ))
}

#[cfg(test)]
mod tests;
