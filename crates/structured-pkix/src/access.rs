//! Where things related to a certificate are published.
//!
//! Every location here is text. Nothing in this crate resolves one, and
//! nothing above it may resolve one without a person choosing to: a parser
//! that fetched a location a document named would ask a server chosen by
//! whoever wrote the document to confirm what the document says, and would
//! tell that server which document is being looked at.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::general_name::{self, GeneralName};
use crate::name::{self, RelativeName};
use crate::oid;
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_asn1::{BitString, Element, Oid, Reader, Tag, universal};

/// One published service or document, and where it is.
#[derive(Debug)]
pub struct AccessDescription<'a> {
    method: Oid<'a>,
    location: GeneralName<'a>,
    at: u64,
}

impl<'a> AccessDescription<'a> {
    /// What sits at the location.
    #[must_use]
    pub fn method(&self) -> Oid<'a> {
        self.method
    }

    /// Where it is, unresolved.
    #[must_use]
    pub fn location(&self) -> &GeneralName<'a> {
        &self.location
    }
}

/// The access descriptions of one extension, whether about the issuer or about
/// the subject.
#[derive(Debug)]
pub struct InfoAccess<'a> {
    descriptions: OwnedVec<AccessDescription<'a>>,
    field: &'static str,
}

impl<'a> InfoAccess<'a> {
    /// Every description, in order.
    #[must_use]
    pub fn descriptions(&self) -> &[AccessDescription<'a>] {
        &self.descriptions
    }

    /// The locations published for one method. Each comparison is admitted
    /// in the current execution domain; an error is yielded once and ends
    /// the iterator. Returned locations borrow this collection.
    pub fn locations_for<'n, 'q>(
        &'n self,
        method: Oid<'q>,
        execution: &'q Memory,
    ) -> impl Iterator<Item = Result<&'n GeneralName<'a>>> + 'q
    where
        'n: 'q,
    {
        let mut descriptions = self.descriptions.iter();
        let mut failed = false;
        core::iter::from_fn(move || {
            if failed {
                return None;
            }
            for description in descriptions.by_ref() {
                let work = 1 + description
                    .method
                    .as_bytes()
                    .len()
                    .max(method.as_bytes().len()) as u64;
                if let Err(reason) = execution.charge_work(work) {
                    failed = true;
                    return Some(Err(Error::resource(reason, self.field, description.at)));
                }
                if description.method == method {
                    return Some(Ok(description.location()));
                }
            }
            None
        })
    }

    /// Reads the value of an authority or subject information access
    /// extension, which have the same shape.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        let field = if extension.kind() == oid::SUBJECT_INFO_ACCESS {
            "extensions.subjectInfoAccess"
        } else {
            "extensions.authorityInfoAccess"
        };

        let mut inside = extension::sequence(extension, field, execution)?;
        let work = inside.execution_in(execution);
        let mut descriptions = work.vector();

        while let Some(entry) = inside.next_element().field(field)? {
            let at = |code| Error::new(code, field, entry.span().start);
            if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(at(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }

            let mut pair = inside.enter(&entry).field(field)?;
            let method = pair.read_oid().field(field)?;
            let location = pair
                .next_element()
                .field(field)?
                .ok_or_else(|| at(ErrorCode::MissingField))?;
            let location = general_name::read(&pair, &location, field)?;
            if !pair.is_empty() {
                return Err(at(ErrorCode::TrailingData));
            }

            descriptions
                .try_push(AccessDescription {
                    method,
                    location,
                    at: entry.span().start,
                })
                .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
        }

        if descriptions.is_empty() {
            return Err(Error::new(
                ErrorCode::EmptySequence,
                field,
                extension.span().start,
            ));
        }
        Ok(Self {
            descriptions: descriptions.into_owned(),
            field,
        })
    }
}

/// One place a revocation list covering this certificate is published.
#[derive(Debug)]
pub struct DistributionPoint<'a> {
    full_name: OwnedVec<GeneralName<'a>>,
    name_relative_to_issuer: Option<RelativeName<'a>>,
    reasons: Option<BitString<'a>>,
    issuer: OwnedVec<GeneralName<'a>>,
}

impl<'a> DistributionPoint<'a> {
    /// Where the list is, where the point names it outright.
    #[must_use]
    pub fn full_name(&self) -> &[GeneralName<'a>] {
        &self.full_name
    }

    /// Where the list is, where the point names it relative to whoever issues
    /// it rather than outright.
    #[must_use]
    pub fn name_relative_to_issuer(&self) -> Option<&RelativeName<'a>> {
        self.name_relative_to_issuer.as_ref()
    }

    /// Which reasons for revocation this list covers, where the point says.
    /// Absent means all of them, and a point that names a few is not a list a
    /// complete answer can be built from on its own.
    #[must_use]
    pub fn reasons(&self) -> Option<BitString<'a>> {
        self.reasons
    }

    /// Who issues the list, where that is not the issuer of the certificate.
    #[must_use]
    pub fn issuer(&self) -> &[GeneralName<'a>] {
        &self.issuer
    }
}

/// The places revocation lists covering this certificate are published.
#[derive(Debug)]
pub struct DistributionPoints<'a> {
    points: OwnedVec<DistributionPoint<'a>>,
}

impl<'a> DistributionPoints<'a> {
    /// Every point, in order.
    #[must_use]
    pub fn points(&self) -> &[DistributionPoint<'a>] {
        &self.points
    }

    /// Reads the value of a distribution points extension, which the freshest
    /// revocation list is published in the same shape as.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        let field = if extension.kind() == oid::FRESHEST_CRL {
            "extensions.freshestCRL"
        } else {
            "extensions.cRLDistributionPoints"
        };

        let mut inside = extension::sequence(extension, field, execution)?;
        let work = inside.execution_in(execution);
        let mut points = work.vector();
        while let Some(entry) = inside.next_element().field(field)? {
            points
                .try_push(read_point(&inside, &entry, field)?)
                .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
        }

        if points.is_empty() {
            return Err(Error::new(
                ErrorCode::EmptySequence,
                field,
                extension.span().start,
            ));
        }
        Ok(Self {
            points: points.into_owned(),
        })
    }
}

fn read_point<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<DistributionPoint<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut inside = parent.enter(element).field(field)?;
    let mut point = DistributionPoint {
        full_name: parent.memory().vector(),
        name_relative_to_issuer: None,
        reasons: None,
        issuer: parent.memory().vector(),
    };

    // The three fields are written in the order of their numbers, once each:
    // a tag at or below the last one read is not this schema.
    let mut last_number = None;
    while let Some(entry) = inside.next_element().field(field)? {
        let tag = extension::context_of(entry.tag());
        match tag {
            Some((0, true)) if last_number.is_none() => {
                read_point_name(&inside, &entry, field, &mut point)?;
            }
            Some((1, false)) if last_number < Some(1) => {
                let reasons = inside.bit_string(&entry).field(field)?;
                // The zero walk below touches every content byte, so it is
                // charged to the shared work budget first.
                inside
                    .charge(reasons.as_bytes().len() as u64)
                    .field(field)?;
                // Present while naming no reason, the field covers none while
                // claiming to narrow the list: a reader would take the point
                // for a partial list and a full one at once. Absent is how
                // "all reasons" is said. Written as zero bits, as zero bytes,
                // or with only bit zero, which the schema names "unused" and
                // gives no meaning (RFC 5280 4.2.1.13), it says the same
                // nothing: a scope whose only member means nothing has no
                // members.
                if !(1..=8).any(|bit| reasons.bit(bit)) {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        field,
                        entry.span().start,
                    ));
                }
                // A named bit list under DER: X.690 11.2.2 trims trailing
                // zero bits, and RFC 5280 4.2.1.13 names bits 0 through 8, so
                // a longer string carries a bit with no name. unused(0) is
                // deliberately readable: it is a named bit of the schema, and
                // RFC 5280 gives it no meaning but no prohibition either;
                // what a set bit means is the revocation evidence's question.
                if inside.encoding().is_der()
                    && (reasons.len() > 9
                        || (!reasons.is_empty() && !reasons.bit(reasons.len() - 1)))
                {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        field,
                        entry.span().start,
                    ));
                }
                point.reasons = Some(reasons);
            }
            Some((2, true)) if last_number < Some(2) => {
                let issuer = general_name::read_all(&inside, &entry, field)?;
                // The profile is explicit that this is exclusive: a present
                // cRLIssuer "MUST only contain the distinguished name (DN)
                // from the issuer field of the CRL" (RFC 5280 4.2.1.13), so
                // every member is required to be a directory name, not
                // merely one of them. Any other form cannot be matched
                // against a list's issuer field anyway. Several directory
                // names stay permitted: the same section contemplates them
                // by forbidding only the relative alternative "when
                // cRLIssuer contains more than one distinguished name", the
                // check below, because the relative fragment appends to
                // exactly one name and with two there is no answer to which
                // list the point names.
                if !issuer
                    .iter()
                    .all(|name| matches!(name, general_name::GeneralName::Directory(_)))
                    || (point.name_relative_to_issuer.is_some() && issuer.len() > 1)
                {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        field,
                        entry.span().start,
                    ));
                }
                point.issuer = issuer;
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    field,
                    entry.span().start,
                ));
            }
        }
        last_number = tag.map(|(number, _)| number);
    }

    // A point must say where the list is or who issues it. With neither, it
    // names no source a list could ever be resolved from, and reporting it as
    // parsed would count a malformed extension as a working one. A relative
    // name WITHOUT a cRLIssuer stays valid on its own: the profile appends
    // the fragment to the certificate issuer's distinguished name when the
    // issuer field is absent (RFC 5280 4.2.1.13), so the point still names a
    // resolvable source. Reasons beside a cRLIssuer with no point name stay
    // valid too: the only shape rule the profile states is that a point
    // "MUST NOT consist of only the reasons field; either distributionPoint
    // or cRLIssuer MUST be present" (RFC 5280 4.2.1.13), and no sentence
    // requires a point name beside reasons; the list is then located
    // through the issuer's directory entry, its reason scope intact.
    if point.full_name.is_empty()
        && point.name_relative_to_issuer.is_none()
        && point.issuer.is_empty()
    {
        return Err(fail(ErrorCode::MalformedValue));
    }

    Ok(point)
}

/// Reads the name of a point, which is a choice between naming the list
/// outright and naming it under whoever issues it. A choice cannot take the
/// tag of its position, so the field wraps it.
#[derive(Debug)]
pub(crate) enum PointName<'a> {
    Full(OwnedVec<GeneralName<'a>>),
    Relative(RelativeName<'a>),
}

/// Shared `DistributionPointName` grammar for certificate DPs and CRL IDPs.
pub(crate) fn read_distribution_name<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<PointName<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);
    let mut inside = parent.enter(element).field(field)?;
    let chosen = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let name = match extension::context_of(chosen.tag()) {
        Some((0, true)) => PointName::Full(general_name::read_locations(&inside, &chosen, field)?),
        Some((1, true)) => {
            let relative = name::read_relative(&inside, &chosen, field)?;
            for attribute in relative.attributes() {
                if !name::well_formed_in(attribute, &inside, field)? {
                    return Err(fail(ErrorCode::MalformedValue));
                }
            }
            PointName::Relative(relative)
        }
        _ => {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    };
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    Ok(name)
}

fn read_point_name<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    point: &mut DistributionPoint<'a>,
) -> Result<()> {
    match read_distribution_name(parent, element, field)? {
        PointName::Full(names) => point.full_name = names,
        PointName::Relative(name) => point.name_relative_to_issuer = Some(name),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
