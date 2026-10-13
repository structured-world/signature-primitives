//! The several kinds of name an extension can carry.
//!
//! Some of these are locations: a distribution point, a status service, a
//! practice statement. They are read as text and nothing here resolves one. A
//! parser that fetched a location a document named would be asking a server
//! chosen by whoever wrote the document to confirm what the document says, and
//! would tell that server which document is being looked at.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::name::{self, Name};
use core::net::{Ipv4Addr, Ipv6Addr};
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{Class, Element, Oid, Reader, Tag, universal};

mod ldap;

/// One name, in whichever of the forms the schema allows.
#[derive(Debug)]
#[non_exhaustive]
pub enum GeneralName<'a> {
    /// A form defined elsewhere, kept as its identifier and its value.
    Other {
        /// What kind of name this is.
        type_id: Oid<'a>,
        /// The value, as it was encoded.
        value: &'a [u8],
    },
    /// An electronic mail address.
    Email(&'a str),
    /// A domain name.
    Dns(&'a str),
    /// An X.400 address, kept as encoded because nothing here reads one.
    X400(&'a [u8]),
    /// A distinguished name, the same kind a certificate's subject is.
    Directory(Name<'a>),
    /// An EDI party name, kept as encoded.
    EdiParty(&'a [u8]),
    /// A location, which is text and is never fetched.
    Uri(&'a str),
    /// An address, as the four or sixteen bytes it is written in. In a name
    /// constraint this is twice that, the address and then its mask.
    IpAddress(&'a [u8]),
    /// A name that is itself an identifier.
    RegisteredId(Oid<'a>),
}

/// Reads a sequence of names.
pub(crate) fn read_all<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<OwnedVec<GeneralName<'a>>> {
    let mut inside = parent.enter(element).field(field)?;
    read_list(&mut inside, field, element.span().start)
}

/// Reads the names of a container already entered.
pub(crate) fn read_list<'a>(
    inside: &mut Reader<'a>,
    field: &'static str,
    offset: u64,
) -> Result<OwnedVec<GeneralName<'a>>> {
    read_list_as(inside, field, offset, AddressForm::Single)
}

/// Distribution locations use URI grammar, rather than SAN host identity
/// rules. RFC5280 §4.2.1.13 explicitly permits ldap:/// with no host.
pub(crate) fn read_locations<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<OwnedVec<GeneralName<'a>>> {
    let mut inside = parent.enter(element).field(field)?;
    read_list_as(
        &mut inside,
        field,
        element.span().start,
        AddressForm::Location,
    )
}

fn read_list_as<'a>(
    inside: &mut Reader<'a>,
    field: &'static str,
    offset: u64,
    form: AddressForm,
) -> Result<OwnedVec<GeneralName<'a>>> {
    let mut names = inside.memory().vector();
    while let Some(entry) = inside.next_element().field(field)? {
        names
            .try_push(read_as(inside, &entry, field, form)?)
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
    }

    // A list of names that holds none says nothing while claiming to, and the
    // schema asks for at least one everywhere this is used.
    if names.is_empty() {
        return Err(Error::new(ErrorCode::EmptySequence, field, offset));
    }
    Ok(names)
}

/// Reads the value of an alternative name extension, which is a list of names
/// and nothing else.
pub fn read_alternative<'a>(
    extension: &Extension<'a>,
    execution: &Memory,
) -> Result<OwnedVec<GeneralName<'a>>> {
    let field = if extension.kind() == crate::oid::ISSUER_ALT_NAME {
        "extensions.issuerAltName"
    } else {
        "extensions.subjectAltName"
    };

    let mut inside = extension::sequence(extension, field, execution)?;
    read_list(&mut inside, field, extension.span().start)
}

/// Where a name sits, which decides which forms its fields take.
///
/// The same tags carry different forms in the two positions: an address is
/// bare in a list of names and paired with its mask in a name-constraint
/// subtree, and a mail or location constraint may name a host or a domain
/// where a name must be a mailbox or a URI. Only the position says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressForm {
    /// A name in a list of names: a bare address, a mailbox, a URI.
    Single,
    /// Distribution location: general URI, not a certificate SAN host.
    Location,
    /// The base of a name-constraint subtree: an address with its mask, and
    /// the host and domain forms of a mail or location constraint.
    WithMask,
}

impl AddressForm {
    fn permits(self, length: usize) -> bool {
        match self {
            Self::Single | Self::Location => length == 4 || length == 16,
            Self::WithMask => length == 8 || length == 32,
        }
    }
}

/// Reads one name from the element whose tag says which kind it is.
///
/// The parent must be the reader that produced the element: decoding retains
/// its shared budget, depth and offsets. This also serves names outside
/// certificates, such as RFC 3161 §2.4.2's timestamp `tsa` field.
/// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
///
/// # Errors
///
/// Reports malformed name syntax, encoding faults and exhausted limits.
pub fn read<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<GeneralName<'a>> {
    read_as(parent, element, field, AddressForm::Single)
}

/// Whether text is the mail form the position takes.
///
/// A name is a mailbox (RFC 5280 4.2.1.6). A constraint may also name every
/// mailbox at a host, or every mailbox in a domain by a leading period
/// (4.2.1.10).
fn mailbox_fits(text: &str, address_form: AddressForm) -> bool {
    match address_form {
        AddressForm::Single | AddressForm::Location => is_mailbox(text),
        AddressForm::WithMask => {
            is_mailbox(text) || is_domain(text) || text.strip_prefix('.').is_some_and(is_domain)
        }
    }
}

/// Whether text is the domain form the position takes.
///
/// A name holds the preferred name syntax (RFC 5280 4.2.1.6, via RFC 1034
/// 3.5 as modified by RFC 1123): a value that is merely ASCII is not yet a
/// domain, and reporting one would put an identity in the report the
/// certificate does not carry.
///
/// A subtree base is written the same way, with one addition the profile
/// does not spell out here. It writes a domain-name restriction as a name
/// further labels are added to the left of (4.2.1.10), and gives the leading
/// period to the mail and location forms in the two paragraphs above that
/// one. It does not say to refuse the period here; issuers write it, and the
/// extension is critical, so refusing the value refuses the authority and
/// every certificate under it over a spelling of the same subtree. What the
/// period means is for the reader of the constraint to decide, and the value
/// is preserved as written.
fn domain_fits(text: &str, address_form: AddressForm) -> bool {
    match address_form {
        AddressForm::Single | AddressForm::Location => is_domain(text),
        AddressForm::WithMask => is_domain(text) || text.strip_prefix('.').is_some_and(is_domain),
    }
}

pub(crate) fn read_as<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    address_form: AddressForm,
) -> Result<GeneralName<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);
    let tag = element.tag();

    if tag.class() != Class::ContextSpecific {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    // The tag says which kind of name this is, and whether the value is a
    // structure or a string. A string written as a structure is the segmented
    // form, which is a second spelling of one value and is not read here. A
    // number this reader does not name is none of the nine forms, and falls
    // to the same refusal as a number it names that this schema does not
    // have.
    let Some(number) = tag.number() else {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    };
    match (number, tag.is_constructed()) {
        (0, true) => read_other(parent, element, field),
        (1, false) => {
            let email = text(parent, element.contents(), field, element)?;
            if !mailbox_fits(email, address_form) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(GeneralName::Email(email))
        }
        (2, false) => {
            let domain = text(parent, element.contents(), field, element)?;
            if !domain_fits(domain, address_form) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(GeneralName::Dns(domain))
        }
        (3, true) => {
            read_x400(parent, element, field)?;
            Ok(GeneralName::X400(element.contents()))
        }
        (4, true) => {
            // The name it holds is a choice, which cannot take the tag of its
            // position, so the tag wraps it rather than replacing it.
            let mut inside = parent.enter(element).field(field)?;
            let inner = inside
                .next_element()
                .field(field)?
                .ok_or_else(|| fail(ErrorCode::MissingField))?;
            let name = name::read(&inside, &inner, field)?;
            // An empty name is legal as a certificate's subject, where the
            // alternative name carries the identity instead. As a general
            // name it IS the identity, and empty it names nobody; as a
            // subtree base it is the root, under which every directory name
            // sits, so only the identity-bearing position refuses it. Every
            // attribute of a kind this crate names must be written inside
            // its syntax either way: an identity this run never read must
            // not read as a supplied one. Unknown kinds stay data.
            //
            // The walk touches every attribute's contents, and a kind whose
            // schema leaves the size unbounded has no local ceiling, so the
            // lengths are charged to the shared work budget before it runs.
            if address_form != AddressForm::WithMask && name.is_empty() {
                return Err(fail(ErrorCode::MalformedValue));
            }
            for attribute in name.attributes() {
                if !name::well_formed_in(attribute, &inside, field)? {
                    return Err(fail(ErrorCode::MalformedValue));
                }
            }
            if !inside.is_empty() {
                return Err(fail(ErrorCode::TrailingData));
            }
            Ok(GeneralName::Directory(name))
        }
        (5, true) => {
            read_edi_party(parent, element, field)?;
            Ok(GeneralName::EdiParty(element.contents()))
        }
        (6, false) => {
            let location = text(parent, element.contents(), field, element)?;
            // RFC5280 §4.2.1.6 requires a scheme and forbids relative URIs.
            // RFC3986 §3's URI includes a fragment; §4.3 absolute-URI is a
            // distinct, fragment-free production, not the SAN grammar.
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6
            // https://www.rfc-editor.org/rfc/rfc3986.html#section-3
            // A constraint
            // applies to the host and is written as a host or a domain
            // (4.2.1.10).
            let fits = match address_form {
                AddressForm::Single => {
                    // Admit the additional fragment-delimiter scan before
                    // selecting the existing scheme/authority semantic core.
                    parent.charge(location.len() as u64).field(field)?;
                    is_uri(location)
                }
                AddressForm::Location => {
                    // RFC5280 §4.2.1.13 permits an empty LDAP host and leaves
                    // server selection to the caller. No host is invented.
                    // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13
                    location_uri(parent, element, location, field)?
                }
                AddressForm::WithMask => {
                    is_domain(location) || location.strip_prefix('.').is_some_and(is_domain)
                }
            };
            if !fits {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(GeneralName::Uri(location))
        }
        (7, false) => {
            let contents = element.contents();
            if !address_form.permits(contents.len()) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            // A constraint region is CIDR (RFC 5280 4.2.1.10, via RFC 4632):
            // the mask half is leading one bits and nothing after them. A
            // gap describes no range this profile defines.
            if address_form == AddressForm::WithMask
                && !is_contiguous_mask(&contents[contents.len() / 2..])
            {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(GeneralName::IpAddress(contents))
        }
        (8, false) => parent
            .oid(element)
            .field(field)
            .map(GeneralName::RegisteredId),
        _ => Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        ))),
    }
}

/// Validates an X.400 OR-address: the mandatory built-in standard
/// attributes, then optionally the domain-defined attributes and the
/// extension attributes (X.411 `ORAddress`, referenced from RFC 5280
/// appendix A). The members inside each container are validated against
/// that schema too, because a critical name extension carrying members
/// outside it must not read as parsed; the address as a whole still stays
/// encoded, since nothing in this product routes to a messaging system.
fn read_x400<'a>(parent: &Reader<'a>, element: &Element<'a>, field: &'static str) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);

    let mut inside = parent.enter(element).field(field)?;
    let standard = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if standard.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    read_standard_attributes(&inside, &standard, field)?;

    // The two optional members, in order: a SEQUENCE OF, then a SET OF.
    let mut next = inside.next_element().field(field)?;
    if let Some(domain_defined) = next
        && domain_defined.tag() == Tag::constructed(universal::SEQUENCE)
    {
        read_domain_defined(&inside, &domain_defined, field)?;
        next = inside.next_element().field(field)?;
    }
    if let Some(extensions) = next {
        if extensions.tag() != Tag::constructed(universal::SET) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        read_extension_attributes(&inside, &extensions, field)?;
        if !inside.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }
    }
    Ok(())
}

/// The tag numbers X.411 string types carry, named here since nothing below
/// the schema needs them.
const X400_NUMERIC_STRING: u32 = 18;

/// Requires a universal string member to be a `NumericString` or a
/// `PrintableString`, inside its repertoire and the size the schema gives
/// that member (X.411 via RFC 5280 appendix A, whose bounds these are).
fn x400_string(element: &Element<'_>, field: &'static str, size: (usize, usize)) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    let contents = element.contents();
    // The primitive form only: DER has no constructed spelling of these
    // strings, and the class and number alone would let one through.
    let fits = match (
        element.tag().class(),
        element.tag().number(),
        element.tag().is_constructed(),
    ) {
        (Class::Universal, Some(X400_NUMERIC_STRING), false) => crate::name::is_numeric(contents),
        (Class::Universal, Some(universal::PRINTABLE_STRING), false) => {
            crate::name::is_printable(contents)
        }
        _ => {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    };
    if !fits || contents.len() < size.0 || contents.len() > size.1 {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// Requires a primitive `PrintableString` of the given size, refusing the
/// numeric alternative the wider choice permits.
fn x400_printable(element: &Element<'_>, field: &'static str, size: (usize, usize)) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    let tag = element.tag();
    if tag.class() != Class::Universal
        || tag.number() != Some(universal::PRINTABLE_STRING)
        || tag.is_constructed()
    {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let contents = element.contents();
    if !crate::name::is_printable(contents) || contents.len() < size.0 || contents.len() > size.1 {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// Which repertoire an X.400 string member is held to. Teletex is a
/// negotiation this crate does not implement, so only its presence and size
/// are checkable.
#[derive(Clone, Copy)]
enum X400Repertoire {
    Numeric,
    Printable,
    Teletex,
}

/// Requires an implicitly tagged member's contents to be one repertoire
/// within one size, the tag having replaced the string type.
fn x400_implicit(
    element: &Element<'_>,
    field: &'static str,
    repertoire: X400Repertoire,
    most: usize,
) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    let contents = element.contents();
    // The size is decided before the repertoire. These fields are bounded to
    // a few dozen characters by the schema, while the element they arrive in
    // may be as long as the parser's length limit permits: walking one to
    // its end to learn it is digits, only to refuse it for its length, is
    // work the caller's budget never asked for. Afterwards the walk is
    // bounded by the schema's own ceiling.
    if contents.is_empty() || contents.len() > most {
        return Err(fail(ErrorCode::MalformedValue));
    }
    let fits = match repertoire {
        X400Repertoire::Numeric => crate::name::is_numeric(contents),
        X400Repertoire::Printable => crate::name::is_printable(contents),
        X400Repertoire::Teletex => true,
    };
    if !fits {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// Requires a universal `TeletexString` member, primitive, within one size.
fn x400_teletex(element: &Element<'_>, field: &'static str, size: (usize, usize)) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    // TeletexString is tag number 20; its repertoire is a negotiation this
    // crate does not implement, so presence and size are what is checkable.
    if element.tag() != Tag::primitive(20) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let length = element.contents().len();
    if length < size.0 || length > size.1 {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// Requires a bare country choice: an X.121 DCC of exactly three digits, or
/// an ISO 3166 alpha-2 code of exactly two uppercase letters. The wider
/// repertoires of the string types name no country.
fn x400_bare_country(value: &Element<'_>, field: &'static str) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    let contents = value.contents();
    let fits = match (
        value.tag().class(),
        value.tag().number(),
        value.tag().is_constructed(),
    ) {
        (Class::Universal, Some(X400_NUMERIC_STRING), false) => {
            contents.len() == 3 && contents.iter().all(u8::is_ascii_digit)
        }
        (Class::Universal, Some(universal::PRINTABLE_STRING), false) => {
            contents.len() == 2 && contents.iter().all(u8::is_ascii_uppercase)
        }
        _ => {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    };
    if !fits {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// Requires a wrapper to hold exactly one country choice.
fn x400_country<'a>(parent: &Reader<'a>, wrapper: &Element<'a>, field: &'static str) -> Result<()> {
    let fail = |code| Error::new(code, field, wrapper.span().start);
    let mut inside = parent.enter(wrapper).field(field)?;
    let value = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    x400_bare_country(&value, field)
}

/// Requires a wrapper to hold exactly one string of a two-way choice, sized
/// as the schema sizes each side of that choice.
fn x400_choice<'a>(
    parent: &Reader<'a>,
    wrapper: &Element<'a>,
    field: &'static str,
    numeric: (usize, usize),
    printable: (usize, usize),
) -> Result<()> {
    let fail = |code| Error::new(code, field, wrapper.span().start);
    let mut inside = parent.enter(wrapper).field(field)?;
    let value = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    let size = match (value.tag().class(), value.tag().number()) {
        (Class::Universal, Some(X400_NUMERIC_STRING)) => numeric,
        (Class::Universal, Some(universal::PRINTABLE_STRING)) => printable,
        _ => {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    };
    x400_string(&value, field, size)
}

/// The members X.411 gives the built-in standard attributes, each optional,
/// each at most once, in schema order, with the strings held to their
/// repertoires and the appendix's upper bounds.
fn read_standard_attributes<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let mut inside = parent.enter(element).field(field)?;
    let mut last_rank = -1i8;
    while let Some(member) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, member.span().start);
        let tag = member.tag();
        // A number this reader does not name is no member of the structure,
        // and falls to the same refusal as any other number it does not have.
        let Some(number) = tag.number() else {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        };
        let rank: i8 = match (tag.class(), number, tag.is_constructed()) {
            // The country: exactly a three-digit or a two-letter code,
            // wrapped because a choice keeps its own tag.
            (Class::Application, 1, true) => {
                x400_country(&inside, &member, field)?;
                0
            }
            // The administration domain: the same choice, up to sixteen
            // characters, empty naming the default domain.
            (Class::Application, 2, true) => {
                x400_choice(&inside, &member, field, (0, 16), (0, 16))?;
                1
            }
            // network-address: an X.121 address of up to sixteen digits.
            (Class::ContextSpecific, 0, false) => {
                x400_implicit(&member, field, X400Repertoire::Numeric, 16)?;
                2
            }
            // terminal-identifier.
            (Class::ContextSpecific, 1, false) => {
                x400_implicit(&member, field, X400Repertoire::Printable, 24)?;
                3
            }
            // private-domain-name: the numeric-or-printable choice again.
            (Class::ContextSpecific, 2, true) => {
                x400_choice(&inside, &member, field, (1, 16), (1, 16))?;
                4
            }
            // organization-name.
            (Class::ContextSpecific, 3, false) => {
                x400_implicit(&member, field, X400Repertoire::Printable, 64)?;
                5
            }
            // numeric-user-identifier.
            (Class::ContextSpecific, 4, false) => {
                x400_implicit(&member, field, X400Repertoire::Numeric, 32)?;
                6
            }
            // personal-name: a set of up to four parts, the surname required.
            (Class::ContextSpecific, 5, true) => {
                read_personal_name(&inside, &member, field, X400Repertoire::Printable)?;
                7
            }
            // organizational-unit-names: one to four unit names, each a
            // PrintableString alone, unlike the explicit numeric-or-printable
            // choices elsewhere in the address.
            (Class::ContextSpecific, 6, true) => {
                let mut units = inside.enter(&member).field(field)?;
                let mut count = 0usize;
                while let Some(unit) = units.next_element().field(field)? {
                    x400_printable(&unit, field, (1, 32))?;
                    count += 1;
                }
                if !(1..=4).contains(&count) {
                    return Err(bad(ErrorCode::MalformedValue));
                }
                8
            }
            _ => {
                return Err(bad(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
        };
        // Each member appears at most once, in the order the schema writes
        // them; a repeat or a step backwards is a second spelling of the
        // structure.
        if rank <= last_rank {
            return Err(bad(ErrorCode::UnexpectedField));
        }
        last_rank = rank;
    }
    Ok(())
}

/// The personal name of X.411: up to four parts, each at most once, the
/// surname required. The built-in form holds printable parts; the teletex
/// extension attribute holds the same shape in teletex strings.
fn read_personal_name<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    repertoire: X400Repertoire,
) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    let mut inside = parent.enter(element).field(field)?;
    let mut seen = [false; 4];
    let mut last: Option<usize> = None;
    while let Some(part) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, part.span().start);
        let (number, most) = match (
            part.tag().class(),
            part.tag().number(),
            part.tag().is_constructed(),
        ) {
            (Class::ContextSpecific, Some(0), false) => (0usize, 40),
            (Class::ContextSpecific, Some(1), false) => (1, 16),
            (Class::ContextSpecific, Some(2), false) => (2, 5),
            (Class::ContextSpecific, Some(3), false) => (3, 3),
            _ => {
                return Err(bad(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
        };
        if seen[number] {
            return Err(bad(ErrorCode::UnexpectedField));
        }
        // A SET's distinct tags come in canonical order under DER (X.690
        // 10.3): out of order is a second spelling of one value. BER carries
        // no such rule.
        if inside.encoding().is_der() && last.is_some_and(|last| number < last) {
            return Err(bad(ErrorCode::UnexpectedField));
        }
        seen[number] = true;
        last = Some(number);
        x400_implicit(&part, field, repertoire, most)?;
    }
    if !seen[0] {
        return Err(fail(ErrorCode::MissingField));
    }
    Ok(())
}

/// The domain-defined attributes of X.411: one to four pairs of a type and a
/// value, each a printable string.
fn read_domain_defined<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    read_defined_pairs(parent, element, field, false)
}

/// One to four pairs of a type and a value: printable strings in the
/// built-in form, teletex strings in the teletex extension attribute.
fn read_defined_pairs<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    teletex: bool,
) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let held_string = |element: &Element<'_>, size: (usize, usize)| {
        if teletex {
            x400_teletex(element, field, size)
        } else {
            // The built-in pair holds PrintableString in both members; the
            // numeric encoding belongs to other positions of the address.
            x400_printable(element, field, size)
        }
    };
    let mut inside = parent.enter(element).field(field)?;
    let mut count = 0usize;
    while let Some(pair) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, pair.span().start);
        if pair.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        let mut two = inside.enter(&pair).field(field)?;
        let kind = two
            .next_element()
            .field(field)?
            .ok_or_else(|| bad(ErrorCode::MissingField))?;
        held_string(&kind, (1, 8))?;
        let value = two
            .next_element()
            .field(field)?
            .ok_or_else(|| bad(ErrorCode::MissingField))?;
        held_string(&value, (1, 128))?;
        if !two.is_empty() {
            return Err(bad(ErrorCode::TrailingData));
        }
        count += 1;
    }
    if !(1..=4).contains(&count) {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

/// The extension attributes of X.411: each an identifying number and an
/// explicitly wrapped value that number defines, decoded by that number
/// below.
fn read_extension_attributes<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);
    let mut inside = parent.enter(element).field(field)?;
    let mut count = 0usize;
    let mut previous: Option<&[u8]> = None;
    while let Some(entry) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, entry.span().start);
        if entry.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        // A SET OF, whose members DER writes in ascending encoded order
        // (X.690 11.6): out of order is a second spelling of one value. BER
        // carries no such rule. The comparison walks up to the longer
        // encoding before either member is decoded, so that length is
        // charged to the shared work budget first.
        if inside.encoding().is_der()
            && let Some(previous) = previous
        {
            inside
                .charge(previous.len().max(entry.as_bytes().len()) as u64)
                .field(field)?;
            if entry.as_bytes() < previous {
                return Err(bad(ErrorCode::UnexpectedField));
            }
        }
        previous = Some(entry.as_bytes());
        let mut two = inside.enter(&entry).field(field)?;
        let kind = two
            .next_element()
            .field(field)?
            .ok_or_else(|| bad(ErrorCode::MissingField))?;
        // The number wears its position's tag; the decoding helper is
        // tag-agnostic, which is exactly right for an implicit field, but the
        // position is required first. The schema bounds it to 0..=256.
        if extension::context_of(kind.tag()) != Some((0, false)) {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        let number = two.integer(&kind).field(field)?;
        if number.as_u32().is_none_or(|number| number > 256) {
            return Err(bad(ErrorCode::MalformedValue));
        }
        let value = two
            .next_element()
            .field(field)?
            .ok_or_else(|| bad(ErrorCode::MissingField))?;
        // The value is wrapped explicitly, because what it is depends on the
        // number before it. It holds exactly one value, kept encoded.
        if extension::context_of(value.tag()) != Some((1, true)) {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        let mut held = two.enter(&value).field(field)?;
        let Some(declared) = held.next_element().field(field)? else {
            return Err(bad(ErrorCode::MissingField));
        };
        // The number declares the value's syntax, so the value is decoded by
        // it: an attribute wearing a number whose syntax it does not have was
        // never decoded, and a critical name built on one must not read as
        // parsed.
        let number = number
            .as_u32()
            .expect("bounded to 0..=256 above, which fits");
        read_extension_value(&held, &declared, number, field)?;
        if !held.is_empty() || !two.is_empty() {
            return Err(bad(ErrorCode::TrailingData));
        }
        count += 1;
        // ub-extension-attributes bounds the set at 256 members (RFC 5280
        // appendix A); a 257th puts the address outside the schema.
        if count > 256 {
            return Err(bad(ErrorCode::MalformedValue));
        }
    }
    if count == 0 {
        return Err(fail(ErrorCode::EmptySequence));
    }
    Ok(())
}

/// The value an extension attribute declares, decoded by the number before
/// it: the syntaxes RFC 5280 appendix A gives the numbers it defines, with
/// that module's size bounds. A number the appendix does not define is a
/// value this crate cannot decode, and a name built on one must not read as
/// parsed.
fn read_extension_value<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    number: u32,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    match number {
        // common-name: PrintableString alone, unlike the explicit
        // numeric-or-printable choices elsewhere in the address.
        1 => x400_printable(value, field, (1, 64)),
        // teletex-common-name and teletex-organization-name.
        2 | 3 => x400_teletex(value, field, (1, 64)),
        // teletex-personal-name: the personal-name shape in teletex strings.
        4 => {
            if value.tag() != Tag::constructed(universal::SET) {
                return Err(fail(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
            read_personal_name(parent, value, field, X400Repertoire::Teletex)
        }
        // teletex-organizational-unit-names: one to four unit names.
        5 => {
            if value.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(fail(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
            let mut units = parent.enter(value).field(field)?;
            let mut count = 0usize;
            while let Some(unit) = units.next_element().field(field)? {
                x400_teletex(&unit, field, (1, 32))?;
                count += 1;
            }
            if !(1..=4).contains(&count) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(())
        }
        // teletex-domain-defined-attributes: the pairs again, in teletex.
        6 => read_defined_pairs(parent, value, field, true),
        // pds-name: PrintableString alone.
        7 => x400_printable(value, field, (1, 16)),
        // physical-delivery-country-name: exactly a three-digit or a
        // two-letter code, the choice bare in this position.
        8 => x400_bare_country(value, field),
        // postal-code.
        9 => x400_bare_choice(value, field, (1, 16), (1, 16)),
        // The postal-delivery parameters, one shape under many numbers: an
        // optional printable and an optional teletex string.
        10..=15 | 17..=21 => read_pds_parameter(parent, value, field, 30),
        // unformatted-postal-address.
        16 => read_unformatted_address(parent, value, field),
        // extended-network-address.
        22 => read_extended_network_address(parent, value, field),
        // terminal-type: an integer of the option table.
        23 => {
            if value.tag() != Tag::primitive(universal::INTEGER) {
                return Err(fail(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
            let option = parent.integer(value).field(field)?;
            if option.as_u32().is_none_or(|option| option > 256) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            Ok(())
        }
        _ => Err(fail(ErrorCode::MalformedValue)),
    }
}

/// Requires a bare two-way choice: the string stands in the choice's own
/// position, so its universal tag says which side it is.
fn x400_bare_choice(
    value: &Element<'_>,
    field: &'static str,
    numeric: (usize, usize),
    printable: (usize, usize),
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    let size = match (
        value.tag().class(),
        value.tag().number(),
        value.tag().is_constructed(),
    ) {
        (Class::Universal, Some(X400_NUMERIC_STRING), false) => numeric,
        (Class::Universal, Some(universal::PRINTABLE_STRING), false) => printable,
        _ => {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    };
    x400_string(value, field, size)
}

/// The postal-delivery parameter of X.411: an optional printable and an
/// optional teletex string, each at most once, each within one size.
fn read_pds_parameter<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    field: &'static str,
    most: usize,
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    if value.tag() != Tag::constructed(universal::SET) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let mut inside = parent.enter(value).field(field)?;
    let mut seen_printable = false;
    let mut seen_teletex = false;
    while let Some(member) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, member.span().start);
        if member.tag() == Tag::primitive(universal::PRINTABLE_STRING) {
            // A SET's distinct tags come in canonical order under DER
            // (X.690 10.3): the printable tag sorts before the teletex one,
            // so arriving after it is a second spelling of one value. BER
            // carries no such rule.
            if seen_printable || (seen_teletex && inside.encoding().is_der()) {
                return Err(bad(ErrorCode::UnexpectedField));
            }
            seen_printable = true;
            x400_string(&member, field, (1, most))?;
        } else if member.tag() == Tag::primitive(20) {
            if seen_teletex {
                return Err(bad(ErrorCode::UnexpectedField));
            }
            seen_teletex = true;
            x400_teletex(&member, field, (1, most))?;
        } else {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    }
    Ok(())
}

/// The unformatted postal address of X.411: up to six printable lines and
/// an optional teletex rendering, each part at most once.
fn read_unformatted_address<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    if value.tag() != Tag::constructed(universal::SET) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    let mut inside = parent.enter(value).field(field)?;
    let mut seen_lines = false;
    let mut seen_teletex = false;
    while let Some(member) = inside.next_element().field(field)? {
        let bad = |code| Error::new(code, field, member.span().start);
        if member.tag() == Tag::constructed(universal::SEQUENCE) {
            // A SET's distinct tags come in canonical order under DER
            // (X.690 10.3): the SEQUENCE tag sorts before the teletex one,
            // so arriving after it is a second spelling of one value. BER
            // carries no such rule.
            if seen_lines || (seen_teletex && inside.encoding().is_der()) {
                return Err(bad(ErrorCode::UnexpectedField));
            }
            seen_lines = true;
            let mut lines = inside.enter(&member).field(field)?;
            let mut count = 0usize;
            while let Some(line) = lines.next_element().field(field)? {
                // Every line of the printable address is a PrintableString;
                // the numeric alternative belongs to other positions.
                x400_printable(&line, field, (1, 30))?;
                count += 1;
            }
            if !(1..=6).contains(&count) {
                return Err(bad(ErrorCode::MalformedValue));
            }
        } else if member.tag() == Tag::primitive(20) {
            if seen_teletex {
                return Err(bad(ErrorCode::UnexpectedField));
            }
            seen_teletex = true;
            x400_teletex(&member, field, (1, 180))?;
        } else {
            return Err(bad(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
    }
    Ok(())
}

/// The E.163/E.164 alternative: a number and an optional sub-address.
fn read_e163_address<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    let mut inside = parent.enter(value).field(field)?;
    let number = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if extension::context_of(number.tag()) != Some((0, false)) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    x400_implicit(&number, field, X400Repertoire::Numeric, 15)?;
    if let Some(sub) = inside.next_element().field(field)? {
        if extension::context_of(sub.tag()) != Some((1, false)) {
            return Err(fail(ErrorCode::Encoding(
                structured_asn1::ErrorCode::UnexpectedTag,
            )));
        }
        x400_implicit(&sub, field, X400Repertoire::Numeric, 40)?;
    }
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    Ok(())
}

/// The extended network address of X.411: an E.163/E.164 number with an
/// optional sub-address, or a presentation address of wrapped selectors and
/// the mandatory network addresses.
fn read_extended_network_address<'a>(
    parent: &Reader<'a>,
    value: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, value.span().start);
    if value.tag() == Tag::constructed(universal::SEQUENCE) {
        read_e163_address(parent, value, field)
    } else if extension::context_of(value.tag()) == Some((0, true)) {
        // psap-address: three optional wrapped selectors, then the mandatory
        // set of network addresses, each member at most once in order.
        let mut inside = parent.enter(value).field(field)?;
        let mut last: i8 = -1;
        let mut saw_network = false;
        while let Some(member) = inside.next_element().field(field)? {
            let bad = |code| Error::new(code, field, member.span().start);
            let Some((number, true)) = extension::context_of(member.tag()) else {
                return Err(bad(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            };
            let rank = i8::try_from(number).map_err(|_| {
                bad(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                ))
            })?;
            if rank > 3 {
                return Err(bad(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }
            if rank <= last {
                return Err(bad(ErrorCode::UnexpectedField));
            }
            last = rank;
            let mut held = inside.enter(&member).field(field)?;
            if rank == 3 {
                // The network addresses: at least one octet string.
                let addresses = held
                    .next_element()
                    .field(field)?
                    .ok_or_else(|| bad(ErrorCode::MissingField))?;
                if addresses.tag() != Tag::constructed(universal::SET) {
                    return Err(bad(ErrorCode::Encoding(
                        structured_asn1::ErrorCode::UnexpectedTag,
                    )));
                }
                let mut each = held.enter(&addresses).field(field)?;
                let mut count = 0usize;
                let mut previous: Option<&[u8]> = None;
                while let Some(address) = each.next_element().field(field)? {
                    if address.tag() != Tag::primitive(universal::OCTET_STRING) {
                        return Err(bad(ErrorCode::Encoding(
                            structured_asn1::ErrorCode::UnexpectedTag,
                        )));
                    }
                    // A SET OF, whose members DER writes in ascending
                    // encoded order (X.690 11.6): out of order is a second
                    // spelling of one value. BER carries no such rule. The
                    // comparison walks up to the longer encoding, so that
                    // length is charged to the shared work budget first.
                    if each.encoding().is_der()
                        && let Some(previous) = previous
                    {
                        each.charge(previous.len().max(address.as_bytes().len()) as u64)
                            .field(field)?;
                        if address.as_bytes() < previous {
                            return Err(bad(ErrorCode::UnexpectedField));
                        }
                    }
                    previous = Some(address.as_bytes());
                    count += 1;
                }
                if count == 0 {
                    return Err(bad(ErrorCode::EmptySequence));
                }
                saw_network = true;
            } else {
                // A selector: one wrapped octet string.
                let selector = held
                    .next_element()
                    .field(field)?
                    .ok_or_else(|| bad(ErrorCode::MissingField))?;
                if selector.tag() != Tag::primitive(universal::OCTET_STRING) {
                    return Err(bad(ErrorCode::Encoding(
                        structured_asn1::ErrorCode::UnexpectedTag,
                    )));
                }
            }
            if !held.is_empty() {
                return Err(bad(ErrorCode::TrailingData));
            }
        }
        if !saw_network {
            return Err(fail(ErrorCode::MissingField));
        }
        Ok(())
    } else {
        Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )))
    }
}

/// Validates an EDI party name: an optional assigner, then the mandatory
/// party, each an explicitly tagged wrapper holding one directory string.
/// The tags wrap rather than replace, because a directory string is a choice
/// and RFC 5280 appendix A keeps a choice's own tag.
fn read_edi_party<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    let fail = |code| Error::new(code, field, element.span().start);

    let mut inside = parent.enter(element).field(field)?;
    let mut next = inside.next_element().field(field)?;

    if let Some(assigner) = next
        && extension::context_of(assigner.tag()) == Some((0, true))
    {
        require_directory_string(&inside, &assigner, field)?;
        next = inside.next_element().field(field)?;
    }

    let party = next.ok_or_else(|| fail(ErrorCode::MissingField))?;
    if extension::context_of(party.tag()) != Some((1, true)) {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            field,
            party.span().start,
        ));
    }
    require_directory_string(&inside, &party, field)?;

    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }
    Ok(())
}

/// Requires a wrapper to hold exactly one non-empty directory string.
fn require_directory_string<'a>(
    parent: &Reader<'a>,
    wrapper: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    /// The ub-name character bound both EDI fields carry (RFC 5280 appendix A).
    const MOST: usize = 32768;
    let fail = |code| Error::new(code, field, wrapper.span().start);

    let mut inside = parent.enter(wrapper).field(field)?;
    let value = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    // The directory string choice of X.520: a primitive universal string of
    // one of its five types, holding one to 32768 characters, the ub-name
    // bound both EDI fields carry (RFC 5280 appendix A). The tag alone is not
    // the type, so the value must also decode under the type chosen.
    let tag = value.tag();
    let is_directory_string = tag.class() == Class::Universal
        && !tag.is_constructed()
        && matches!(tag.number(), Some(12 | 19 | 20 | 28 | 30));
    // The ceiling is checked on the encoded bytes before any text is
    // materialized: each encoding spends a known number of bytes per
    // character, so contents past the per-encoding multiple of the bound
    // can never fit it and are refused without allocating a copy.
    let ceiling = match tag.number() {
        Some(12 | 28) => MOST.saturating_mul(4),
        Some(30) => MOST.saturating_mul(2),
        _ => MOST,
    };
    if value.contents().len() > ceiling {
        return Err(fail(ErrorCode::MalformedValue));
    }
    // The decode below scans every content byte, and the per-field ceiling
    // does not bound the aggregate across many fields: the scan is charged
    // to the shared work budget first.
    parent.charge(value.contents().len() as u64).field(field)?;
    let decodes = match tag.number() {
        Some(12) => {
            core::str::from_utf8(value.contents()).is_ok_and(|text| text.chars().count() <= MOST)
        }
        Some(19) => crate::name::is_printable(value.contents()) && value.contents().len() <= MOST,
        Some(28) => {
            crate::name::wide_char_count(value.contents(), 4).is_some_and(|count| count <= MOST)
        }
        Some(30) => {
            crate::name::wide_char_count(value.contents(), 2).is_some_and(|count| count <= MOST)
        }
        // TeletexString's repertoire is a negotiation this crate does not
        // implement: the bytes being there and inside the bound is what is
        // checkable.
        _ => value.contents().len() <= MOST,
    };
    if !is_directory_string || value.contents().is_empty() || !decodes {
        return Err(fail(ErrorCode::MalformedValue));
    }
    Ok(())
}

fn read_other<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<GeneralName<'a>> {
    let fail = |code| Error::new(code, field, element.span().start);

    let mut inside = parent.enter(element).field(field)?;
    let type_id = inside.read_oid().field(field)?;
    let wrapper = inside
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;

    // The value is tagged explicitly, because what it is depends on the
    // identifier before it and a tag cannot replace one it does not know.
    if wrapper.tag() != Tag::context(true, 0) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    // The wrapper holds the one value the identifier describes. Empty it
    // names nothing, and with a second element there is no answer to which
    // value the name is.
    let mut held = inside.enter(&wrapper).field(field)?;
    let value = held
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if !held.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    // The outer tag is not the whole value: a container this crate does not
    // interpret may still hold children that are not DER, an integer written
    // a byte longer than it needs or a marker belonging to the indefinite
    // lengths DER does not have. A recognizer clears a critical extension on
    // the strength of this value, so every element inside it is held to the
    // encoding's rules before it is preserved.
    crate::name::walk_der(&held, &value, field, crate::name::Strings::Checked)?;

    Ok(GeneralName::Other {
        type_id,
        value: value.as_bytes(),
    })
}

/// Reads the ASCII a schema calls an `IA5String`.
/// Whether text is a domain in the preferred name syntax: dot-separated
/// labels of letters, digits and inner hyphens, each of one to sixty-three
/// characters (RFC 1034 3.5, its leading letter relaxed to a letter or digit
/// by RFC 1123 2.1).
pub(crate) fn is_domain(text: &str) -> bool {
    // The whole name is bounded too: 255 octets in the wire form, which is
    // 253 characters of the presentation form (RFC 1035 2.3.4). The
    // highest-level label stays alphabetic-bearing (RFC 1123 2.1), which is
    // what separates a host name from a dotted-decimal address: an address
    // wearing this field would ride under the wrong name-constraint form.
    text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && text
            .rsplit('.')
            .next()
            .is_some_and(|top| top.bytes().any(|byte| byte.is_ascii_alphabetic()))
}

/// Whether text is a mailbox, the form RFC 5280 4.2.1.6 points at: "the
/// format of an rfc822Name is a Mailbox as defined in RFC 5321 section
/// 4.1.2".
///
/// The dependency's ASCII SMTP predicate shares its strict envelope grammar,
/// including quoted local parts, single-label domains and §4.1.3 literals.
/// It performs no allocation or normalization. Both callers admit the bounded
/// linear scan first: name decoding through `text()`, and legacy subject
/// mailbox formation through the path's current execution account. Header
/// comments are outside this grammar. Literal tag registration/deliverability
/// is not established by this syntax check.
pub(crate) fn is_mailbox(text: &str) -> bool {
    structured_email_address::is_smtp_mailbox(text)
}

/// Whether text is an absolute URI: a scheme of a letter then letters,
/// digits, plus, minus and dots (RFC 3986 3.1), a colon, and a non-empty
/// remainder inside the URI alphabet, a percent sign spelling a byte only
/// with two hexadecimal digits behind it (RFC 3986 2.1). The fragment
/// delimiter is not in the alphabet: absolute-URI carries no fragment
/// (RFC 3986 4.3), which belongs to URI references. What follows the scheme
/// is the scheme's to define, and is never fetched.
pub(crate) fn is_absolute_uri(text: &str) -> bool {
    absolute_uri::<true>(text)
}

fn absolute_uri<const CERTIFICATE_NAME: bool>(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    if !(bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    {
        return false;
    }
    // The remainder is required, which the generic grammar does not require:
    // RFC 3986's hier-part admits path-empty, so "urn:" parses there. The
    // profile is stricter, and it is the profile this reads under: a name
    // "MUST include both a scheme (e.g., "http" or "ftp") and a
    // scheme-specific-part" (RFC 5280 4.2.1.6). A scheme alone names no
    // place, and accepting one would report a location a report cannot
    // explain.
    if CERTIFICATE_NAME && rest.is_empty() {
        return false;
    }

    // The authority is [userinfo "@"] host [":" port] (RFC 3986 3.2), and
    // it is validated structurally: the user-info delimiter appears at most
    // once, the brackets exist only around an IP literal in the host
    // (3.2.2), and the port holds digits and nothing else (3.2.3). The
    // character walk below covers the remaining free-form segments.
    let mut userinfo = "";
    let mut bare_host = "";
    let mut tail = rest;
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?']).unwrap_or(after.len());
        let authority = &after[..end];
        tail = &after[end..];
        let (before, host_port) = match authority.split_once('@') {
            Some((before, host_port)) => (before, host_port),
            None => ("", authority),
        };
        // A second raw at-sign belongs to no component: neither user-info
        // nor the host may carry one.
        if host_port.contains('@') {
            return false;
        }
        userinfo = before;
        let port = if let Some(inside) = host_port.strip_prefix('[') {
            let Some((literal, past)) = inside.split_once(']') else {
                return false;
            };
            if !is_ip_literal(literal) {
                return false;
            }
            // After the literal only a port may follow within the authority.
            if past.is_empty() {
                None
            } else {
                let Some(digits) = past.strip_prefix(':') else {
                    return false;
                };
                Some(digits)
            }
        } else {
            // A colon in a bare host is the port delimiter: reg-names have
            // no colon of their own.
            let port = if let Some((host, port)) = host_port.split_once(':') {
                bare_host = host;
                Some(port)
            } else {
                bare_host = host_port;
                None
            };
            // "URIs that include an authority (RFC 3986 3.2) MUST include a
            // fully qualified domain name or IP address as the host"
            // (RFC 5280 4.2.1.6). The bracketed form is an address already;
            // a bare host is a name or a dotted-quad, and nothing else, so
            // an empty authority and a word that is neither are refused
            // here rather than passed on as a location.
            //
            // A single closing period is the absolute spelling of a name,
            // which ends at the root (RFC 1034 3.1). It qualifies a name
            // rather than leaving it short of qualified, so it is read here
            // and kept in the location, which is preserved as written.
            let named = bare_host.strip_suffix('.').unwrap_or(bare_host);
            if CERTIFICATE_NAME && !is_domain(named) && bare_host.parse::<Ipv4Addr>().is_err() {
                return false;
            }
            port
        };
        // The port is digits alone, the grammar's *DIGIT; empty included.
        if port.is_some_and(|digits| !digits.bytes().all(|byte| byte.is_ascii_digit())) {
            return false;
        }
    }

    uri_alphabet(userinfo) && uri_alphabet(bare_host) && uri_alphabet(tail)
}

/// Whether a segment holds only what a URI is written from: the unreserved
/// characters, the sub-delimiters, the two component delimiters that appear
/// inside a path or a query, and a percent sign only where two hexadecimal
/// digits follow it (RFC 3986 2).
fn uri_alphabet(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        let permitted = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            );
        if byte == b'%' {
            let mut pair = [bytes.next(), bytes.next()].into_iter();
            if !pair.all(|digit| digit.is_some_and(|digit| digit.is_ascii_hexdigit())) {
                return false;
            }
        } else if !permitted {
            return false;
        }
    }
    true
}

/// Whether text is a URI, the production that carries an optional fragment
/// after the rest of it (RFC 3986 3).
///
/// Certificate names (RFC5280 §4.2.1.6) additionally require their
/// scheme-specific part and host shape. A fragment does not make a
/// scheme-bearing URI relative. CPS pointers use the generic branch below.
pub(crate) fn is_uri(text: &str) -> bool {
    uri::<true>(text)
}

/// `CPSuri` uses RFC3986 URI grammar (RFC5280 §4.2.1.4), independently of
/// §4.2.1.6's certificate-name host and scheme-specific-part requirements.
/// <https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4>
pub(crate) fn is_cps_uri(text: &str) -> bool {
    uri::<false>(text)
}

fn location_uri(
    parent: &Reader<'_>,
    element: &Element<'_>,
    text: &str,
    field: &'static str,
) -> Result<bool> {
    // Admit generic syntax plus scheme/authority/host scans through both the
    // producing Reader and aggregate domain before any of those scans.
    let work = u64::try_from(text.len())
        .ok()
        .and_then(|n| n.checked_mul(32))
        .and_then(|n| n.checked_add(256))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                element.span().start,
            )
        })?;
    parent.charge(work).field(field)?;
    if !is_cps_uri(text) {
        return Ok(false);
    }
    if text
        .split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("ldap"))
    {
        return ldap::valid(parent, element, text, field);
    }
    Ok(location_authority(text))
}

fn location_authority(text: &str) -> bool {
    let (scheme, rest) = text.split_once(':').expect("URI syntax checked");
    let ftp = scheme.eq_ignore_ascii_case("ftp");
    if !ftp && !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    // HTTP(S) requires //authority and forbids empty hosts; FTP uses the
    // mandatory Internet host syntax. LDAP's empty host is a separate contract.
    // RFC9110 §§4.2.1/4.2.2; RFC1738 §§3.1/3.2.
    // <https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1>
    // <https://www.rfc-editor.org/rfc/rfc1738#section-3.1>
    let Some(after) = rest.strip_prefix("//") else {
        return false;
    };
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_port.starts_with('[') {
        // The shared grammar already checked the literal and following port.
        return true;
    }
    let host = host_port
        .split_once(':')
        .map_or(host_port, |(host, _)| host);
    if host.is_empty() {
        return false;
    }
    !ftp || is_domain(host.strip_suffix('.').unwrap_or(host)) || host.parse::<Ipv4Addr>().is_ok()
}

fn uri<const CERTIFICATE_NAME: bool>(text: &str) -> bool {
    match text.split_once('#') {
        // The fragment is written from the same alphabet, and the delimiter
        // appears once: a second one is inside no production.
        Some((rest, fragment)) => absolute_uri::<CERTIFICATE_NAME>(rest) && uri_alphabet(fragment),
        None => absolute_uri::<CERTIFICATE_NAME>(text),
    }
}

/// Whether mask bytes are leading one bits and nothing after them.
/// Whether bracketed host contents are one of the two IP-literal forms of
/// RFC 3986 3.2.2: an IPv6 address, or the versioned future form. A word
/// that merely fits the bracket alphabet is neither and names no host.
fn is_ip_literal(text: &str) -> bool {
    if let Some(rest) = text.strip_prefix(['v', 'V']) {
        // IPvFuture: "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
        let Some((version, suffix)) = rest.split_once('.') else {
            return false;
        };
        return !version.is_empty()
            && version.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !suffix.is_empty()
            && suffix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b':'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                    )
            });
    }
    text.parse::<Ipv6Addr>().is_ok()
}

fn is_contiguous_mask(mask: &[u8]) -> bool {
    let mut still_ones = true;
    for &byte in mask {
        if still_ones {
            if byte == 0xff {
                continue;
            }
            // The one partial byte: leading ones, then zeros to its end.
            let ones = byte.leading_ones();
            let expected = if ones == 0 { 0 } else { 0xffu8 << (8 - ones) };
            if byte != expected {
                return false;
            }
            still_ones = false;
        } else if byte != 0 {
            return false;
        }
    }
    true
}

fn text<'a>(
    parent: &Reader<'a>,
    contents: &'a [u8],
    field: &'static str,
    element: &Element<'a>,
) -> Result<&'a str> {
    // The scans behind this text, ASCII, grammar and bounds alike, walk
    // every content byte: they are charged to the shared work budget, so a
    // caller bounding work sees them on the same meter the reads use.
    parent.charge(contents.len() as u64).field(field)?;
    // An empty address, domain or location satisfies the shape while naming
    // nothing, and a critical alternative-name list carrying only one of
    // these would count as having supplied an identity.
    if contents.is_empty() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            element.span().start,
        ));
    }
    if !contents.is_ascii() {
        // The schema's alphabet is ASCII, and a byte outside it is a name
        // written in an encoding the field does not have. Guessing at one
        // would put a domain or an address in the report that the certificate
        // does not carry.
        return Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            element.span().start,
        ));
    }
    core::str::from_utf8(contents)
        .map_err(|_| Error::new(ErrorCode::MalformedValue, field, element.span().start))
}

#[cfg(test)]
mod tests;
