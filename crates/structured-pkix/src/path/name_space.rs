//! The names an authority may certify below itself.
//!
//! An authority can say that everything under it belongs to one part of the
//! name space: a directory subtree, a domain, a mail domain, a network. That
//! is what keeps a certificate issued for one organization's names from
//! standing for another's, and it is checked here rather than reported,
//! because a name outside the space its authority allowed is not a fact
//! about a path, it is the absence of one.
//!
//! The regions are kept as the authorities wrote them, one layer per
//! authority, and a name is admitted when every layer that speaks about its
//! form admits it (RFC 5280 6.1.4 (g), which computes the intersection).
//! Intersecting subtrees into a single set would ask this crate to invent a
//! region no certificate wrote; asking every layer in turn answers the same
//! question and can only answer it with what somebody signed.

use super::{Meter, cost};
use crate::constraints::NameConstraints;
use crate::error::{CallbackError, CallbackResult, Result};
use crate::extension::Recognizer;
use crate::general_name::GeneralName;
use crate::name::Name;
use crate::oid;
use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec};

/// Where a name falls with respect to one region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// The region holds the name.
    Inside,
    /// The region is of the name's form and does not hold it.
    Outside,
    /// The region is of another form, so it says nothing about this name.
    Elsewhere,
    /// The region is of the name's form and this crate cannot say whether it
    /// holds the name.
    Unknown,
}

/// What the name space says about one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// Every name the certificate carries is where it is allowed to be.
    Admitted,
    /// A name sits in a region an authority above forbade.
    Excluded,
    /// A name sits outside every region an authority above allowed for its
    /// form.
    NotPermitted,
    /// A constraint speaks about a form of name this crate does not match
    /// against, so whether the certificate obeys it has no answer here. It
    /// is not admitted: an unenforceable constraint that let a path through
    /// would be a constraint that did nothing.
    Unenforceable,
}

/// A name of a certificate, in the form a constraint is written against.
#[derive(Debug, Clone, Copy)]
enum Presented<'a> {
    /// A distinguished name: the subject, or a directory alternative name.
    Directory(&'a Name<'a>),
    /// A mailbox, from an alternative name or from the legacy attribute a
    /// subject can carry one in.
    Email(&'a [u8]),
    /// A host or domain name.
    Dns(&'a [u8]),
    /// A location, of which only the host part is constrained. This is how a
    /// region is written; a location a certificate carries arrives as the
    /// [`Host`](Self::Host) it names.
    Uri(&'a [u8]),
    /// The host a location names, read out of it once.
    ///
    /// Finding it reads the authority from the front, and the regions of a
    /// space are many: reading it again for each of them is their product,
    /// where reading it once and comparing the result is their sum.
    Host(&'a [u8]),
    /// An address, four or sixteen bytes of it.
    Ip(&'a [u8]),
    /// A form no constraint here is matched against. It carries which form,
    /// so that a constraint of the same form is the one that has no answer
    /// and a constraint of another form still says nothing about it.
    Opaque(Form<'a>),
    /// Text written where a name of a matched form belongs that is not one.
    /// A region of that same form has no answer about it, and one of another
    /// form still says nothing about it, so which form it was written in is
    /// carried.
    Unreadable(Malformed),
}

/// Which form text was written in, where the text is not a name of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Malformed {
    /// Written where a mailbox belongs.
    Mailbox,
    /// Written where a location belongs, and naming no host that can be
    /// established.
    Location,
}

/// Which of the forms a general name takes, for the ones that are compared
/// without being matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form<'a> {
    /// A name whose meaning is its type identifier's, which is carried
    /// because it is what tells one such form from another: a constraint
    /// over one type says nothing about a name of a different one.
    Other(Oid<'a>),
    /// An X.400 address.
    X400,
    /// An EDI party name.
    EdiParty,
    /// A name that is an identifier.
    RegisteredId,
}

/// How many forms a name or a region can be counted in.
const SHAPES: usize = 6;

impl Presented<'_> {
    /// Which of the forms this counts in.
    ///
    /// A region and a name are compared only where the two are of one form:
    /// [`fit`] answers [`Elsewhere`](Fit::Elsewhere) for any other pair
    /// without reading either of them. Counting by form is what lets a
    /// charge be taken for the comparisons that will happen rather than for
    /// every name against every region.
    ///
    /// The forms nothing is matched against share one count. Two of them
    /// meet only where their type identifiers agree, so counting them
    /// together pays for a few comparisons that will not happen, which is a
    /// far smaller error than the product of everything with everything.
    fn shape(self) -> usize {
        match self {
            Self::Directory(_) => 0,
            Self::Email(_) | Self::Unreadable(Malformed::Mailbox) => 1,
            Self::Dns(_) => 2,
            Self::Uri(_) | Self::Host(_) | Self::Unreadable(Malformed::Location) => 3,
            Self::Ip(_) => 4,
            Self::Opaque(_) => 5,
        }
    }

    /// How many bytes one comparison against a region of its form reads.
    fn weight(self) -> u64 {
        match self {
            Self::Directory(name) => name.as_bytes().len() as u64,
            Self::Email(text) | Self::Dns(text) | Self::Uri(text) | Self::Host(text) => {
                text.len() as u64
            }
            Self::Ip(octets) => octets.len() as u64,
            // A name whose form is named by a type identifier is told from a
            // region by comparing those identifiers, which reads them: a
            // certificate writes the one and an extension the other, so how
            // long they are is not ours, and two sharing a prefix are read
            // to where they part.
            Self::Opaque(Form::Other(identifier)) => identifier.as_bytes().len() as u64,
            // The rest are told apart by which form they are and nothing
            // else, so no bytes are read and there is nothing to charge.
            Self::Opaque(_) | Self::Unreadable(_) => 0,
        }
    }
}

impl<'a> Presented<'a> {
    /// The form a general name is presented in.
    fn of(name: &'a GeneralName<'a>) -> Self {
        match name {
            GeneralName::Directory(name) => Self::Directory(name),
            GeneralName::Email(address) => Self::Email(address.as_bytes()),
            GeneralName::Dns(host) => Self::Dns(host.as_bytes()),
            GeneralName::Uri(location) => Self::Uri(location.as_bytes()),
            GeneralName::IpAddress(address) => Self::Ip(address),
            GeneralName::Other { type_id, .. } => Self::Opaque(Form::Other(*type_id)),
            GeneralName::X400(_) => Self::Opaque(Form::X400),
            GeneralName::EdiParty(_) => Self::Opaque(Form::EdiParty),
            GeneralName::RegisteredId(_) => Self::Opaque(Form::RegisteredId),
        }
    }
}

/// The regions the authorities above a certificate named, one layer each.
#[derive(Debug)]
pub(super) struct NameSpace<'a, S = ()> {
    layers: OwnedVec<Layer<'a, S>>,
}

#[derive(Debug)]
struct Layer<'a, S> {
    constraints: NameConstraints<'a>,
    source: S,
}

impl<'a, S> core::ops::Deref for Layer<'a, S> {
    type Target = NameConstraints<'a>;

    fn deref(&self) -> &Self::Target {
        &self.constraints
    }
}

#[cfg(test)]
impl<'a> NameSpace<'a> {
    pub(super) fn new(execution: &Memory) -> Self {
        Self::with_sources(execution)
    }
    /// Narrows the space by what one authority said, which applies to every
    /// certificate below it and not to the authority itself.
    pub(super) fn narrow(
        &mut self,
        constraints: NameConstraints<'a>,
    ) -> core::result::Result<(), MemoryError> {
        self.narrow_from(constraints, ())
    }
}

impl<'a, S: Copy> NameSpace<'a, S> {
    pub(super) fn with_sources(execution: &Memory) -> Self {
        Self {
            layers: execution.vector(),
        }
    }

    /// Source identity travels with each retained constraint allocation.
    pub(super) fn narrow_from(
        &mut self,
        constraints: NameConstraints<'a>,
        source: S,
    ) -> core::result::Result<(), MemoryError> {
        self.layers.try_push(Layer {
            constraints,
            source,
        })
    }

    /// Whether anything constrains the space at all, which is the common
    /// case and the one that costs nothing to answer.
    pub(super) fn is_open(&self) -> bool {
        self.layers.is_empty()
    }

    /// How many regions the space is described by, of every form together.
    /// What a comparison costs is counted per form by [`Self::comparisons`];
    /// this is here so a test can say how much was narrowed.
    #[cfg(test)]
    pub(super) fn regions(&self) -> usize {
        self.layers
            .iter()
            .map(|layer| layer.permitted().len() + layer.excluded().len())
            .sum()
    }

    /// Charges what holding a certificate's names to this space will read,
    /// and says whether there is budget left to read it.
    ///
    /// Counted by form, because a region and a name are compared only where
    /// the two are of one form. Charging every name against every region
    /// makes a long distinguished name pay for each domain an authority
    /// happened to write, and the path is then refused for work nobody was
    /// going to do.
    ///
    /// By form rather than pair by pair, which would itself be the product
    /// this exists to keep off the meter: the regions are counted once and
    /// the names once, and the two counts are multiplied per form.
    ///
    /// Name by name rather than as one sum at the end, because forming a
    /// name reads it: a list priced in full before the meter is consulted
    /// is a list read in full whatever the budget said.
    pub(super) fn charge(
        &self,
        subject: &Name<'_>,
        alternatives: &[GeneralName<'_>],
        meter: &mut impl Meter,
        execution: &Memory,
    ) -> Result<bool> {
        let mut regions = [0u64; SHAPES];
        for layer in &self.layers {
            for region in layer.permitted().iter().chain(layer.excluded().iter()) {
                if !meter.spend(cost::ENTRY)? {
                    return Ok(false);
                }
                regions[Presented::of(region.base()).shape()] += 1;
            }
        }

        for unformed in unformed(subject, alternatives, execution) {
            let unformed = unformed?;
            // What putting this name into its form reads, charged before it
            // is read. A mailbox attribute is held to the grammar and a
            // location is scanned to where its host begins, and how much
            // text either holds is a certificate's to decide: pricing the
            // whole list first and consulting the meter afterwards runs
            // that reading past a budget that was already spent.
            if !meter.spend(unformed.forming() / cost::COMPARED)? {
                return Ok(false);
            }
            execution
                .charge_work(1 + unformed.forming())
                .map_err(|reason| subject.resource(reason))?;
            let name = unformed.form();

            // And what comparing it against the regions of its own form
            // will read. Regions of another form are answered without
            // reading either side, so they are not counted here.
            let against = regions[name.shape()];
            let reads = against
                .checked_mul(name.weight())
                .ok_or_else(|| subject.resource(MemoryError::WorkExceeded))?
                / cost::COMPARED;
            let work = cost::NAME
                .checked_mul(against)
                .and_then(|work| work.checked_add(reads))
                .ok_or_else(|| subject.resource(MemoryError::WorkExceeded))?;
            if !meter.spend(work)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the names a certificate carries are where its authorities
    /// allowed them to be.
    ///
    /// The subject's distinguished name is checked where it holds anything,
    /// and an empty one carries no identity to constrain (RFC 5280 4.2.1.6).
    /// A mailbox written into the subject as the legacy attribute is checked
    /// against the mail constraints, because that is where such a
    /// certificate's mail identity is (RFC 5280 4.2.1.10).
    #[cfg(test)]
    pub(super) fn admits<E>(
        &self,
        subject: &Name<'_>,
        alternatives: &[GeneralName<'_>],
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<Admission, E> {
        self.admits_located(subject, alternatives, recognizer, execution)
            .map(|(admission, _)| admission)
    }

    /// Returns the source of the decisive constraint without cloning its data.
    pub(super) fn admits_located<E>(
        &self,
        subject: &Name<'_>,
        alternatives: &[GeneralName<'_>],
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<(Admission, Option<S>), E> {
        if self.layers.is_empty() {
            return Ok((Admission::Admitted, None));
        }

        let mut worst = (Admission::Admitted, None);
        for name in presented(subject, alternatives, execution) {
            match self.admits_one(name?, subject, recognizer, execution)? {
                // Forbidden outright is the answer whatever else was found:
                // no other region can make a name that was excluded allowed.
                decision @ (Admission::Excluded, _) => return Ok(decision),
                decision @ (Admission::NotPermitted, _) => worst = decision,
                decision @ (Admission::Unenforceable, _) if worst.0 == Admission::Admitted => {
                    worst = decision;
                }
                _ => {}
            }
        }
        Ok(worst)
    }

    /// Where one name of a certificate falls, across every layer.
    fn admits_one<E>(
        &self,
        name: Presented<'_>,
        origin: &Name<'_>,
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<(Admission, Option<S>), E> {
        let mut worst = (Admission::Admitted, None);
        for layer in &self.layers {
            // Forbidden first: a region that excludes a name excludes it
            // however many other regions allow it (RFC 5280 6.1.4 (g)).
            let mut unreadable = false;
            for region in layer.excluded() {
                execution
                    .charge_work(1)
                    .map_err(|reason| origin.resource(reason))?;
                match fit(region.base(), name, origin, recognizer, execution)? {
                    Fit::Inside => return Ok((Admission::Excluded, Some(layer.source))),
                    Fit::Unknown => unreadable = true,
                    Fit::Outside | Fit::Elsewhere => {}
                }
            }

            // Allowed: where a layer names any region of this form, the name
            // has to be in one of them. Where it names none, this layer says
            // nothing about names of this form and allows them all.
            let mut spoken_for = false;
            let mut inside = false;
            for region in layer.permitted() {
                execution
                    .charge_work(1)
                    .map_err(|reason| origin.resource(reason))?;
                match fit(region.base(), name, origin, recognizer, execution)? {
                    Fit::Inside => {
                        inside = true;
                        break;
                    }
                    Fit::Outside => spoken_for = true,
                    Fit::Unknown => {
                        spoken_for = true;
                        unreadable = true;
                    }
                    Fit::Elsewhere => {}
                }
            }

            if !inside && spoken_for {
                // A region this crate cannot match leaves the question open
                // rather than answered against the certificate.
                // Keep looking for an explicit exclusion in later layers.
                // The report gives exclusion precedence over a permitted-set
                // miss; RFC5280 §6.1.3(b,c) requires both constraints to hold.
                let admission = if unreadable {
                    Admission::Unenforceable
                } else {
                    Admission::NotPermitted
                };
                if admission == Admission::NotPermitted || worst.0 == Admission::Admitted {
                    worst = (admission, Some(layer.source));
                }
            }
            if unreadable && worst.0 == Admission::Admitted {
                worst = (Admission::Unenforceable, Some(layer.source));
            }
        }
        Ok(worst)
    }
}

/// The legacy mail identity of a subject, as a name to be matched or as
/// text that cannot be one.
///
/// An alternative name of the mail form arrives already held to the mailbox
/// grammar by the reader, and needs no second look. The attribute a subject
/// may carry the same identity in is a directory string, held to nothing:
/// whatever an issuer wrote is what reaches here. Matching such text anyway
/// reads a host out of it that a mail client would not agree with, since
/// `user@example.com@evil.net` has no local part a mailbox may hold and the
/// last separator is not where the host begins. Taking it as a mailbox puts
/// the certificate under whoever holds `evil.net`, and text with no host at
/// all falls outside every region, which walks it past an excluded subtree
/// where nothing else would catch it. Neither is a fact about the regions,
/// so this is the constraint's refusal rather than a region's, as it is for
/// a location whose host cannot be established (RFC 5280 4.2.1.10).
fn presented_mailbox(value: &[u8]) -> Presented<'_> {
    match core::str::from_utf8(value) {
        Ok(text) if crate::general_name::is_mailbox(text) => Presented::Email(value),
        _ => Presented::Unreadable(Malformed::Mailbox),
    }
}

/// One name a certificate carries, before it has been put into its form.
///
/// Between the two so that what forming a name reads can be charged before
/// it is read: a name already formed has already cost whatever forming it
/// cost, and the meter is then being told about work it could not refuse.
#[derive(Clone, Copy)]
enum Unformed<'a> {
    /// The subject's distinguished name, which is already in its form.
    Directory(&'a Name<'a>),
    /// The contents of a legacy mail attribute, still to be held to the
    /// mailbox grammar.
    Mailbox(&'a [u8]),
    /// One alternative name, still to be reduced to what is matched.
    Alternative(&'a GeneralName<'a>),
}

impl<'a> Unformed<'a> {
    /// What putting it into its form reads, which happens once for the name
    /// whatever the regions say.
    ///
    /// A location is scanned from the front to find where its host begins,
    /// and a legacy mail attribute is read against the mailbox grammar.
    /// Both are done once per name rather than once per region, which is
    /// why they are counted here rather than in the per-form weight: that
    /// weight is what one comparison against one region reads, and a
    /// location's is its host.
    fn forming(self) -> u64 {
        match self {
            Self::Mailbox(value) => value.len() as u64,
            Self::Alternative(GeneralName::Uri(location)) => location.len() as u64,
            // The subject is already a name, and an alternative of any
            // other form is carried as it was written: nothing is read to
            // put either into its form.
            Self::Directory(_) | Self::Alternative(_) => 0,
        }
    }

    /// Puts it into the form the regions are matched against it in.
    fn form(self) -> Presented<'a> {
        match self {
            Self::Directory(subject) => Presented::Directory(subject),
            Self::Mailbox(value) => presented_mailbox(value),
            Self::Alternative(name) => presented_name(name),
        }
    }
}

/// The names a certificate carries, before they are put into the forms the
/// regions are matched against them in.
///
/// One definition, because what is counted before the comparison and what
/// is compared have to be the same list: a charge for a name nobody looks
/// at refuses a path for work nobody does, and a name left out of the count
/// is compared for nothing.
///
/// The subject's distinguished name is here where it holds anything, and an
/// empty one carries no identity to constrain (RFC 5280 4.2.1.6). The
/// legacy mail identity is here only where it is the identity: "when
/// constraints are imposed on the rfc822Name name form, but the certificate
/// does not include a subject alternative name, the rfc822Name constraint
/// MUST be applied to the attribute of type emailAddress in the subject
/// distinguished name" (RFC 5280 4.2.1.10). A certificate that carries
/// alternative names carries its mail identity among them, and holding its
/// subject attribute to the mail regions as well would refuse it for an
/// address the regions were never about.
fn unformed<'a, 'q>(
    subject: &'a Name<'a>,
    alternatives: &'a [GeneralName<'a>],
    execution: &'q Memory,
) -> impl Iterator<Item = Result<Unformed<'a>>> + 'q
where
    'a: 'q,
{
    let directory = (!subject.is_empty()).then_some(Unformed::Directory(subject));
    let mailboxes = alternatives
        .is_empty()
        .then(|| {
            subject
                .attributes_of(oid::EMAIL_ADDRESS, execution)
                .map(|attribute| {
                    attribute.map(|attribute| Unformed::Mailbox(attribute.value().contents()))
                })
        })
        .into_iter()
        .flatten();
    directory.into_iter().map(Ok).chain(mailboxes).chain(
        alternatives
            .iter()
            .map(|name| Ok(Unformed::Alternative(name))),
    )
}

/// The same names, in the forms the regions are matched against them.
fn presented<'a, 'q>(
    subject: &'a Name<'a>,
    alternatives: &'a [GeneralName<'a>],
    execution: &'q Memory,
) -> impl Iterator<Item = Result<Presented<'a>>> + 'q
where
    'a: 'q,
{
    unformed(subject, alternatives, execution).map(move |name| {
        let name = name?;
        execution
            .charge_work(1 + name.forming())
            .map_err(|reason| subject.resource(reason))?;
        Ok(name.form())
    })
}

/// One name a certificate carries, in the form the regions are matched
/// against it.
///
/// A location is reduced to the host it names here rather than inside the
/// comparison, because finding that host reads the authority from the front
/// and a space holds as many regions as the authorities above wrote. Doing
/// it per region is their product; doing it once is their sum, and the
/// answer is the same either way.
fn presented_name<'a>(name: &'a GeneralName<'a>) -> Presented<'a> {
    match name {
        GeneralName::Uri(location) => match host_of(location.as_bytes()) {
            Some(host) => Presented::Host(host),
            // "If a constraint is applied to the uniformResourceIdentifier
            // name form and a subsequent certificate includes a
            // subjectAltName extension with a uniformResourceIdentifier that
            // does not include an authority component with a host name
            // specified as a fully qualified domain name ... then the
            // application MUST reject the certificate" (RFC 5280 4.2.1.10).
            // Reading such a location as merely outside the region would let
            // it past an excluded subtree, where nothing else would catch
            // it, so the refusal is the constraint's rather than the
            // region's.
            None => Presented::Unreadable(Malformed::Location),
        },
        other => Presented::of(other),
    }
}

/// Where one name falls with respect to one region.
fn fit<E>(
    base: &GeneralName<'_>,
    name: Presented<'_>,
    origin: &Name<'_>,
    recognizer: &impl Recognizer<Error = E>,
    execution: &Memory,
) -> CallbackResult<Fit, E> {
    let admit = |work| {
        execution
            .charge_work(work)
            .map_err(|reason| origin.resource(reason))
    };
    Ok(match (Presented::of(base), name) {
        (Presented::Directory(region), Presented::Directory(name)) => {
            decide(name.starts_with(region, execution)?)
        }
        (Presented::Dns(region), Presented::Dns(name)) => {
            admit(region.len().min(name.len()) as u64)?;
            decide(host_within(region, name))
        }
        (Presented::Email(region), Presented::Email(name)) => {
            // Locate both separators, then compare local/host portions. The
            // region belongs to retained storage, not necessarily this run.
            let work = (region.len() as u64)
                .checked_add(name.len() as u64)
                .and_then(|work| work.checked_mul(2))
                .ok_or_else(|| origin.resource(MemoryError::WorkExceeded))?;
            admit(work)?;
            decide(mailbox_within(region, name))
        }
        (Presented::Uri(region), Presented::Host(host)) => {
            admit(region.len().min(host.len()) as u64)?;
            decide(at_or_under(region, host))
        }
        (Presented::Ip(region), Presented::Ip(name)) => {
            admit(name.len() as u64)?;
            decide(network_within(region, name))
        }
        // A region and text written where a name of its form belongs that is
        // not one. The region is about names of that form and this is not
        // one, so the region has no answer about it rather than an answer
        // against it: reading it as outside would let it past an excluded
        // subtree. Which form the text was written in is what keeps this to
        // the regions it is about: an unreadable mailbox says nothing about
        // a location region, and the reverse.
        (Presented::Email(_), Presented::Unreadable(Malformed::Mailbox))
        | (Presented::Uri(_), Presented::Unreadable(Malformed::Location)) => Fit::Unknown,
        // A constraint over a name type defined elsewhere, and a name of
        // that same type. Whether the scheme enforces it is the scheme's to
        // say: it is what clears the extension's critical mark, and a
        // constraint claimed there and refused here would make the claim
        // buy nothing, since a certificate actually carrying such a name
        // could then never be on a path. Where nobody claims it, the
        // constraint is real and unanswered, which is not the same as
        // absent.
        (Presented::Opaque(Form::Other(region)), Presented::Opaque(Form::Other(name))) => {
            if region.as_bytes().len() != name.as_bytes().len() {
                return Ok(Fit::Elsewhere);
            }
            admit(region.as_bytes().len() as u64)?;
            if region != name {
                return Ok(Fit::Elsewhere);
            }
            if recognizer
                .recognizes_name_constraint(region, execution)
                .map_err(CallbackError::Callback)?
            {
                Fit::Elsewhere
            } else {
                Fit::Unknown
            }
        }
        // The other forms have no such claim to make: nothing here or in a
        // scheme states a containment rule for them.
        (Presented::Opaque(region), Presented::Opaque(name)) if region == name => Fit::Unknown,
        _ => Fit::Elsewhere,
    })
}

/// A yes or a no as the fit it is.
fn decide(inside: bool) -> Fit {
    if inside { Fit::Inside } else { Fit::Outside }
}

/// Whether a host name sits in a domain, which is the whole of it or
/// anything under it (RFC 5280 4.2.1.10).
///
/// The region is written without a leading separator in the profile, and
/// with one by issuers who mean strictly below it. Both are read: a leading
/// separator asks for something under the domain, and without one the domain
/// itself is in its own region.
fn host_within(region: &[u8], name: &[u8]) -> bool {
    // The region of no name is the whole space, which is how a constraint
    // that permits every host is written.
    if region.is_empty() {
        return true;
    }
    let Some(rest) = name.len().checked_sub(region.len()) else {
        return false;
    };
    if !name[rest..].eq_ignore_ascii_case(region) {
        return false;
    }
    // The tail matching is not enough on its own: `notexample.com` ends with
    // `example.com` and is a different domain. What is left in front has to
    // be nothing, or a label boundary.
    rest == 0 || region.first() == Some(&b'.') || name[rest - 1] == b'.'
}

/// Whether a mailbox sits in a region: the same mailbox, or one at a host
/// the region names (RFC 5280 4.2.1.10).
///
/// A region holding a separator is one mailbox, and the comparison is the
/// mailbox comparison: the host part without regard to case, the local part
/// with it, because what a local part means belongs to the host that issues
/// it and nothing here may fold two of them together.
fn mailbox_within(region: &[u8], name: &[u8]) -> bool {
    let Some(host) = host_of_mailbox(name) else {
        return false;
    };
    match host_of_mailbox(region) {
        Some(region_host) => {
            let local = name.len() - host.len();
            let region_local = region.len() - region_host.len();
            region[..region_local] == name[..local] && region_host.eq_ignore_ascii_case(host)
        }
        None => at_or_under(region, host),
    }
}

/// Whether a host is the one a region names, or under the domain it names.
///
/// This is the rule the mail and location forms are written to, where a
/// region without a leading separator names one host and a region with one
/// names a domain that "may be expanded with one or more labels"
/// (RFC 5280 4.2.1.10). It is not the rule the domain-name form uses, where
/// the region names a subtree whether or not the separator is written, and
/// reading the two the same way would let a certificate for one host stand
/// for every host under it.
fn at_or_under(region: &[u8], host: &[u8]) -> bool {
    if region.first() == Some(&b'.') {
        return host.len() > region.len() && host_within(region, host);
    }
    region.eq_ignore_ascii_case(host)
}

/// The host part of a mailbox, which is everything after the last separator.
/// A mailbox without one names no host and is in no region.
fn host_of_mailbox(mailbox: &[u8]) -> Option<&[u8]> {
    let at = mailbox.iter().rposition(|byte| *byte == b'@')?;
    Some(&mailbox[at + 1..])
}

/// The host part of a location, without the user information in front of it
/// or the port after it, and unwrapped from the brackets an address is
/// written in.
///
/// This reads the text and resolves nothing: a location in a certificate is
/// a string, and a parser that fetched one would be asking a server chosen
/// by whoever wrote the document to confirm what the document says.
fn host_of(location: &[u8]) -> Option<&[u8]> {
    // No authority, no host: a location written without one names a
    // resource rather than a server, and reading what follows the scheme as
    // a host would find one in `mailto:a@b`. The authority begins with the
    // two separators immediately after the scheme's colon and nowhere else
    // (RFC 3986 3), so `urn:a//host.example.com/x` has a path that begins
    // with them and still names no server: taking those would admit a
    // certificate under a region that permits a host the location does not
    // have.
    let scheme = location.iter().position(|byte| *byte == b':')?;
    let rest = location.get(scheme + 1..)?.strip_prefix(b"//".as_slice())?;
    let end = rest
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..end];

    // The user information is separated from the host by the last separator
    // in the authority, since the information itself may hold one.
    let authority = match authority.iter().rposition(|byte| *byte == b'@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };

    // An address is written in brackets, and only an address is: what the
    // brackets hold is an IPv6 address or an IPvFuture literal, never a
    // registered name (RFC 3986 3.2.2). A constraint applies to the host of
    // a location "if the authority contains a domain name" (RFC 5280
    // 4.2.1.10), and this authority does not, whatever the text inside the
    // brackets is spelled like.
    //
    // Unwrapping them and reading what is inside as a name is how
    // `http://[v1.example.com]/` would be admitted under a region that
    // permits hosts in `example.com`: the IPvFuture grammar holds periods
    // and letters, so a literal can be written to read as a domain that
    // whoever wrote it does not hold. There is no host here, so no region
    // applies and the caller answers that the constraint could not be
    // enforced.
    if authority.first() == Some(&b'[') {
        return None;
    }
    let host = match authority.iter().rposition(|byte| *byte == b':') {
        Some(at) => &authority[..at],
        None => authority,
    };

    // A single closing period is the absolute spelling of a name, ending it
    // at the root (RFC 1034 3.1). It qualifies the name rather than making
    // it a different one, and the reader keeps it because that is how the
    // location was written; a region names the same host without it, so the
    // two are brought to one spelling before they are compared.
    let host = host.strip_suffix(b".".as_slice()).unwrap_or(host);

    // And it has to be a host name. A location whose authority names an
    // address rather than a fully qualified domain name is one a location
    // constraint cannot be applied to (RFC 5280 4.2.1.10), which the caller
    // answers as unenforceable rather than as a name in some other region.
    core::str::from_utf8(host)
        .ok()
        .filter(|host| crate::general_name::is_domain(host))
        .map(str::as_bytes)
}

/// Whether an address sits in a network, where the region is the address and
/// the mask of the same width (RFC 5280 4.2.1.10), and `None` where the
/// region is not a network of the address's width.
fn network_within(region: &[u8], name: &[u8]) -> bool {
    // A network is an address and a mask of one width and an address is one
    // of half it, both fixed by the profile and both checked when they were
    // read (RFC 5280 4.2.1.10). Widths that do not pair are therefore two
    // address families, and an address of one family is certainly not inside
    // a network of the other: answering that the comparison could not be
    // made would refuse a certificate for carrying an address the
    // constraint never spoke about.
    if region.len() != name.len() * 2 {
        return false;
    }
    let (network, mask) = region.split_at(name.len());
    network
        .iter()
        .zip(mask)
        .zip(name)
        .all(|((network, mask), address)| network & mask == address & mask)
}

#[cfg(test)]
mod tests;
