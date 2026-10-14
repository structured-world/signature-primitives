//! The extensions a certificate carries, kept whether or not they are
//! understood.
//!
//! An extension marked critical says that a relying party which does not
//! understand it must not use the certificate. That is a decision about a
//! verdict, not about whether the bytes can be read, so an unknown critical
//! extension is reported here rather than refused: the product has to be able
//! to say what it found and why it stopped, and a parser that refused would
//! leave nothing to say it with.
//!
//! Which identifiers count as understood is not fixed by this crate alone. A
//! scheme knows extensions of its own, and says so by implementing
//! [`Recognizer`]. What it supplies is a set of identifiers, never code and
//! never a place to fetch anything from.

use crate::access::{DistributionPoints, InfoAccess};
use crate::constraints::{BasicConstraints, InhibitAnyPolicy, NameConstraints, PolicyConstraints};
use crate::error::{CallbackError, CallbackResult, Error, ErrorCode, Located, Result, gate};
use crate::general_name::{self, GeneralName};
use crate::identifier::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use crate::oid;
use crate::policy::{CertificatePolicies, PolicyMappings};
use crate::qualified::QcStatements;
use crate::usage::{ExtendedKeyUsage, KeyUsage};
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};
use structured_asn1::{Element, Oid, Parser, Reader, Span, Tag, universal};

mod entry;
pub use entry::{ExtensionFields, ExtensionHeader, ExtensionValue, open, read_with};

/// One extension: what it is, whether it must be understood, and its value.
#[derive(Debug, Clone, Copy)]
pub struct Extension<'a> {
    kind: Oid<'a>,
    critical: bool,
    value: &'a [u8],
    value_span: Span,
    span: Span,
    /// The parser the certificate was read with, kept so every later decode
    /// of this value is charged to that one budget: a signature accepting an
    /// unrelated parser would let repeated decodes reset the counters and
    /// cost many times the caller's declared limit.
    parser: &'a Parser,
    /// Depth of the reader that produced extnValue; lazy decoding must not
    /// reset the certificate's aggregate depth allowance.
    outer: u32,
}

impl<'a> Extension<'a> {
    /// Which extension this is.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }

    /// Whether a relying party that does not understand this extension must
    /// refuse the certificate.
    #[must_use]
    pub fn is_critical(self) -> bool {
        self.critical
    }

    /// The value, still encoded: the contents of the octet string the
    /// extension wraps it in, which is a structure of its own.
    #[must_use]
    pub fn value(self) -> &'a [u8] {
        self.value
    }

    /// Where the extension sits in the document.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }

    /// A reader over the value using the current execution domain and the
    /// original parser session's cumulative ceilings, offsets and depth.
    ///
    /// How a scheme reads an extension of its own. Sharing the budget is what
    /// keeps a certificate carrying a hundred extensions from costing a
    /// hundred times what the caller allowed, and the offsets a reader made
    /// this way reports are offsets in the whole document. The wrapped value
    /// sits below extnValue and retains the certificate's depth allowance.
    pub fn reader(self, execution: &Memory) -> structured_asn1::Result<Reader<'a>> {
        // Always DER: the value lives inside the certificate, which RFC 5280
        // section 4.1 defines in DER, whatever encoding the envelope was
        // read in. A caller that read a BER envelope must not have its
        // leniency reach into the certificate's own structures.
        self.parser.read_nested_in(
            self.value,
            self.value_span.start,
            structured_asn1::Encoding::Der,
            self.outer,
            execution,
        )
    }

    /// Original DER value under both origin and current query ceilings.
    ///
    /// The query may come from another source. Original parser identity,
    /// offsets and inherited depth are preserved from creation; allocation,
    /// traversal and scratch also obey the current operation's local budget
    /// and aggregate account. Previously retained storage is not transferred.
    pub fn reader_in<'work>(self, query: &Reader<'work>) -> structured_asn1::Result<Reader<'work>>
    where
        'a: 'work,
    {
        self.parser.read_nested_query_in(
            query,
            self.value,
            self.value_span.start,
            structured_asn1::Encoding::Der,
            self.outer,
        )
    }

    /// The parser the certificate was read with, whose budget every decode
    /// of this extension shares.
    #[must_use]
    pub fn parser(self) -> &'a Parser {
        self.parser
    }
}

/// The extensions of one certificate, in the order it holds them.
#[derive(Debug)]
pub struct Extensions<'a> {
    items: OwnedVec<Extension<'a>>,
}

impl<'a> Extensions<'a> {
    /// Account retaining this collection's storage. Deferred decoding may
    /// explicitly use a different current execution domain.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.items.memory()
    }

    pub(crate) fn empty(execution: &Memory) -> Self {
        Self {
            items: execution.vector(),
        }
    }
    /// Every extension in order, funded by this query's current execution.
    /// The constructor allocates/clones nothing. Each metadata step is paid
    /// before advancing; a resource failure is yielded once, then traversal
    /// stops. Empty/exhausted catalogues perform no additional charged work.
    /// Recognition and payload parsing must fund their own data-dependent work.
    pub fn iter<'r, 'e, W: Work + 'e>(
        &'r self,
        execution: &'e W,
    ) -> impl Iterator<Item = Result<&'r Extension<'a>>> + 'e
    where
        'r: 'e,
    {
        let mut entries = self.items.iter();
        let mut failed = false;
        core::iter::from_fn(move || {
            if failed || entries.as_slice().is_empty() {
                return None;
            }
            if let Err(reason) = execution.charge_work(1) {
                failed = true;
                // Source metadata for the refusal; the traversal has not
                // advanced or exposed this item as a successful reading.
                let at = entries.as_slice()[0].span.start;
                return Some(Err(Error::resource(reason, "extensions", at)));
            }
            entries.next().map(Ok)
        })
    }

    /// How many there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// One extension by identifier. There is at most one of each: a
    /// certificate carrying two copies is refused when it is read, because
    /// which of them applies would have no answer.
    pub fn get<W: Work>(&self, kind: Oid<'_>, execution: &W) -> Result<Option<&Extension<'a>>> {
        for item in &self.items {
            let work = item.kind.as_bytes().len().max(kind.as_bytes().len()) as u64;
            execution
                .charge_work(1 + work)
                .map_err(|reason| Error::resource(reason, "extensions", item.span.start))?;
            if item.kind == kind {
                return Ok(Some(item));
            }
        }
        Ok(None)
    }

    /// The critical extensions this run did not understand: the ones nobody
    /// knows, and the ones this crate knows by identifier but whose values do
    /// not parse.
    ///
    /// A non-empty answer is what blocks a verdict. Knowing the identifier is
    /// not understanding the extension: a critical key usage whose value
    /// never parsed was never understood, and filtering it out by identifier
    /// alone would leave a validator seeing no blocker for a demand the
    /// certificate marked as one. Extensions a `recognizer` claims are that
    /// scheme's to decode and are taken at its word.
    ///
    /// The answer is returned rather than acted on, because what to do about
    /// it belongs to the policy layer and the report has to name them. An
    /// error is a spent budget and only that: it says this run gave up before
    /// the question was answered, which must not be reported as a demand
    /// nobody understood.
    pub fn unhandled_critical<'r, E>(
        &'r self,
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<OwnedVec<&'r Extension<'a>>, E> {
        let mut unhandled = execution.vector();
        for item in self.criticals(execution) {
            let item = item?;
            if !self.understands(item, recognizer, execution)? {
                unhandled
                    .try_push(item)
                    .map_err(|reason| Error::resource(reason, "extensions", item.span().start))?;
            }
        }
        Ok(unhandled)
    }

    /// The critical extensions, in the order the certificate wrote them and
    /// without reading any of their values.
    ///
    /// Separate from [`Self::understands`] because working out whether one
    /// was understood decodes its value, and how much that value holds is a
    /// document's to decide. A caller holding a budget charges for an entry
    /// and then asks: the two joined into one step would decode before the
    /// charge could refuse it, since asking for the next entry is what would
    /// do the decoding.
    /// Each metadata entry is admitted before testing its critical flag,
    /// including skipped entries and a complete miss. A resource error is
    /// yielded once, then iteration permanently ends without further charges.
    ///
    /// # Examples
    /// ```no_run
    /// use structured_asn1::memory::Memory;
    /// use structured_pkix::{Certificate, Result};
    /// fn has_critical(certificate: &Certificate<'_>, execution: &Memory) -> Result<bool> {
    ///     match certificate.tbs().extensions().criticals(execution).next() {
    ///         Some(item) => { item?; Ok(true) }
    ///         None => Ok(false),
    ///     }
    /// }
    /// ```
    pub fn criticals<'r, 'e>(
        &'r self,
        execution: &'e Memory,
    ) -> impl Iterator<Item = Result<&'r Extension<'a>>> + 'e
    where
        'r: 'e,
    {
        let mut entries = self.iter(execution);
        core::iter::from_fn(move || {
            for item in entries.by_ref() {
                let item = match item {
                    Ok(item) => item,
                    Err(error) => return Some(Err(error)),
                };
                if item.critical {
                    return Some(Ok(item));
                }
            }
            None
        })
    }

    /// Whether this run understood one extension: this crate decodes it, or
    /// a scheme claims it and it holds one complete value.
    ///
    /// Knowing the identifier is not understanding the extension: a critical
    /// key usage whose value never parsed was never understood, and taking
    /// it by identifier alone would leave a validator seeing no blocker for
    /// a demand the certificate marked as one.
    pub fn understands<E>(
        &self,
        item: &Extension<'a>,
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<bool, E> {
        let work = (item.kind.as_bytes().len() as u64)
            .checked_mul(64)
            .ok_or_else(|| {
                Error::resource(MemoryError::WorkExceeded, "extensions", item.span.start)
            })?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, "extensions", item.span.start))?;
        if is_known(item.kind) {
            return Self::decodes(item, recognizer, execution);
        }
        Ok(recognizer
            .recognizes(item.kind, execution)
            .map_err(CallbackError::Callback)?
            && Self::holds_one_value(item, execution)?)
    }

    /// Whether the value of an extension this crate does not decode is one
    /// complete DER value, all the way down.
    ///
    /// A scheme says which identifiers are its to decode. It never sees the
    /// bytes, so its claim cannot be a statement about them, and "the
    /// corresponding ASN.1 DER encoded structure is the value of the octet
    /// string extnValue" (RFC 5280 4.1.2.9) is the one thing that can be
    /// asked here: one structure, nothing after it, and every element under
    /// it written the way the encoding writes it. Without this a critical
    /// demand carrying bytes that are a value of no type would clear the
    /// gate on an identifier alone.
    fn holds_one_value(item: &Extension<'a>, execution: &Memory) -> Result<bool> {
        const FIELD: &str = "extensions";
        let read = || -> Result<()> {
            let at = |code| Error::new(code, FIELD, item.value_span.start);
            let mut reader = item.reader(execution).field(FIELD)?;
            let element = reader
                .next_element()
                .field(FIELD)?
                .ok_or_else(|| at(ErrorCode::MissingField))?;
            crate::name::walk_der(&reader, &element, FIELD, crate::name::Strings::Checked)?;
            if reader.is_empty() {
                Ok(())
            } else {
                Err(at(ErrorCode::TrailingData))
            }
        };
        Ok(gate(read())?.is_some())
    }

    /// Whether a known extension's value actually parses. An error is a spent
    /// budget, never a malformed value.
    fn decodes<E>(
        item: &Extension<'a>,
        recognizer: &impl Recognizer<Error = E>,
        execution: &Memory,
    ) -> CallbackResult<bool, E> {
        let kind = item.kind;
        Ok(if kind == oid::BASIC_CONSTRAINTS {
            gate(BasicConstraints::read(item, execution))?.is_some()
        } else if kind == oid::KEY_USAGE {
            gate(KeyUsage::read(item, execution))?.is_some()
        } else if kind == oid::EXT_KEY_USAGE {
            gate(ExtendedKeyUsage::read(item, execution))?.is_some()
        } else if kind == oid::SUBJECT_ALT_NAME || kind == oid::ISSUER_ALT_NAME {
            // The names read for the report either way; understanding also
            // asks that every other-name type be one somebody claims.
            match gate(general_name::read_alternative(item, execution))? {
                Some(names) => all(names.iter(), item, execution, |name| {
                    other_name_known(name, recognizer, execution)
                })?,
                None => false,
            }
        } else if kind == oid::SUBJECT_KEY_IDENTIFIER {
            gate(SubjectKeyIdentifier::read(item, execution))?.is_some()
        } else if kind == oid::AUTHORITY_KEY_IDENTIFIER {
            // The issuer names inside are the identity the extension points
            // at, so they answer the same other-name question.
            match gate(AuthorityKeyIdentifier::read(item, execution))? {
                Some(identifier) => all(identifier.issuer().iter(), item, execution, |name| {
                    other_name_known(name, recognizer, execution)
                })?,
                None => false,
            }
        } else if kind == oid::NAME_CONSTRAINTS {
            match gate(NameConstraints::read(item, execution))? {
                Some(constraints) => all(
                    constraints.permitted().iter().chain(constraints.excluded()),
                    item,
                    execution,
                    |subtree| {
                        // A constraint is understood only where a
                        // certificate's names can be matched against it. The
                        // X.400 and EDI forms are kept as opaque encoded
                        // bytes, and a registered identifier has no defined
                        // constraint-matching rule either, so a critical
                        // constraint built on any of them was not understood
                        // even though its structure parsed.
                        //
                        // An other-name is the same question asked of a
                        // scheme, and it is the constraint question and not
                        // the reading one: knowing what a name of that type
                        // says is not knowing which names sit inside a
                        // subtree of it.
                        Ok(match subtree.base() {
                            GeneralName::X400(_)
                            | GeneralName::EdiParty(_)
                            | GeneralName::RegisteredId(_) => false,
                            GeneralName::Other { type_id, .. } => recognizer
                                .recognizes_name_constraint(*type_id, execution)
                                .map_err(CallbackError::Callback)?,
                            _ => true,
                        })
                    },
                )?,
                None => false,
            }
        } else if kind == oid::CERTIFICATE_POLICIES {
            // The list parsing keeps qualifiers encoded; understanding a
            // critical policy extension includes interpreting them.
            match gate(CertificatePolicies::read(item, execution))? {
                Some(policies) => policies.understood(item.parser, execution)?,
                None => false,
            }
        } else if kind == oid::POLICY_MAPPINGS {
            gate(PolicyMappings::read(item, execution))?.is_some()
        } else if kind == oid::POLICY_CONSTRAINTS {
            gate(PolicyConstraints::read(item, execution))?.is_some()
        } else if kind == oid::INHIBIT_ANY_POLICY {
            gate(InhibitAnyPolicy::read(item, execution))?.is_some()
        } else if kind == oid::AUTHORITY_INFO_ACCESS || kind == oid::SUBJECT_INFO_ACCESS {
            // A description's meaning is its method identifier, and a known
            // method does not vouch for its location: an other-name there
            // whose type nobody claims is a location this run never
            // interpreted, and a form outside the ones the method names is
            // an endpoint it cannot use. Either way the accessor still
            // reports it.
            match gate(InfoAccess::read(item, execution))? {
                Some(access) => all(
                    access.descriptions().iter(),
                    item,
                    execution,
                    |description| {
                        let method = description.method();
                        // Each extension defines its own methods: OCSP and the
                        // issuing certificates on the authority side (RFC 5280
                        // 4.2.2.1), the repository and the time-stamping service
                        // on the subject side (RFC 5280 4.2.2.2). A method
                        // carried by the other extension has no defined meaning
                        // there and was not understood.
                        let named = if kind == oid::AUTHORITY_INFO_ACCESS {
                            [oid::OCSP, oid::CA_ISSUERS].contains(&method)
                        } else {
                            [oid::TIME_STAMPING_ACCESS, oid::CA_REPOSITORY].contains(&method)
                        };
                        Ok((named
                            || recognizer
                                .recognizes_access_method(method, execution)
                                .map_err(CallbackError::Callback)?)
                            && other_name_known(description.location(), recognizer, execution)?
                            && (!named || method_location_fits(method, description.location())))
                    },
                )?,
                None => false,
            }
        } else if kind == oid::CRL_DISTRIBUTION_POINTS || kind == oid::FRESHEST_CRL {
            // A point's names say where the revocation evidence is, and the
            // issuer names who signs it: both answer the other-name question.
            match gate(DistributionPoints::read(item, execution))? {
                Some(points) => all(points.points().iter(), item, execution, |point| {
                    all(
                        point.full_name().iter().chain(point.issuer()),
                        item,
                        execution,
                        |name| other_name_known(name, recognizer, execution),
                    )
                })?,
                None => false,
            }
        } else if kind == oid::OCSP_NO_CHECK {
            gate(crate::ocsp::read_no_check(item, execution))?.is_some()
        } else if kind == oid::QC_STATEMENTS {
            // The outer list parsing is not understanding: the statement
            // payloads decode lazily, and a critical list whose statement
            // carries garbage, or whose identifier nobody here knows, is a
            // critical demand this run never understood, one level down from
            // an unknown extension.
            match gate(QcStatements::read(item, execution))? {
                Some(statements) => statements.understood(recognizer, execution)?,
                None => false,
            }
        } else {
            // is_known and this list name the same identifiers; a mismatch is
            // a bug, and claiming the value parsed would hide it.
            false
        })
    }
}

/// Generates one typed accessor per extension: absent when the list does not
/// carry the identifier, otherwise whatever the reader makes of the value.
/// The table is the single place an accessor name, its identifier and its
/// reader meet, so the three cannot drift apart.
macro_rules! typed_accessors {
    ($($(#[$doc:meta])* $name:ident, $oid:path => $reader:path, $result:ty;)+) => {
        $(
            $(#[$doc])*
            pub fn $name(&self, execution: &Memory) -> Result<Option<$result>> {
                match self.get($oid, execution)? {
                    Some(item) => $reader(item, execution).map(Some),
                    None => Ok(None),
                }
            }
        )+
    };
}

/// The extensions this crate reads into structures of their own.
///
/// Each is read when it is asked for rather than when the certificate is,
/// because an extension that cannot be read is not a certificate that cannot
/// be read. Lookup and decoding use the caller's current execution domain;
/// the original parser's cumulative local ceilings still apply.
impl<'a> Extensions<'a> {
    /// Reads one original Extensions SEQUENCE with the certificate catalogue
    /// invariants: nonempty, no duplicate OIDs, primitive extnValue, and the
    /// producing encoding's DEFAULT rules. This does not recognize/trust values.
    pub fn read_element(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        read(parent, element, field)
    }

    /// Reads `[number] IMPLICIT Extensions` without changing original bytes.
    /// The number is selected by the enclosing schema (RFC3161 §§2.4.1–2.4.2).
    /// This strict catalogue is suitable for requests, not `TSTInfo` inspection
    /// recovery; use [`read_with`] there before deciding duplicate/fault policy.
    /// Original source/depth and producing local/current aggregate work survive.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1>
    pub fn read_implicit(
        parent: &Reader<'a>,
        element: &Element<'a>,
        number: u32,
        field: &'static str,
    ) -> Result<Self> {
        read_tagged(parent, element, Tag::context(true, number), field)
    }

    typed_accessors! {
        /// Whether this is a certification authority, and how deep a path
        /// below it may go.
        basic_constraints, oid::BASIC_CONSTRAINTS => BasicConstraints::read, BasicConstraints;
        /// What the key may be used for.
        key_usage, oid::KEY_USAGE => KeyUsage::read, KeyUsage<'a>;
        /// The further purposes the key is named for.
        extended_key_usage, oid::EXT_KEY_USAGE => ExtendedKeyUsage::read, ExtendedKeyUsage<'a>;
        /// The further names for the subject.
        subject_alt_name, oid::SUBJECT_ALT_NAME => general_name::read_alternative, OwnedVec<GeneralName<'a>>;
        /// The further names for the issuer.
        issuer_alt_name, oid::ISSUER_ALT_NAME => general_name::read_alternative, OwnedVec<GeneralName<'a>>;
        /// The identifier for the key this certificate carries.
        subject_key_identifier, oid::SUBJECT_KEY_IDENTIFIER => SubjectKeyIdentifier::read, SubjectKeyIdentifier<'a>;
        /// The identifier for the key that signed it.
        authority_key_identifier, oid::AUTHORITY_KEY_IDENTIFIER => AuthorityKeyIdentifier::read, AuthorityKeyIdentifier<'a>;
        /// The name space this authority may certify within.
        name_constraints, oid::NAME_CONSTRAINTS => NameConstraints::read, NameConstraints<'a>;
        /// The policies the certificate was issued under.
        certificate_policies, oid::CERTIFICATE_POLICIES => CertificatePolicies::read, CertificatePolicies<'a>;
        /// The policies of one domain treated as equivalent to another's.
        policy_mappings, oid::POLICY_MAPPINGS => PolicyMappings::read, PolicyMappings<'a>;
        /// The limits on policy processing below this certificate.
        policy_constraints, oid::POLICY_CONSTRAINTS => PolicyConstraints::read, PolicyConstraints;
        /// After how many certificates the identifier standing for any policy
        /// stops being accepted.
        inhibit_any_policy, oid::INHIBIT_ANY_POLICY => InhibitAnyPolicy::read, InhibitAnyPolicy;
        /// Where the issuer's certificate and status service are published.
        authority_info_access, oid::AUTHORITY_INFO_ACCESS => InfoAccess::read, InfoAccess<'a>;
        /// Where services belonging to the subject are published.
        subject_info_access, oid::SUBJECT_INFO_ACCESS => InfoAccess::read, InfoAccess<'a>;
        /// Where revocation lists covering this certificate are published.
        crl_distribution_points, oid::CRL_DISTRIBUTION_POINTS => DistributionPoints::read, DistributionPoints<'a>;
        /// Where the delta revocation list is published.
        freshest_crl, oid::FRESHEST_CRL => DistributionPoints::read, DistributionPoints<'a>;
        /// What the issuer claims about this being a qualified certificate.
        qc_statements, oid::QC_STATEMENTS => QcStatements::read, QcStatements<'a>;
    }
}

/// Whether a name is not an other-name, or is one whose type identifier a
/// scheme claims. An other-name's value means what its type says, this crate
/// names no such types itself, and a critical name extension carrying one
/// nobody claims was not understood.
/// Whether a location takes a form its access method names (RFC 5280
/// 4.2.2.1 and 4.2.2.2): the status responder is reached by a URI; the
/// issuing certificates and the repository publish over transfer protocols,
/// a URI, or the directory, a directory name, and a mailbox names no
/// publication location for them; the timestamping service adds the mailbox,
/// host and address forms. A method a recognizer claims keeps its own forms.
fn method_location_fits(method: Oid<'_>, location: &GeneralName<'_>) -> bool {
    if method == oid::OCSP {
        matches!(location, GeneralName::Uri(_))
    } else if method == oid::CA_ISSUERS || method == oid::CA_REPOSITORY {
        matches!(location, GeneralName::Uri(_) | GeneralName::Directory(_))
    } else if method == oid::TIME_STAMPING_ACCESS {
        matches!(
            location,
            GeneralName::Uri(_)
                | GeneralName::Email(_)
                | GeneralName::Dns(_)
                | GeneralName::IpAddress(_)
        )
    } else {
        true
    }
}

pub(crate) fn other_name_known<E>(
    name: &GeneralName<'_>,
    recognizer: &impl Recognizer<Error = E>,
    execution: &Memory,
) -> CallbackResult<bool, E> {
    match name {
        GeneralName::Other { type_id, .. } => recognizer
            .recognizes_other_name(*type_id, execution)
            .map_err(CallbackError::Callback),
        _ => Ok(true),
    }
}

fn all<T, E>(
    values: impl Iterator<Item = T>,
    item: &Extension<'_>,
    execution: &Memory,
    mut understood: impl FnMut(T) -> CallbackResult<bool, E>,
) -> CallbackResult<bool, E> {
    for value in values {
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, "extensions", item.span.start))?;
        if !understood(value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The identifiers a scheme understands, answered by the role an identifier
/// plays: claiming an extension says nothing about interpreting an
/// other-name or an access method that reuses the same identifier.
///
/// Data, not behaviour: an implementation answers whether an identifier is one
/// it knows. It cannot decode anything, and nothing here gives it a way to
/// reach the network. Each role defaults to no, the direction that blocks
/// rather than vouches.
pub trait Recognizer {
    /// The original policy, provider or resource error of this implementation.
    type Error;

    /// Whether this scheme understands the extension.
    fn recognizes(
        &self,
        kind: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error>;

    /// Whether this scheme can interpret an other-name of this type.
    fn recognizes_other_name(
        &self,
        _type_id: Oid<'_>,
        _execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    /// Whether this scheme enforces a name constraint written over an
    /// other-name of this type.
    ///
    /// A different question from reading one. Reading asks what a name of
    /// this type says; a constraint asks whether a certificate's names fall
    /// inside a subtree of it, which needs a containment rule the type's
    /// reader never states. A scheme that reads the type and has no such
    /// rule leaves the constraint enforced by nobody, so this role is
    /// answered separately and defaults to no.
    fn recognizes_name_constraint(
        &self,
        _type_id: Oid<'_>,
        _execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    /// Whether this scheme understands an information-access method, its
    /// location forms included.
    fn recognizes_access_method(
        &self,
        _method: Oid<'_>,
        _execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }

    /// Whether this scheme can interpret a qualified statement of this kind:
    /// a national statement is knowledge a scheme carries, not this crate.
    fn recognizes_statement(
        &self,
        _kind: Oid<'_>,
        _execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }
}

/// Nothing beyond what this crate itself understands.
impl Recognizer for () {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        _kind: Oid<'_>,
        _execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(false)
    }
}

impl Recognizer for [Oid<'_>] {
    type Error = MemoryError;
    fn recognizes(
        &self,
        kind: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        for candidate in self {
            execution
                .charge_work(1 + candidate.as_bytes().len().max(kind.as_bytes().len()) as u64)?;
            if *candidate == kind {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A scheme reached by reference answers exactly as it does directly.
///
/// Every role of the trait is forwarded, and a new role must be added here
/// too: each default answers no, so a role left behind silently drops the
/// scheme's knowledge for callers holding it behind a reference, which is
/// how a generic wrapper and a `&dyn Recognizer` both arrive.
impl<T: Recognizer + ?Sized> Recognizer for &T {
    type Error = T::Error;
    fn recognizes(
        &self,
        kind: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        (*self).recognizes(kind, execution)
    }

    fn recognizes_other_name(
        &self,
        type_id: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        (*self).recognizes_other_name(type_id, execution)
    }

    fn recognizes_name_constraint(
        &self,
        type_id: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        (*self).recognizes_name_constraint(type_id, execution)
    }

    fn recognizes_access_method(
        &self,
        method: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        (*self).recognizes_access_method(method, execution)
    }

    fn recognizes_statement(
        &self,
        kind: Oid<'_>,
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error> {
        (*self).recognizes_statement(kind, execution)
    }
}

/// Whether this crate reads the extension into a structure of its own.
#[must_use]
pub fn is_known(kind: Oid<'_>) -> bool {
    [
        oid::BASIC_CONSTRAINTS,
        oid::KEY_USAGE,
        oid::EXT_KEY_USAGE,
        oid::SUBJECT_ALT_NAME,
        oid::ISSUER_ALT_NAME,
        oid::SUBJECT_KEY_IDENTIFIER,
        oid::AUTHORITY_KEY_IDENTIFIER,
        oid::NAME_CONSTRAINTS,
        oid::CERTIFICATE_POLICIES,
        oid::POLICY_MAPPINGS,
        oid::POLICY_CONSTRAINTS,
        oid::INHIBIT_ANY_POLICY,
        oid::AUTHORITY_INFO_ACCESS,
        oid::SUBJECT_INFO_ACCESS,
        oid::CRL_DISTRIBUTION_POINTS,
        oid::FRESHEST_CRL,
        oid::QC_STATEMENTS,
        oid::OCSP_NO_CHECK,
    ]
    .contains(&kind)
}

/// A reader over the members of the one sequence an extension's value holds,
/// which is the shape of most of them.
pub(crate) fn sequence<'a>(
    extension: &Extension<'a>,
    field: &'static str,
    execution: &Memory,
) -> Result<Reader<'a>> {
    sequence_reader(
        extension.reader(execution).field(field)?,
        field,
        extension.span().start,
    )
}

pub(crate) fn sequence_reader<'a>(
    mut reader: Reader<'a>,
    field: &'static str,
    at: u64,
) -> Result<Reader<'a>> {
    let fail = |code| Error::new(code, field, at);
    let element = reader
        .next_element()
        .field(field)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }
    // A value holding a second structure after the first is two answers to
    // what the extension says.
    if !reader.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    reader.enter(&element).field(field)
}

/// The number and construction of a context-specific tag, and `None` for a
/// tag of any other class.
///
/// The fields these schemas tag by position are context-specific, and a match
/// on number and construction alone would read an APPLICATION or PRIVATE tag
/// with the same number as the field it is not.
pub(crate) fn context_of(tag: Tag) -> Option<(u32, bool)> {
    // A number this reader does not name is not a field any schema wrote.
    (tag.class() == structured_asn1::Class::ContextSpecific)
        .then(|| tag.number().map(|number| (number, tag.is_constructed())))
        .flatten()
}

/// Reads the extensions from the element the schema wraps them in. The
/// parent reader's parser is kept with each extension, so every later decode
/// of its value is charged to the budget the certificate was read with, and
/// no other parser can be handed in beside the reader.
pub(crate) fn read<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<Extensions<'a>> {
    read_tagged(
        parent,
        element,
        Tag::constructed(universal::SEQUENCE),
        field,
    )
}

fn read_tagged<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    expected: Tag,
    field: &'static str,
) -> Result<Extensions<'a>> {
    let parser = parent.parser();
    let fail = |code| Error::new(code, field, element.span().start);

    if element.tag() != expected {
        return Err(fail(ErrorCode::Encoding(
            structured_asn1::ErrorCode::UnexpectedTag,
        )));
    }

    let mut sequence = parent.enter(element).field(field)?;
    let mut items = parent.execution().vector();
    // A set rather than a scan of what came before: a certificate can carry
    // tens of thousands of extensions within the parse budget, and a per-item
    // scan of the list would be quadratic work the budget never sees.
    let mut kinds = parent.execution().map::<Oid<'a>, ()>();

    while let Some(entry) = sequence.next_element().field(field)? {
        let at = |code| Error::new(code, field, entry.span().start);

        let fields = open(&sequence, &entry, field)?;
        if fields.header().default_written() && fields.reader().encoding().is_der() {
            let at = fields
                .header()
                .critical_span()
                .expect("written flag has a span")
                .start;
            return Err(Error::new(ErrorCode::MalformedValue, field, at));
        }
        let decoded = fields
            .read_with(|_header, inside, value| {
                // RFC5280 §4.1 / X.690 §11.5: the strict certificate profile
                // keeps its primitive-value and DER-default invariants. TSP
                // inspection can instead retain the common structural metadata.
                // https://www.rfc-editor.org/rfc/rfc5280#section-4.1
                if value.tag() != Tag::primitive(universal::OCTET_STRING) {
                    return Err(Error::new(
                        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                        field,
                        value.span().start,
                    ));
                }
                if !inside.is_empty() {
                    return Err(at(ErrorCode::TrailingData));
                }
                Ok((value.contents(), value.contents_span(), inside.depth()))
            })
            .map_err(|error| match error {
                CallbackError::Processing(error) | CallbackError::Callback(error) => error,
            })?;
        let header = decoded.header();
        let kind = header.kind();
        let critical = header.is_critical();
        let (value, value_span, outer) = decoded.into_value();

        // Two copies of one extension leave no answer to which applies, and a
        // reader that took the first would disagree with one that took the
        // last about what the certificate says.
        if kinds
            .try_insert(kind, ())
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?
            .is_some()
        {
            return Err(at(ErrorCode::DuplicateExtension));
        }

        items
            .try_push(Extension {
                kind,
                critical,
                value,
                value_span,
                span: entry.span(),
                parser,
                outer,
            })
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
    }

    // The schema requires at least one, and an empty sequence is a structure
    // that says nothing while claiming to.
    if items.is_empty() {
        return Err(fail(ErrorCode::EmptySequence));
    }

    Ok(Extensions {
        items: items.into_owned(),
    })
}

#[cfg(test)]
mod tests;
