//! What a certificate claims about being a qualified certificate.
//!
//! These statements are claims the issuer makes, not facts this crate can
//! confirm. Whether a certificate is qualified is decided by the trusted list,
//! against the service that issued it, at the moment in question. A statement
//! saying so is evidence about what the issuer intended, and the report has to
//! keep the two apart.

use crate::error::{Error, ErrorCode, Located, Result, gate};
use crate::extension::{self, Extension};
use crate::name::is_ia5;
use crate::oid;
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_asn1::{Oid, Parser, Tag, universal};

/// One statement: what it is, and whatever was written with it.
#[derive(Debug, Clone, Copy)]
pub struct QcStatement<'a> {
    kind: Oid<'a>,
    info: Option<&'a [u8]>,
    /// Where the information sits in the document, so an error found while
    /// re-parsing it points at the statement rather than at the front of the
    /// certificate.
    at: u64,
    /// Depth above the statement pair, retained for information decoders.
    outer: u32,
}

impl<'a> QcStatement<'a> {
    /// Which statement this is.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }

    /// What was written with it, as encoded. What it means depends on the
    /// statement, and the ones this crate reads are below.
    #[must_use]
    pub fn info(self) -> Option<&'a [u8]> {
        self.info
    }
}

/// How long the issuer says it keeps what is needed to check a certificate.
///
/// The statement is a bare `INTEGER` of years (ETSI TS 101 862, annex B), so
/// a period wider than the counter is inside the schema. It is kept as what
/// it is, longer than any interval a question will be asked over, rather
/// than refused as malformed or folded into a number nobody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPeriod {
    /// The number of years the statement names.
    Years(u32),
    /// A period past any interval a report covers.
    BeyondAnyInterval,
}

impl RetentionPeriod {
    /// The years where an interval could reach them, and `None` where none
    /// can.
    #[must_use]
    pub fn years(self) -> Option<u32> {
        match self {
            Self::Years(years) => Some(years),
            Self::BeyondAnyInterval => None,
        }
    }
}

/// Which kind of qualified certificate this claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QualifiedType {
    /// For an electronic signature, which a natural person makes.
    ElectronicSignature,
    /// For an electronic seal, which a legal person makes.
    ElectronicSeal,
    /// For website authentication.
    WebsiteAuthentication,
}

/// The statements a certificate carries.
#[derive(Debug)]
pub struct QcStatements<'a> {
    statements: OwnedVec<QcStatement<'a>>,
    parser: &'a Parser,
}

impl<'a> QcStatements<'a> {
    /// Account retaining the statement collection's storage. Deferred
    /// decoding uses the explicitly supplied current execution domain.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.statements.memory()
    }

    /// Re-read information at its original offset and depth under the same
    /// document budget. Every lazy decoder goes through this boundary.
    fn info_reader<W: Work + 'a>(
        &self,
        info: &'a [u8],
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> structured_asn1::Result<structured_asn1::Reader<'a>> {
        execution.read_nested(
            self.parser,
            info,
            statement.at,
            structured_asn1::Encoding::Der,
            statement.outer,
        )
    }

    /// Every statement, in order.
    #[must_use]
    pub fn statements(&self) -> &[QcStatement<'a>] {
        &self.statements
    }

    /// One statement by identifier, for the ones this crate does not read.
    pub fn get<W: Work>(&self, kind: Oid<'_>, execution: &W) -> Result<Option<QcStatement<'a>>> {
        for statement in &self.statements {
            let work = statement.kind.as_bytes().len().max(kind.as_bytes().len()) as u64;
            execution
                .charge_work(1 + work)
                .map_err(|reason| Error::resource(reason, STATEMENT_FIELD, statement.at))?;
            if statement.kind == kind {
                return Ok(Some(*statement));
            }
        }
        Ok(None)
    }

    /// Whether the issuer claims this is a qualified certificate.
    ///
    /// A claim, not a finding. The trusted list decides.
    pub fn claims_compliance<W: Work>(&self, execution: &W) -> Result<bool> {
        Ok(self.get(oid::QC_COMPLIANCE, execution)?.is_some())
    }

    /// Whether the issuer claims the private key is held in a qualified
    /// device.
    pub fn claims_qualified_device<W: Work>(&self, execution: &W) -> Result<bool> {
        Ok(self.get(oid::QC_SSCD, execution)?.is_some())
    }

    /// Which kinds of qualified certificate this claims to be.
    ///
    /// This is what separates a signature made by a person from a seal made by
    /// an organization, which is a difference the report must never collapse.
    pub fn types<W: Work + 'a>(&self, execution: &W) -> Result<OwnedVec<QualifiedType>> {
        const FIELD: &str = "extensions.qcStatements.qcType";
        // Statement information lives inside the DER certificate like every
        // extension value, so its re-parses below are DER whatever parser
        // carries the budget.
        let Some(statement) = self.get(oid::QC_TYPE, execution)? else {
            return Ok(execution.memory().vector());
        };
        let info = statement
            .info
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, statement.at))?;

        // Re-parsed from where it sits, so every offset below is an offset in
        // the document, which is what the error type promises.
        let mut reader = self.info_reader(info, &statement, execution).field(FIELD)?;
        let sequence = reader
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, statement.at))?;
        if sequence.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                FIELD,
                sequence.span().start,
            ));
        }
        let mut inside = reader.enter(&sequence).field(FIELD)?;
        let mut types = execution.vector();
        while !inside.is_empty() {
            let identifier = inside.read_oid().field(FIELD)?;
            // An identifier this crate does not know is a kind defined
            // elsewhere. It is skipped rather than refused, and stays visible
            // through the statement it was written in.
            if identifier == oid::QCT_ESIGN {
                types
                    .try_push(QualifiedType::ElectronicSignature)
                    .map_err(|reason| Error::resource(reason, FIELD, inside.offset()))?;
            } else if identifier == oid::QCT_ESEAL {
                types
                    .try_push(QualifiedType::ElectronicSeal)
                    .map_err(|reason| Error::resource(reason, FIELD, inside.offset()))?;
            } else if identifier == oid::QCT_WEB {
                types
                    .try_push(QualifiedType::WebsiteAuthentication)
                    .map_err(|reason| Error::resource(reason, FIELD, inside.offset()))?;
            }
        }

        Ok(types.into_owned())
    }

    /// How long the issuer says it keeps what is needed to check this
    /// certificate, in years.
    pub fn retention_period<W: Work + 'a>(&self, execution: &W) -> Result<Option<RetentionPeriod>> {
        const FIELD: &str = "extensions.qcStatements.qcRetentionPeriod";
        let Some(statement) = self.get(oid::QC_RETENTION_PERIOD, execution)? else {
            return Ok(None);
        };
        let info = statement
            .info
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, statement.at))?;

        let mut reader = self.info_reader(info, &statement, execution).field(FIELD)?;
        let years = reader.read_integer().field(FIELD)?;
        if !reader.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, FIELD, statement.at));
        }

        // Below zero is not a duration at all. Above the counter is still a
        // duration, and what it says is that nothing asks over that long.
        if years.is_negative() {
            return Err(Error::new(ErrorCode::MalformedValue, FIELD, statement.at));
        }
        Ok(Some(years.as_u32().map_or(
            RetentionPeriod::BeyondAnyInterval,
            RetentionPeriod::Years,
        )))
    }

    /// Which kind of person the subject's identifiers are to be read as.
    ///
    /// Says how to read an organization identifier or a serial number in the
    /// subject's name, and getting it wrong turns an organization into a
    /// person or the reverse.
    pub fn semantics<W: Work + 'a>(&self, execution: &W) -> Result<Option<Oid<'a>>> {
        // Both versions may be present, each saying which profile the
        // certificate claims conformance with (RFC 3739 3.2.6), and each may
        // carry an identifier. Two that differ say the subject's identifiers
        // are to be read two ways, and the certificate does not say which:
        // answering with either would put one of them in a report as though
        // the document had settled it.
        let mut said: Option<(Oid<'a>, u64)> = None;
        for kind in [oid::PKIX_QC_SYNTAX_V2, oid::PKIX_QC_SYNTAX_V1] {
            let Some(statement) = self.get(kind, execution)? else {
                continue;
            };
            let Some(identifier) = self.semantics_parts(&statement, execution)?.0 else {
                continue;
            };
            if said.is_some_and(|(said, _)| said != identifier) {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    "extensions.qcStatements.semanticsInformation",
                    statement.at,
                ));
            }
            said = Some((identifier, statement.at));
        }
        Ok(said.map(|(identifier, _)| identifier))
    }

    /// Reads one syntax statement's semantics information: the identifier if
    /// one was written, and the registration authorities. The accessor above
    /// prefers the newer statement, but where both appear each is validated on
    /// its own: a well-formed preferred statement must not vouch for the other.
    #[allow(clippy::type_complexity)]
    fn semantics_parts<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<(
        Option<Oid<'a>>,
        OwnedVec<crate::general_name::GeneralName<'a>>,
    )> {
        const FIELD: &str = "extensions.qcStatements.semanticsInformation";
        // The information is optional even where the statement is present.
        let Some(info) = statement.info else {
            return Ok((None, execution.memory().vector()));
        };

        let mut reader = self.info_reader(info, statement, execution).field(FIELD)?;
        let sequence = reader
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, statement.at))?;
        if sequence.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                FIELD,
                sequence.span().start,
            ));
        }
        let mut inside = reader.enter(&sequence).field(FIELD)?;
        // Both members are optional, but at least one must be present
        // (RFC 3739, 3.2.6.1): empty, the structure says nothing while
        // wearing the statement.
        let Some(first) = inside.next_element().field(FIELD)? else {
            return Err(Error::new(ErrorCode::MissingField, FIELD, statement.at));
        };

        // Both members are optional, but the structure is closed: after the
        // identifier only the list of registration authorities may follow,
        // and anything else riding along under a value that decides person
        // versus organization is a malformed statement, not extra context.
        let parts = if first.tag() == Tag::primitive(universal::OID) {
            let identifier = inside.oid(&first).field(FIELD)?;
            match inside.next_element().field(FIELD)? {
                Some(authorities) => (
                    Some(identifier),
                    require_authorities(&inside, &authorities)?,
                ),
                None => return Ok((Some(identifier), execution.memory().vector())),
            }
        } else {
            (None, require_authorities(&inside, &first)?)
        };

        if !inside.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, FIELD, statement.at));
        }
        Ok(parts)
    }

    /// Reads the value of a qualified statements extension.
    pub fn read<W: Work + 'a>(extension: &Extension<'a>, execution: &W) -> Result<Self> {
        const FIELD: &str = "extensions.qcStatements";

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let work = inside.execution_in(execution.memory());
        let mut statements = work.vector();
        let mut kinds = work.map::<Oid<'a>, Option<&'a [u8]>>();

        while let Some(entry) = inside.next_element().field(FIELD)? {
            let at = |code| Error::new(code, FIELD, entry.span().start);
            if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(at(ErrorCode::Encoding(
                    structured_asn1::ErrorCode::UnexpectedTag,
                )));
            }

            let mut pair = inside.enter(&entry).field(FIELD)?;
            let kind = pair.read_oid().field(FIELD)?;
            let info_element = pair.next_element().field(FIELD)?;
            let info = info_element.map(structured_asn1::Element::as_bytes);
            let info_at =
                info_element.map_or_else(|| entry.span().start, |element| element.span().start);
            // Exactly one element. This check is what lets every decoder above
            // re-parse the information knowing it holds one value and nothing
            // after it: a statement written as a structure plus trailing bytes
            // is refused here, not misread there.
            if !pair.is_empty() {
                return Err(at(ErrorCode::TrailingData));
            }

            // The payload is preserved for a scheme that knows the
            // statement, and that scheme clears a critical extension on the
            // strength of it, so the whole of it has to be the encoding the
            // document claims and not only its outer tag.
            if let Some(element) = info_element {
                crate::name::walk_der(&pair, &element, FIELD, crate::name::Strings::Checked)?;
            }

            // One statement written twice with different information leaves
            // no answer to what the issuer claimed. Written twice with the
            // same information it claims one thing twice: the schema is a
            // SEQUENCE OF with no uniqueness constraint, so the repeat is
            // folded rather than refused. A map rather than a scan, so a
            // long list costs the work its size says and not its square.
            if let Some(existing) = kinds
                .try_insert(kind, info)
                .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?
            {
                // Deciding which of the two it is walks both payloads, which
                // are opaque and have no local ceiling, so the longer of them
                // is charged to the shared work budget first.
                let compared = existing
                    .map_or(0, <[u8]>::len)
                    .max(info.map_or(0, <[u8]>::len));
                inside.charge(compared as u64).field(FIELD)?;
                if existing != info {
                    return Err(at(ErrorCode::MalformedValue));
                }
                continue;
            }

            // The compliance and qualified-device statements are bare claims
            // whose identifiers define no information value. A value there is
            // malformed statement data, and a reader that kept the claim
            // while carrying it would report a qualified certificate on the
            // strength of a statement that is not one.
            if info.is_some() && (kind == oid::QC_COMPLIANCE || kind == oid::QC_SSCD) {
                return Err(at(ErrorCode::MalformedValue));
            }

            statements
                .try_push(QcStatement {
                    kind,
                    info,
                    at: info_at,
                    outer: inside.depth(),
                })
                .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
        }

        // No minimum size: QCStatements is a bare SEQUENCE OF (RFC 3739
        // 3.2.6), unlike the lists this crate refuses empty, whose schema
        // writes SIZE (1..MAX). An empty one makes no qualified claim, which
        // is an answer a report can give.
        Ok(Self {
            statements: statements.into_owned(),
            parser: extension.parser(),
        })
    }
}

impl<'a> QcStatements<'a> {
    /// Whether every statement was actually understood, for the gate that
    /// decides what a critical extension blocked: each identifier is one
    /// this crate names, and each structured payload has its shape. An error
    /// is a spent budget and only that.
    pub(crate) fn understood<E, W: Work + 'a>(
        &self,
        recognizer: &impl crate::extension::Recognizer<W, Error = E>,
        execution: &W,
    ) -> crate::error::CallbackResult<bool, E> {
        if gate(self.types(execution))?.is_none()
            || gate(self.retention_period(execution))?.is_none()
        {
            return Ok(false);
        }
        // Two syntax statements that name different semantics leave the
        // subject's identifiers with two readings and the certificate with
        // no answer between them. Each statement is well formed on its own,
        // so this is asked once over the pair rather than inside the walk
        // below.
        if gate(self.semantics(execution))?.is_none() {
            return Ok(false);
        }
        for statement in &self.statements {
            let work = (statement.kind.as_bytes().len() as u64)
                .checked_mul(8)
                .and_then(|work| work.checked_add(1))
                .ok_or_else(|| {
                    Error::resource(
                        structured_asn1::memory::MemoryError::WorkExceeded,
                        STATEMENT_FIELD,
                        statement.at,
                    )
                })?;
            execution
                .charge_work(work)
                .map_err(|reason| Error::resource(reason, STATEMENT_FIELD, statement.at))?;
            let kind = statement.kind;
            let statement_understood = if kind == oid::QC_TYPE {
                self.qc_types_understood(statement, execution)?
            } else if kind == oid::QC_LIMIT_VALUE {
                self.limit_value_understood(statement, execution)?
            } else if kind == oid::QC_PDS {
                self.pds_understood(statement, execution)?
            } else if kind == oid::QC_CC_LEGISLATION {
                self.legislation_understood(statement, execution)?
            } else if kind == oid::PKIX_QC_SYNTAX_V1 || kind == oid::PKIX_QC_SYNTAX_V2 {
                // Each syntax statement on its own, not just the one the
                // accessor prefers: with both present, a well-formed
                // preferred statement must not hide the other's garbage.
                // An identifier decides how the subject's identifiers are
                // read; one this crate does not name is a reading this run
                // cannot perform. And the registration authorities answer
                // the other-name question every list of names answers: a
                // type nobody claims was never interpreted. The accessor
                // still reports both.
                match gate(self.semantics_parts(statement, execution))? {
                    None => false,
                    Some((identifier, authorities)) => {
                        identifier.is_none_or(|identifier| {
                            identifier == oid::SEMANTICS_NATURAL_PERSON
                                || identifier == oid::SEMANTICS_LEGAL_PERSON
                        }) && {
                            let mut known = true;
                            for name in &authorities {
                                execution.charge_work(1).map_err(|reason| {
                                    Error::resource(reason, "qcStatements", statement.at)
                                })?;
                                if !crate::extension::other_name_known(name, recognizer, execution)?
                                {
                                    known = false;
                                    break;
                                }
                            }
                            known
                        }
                    }
                }
            } else {
                // A statement this crate does not name may still be one the
                // caller's scheme carries: a national statement is the
                // scheme's knowledge, and only with neither does a critical
                // list hold a claim nobody read.
                is_known_statement(kind)
                    || recognizer
                        .recognizes_statement(kind, execution)
                        .map_err(crate::error::CallbackError::Callback)?
            };
            if !statement_understood {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The type statement of ETSI EN 319 412-5, read for the gate: every
    /// identifier is one of the three purposes this crate names.
    ///
    /// The accessor skips an unknown identifier so a report can still show
    /// the rest; this gate cannot, because the payload's identifiers are what
    /// carry the meaning, and a critical list declaring a purpose nobody here
    /// can name was not understood (RFC 3739, 3.2.6: applications that do not
    /// understand a statement in a critical extension reject the certificate).
    fn qc_types_understood<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<bool> {
        let Some(mut inside) = self.payload_sequence(statement, execution)? else {
            return Ok(false);
        };
        // read_oid rather than the tag-agnostic decoding helper: the schema
        // says SEQUENCE OF OBJECT IDENTIFIER, and this gate must not depend
        // on another accessor happening to check the tag first.
        let mut any = false;
        while !inside.is_empty() {
            let Some(identifier) = gate(inside.read_oid().field(STATEMENT_FIELD))? else {
                return Ok(false);
            };
            if ![oid::QCT_ESIGN, oid::QCT_ESEAL, oid::QCT_WEB].contains(&identifier) {
                return Ok(false);
            }
            any = true;
        }
        // The statement declares which purpose the certificate is issued for
        // (ETSI EN 319 412-5, clause 4.2.3): zero purposes declares nothing
        // while wearing the statement, which is not a statement understood.
        Ok(any)
    }

    /// The monetary limit of ETSI EN 319 412-5: a currency as a three-letter
    /// code or a number, then the amount and the exponent.
    fn limit_value_understood<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<bool> {
        let Some(mut inside) = self.payload_sequence(statement, execution)? else {
            return Ok(false);
        };
        let Some(Some(currency)) = gate(inside.next_element().field(STATEMENT_FIELD))? else {
            return Ok(false);
        };
        // The alphabetic choice is an ISO 4217 code, three uppercase
        // letters; the numeric choice is INTEGER (1..999), that standard's
        // numeric code space (ETSI EN 319 412-5, clause 4.3.2,
        // Iso4217CurrencyCode). Either outside its form wears the type but
        // names no currency. The universal tag is required first, because
        // the decoding helper is deliberately tag-agnostic for implicitly
        // tagged fields.
        let currency_ok = (currency.tag() == Tag::primitive(universal::PRINTABLE_STRING)
            && currency.contents().len() == 3
            && currency.contents().iter().all(u8::is_ascii_uppercase))
            || (currency.tag() == Tag::primitive(universal::INTEGER)
                && gate(inside.integer(&currency).field(STATEMENT_FIELD))?.is_some_and(|code| {
                    code.as_u32().is_some_and(|code| (1..=999).contains(&code))
                }));
        // The amount and the exponent are written `INTEGER`, with no range
        // (ETSI EN 319 412-5, clause 4.3.2: `MonetaryValue ::= SEQUENCE {
        // currency Iso4217CurrencyCode, amount INTEGER, exponent INTEGER }`,
        // the currency being the only member the schema constrains). Neither
        // is held to a sign here: a negative amount is inside the type, and
        // refusing one would leave a critical extension unhandled over a
        // value the schema names. What the issuer meant by it is the
        // issuer's to answer, and this layer reports the claim rather than
        // grading it.
        Ok(currency_ok
            && gate(inside.read_integer().field(STATEMENT_FIELD))?.is_some()
            && gate(inside.read_integer().field(STATEMENT_FIELD))?.is_some()
            && inside.is_empty())
    }

    /// The disclosure locations of ETSI EN 319 412-5: at least one pair of a
    /// location and a two-letter language. Locations are read, never fetched.
    fn pds_understood<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<bool> {
        let Some(mut inside) = self.payload_sequence(statement, execution)? else {
            return Ok(false);
        };
        let mut any = false;
        loop {
            match gate(inside.next_element().field(STATEMENT_FIELD))? {
                Some(Some(location)) => {
                    if location.tag() != Tag::constructed(universal::SEQUENCE) {
                        return Ok(false);
                    }
                    let Some(mut pair) = gate(inside.enter(&location).field(STATEMENT_FIELD))?
                    else {
                        return Ok(false);
                    };
                    let Some(Some(url)) = gate(pair.next_element().field(STATEMENT_FIELD))? else {
                        return Ok(false);
                    };
                    let Some(Some(language)) = gate(pair.next_element().field(STATEMENT_FIELD))?
                    else {
                        return Ok(false);
                    };
                    // The location is a URL, so it answers the same
                    // absolute-URI question every location field answers;
                    // the language is an ISO 639-1 code, two lowercase
                    // letters, the form the pair's schema names. The URL
                    // scans touch every content byte and the field has no
                    // local size bound, so the length is charged to the
                    // shared work budget first.
                    pair.charge(url.contents().len() as u64)
                        .field(STATEMENT_FIELD)?;
                    if url.tag() != Tag::primitive(universal::IA5_STRING)
                        || !is_ia5(url.contents())
                        || !core::str::from_utf8(url.contents())
                            .is_ok_and(crate::general_name::is_absolute_uri)
                        || language.tag() != Tag::primitive(universal::PRINTABLE_STRING)
                        || language.contents().len() != 2
                        || !language.contents().iter().all(u8::is_ascii_lowercase)
                        || !pair.is_empty()
                    {
                        return Ok(false);
                    }
                    any = true;
                }
                Some(None) => return Ok(any && inside.is_empty()),
                None => return Ok(false),
            }
        }
    }

    /// The legislation countries of ETSI EN 319 412-5: at least one
    /// two-letter country code.
    fn legislation_understood<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<bool> {
        let Some(mut inside) = self.payload_sequence(statement, execution)? else {
            return Ok(false);
        };
        let mut any = false;
        loop {
            match gate(inside.next_element().field(STATEMENT_FIELD))? {
                Some(Some(country)) => {
                    // An ISO 3166-1 alpha-2 code, the form the entries are
                    // defined as: two uppercase letters. A digit or
                    // punctuation in the pair names no country.
                    if country.tag() != Tag::primitive(universal::PRINTABLE_STRING)
                        || country.contents().len() != 2
                        || !country.contents().iter().all(u8::is_ascii_uppercase)
                    {
                        return Ok(false);
                    }
                    any = true;
                }
                Some(None) => return Ok(any),
                None => return Ok(false),
            }
        }
    }

    /// The one sequence a structured payload holds, or `None` where the
    /// information is absent or not that. An error is a spent budget.
    fn payload_sequence<W: Work + 'a>(
        &self,
        statement: &QcStatement<'a>,
        execution: &W,
    ) -> Result<Option<structured_asn1::Reader<'a>>> {
        let Some(info) = statement.info else {
            return Ok(None);
        };
        let Some(mut reader) = gate(
            self.info_reader(info, statement, execution)
                .field(STATEMENT_FIELD),
        )?
        else {
            return Ok(None);
        };
        let Some(Some(sequence)) = gate(reader.next_element().field(STATEMENT_FIELD))? else {
            return Ok(None);
        };
        if sequence.tag() != Tag::constructed(universal::SEQUENCE) || !reader.is_empty() {
            return Ok(None);
        }
        gate(reader.enter(&sequence).field(STATEMENT_FIELD))
    }
}

/// The field the statement gates above report a spent budget in.
const STATEMENT_FIELD: &str = "extensions.qcStatements";

/// Whether a qualified statement identifier is one this crate names.
fn is_known_statement(kind: Oid<'_>) -> bool {
    [
        oid::QC_COMPLIANCE,
        oid::QC_RETENTION_PERIOD,
        oid::QC_SSCD,
        oid::QC_TYPE,
        oid::PKIX_QC_SYNTAX_V1,
        oid::PKIX_QC_SYNTAX_V2,
    ]
    .contains(&kind)
}

/// Requires an element to be the list of registration authorities: a
/// non-empty sequence of names. The names are validated as names, since a
/// value that merely wears the sequence tag is the same malformed statement.
fn require_authorities<'a>(
    parent: &structured_asn1::Reader<'a>,
    element: &structured_asn1::Element<'a>,
) -> Result<OwnedVec<crate::general_name::GeneralName<'a>>> {
    const FIELD: &str = "extensions.qcStatements.semanticsInformation";
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            FIELD,
            element.span().start,
        ));
    }
    crate::general_name::read_all(parent, element, FIELD)
}

#[cfg(test)]
mod tests;
