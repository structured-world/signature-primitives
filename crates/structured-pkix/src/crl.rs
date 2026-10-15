//! Borrowed certificate revocation lists and their original signed ranges.
//!
//! Reading preserves evidence; it does not authenticate the issuer or establish
//! a certificate's revocation status. Deferred extension decoding uses the
//! caller's current execution account and the producing parser's ceilings.

use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extensions};
use crate::name::{self, Name};
use crate::path::{Verified, Verify, WorkingKey};
use crate::time::{self, Time};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{BitString, Element, Integer, Parser, Reader, Span, Tag, universal};

mod scope;
pub use scope::{CertificateKind, IssuingDistributionPoint, Reasons, ScopeFailure, ScopeOutcome};
mod entry;
pub use entry::EntryLookup;
pub use entry::Reason;
pub(crate) use entry::reason_element;
mod delta;
pub use delta::{
    BoundDelta, CombinedEntry, DeltaBinding, DeltaFailure, EntryOrigin, MissingDeltaField,
};
mod freshness;
pub use freshness::Freshness;
pub(crate) use freshness::update_window;

mod evidence;
pub use evidence::{
    AbsenceEvidence, CompleteEvidence, CompleteFacts, Coverage, CoverageAdmission, DeltaEvidence,
    DeltaFacts, Evaluation, EvidenceSource, SourceOrigin,
};

/// The CRL schema version, independently of the issuer certificate's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Original schema, with neither CRL nor entry extensions.
    V1,
    /// Extension-bearing schema; its encoded version is INTEGER 1.
    V2,
}

/// Why a supplied signing authority did not authenticate this CRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationFailure {
    /// The effective key's original SPKI is not the issuer certificate's key.
    KeyBinding,
    /// The CRL issuer does not match the supplied issuer's subject.
    IssuerName,
    /// The issuer's certificate does not permit signing revocation lists.
    KeyUsage,
    /// The verifier completed and rejected the signature.
    Signature,
}

/// An authenticated signature and its exact source authority. This does not
/// claim freshness, distribution-point applicability or non-revocation.
#[derive(Debug, Clone, Copy)]
pub struct Authenticated<'r, 'a> {
    crl: &'r CertificateList<'a>,
    issuer: &'r crate::Certificate<'a>,
    key: WorkingKey<'a>,
}

impl<'r, 'a> Authenticated<'r, 'a> {
    /// Original CRL whose signed bytes the callback authenticated.
    #[must_use]
    pub fn crl(self) -> &'r CertificateList<'a> {
        self.crl
    }
    /// Certificate supplied as the already authenticated signing authority.
    #[must_use]
    pub fn issuer(self) -> &'r crate::Certificate<'a> {
        self.issuer
    }
    /// Effective key, bound to this issuer's original SPKI.
    #[must_use]
    pub fn key(self) -> WorkingKey<'a> {
        self.key
    }
}

/// Completed authentication result, separately from processing and callback
/// failures. Unsupported verification is never a rejected signature.
#[derive(Debug)]
pub enum Authentication<'r, 'a> {
    /// Signature and issuer binding were established.
    Authenticated(Authenticated<'r, 'a>),
    /// A completed binding or verification check rejected the authority.
    Rejected(AuthenticationFailure),
    /// The callback does not support this signature or effective key.
    Unsupported,
}

/// One CRL entry. An indirect CRL's effective issuer is determined by the
/// certificateIssuer extension and preceding entries, not by this serial alone.
#[derive(Debug)]
pub struct RevokedCertificate<'a> {
    serial: Integer<'a>,
    revocation_date: Time,
    revocation_date_offset: u64,
    extensions: Extensions<'a>,
    span: Span,
}

impl<'a> RevokedCertificate<'a> {
    /// Serial exactly as encoded, without narrowing to a machine integer.
    #[must_use]
    pub fn serial(&self) -> Integer<'a> {
        self.serial
    }

    /// The issuer's stated revocation date, retaining its UTC label and form.
    #[must_use]
    pub fn revocation_date(&self) -> Time {
        self.revocation_date
    }

    /// Establish the recorded date's relation to an explicit UTC reading.
    /// Caller decides how that fact affects historical/current acceptance;
    /// this never silently makes a future-dated entry an absence statement.
    pub fn time_relation<W: Work>(
        &self,
        now: crate::temporal::Reading,
        utc: &crate::temporal::LeapTable<'_>,
        execution: &W,
    ) -> Result<crate::time::Relation> {
        crate::time::relation_in(
            self.revocation_date.instant(),
            now,
            utc,
            execution,
            (
                "certificateList.revokedCertificates.revocationDate",
                self.revocation_date_offset,
            ),
        )
    }

    /// Entry extensions, including unknown critical demands.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }

    /// Original document location of this entry.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

/// The signed CRL fields. Collection capacity is owned and accounted; input,
/// identifiers, names and extension values remain borrowed.
#[derive(Debug)]
pub struct TbsCertList<'a> {
    version: Version,
    signature: AlgorithmIdentifier<'a>,
    issuer: Name<'a>,
    this_update: Time,
    next_update: Option<Time>,
    revoked: OwnedVec<RevokedCertificate<'a>>,
    extensions: Extensions<'a>,
    bytes: &'a [u8],
    span: Span,
}

impl<'a> TbsCertList<'a> {
    /// Which CRL schema was used.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }
    /// Algorithm inside the authenticated range.
    #[must_use]
    pub fn signature(&self) -> AlgorithmIdentifier<'a> {
        self.signature
    }
    /// Nonempty CRL issuer distinguished name.
    #[must_use]
    pub fn issuer(&self) -> &Name<'a> {
        &self.issuer
    }
    /// Issue time, without consulting a clock or UTC correction service.
    #[must_use]
    pub fn this_update(&self) -> Time {
        self.this_update
    }
    /// Advertised next issue time. Its absence is preserved: RFC 5280 §5.1.2.5
    /// leaves client behavior for this case unspecified.
    #[must_use]
    pub fn next_update(&self) -> Option<Time> {
        self.next_update
    }
    /// Entries in wire order, required for indirect issuer inheritance.
    #[must_use]
    pub fn revoked_certificates(&self) -> &[RevokedCertificate<'a>] {
        &self.revoked
    }
    /// CRL extensions, kept independently of recognition or authentication.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }
    /// Exact DER `TBSCertList`, including its original tag and length.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Original document location of `TBSCertList`.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

/// A DER `CertificateList`, with no fetching or implicit trust decisions.
#[derive(Debug)]
pub struct CertificateList<'a> {
    tbs: TbsCertList<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitString<'a>,
    bytes: &'a [u8],
    span: Span,
}

impl<'a> CertificateList<'a> {
    /// Authenticate with an already authenticated issuer and its effective
    /// working key. The caller establishes the issuer path and its trust-anchor
    /// provenance; this operation binds that certificate to the actual key and
    /// CRL. It performs no path search, fetching, clock access or status verdict.
    ///
    /// The verifier must account its own transitive work and allocations in
    /// `execution`. Passing this domain is not evidence that an opaque provider
    /// backend enforces the accounting contract.
    pub fn authenticate<'r, V: Verify<E>, E: Work + 'a>(
        &'r self,
        issuer: &'r crate::Certificate<'a>,
        key: WorkingKey<'a>,
        verifier: &V,
        execution: &E,
    ) -> crate::error::CallbackResult<Authentication<'r, 'a>, V::Error> {
        use crate::error::CallbackError;
        let encoded_key = key.key().as_bytes();
        let issuer_key = issuer.tbs().public_key().as_bytes();
        let work = (encoded_key.len().max(issuer_key.len()) as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                Error::resource(
                    structured_asn1::memory::MemoryError::WorkExceeded,
                    FIELD,
                    self.span.start,
                )
            })?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, FIELD, self.span.start))?;
        if encoded_key != issuer_key {
            return Ok(Authentication::Rejected(AuthenticationFailure::KeyBinding));
        }
        if !self.tbs.issuer.matches(issuer.tbs().subject(), execution)? {
            return Ok(Authentication::Rejected(AuthenticationFailure::IssuerName));
        }
        let usage = issuer.tbs().extensions().key_usage(execution)?;
        // RFC 10007 §4: version 3 CRL issuer certificates require keyUsage
        // with cRLSign. Version 1/2 certificates are exempt from its presence;
        // an existing keyUsage still constrains the operation (RFC 5280 §6.3.3).
        // https://www.rfc-editor.org/rfc/rfc10007#section-4
        if usage.is_some_and(|usage| !usage.crl_sign())
            || (usage.is_none() && issuer.tbs().version() == crate::Version::V3)
        {
            return Ok(Authentication::Rejected(AuthenticationFailure::KeyUsage));
        }
        match verifier
            .verify(
                &self.tbs.signature,
                key,
                self.signed_bytes(),
                self.signature,
                execution,
            )
            .map_err(CallbackError::Callback)?
        {
            Verified::Yes => Ok(Authentication::Authenticated(Authenticated {
                crl: self,
                issuer,
                key,
            })),
            Verified::No => Ok(Authentication::Rejected(AuthenticationFailure::Signature)),
            Verified::Unsupported => Ok(Authentication::Unsupported),
        }
    }

    /// Read exactly one CRL, retaining original offsets and the shared parser.
    pub fn read(parser: &'a Parser, bytes: &'a [u8], base: u64) -> Result<Self> {
        let mut reader = parser.read(bytes, base).field(FIELD)?;
        let element = required(&mut reader, FIELD, base)?;
        let crl = Self::read_element(&reader, &element)?;
        if !reader.is_empty() {
            return Err(Error::new(
                ErrorCode::TrailingData,
                FIELD,
                element.span().end(),
            ));
        }
        Ok(crl)
    }

    /// Read an embedded CRL through its producing Reader. A BER envelope does
    /// not relax the CRL's DER spelling or reset depth and work limits.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        // RFC 5280 §5.1 and Appendix A.1 require the CertificateList DER model.
        // https://www.rfc-editor.org/rfc/rfc5280#section-5.1
        let mut outer = parent
            .reread(element, structured_asn1::Encoding::Der)
            .field(FIELD)?;
        let root = outer
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(FIELD)?;
        let mut inside = outer.enter(&root).field(FIELD)?;
        let tbs_element = required(&mut inside, TBS, root.span().start)?;
        let tbs = read_tbs(&inside, &tbs_element)?;
        let algorithm_element = required(&mut inside, ALGORITHM, root.span().start)?;
        let signature_algorithm = algorithm::read(&inside, &algorithm_element, ALGORITHM)?;
        let signature = inside.read_bit_string().field(SIGNATURE)?;
        end(&inside, FIELD, root.span().start)?;
        // RFC 5280 §§5.1.1.2, 5.1.2.2: the unsigned algorithm must agree with
        // the signed identifier. Preserve both execution and parser ceilings.
        if !signature_algorithm.matches_in(&tbs.signature, &inside)? {
            return Err(Error::new(
                ErrorCode::AlgorithmMismatch,
                ALGORITHM,
                algorithm_element.span().start,
            ));
        }
        Ok(Self {
            tbs,
            signature_algorithm,
            signature,
            bytes: root.as_bytes(),
            span: root.span(),
        })
    }

    /// Signed fields and retained revocation entries.
    #[must_use]
    pub fn tbs(&self) -> &TbsCertList<'a> {
        &self.tbs
    }
    /// Outer algorithm, already required to match the signed algorithm.
    #[must_use]
    pub fn signature_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.signature_algorithm
    }
    /// Original signature BIT STRING.
    #[must_use]
    pub fn signature(&self) -> BitString<'a> {
        self.signature
    }
    /// Exact `TBSCertList` range to supply to a signature verifier.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.tbs.bytes
    }
    /// Whole original `CertificateList` encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Whole CRL location in its enclosing document.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

const FIELD: &str = "certificateList";
const TBS: &str = "certificateList.tbsCertList";
const ALGORITHM: &str = "certificateList.signatureAlgorithm";
const SIGNATURE: &str = "certificateList.signature";
const ISSUER: &str = "certificateList.tbsCertList.issuer";
const THIS_UPDATE: &str = "certificateList.tbsCertList.thisUpdate";
const NEXT_UPDATE: &str = "certificateList.tbsCertList.nextUpdate";
const ENTRIES: &str = "certificateList.tbsCertList.revokedCertificates";
const EXTENSIONS: &str = "certificateList.tbsCertList.crlExtensions";

fn required<'a>(reader: &mut Reader<'a>, field: &'static str, at: u64) -> Result<Element<'a>> {
    reader
        .next_element()
        .field(field)?
        .ok_or_else(|| Error::new(ErrorCode::MissingField, field, at))
}

fn end(reader: &Reader<'_>, field: &'static str, at: u64) -> Result<()> {
    if reader.is_empty() {
        return Ok(());
    }
    Err(Error::new(ErrorCode::TrailingData, field, at))
}

fn is_time(element: &Element<'_>) -> bool {
    element.tag() == Tag::primitive(universal::UTC_TIME)
        || element.tag() == Tag::primitive(universal::GENERALIZED_TIME)
}

fn read_tbs<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<TbsCertList<'a>> {
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            TBS,
            element.span().start,
        ));
    }
    let mut inside = parent.enter(element).field(TBS)?;
    let mut next = required(&mut inside, TBS, element.span().start)?;
    let version = if next.tag() == Tag::primitive(universal::INTEGER) {
        // as_u64 refuses wider inputs before scanning, and converts at most
        // eight magnitude bytes. Admit that bounded conversion before it runs.
        inside.charge(9).field(TBS)?;
        if inside.integer(&next).field(TBS)?.as_u64() != Some(1) {
            return Err(Error::new(
                ErrorCode::UnsupportedVersion,
                TBS,
                next.span().start,
            ));
        }
        next = required(&mut inside, TBS, element.span().start)?;
        Version::V2
    } else {
        Version::V1
    };
    let signature = algorithm::read(&inside, &next, TBS)?;
    let issuer_element = required(&mut inside, ISSUER, element.span().start)?;
    let issuer = name::read(&inside, &issuer_element, ISSUER)?;
    // RFC 5280 §5.1.2.3: issuer MUST contain a nonempty distinguished name.
    if issuer.is_empty() {
        return Err(Error::new(
            ErrorCode::EmptySequence,
            ISSUER,
            issuer_element.span().start,
        ));
    }
    let this = required(&mut inside, THIS_UPDATE, element.span().start)?;
    let this_update = time::read_in(&inside, &this, THIS_UPDATE)?;
    let mut next = inside.next_element().field(TBS)?;
    let next_update = match next {
        Some(value) if is_time(&value) => {
            let time = time::read_in(&inside, &value, NEXT_UPDATE)?;
            next = inside.next_element().field(TBS)?;
            Some(time)
        }
        _ => None,
    };
    let work = parent.execution();
    let mut revoked = work.vector();
    if let Some(sequence) =
        next.filter(|value| value.tag() == Tag::constructed(universal::SEQUENCE))
    {
        let mut entries = inside.enter(&sequence).field(ENTRIES)?;
        while let Some(entry) = entries.next_element().field(ENTRIES)? {
            let value = read_entry(&entries, &entry, version)?;
            revoked
                .try_push(value)
                .map_err(|reason| Error::resource(reason, ENTRIES, entry.span().start))?;
        }
        // RFC 5280 §5.1.2.6: no revoked certificates means the list is absent.
        if revoked.is_empty() {
            return Err(Error::new(
                ErrorCode::EmptySequence,
                ENTRIES,
                sequence.span().start,
            ));
        }
        next = inside.next_element().field(TBS)?;
    }
    let mut extensions = Extensions::empty(inside.memory());
    if let Some(tagged) = next {
        if tagged.tag() != Tag::context(true, 0) || version != Version::V2 {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                EXTENSIONS,
                tagged.span().start,
            ));
        }
        let mut wrapper = inside.enter(&tagged).field(EXTENSIONS)?;
        let sequence = required(&mut wrapper, EXTENSIONS, tagged.span().start)?;
        extensions = extension::read(&wrapper, &sequence, EXTENSIONS)?;
        end(&wrapper, EXTENSIONS, tagged.span().start)?;
    }
    end(&inside, TBS, element.span().start)?;
    Ok(TbsCertList {
        version,
        signature,
        issuer,
        this_update,
        next_update,
        revoked: revoked.into_owned(),
        extensions,
        bytes: element.as_bytes(),
        span: element.span(),
    })
}

fn read_entry<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    version: Version,
) -> Result<RevokedCertificate<'a>> {
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            ENTRIES,
            element.span().start,
        ));
    }
    let mut inside = parent.enter(element).field(ENTRIES)?;
    let serial = inside.read_integer().field(ENTRIES)?;
    let date = required(&mut inside, ENTRIES, element.span().start)?;
    let revocation_date = time::read_in(&inside, &date, ENTRIES)?;
    let extensions = match inside.next_element().field(ENTRIES)? {
        Some(value) => {
            // RFC 5280 §5.1.2.6: entry extensions require CRL version 2.
            if version != Version::V2 {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    ENTRIES,
                    value.span().start,
                ));
            }
            extension::read(&inside, &value, ENTRIES)?
        }
        None => Extensions::empty(inside.memory()),
    };
    end(&inside, ENTRIES, element.span().start)?;
    Ok(RevokedCertificate {
        serial,
        revocation_date,
        revocation_date_offset: date.span().start,
        extensions,
        span: element.span(),
    })
}
