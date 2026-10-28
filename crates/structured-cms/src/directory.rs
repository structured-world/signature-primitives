//! Accounted certificate hint indexes, without signer identity or trust verdicts.

use crate::Error as ProcessingError;
use crate::signer::SignerIdentifier;
use core::cmp::Ordering;
use core::fmt;
use structured_asn1::Reader;
use structured_asn1::memory::{Execution, Memory, MemoryError, OwnedVec, SortError, Work};
use structured_pkix::{Certificate, Name, Ordered};

/// A directory operation has either an original document cause or a storage/
/// metadata admission failure that has no document position of its own.
#[derive(Debug)]
pub enum Error {
    /// Original certificate, name or signer-hint processing failure.
    Processing(ProcessingError),
    /// Source-free retained catalogue work or storage refusal.
    Resource(MemoryError),
}

impl Error {
    fn pkix(source: structured_pkix::Error) -> Self {
        Self::Processing(ProcessingError::pkix(source))
    }
    fn resource(reason: MemoryError, field: &'static str, at: u64) -> Self {
        Self::Processing(ProcessingError::resource(reason, field, at))
    }
    fn admission(reason: MemoryError, origin: Option<u64>) -> Self {
        match origin {
            Some(at) => Self::resource(reason, "signedData.certificates", at),
            None => Self::Resource(reason),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing(source) => source.fmt(formatter),
            Self::Resource(source) => source.fmt(formatter),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Processing(source) => Some(source),
            Self::Resource(source) => Some(source),
        }
    }
}

/// A complete catalogue operation; refusal never becomes a match answer.
pub type Result<T> = core::result::Result<T, Error>;

/// What the complete catalogue can establish about one certificate hint.
/// Matching a hint never authenticates that certificate or its path.
#[derive(Debug)]
pub enum Match<'c, 'a> {
    /// No certificate answers the complete hint, with no unreadable SKI gap.
    None,
    /// Exactly one certificate answers the complete hint.
    One(&'c Certificate<'a>),
    /// More than one certificate answers the complete hint; no candidate chosen.
    Ambiguous,
    /// An SKI value could not be read, so uniqueness/absence is unestablished.
    /// Original diagnostics are retained by [`Directory::unreadable_identifiers`].
    Unreadable,
}

/// One caller-selected certificate's hint agreement, without uniqueness/trust.
#[derive(Debug)]
pub enum CertificateAgreement {
    /// The original issuer/serial or SKI hint agrees.
    Matches,
    /// The complete readable hint names something else.
    Differs,
    /// Original certificate SKI syntax prevents a comparison.
    Unreadable(structured_pkix::Error),
}

/// Compares a selected certificate without constructing an issuer directory.
///
/// This uses the same paid byte/segmented and shared Name kernels as directory
/// search. Original certificate parsing may be a different session; lazy SKI
/// keeps that origin and also obeys the current query operation. This establishes
/// neither uniqueness in a pool nor signature/path trust for the selected key.
pub fn matches_certificate_in(
    named: &SignerIdentifier<'_>,
    certificate: &Certificate<'_>,
    parent: &Reader<'_>,
) -> Result<CertificateAgreement> {
    let execution = parent.execution();
    let at = certificate.span().start;
    match named {
        SignerIdentifier::IssuerAndSerial { issuer, serial } => {
            if bytes_order(
                serial.as_bytes(),
                certificate.tbs().serial().as_bytes(),
                &execution,
                at,
            )? != Ordering::Equal
            {
                return Ok(CertificateAgreement::Differs);
            }
            if issuer
                .matches_in(certificate.tbs().issuer(), parent)
                .map_err(Error::pkix)?
            {
                Ok(CertificateAgreement::Matches)
            } else {
                Ok(CertificateAgreement::Differs)
            }
        }
        SignerIdentifier::SubjectKeyIdentifier(wanted) => {
            let Some(extension) = certificate
                .tbs()
                .extensions()
                .get(structured_pkix::oid::SUBJECT_KEY_IDENTIFIER, &execution)
                .map_err(Error::pkix)?
            else {
                return Ok(CertificateAgreement::Differs);
            };
            let identifier =
                match structured_pkix::identifier::SubjectKeyIdentifier::read_in(extension, parent)
                {
                    Ok(identifier) => identifier,
                    Err(error)
                        if error.is_resource()
                            || error.code() == structured_pkix::ErrorCode::ForeignReader =>
                    {
                        return Err(Error::pkix(error));
                    }
                    Err(error) => return Ok(CertificateAgreement::Unreadable(error)),
                };
            if segmented_matches(wanted, identifier.as_bytes(), &execution, at)? {
                Ok(CertificateAgreement::Matches)
            } else {
                Ok(CertificateAgreement::Differs)
            }
        }
    }
}

/// Original malformed identifier diagnostic, independently of resource failures.
#[derive(Debug)]
pub struct Unreadable<'c, 'a> {
    certificate: &'c Certificate<'a>,
    reason: structured_pkix::Error,
}
impl<'c, 'a> Unreadable<'c, 'a> {
    /// Certificate whose actual extension was unreadable.
    #[must_use]
    pub fn certificate(&self) -> &'c Certificate<'a> {
        self.certificate
    }
    /// Original located encoding/schema cause, without conversion to absence.
    #[must_use]
    pub fn reason(&self) -> &structured_pkix::Error {
        &self.reason
    }
}

struct Identifier<'a> {
    bytes: &'a [u8],
    index: usize,
}

/// Prepared issuer/serial and SKI indexes retaining their own capacity charges.
///
/// Names are prepared once per certificate, not inside sorting comparators.
/// Owner type determines storage/execution lifetime, never semantic ordering.
/// Every new lookup explicitly funds its current domain. Unknown/malformed SKI
/// gaps cannot become a completed None/One result; resource refusal aborts.
pub struct Directory<'c, 'a, W: Work = Memory> {
    certificates: OwnedVec<&'c Certificate<'a>, W>,
    issuers: OwnedVec<Ordered<'a, W>, W>,
    serials: OwnedVec<usize, W>,
    identifiers: OwnedVec<Identifier<'a>, W>,
    unreadable: OwnedVec<Unreadable<'c, 'a>, W>,
}

impl<'c, 'a> Directory<'c, 'a> {
    /// Independently retained directory over certificates from any source session.
    /// Current Memory funds all construction; deferred SKI parsing preserves
    /// each original certificate's reader/depth and its cumulative parse ceiling.
    pub fn of(certificates: &[&'c Certificate<'a>], execution: &Memory) -> Result<Self> {
        let mut kept = execution.vector();
        kept.try_extend_from_slice(certificates)
            .map_err(Error::Resource)?;
        build(
            kept,
            execution,
            None,
            |name| name.ordered(execution),
            |extension| {
                structured_pkix::identifier::SubjectKeyIdentifier::read(extension, execution)
            },
        )
    }
}

impl<'c, 'a, 'p> Directory<'c, 'a, Execution<'p>> {
    /// Scoped directory over carried certificates from this one parser session.
    ///
    /// The source identity of every certificate is checked before allocation,
    /// normalization or lazy SKI parsing. A foreign pool belongs in [`Directory::of`];
    /// account equality cannot make it part of the producing document session.
    pub fn of_in(certificates: &[&'c Certificate<'a>], parent: &'p Reader<'_>) -> Result<Self>
    where
        'a: 'p,
    {
        let execution = parent.execution();
        // Preflight the borrowed catalogue before any retained storage or
        // deferred processing. One handle copy then feeds the shared builder.
        for certificate in certificates {
            execution.charge_work(1).map_err(|reason| {
                Error::resource(reason, "signedData.certificates", parent.offset())
            })?;
            if !certificate
                .tbs()
                .public_key()
                .algorithm()
                .same_session(parent)
            {
                return Err(Error::pkix(structured_pkix::Error::new(
                    structured_pkix::ErrorCode::ForeignReader,
                    "signedData.certificates",
                    certificate.span().start,
                )));
            }
        }
        let mut gathered = execution.vector();
        gathered
            .try_extend_from_slice(certificates)
            .map_err(|reason| Error::admission(reason, Some(parent.offset())))?;
        build(
            gathered,
            &execution,
            Some(parent.offset()),
            |name| name.ordered_in(parent),
            |extension| {
                structured_pkix::identifier::SubjectKeyIdentifier::read_in(extension, parent)
            },
        )
    }
}

impl<'c, 'a, W: Work> Directory<'c, 'a, W> {
    /// Indexed certificate count, without rescanning.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }
    /// Whether this directory carries no certificate hints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
    /// Original malformed SKI diagnostics, with their actual certificates.
    #[must_use]
    pub fn unreadable_identifiers(&self) -> &[Unreadable<'c, 'a>] {
        &self.unreadable
    }

    /// Retained query using current aggregate funding, independent of storage owner.
    pub fn find(&self, named: &SignerIdentifier<'_>, execution: &Memory) -> Result<Match<'c, 'a>> {
        self.find_with(named, execution, None, |name| name.ordered(execution))
    }
    /// Producing query using both current local and aggregate ceilings.
    /// A retained pool and scoped pool use the same index/search kernel.
    pub fn find_in(
        &self,
        named: &SignerIdentifier<'_>,
        parent: &Reader<'_>,
    ) -> Result<Match<'c, 'a>> {
        self.find_with(named, &parent.execution(), Some(parent.offset()), |name| {
            name.ordered_in(parent)
        })
    }

    fn find_with<'n, V: Work, E: Work>(
        &self,
        named: &SignerIdentifier<'n>,
        execution: &E,
        origin: Option<u64>,
        prepare: impl FnOnce(&Name<'n>) -> structured_pkix::Result<Ordered<'n, V>>,
    ) -> Result<Match<'c, 'a>> {
        match named {
            SignerIdentifier::IssuerAndSerial { issuer, serial } => {
                let asked = prepare(issuer).map_err(Error::pkix)?;
                let against = |index: usize| -> Result<Ordering> {
                    let held = self.certificates[index].tbs().serial().as_bytes();
                    let order = bytes_order(
                        held,
                        serial.as_bytes(),
                        execution,
                        self.certificates[index].span().start,
                    )?;
                    if order != Ordering::Equal {
                        return Ok(order);
                    }
                    self.issuers[index]
                        .order(&asked, execution)
                        .map_err(Error::pkix)
                };
                let from = lower_bound(self.serials.len(), execution, origin, |at| {
                    against(self.serials[at])
                })?;
                let mut first = None;
                for &index in &self.serials[from..] {
                    if against(index)? != Ordering::Equal {
                        break;
                    }
                    if first.is_some() {
                        return Ok(Match::Ambiguous);
                    }
                    first = Some(self.certificates[index]);
                }
                Ok(match first {
                    Some(certificate) => Match::One(certificate),
                    None => Match::None,
                })
            }
            SignerIdentifier::SubjectKeyIdentifier(wanted) => {
                let mut first = None;
                if let Some(bytes) = wanted.as_one() {
                    let from = lower_bound(self.identifiers.len(), execution, origin, |at| {
                        bytes_order(
                            self.identifiers[at].bytes,
                            bytes,
                            execution,
                            self.certificates[self.identifiers[at].index].span().start,
                        )
                    })?;
                    for held in &self.identifiers[from..] {
                        if bytes_order(
                            held.bytes,
                            bytes,
                            execution,
                            self.certificates[held.index].span().start,
                        )? != Ordering::Equal
                        {
                            break;
                        }
                        if first.is_some() {
                            return Ok(Match::Ambiguous);
                        }
                        first = Some(self.certificates[held.index]);
                    }
                } else {
                    // Compare the original segmented identifier without joining.
                    for held in &self.identifiers {
                        let at = self.certificates[held.index].span().start;
                        execution
                            .charge_work(1)
                            .map_err(|reason| Error::resource(reason, "signerInfo.sid", at))?;
                        if segmented_matches(wanted, held.bytes, execution, at)? {
                            if first.is_some() {
                                return Ok(Match::Ambiguous);
                            }
                            first = Some(self.certificates[held.index]);
                        }
                    }
                }
                if !self.unreadable.is_empty() {
                    return Ok(Match::Unreadable);
                }
                Ok(match first {
                    Some(certificate) => Match::One(certificate),
                    None => Match::None,
                })
            }
        }
    }
}

fn build<'c, 'a, W: Work>(
    kept: OwnedVec<&'c Certificate<'a>, W>,
    execution: &W,
    origin: Option<u64>,
    mut prepare: impl FnMut(&Name<'a>) -> structured_pkix::Result<Ordered<'a, W>>,
    mut read_identifier: impl FnMut(
        &structured_pkix::Extension<'a>,
    ) -> structured_pkix::Result<
        structured_pkix::identifier::SubjectKeyIdentifier<'a>,
    >,
) -> Result<Directory<'c, 'a, W>> {
    let mut issuers = execution.vector();
    let mut serials = execution.vector();
    let mut identifiers = execution.vector();
    let mut unreadable = execution.vector();
    for (index, certificate) in kept.iter().enumerate() {
        let at = certificate.span().start;
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, "signedData.certificates", at))?;
        issuers
            .try_push(prepare(certificate.tbs().issuer()).map_err(Error::pkix)?)
            .map_err(|reason| Error::resource(reason, "signedData.certificates", at))?;
        serials
            .try_push(index)
            .map_err(|reason| Error::resource(reason, "signedData.certificates", at))?;
        let extension = certificate
            .tbs()
            .extensions()
            .get(structured_pkix::oid::SUBJECT_KEY_IDENTIFIER, execution)
            .map_err(Error::pkix)?;
        if let Some(extension) = extension {
            match read_identifier(extension) {
                Ok(identifier) => identifiers
                    .try_push(Identifier {
                        bytes: identifier.as_bytes(),
                        index,
                    })
                    .map_err(|reason| {
                        Error::resource(
                            reason,
                            "extensions.subjectKeyIdentifier",
                            extension.span().start,
                        )
                    })?,
                Err(reason) if reason.is_resource() => return Err(Error::pkix(reason)),
                Err(reason) => unreadable
                    .try_push(Unreadable {
                        certificate,
                        reason,
                    })
                    .map_err(|reason| {
                        Error::resource(
                            reason,
                            "extensions.subjectKeyIdentifier",
                            extension.span().start,
                        )
                    })?,
            }
        }
    }
    serials
        .try_sort_unstable_by(|left, right| {
            let order = bytes_order(
                kept[*left].tbs().serial().as_bytes(),
                kept[*right].tbs().serial().as_bytes(),
                execution,
                kept[*left].span().start,
            )?;
            if order != Ordering::Equal {
                return Ok(order);
            }
            issuers[*left]
                .order(&issuers[*right], execution)
                .map_err(Error::pkix)
        })
        .map_err(|error| sort_error(error, origin))?;
    identifiers
        .try_sort_unstable_by(|left, right| {
            bytes_order(
                left.bytes,
                right.bytes,
                execution,
                kept[left.index].span().start,
            )
        })
        .map_err(|error| sort_error(error, origin))?;
    Ok(Directory {
        certificates: kept,
        issuers,
        serials,
        identifiers,
        unreadable,
    })
}

fn sort_error(error: SortError<Error>, origin: Option<u64>) -> Error {
    match error {
        SortError::Resource(reason) => Error::admission(reason, origin),
        SortError::Comparison(error) => error,
    }
}
fn bytes_order<W: Work>(left: &[u8], right: &[u8], execution: &W, at: u64) -> Result<Ordering> {
    execution
        .charge_work(1 + left.len().max(right.len()) as u64)
        .map_err(|reason| Error::resource(reason, "signerInfo.sid", at))?;
    Ok(left.cmp(right))
}
fn lower_bound<W: Work>(
    length: usize,
    execution: &W,
    origin: Option<u64>,
    mut compare: impl FnMut(usize) -> Result<Ordering>,
) -> Result<usize> {
    let mut from = 0;
    let mut to = length;
    while from < to {
        execution
            .charge_work(1)
            .map_err(|reason| Error::admission(reason, origin))?;
        let middle = from + (to - from) / 2;
        if compare(middle)? == Ordering::Less {
            from = middle + 1;
        } else {
            to = middle;
        }
    }
    Ok(from)
}
fn segmented_matches<W: Work>(
    wanted: &crate::Octets<'_>,
    held: &[u8],
    execution: &W,
    at: u64,
) -> Result<bool> {
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, "signerInfo.sid", at))?;
    if wanted.len() != held.len() {
        return Ok(false);
    }
    let mut offset = 0;
    for piece in wanted.pieces() {
        let bytes = piece.as_bytes();
        execution
            .charge_work(1 + bytes.len() as u64)
            .map_err(|reason| Error::resource(reason, "signerInfo.sid", at))?;
        if bytes != &held[offset..offset + bytes.len()] {
            return Ok(false);
        }
        offset += bytes.len();
    }
    debug_assert_eq!(offset, held.len());
    Ok(true)
}
