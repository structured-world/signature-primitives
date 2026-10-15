//! Binding an authenticated delta to an authenticated complete CRL.

use super::{Authenticated, EntryLookup, Reason, RevokedCertificate};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{Extension, Extensions};
use crate::identifier::AuthorityKeyIdentifier;
use crate::oid;
use core::cmp::Ordering;
use structured_asn1::memory::Work;
use structured_asn1::{Integer, Oid, Span};

/// Required metadata that was absent, rather than a mismatched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingDeltaField {
    /// Complete CRL does not carry a CRL number.
    BaseNumber,
    /// Delta does not carry a CRL number.
    DeltaNumber,
    /// Candidate delta does not carry a deltaCRLIndicator.
    Indicator,
    /// Complete CRL omits the authority key identifier required by its profile.
    BaseAuthorityIdentifier,
    /// Delta omits the authority key identifier required by its profile.
    DeltaAuthorityIdentifier,
}

/// Why two authenticated lists cannot form a complete-plus-delta pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaFailure {
    /// The proposed base is itself a delta.
    BaseIsDelta,
    /// The CRLs name different issuing authorities.
    Issuer,
    /// Original public keys or their effective parameters differ.
    SigningKey,
    /// Issuing distribution point encodings differ, including presence.
    Scope,
    /// Base number precedes the delta's minimum base.
    BaseTooOld,
    /// Delta number is not strictly greater than the complete CRL number.
    NumberOrder,
    /// An extension's criticality contradicts its specified role.
    Criticality,
    /// Complete validated AKI payloads differ, including optional fields.
    AuthorityIdentifier,
}

/// Authenticated source pair bound according to RFC 5280 §§5.2.4/6.3.3(c). Entries,
/// freshness and critical demands still require interpretation before status.
#[derive(Debug, Clone, Copy)]
pub struct BoundDelta<'b, 'r, 'a> {
    base: &'b Authenticated<'r, 'a>,
    delta: &'b Authenticated<'r, 'a>,
}

/// Source of an entry in combined evidence; original ranges remain untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryOrigin {
    /// The authenticated complete CRL.
    Complete,
    /// The authenticated delta CRL.
    Delta,
}

/// Delta-first entry interpretation, without freshness or coverage claims.
#[derive(Debug)]
pub enum CombinedEntry<'r, 'a> {
    /// Neither source lists this issuer/serial. This alone is not non-revocation.
    Absent,
    /// The selected original entry states revocation.
    Revoked {
        /// Source whose entry takes effect.
        origin: EntryOrigin,
        /// Original entry, including date and deferred metadata.
        entry: &'r RevokedCertificate<'a>,
        /// Encoded reason or the normative unspecified default.
        reason: Reason,
    },
    /// Delta removes the entry. Full reason coverage is still required.
    Removed {
        /// Original delta removal entry.
        entry: &'r RevokedCertificate<'a>,
    },
    /// One source contains ambiguous repeated identity.
    Conflict {
        /// Source containing both entries.
        origin: EntryOrigin,
        /// Earlier original entry.
        first: &'r RevokedCertificate<'a>,
        /// Later original entry.
        second: &'r RevokedCertificate<'a>,
    },
    /// A critical demand anywhere prevents using this source pair.
    Unsupported {
        /// Source whose critical demand is not understood.
        origin: EntryOrigin,
        /// Demand identifier, preserved as borrowed source bytes.
        kind: Oid<'a>,
        /// Original demand location.
        span: Span,
    },
}

impl<'b, 'r, 'a> BoundDelta<'b, 'r, 'a> {
    /// Apply RFC5280 §6.3.3(i)–(k) over original authenticated sources.
    /// Each source is scanned independently so indirect issuer state never
    /// leaks between lists. Critical demands and conflicting duplicates are
    /// checked in both sources before selecting a delta override.
    /// <https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3>
    pub fn entry<W: Work + 'a>(
        self,
        target: &crate::Certificate<'_>,
        execution: &W,
    ) -> Result<CombinedEntry<'r, 'a>> {
        let base = match usable(self.base.entry(target, execution)?, EntryOrigin::Complete) {
            Ok(entry) => entry,
            Err(refusal) => return Ok(refusal),
        };
        let delta = match usable(self.delta.entry(target, execution)?, EntryOrigin::Delta) {
            Ok(entry) => entry,
            Err(refusal) => return Ok(refusal),
        };
        let (origin, entry) = match (base, delta) {
            (_, Some(entry)) => (EntryOrigin::Delta, entry),
            (Some(entry), None) => (EntryOrigin::Complete, entry),
            (None, None) => return Ok(CombinedEntry::Absent),
        };
        let reason = entry.reason(execution)?.unwrap_or(Reason::Unspecified);
        // RFC5280 §5.2.4 permits removal even when this base lacked a hold
        // entry (intervening hold changes or expiration). Do not invent a
        // certificateHold prerequisite or reuse the base entry after removal.
        Ok(if reason == Reason::RemoveFromCrl {
            CombinedEntry::Removed { entry }
        } else {
            CombinedEntry::Revoked {
                origin,
                entry,
                reason,
            }
        })
    }
    /// Complete source CRL, not a serialized reconstructed list.
    #[must_use]
    pub fn base(self) -> &'b Authenticated<'r, 'a> {
        self.base
    }
    /// Delta source CRL, whose update times govern the combined list.
    #[must_use]
    pub fn delta(self) -> &'b Authenticated<'r, 'a> {
        self.delta
    }
}

fn usable<'r, 'a>(
    lookup: EntryLookup<'r, 'a>,
    origin: EntryOrigin,
) -> core::result::Result<Option<&'r RevokedCertificate<'a>>, CombinedEntry<'r, 'a>> {
    match lookup {
        EntryLookup::Conflict { first, second } => Err(CombinedEntry::Conflict {
            origin,
            first,
            second,
        }),
        EntryLookup::Unsupported { kind, span } => {
            Err(CombinedEntry::Unsupported { origin, kind, span })
        }
        EntryLookup::Absent => Ok(None),
        EntryLookup::Found(entry) => Ok(Some(entry)),
    }
}

/// Binding outcome, independent of processing/resource failures.
#[derive(Debug)]
pub enum DeltaBinding<'b, 'r, 'a> {
    /// Issuer, effective signing key, scope and numbers are bound.
    Bound(BoundDelta<'b, 'r, 'a>),
    /// Required metadata is missing.
    Missing(MissingDeltaField),
    /// Metadata establishes that this pair cannot be combined.
    Rejected(DeltaFailure),
}

impl<'r, 'a> Authenticated<'r, 'a> {
    /// Bind a candidate delta to this complete CRL without copying entries.
    /// The caller supplies both issuer paths' same-anchor trust provenance.
    /// Each comparison and lazy read uses the current execution account.
    pub fn bind_delta<'b, W: Work + 'a>(
        &'b self,
        delta: &'b Self,
        execution: &W,
    ) -> Result<DeltaBinding<'b, 'r, 'a>> {
        const FIELD: &str = "certificateList.deltaBinding";
        let at = delta.crl().span().start;
        let base_extensions = self.crl().tbs().extensions();
        let delta_extensions = delta.crl().tbs().extensions();
        if base_extensions
            .get(oid::DELTA_CRL_INDICATOR, execution)?
            .is_some()
        {
            return Ok(DeltaBinding::Rejected(DeltaFailure::BaseIsDelta));
        }
        let Some(indicator) = delta_extensions.get(oid::DELTA_CRL_INDICATOR, execution)? else {
            return Ok(DeltaBinding::Missing(MissingDeltaField::Indicator));
        };
        if !indicator.is_critical() {
            return Ok(DeltaBinding::Rejected(DeltaFailure::Criticality));
        }
        let minimum = number(indicator, execution)?;
        let Some(base_number) = base_extensions.get(oid::CRL_NUMBER, execution)? else {
            return Ok(DeltaBinding::Missing(MissingDeltaField::BaseNumber));
        };
        let Some(delta_number) = delta_extensions.get(oid::CRL_NUMBER, execution)? else {
            return Ok(DeltaBinding::Missing(MissingDeltaField::DeltaNumber));
        };
        if base_number.is_critical() || delta_number.is_critical() {
            return Ok(DeltaBinding::Rejected(DeltaFailure::Criticality));
        }
        let base_number = number(base_number, execution)?;
        let delta_number = number(delta_number, execution)?;
        match authority_pair(base_extensions, delta_extensions, execution, at)? {
            AuthorityMatch::Matched => (),
            AuthorityMatch::Missing(field) => return Ok(DeltaBinding::Missing(field)),
            AuthorityMatch::Rejected(reason) => return Ok(DeltaBinding::Rejected(reason)),
        }
        // RFC 5280 §5.2.4 conditions (a)-(d): same issuer, same signing key,
        // same scope, baseNumber >= BaseCRLNumber and < delta's CRL number.
        // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.4
        if !self
            .crl()
            .tbs()
            .issuer()
            .matches(delta.crl().tbs().issuer(), execution)?
        {
            return Ok(DeltaBinding::Rejected(DeltaFailure::Issuer));
        }
        if !equal(
            self.key().key().as_bytes(),
            delta.key().key().as_bytes(),
            execution,
            FIELD,
            at,
        )? || !optional_equal(
            self.key().parameters(),
            delta.key().parameters(),
            execution,
            FIELD,
            at,
        )? {
            return Ok(DeltaBinding::Rejected(DeltaFailure::SigningKey));
        }
        let base_scope = base_extensions.get(oid::ISSUING_DISTRIBUTION_POINT, execution)?;
        let delta_scope = delta_extensions.get(oid::ISSUING_DISTRIBUTION_POINT, execution)?;
        if base_scope.is_some_and(|extension| !extension.is_critical())
            || delta_scope.is_some_and(|extension| !extension.is_critical())
        {
            return Ok(DeltaBinding::Rejected(DeltaFailure::Criticality));
        }
        if !optional_equal(
            base_scope.map(|extension| extension.value()),
            delta_scope.map(|extension| extension.value()),
            execution,
            FIELD,
            at,
        )? {
            return Ok(DeltaBinding::Rejected(DeltaFailure::Scope));
        }
        if compare(base_number, minimum, execution, FIELD, at)? == Ordering::Less {
            return Ok(DeltaBinding::Rejected(DeltaFailure::BaseTooOld));
        }
        if compare(base_number, delta_number, execution, FIELD, at)? != Ordering::Less {
            return Ok(DeltaBinding::Rejected(DeltaFailure::NumberOrder));
        }
        Ok(DeltaBinding::Bound(BoundDelta { base: self, delta }))
    }
}

enum AuthorityMatch {
    Matched,
    Missing(MissingDeltaField),
    Rejected(DeltaFailure),
}

fn authority_pair<'a, W: Work + 'a>(
    base: &Extensions<'a>,
    delta: &Extensions<'a>,
    execution: &W,
    at: u64,
) -> Result<AuthorityMatch> {
    let Some(base) = base.get(oid::AUTHORITY_KEY_IDENTIFIER, execution)? else {
        return Ok(AuthorityMatch::Missing(
            MissingDeltaField::BaseAuthorityIdentifier,
        ));
    };
    let Some(delta) = delta.get(oid::AUTHORITY_KEY_IDENTIFIER, execution)? else {
        return Ok(AuthorityMatch::Missing(
            MissingDeltaField::DeltaAuthorityIdentifier,
        ));
    };
    if base.is_critical() || delta.is_critical() {
        return Ok(AuthorityMatch::Rejected(DeltaFailure::Criticality));
    }
    for extension in [base, delta] {
        let parsed = AuthorityKeyIdentifier::read(extension, execution)?;
        // RFC5280 §5.2.1 requires CRLs to carry the keyIdentifier method,
        // not just the optional issuer/serial alternative.
        if parsed.key_id().is_none() {
            return Err(Error::new(
                ErrorCode::MissingField,
                "extensions.authorityKeyIdentifier.keyIdentifier",
                extension.span().start,
            ));
        }
    }
    // RFC5280 §6.3.3(c)(3) requires matching extensions. It does not define
    // additional DN/set equivalence here. Full validated DER-value equality
    // follows OpenSSL check_delta_base and Bouncy Castle PKIXCRLValidator;
    // optional field presence and order remain significant. Outer Extension
    // headers are not compared; criticality is checked independently above.
    // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
    // https://github.com/openssl/openssl/blob/2506f1fc323b567b0e48a13b6069c7778077e55e/crypto/x509/x509_vfy.c#L1482
    Ok(
        if equal(
            base.value(),
            delta.value(),
            execution,
            "certificateList.deltaBinding",
            at,
        )? {
            AuthorityMatch::Matched
        } else {
            AuthorityMatch::Rejected(DeltaFailure::AuthorityIdentifier)
        },
    )
}

pub(super) fn number<'a, W: Work + 'a>(
    extension: &Extension<'a>,
    execution: &W,
) -> Result<Integer<'a>> {
    const FIELD: &str = "extensions.cRLNumber";
    let mut reader = extension.reader(execution).field(FIELD)?;
    let value = reader.read_integer().field(FIELD)?;
    super::end(&reader, FIELD, extension.span().start)?;
    if value.is_negative() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            extension.span().start,
        ));
    }
    Ok(value)
}

fn compare(
    left: Integer<'_>,
    right: Integer<'_>,
    execution: &impl Work,
    field: &'static str,
    at: u64,
) -> Result<Ordering> {
    let left = magnitude(left.as_bytes());
    let right = magnitude(right.as_bytes());
    // DER INTEGER is minimal; a possible zero sign octet has no magnitude.
    admit(left.len().max(right.len()), execution, field, at)?;
    Ok(left.len().cmp(&right.len()).then_with(|| left.cmp(right)))
}

fn magnitude(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0, rest @ ..] => rest,
        all => all,
    }
}

fn optional_equal(
    left: Option<&[u8]>,
    right: Option<&[u8]>,
    execution: &impl Work,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    match (left, right) {
        (Some(left), Some(right)) => equal(left, right, execution, field, at),
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

fn equal(
    left: &[u8],
    right: &[u8],
    execution: &impl Work,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    admit(left.len().max(right.len()), execution, field, at)?;
    Ok(left == right)
}

fn admit(width: usize, execution: &impl Work, field: &'static str, at: u64) -> Result<()> {
    let work = (width as u64)
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                field,
                at,
            )
        })?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, field, at))
}
