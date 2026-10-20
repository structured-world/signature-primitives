//! Status retention and the extended revoked definition (RFC6960 §§2.2, 4.4.4, 4.4.8).

use super::{BasicResponse, RecordedStatus, SingleResponse, end};
use crate::crl::Reason;
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::Extension;
use crate::temporal::Instant;
use crate::{Time, oid};
use structured_asn1::memory::Work;
use structured_asn1::{Tag, universal};

const CUTOFF: &str = "ocspResponse.singleResponse.archiveCutoff";
const EXTENDED: &str = "ocspResponse.extendedRevoke";

// RFC6960 §4.4.4: `ArchiveCutoff ::= GeneralizedTime`, with no criticality
// requirement, so either marking is accepted.
// https://www.rfc-editor.org/rfc/rfc6960#section-4.4.4
pub(super) fn archive_cutoff<W: Work>(extension: &Extension<'_>, execution: &W) -> Result<Time> {
    let mut reader = extension.reader_scoped(execution).field(CUTOFF)?;
    let value = reader
        .expect(Tag::primitive(universal::GENERALIZED_TIME))
        .field(CUTOFF)?;
    end(&reader, CUTOFF)?;
    crate::time::read_in(&reader, &value, CUTOFF)
}

// RFC6960 §4.4.8: "The value of the extension SHALL be NULL. This extension
// MUST NOT be marked critical."
// https://www.rfc-editor.org/rfc/rfc6960#section-4.4.8
pub(super) fn extended_revoke<W: Work>(extension: &Extension<'_>, execution: &W) -> Result<()> {
    if extension.is_critical() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            EXTENDED,
            extension.span().start,
        ));
    }
    let mut reader = extension.reader_scoped(execution).field(EXTENDED)?;
    let value = reader
        .expect(Tag::primitive(universal::NULL))
        .field(EXTENDED)?;
    reader.null(&value).field(EXTENDED)?;
    end(&reader, EXTENDED)
}

// RFC6960 §4.4.8: the extension "MUST be placed in responseExtensions, and it
// MUST NOT appear in singleExtensions".
pub(super) fn misplaced(extension: &Extension<'_>) -> Error {
    Error::new(
        ErrorCode::MalformedValue,
        "ocspResponse.singleResponse.extendedRevoke",
        extension.span().start,
    )
}

// RFC6960 §2.2: a "revoked" answer for a non-issued certificate specifies
// certificateHold and revocationTime January 1, 1970, and includes neither CRL
// references (§4.4.2) nor CRL entry extensions (§4.4.5). Only that exact
// assertion, under a response carrying the extended revoked definition, is
// read as non-issued; any other hold stays a hold.
// https://www.rfc-editor.org/rfc/rfc6960#section-2.2
pub(super) fn not_issued<W: Work>(assertion: &SingleResponse<'_>, execution: &W) -> Result<bool> {
    let RecordedStatus::Revoked {
        time,
        reason: Some(Reason::CertificateHold),
        ..
    } = assertion.status
    else {
        return Ok(false);
    };
    if time.instant() != Instant::whole(0) {
        return Ok(false);
    }
    for kind in [
        oid::OCSP_CRL,
        oid::CRL_REASON,
        oid::INVALIDITY_DATE,
        oid::CERTIFICATE_ISSUER,
    ] {
        if assertion.extensions.get(kind, execution)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

impl BasicResponse<'_> {
    /// Whether the responder applies the extended revoked definition, so that a
    /// matching "revoked" assertion can name a certificate that was never issued.
    pub fn extended_revoke<W: Work>(&self, execution: &W) -> Result<bool> {
        match self.extensions.get(oid::OCSP_EXTENDED_REVOKE, execution)? {
            Some(extension) => extended_revoke(extension, execution).map(|()| true),
            None => Ok(false),
        }
    }

    /// The assertion's status under this response's extended revoked definition:
    /// [`super::Status::NotIssued`] for the exact RFC6960 §2.2 non-issued answer,
    /// otherwise the same reading as [`SingleResponse::status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::Parser;
    /// use structured_asn1::memory::{Memory, MemoryAccount};
    /// use structured_pkix::ocsp::{Response, Status};
    ///
    /// fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    ///     let length = contents.len() as u8;
    ///     let header: &[u8] = if length < 128 { &[tag, length] } else { &[tag, 0x81, length] };
    ///     [header, contents].concat()
    /// }
    /// let algorithm = tlv(0x30, &[6, 3, 0x2a, 3, 4]);
    /// let id = tlv(0x30, &[algorithm.clone(), tlv(4, &[1; 20]), tlv(4, &[2; 20]), vec![2, 1, 1]].concat());
    /// let date = tlv(24, b"20261012120000Z");
    /// // revoked, certificateHold, 1970-01-01T00:00:00Z
    /// let hold = tlv(0xa1, &[tlv(24, b"19700101000000Z"), tlv(0xa0, &[10, 1, 6])].concat());
    /// let single = tlv(0x30, &[id, hold, date.clone()].concat());
    /// let extended = tlv(0x30, &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 9]), tlv(4, &[5, 0])].concat());
    /// let data = tlv(0x30, &[
    ///     tlv(0xa2, &tlv(4, &[3; 20])), date, tlv(0x30, &single), tlv(0xa1, &tlv(0x30, &extended)),
    /// ].concat());
    /// let basic = tlv(0x30, &[data, algorithm, vec![3, 2, 0, 0xab]].concat());
    /// let bytes = tlv(0x30, &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]), tlv(4, &basic)].concat());
    /// let envelope = tlv(0x30, &[&[10, 1, 0][..], &tlv(0xa0, &bytes)].concat());
    ///
    /// let execution = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    /// let parser = Parser::der(execution.clone());
    /// let Response::Successful(payload) = Response::read(&parser, &envelope, 0).unwrap() else {
    ///     unreachable!()
    /// };
    /// let response = payload.into_basic(&execution).unwrap().unwrap();
    /// let assertion = &response.responses()[0];
    /// assert!(matches!(assertion.status(), Status::Revoked { .. }));
    /// assert_eq!(response.status_of(assertion, &execution).unwrap(), Status::NotIssued);
    /// ```
    ///
    /// # Errors
    ///
    /// A malformed extended revoked definition or CRL entry extension, or a
    /// spent work ceiling.
    pub fn status_of<W: Work>(
        &self,
        assertion: &SingleResponse<'_>,
        execution: &W,
    ) -> Result<super::Status> {
        let extended = self.extended_revoke(execution)?;
        status(assertion, extended, execution)
    }
}

pub(super) fn status<W: Work>(
    assertion: &SingleResponse<'_>,
    extended: bool,
    execution: &W,
) -> Result<super::Status> {
    if extended && not_issued(assertion, execution)? {
        return Ok(super::Status::NotIssued);
    }
    Ok(assertion.status())
}

impl SingleResponse<'_> {
    /// The responder's archive cutoff for this assertion: status is retained for
    /// certificates whose validity ended at or after it, so a certificate with
    /// `notAfter >= cutoff` stays covered after its expiry.
    pub fn archive_cutoff<W: Work>(&self, execution: &W) -> Result<Option<Time>> {
        match self.extensions.get(oid::OCSP_ARCHIVE_CUTOFF, execution)? {
            Some(extension) => archive_cutoff(extension, execution).map(Some),
            None => Ok(None),
        }
    }
}
