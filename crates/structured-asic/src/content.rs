//! A complete original member owns its decoded CMS or evidence-record source.

use crate::{
    error::Error,
    zip::{Member, MemberId, ReadFailure},
};
use structured_asn1::{
    Reader, Span,
    memory::{OwnedVec, Work},
    range::RangeSource,
};
use structured_cms::{ContentInfo, SignedData, evidence::EvidenceRecord, timestamp::Token};

/// A complete carried extent cannot be interpreted as the selected envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// No element was present.
    Empty,
    /// Bytes follow the one complete evidence record.
    Trailing,
    /// `ContentInfo` names an alternative content type.
    ContentType,
}

/// Physical member provenance and decoded logical diagnostics stay distinct.
#[derive(Debug)]
pub enum CarriedError<E, D, G> {
    /// Original source/current query refused before the carried operation.
    Archive(Error<E>),
    /// Original ASN.1 diagnostic in decoded-member coordinates.
    Encoding {
        /// Original member, independent of a temporary parsed view.
        member: MemberId<D, G>,
        /// Honest physical enclosure, not an invented inner physical offset.
        physical: Span,
        /// Unchanged original logical diagnostic.
        cause: structured_asn1::Error,
    },
    /// Original CMS or RFC4998 diagnostic in decoded-member coordinates.
    Cms {
        /// Original member identity.
        member: MemberId<D, G>,
        /// Actual physical enclosure of the encoded member.
        physical: Span,
        /// Unchanged common error.
        cause: structured_cms::Error,
    },
    /// A completed negative carried-envelope fact.
    Syntax {
        /// Original member identity.
        member: MemberId<D, G>,
        /// Actual physical enclosure.
        physical: Span,
        /// Envelope-level negative fact.
        kind: Syntax,
    },
}

/// Independent storage for one complete original decoded member. Its ASN.1
/// cursor always inherits the archive's producing session and current query;
/// neither moving storage nor reopening a cursor resets cumulative work.
pub struct Content<'v, 's, S: RangeSource> {
    member: Member<'v, 's, S>,
    bytes: OwnedVec<u8>,
}

impl<'v, 's, S: RangeSource> Member<'v, 's, S> {
    /// Acquires exactly this original occurrence through complete EOF/CRC.
    /// Signed data objects can instead use `source` without retention.
    pub async fn content<W: Work>(
        &self,
        work: &W,
    ) -> Result<Content<'v, 's, S>, ReadFailure<S::Error, S::Document, S::Generation>> {
        let bytes = self.read_bytes(work).await?;
        let member =
            self.archive()
                .original(self.id(), work)
                .map_err(|cause| ReadFailure::Processing {
                    member: self.id(),
                    cause,
                })?;
        Ok(Content { member, bytes })
    }
}

/// Original logical reading result, retaining the source's acquisition cause.
pub type ResultOf<T, S> = Result<
    T,
    CarriedError<
        <S as RangeSource>::Error,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
>;

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    pub(crate) fn into_parts(self) -> (Member<'v, 's, S>, OwnedVec<u8>) {
        (self.member, self.bytes)
    }
    /// Exact original central-directory occurrence that supplied these bytes.
    #[must_use]
    pub fn member(&self) -> &Member<'v, 's, S> {
        &self.member
    }
    /// Complete decoded bytes, without copying or treating them as physical offsets.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Physical original local record, including any descriptor.
    ///
    /// # Panics
    /// Only if the private complete-content construction invariant is broken:
    /// complete CRC-checked bytes always have a validated local enclosure.
    #[must_use]
    pub fn enclosure(&self) -> Span {
        self.member
            .local_span()
            .expect("complete original content has a local enclosure")
    }
    fn cursor<'q, W: Work + 'q>(&'q self, work: &W) -> ResultOf<Reader<'q>, S> {
        self.member
            .archive()
            .admit(work, self.enclosure())
            .map_err(CarriedError::Archive)?;
        self.member
            .session()
            .carried(&self.bytes, work)
            .map_err(|cause| self.encoding(cause))
    }
    fn encoding(
        &self,
        cause: structured_asn1::Error,
    ) -> CarriedError<S::Error, S::Document, S::Generation> {
        CarriedError::Encoding {
            member: self.member.id(),
            physical: self.enclosure(),
            cause,
        }
    }
    fn cms(
        &self,
        cause: structured_cms::Error,
    ) -> CarriedError<S::Error, S::Document, S::Generation> {
        CarriedError::Cms {
            member: self.member.id(),
            physical: self.enclosure(),
            cause,
        }
    }
    fn syntax(&self, kind: Syntax) -> CarriedError<S::Error, S::Document, S::Generation> {
        CarriedError::Syntax {
            member: self.member.id(),
            physical: self.enclosure(),
            kind,
        }
    }
    /// Inspects the original carried CMS without a replacement parser or copy.
    pub fn read<'q, W: Work + 'q>(&'q self, work: &W) -> ResultOf<(SignedData<'q>, Reader<'q>), S> {
        let mut root = self.cursor(work)?;
        let (content, parent) = ContentInfo::read(&mut root).map_err(|cause| self.cms(cause))?;
        parent
            .execution()
            .charge_work(content.kind().as_bytes().len() as u64)
            .map_err(|cause| {
                CarriedError::Archive(crate::error::resource(self.enclosure(), cause))
            })?;
        if content.kind() != structured_cms::oid::SIGNED_DATA {
            return Err(self.syntax(Syntax::ContentType));
        }
        let message = SignedData::read_element(&parent, content.content())
            .map_err(|cause| self.cms(cause))?;
        self.require(&message, &parent, work)
            .map_err(CarriedError::Archive)?;
        Ok((message, parent))
    }
    /// Uses the existing complete RFC3161 envelope reader on this source.
    pub fn read_timestamp<'q, W: Work + 'q>(
        &'q self,
        work: &W,
    ) -> ResultOf<(Token<'q>, Reader<'q>), S> {
        let mut reader = self.cursor(work)?;
        let token = Token::read_from(&mut reader).map_err(|cause| self.cms(cause))?;
        self.require(token.message(), &reader, work)
            .map_err(CarriedError::Archive)?;
        Ok((token, reader))
    }
    /// Uses the shared RFC4998 grammar for one entire original member.
    pub fn read_evidence<'q, W: Work + 'q>(
        &'q self,
        work: &W,
    ) -> ResultOf<(EvidenceRecord<'q>, Reader<'q>), S> {
        let mut reader = self.cursor(work)?;
        let element = reader
            .next_element()
            .map_err(|cause| self.encoding(cause))?
            .ok_or_else(|| self.syntax(Syntax::Empty))?;
        if !reader.is_empty() {
            return Err(self.syntax(Syntax::Trailing));
        }
        let record = EvidenceRecord::read(&reader, &element).map_err(|cause| self.cms(cause))?;
        Ok((record, reader))
    }
    pub(crate) fn require<W: Work>(
        &self,
        message: &SignedData<'_>,
        parent: &Reader<'_>,
        work: &W,
    ) -> Result<(), Error<S::Error>> {
        self.require_original(message.as_bytes(), message.span().start, parent, work)
    }
    pub(crate) fn require_original<W: Work>(
        &self,
        original: &[u8],
        offset: u64,
        parent: &Reader<'_>,
        work: &W,
    ) -> Result<(), Error<S::Error>> {
        self.member.archive().admit(work, self.enclosure())?;
        let at = usize::try_from(offset).map_err(|_| Error::Foreign {
            range: self.enclosure(),
        })?;
        let end = at.checked_add(original.len()).ok_or(Error::Foreign {
            range: self.enclosure(),
        })?;
        if !self.member.session().owns(parent)
            || self
                .bytes
                .get(at..end)
                .is_none_or(|bytes| !core::ptr::eq(bytes, original))
        {
            return Err(Error::Foreign {
                range: self.enclosure(),
            });
        }
        Ok(())
    }
}
