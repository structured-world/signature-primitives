//! Timestamp CMS envelope and scoped original `TSTInfo` inspection.

use super::{TokenInfo, record};
use crate::content_source::{ContentError, SourceMap};
use crate::{ContentInfo, Error, ErrorCode, Result, SignedData, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Encoding, Parser, Reader, Tag, universal};

/// Timestamp envelope; reading does not establish signature, trust or chronology.
///
/// The original signed message stays borrowed. `TSTInfo` is read through a scoped
/// callback so BER joins cannot produce dangling borrowed models or require a
/// self-referential owned container. Independently retained results are explicit.
#[derive(Debug)]
pub struct Token<'a> {
    message: SignedData<'a>,
    faults: OwnedVec<Error>,
}

/// Failure inside the explicitly identified carried-content source.
#[derive(Debug)]
pub enum InfoError<E> {
    /// Located `TSTInfo` processing failure, using the supplied source coordinates.
    Processing(Error),
    /// The caller's unchanged error from its inspection/verification operation.
    Callback(E),
}

impl<'a> Token<'a> {
    /// Reads the complete timestamp CMS envelope using the original parser.
    /// The attached `TSTInfo` bytes are inspected by [`Self::with_info`].
    pub fn read(parser: &'a Parser, document: &'a [u8], base: u64) -> Result<Self> {
        let mut root = parser
            .read(document, base)
            .map_err(|error| Error::encoding(error, "contentInfo"))?;
        let (envelope, parent) = ContentInfo::read(&mut root)?;
        parent
            .execution()
            .charge_work(envelope.kind().as_bytes().len() as u64)
            .map_err(|reason| {
                Error::resource(reason, "contentInfo.contentType", envelope.span().start)
            })?;
        if envelope.kind() != oid::SIGNED_DATA {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                "contentInfo.contentType",
                envelope.span().start,
            ));
        }
        let message = SignedData::read_element(&parent, envelope.content())?;
        Self::from_message(message, &parent)
    }

    /// Applies timestamp envelope rules to an already decoded signed message.
    ///
    /// RFC3161 §2.4.2 requires attached `TSTInfo` and only the TSA signature.
    /// Inspection recovery of equal parsed signers is explicitly nonconforming:
    /// retain the first original encoding and one `ExtraSignature` fault. The
    /// common narrow comparer ignores BER container spellings, preserves exact
    /// signedAttrs and opaque field identity, and never rewrites signed bytes.
    /// Conflicting signer values refuse; this is not a trust/provider selector.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
    pub fn from_message(message: SignedData<'a>, parent: &Reader<'a>) -> Result<Self> {
        let field = "signedData.signerInfos";
        let first = message
            .signers()
            .first()
            .ok_or_else(|| Error::schema(ErrorCode::SignerCount, field, message.span().start))?;
        first.require_session(parent, field)?;
        let execution = parent.execution();
        let mut faults = execution.vector();
        let mut duplicate = None;
        for extra in &message.signers()[1..] {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, field, extra.span().start))?;
            if !first.same_value(extra, parent)? {
                return Err(Error::schema(
                    ErrorCode::SignerCount,
                    field,
                    extra.span().start,
                ));
            }
            duplicate.get_or_insert(extra.span().start);
        }
        if let Some(at) = duplicate {
            record(
                &mut faults,
                Error::schema(ErrorCode::ExtraSignature, field, at),
            )?;
        }
        record_counters(first, parent, &mut faults)?;
        let content = message.content();
        execution
            .charge_work(content.kind().as_bytes().len() as u64)
            .map_err(|reason| {
                Error::resource(
                    reason,
                    "signedData.encapContentInfo.eContentType",
                    content.span().start,
                )
            })?;
        if content.kind() != oid::TST_INFO {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                "signedData.encapContentInfo.eContentType",
                content.span().start,
            ));
        }
        if content.content().is_none() {
            return Err(Error::schema(
                ErrorCode::DetachedContent,
                "signedData.encapContentInfo.eContent",
                content.span().start,
            ));
        }
        Ok(Self {
            message,
            faults: faults.into_owned(),
        })
    }

    /// Original signed message, including unmodified signed attribute ranges.
    #[must_use]
    pub fn message(&self) -> &SignedData<'a> {
        &self.message
    }

    /// The first original TSA signer, after nonempty/unique-reading admission.
    #[must_use]
    pub fn signer(&self) -> &crate::signer::SignerInfo<'a> {
        &self.message.signers()[0]
    }

    /// Additional envelope diagnostics, separate from CMS and `TSTInfo` faults.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }

    /// Reads the complete attached `TSTInfo` in a callback with honest provenance.
    ///
    /// Owned output/error types cannot borrow temporary joins. Located errors
    /// use the provided map's coordinates; that map is retained with every inner
    /// error. The caller chooses verification/trust/request context, and admits
    /// explicit independent proof data before leaving the callback.
    #[expect(
        clippy::result_large_err,
        reason = "preserve both original cause and accounted source context without allocating an error envelope"
    )]
    pub fn with_info<R, E>(
        &self,
        parent: &Reader<'_>,
        callback: impl for<'scope> FnOnce(
            &TokenInfo<'scope>,
            &Reader<'scope>,
            &SourceMap,
        ) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<InfoError<E>>> {
        self.inspect(parent, None, callback)
    }

    /// Inspects a token decoded inside another scoped content source.
    ///
    /// The parent map is composed before inspection. Errors retain physical
    /// range metadata independently of both joined buffers; the original
    /// parser depth and operation budgets still govern the nested reader.
    #[expect(
        clippy::result_large_err,
        reason = "retain original cause and accounted physical source context"
    )]
    pub fn with_info_mapped<R, E>(
        &self,
        parent: &Reader<'_>,
        source: &SourceMap,
        callback: impl for<'scope> FnOnce(
            &TokenInfo<'scope>,
            &Reader<'scope>,
            &SourceMap,
        ) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<InfoError<E>>> {
        self.inspect(parent, Some(source), callback)
    }

    #[expect(
        clippy::result_large_err,
        reason = "retain original cause and accounted physical source context"
    )]
    fn inspect<R, E>(
        &self,
        parent: &Reader<'_>,
        source: Option<&SourceMap>,
        callback: impl for<'scope> FnOnce(
            &TokenInfo<'scope>,
            &Reader<'scope>,
            &SourceMap,
        ) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<InfoError<E>>> {
        let Some(content) = self.message.content().content() else {
            return Err(ContentError::Processing(Error::schema(
                ErrorCode::DetachedContent,
                "signedData.encapContentInfo.eContent",
                self.message.content().span().start,
            )));
        };
        let decode = |reader: &mut Reader<'_>, context: &SourceMap| {
            let element = reader
                .expect(Tag::constructed(universal::SEQUENCE))
                .map_err(|error| InfoError::Processing(Error::encoding(error, "tstInfo")))?;
            let info = TokenInfo::read(reader, &element).map_err(InfoError::Processing)?;
            if !reader.is_empty() {
                return Err(InfoError::Processing(Error::schema(
                    ErrorCode::TrailingData,
                    "tstInfo",
                    reader.offset(),
                )));
            }
            callback(&info, reader, context).map_err(InfoError::Callback)
        };
        match source {
            Some(source) => {
                content.with_nested_reader_mapped(parent, source, Encoding::Ber, "tstInfo", decode)
            }
            None => content.with_nested_reader(parent, Encoding::Ber, "tstInfo", decode),
        }
    }
}

fn record_counters<W: Work>(
    signer: &crate::signer::SignerInfo<'_>,
    parent: &Reader<'_>,
    faults: &mut OwnedVec<Error, W>,
) -> Result<()> {
    // RFC3161 §2.4.2 forbids signatures other than the TSA's. This presence
    // check is separate from the legal unsigned countersignature walker:
    // known OID plus unreadable/empty values or signed placement still counts.
    // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
    for (attributes, field) in [
        (
            signer.signed_attributes(),
            "signerInfo.signedAttrs.countersignature",
        ),
        (
            signer.unsigned_attributes(),
            "signerInfo.unsignedAttrs.countersignature",
        ),
    ] {
        let Some(attributes) = attributes else {
            continue;
        };
        for attribute in attributes.all_in(oid::COUNTERSIGNATURE, parent) {
            let attribute = attribute?;
            record(
                faults,
                Error::schema(ErrorCode::ExtraSignature, field, attribute.span().start),
            )?;
        }
    }
    Ok(())
}
