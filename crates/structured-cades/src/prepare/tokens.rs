//! One original timestamp envelope reading shared by preparation and material.

use super::{Finding, Rule, Severity, Timestamp, finding};
use crate::{
    Error,
    source::{Document, Node},
};
use core::convert::Infallible;
use structured_asn1::{
    Reader,
    memory::{OwnedMap, OwnedVec, Work},
};
use structured_cms::{
    content_source::ContentError,
    timestamp::{InfoError, Token},
};

/// An original timestamp syntax refusal with independently retained source maps.
#[derive(Debug)]
pub enum ReadError {
    /// Original outer-source or processing refusal.
    Processing(Error),
    /// Original carried-information refusal. The retained map describes the
    /// cause's coordinate system; the physical carrier is an honest enclosure.
    Information(ContentError<InfoError<Infallible>>),
}
impl From<Error> for ReadError {
    fn from(cause: Error) -> Self {
        Self::Processing(cause)
    }
}
impl From<structured_cms::Error> for ReadError {
    fn from(cause: structured_cms::Error) -> Self {
        Self::Processing(Error::Cms(cause))
    }
}
impl ReadError {
    /// Resource/source misuse aborts preparation rather than becoming a finding.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Processing(cause) => cause.is_terminal(),
            Self::Information(cause) => information_cause(cause).is_terminal(),
        }
    }
    /// Original physical failure position or carried-source enclosure start.
    #[must_use]
    pub fn offset(&self) -> u64 {
        match self {
            Self::Processing(cause) => cause.offset(),
            Self::Information(ContentError::Processing(cause)) => cause.offset(),
            Self::Information(
                ContentError::Decoding { context, .. } | ContentError::Callback { context, .. },
            ) => context.carrier().start,
        }
    }
}
fn information_cause(cause: &ContentError<InfoError<Infallible>>) -> &structured_cms::Error {
    match cause {
        ContentError::Processing(cause)
        | ContentError::Decoding { source: cause, .. }
        | ContentError::Callback {
            source: InfoError::Processing(cause),
            ..
        } => cause,
        ContentError::Callback {
            source: InfoError::Callback(never),
            ..
        } => match *never {},
    }
}
pub(crate) struct Model<'d> {
    pub(crate) ordinal: usize,
    pub(crate) token: Token<'d>,
}
pub(crate) struct Cache<'d> {
    pub(crate) models: OwnedVec<Model<'d>>,
    pub(crate) ordinals: OwnedVec<Option<usize>>,
    pub(crate) faults: OwnedVec<(Node, ReadError)>,
}

#[expect(
    clippy::result_large_err,
    reason = "retain the original information refusal and source map without allocating while refusing resources"
)]
pub(super) fn read<'m, 'd>(
    document: &Document<'m, 'd>,
    timestamps: &[Timestamp<'d>],
    preservation: &[crate::preservation::Required<'d>],
    root: Node,
    counters: &OwnedMap<Node, usize, impl Work>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<Cache<'d>, ReadError> {
    let work = parent.execution();
    let mut models = work.vector();
    let mut ordinals = work.vector();
    let mut faults = work.vector();
    ordinals
        .try_reserve_exact(timestamps.len())
        .map_err(|cause| {
            Error::resource(cause, "cades.timestamp", document.message().span().start)
        })?;
    for (ordinal, entry) in timestamps.iter().enumerate() {
        let at = entry.property.span().start;
        let resource = |cause| Error::resource(cause, "cades.timestamp", at);
        work.charge_work(1).map_err(resource)?;
        let mut selected = None;
        if let Some(source) = entry.value {
            let mut reader = source.reader_in(parent)?;
            match Token::read_from(&mut reader) {
                Ok(token) => {
                    if let Err(cause) = inspect(document, entry, &token, &reader, findings) {
                        if cause.is_terminal() {
                            return Err(cause);
                        }
                        let ReadError::Information(source) = cause else {
                            return Err(cause);
                        };
                        finding(
                            document,
                            entry.property.span(),
                            Severity::Required,
                            Rule::Schema {
                                code: information_cause(&source).code(),
                                field: information_cause(&source).field(),
                            },
                            findings,
                        )?;
                        faults
                            .try_push((entry.property, ReadError::Information(source)))
                            .map_err(resource)?;
                    }
                    selected = Some(models.len());
                    models
                        .try_push(Model { ordinal, token })
                        .map_err(resource)?;
                }
                Err(cause) => {
                    if cause.is_terminal() {
                        return Err(cause.into());
                    }
                    finding(
                        document,
                        entry.property.span(),
                        Severity::Required,
                        Rule::Schema {
                            code: cause.code(),
                            field: cause.field(),
                        },
                        findings,
                    )?;
                    faults
                        .try_push((entry.property, ReadError::from(cause)))
                        .map_err(resource)?;
                }
            }
        } else {
            let cause = Error::Syntax {
                code: structured_cms::ErrorCode::MissingField,
                field: "cades.timestamp",
                at,
            };
            finding(
                document,
                entry.property.span(),
                Severity::Required,
                Rule::Schema {
                    code: structured_cms::ErrorCode::MissingField,
                    field: "cades.timestamp",
                },
                findings,
            )?;
            faults
                .try_push((entry.property, ReadError::from(cause)))
                .map_err(resource)?;
        }
        ordinals.try_push(selected).map_err(resource)?;
    }
    inspect_references(
        document,
        preservation,
        root,
        counters,
        parent,
        findings,
        &mut faults,
    )?;
    Ok(Cache {
        models: models.into_owned(),
        ordinals: ordinals.into_owned(),
        faults: faults.into_owned(),
    })
}

#[expect(
    clippy::result_large_err,
    reason = "retain original carried-information failures and source maps without allocating during refusal"
)]
fn inspect_references<'m, 'd>(
    document: &Document<'m, 'd>,
    required: &[crate::preservation::Required<'d>],
    root: Node,
    counters: &OwnedMap<Node, usize, impl Work>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
    faults: &mut OwnedVec<(Node, ReadError), impl Work>,
) -> Result<(), ReadError> {
    let work = parent.execution();
    for requirement in required {
        let at = requirement.property.span().start;
        let resource = |cause| Error::resource(cause, "cades.legacy.timestamp", at);
        work.charge_work(1).map_err(resource)?;
        if !requirement.kind.is_reference_timestamp() {
            continue;
        }
        // Other parallel roots remain preservation obligations. Their optional
        // values do not change the selected root's B-B syntax assessment.
        if requirement.signature != root
            && counters
                .get(&requirement.signature, &work)
                .map_err(resource)?
                .is_none()
        {
            continue;
        }
        let entry = Timestamp {
            owner: requirement.signature,
            property: requirement.property,
            value: requirement.value,
            purpose: structured_ltv::timestamp::Purpose::ValidationData,
        };
        let Some(source) = entry.value else {
            finding(
                document,
                entry.property.span(),
                Severity::Required,
                Rule::Schema {
                    code: structured_cms::ErrorCode::MissingField,
                    field: "cades.legacy.timestamp",
                },
                findings,
            )?;
            faults
                .try_push((
                    entry.property,
                    Error::Syntax {
                        code: structured_cms::ErrorCode::MissingField,
                        field: "cades.legacy.timestamp",
                        at,
                    }
                    .into(),
                ))
                .map_err(resource)?;
            continue;
        };
        let mut reader = source.reader_in(parent)?;
        let token = match Token::read_from(&mut reader) {
            Ok(token) => token,
            Err(cause) => {
                if cause.is_terminal() {
                    return Err(cause.into());
                }
                finding(
                    document,
                    entry.property.span(),
                    Severity::Required,
                    Rule::Schema {
                        code: cause.code(),
                        field: cause.field(),
                    },
                    findings,
                )?;
                faults
                    .try_push((entry.property, cause.into()))
                    .map_err(resource)?;
                continue;
            }
        };
        if let Err(cause) = inspect(document, &entry, &token, &reader, findings) {
            if cause.is_terminal() {
                return Err(cause);
            }
            let ReadError::Information(source) = cause else {
                return Err(cause);
            };
            finding(
                document,
                entry.property.span(),
                Severity::Required,
                Rule::Schema {
                    code: information_cause(&source).code(),
                    field: information_cause(&source).field(),
                },
                findings,
            )?;
            faults
                .try_push((entry.property, ReadError::Information(source)))
                .map_err(resource)?;
        }
        // Syntax only: an AnnexA reference proof needs its own historical
        // coverage processor. Never mint a modern token/actor from this read.
    }
    Ok(())
}

#[expect(
    clippy::result_large_err,
    reason = "retain the original information refusal and source map without allocating while refusing resources"
)]
fn inspect<'m, 'd>(
    document: &Document<'m, 'd>,
    entry: &Timestamp<'d>,
    token: &Token<'d>,
    reader: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, impl Work>,
) -> Result<(), ReadError> {
    let md5 = structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
    let digest = token.signer().digest_algorithm();
    reader
        .charge(
            1 + digest
                .algorithm()
                .as_bytes()
                .len()
                .min(md5.as_bytes().len()) as u64,
        )
        .map_err(|cause| Error::encoding(cause, "cades.timestamp"))?;
    // EN319122-1 §6.2.1 applies even when only B-B was requested and no
    // timestamp math will run. Inspect actual use, before opening TSTInfo;
    // a malformed information value cannot hide the envelope's digest.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    if digest.algorithm() == md5 {
        finding(
            document,
            entry.property.span(),
            Severity::Required,
            Rule::Md5,
            findings,
        )?;
    }
    // The envelope model is retained once. A subsequent cryptographic check
    // opens information under CURRENT work: temporary joined TSTInfo cannot
    // be pinned in this cache. Its faults use a physical attribute enclosure,
    // never a logical offset disguised as an original document position.
    let inspection = token.with_info(reader, |info, inside, _| {
        if let structured_cms::timestamp::HashAlgorithmReading::Identifier(algorithm) =
            info.imprint().algorithm()
        {
            inside
                .charge(
                    1 + algorithm
                        .algorithm()
                        .as_bytes()
                        .len()
                        .min(md5.as_bytes().len()) as u64,
                )
                .map_err(|cause| Error::encoding(cause, "cades.timestamp"))?;
            if algorithm.algorithm() == md5 {
                // The original physical carrier is the location here, not an
                // inner logical offset mislabeled as a document position.
                finding(
                    document,
                    entry.property.span(),
                    Severity::Required,
                    Rule::Md5,
                    findings,
                )?;
            }
        }
        for cause in token
            .faults()
            .iter()
            .chain(token.message().faults())
            .chain(token.signer().faults())
            .chain(info.faults())
        {
            reader
                .charge(1)
                .map_err(|cause| Error::encoding(cause, "cades.timestamp"))?;
            finding(
                document,
                entry.property.span(),
                Severity::Required,
                Rule::Schema {
                    code: cause.code(),
                    field: cause.field(),
                },
                findings,
            )?;
        }
        Ok::<_, Error>(())
    });
    let source = match inspection {
        Ok(()) => return Ok(()),
        Err(ContentError::Callback {
            source: InfoError::Callback(cause),
            ..
        }) => {
            return Err(cause.into());
        }
        Err(ContentError::Processing(cause)) => ContentError::Processing(cause),
        Err(ContentError::Decoding { source, context }) => {
            ContentError::Decoding { source, context }
        }
        Err(ContentError::Callback {
            source: InfoError::Processing(source),
            context,
        }) => ContentError::Callback {
            source: InfoError::Processing(source),
            context,
        },
    };
    Err(ReadError::Information(source))
}
