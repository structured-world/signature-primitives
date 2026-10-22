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
    content_source::{ContentError, Coordinates, SourceMap},
    timestamp::{InfoError, Token},
};

mod index;
mod signing;

/// An original timestamp syntax refusal with independently retained source maps.
#[derive(Debug)]
pub enum ReadError {
    /// Original outer-source or processing refusal.
    Processing(Error),
    /// Original carried-information refusal. The retained map describes the
    /// cause's coordinate system; the physical carrier is an honest enclosure.
    Information(ContentError<InfoError<Infallible>>),
    /// Inspection callback refusal with its independent carried source map.
    /// The coordinate discriminator separates reader-derived locations from
    /// failures retaining findings at an already physical carrier location.
    Inspection {
        /// Unchanged callback cause, including resource refusal.
        source: Error,
        /// Original physical fragments, never a retained temporary join.
        context: SourceMap,
        /// Coordinate system of the callback cause's own offset.
        coordinates: Coordinates,
    },
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
            Self::Inspection { source, .. } => source.is_terminal(),
        }
    }
    /// Original physical failure position or carried-source enclosure start.
    #[must_use]
    pub fn offset(&self) -> u64 {
        match self {
            Self::Processing(cause) => cause.offset(),
            Self::Information(ContentError::Processing(cause)) => cause.offset(),
            Self::Inspection { context, .. }
            | Self::Information(
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
    pub(crate) properties: Option<crate::properties::Properties<'d>>,
}
pub(crate) struct Cache<'m, 'd> {
    pub(crate) models: OwnedVec<Model<'d>>,
    pub(crate) ordinals: OwnedVec<Option<usize>>,
    pub(crate) faults: OwnedVec<(Node, ReadError)>,
    pub(crate) related: Option<OwnedVec<Finding<'m, 'd>>>,
}

pub(super) struct Findings<'a, 'm, 'd, W: Work> {
    pub(super) rows: &'a mut OwnedVec<Finding<'m, 'd>, W>,
    pub(super) work: &'a W,
}
struct Reading<'d> {
    model: Option<Model<'d>>,
    fault: Option<ReadError>,
}

#[expect(
    clippy::result_large_err,
    reason = "retain the original source map without allocating during resource refusal"
)]
fn read_one<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    ordinal: usize,
    entry: &Timestamp<'d>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<Reading<'d>, ReadError> {
    let at = entry.property.span().start;
    let cause = if let Some(source) = entry.value {
        let mut reader = source.reader_in(parent)?;
        match Token::read_from(&mut reader) {
            Ok(token) => {
                let properties =
                    if crate::properties::Properties::has_legacy_values(token.signer(), &reader)? {
                        // The shared property reader retains AnnexA cardinality
                        // faults too, before skipping an unreadable value.
                        // Timestamp signers must not rely on root-only rules.
                        let properties =
                            crate::properties::Properties::read(token.signer(), &reader)?;
                        super::property_findings(document, &properties, &reader, findings)?;
                        Some(properties)
                    } else {
                        None
                    };
                let fault = if let Err(cause) = inspect(document, entry, &token, &reader, findings)
                {
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
                    Some(ReadError::Information(source))
                } else {
                    None
                };
                return Ok(Reading {
                    model: Some(Model {
                        ordinal,
                        token,
                        properties,
                    }),
                    fault,
                });
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
                ReadError::from(cause)
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
        ReadError::from(cause)
    };
    Ok(Reading {
        model: None,
        fault: Some(cause),
    })
}

#[expect(
    clippy::result_large_err,
    reason = "retain the original information refusal and source map without allocating while refusing resources"
)]
pub(super) fn read<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    timestamps: &[Timestamp<'d>],
    root: Node,
    counters: &OwnedMap<Node, usize, impl Work>,
    parent: &Reader<'d>,
    findings: Findings<'_, 'm, 'd, W>,
) -> Result<Cache<'m, 'd>, ReadError> {
    let Findings {
        rows: findings,
        work: findings_work,
    } = findings;
    let work = parent.execution();
    let mut models = work.vector();
    let mut ordinals = work.vector();
    let mut faults = work.vector();
    let mut related = None;
    ordinals
        .try_reserve_exact(timestamps.len())
        .map_err(|cause| {
            Error::resource(cause, "cades.timestamp", document.message().span().start)
        })?;
    for (ordinal, entry) in timestamps.iter().enumerate() {
        let at = entry.property.span().start;
        let resource = |cause| Error::resource(cause, "cades.timestamp", at);
        work.charge_work(1).map_err(resource)?;
        let selected_owner = entry.owner == root
            || counters
                .get(&entry.owner, &work)
                .map_err(resource)?
                .is_some();
        // Other roots' preservation findings stay visible without becoming
        // this selected root's B-B syntax. Their actual tokens STILL enter
        // the complete historical TSA census and must independently validate.
        let entry_findings = if selected_owner {
            &mut *findings
        } else {
            related.get_or_insert_with(|| findings_work.vector())
        };
        let reading = read_one(document, ordinal, entry, parent, entry_findings)?;
        if let Some(fault) = reading.fault {
            faults.try_push((entry.property, fault)).map_err(resource)?;
        }
        let selected = if let Some(model) = reading.model {
            let index = models.len();
            models.try_push(model).map_err(resource)?;
            Some(index)
        } else {
            None
        };
        ordinals.try_push(selected).map_err(resource)?;
    }
    Ok(Cache {
        models: models.into_owned(),
        ordinals: ordinals.into_owned(),
        faults: faults.into_owned(),
        related: related
            .filter(|rows| !rows.is_empty())
            .map(OwnedVec::into_owned),
    })
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
    let index_algorithm = {
        let signing_fields = signing::read(document, entry, token, reader, findings)?;
        index::read(document, entry, token, &signing_fields, reader, findings)?
    };
    // ESS/index catalogues are temporary inspection scratch. Release their
    // capacity before opening potentially fragmented carried information.
    // The envelope model is retained once. A subsequent cryptographic check
    // opens information under CURRENT work: temporary joined TSTInfo cannot
    // be pinned in this cache. Its faults use a physical attribute enclosure,
    // never a logical offset disguised as an original document position.
    let inspection = token.with_info(reader, |info, inside, _| {
        if let structured_cms::timestamp::HashAlgorithmReading::Identifier(algorithm) =
            info.imprint().algorithm()
        {
            let imprint = signing::digest(
                document,
                entry.property.span(),
                algorithm,
                Some(info.imprint().hashed().len()),
                "tstInfo.messageImprint.hashedMessage",
                inside,
                findings,
            )?;
            if let Some((structured_asn1::digest::Resolution::Supported(index), span)) =
                &index_algorithm
                && let structured_asn1::digest::Resolution::Supported(imprint) = imprint
            {
                reader.charge(1).map_err(|cause| {
                    signing::InspectionError::Physical(Error::encoding(
                        cause,
                        "cades.archive.index",
                    ))
                })?;
                if *index != imprint {
                    finding(
                        document,
                        *span,
                        Severity::Required,
                        Rule::ArchiveAlgorithm,
                        findings,
                    )
                    .map_err(signing::InspectionError::Physical)?;
                }
            }
        }
        for cause in token
            .faults()
            .iter()
            .chain(token.message().faults())
            .chain(token.signer().faults())
            .chain(info.faults())
        {
            reader.charge(1).map_err(|cause| {
                signing::InspectionError::Physical(Error::encoding(cause, "cades.timestamp"))
            })?;
            finding(
                document,
                entry.property.span(),
                Severity::Required,
                Rule::Schema {
                    code: cause.code(),
                    field: cause.field(),
                },
                findings,
            )
            .map_err(signing::InspectionError::Physical)?;
        }
        Ok::<_, signing::InspectionError>(())
    });
    let source = match inspection {
        Ok(()) => return Ok(()),
        Err(ContentError::Callback {
            source: InfoError::Callback(cause),
            context,
        }) => {
            let coordinates = match &cause {
                signing::InspectionError::Reader(_) => context.coordinates(),
                signing::InspectionError::Physical(_) => Coordinates::Original,
            };
            return Err(ReadError::Inspection {
                source: cause.into_source(),
                context,
                coordinates,
            });
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
