//! Parsed retained DSS items and the existing exact-artifact index.

use super::{Decoded, MaterialError, Validation};
use crate::{
    error::{Error, ErrorKind},
    model::admit,
    signature::Signature,
    timestamp::{ISSUER, Node, Pades},
};
use structured_asn1::memory::{Execution, Memory, OwnedVec, Work};
use structured_ltv::{
    material::{ArtifactRef, ArtifactSource, Index, IndexError, Occurrence},
    source::{Location, Query},
};

/// Original parsed value, without authentication or a successful status claim.
pub enum Value<'a> {
    /// Actual X.509 certificate.
    Certificate(structured_pkix::Certificate<'a>),
    /// Actual complete or delta `CertificateList`.
    Crl(structured_pkix::crl::CertificateList<'a>),
    /// Original whole OCSP envelope and its known basic payload, if available.
    Ocsp {
        /// Whole original response, retaining protocol failures independently.
        envelope: structured_pkix::ocsp::Response<'a>,
        /// Parsed original known payload; absent is not a successful status.
        basic: Result<Option<structured_pkix::ocsp::BasicResponse<'a>>, structured_pkix::Error>,
    },
    /// Actual optional VRI time-stamp token.
    Timestamp(TimestampValue<'a>),
    /// Original whole value was unreadable; raw bytes/placement remain owned
    /// by Validation and the located cause is not converted to absence.
    Unreadable(MaterialError),
}
/// Once-read VRI TS envelope and its actual carried revocation choices.
pub struct TimestampValue<'a> {
    pub(crate) token: structured_cms::timestamp::Token<'a>,
    pub(crate) revocations: OwnedVec<crate::timestamp::sources::Revocation<'a>>,
}
impl<'a> TimestampValue<'a> {
    /// Original parsed envelope, without replaying the TS stream.
    #[must_use]
    pub fn token(&self) -> &structured_cms::timestamp::Token<'a> {
        &self.token
    }
}

/// One actual DSS occurrence's historical placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Historical revision selecting the original stream definition.
    Dss {
        /// Historical revision in which the source was visible.
        revision: usize,
        /// Ordinal in the same owning Validation item pool.
        item: usize,
    },
    /// Unchanged inner CMS location, projected only at its PDF enclosure.
    Cms(structured_cades::material::Placement),
    /// Actual certificate/revocation choice of a PDF document timestamp.
    DocumentTimestamp {
        /// Original PDF timestamp occurrence, including earlier failed slots.
        timestamp: usize,
        /// Original certificate or revocation CHOICE ordinal.
        choice: TokenChoice,
    },
    /// Material carried by an actual VRI TS in this historical DSS window.
    VriTimestamp {
        /// Original historical DSS revision.
        revision: usize,
        /// Original VRI dictionary ordinal in that window.
        vri: usize,
        /// Original certificate or revocation choice in the TS envelope.
        choice: TokenChoice,
    },
}

/// CMS CHOICE role inside one original PDF document timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenChoice {
    /// Original certificate CHOICE index, not the normalized X.509 catalogue.
    Certificate(usize),
    /// Original revocation CHOICE index.
    Revocation(usize),
}

/// One parse of every retained material stream. Models borrow the actual
/// Validation owner; no second DER grammar or copied certificate is introduced.
pub struct Parsed<'v, 's, D, G> {
    pub(super) owner: &'v Validation<'s, D, G>,
    pub(super) values: OwnedVec<Value<'v>, Memory>,
    readable: bool,
}

/// Existing exact identity/occurrence mechanism in the original PDF domain.
pub type MaterialIndex<'v, D, G, W> = Index<'v, Node, D, G, Placement, (), W, Pades>;

impl<'s, D: Copy + Eq, G: Copy + Eq> Validation<'s, D, G> {
    /// Parses every value once under the actual current/original execution.
    /// Protocol OCSP failures and unknown response syntaxes remain distinct
    /// retained values and never become a fabricated basic response.
    #[expect(
        clippy::result_large_err,
        reason = "a terminal inner diagnostic retains its actual encoded material enclosure without allocating on the refusal path"
    )]
    pub fn parse<'v, W: Work + 'v>(
        &'v self,
        operation: &'v W,
    ) -> Result<Parsed<'v, 's, D, G>, super::MaterialFailure> {
        let execution = self.session.query(operation);
        let mut values = execution.vector();
        let mut readable = true;
        for item in &self.items {
            let located = |cause| super::MaterialFailure {
                location: item.location,
                cause,
            };
            let work = item.session.query(operation);
            admit(&work, item.location, 1).map_err(|cause| located(MaterialError::Pdf(cause)))?;
            let (value, reader) = match item.read(&work) {
                Ok(value) => value,
                Err(cause) if cause.is_terminal() => return Err(located(cause)),
                Err(cause) => {
                    readable = false;
                    values.try_push(Value::Unreadable(cause)).map_err(|cause| {
                        located(MaterialError::Pdf(Error {
                            kind: ErrorKind::Resource(cause),
                            location: item.location,
                        }))
                    })?;
                    continue;
                }
            };
            let value = match value {
                Decoded::Certificate(value) => Value::Certificate(value),
                Decoded::Crl(value) => Value::Crl(value),
                Decoded::Ocsp(envelope) => {
                    let basic =
                        if let structured_pkix::ocsp::Response::Successful(value) = &envelope {
                            match value.basic_in(&reader) {
                                Ok(value) => Ok(value),
                                Err(cause)
                                    if cause.is_resource()
                                        || cause.code()
                                            == structured_pkix::ErrorCode::ForeignReader =>
                                {
                                    return Err(located(MaterialError::Pkix(cause)));
                                }
                                Err(cause) => {
                                    readable = false;
                                    Err(cause)
                                }
                            }
                        } else {
                            Ok(None)
                        };
                    Value::Ocsp { envelope, basic }
                }
                Decoded::Timestamp(token) => {
                    let revocations = crate::timestamp::sources::read_revocations(
                        &token,
                        &reader,
                        &work,
                        item.location,
                    )
                    .map_err(|cause| match cause {
                        crate::timestamp::sources::RevocationError::Pdf(cause) => {
                            MaterialError::Pdf(cause)
                        }
                        crate::timestamp::sources::RevocationError::Cms(cause) => {
                            MaterialError::Cms(cause)
                        }
                        crate::timestamp::sources::RevocationError::Pkix(cause) => {
                            MaterialError::Pkix(cause)
                        }
                    })
                    .map_err(located)?;
                    Value::Timestamp(TimestampValue { token, revocations })
                }
            };
            values.try_push(value).map_err(|cause| {
                located(MaterialError::Pdf(Error {
                    kind: ErrorKind::Resource(cause),
                    location: item.location,
                }))
            })?;
        }
        Ok(Parsed {
            owner: self,
            values: values.into_owned(),
            readable,
        })
    }
}

impl<'v, D: Copy + Eq, G: Copy + Eq> Parsed<'v, '_, D, G> {
    /// Historical VRI inclusion independently of individual value syntax.
    #[must_use]
    pub fn all_vri_material_in_dss(&self) -> bool {
        self.owner.all_vri_material_in_dss()
    }
    /// All parsed values in the immutable owning Validation item order.
    #[must_use]
    pub fn values(&self) -> &[Value<'v>] {
        &self.values
    }
    /// Every known whole value and basic OCSP body was readable. This is
    /// independent of successful wire status, authentication or freshness.
    #[must_use]
    pub fn all_values_readable(&self) -> bool {
        self.readable
    }

    /// Builds the common index from actual original occurrences, preserving
    /// the whole OCSP envelope and its independently parsed basic payload.
    pub fn index<'q, 'operation, S: crate::range::RangeSource<Document = D, Generation = G>>(
        &'q self,
        signature: Signature<'_, '_, D, G>,
        query: &crate::query::Query<'operation, '_, S>,
    ) -> Result<MaterialIndex<'q, D, G, Execution<'operation>>, IndexError<Node>>
    where
        'v: 'q,
    {
        let source = signature.owner();
        let root = Node::of(signature.location());
        if !core::ptr::eq(source.value.session, self.owner.session)
            || !query.belongs(self.owner.session)
            || source.value.stamp != self.owner.stamp
            || query.snapshot() != self.owner.stamp.snapshot
        {
            return Err(IndexError::Foreign { signature: root });
        }
        let mut index = Index::new(ISSUER, root, &[], query)?;
        let mut ordinal = 0;
        self.append(&mut index, &mut ordinal, query)?;
        Ok(index)
    }

    pub(super) fn append<'q, Q, O>(
        &'q self,
        index: &mut Index<'q, Node, D, G, Placement, O, Q::Work, Pades>,
        ordinal: &mut usize,
        query: &Q,
    ) -> Result<(), IndexError<Node>>
    where
        Q: Query<Id = Node, Document = D, Generation = G>,
        'v: 'q,
    {
        if query.snapshot() != self.owner.stamp.snapshot {
            return Err(IndexError::Foreign {
                signature: index.signature(),
            });
        }
        for (item_ordinal, value) in self.values.iter().enumerate() {
            index.admit(query)?;
            let item = &self.owner.items[item_ordinal];
            let artifact = match value {
                Value::Certificate(value) => Some(ArtifactRef::Certificate(value)),
                Value::Crl(value) => Some(ArtifactRef::Crl(value)),
                Value::Ocsp {
                    basic: Ok(Some(value)),
                    ..
                } => Some(ArtifactRef::Ocsp(value)),
                Value::Ocsp {
                    basic: Ok(None) | Err(_),
                    ..
                }
                | Value::Timestamp(_)
                | Value::Unreadable(_) => None,
            };
            if let Some(artifact) = artifact {
                index.insert(
                    ISSUER,
                    artifact,
                    Occurrence::new(
                        ArtifactSource::Material(*ordinal),
                        Location {
                            snapshot: self.owner.stamp.snapshot,
                            node: Node::dss(item.location, self.owner.revision),
                        },
                        Placement::Dss {
                            revision: self.owner.revision,
                            item: item_ordinal,
                        },
                    ),
                    query,
                )?;
                *ordinal = ordinal.checked_add(1).ok_or(IndexError::Resource {
                    signature: index.signature(),
                    cause: structured_asn1::memory::MemoryError::CapacityOverflow,
                })?;
            }
        }
        Ok(())
    }
}
