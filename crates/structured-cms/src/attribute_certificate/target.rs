//! Attribute-certificate recipient targeting (RFC5755 §4.3.2 / Appendix B).
//!
//! This predicate is separate from holder authentication, AA trust, revocation
//! and application authorization. A positive answer only establishes targeting
//! for the caller's already-known recipient names or group-membership facts.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-4.3.2>

use super::{IssuerSerial, ObjectDigestInfo, end, issuer_serial, object_digest, sequence, tag};
use crate::signer::required;
use crate::{Error, ErrorCode, Result};
use core::ops::Range;
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_asn1::{Class, Element, Oid, Parser, ScopedReader, Span, Tag};
use structured_pkix::Extension;
use structured_pkix::general_name::{self, GeneralName};

pub(super) const FIELD: &str = "attributeCertificate.targetInformation";

/// `id-ce-targetInformation`, RFC5755 Appendix B.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 55]);

/// One original `Targets` group. Consumers treat all groups as one union.
#[derive(Debug)]
pub struct Group<'a> {
    /// Original SEQUENCE, including an empty group.
    pub element: Element<'a>,
    /// Range in [`TargetInformation::targets`], in original source order.
    pub targets: Range<usize>,
}

/// One original recipient or group assertion.
#[derive(Debug)]
pub struct Target<'a> {
    /// Original context-tagged CHOICE, without retagging.
    pub element: Element<'a>,
    /// Ordinal of its original `Targets` group.
    pub group: usize,
    /// Decoded alternative. It is not an authenticated identity.
    pub value: Value<'a>,
}

/// All ASN.1 alternatives remain inspectable, including the forbidden one.
#[derive(Debug)]
pub enum Value<'a> {
    /// `[0] EXPLICIT GeneralName` (a tagged CHOICE is explicitly wrapped).
    Name(GeneralName<'a>),
    /// `[1] EXPLICIT GeneralName`; membership is supplied by the caller.
    Group(GeneralName<'a>),
    /// Index in [`TargetInformation::certificates`]. RFC5755 forbids its use.
    Certificate(usize),
}

/// Original `TargetCert`, inspectable but never sufficient for a targeting match.
#[derive(Debug)]
pub struct TargetCertificate<'a> {
    /// Ordinal in [`TargetInformation::targets`].
    pub target: usize,
    /// Original `[2] IMPLICIT TargetCert`.
    pub element: Element<'a>,
    /// Certificate assertion, without looking up a certificate.
    pub certificate: IssuerSerial<'a>,
    /// Optional original name.
    pub name: Option<GeneralName<'a>>,
    /// Optional original digest assertion, without hashing an object.
    pub digest: Option<ObjectDigestInfo<'a>>,
}

/// Fully decoded extension, retaining original ranges and independently owned
/// catalogues. The short operation used to read it need not remain alive.
#[derive(Debug)]
pub struct TargetInformation<'a> {
    parser: &'a Parser,
    element: Element<'a>,
    critical: bool,
    groups: OwnedVec<Group<'a>>,
    targets: OwnedVec<Target<'a>>,
    certificates: OwnedVec<TargetCertificate<'a>>,
}

impl<'a> TargetInformation<'a> {
    /// Reads the complete original extension using the shared Extension reader.
    /// All alternatives are decoded before any membership callback can run.
    /// Catalogues and nested Name storage obey source and current work/capacity
    /// admission; no bytes are joined, retagged or re-encoded.
    pub fn read<W: Work>(extension: &Extension<'a>, work: &W) -> Result<Self> {
        let execution = work.execution_for(extension.parser());
        execution
            .charge_work(IDENTIFIER.as_bytes().len() as u64 + 1)
            .map_err(|e| Error::resource(e, FIELD, extension.span().start))?;
        if extension.kind() != IDENTIFIER {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                FIELD,
                extension.span().start,
            ));
        }
        let mut reader = extension
            .reader_scoped(&execution)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = required(&mut reader, FIELD)?;
        tag(&element, sequence(), FIELD)?;
        end(&reader, FIELD)?;
        let mut inside = reader
            .enter(&element)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let mut groups = execution.vector();
        let mut targets = execution.vector();
        let mut certificates = execution.vector();
        while let Some(group) = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?
        {
            tag(&group, sequence(), FIELD)?;
            groups
                .try_reserve(1)
                .map_err(|e| Error::resource(e, FIELD, group.span().start))?;
            let start = targets.len();
            let mut entries = inside
                .enter(&group)
                .map_err(|e| Error::encoding(e, FIELD))?;
            while let Some(entry) = entries
                .next_element()
                .map_err(|e| Error::encoding(e, FIELD))?
            {
                let at = entry.span().start;
                targets
                    .try_reserve(1)
                    .map_err(|e| Error::resource(e, FIELD, at))?;
                let value = if entry.tag() == Tag::context(true, 0)
                    || entry.tag() == Tag::context(true, 1)
                {
                    // RFC5755 Appendix B tags GeneralName, an untagged CHOICE:
                    // its selected name tag remains inside an explicit wrapper.
                    let mut name = entries
                        .enter(&entry)
                        .map_err(|e| Error::encoding(e, FIELD))?;
                    let encoded = required(&mut name, FIELD)?;
                    let decoded =
                        general_name::read(&name, &encoded, FIELD).map_err(Error::pkix)?;
                    end(&name, FIELD)?;
                    if entry.tag() == Tag::context(true, 0) {
                        Value::Name(decoded)
                    } else {
                        Value::Group(decoded)
                    }
                } else if entry.tag() == Tag::context(true, 2) {
                    certificates
                        .try_reserve(1)
                        .map_err(|e| Error::resource(e, FIELD, at))?;
                    let decoded = certificate(&entries, &entry, targets.len())?;
                    let index = certificates.len();
                    certificates
                        .try_push(decoded)
                        .map_err(|e| Error::resource(e, FIELD, at))?;
                    Value::Certificate(index)
                } else {
                    return Err(Error::schema(ErrorCode::UnexpectedTag, FIELD, at));
                };
                targets
                    .try_push(Target {
                        element: entry,
                        group: groups.len(),
                        value,
                    })
                    .map_err(|e| Error::resource(e, FIELD, at))?;
            }
            groups
                .try_push(Group {
                    element: group,
                    targets: start..targets.len(),
                })
                .map_err(|e| Error::resource(e, FIELD, group.span().start))?;
        }
        Ok(Self {
            parser: extension.parser(),
            element,
            critical: extension.is_critical(),
            groups: groups.into_owned(),
            targets: targets.into_owned(),
            certificates: certificates.into_owned(),
        })
    }

    /// Original whole extension value SEQUENCE.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Original extension criticality, not inferred from its identifier.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical
    }
    /// Original groups and their flat target ranges. Traversal by callers must
    /// be admitted by their own current Work; [`Self::check`] does this itself.
    #[must_use]
    pub fn groups(&self) -> &[Group<'a>] {
        &self.groups
    }
    /// Original target order, with no implicit sorting or deduplication.
    #[must_use]
    pub fn targets(&self) -> &[Target<'a>] {
        &self.targets
    }
    /// Typed forbidden alternatives, without treating them as accepted targets.
    #[must_use]
    pub fn certificates(&self) -> &[TargetCertificate<'a>] {
        &self.certificates
    }

    /// Tests recipient targeting only. Names must be already-known identities;
    /// successfully decode untrusted names before supplying them here.
    ///
    /// RFC5755 §4.3.2 requires criticality, prohibits targetCert and treats all
    /// Targets groups as one union. These profile gates run before comparison
    /// or callback effects. A recipient-name match OR confirmed group membership
    /// suffices. Present empty groups match nothing. Other/X.400/EDI recipient
    /// names remain unproven because the shared name core only knows their
    /// encoded identity; their type-specific semantic identity is not inferred.
    /// This is not a complete AC profile check (including `GeneralName` profile
    /// restrictions), holder authentication or an authorization decision.
    ///
    /// `membership` owns group discovery and must admit its own data-dependent
    /// work through the supplied execution. Unknown membership differs from a
    /// completed negative answer. Errors preserve their cause and original
    /// target span; external callback side effects cannot be rolled back.
    pub fn check<W: Work, E>(
        &self,
        recipients: &[GeneralName<'_>],
        work: &W,
        mut membership: impl FnMut(
            &GeneralName<'a>,
            &Execution<'_>,
        ) -> core::result::Result<Membership, E>,
    ) -> core::result::Result<Decision, CheckError<E>> {
        let execution = work.execution_for(self.parser);
        let pay = |at| {
            execution
                .charge_work(1)
                .map_err(|e| CheckError::Processing(Error::resource(e, FIELD, at)))
        };
        pay(self.element.span().start)?;
        if !self.critical {
            return Ok(Decision::NonCritical);
        }
        if let Some(certificate) = self.certificates.first() {
            return Ok(Decision::ProhibitedTargetCertificate {
                target: certificate.target,
            });
        }
        let mut unknown = false;
        for (index, target) in self.targets.iter().enumerate() {
            let at = target.element.span().start;
            pay(at)?;
            match &target.value {
                Value::Name(name) => {
                    if opaque(name) {
                        unknown = true;
                        continue;
                    }
                    for recipient in recipients {
                        pay(at)?;
                        if general_name::matches_at(name, recipient, &execution, at, FIELD)
                            .map_err(|e| CheckError::Processing(Error::pkix(e)))?
                        {
                            return Ok(Decision::Matches { target: index });
                        }
                    }
                }
                Value::Group(name) => {
                    match membership(name, &execution).map_err(|source| CheckError::Callback {
                        target: target.element.span(),
                        source,
                    })? {
                        Membership::Member => return Ok(Decision::Matches { target: index }),
                        Membership::NotMember => {}
                        Membership::Unknown => unknown = true,
                    }
                }
                // All certificate alternatives were indexed during the complete
                // read and rejected above, before any successful short circuit.
                Value::Certificate(_) => unreachable!("certificate preflight"),
            }
        }
        Ok(if unknown {
            Decision::Unproven
        } else {
            Decision::Differs
        })
    }
}

fn opaque(name: &GeneralName<'_>) -> bool {
    matches!(
        name,
        GeneralName::Other { .. } | GeneralName::X400(_) | GeneralName::EdiParty(_)
    )
}

fn certificate<'a>(
    parent: &ScopedReader<'a, '_>,
    element: &Element<'a>,
    target: usize,
) -> Result<TargetCertificate<'a>> {
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let issuer = required(&mut inside, FIELD)?;
    tag(&issuer, sequence(), FIELD)?;
    let certificate = issuer_serial(&inside, &issuer, FIELD)?;
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, FIELD))?;
    let name = if next
        .as_ref()
        .is_some_and(|e| e.tag().class() == Class::ContextSpecific)
    {
        let decoded = general_name::read(&inside, next.as_ref().expect("present name"), FIELD)
            .map_err(Error::pkix)?;
        next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?;
        Some(decoded)
    } else {
        None
    };
    let digest = if let Some(value) = next {
        tag(&value, sequence(), FIELD)?;
        Some(object_digest(&inside, &value, FIELD)?)
    } else {
        None
    };
    end(&inside, FIELD)?;
    Ok(TargetCertificate {
        target,
        element: *element,
        certificate,
        name,
        digest,
    })
}

/// Caller-known group membership. No group is discovered by the format reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// The recipient belongs to the named group.
    Member,
    /// Membership was checked and the recipient is not a member.
    NotMember,
    /// The caller cannot establish whether the recipient belongs to this group.
    Unknown,
}

/// Completed targeting facts, not AA trust or application permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The indicated original target names the recipient or one of its groups.
    Matches {
        /// Original flat target ordinal.
        target: usize,
    },
    /// All target alternatives were checked and none matched.
    Differs,
    /// No match was established, with at least one undecidable name/membership.
    Unproven,
    /// RFC5755 §4.3.2 requires this extension to be critical.
    NonCritical,
    /// RFC5755 §4.3.2 prohibits targetCert, even if another target would match.
    ProhibitedTargetCertificate {
        /// Original flat target ordinal.
        target: usize,
    },
}

/// Terminal processing/callback refusal, never represented as a mismatch.
#[derive(Debug)]
pub enum CheckError<E> {
    /// A source/current-operation resource or shared name processing failure.
    Processing(Error),
    /// The caller's original cause and the original group-target range.
    Callback {
        /// Original group target CHOICE range.
        target: Span,
        /// Original callback error, without conversion.
        source: E,
    },
}
