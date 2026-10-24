//! File-layout requirements, separate from content, coverage and attained level.

use super::{Census, Role};
use crate::{
    error::{Error, resource},
    zip::{FaultKind, MemberId},
};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::RangeSource,
};

/// One principal file format for a simple container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The original `META-INF/signature.p7s` file.
    Cades,
    /// The original `META-INF/signatures.xml` file.
    Xades,
    /// The original `META-INF/timestamp.tst` file.
    Timestamp,
    /// The original `META-INF/evidencerecord.ers` file.
    Evidence,
    /// XMLERS is retained as a distinct format, without an implemented engine.
    XmlEvidence,
}
impl Principal {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Cades => b"META-INF/signature.p7s",
            Self::Xades => b"META-INF/signatures.xml",
            Self::Timestamp => b"META-INF/timestamp.tst",
            Self::Evidence => b"META-INF/evidencerecord.ers",
            Self::XmlEvidence => b"META-INF/evidencerecord.xml",
        }
    }
}

/// Explicit format being assessed, never inferred as an acceptance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// One original root data file and one principal file.
    Simple(Principal),
    /// Extended container using XML signature files and optional evidence records.
    ExtendedXades,
    /// Extended container using `CAdES` signatures and/or time assertions.
    ExtendedCadesAndAssertions,
}

/// Normative rule set. Signature levels remain separate common stage reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// EN319162-1 clause4 syntax and layout.
    General,
    /// EN319162-1 clause5, only its defined S-signature/E-XAdES routes.
    BaselinePart1,
    /// EN319162-2 additional-container requirements, composed with clause4.
    AdditionalPart2,
}

/// A recommendation is preserved without turning SHOULD into SHALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// A required layout condition is not satisfied.
    Required,
    /// A normative recommended encoding condition is not satisfied.
    Recommended,
}

/// Located independent layout requirement, not a mathematical/trust outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The archive's original ZIP/UTF-8 fact violates the applicable encoding.
    Zip(FaultKind),
    /// Simple data cardinality is not one, or extended data cardinality is zero.
    DataCount,
    /// A simple data file is not an original root-level file.
    SimpleDataPath,
    /// The original principal-file cardinality does not satisfy the form.
    PrincipalCount,
    /// Another principal signature/time-assertion family occurs in the layout.
    PrincipalFamily,
    /// An optional mimetype has several original occurrences.
    MimetypeCount,
    /// Actual physical mimetype framing violates Annex A.1.
    MimetypeHeader,
    /// Baseline S contains an additional original file/directory.
    BaselineSimpleExtra,
    /// Baseline E-XAdES lacks exactly one original META-INF/manifest.xml.
    BaselineOdfManifest,
    /// Application metadata uses a reserved name outside a defined role.
    ReservedName,
}

/// One original constraint failure. None denotes a container cardinality.
#[derive(Debug, Clone, Copy)]
pub struct Issue<D, G> {
    /// Exact original member, where the requirement concerns one occurrence.
    pub member: Option<MemberId<D, G>>,
    /// Actual physical original enclosure.
    pub range: Span,
    /// Independent layout requirement.
    pub requirement: Requirement,
    /// Normative requirement versus recommendation.
    pub strength: Strength,
}

/// Complete paid layout pass. This does not attest XML schema, actual signed
/// coverage, MIME association, archive continuity or any signature's level.
pub struct Inspection<'c, 'v, 's, S: RangeSource> {
    census: &'c Census<'v, 's, S>,
    form: Form,
    rules: Rules,
    defined: bool,
    required: bool,
    issues: OwnedVec<Issue<S::Document, S::Generation>>,
}

struct Issues<D, G, W: Work> {
    required: bool,
    values: OwnedVec<Issue<D, G>, W>,
}
impl<D, G, W: Work> Issues<D, G, W> {
    fn push<E>(
        &mut self,
        member: Option<MemberId<D, G>>,
        range: Span,
        requirement: Requirement,
        strength: Strength,
    ) -> Result<(), Error<E>> {
        self.values
            .try_push(Issue {
                member,
                range,
                requirement,
                strength,
            })
            .map_err(|cause| resource(range, cause))?;
        if strength == Strength::Required {
            self.required = false;
        }
        Ok(())
    }
}

impl<'c, 'v, 's, S: RangeSource> Inspection<'c, 'v, 's, S> {
    /// Checks every original occurrence. Resource/source refusal is terminal;
    /// a readable negative member never becomes a successful partial census.
    ///
    /// # Panics
    /// An internal immutable census invariant fails if its bounded ordinal or
    /// retained fault ordinal is absent from the same original archive.
    #[expect(
        clippy::too_many_lines,
        reason = "the complete layout rule table is evaluated in one paid pass, preserving independent per-occurrence and aggregate findings"
    )]
    pub fn read<W: Work>(
        census: &'c Census<'v, 's, S>,
        form: Form,
        rules: Rules,
        work: &W,
    ) -> Result<Self, Error<S::Error>> {
        let archive = census.archive;
        let execution = archive.session().query(work);
        archive.admit(&execution, archive.directory_span())?;
        let defined = match rules {
            Rules::General => true,
            Rules::BaselinePart1 => matches!(
                form,
                Form::Simple(Principal::Cades | Principal::Xades) | Form::ExtendedXades
            ),
            Rules::AdditionalPart2 => matches!(
                form,
                Form::Simple(Principal::Timestamp | Principal::Evidence | Principal::XmlEvidence)
                    | Form::ExtendedCadesAndAssertions
            ),
        };
        // EN319162-2 §4 incorporates Part1 clause4, not the additional ISO
        // restriction in Part1 §5.3.1. Additional is not a baseline alias.
        let baseline = rules == Rules::BaselinePart1 && defined;
        let mut result = Issues {
            required: true,
            values: execution.vector(),
        };
        let mut data = 0;
        let mut principal = 0;
        let mut mimetypes = 0;
        let mut odf_manifests = 0;
        for ordinal in 0..census.len() {
            let (member, role) = census
                .occurrence(ordinal, &execution)?
                .expect("bounded original ordinal");
            let name = member.name();
            execution
                .charge_work(name.len() as u64 + 1)
                .map_err(|cause| resource(member.name_span(), cause))?;
            match role {
                Role::Data => {
                    data += 1;
                    if matches!(form, Form::Simple(_)) && name.contains(&b'/') {
                        result.push(
                            Some(member.id()),
                            member.name_span(),
                            Requirement::SimpleDataPath,
                            Strength::Required,
                        )?;
                    }
                }
                Role::Mimetype => mimetypes += 1,
                Role::OdfManifest => odf_manifests += 1,
                _ => {}
            }
            match form {
                Form::Simple(selected) => {
                    if name == selected.name() {
                        principal += 1;
                    } else if matches!(
                        name,
                        b"META-INF/signature.p7s"
                            | b"META-INF/signatures.xml"
                            | b"META-INF/timestamp.tst"
                            | b"META-INF/evidencerecord.ers"
                            | b"META-INF/evidencerecord.xml"
                    ) {
                        result.push(
                            Some(member.id()),
                            member.name_span(),
                            Requirement::PrincipalFamily,
                            Strength::Required,
                        )?;
                    }
                    // EN319162-1 §§5.3.2.2/5.3.2.3: the baseline is stricter
                    // than §4.3.3.2(5), which permits general auxiliary metadata.
                    if baseline
                        && name != selected.name()
                        && role != Role::Data
                        && role != Role::Mimetype
                        && name != b"META-INF/"
                    {
                        result.push(
                            Some(member.id()),
                            member.name_span(),
                            Requirement::BaselineSimpleExtra,
                            Strength::Required,
                        )?;
                    }
                }
                Form::ExtendedXades => {
                    if role == Role::Xades {
                        principal += 1;
                    } else if matches!(role, Role::Cades | Role::Timestamp) {
                        result.push(
                            Some(member.id()),
                            member.name_span(),
                            Requirement::PrincipalFamily,
                            Strength::Required,
                        )?;
                    }
                }
                Form::ExtendedCadesAndAssertions => {
                    if matches!(
                        role,
                        Role::Cades | Role::Timestamp | Role::Evidence | Role::XmlEvidence
                    ) {
                        principal += 1;
                    } else if role == Role::Xades {
                        result.push(
                            Some(member.id()),
                            member.name_span(),
                            Requirement::PrincipalFamily,
                            Strength::Required,
                        )?;
                    }
                }
            }
            if !matches!(form, Form::Simple(_)) && role == Role::Reserved {
                result.push(
                    Some(member.id()),
                    member.name_span(),
                    Requirement::ReservedName,
                    Strength::Required,
                )?;
            }
        }
        if (matches!(form, Form::Simple(_)) && data != 1) || data == 0 {
            result.push(
                None,
                archive.directory_span(),
                Requirement::DataCount,
                Strength::Required,
            )?;
        }
        if (matches!(form, Form::Simple(_)) && principal != 1) || principal == 0 {
            result.push(
                None,
                archive.directory_span(),
                Requirement::PrincipalCount,
                Strength::Required,
            )?;
        }
        if mimetypes > 1 {
            result.push(
                None,
                archive.directory_span(),
                Requirement::MimetypeCount,
                Strength::Required,
            )?;
        }
        if baseline && form == Form::ExtendedXades && odf_manifests != 1 {
            result.push(
                None,
                archive.directory_span(),
                Requirement::BaselineOdfManifest,
                Strength::Required,
            )?;
        }
        for header in census.mimetypes(&execution) {
            let header = header?;
            if !header.first() || !header.stored() || !header.no_extra() || !header.unencrypted() {
                let member = archive.original(header.member, &execution)?;
                result.push(
                    Some(header.member),
                    member.central_span(),
                    Requirement::MimetypeHeader,
                    Strength::Required,
                )?;
            }
        }
        for fault in archive.faults(&execution)? {
            let fault = fault?;
            let strength = match fault.kind {
                FaultKind::Utf8
                | FaultKind::Name
                | FaultKind::LocalMismatch
                | FaultKind::Descriptor
                | FaultKind::Overlap
                | FaultKind::LocalBounds
                | FaultKind::StoredLength
                | FaultKind::Zip64 => Some(Strength::Required),
                FaultKind::Compression => Some(if baseline {
                    Strength::Required
                } else {
                    Strength::Recommended
                }),
                FaultKind::IsoProfile | FaultKind::DirectorySignature | FaultKind::Encrypted
                    if baseline =>
                {
                    Some(Strength::Required)
                }
                _ => None,
            };
            if let Some(strength) = strength {
                let member = if let Some(ordinal) = fault.member {
                    Some(
                        archive
                            .member(ordinal, &execution)?
                            .expect("original fault ordinal")
                            .id(),
                    )
                } else {
                    None
                };
                result.push(member, fault.range, Requirement::Zip(fault.kind), strength)?;
            }
        }
        archive.admit(&execution, archive.directory_span())?;
        Ok(Self {
            census,
            form,
            rules,
            defined,
            required: result.required,
            issues: result.values.into_owned(),
        })
    }

    /// Exact complete original role catalogue used by this pass.
    #[must_use]
    pub fn census(&self) -> &'c Census<'v, 's, S> {
        self.census
    }
    /// Explicit requested form.
    #[must_use]
    pub fn form(&self) -> Form {
        self.form
    }
    /// Explicit requested normative rule set.
    #[must_use]
    pub fn rules(&self) -> Rules {
        self.rules
    }
    /// Whether this rule set defines the requested format route.
    #[must_use]
    pub fn defined(&self) -> bool {
        self.defined
    }
    /// Only file layout, with recommendations independent. None means the
    /// selected standard does not define this route, not a successful baseline.
    #[must_use]
    pub fn required_layout(&self) -> Option<bool> {
        if self.defined {
            Some(self.required)
        } else {
            None
        }
    }
    /// Full paid issue traversal, with first resource refusal followed by None.
    pub fn issues<'q, W: Work>(
        &'q self,
        work: &'q W,
    ) -> impl Iterator<Item = IssueResult<S>> + use<'q, 'c, 'v, 's, S, W> {
        let mut at = 0;
        let mut stopped = false;
        core::iter::from_fn(move || {
            if stopped || at == self.issues.len() {
                return None;
            }
            if let Err(cause) = self
                .census
                .archive
                .admit(work, self.census.archive.directory_span())
            {
                stopped = true;
                return Some(Err(cause));
            }
            let issue = self.issues[at];
            at += 1;
            Some(Ok(issue))
        })
    }
}

type IssueResult<S> = crate::error::SourceResult<
    Issue<<S as RangeSource>::Document, <S as RangeSource>::Generation>,
    S,
>;
