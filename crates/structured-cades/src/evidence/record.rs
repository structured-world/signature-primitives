//! Bind complete RFC4998 execution to the actual CMS object and `CAdES` paths.
use super::{CmsObject, ObjectError, View};
use crate::{
    Error,
    basic::PathRestriction,
    prepare::Preparation,
    preservation::{Kind, Required},
    timestamp::{self, ProfileError, VisitError},
};
use core::{
    cell::{Cell, RefCell},
    convert::Infallible,
};
use structured_asn1::{
    Element, Reader,
    memory::{Execution, OwnedVec, Work},
};
use structured_cms::{
    evidence::{ArchiveTimeStamp, Membership, verify as ers},
    provider::SignatureProvider,
    stream::{Receiver, Source},
    timestamp::TokenExtension,
};
use structured_ltv::pki::CheckedPath;
use structured_pkix::temporal::{Instant, LeapTable};

const FIELD: &str = "cades.evidence.record";

/// The original candidate's already checked path and certificate source.
pub struct Authority<'path, 'd> {
    /// Same original effective key/path used for signed ESS restrictions.
    pub path: &'path CheckedPath<'d>,
    /// Candidate's own original producing reader, not a token/default parser.
    pub certificate_parent: &'path Reader<'d>,
}
/// Select paths for actual original ERS timestamps; no crypto runs here.
pub trait Authorities<'d> {
    /// Original caller selection failure.
    type Error;
    /// Current Work must fund any caller-side catalogue/discovery work.
    fn select<'path, W: Work>(
        &'path self,
        index: usize,
        token: &structured_cms::timestamp::Token<'d>,
        work: &W,
    ) -> Result<Authority<'path, 'd>, Self::Error>
    where
        'd: 'path;
}

/// Original whole-object/explicit detached acquisition failure.
#[derive(Debug)]
pub enum SourceError<E> {
    /// Exact adapted CMS framing/source refusal.
    Cms(ObjectError),
    /// Exact caller-supplied separate signed-content refusal.
    Detached(E),
}
enum Object<'s, 'a, 'd, S> {
    Cms(&'s mut CmsObject<'a, 'd>),
    Detached(&'s mut S),
}
impl<S: Source> Source for Object<'_, '_, '_, S> {
    type Error = SourceError<S::Error>;
    fn stream<W: Work>(&mut self, out: &mut impl Receiver, work: &W) -> Result<(), Self::Error> {
        match self {
            Self::Cms(source) => source.stream(out, work).map_err(SourceError::Cms),
            Self::Detached(source) => source.stream(out, work).map_err(SourceError::Detached),
        }
    }
}
/// Selection preserves caller failures separately from adapter processing refusal.
#[derive(Debug)]
pub enum SelectionError<E> {
    /// Actual caller discovery failure.
    Caller(E),
    /// Current work, slot admission or source mismatch.
    Processing(Error),
}
pub(super) struct Selected<'path, 'd, A> {
    pub(super) source: &'path A,
    pub(super) start: usize,
    pub(super) items: RefCell<OwnedVec<Option<Authority<'path, 'd>>>>,
}
impl<'path, 'd, A> Selected<'path, 'd, A> {
    pub(super) fn path<W: Work>(
        &self,
        index: usize,
        work: &W,
        at: u64,
    ) -> Result<&'path CheckedPath<'d>, Error> {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, at))?;
        let items = self.items.try_borrow().map_err(|_| Error::Foreign { at })?;
        let selected = items
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Foreign { at })?;
        Ok(selected.path)
    }
}
impl<'path, 'd, A: Authorities<'d>> ers::Authorities<'d> for Selected<'path, 'd, A>
where
    'd: 'path,
{
    type Error = SelectionError<A::Error>;
    fn select<'a, W: Work>(
        &'a self,
        index: usize,
        stamp: &'a ArchiveTimeStamp<'d>,
        work: &W,
    ) -> Result<ers::Selection<'a>, Self::Error>
    where
        'd: 'a,
    {
        let at = stamp.original().element().span().start;
        work.charge_work(1)
            .map_err(|cause| SelectionError::Processing(Error::resource(cause, FIELD, at)))?;
        // Discovery is driven by the common verifier AFTER membership and
        // preceding-sequence preflight. Never call it in a preparatory loop.
        let source: &'path A = self.source;
        let structured_cms::evidence::TimeStamp::Rfc3161(token) = stamp.timestamp() else {
            return Err(SelectionError::Processing(Error::Foreign { at }));
        };
        let selected: Authority<'path, 'd> = source
            .select(self.start + index, token, work)
            .map_err(SelectionError::Caller)?;
        let target = selected
            .path
            .members()
            .last()
            .ok_or(SelectionError::Processing(Error::Foreign { at }))?;
        let result = ers::Selection {
            certificate: target.certificate(),
            certificate_parent: selected.certificate_parent,
            key: target.key(),
        };
        let mut items = self
            .items
            .try_borrow_mut()
            .map_err(|_| SelectionError::Processing(Error::Foreign { at }))?;
        let slot = items
            .get_mut(index)
            .ok_or(SelectionError::Processing(Error::Foreign { at }))?;
        if slot.is_some() {
            return Err(SelectionError::Processing(Error::Foreign { at }));
        }
        *slot = Some(selected);
        Ok(result)
    }
}

/// Complete source-bound report, including every failed/uncertain participant.
/// Mathematical TSA facts are reused for actors without a second signature
/// verification. Modern baseline promotion still requires its independent
/// complete status/material/coverage/chronology closure.
pub struct Checked<'prepared, 'm, 'd, 'path> {
    pub(super) prepared: &'prepared Preparation<'m, 'd>,
    pub(super) required: Required<'d>,
    pub(super) proof: usize,
    pub(super) covered: Option<OwnedVec<structured_asn1::Span>>,
    pub(super) timestamps: core::ops::Range<usize>,
    pub(super) checks: OwnedVec<timestamp::Checked<'m, 'd, 'path>>,
    pub(super) ordering: OwnedVec<ers::OrderFinding>,
    pub(super) complete: bool,
}
/// Private-constructor source/recipe/history receipt; public facts cannot make it.
pub struct Verified<'check, 'prepared, 'm, 'd, 'path>(&'check Checked<'prepared, 'm, 'd, 'path>);
impl<'prepared, 'm, 'd, 'path> Checked<'prepared, 'm, 'd, 'path> {
    pub(super) fn bind_coverage<W: Work>(
        &mut self,
        spans: Option<OwnedVec<structured_asn1::Span>>,
        work: &W,
    ) -> Result<(), Error> {
        self.covered = spans
            .map(|spans| {
                super::coverage::normalize_owned(spans, work, self.required.property.span().start)
            })
            .transpose()?;
        Ok(())
    }
    /// Every actual TSA result, in original record order.
    pub fn checks(
        &self,
    ) -> impl DoubleEndedIterator<Item = &timestamp::Checked<'m, 'd, 'path>> + ExactSizeIterator
    {
        self.checks.iter().rev()
    }
    /// Actual failed adjacent chronology comparisons.
    #[must_use]
    pub fn ordering(&self) -> &[ers::OrderFinding] {
        &self.ordering
    }
    /// Present only after the COMPLETE record, input, profiles and history hold.
    #[must_use]
    pub fn verified(&self) -> Option<Verified<'_, 'prepared, 'm, 'd, 'path>> {
        if self.complete {
            Some(Verified(self))
        } else {
            None
        }
    }
}
impl<'prepared, 'm, 'd, 'path> Verified<'_, 'prepared, 'm, 'd, 'path> {
    pub(super) fn report(&self) -> &Checked<'prepared, 'm, 'd, 'path> {
        self.0
    }
    /// Exact original `CAdES` attribute/value/placement, not a `genTime` selector.
    #[must_use]
    pub fn required(&self) -> Required<'d> {
        self.0.required
    }
    /// Same complete source preparation and its timestamp/material catalogue.
    #[must_use]
    pub fn prepared(&self) -> &'prepared Preparation<'m, 'd> {
        self.0.prepared
    }
    /// Original global TSA ordinals covered by this complete receipt.
    #[must_use]
    pub fn timestamps(&self) -> core::ops::Range<usize> {
        self.0.timestamps.clone()
    }
}

/// Source/profile/common failures stay distinct; no successful partial record.
#[derive(Debug)]
pub enum CheckError<SE, PE, RE, AE, HE> {
    /// Wrong placement/source/recipe or current processing refusal.
    Selection(Error),
    /// Actual previous/current source binding refusal.
    Snapshot(super::SnapshotError),
    /// Original schema/algorithm/source-mapped information preflight failure.
    Plan(ers::PlanError),
    /// Original caller path selection failure.
    Authority(AE),
    /// Unmodified whole common record failure, including `CAdES` ESS restrictions.
    Record(
        ers::VerificationError<
            SourceError<SE>,
            PE,
            RE,
            SelectionError<AE>,
            HE,
            ProfileError<PE, Error>,
        >,
    ),
}

/// Complete source-bound record result with independent original failure classes.
pub type CheckResult<'a, 'm, 'd, 'path, SE, PE, RE, AE, HE> =
    Result<Checked<'a, 'm, 'd, 'path>, CheckError<SE, PE, RE, AE, HE>>;

impl<'a, 'm, 'd> View<'a, 'm, 'd> {
    /// Verifies RFC4998 Appendix A's INTERNAL original whole-CMS recipe.
    /// Whole record/history/path and every actual contained TSA are checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original CMS, current execution, selected provider/path and independent trust callbacks are separate agreed boundaries."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Source maps and opaque provider/history causes remain inline even on allocation refusal."
    )]
    pub fn check_internal<'path, P, PE, A, RE, HE>(
        &self,
        envelope: Element<'d>,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, Infallible, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        'd: 'path,
    {
        if self.required().kind != Kind::EvidenceRecordInternal {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.required().property.span().start,
            }));
        }
        let mut source = self
            .cms_object(envelope, operation)
            .map_err(CheckError::Selection)?;
        let covered = source
            .coverage(self, operation)
            .map_err(CheckError::Selection)?;
        self.check_objects(
            covered,
            provider,
            operation,
            authorities,
            utc,
            reference,
            &mut [Object::<timestamp::NoDetached>::Cms(&mut source)],
            Membership::Object,
            recognizes,
            historical,
        )
    }
    /// Same complete INTERNAL record with a genuine earlier CMS source.
    /// The snapshot must preserve all selected fields and prior attributes;
    /// lost historical BER coding is never reconstructed from a claimed date.
    #[expect(
        clippy::too_many_arguments,
        reason = "The actual previous snapshot supplements the independent source, provider/path and history inputs."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Snapshot and source-mapped verification failures preserve their causes without error-path allocation."
    )]
    pub fn check_internal_snapshot<'path, P, PE, A, RE, HE>(
        &self,
        envelope: Element<'d>,
        snapshot: &super::CmsSnapshot<'_, 'd>,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, Infallible, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        'd: 'path,
    {
        if self.required().kind != Kind::EvidenceRecordInternal {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.required().property.span().start,
            }));
        }
        let mut source = self
            .cms_object_snapshot(envelope, snapshot, operation)
            .map_err(CheckError::Snapshot)?;
        let covered = source
            .coverage(self, operation)
            .map_err(CheckError::Selection)?;
        self.check_objects(
            covered,
            provider,
            operation,
            authorities,
            utc,
            reference,
            &mut [Object::<timestamp::NoDetached>::Cms(&mut source)],
            Membership::Object,
            recognizes,
            historical,
        )
    }
    /// Verifies EXTERNAL whole CMS plus the ACTUAL separately supplied signed
    /// content as one exact document group. No whole-content buffering occurs.
    #[expect(
        clippy::too_many_arguments,
        reason = "The caller's detached source cannot be conflated with original CMS provenance or trust/provider callbacks."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Detached acquisition and original mapped/provider failures must survive resource refusal without boxing."
    )]
    pub fn check_external<'path, P, PE, A, S, RE, HE>(
        &self,
        envelope: Element<'d>,
        detached: &mut S,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, S::Error, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
        'd: 'path,
    {
        if self.required().kind != Kind::EvidenceRecordExternal {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.required().property.span().start,
            }));
        }
        let mut source = self
            .cms_object(envelope, operation)
            .map_err(CheckError::Selection)?;
        let covered = source
            .coverage(self, operation)
            .map_err(CheckError::Selection)?;
        self.check_objects(
            covered,
            provider,
            operation,
            authorities,
            utc,
            reference,
            &mut [Object::Cms(&mut source), Object::Detached(detached)],
            Membership::Group,
            recognizes,
            historical,
        )
    }

    /// EXTERNAL group using the genuine previous CMS encoding plus actual
    /// separate content. Snapshot binding runs before source/provider work.
    #[expect(
        clippy::too_many_arguments,
        reason = "Genuine previous CMS and detached content are distinct original sources alongside current verification inputs."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Original two-source and snapshot failures remain inline with the complete common verification cause."
    )]
    pub fn check_external_snapshot<'path, P, PE, A, S, RE, HE>(
        &self,
        envelope: Element<'d>,
        snapshot: &super::CmsSnapshot<'_, 'd>,
        detached: &mut S,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, S::Error, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
        'd: 'path,
    {
        if self.required().kind != Kind::EvidenceRecordExternal {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.required().property.span().start,
            }));
        }
        let mut source = self
            .cms_object_snapshot(envelope, snapshot, operation)
            .map_err(CheckError::Snapshot)?;
        let covered = source
            .coverage(self, operation)
            .map_err(CheckError::Selection)?;
        self.check_objects(
            covered,
            provider,
            operation,
            authorities,
            utc,
            reference,
            &mut [Object::Cms(&mut source), Object::Detached(detached)],
            Membership::Group,
            recognizes,
            historical,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This single kernel shares actual object/group recipes, provider/path checks and independent history callbacks."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Common ERS failures retain source mapping and opaque callback causes without a new allocation."
    )]
    fn check_objects<'path, P, PE, A, S, RE, HE>(
        &self,
        covered: OwnedVec<structured_asn1::Span>,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        objects: &mut [Object<'_, 'a, 'd, S>],
        membership: Membership,
        mut recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        mut historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, S::Error, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
        'd: 'path,
    {
        let required = self.required();
        let record = self.record().ok_or_else(|| {
            CheckError::Selection(Error::Foreign {
                at: required.property.span().start,
            })
        })?;
        let plan = record.input_plan(operation).map_err(CheckError::Plan)?;
        let work = operation.execution();
        let resource = |cause| {
            CheckError::Selection(Error::resource(
                cause,
                FIELD,
                required.property.span().start,
            ))
        };
        let mut selected = work.vector();
        let mut restrictions = work.vector();
        selected
            .try_reserve_exact(record.timestamps().len())
            .map_err(resource)?;
        restrictions
            .try_reserve_exact(record.timestamps().len())
            .map_err(resource)?;
        for _ in record.timestamps() {
            work.charge_work(1).map_err(resource)?;
            selected.try_push(None).map_err(resource)?;
            restrictions
                .try_push(Cell::new(PathRestriction::Unproven))
                .map_err(resource)?;
        }
        let selected = Selected {
            source: authorities,
            start: self.entry.timestamps.start,
            items: RefCell::new(selected.into_owned()),
        };
        let report = plan
            .verify_with_profile(
                provider,
                operation,
                &selected,
                utc,
                reference,
                objects,
                membership,
                |index, extension, execution| {
                    recognizes(self.entry.timestamps.start + index, extension, execution)
                },
                |mut facts, execution| {
                    facts.index += self.entry.timestamps.start;
                    historical(facts, execution)
                },
                |index, input| {
                    let path = selected
                        .path(
                            index,
                            &input.parent.execution(),
                            required.property.span().start,
                        )
                        .map_err(|cause| structured_cms::timestamp::ProfileFailure {
                            source: structured_cms::timestamp::ProfileSource::Envelope,
                            cause: ProfileError::Input(cause),
                        })?;
                    let restriction = timestamp::Context::profile_rules(&input, path, provider)?;
                    restrictions[index].set(restriction);
                    Ok(())
                },
            )
            .map_err(CheckError::Record)?;
        let mut checked = self
            .finish_record(report, &selected, &restrictions, operation)
            .map_err(CheckError::Selection)?;
        checked
            .bind_coverage(Some(covered), &work)
            .map_err(CheckError::Selection)?;
        Ok(checked)
    }
    pub(super) fn finish_record<'path, A, W: Work>(
        &self,
        report: ers::Report<'_, 'd>,
        selected: &Selected<'path, 'd, A>,
        restrictions: &OwnedVec<Cell<PathRestriction>, W>,
        operation: &Reader<'d>,
    ) -> Result<Checked<'a, 'm, 'd, 'path>, Error>
    where
        'd: 'path,
    {
        let required = self.required();
        let work = operation.execution();
        let resource = |cause| Error::resource(cause, FIELD, required.property.span().start);
        let (_, results, ordering, mut complete) = report.into_parts();
        let mut checks = work.vector();
        checks.try_reserve_exact(results.len()).map_err(resource)?;
        for result in results {
            let (index, common, _, _) = result.into_parts();
            let path = selected.path(index, &work, required.property.span().start)?;
            let target = path
                .members()
                .last()
                .expect("nonempty selection admitted above");
            let global = self.entry.timestamps.start + index;
            let checked = timestamp::with_token(self.prepared, global, operation, |context| {
                Ok::<_, Infallible>(context.checked(
                    common,
                    restrictions[index].get(),
                    target.certificate(),
                    target.key(),
                ))
            })
            .map_err(|cause| match cause {
                VisitError::Processing(cause) => cause,
                VisitError::Unreadable { property } => Error::Foreign {
                    at: property.span().start,
                },
                VisitError::Callback(never) => match never {},
            })?;
            if checked.actor().is_none() {
                complete = false;
            }
            checks.try_push(checked).map_err(resource)?;
        }
        Ok(Checked {
            prepared: self.prepared,
            required,
            proof: self.ordinal,
            covered: None,
            timestamps: self.entry.timestamps.clone(),
            checks: checks.into_owned(),
            ordering,
            complete,
        })
    }
}
