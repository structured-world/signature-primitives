//! Close the SAME source-derived `PoE` recipe with every actual TSA participant.
use super::{InputError, Lazy};
use crate::{
    Error,
    basic::PathRestriction,
    evidence::{
        PoeValue, View,
        record::{Authorities, Checked, Selected, SelectionError},
    },
    timestamp::{self, ProfileError, VisitError},
};
use core::{
    cell::{Cell, RefCell},
    convert::Infallible,
};
use structured_asn1::{
    Reader,
    memory::{Execution, Work},
};
use structured_cms::{
    evidence::{Membership, verify as ers},
    provider::SignatureProvider,
    stream::Source,
    timestamp::{self as tsp, TokenExtension},
};
use structured_pkix::temporal::{Instant, LeapTable};
const FIELD: &str = "cades.longTermValidation.check";

type ErsFailure<SE, PE, RE, AE, HE> = ers::VerificationError<
    InputError<SE, PE>,
    PE,
    RE,
    SelectionError<AE>,
    HE,
    ProfileError<PE, Error>,
>;
/// Original `PoE`-specific refusal; completed negative facts stay in the report.
#[derive(Debug)]
pub enum CheckError<SE, PE, RE, AE, HE> {
    /// Original source/schema/current work refusal or absent optional proof.
    Processing(Error),
    /// Original carried-information and algorithm preflight failure.
    Plan(ers::PlanError),
    /// Original caller candidate/path discovery failure.
    Authority(AE),
    /// Actual complete ERS execution over the per-algorithm eight-hash source.
    Record(ErsFailure<SE, PE, RE, AE, HE>),
    /// Complete single timestamp check, preserving input/provider/source maps.
    Timestamp(tsp::ProfileCheckError<InputError<SE, PE>, PE, RE, ProfileError<PE, Error>>),
    /// Actual independently executed historical validator refusal.
    Historical(HE),
}

/// Full original proof result, preserving independent source/provider failures.
pub type CheckResult<'a, 'm, 'd, 'path, SE, PE, RE, AE, HE> =
    Result<Checked<'a, 'm, 'd, 'path>, CheckError<SE, PE, RE, AE, HE>>;

impl<'a, 'm, 'd> View<'a, 'm, 'd> {
    /// Verifies the original TS101733 §6.5.1 `PoE`, either a timestamp or an
    /// entire ERS record with BOTH renewal mechanisms. Each algorithm uses its
    /// own complete eight-hash recipe. Actual content is acquired once, after
    /// the selected candidate/key and signed ESS profile preflight.
    ///
    /// `poeDate` selects earlier instances only; it cannot establish historical
    /// authority. The callback must establish path/status/algorithm validity at
    /// the following authenticated proof, or at explicit `reference` for the
    /// final proof. Closing ALL other original obligations remains separate.
    #[expect(
        clippy::too_many_arguments,
        reason = "Actual payload acquisition, current execution, path/provider selection and historical validation are separate contracts."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Original source maps and opaque acquisition/provider/history failures survive allocation refusal inline."
    )]
    pub fn check_poe<'path, P, PE, A, S, RE, HE>(
        &self,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        detached: Option<&mut S>,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, S::Error, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
        'd: 'path,
    {
        self.check_poe_with_later(
            provider,
            operation,
            authorities,
            utc,
            reference,
            detached,
            &[],
            recognizes,
            historical,
        )
    }

    /// Same source recipe, excluding ONLY a subsequently added ATSv3/Annex B
    /// proof whose already verified coverage authenticates this actual `PoE`.
    /// EN319122-1 §5.5.3 requires this admission before ignoring later proofs;
    /// untrusted dates/order never authorize an exclusion.
    #[expect(
        clippy::too_many_arguments,
        reason = "Sealed later-proof coverage supplements the independent source, execution and verification callbacks."
    )]
    #[expect(
        clippy::result_large_err,
        reason = "Neither the mapped ERS nor timestamp failure can be boxed on an exhausted operation budget."
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "The two first-read formats share one atomic source/profile/history ledger and return no successful partial report."
    )]
    pub fn check_poe_with_later<'path, P, PE, A, S, RE, HE>(
        &self,
        provider: &P,
        operation: &Reader<'d>,
        authorities: &'path A,
        utc: &LeapTable<'d>,
        reference: Instant,
        detached: Option<&mut S>,
        later: &[crate::timestamp::historical::Later<'_, 'm, 'd>],
        mut recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        mut historical: impl FnMut(ers::Historical<'_, '_>, &Execution<'_>) -> Result<ers::Decision, HE>,
    ) -> CheckResult<'a, 'm, 'd, 'path, S::Error, PE, RE, A::Error, HE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        A: Authorities<'d>,
        S: Source,
        'd: 'path,
    {
        let poe = self.poe().ok_or_else(|| {
            CheckError::Processing(Error::Foreign {
                at: self.required().property.span().start,
            })
        })?;
        let required = self.required();
        if required.placement != structured_cms::attribute::Placement::Unsigned {
            return Err(CheckError::Processing(Error::Syntax {
                code: structured_cms::ErrorCode::AttributePlacement,
                field: FIELD,
                at: required.property.span().start,
            }));
        }
        let signer = self
            .prepared
            .signer_encoding(required.signature, operation)
            .map_err(CheckError::Processing)?;
        let mut single = false;
        for ordinal in 0..signer.attributes() {
            operation
                .charge(1)
                .map_err(|cause| CheckError::Processing(Error::encoding(cause, FIELD)))?;
            let attribute =
                signer
                    .attribute(ordinal)
                    .ok_or(CheckError::Processing(Error::Foreign {
                        at: required.property.span().start,
                    }))?;
            if attribute.span == required.property.span() {
                single = attribute.single.is_some()
                    && attribute.single == required.value.map(|value| value.element().span());
                break;
            }
        }
        if !single {
            return Err(CheckError::Processing(Error::Syntax {
                code: structured_cms::ErrorCode::AttributeCardinality,
                field: FIELD,
                at: required.property.span().start,
            }));
        }
        let at = poe.element().span().start;
        let resource = |cause| CheckError::Processing(Error::resource(cause, FIELD, at));
        let work = operation.execution();
        let proof = poe
            .proof()
            .ok_or(CheckError::Processing(Error::Foreign { at }))?;
        match proof {
            PoeValue::EvidenceRecord(record) => {
                let plan = record.input_plan(operation).map_err(CheckError::Plan)?;
                self.admit_poe_algorithms(plan.algorithms(), operation)
                    .map_err(CheckError::Processing)?;
                let mut slots = work.vector();
                let mut restrictions = work.vector();
                slots
                    .try_reserve_exact(record.timestamps().len())
                    .map_err(resource)?;
                restrictions
                    .try_reserve_exact(record.timestamps().len())
                    .map_err(resource)?;
                for _ in record.timestamps() {
                    slots.try_push(None).map_err(resource)?;
                    restrictions
                        .try_push(Cell::new(PathRestriction::Unproven))
                        .map_err(resource)?;
                }
                let selected = Selected {
                    source: authorities,
                    start: self.entry.timestamps.start,
                    items: RefCell::new(slots.into_owned()),
                };
                let mut sources = [Lazy {
                    view: self,
                    later,
                    provider,
                    algorithms: plan.algorithms(),
                    operation,
                    utc,
                    detached,
                    ready: None,
                }];
                let report = plan
                    .verify_requests_with_profile(
                        provider,
                        operation,
                        &selected,
                        utc,
                        reference,
                        &mut sources,
                        Membership::Object,
                        |index, extension, execution| {
                            recognizes(self.entry.timestamps.start + index, extension, execution)
                        },
                        |mut facts, execution| {
                            facts.index += self.entry.timestamps.start;
                            historical(facts, execution)
                        },
                        |index, input| {
                            let path = selected
                                .path(index, &input.parent.execution(), at)
                                .map_err(|cause| tsp::ProfileFailure {
                                    source: tsp::ProfileSource::Envelope,
                                    cause: ProfileError::Input(cause),
                                })?;
                            restrictions[index]
                                .set(timestamp::Context::profile_rules(&input, path, provider)?);
                            Ok(())
                        },
                    )
                    .map_err(CheckError::Record)?;
                let covered = sources[0].ready.take().map(|eight| eight.covered);
                let mut checked = self
                    .finish_record(report, &selected, &restrictions, operation)
                    .map_err(CheckError::Processing)?;
                checked
                    .bind_coverage(covered, &work)
                    .map_err(CheckError::Processing)?;
                Ok(checked)
            }
            PoeValue::Timestamp(token) => {
                let source = poe
                    .timestamp_source()
                    .ok_or(CheckError::Processing(Error::Foreign { at }))?;
                let reader = source
                    .reader_in(operation)
                    .map_err(CheckError::Processing)?;
                // Same checked algorithm grammar as ERS InputPlan; retain its
                // real carried source map for malformed/unknown identifiers.
                if !token.faults().is_empty()
                    || !token.message().faults().is_empty()
                    || !token.signer().faults().is_empty()
                {
                    return Err(CheckError::Plan(ers::PlanError::Nonconforming {
                        index: self.entry.timestamps.start,
                        span: token.message().span(),
                    }));
                }
                let algorithm = ers::token_algorithm(token, &reader)
                    .map_err(|cause| CheckError::Plan(ers::PlanError::Information(cause)))?;
                self.admit_poe_algorithms(&[algorithm], operation)
                    .map_err(CheckError::Processing)?;
                let choice = authorities
                    .select(self.entry.timestamps.start, token, &reader.execution())
                    .map_err(CheckError::Authority)?;
                let target = choice
                    .path
                    .members()
                    .last()
                    .ok_or(CheckError::Processing(Error::Foreign { at }))?;
                let selection = ers::Selection {
                    certificate: target.certificate(),
                    certificate_parent: choice.certificate_parent,
                    key: target.key(),
                };
                let context = tsp::CheckContext {
                    certificate: selection.certificate,
                    certificate_parent: selection.certificate_parent,
                    key: selection.key,
                    requested: None,
                    utc,
                    reference: None,
                    window: None,
                };
                let mut covered = Lazy {
                    view: self,
                    later,
                    provider,
                    algorithms: &[algorithm],
                    operation,
                    utc,
                    detached,
                    ready: None,
                };
                let restriction = Cell::new(PathRestriction::Unproven);
                let common = token
                    .check_historical_input_with_profile(
                        provider,
                        &reader,
                        &context,
                        &mut tsp::RawInput::new(&mut covered),
                        |extension, execution| {
                            recognizes(self.entry.timestamps.start, extension, execution)
                        },
                        |input| {
                            restriction.set(timestamp::Context::profile_rules(
                                &input,
                                choice.path,
                                provider,
                            )?);
                            Ok(())
                        },
                    )
                    .map_err(CheckError::Timestamp)?;
                let history = historical(
                    ers::Historical {
                        index: self.entry.timestamps.start,
                        current: &common,
                        selection: &selection,
                        following: None,
                        following_chain: None,
                        verification_time: reference,
                    },
                    &reader.execution(),
                )
                .map_err(CheckError::Historical)?;
                let mut complete = history == ers::Decision::Valid && common.evidence().is_some();
                let checked = timestamp::with_token(
                    self.prepared,
                    self.entry.timestamps.start,
                    operation,
                    |context| {
                        Ok::<_, Infallible>(context.checked(
                            common,
                            restriction.get(),
                            target.certificate(),
                            target.key(),
                        ))
                    },
                )
                .map_err(|cause| {
                    CheckError::Processing(match cause {
                        VisitError::Processing(cause) => cause,
                        VisitError::Unreadable { property } => Error::Foreign {
                            at: property.span().start,
                        },
                        VisitError::Callback(never) => match never {},
                    })
                })?;
                if checked.actor().is_none() {
                    complete = false;
                }
                let mut checks = work.vector();
                checks.try_push(checked).map_err(resource)?;
                let spans = covered.ready.take().map(|eight| eight.covered);
                let mut checked = Checked {
                    prepared: self.prepared,
                    required: self.required(),
                    proof: self.ordinal,
                    covered: None,
                    timestamps: self.entry.timestamps.clone(),
                    checks: checks.into_owned(),
                    ordering: work.vector().into_owned(),
                    complete,
                };
                checked
                    .bind_coverage(spans, &work)
                    .map_err(CheckError::Processing)?;
                Ok(checked)
            }
        }
    }
}
