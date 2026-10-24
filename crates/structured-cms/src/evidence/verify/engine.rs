//! One sequence-processing model for resident and suspending acquisition.
//! Expansion keeps the resident API synchronous, without a poll adapter,
//! boxed future, executor, or changed renewal/preflight order.

macro_rules! memos {
    (resident, $name:ident, $provider:expr, $algorithms:expr, $objects:expr) => {
        let $name = $crate::evidence::input::LazyMemos::new($provider, $algorithms, $objects);
    };
    (suspending, $name:ident, $provider:expr, $algorithms:expr, $objects:expr) => {
        let mut $name = $crate::evidence::input::AsyncMemos::new($provider, $algorithms, $objects);
    };
}
pub(super) use memos;

macro_rules! cached {
    (resident, $stamp:expr, $memos:ident, $ordinal:expr, $membership:expr, $prior:expr) => {
        $crate::evidence::input::CachedInput {
            stamp: $stamp,
            memos: &$memos,
            ordinal: $ordinal,
            membership: $membership,
            previous: $prior,
        }
    };
    (suspending, $stamp:expr, $memos:ident, $ordinal:expr, $membership:expr, $prior:expr) => {
        $crate::evidence::input::AsyncCachedInput {
            stamp: $stamp,
            memos: &mut $memos,
            ordinal: $ordinal,
            membership: $membership,
            previous: $prior,
        }
    };
}
pub(super) use cached;

macro_rules! renewal {
    (resident, $input:expr) => {
        $input
    };
    (suspending, $input:expr) => {
        $crate::evidence::input::ResidentInput($input)
    };
}
pub(super) use renewal;

macro_rules! check {
    (resident, $token:expr, $provider:expr, $reader:expr, $context:expr,
     $input:expr, $recognizes:expr, $profile:expr) => {
        $token.check_historical_input_with_profile(
            $provider,
            $reader,
            $context,
            $input,
            $recognizes,
            $profile,
        )
    };
    (suspending, $token:expr, $provider:expr, $reader:expr, $context:expr,
     $input:expr, $recognizes:expr, $profile:expr) => {
        $token
            .check_historical_async_with_profile(
                $provider,
                $reader,
                $context,
                $input,
                $recognizes,
                $profile,
            )
            .await
    };
}
pub(super) use check;

macro_rules! execute {
    ($mode:ident, $record:ident, $plan:ident, $provider:ident, $operation:ident,
     $authorities:ident, $utc:ident, $reference:ident, $objects:ident,
     $membership:ident, $recognizes:ident, $historical:ident, $profile:ident) => {{
        use $crate::evidence::verify::{
            Checked, Decision, GroupError, Report, VerificationError, admit_membership,
            history_input, order_findings, prior_views,
        };
        let origin = $record
            .original
            .reader_in($operation)
            .map_err(VerificationError::Processing)?;
        let work = origin.execution_query($operation);
        let at = $record.original.element.span().start;
        let resource = |cause| {
            VerificationError::Processing($crate::Error::resource(
                cause,
                $crate::evidence::FIELD,
                at,
            ))
        };
        admit_membership($record, $objects.len(), $membership, &work).map_err(
            |cause| match cause {
                GroupError::Processing(cause) => VerificationError::Processing(cause),
                GroupError::Membership(index) => VerificationError::Membership { index },
            },
        )?;
        // A single flat projection owns all prefix views for both drivers.
        let projected = $crate::evidence::PriorSequence::all($record, $operation)
            .map_err(VerificationError::Processing)?;
        let prefixes = prior_views($record, &projected, $operation, &work)
            .map_err(VerificationError::Processing)?;
        $crate::evidence::verify::engine::memos!(
            $mode,
            memo_set,
            $provider,
            &$plan.chains,
            $objects
        );
        let mut checks = work.vector();
        checks
            .try_reserve_exact($record.timestamps.len())
            .map_err(resource)?;
        let mut complete = true;
        for chain_index in (0..$record.chains.len()).rev() {
            let chain = &$record.chains[chain_index];
            let prior = prefixes[chain_index].as_ref();
            for index in (chain.first..chain.end).rev() {
                work.charge_work(1).map_err(resource)?;
                let (stamp, token) = $plan.token(index);
                let reader = stamp
                    .timestamp
                    .reader_in($operation)
                    .map_err(VerificationError::Processing)?;
                let selection = $authorities
                    .select(index, stamp, &reader.execution())
                    .map_err(|cause| VerificationError::Selection { index, cause })?;
                let context = selection.historical_context($utc);
                let common = if index == chain.first {
                    let mut input = $crate::evidence::verify::engine::cached!(
                        $mode,
                        stamp,
                        memo_set,
                        chain_index,
                        $membership,
                        prior
                    );
                    $crate::evidence::verify::engine::check!(
                        $mode,
                        token,
                        $provider,
                        &reader,
                        &context,
                        &mut input,
                        |extension, execution| $recognizes(index, extension, execution),
                        |input| $profile(index, input)
                    )
                    .map_err(|cause| VerificationError::Timestamp { index, cause })?
                } else {
                    let mut source = [[$record.timestamps[index - 1].timestamp.element.as_bytes()]];
                    let mut input = $crate::evidence::verify::engine::renewal!(
                        $mode,
                        $crate::evidence::ObjectInput::new(
                            stamp,
                            &mut source,
                            $crate::evidence::Membership::Object
                        )
                    );
                    $crate::evidence::verify::engine::check!(
                        $mode,
                        token,
                        $provider,
                        &reader,
                        &context,
                        &mut input,
                        |extension, execution| $recognizes(index, extension, execution),
                        |input| $profile(index, input)
                    )
                    .map_err(|cause| VerificationError::Renewal { index, cause })?
                };
                let history = $historical(
                    history_input(
                        $record,
                        chain_index,
                        index,
                        &common,
                        &selection,
                        &checks,
                        $reference,
                    ),
                    &reader.execution(),
                )
                .map_err(|cause| VerificationError::Historical { index, cause })?;
                complete &= common.evidence().is_some() && history == Decision::Valid;
                checks
                    .try_push(Checked {
                        index,
                        common,
                        selection,
                        history,
                    })
                    .map_err(resource)?;
            }
        }
        let ordering = order_findings(&checks, $utc, $operation, &work, at)
            .map_err(VerificationError::Processing)?;
        complete &= ordering.is_empty();
        Ok(Report {
            record: $record,
            checks: checks.into_owned(),
            ordering,
            complete,
        })
    }};
}
pub(super) use execute;
