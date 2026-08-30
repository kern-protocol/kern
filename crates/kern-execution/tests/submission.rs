//! Preparation, the submit-time authority check, and what an adapter's answer
//! does to a record.

mod support;

use kern_core::{TestMonotonicClock, Uptime};
use kern_enforcer::EnforcementError;
use kern_execution::{
    AuthorityLapseReason, AuthorityState, ExecutionGovernor, ExecutionState, GovernError,
    GovernorConfig, LapseAction, NotStartedReason, RejectionReason, SequentialExecutionIds,
    StartupPolicy, SubmitOutcome, UnknownPhase,
};
use support::{
    config, declaration, governor, governor_with, install, operation, other_session, session,
    store_for, Harness, TestExecutor, LEASE_TTL_MS, START_UPTIME_MS,
};

#[test]
fn a_live_preparation_invokes_the_executor_exactly_once() {
    let mut harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let prepared = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized");
    let receipt = prepared.submit(&harness.store, &mut executor);

    assert_eq!(executor.submit_count(), 1);
    assert!(receipt.executor_invoked());
    assert_eq!(receipt.state(), ExecutionState::Submitted);
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert_eq!(record.operation(), Some(&100));
    assert_eq!(record.authority(), AuthorityState::Current);
    assert!(record.submitted_at().is_some());
    // The digest binds the record to the operation the host holds.
    assert_eq!(record.command_digest(), receipt.command_digest());
    let _ = harness.supersede(300);
}

/// A preparation is not an authority reservation.
#[test]
fn authority_that_expires_before_submit_prevents_the_executor_call() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let prepared = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized");
    harness.clock.advance(LEASE_TTL_MS + 1);
    let receipt = prepared.submit(&harness.store, &mut executor);

    assert_eq!(executor.submit_count(), 0);
    assert!(!receipt.executor_invoked());
    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::AuthorityLost(
            AuthorityLapseReason::LeaseExpired
        ))
    );
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert_eq!(
        record.authority().lapse_reason(),
        Some(AuthorityLapseReason::LeaseExpired)
    );
}

/// Superseding authority never adopts an execution prepared under the older
/// generation.
#[test]
fn supersession_before_submit_prevents_the_executor_call() {
    let mut harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let prepared = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized");
    let newer = harness.supersede(300);
    assert_ne!(newer.lease_id(), harness.handle.lease_id());

    let receipt = prepared.submit(&harness.store, &mut executor);

    assert_eq!(executor.submit_count(), 0);
    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::AuthorityLost(
            AuthorityLapseReason::Superseded
        ))
    );
    // The record still names the authority that prepared it.
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert_eq!(record.handle().lease_id(), harness.handle.lease_id());
    assert_ne!(record.handle().lease_id(), newer.lease_id());
}

#[test]
fn a_store_from_another_session_prevents_the_executor_call() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let prepared = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized");

    let fresh_clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let other = store_for(other_session(), fresh_clock);
    let receipt = prepared.submit(&other, &mut executor);

    assert_eq!(executor.submit_count(), 0);
    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::AuthorityLost(
            AuthorityLapseReason::AuthorityMissing
        ))
    );
}

#[test]
fn a_dropped_preparation_is_abandoned_and_sends_nothing() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let executor = TestExecutor::new();
    let op = operation(400, "cafe");
    let execution_id = {
        let prepared = governor
            .prepare(&harness.store, &harness.handle, &op)
            .expect("authorized");
        prepared.execution_id()
    };

    assert_eq!(executor.submit_count(), 0);
    let record = governor.record(execution_id).expect("recorded");
    assert_eq!(
        record.execution(),
        ExecutionState::NotStarted(NotStartedReason::Abandoned)
    );
    // Drop checked nothing, so it asserts nothing about authority.
    assert_eq!(record.authority(), AuthorityState::Current);
    assert!(record.submitted_at().is_none());
}

#[test]
fn a_proven_rejection_is_not_started_but_the_executor_was_invoked() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Rejected {
        reason: RejectionReason::Unavailable,
    });
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    assert_eq!(executor.submit_count(), 1);
    assert!(receipt.executor_invoked());
    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::Rejected(RejectionReason::Unavailable))
    );
    assert!(governor
        .record(receipt.execution_id())
        .expect("recorded")
        .operation()
        .is_none());
}

/// A lost acknowledgement is not evidence that nothing happened, so nothing is
/// retried and the record keeps its uncertainty.
#[test]
fn a_lost_acknowledgement_becomes_unknown_and_is_never_retried() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    assert_eq!(
        receipt.state(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: kern_execution::LastKnown::Prepared,
        }
    );

    // Ticking repeatedly, with and without an expiry, must never resubmit.
    for _ in 0..3 {
        governor.tick_observed(&harness.store, &mut executor);
    }
    harness.clock.advance(LEASE_TTL_MS + 1);
    for _ in 0..3 {
        governor.tick_observed(&harness.store, &mut executor);
    }
    assert_eq!(executor.submit_count(), 1);
    assert!(governor
        .record(receipt.execution_id())
        .expect("recorded")
        .execution()
        .is_unknown());
}

#[test]
fn an_unauthorized_operation_never_reaches_the_executor() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");
    // Schema-valid, and outside the bounds the lease carries.
    let too_fast = support::navigate_schema()
        .normalize(&support::navigate_proposal(600, "cafe"))
        .expect("schema-valid");

    let error = governor
        .prepare(&harness.store, &harness.handle, &too_fast)
        .err()
        .expect("the lease permits at most 400");

    assert_eq!(
        error,
        GovernError::Authorization(EnforcementError::ConstraintViolation)
    );
    assert_eq!(executor.submit_count(), 0);
    assert_eq!(governor.records().count(), 0);
    // The governor is still usable for an operation the lease does permit.
    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);
    assert!(receipt.executor_invoked());
}

#[test]
fn expired_authority_is_refused_at_preparation() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let executor = TestExecutor::new();
    let op = operation(400, "cafe");

    harness.clock.advance(LEASE_TTL_MS + 1);
    let error = governor
        .prepare(&harness.store, &harness.handle, &op)
        .err()
        .expect("expired");

    assert_eq!(
        error,
        GovernError::Authorization(EnforcementError::DeadlineExpired)
    );
    assert_eq!(executor.submit_count(), 0);
}

#[test]
fn a_full_table_of_live_executions_refuses_preparation() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let mut store = store_for(session(), clock.clone());
    let mut issuer = support::issuer();
    let handle = install(&mut store, &mut issuer, 400, "cafe", LEASE_TTL_MS);
    let mut governor = governor_with(
        clock,
        GovernorConfig {
            capacity: 2,
            ..config()
        },
        declaration(),
    );
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    for _ in 0..2 {
        governor
            .prepare(&store, &handle, &op)
            .expect("authorized")
            .submit(&store, &mut executor);
    }

    let error = governor.prepare(&store, &handle, &op).err().expect("full");
    assert_eq!(error, GovernError::CapacityExhausted);
    assert_eq!(executor.submit_count(), 2);
}

/// A terminal record's storage may be reclaimed; a live or unknown one may not.
#[test]
fn a_terminal_record_is_reclaimed_to_make_room() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let mut store = store_for(session(), clock.clone());
    let mut issuer = support::issuer();
    let handle = install(&mut store, &mut issuer, 400, "cafe", LEASE_TTL_MS);
    let mut governor = governor_with(
        clock,
        GovernorConfig {
            capacity: 1,
            ..config()
        },
        declaration(),
    );
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Rejected {
        reason: RejectionReason::Busy,
    });
    let op = operation(400, "cafe");

    let first = governor
        .prepare(&store, &handle, &op)
        .expect("authorized")
        .submit(&store, &mut executor);
    assert!(!first.state().is_unknown());

    let second = governor
        .prepare(&store, &handle, &op)
        .expect("the terminal record is reclaimable")
        .submit(&store, &mut executor);
    assert_ne!(first.execution_id(), second.execution_id());
    assert!(governor.record(first.execution_id()).is_none());
}

#[test]
fn a_governor_refuses_a_store_from_another_session_at_preparation() {
    let harness = Harness::new();
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let mut governor: ExecutionGovernor<u64, _, _> = ExecutionGovernor::new(
        other_session(),
        config(),
        clock,
        SequentialExecutionIds::new(),
        declaration(),
    )
    .expect("valid configuration");
    let op = operation(400, "cafe");

    let error = governor
        .prepare(&harness.store, &harness.handle, &op)
        .err()
        .expect("wrong session");
    assert_eq!(error, GovernError::SessionMismatch);
}

#[test]
fn an_adapter_that_cannot_perform_the_configured_action_is_refused_at_wiring() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let hold_only = kern_execution::ExecutorDeclaration {
        supported_lapse_actions: kern_execution::LapseActionSet::none().with(LapseAction::Hold),
        ..declaration()
    };

    let error = ExecutionGovernor::<u64, _, _>::new(
        session(),
        GovernorConfig {
            lapse_action: LapseAction::Cancel,
            ..config()
        },
        clock,
        SequentialExecutionIds::new(),
        hold_only,
    )
    .err()
    .expect("cancel is not declared");

    assert_eq!(
        error,
        kern_execution::ConfigError::LapseActionUnsupported {
            required: LapseAction::Cancel
        }
    );
}

#[test]
fn zero_sized_configuration_is_refused() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let build = |config: GovernorConfig| {
        ExecutionGovernor::<u64, _, _>::new(
            session(),
            config,
            clock.clone(),
            SequentialExecutionIds::new(),
            declaration(),
        )
        .err()
    };

    assert_eq!(
        build(GovernorConfig {
            capacity: 0,
            ..config()
        }),
        Some(kern_execution::ConfigError::ZeroCapacity)
    );
    assert_eq!(
        build(GovernorConfig {
            journal_capacity: 0,
            ..config()
        }),
        Some(kern_execution::ConfigError::ZeroJournalCapacity)
    );
    assert_eq!(
        build(GovernorConfig {
            observation_budget: 0,
            ..config()
        }),
        Some(kern_execution::ConfigError::ZeroObservationBudget)
    );
    let _ = StartupPolicy::ReportOnly;
}
