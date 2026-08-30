//! Applying what an adapter reports: ordering, disconnection, and contradictory
//! evidence.

mod support;

use kern_execution::{
    ExecutionState, FailureClass, LastKnown, ObservationOrdering, ObservationPoll, ObservedReport,
    ResolutionSource, ResolveDisputeError, SubmitOutcome, TerminalOutcome, TransitionKind,
    UnknownPhase,
};
use support::{
    config, declaration, governor, governor_with, observation, operation, sequenced, Harness,
    TestExecutor,
};

fn running_execution(
    harness: &Harness,
    governor: &mut support::Governor,
    executor: &mut TestExecutor,
) -> kern_execution::ExecutionId {
    let op = operation(400, "cafe");
    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, executor);
    receipt.execution_id()
}

#[test]
fn a_running_report_moves_a_submitted_execution_to_running() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut reporting = TestExecutor::new().poll(observation(100, ObservedReport::Running));
    let report = governor.tick_observed(&harness.store, &mut reporting);

    assert_eq!(report.observations_applied, 1);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Running
    );
}

/// Loss of observation is loss of knowledge, never evidence of failure.
#[test]
fn a_disconnect_during_a_running_operation_becomes_unknown_and_never_failed() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Running))
        .poll(ObservationPoll::Disconnected);
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.entered_unknown, 1);
    assert!(matches!(
        governor.link(),
        kern_execution::LinkState::Disconnected { .. }
    ));
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Result,
            last_known: LastKnown::Running,
        }
    );
}

/// A restored link is not evidence about a machine: it resolves nothing.
#[test]
fn reconnecting_does_not_resolve_an_unknown_execution() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new().poll(ObservationPoll::Disconnected);
    governor.tick_observed(&harness.store, &mut adapter);

    let mut quiet = TestExecutor::new();
    governor.tick_observed(&harness.store, &mut quiet);

    assert_eq!(governor.link(), kern_execution::LinkState::Connected);
    assert!(governor.record(execution).unwrap().execution().is_unknown());
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::LinkRestored));
}

/// A lost submission carries no operation identity, so a disconnect adds nothing
/// to what is already unknown about it.
#[test]
fn a_disconnect_does_not_disturb_a_lost_submission() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Unknown);
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new().poll(ObservationPoll::Disconnected);
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.entered_unknown, 0);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: LastKnown::Prepared,
        }
    );
}

#[test]
fn a_sequenced_adapter_drops_out_of_order_reports() {
    let harness = Harness::new();
    let sequenced_declaration = kern_execution::ExecutorDeclaration {
        ordering: ObservationOrdering::Sequenced,
        ..declaration()
    };
    let mut governor = governor_with(harness.clock.clone(), config(), sequenced_declaration);
    let mut executor = TestExecutor::new().with_declaration(sequenced_declaration);
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .with_declaration(sequenced_declaration)
        .poll(sequenced(100, ObservedReport::Running, 7))
        .poll(sequenced(100, ObservedReport::Completed, 3));
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.observations_applied, 1);
    assert_eq!(report.observations_dropped_stale, 1);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Running
    );
}

/// Without a declared order, the state lattice decides: a running report after a
/// terminal one is a report about the past.
#[test]
fn a_running_report_after_a_terminal_result_is_dropped() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Completed))
        .poll(observation(100, ObservedReport::Running));
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.observations_dropped_stale, 1);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Completed
    );
}

#[test]
fn a_repeated_terminal_report_changes_nothing() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Completed))
        .poll(observation(100, ObservedReport::Completed));
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.disputes_opened, 0);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Completed
    );
}

/// Contradictory terminal evidence is not resolved by Kern, and cannot be
/// consumed as a plain result by a caller that forgets to check a flag.
#[test]
fn contradictory_terminal_reports_produce_a_dispute() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Completed))
        .poll(observation(
            100,
            ObservedReport::Failed(FailureClass::OperationFailed),
        ))
        .poll(observation(100, ObservedReport::Cancelled));
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.disputes_opened, 1);
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Disputed {
            first: TerminalOutcome::Completed,
            conflicting: TerminalOutcome::Failed(FailureClass::OperationFailed),
        }
    );
    // Later reports do not rewrite the recorded contradiction.
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::DisputeObservedAgain));
}

#[test]
fn a_dispute_is_left_only_by_explicit_attribution() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Completed))
        .poll(observation(100, ObservedReport::Cancelled));
    governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(
        governor.resolve_dispute(
            execution,
            TerminalOutcome::Completed,
            ResolutionSource::OperatorAttested
        ),
        Ok(())
    );
    assert_eq!(
        governor.record(execution).unwrap().execution(),
        ExecutionState::Completed
    );

    // Resolution settles contradictions; it is not a way to overwrite an
    // undisputed result.
    assert_eq!(
        governor.resolve_dispute(
            execution,
            TerminalOutcome::Cancelled,
            ResolutionSource::ExecutorReconciliation
        ),
        Err(ResolveDisputeError::NotDisputed)
    );
    assert_eq!(
        governor.resolve_dispute(
            kern_execution::ExecutionId::from_u128(9_999),
            TerminalOutcome::Completed,
            ResolutionSource::OperatorAttested
        ),
        Err(ResolveDisputeError::NoSuchExecution)
    );
}

#[test]
fn an_observation_for_an_unknown_operation_is_recorded_and_ignored() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut adapter = TestExecutor::new().poll(observation(777, ObservedReport::Completed));

    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.observations_unmatched, 1);
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::UnmatchedObservation));
}

/// Journal overflow costs provenance detail and nothing else.
#[test]
fn journal_overflow_never_suppresses_authority_behaviour() {
    let harness = Harness::new();
    let mut governor = governor_with(
        harness.clock.clone(),
        kern_execution::GovernorConfig {
            journal_capacity: 1,
            ..config()
        },
        declaration(),
    );
    let mut executor = TestExecutor::new();
    let execution = running_execution(&harness, &mut governor, &mut executor);

    harness.clock.advance(support::LEASE_TTL_MS + 1);
    let report = governor.tick(&harness.store, &mut executor);

    assert!(report.journal_overflowed);
    assert!(governor.dropped_transitions() > 0);
    // The lapse still happened, and the executor was still instructed.
    assert_eq!(report.lapses_detected, 1);
    assert_eq!(report.lapse_requests_issued, 1);
    assert_eq!(executor.lapse_count(), 1);
    assert!(governor.record(execution).unwrap().authority().is_lapsed());
}

/// The observation budget bounds one pass, so a chatty adapter cannot starve the
/// lapse pass.
#[test]
fn the_observation_budget_bounds_one_pass() {
    let harness = Harness::new();
    let mut governor = governor_with(
        harness.clock.clone(),
        kern_execution::GovernorConfig {
            observation_budget: 2,
            ..config()
        },
        declaration(),
    );
    let mut executor = TestExecutor::new();
    running_execution(&harness, &mut governor, &mut executor);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Running))
        .poll(observation(100, ObservedReport::Running))
        .poll(observation(100, ObservedReport::Completed));
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.observations_applied, 2);
    assert_eq!(
        governor.records().next().unwrap().execution(),
        ExecutionState::Running
    );
}
