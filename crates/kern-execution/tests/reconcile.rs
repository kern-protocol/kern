//! Recovering — and failing to recover — from lost knowledge.

mod support;

use kern_execution::{
    ExecutionObservation, ExecutionState, ExecutorDeclaration, GovernorConfig, LastKnown,
    ObservedReport, QueryOutcome, ReconcileOutcome, ReconcileReport, StartupPolicy, SubmitOutcome,
    TransitionKind, UnknownPhase,
};
use support::{
    config, declaration, governor, governor_with, observation, operation, Harness, TestExecutor,
};

fn echoing() -> ExecutorDeclaration {
    ExecutorDeclaration {
        echoes_execution_id: true,
        ..declaration()
    }
}

/// The only route out of a lost submission acknowledgement.
#[test]
fn an_echoed_identifier_rebinds_a_lost_submission() {
    let harness = Harness::new();
    let mut governor = governor_with(harness.clock.clone(), config(), echoing());
    let mut executor = TestExecutor::new()
        .with_declaration(echoing())
        .script_submit(SubmitOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);
    assert_eq!(
        receipt.state(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: LastKnown::Prepared,
        }
    );

    let mut adapter =
        TestExecutor::new()
            .with_declaration(echoing())
            .reconcile(ReconcileOutcome::Report(ReconcileReport {
                discovered: vec![(55, Some(receipt.execution_id()))],
                complete: true,
            }));
    let summary = governor.reconcile(&mut adapter);

    assert_eq!(summary.resolved, 1);
    assert_eq!(summary.unattributed, 0);
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert_eq!(record.operation(), Some(&55));
    assert_eq!(record.execution(), ExecutionState::Running);
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::UnknownResolvedByReconcile));
}

/// Without a declared echo there is no correlation data, so the record stays
/// unknown — there is no heuristic that would be honest here.
#[test]
fn without_a_declared_echo_a_lost_submission_stays_unknown() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    let mut adapter = TestExecutor::new().reconcile(ReconcileOutcome::Report(ReconcileReport {
        discovered: vec![(55, Some(receipt.execution_id()))],
        complete: true,
    }));
    let summary = governor.reconcile(&mut adapter);

    assert_eq!(summary.resolved, 0);
    assert_eq!(summary.unattributed, 1);
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().execution(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: LastKnown::Prepared,
        }
    );
}

/// After a restart there are no records at all, so nothing discovered can be
/// attributed to a subject or a lease. Kern refuses to invent provenance for it.
#[test]
fn a_fresh_session_leaves_discovered_operations_unattributed() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut adapter = TestExecutor::new().reconcile(ReconcileOutcome::Report(ReconcileReport {
        discovered: vec![(11, None), (12, None)],
        complete: true,
    }));

    let summary = governor.reconcile(&mut adapter);

    assert_eq!(summary.unattributed, 2);
    assert_eq!(summary.attributed, 0);
    assert_eq!(governor.records().count(), 0);
    // A fresh session holds no authority for them, which is literally the
    // reason passed to the executor.
    assert_eq!(
        adapter
            .lapse_calls
            .iter()
            .map(|call| (call.0, call.2))
            .collect::<Vec<_>>(),
        vec![
            (11, kern_execution::AuthorityLapseReason::AuthorityMissing),
            (12, kern_execution::AuthorityLapseReason::AuthorityMissing),
        ]
    );
    let _ = &harness;
}

#[test]
fn report_only_startup_instructs_nothing() {
    let harness = Harness::new();
    let mut governor = governor_with(
        harness.clock.clone(),
        GovernorConfig {
            startup_policy: StartupPolicy::ReportOnly,
            ..config()
        },
        declaration(),
    );
    let mut adapter = TestExecutor::new().reconcile(ReconcileOutcome::Report(ReconcileReport {
        discovered: vec![(11, None)],
        complete: true,
    }));

    let summary = governor.reconcile(&mut adapter);

    assert_eq!(summary.unattributed, 1);
    assert_eq!(summary.lapse_requests_issued, 0);
    assert_eq!(adapter.lapse_count(), 0);
    assert!(governor
        .journal()
        .iter()
        .any(|entry| matches!(entry.kind, TransitionKind::ReconciliationDiscovered { .. })));
}

/// An incomplete enumeration proves nothing about what it did not list.
#[test]
fn an_incomplete_enumeration_resolves_nothing_by_omission() {
    let harness = Harness::new();
    let mut governor = governor_with(harness.clock.clone(), config(), echoing());
    let mut executor = TestExecutor::new()
        .with_declaration(echoing())
        .script_submit(SubmitOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    let mut adapter =
        TestExecutor::new()
            .with_declaration(echoing())
            .reconcile(ReconcileOutcome::Report(ReconcileReport {
                discovered: vec![],
                complete: false,
            }));
    let summary = governor.reconcile(&mut adapter);

    assert!(!summary.complete);
    assert_eq!(summary.resolved, 0);
    assert!(governor
        .record(receipt.execution_id())
        .unwrap()
        .execution()
        .is_unknown());
}

#[test]
fn an_adapter_that_cannot_enumerate_says_so() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut adapter = TestExecutor::new();

    let summary = governor.reconcile(&mut adapter);

    assert!(!summary.supported);
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::ReconciliationUnsupported));
}

#[test]
fn an_already_matched_operation_is_attributed_not_relapsed() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    let mut adapter = TestExecutor::new().reconcile(ReconcileOutcome::Report(ReconcileReport {
        discovered: vec![(100, None)],
        complete: true,
    }));
    let summary = governor.reconcile(&mut adapter);

    assert_eq!(summary.attributed, 1);
    assert_eq!(summary.unattributed, 0);
    assert_eq!(adapter.lapse_count(), 0);
}

/// Querying reaches executions Kern holds an operation identity for, and only
/// those.
#[test]
fn a_query_resolves_a_lost_result_but_never_a_lost_submission() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let running = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);
    let mut unknown_submission = TestExecutor::new().script_submit(SubmitOutcome::Unknown);
    let lost = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut unknown_submission);

    let mut adapter = TestExecutor::new()
        .poll(observation(100, ObservedReport::Running))
        .poll(kern_execution::ObservationPoll::Disconnected);
    governor.tick_observed(&harness.store, &mut adapter);
    assert!(governor
        .record(running.execution_id())
        .unwrap()
        .execution()
        .is_unknown());

    let mut answering = TestExecutor::new().query(
        100,
        QueryOutcome::Observed(ExecutionObservation {
            operation: 100,
            report: ObservedReport::Completed,
            sequence: None,
        }),
    );
    let resolved = governor.query_unknown(&mut answering);

    assert_eq!(resolved, 1);
    assert_eq!(
        governor.record(running.execution_id()).unwrap().execution(),
        ExecutionState::Completed
    );
    // The lost submission has no operation identity to ask about.
    assert_eq!(
        governor.record(lost.execution_id()).unwrap().execution(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: LastKnown::Prepared,
        }
    );
}
