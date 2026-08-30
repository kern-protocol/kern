//! Authority lapse while an operation is already running.
//!
//! Every assertion here is about what Kern *asked* and *recorded*. None is about
//! whether a machine stopped: Kern cannot establish that, and nothing in the
//! crate claims it.

mod support;

use kern_core::{TestMonotonicClock, Uptime};
use kern_execution::{
    AuthorityLapseReason, CancelRefusal, CancelRequestOutcome, CancellationState, ExecutionState,
    LapseAction, ObservedReport, SubmitOutcome, TerminalOutcome, TransitionKind,
};
use support::{
    governor, install, observation, operation, other_session, session, store_for, Harness,
    TestExecutor, LEASE_TTL_MS, START_UPTIME_MS,
};

/// The centre of the phase: expiry during a running operation lapses authority,
/// instructs the executor, and leaves the execution running until evidence says
/// otherwise.
#[test]
fn expiry_during_a_running_operation_lapses_authority_and_instructs_the_executor() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().poll(observation(100, ObservedReport::Running));
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);
    governor.tick_observed(&harness.store, &mut executor);
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().execution(),
        ExecutionState::Running
    );

    harness.clock.advance(LEASE_TTL_MS + 1);
    let report = governor.tick_observed(&harness.store, &mut executor);

    assert_eq!(report.lapses_detected, 1);
    assert_eq!(report.lapse_requests_issued, 1);
    assert_eq!(
        executor.lapse_calls,
        vec![(100, LapseAction::Cancel, AuthorityLapseReason::LeaseExpired)]
    );

    let record = governor.record(receipt.execution_id()).expect("recorded");
    // Authority is gone. The execution is still, as far as anyone knows, running.
    assert_eq!(
        record.authority().lapse_reason(),
        Some(AuthorityLapseReason::LeaseExpired)
    );
    assert_eq!(record.execution(), ExecutionState::Running);
    assert!(matches!(
        record.cancellation(),
        CancellationState::RequestAccepted { .. }
    ));
}

#[test]
fn a_lapse_instruction_is_issued_at_most_once() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    harness.clock.advance(LEASE_TTL_MS + 1);
    for _ in 0..5 {
        governor.tick(&harness.store, &mut executor);
    }

    assert_eq!(executor.lapse_count(), 1);
}

#[test]
fn supersession_lapses_the_older_execution_without_adopting_it() {
    let mut harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);
    let newer = harness.supersede(300);

    let report = governor.tick(&harness.store, &mut executor);

    assert_eq!(report.lapses_detected, 1);
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert_eq!(
        record.authority().lapse_reason(),
        Some(AuthorityLapseReason::Superseded)
    );
    assert_eq!(record.handle().lease_id(), harness.handle.lease_id());
    assert_ne!(record.handle().lease_id(), newer.lease_id());
    assert_eq!(
        executor.lapse_calls,
        vec![(100, LapseAction::Cancel, AuthorityLapseReason::Superseded)]
    );
}

/// One operation the adapter cannot handle must not suppress lapse handling for
/// the others.
#[test]
fn one_broken_operation_does_not_abort_the_lapse_pass() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().lapse_override(101, CancelRequestOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipts: Vec<_> = (0..3)
        .map(|_| {
            governor
                .prepare(&harness.store, &harness.handle, &op)
                .expect("authorized")
                .submit(&harness.store, &mut executor)
        })
        .collect();

    harness.clock.advance(LEASE_TTL_MS + 1);
    let report = governor.tick(&harness.store, &mut executor);

    assert_eq!(report.lapses_detected, 3);
    assert_eq!(report.lapse_requests_issued, 3);
    assert_eq!(
        executor
            .lapse_calls
            .iter()
            .map(|call| call.0)
            .collect::<Vec<_>>(),
        vec![100, 101, 102]
    );
    // The broken one records uncertainty; its neighbours are unaffected.
    assert_eq!(
        governor
            .record(receipts[1].execution_id())
            .unwrap()
            .cancellation(),
        CancellationState::RequestUnknown
    );
    for index in [0, 2] {
        assert!(matches!(
            governor
                .record(receipts[index].execution_id())
                .unwrap()
                .cancellation(),
            CancellationState::RequestAccepted { .. }
        ));
    }
}

/// A lost submission leaves no operation identity, so there is nothing to
/// instruct — and Kern says so rather than inventing a target.
#[test]
fn a_lapse_without_an_operation_identity_instructs_nothing() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().script_submit(SubmitOutcome::Unknown);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    harness.clock.advance(LEASE_TTL_MS + 1);
    let report = governor.tick(&harness.store, &mut executor);

    assert_eq!(report.lapses_detected, 1);
    assert_eq!(report.lapse_requests_issued, 0);
    assert_eq!(report.lapse_skipped_no_operation, 1);
    assert_eq!(executor.lapse_count(), 0);
    assert!(governor
        .journal()
        .iter()
        .any(|entry| entry.kind == TransitionKind::LapseNotRequestedNoOperation));
    let record = governor.record(receipt.execution_id()).expect("recorded");
    assert!(record.authority().is_lapsed());
    assert!(record.execution().is_unknown());
}

#[test]
fn a_refused_cancellation_is_recorded_as_refused() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new().lapse_default(CancelRequestOutcome::Unsupported);
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    harness.clock.advance(LEASE_TTL_MS + 1);
    governor.tick(&harness.store, &mut executor);

    assert_eq!(
        governor
            .record(receipt.execution_id())
            .unwrap()
            .cancellation(),
        CancellationState::Refused(CancelRefusal::Unsupported)
    );
}

/// A cancellation request is not a cancellation. Only an observation confirms
/// one.
#[test]
fn cancellation_is_confirmed_only_by_an_observation() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    harness.clock.advance(LEASE_TTL_MS + 1);
    governor.tick(&harness.store, &mut executor);
    let record = governor.record(receipt.execution_id()).unwrap();
    assert!(matches!(
        record.cancellation(),
        CancellationState::RequestAccepted { .. }
    ));
    assert_ne!(record.execution(), ExecutionState::Cancelled);

    let mut confirming = TestExecutor::new().poll(observation(100, ObservedReport::Cancelled));
    governor.tick_observed(&harness.store, &mut confirming);

    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(record.execution(), ExecutionState::Cancelled);
    assert!(matches!(
        record.cancellation(),
        CancellationState::Confirmed { .. }
    ));
}

/// Completion racing a cancellation request: the completion stands and the
/// request becomes moot. Kern does not rewrite one into the other.
#[test]
fn completion_after_a_cancellation_request_makes_the_request_moot() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    harness.clock.advance(LEASE_TTL_MS + 1);
    governor.tick(&harness.store, &mut executor);

    let mut completing = TestExecutor::new().poll(observation(100, ObservedReport::Completed));
    // The record already holds operation 100 from the first adapter.
    governor.tick_observed(&harness.store, &mut completing);

    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(record.execution(), ExecutionState::Completed);
    assert_eq!(record.cancellation(), CancellationState::Moot);
    // The completion is recorded alongside the lapse, not judged against it.
    assert!(record.authority().is_lapsed());
    assert!(record.terminal_observed_at().is_some());
    let _ = TerminalOutcome::Completed;
}

/// A store from another session holds no authority for these executions, which
/// is what AuthorityMissing means. The wiring fault is reported too.
#[test]
fn a_store_from_another_session_lapses_everything_as_authority_missing() {
    let harness = Harness::new();
    let mut governor = governor(harness.clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut executor);

    let fresh_clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let other = store_for(other_session(), fresh_clock);
    let report = governor.tick(&other, &mut executor);

    assert!(report.session_mismatch);
    assert_eq!(report.lapses_detected, 1);
    assert_eq!(
        governor
            .record(receipt.execution_id())
            .unwrap()
            .authority()
            .lapse_reason(),
        Some(AuthorityLapseReason::AuthorityMissing)
    );
}

/// A backwards clock makes lifetime accounting untrustworthy, so authority
/// lapses in the fail-closed direction.
#[test]
fn a_backwards_clock_lapses_authority() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
    let mut store = store_for(session(), clock.clone());
    let mut issuer = support::issuer();
    let handle = install(&mut store, &mut issuer, 400, "cafe", LEASE_TTL_MS);
    let mut governor = governor(clock.clone());
    let mut executor = TestExecutor::new();
    let op = operation(400, "cafe");

    let receipt = governor
        .prepare(&store, &handle, &op)
        .expect("authorized")
        .submit(&store, &mut executor);

    clock.set(Uptime::from_millis(START_UPTIME_MS - 500));
    governor.tick(&store, &mut executor);

    assert_eq!(
        governor
            .record(receipt.execution_id())
            .unwrap()
            .authority()
            .lapse_reason(),
        Some(AuthorityLapseReason::ClockUntrusted)
    );
}
