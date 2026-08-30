//! Layer 2: the governor driving the real adapter against a deterministic
//! backend. Everything the ROS bridge will do, minus ROS.

mod support;

use kern_execution::{
    AuthorityLapseReason, CancellationState, ExecutionState, FailureClass, LastKnown, LinkState,
    NotStartedReason, ObservationPoll, RejectionReason, UnknownPhase,
};
use kern_execution_nav2::backend::{BackendEvent, CancelSend, SendGoal, SpeedLimitOutcome};
use kern_execution_nav2::{FakeNav2Backend, Nav2OperationId};
use support::{adapter, governor, operation, Harness, LEASE_TTL_MS, POLICY_MAX_SPEED_MM_S};

const FIRST_GOAL: Nav2OperationId =
    Nav2OperationId::from_uuid([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

/// Demo A, in miniature: authority is live, Nav2 accepts, the robot runs, the
/// goal completes.
#[test]
fn an_authorized_navigation_runs_to_completion() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(300);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    assert_eq!(receipt.state(), ExecutionState::Submitted);
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().operation(),
        Some(&FIRST_GOAL)
    );

    adapter.backend_mut().emit(BackendEvent::Feedback {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().execution(),
        ExecutionState::Running
    );

    adapter.backend_mut().emit(BackendEvent::Succeeded {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);

    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(record.execution(), ExecutionState::Completed);
    assert_eq!(record.authority(), kern_execution::AuthorityState::Current);
    // The bound was applied before the goal and released after it.
    assert_eq!(adapter.backend().speed_limits, vec![Some(0.3), None]);
}

/// The frozen submit-time check, through the real adapter: no goal, no speed
/// limit, no transport call of any kind.
#[test]
fn authority_lost_before_submit_reaches_no_ros_call() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(300);

    let prepared = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized");
    harness.clock.advance(LEASE_TTL_MS + 1);
    let receipt = prepared.submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::AuthorityLost(
            AuthorityLapseReason::LeaseExpired
        ))
    );
    assert!(!receipt.executor_invoked());
    assert!(adapter.backend().sent.is_empty());
    assert!(adapter.backend().speed_limits.is_empty());
    assert!(adapter.backend().cancelled.is_empty());
}

/// The killer demo, as a test: expiry mid-navigation.
#[test]
fn expiry_mid_navigation_lapses_authority_and_cancels_once() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(300);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    adapter.backend_mut().emit(BackendEvent::Feedback {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);

    harness.clock.advance(LEASE_TTL_MS + 1);
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.lapses_detected, 1);
    assert_eq!(report.lapse_requests_issued, 1);
    assert_eq!(adapter.backend().cancelled, vec![FIRST_GOAL]);

    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(
        record.authority().lapse_reason(),
        Some(AuthorityLapseReason::LeaseExpired)
    );
    // Authority is gone; the robot is still, as far as anyone knows, navigating.
    assert_eq!(record.execution(), ExecutionState::Running);
    // A cancel acknowledgement is not a cancellation.
    assert!(matches!(
        record.cancellation(),
        CancellationState::RequestAccepted { .. }
    ));
    assert_ne!(record.execution(), ExecutionState::Cancelled);

    // Repeated ticks must not re-ask.
    for _ in 0..3 {
        governor.tick_observed(&harness.store, &mut adapter);
    }
    assert_eq!(adapter.backend().cancelled.len(), 1);

    // Only Nav2 reporting CANCELED makes it cancelled.
    adapter.backend_mut().emit(BackendEvent::Canceled {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);
    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(record.execution(), ExecutionState::Cancelled);
    assert!(matches!(
        record.cancellation(),
        CancellationState::Confirmed { .. }
    ));
}

/// Demo C: a newer lease lapses the old execution and does not adopt it.
#[test]
fn supersession_cancels_the_old_goal_exactly_once_and_adopts_nothing() {
    let mut harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(300);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    let newer = harness.supersede();

    for _ in 0..3 {
        governor.tick_observed(&harness.store, &mut adapter);
    }

    assert_eq!(adapter.backend().cancelled, vec![FIRST_GOAL]);
    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(
        record.authority().lapse_reason(),
        Some(AuthorityLapseReason::Superseded)
    );
    assert_eq!(record.handle().lease_id(), harness.handle.lease_id());
    assert_ne!(record.handle().lease_id(), newer.lease_id());

    // The new authority may run its own execution; it never inherits the old.
    adapter.backend_mut().emit(BackendEvent::Canceled {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);
    let second = governor
        .prepare(&harness.store, &newer, &op)
        .expect("authorized under the newer lease")
        .submit(&harness.store, &mut adapter);
    assert_ne!(second.execution_id(), receipt.execution_id());
    assert_eq!(
        governor
            .record(second.execution_id())
            .unwrap()
            .handle()
            .lease_id(),
        newer.lease_id()
    );
}

#[test]
fn an_aborted_goal_is_failed_not_unknown() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    adapter.backend_mut().emit(BackendEvent::Aborted {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().execution(),
        ExecutionState::Failed(FailureClass::OperationFailed)
    );
}

#[test]
fn an_explicit_goal_rejection_starts_nothing_and_releases_the_limit() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new().script_send(SendGoal::Rejected {
        reason: RejectionReason::Refused,
    }));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::Rejected(RejectionReason::Refused))
    );
    assert!(receipt.executor_invoked());
    assert_eq!(adapter.backend().speed_limits, vec![Some(0.3), None]);
}

/// A speed limit that did not land means no goal is sent — which is a rejection
/// the adapter can prove.
#[test]
fn a_speed_limit_that_cannot_be_applied_prevents_the_goal() {
    let harness = Harness::new();
    let mut adapter =
        adapter(FakeNav2Backend::new().script_speed_limit(SpeedLimitOutcome::NotDelivered));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(NotStartedReason::Rejected(RejectionReason::Unavailable))
    );
    assert!(adapter.backend().sent.is_empty());
}

/// Evidence that `max_speed_mm_s` is not decoration.
#[test]
fn the_authorized_speed_bound_is_applied_to_the_controller() {
    for (mm_s, expected) in [(150_i64, 0.15_f64), (350, 0.35)] {
        let harness = Harness::new();
        let mut adapter = adapter(FakeNav2Backend::new());
        let mut governor = governor(harness.clock.clone(), &adapter);

        governor
            .prepare(&harness.store, &harness.handle, &operation(mm_s))
            .expect("authorized")
            .submit(&harness.store, &mut adapter);

        assert_eq!(adapter.backend().speed_limits, vec![Some(expected)]);
        let goal = adapter.backend().sent.first().expect("sent");
        assert!((goal.max_speed_m_s - expected).abs() < 1e-9);
        assert!(mm_s <= POLICY_MAX_SPEED_MM_S);
    }
}

#[test]
fn an_ambiguous_goal_send_is_unknown_and_is_never_resubmitted() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new().script_send(SendGoal::Unknown));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Submission,
            last_known: LastKnown::Prepared,
        }
    );
    // The limit stays applied: a goal may be running under it.
    assert_eq!(adapter.backend().speed_limits, vec![Some(0.3)]);

    harness.clock.advance(LEASE_TTL_MS + 1);
    for _ in 0..5 {
        governor.tick_observed(&harness.store, &mut adapter);
    }

    assert_eq!(adapter.backend().sent.len(), 1);
    // No operation identity exists, so there is nothing to cancel.
    assert!(adapter.backend().cancelled.is_empty());
    assert!(governor
        .record(receipt.execution_id())
        .unwrap()
        .execution()
        .is_unknown());
}

#[test]
fn a_disconnect_during_navigation_is_unknown_never_failed() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    adapter.backend_mut().emit(BackendEvent::Feedback {
        operation: FIRST_GOAL,
    });
    governor.tick_observed(&harness.store, &mut adapter);

    adapter.backend_mut().disconnect();
    let report = governor.tick_observed(&harness.store, &mut adapter);

    assert_eq!(report.entered_unknown, 1);
    assert!(matches!(governor.link(), LinkState::Disconnected { .. }));
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().execution(),
        ExecutionState::Unknown {
            phase: UnknownPhase::Result,
            last_known: LastKnown::Running,
        }
    );
}

#[test]
fn cancelling_while_disconnected_is_request_unknown() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new().script_cancel(CancelSend::Disconnected));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    adapter.backend_mut().disconnect();
    harness.clock.advance(LEASE_TTL_MS + 1);
    governor.tick_observed(&harness.store, &mut adapter);

    let record = governor.record(receipt.execution_id()).unwrap();
    assert_eq!(record.cancellation(), CancellationState::RequestUnknown);
    assert!(record.authority().is_lapsed());
    // Asked once, and not asked again.
    assert_eq!(adapter.backend().cancelled.len(), 1);
    governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(adapter.backend().cancelled.len(), 1);
}

/// A full queue means Kern's picture is incomplete, not that anything failed.
#[test]
fn dropped_events_become_loss_of_knowledge() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new().with_queue_capacity(1));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    for _ in 0..4 {
        adapter.backend_mut().emit(BackendEvent::Feedback {
            operation: FIRST_GOAL,
        });
    }
    assert!(adapter.backend().dropped_events() > 0);

    let report = governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(report.entered_unknown, 1);
    assert!(governor
        .record(receipt.execution_id())
        .unwrap()
        .execution()
        .is_unknown());
}

/// A dead worker surfaces as lost observation, never as a machine result.
#[test]
fn a_failed_worker_becomes_disconnected_not_failed() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    adapter.backend_mut().fail_worker();
    governor.tick_observed(&harness.store, &mut adapter);

    let state = governor.record(receipt.execution_id()).unwrap().execution();
    assert!(state.is_unknown(), "{state:?}");
    assert_ne!(state, ExecutionState::Failed(FailureClass::OperationFailed));
}

#[test]
fn a_second_concurrent_goal_is_refused_with_nothing_sent() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    let second = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        second.state(),
        ExecutionState::NotStarted(NotStartedReason::Rejected(RejectionReason::Busy))
    );
    assert_eq!(adapter.backend().sent.len(), 1);
}

#[test]
fn the_observation_budget_is_respected() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new().with_queue_capacity(32));
    let mut governor = governor(harness.clock.clone(), &adapter);

    governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    for _ in 0..20 {
        adapter.backend_mut().emit(BackendEvent::Feedback {
            operation: FIRST_GOAL,
        });
    }

    // The configured budget is 8.
    let report = governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(report.observations_applied, 8);
}

#[test]
fn shutdown_releases_the_speed_limit_and_the_transport() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);
    adapter.shutdown();

    assert_eq!(adapter.backend().shutdowns, 1);
    assert_eq!(adapter.backend().speed_limits, vec![Some(0.3), None]);
    // Idempotent.
    adapter.shutdown();
    assert_eq!(adapter.backend().shutdowns, 2);
    assert_eq!(adapter.backend().speed_limits.len(), 2);
}

/// Simulation time is not authority time. Advancing the robot's clock does
/// nothing to a lease; only the enforcer's monotonic clock does.
#[test]
fn simulation_time_cannot_move_a_lease_deadline() {
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation(300))
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    // An hour of simulated time, and a paused, rewound one for good measure.
    adapter.backend_mut().sim_time_ms = 3_600_000;
    let report = governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(report.lapses_detected, 0);
    assert_eq!(
        governor.record(receipt.execution_id()).unwrap().authority(),
        kern_execution::AuthorityState::Current
    );
    adapter.backend_mut().sim_time_ms = 0;
    assert_eq!(
        governor
            .tick_observed(&harness.store, &mut adapter)
            .lapses_detected,
        0
    );

    // Kern's own clock is the only thing that ends authority.
    harness.clock.advance(LEASE_TTL_MS + 1);
    assert_eq!(
        governor
            .tick_observed(&harness.store, &mut adapter)
            .lapses_detected,
        1
    );
}

#[test]
fn an_idle_backend_reports_idle() {
    use kern_execution::{Executor, ExecutorObservations};

    let mut adapter = adapter(FakeNav2Backend::new());
    assert!(matches!(
        adapter.poll_observation(),
        ObservationPoll::<Nav2OperationId>::Idle
    ));
    assert!(adapter.declaration().confirms_cancellation);
}
