//! Layer 1: conversion and command mapping. No governor, no backend, no ROS.

mod support;

use kern_execution_nav2::backend::{BackendDeclaration, SpeedControl};
use kern_execution_nav2::units::{mdeg_to_rad, mm_s_to_m_s, mm_to_m, yaw_quaternion};
use kern_execution_nav2::{
    navigate_schema, AdapterError, BackendEvent, CommandError, EventQueue, FakeNav2Backend,
    Nav2Config, Nav2Executor, Nav2OperationId, NavigateRequest,
};

const EPSILON: f64 = 1e-9;

#[test]
fn millimetres_convert_to_metres() {
    assert!((mm_to_m(4_000) - 4.0).abs() < EPSILON);
    assert!((mm_to_m(-1_250) + 1.25).abs() < EPSILON);
    assert!((mm_s_to_m_s(350) - 0.35).abs() < EPSILON);
}

#[test]
fn millidegrees_convert_to_radians() {
    assert!((mdeg_to_rad(90_000) - std::f64::consts::FRAC_PI_2).abs() < EPSILON);
    assert!((mdeg_to_rad(-180_000) + std::f64::consts::PI).abs() < EPSILON);
    assert!(mdeg_to_rad(0).abs() < EPSILON);
}

#[test]
fn yaw_becomes_a_planar_quaternion() {
    let (qz, qw) = yaw_quaternion(0.0);
    assert!(qz.abs() < EPSILON);
    assert!((qw - 1.0).abs() < EPSILON);

    // A quarter turn: z = w = sin(pi/4).
    let (qz, qw) = yaw_quaternion(std::f64::consts::FRAC_PI_2);
    assert!((qz - std::f64::consts::FRAC_1_SQRT_2).abs() < EPSILON);
    assert!((qw - std::f64::consts::FRAC_1_SQRT_2).abs() < EPSILON);

    // Every yaw stays a unit quaternion.
    for mdeg in [-180_000, -45_000, 0, 30_000, 179_999] {
        let (qz, qw) = yaw_quaternion(mdeg_to_rad(mdeg));
        assert!((qz * qz + qw * qw - 1.0).abs() < 1e-12, "{mdeg}");
    }
}

#[test]
fn a_navigate_command_converts_into_a_pose_goal() {
    let harness = support::Harness::new();
    let mut adapter = support::adapter(FakeNav2Backend::new());
    let mut governor = support::governor(harness.clock.clone(), &adapter);
    let operation = support::operation(350);

    governor
        .prepare(&harness.store, &harness.handle, &operation)
        .expect("authorized")
        .submit(&harness.store, &mut adapter);

    let goal = adapter.backend().sent.first().expect("one goal was sent");
    assert_eq!(goal.frame_id, "map");
    assert!((goal.x_m - 4.0).abs() < EPSILON);
    assert!((goal.y_m - 1.2).abs() < EPSILON);
    assert!((goal.yaw_rad - std::f64::consts::FRAC_PI_2).abs() < EPSILON);
    assert!((goal.qz - std::f64::consts::FRAC_1_SQRT_2).abs() < EPSILON);
    assert!((goal.qw - std::f64::consts::FRAC_1_SQRT_2).abs() < EPSILON);
    assert!((goal.max_speed_m_s - 0.35).abs() < EPSILON);
}

#[test]
fn the_schema_requires_every_parameter() {
    let schema = navigate_schema().expect("well-formed");
    let incomplete = kern_core::ActionProposal::new(
        support::subject(),
        support::device(),
        support::capability(),
    )
    .with_param(
        kern_core::ParamName::new(kern_execution_nav2::DESTINATION_X_MM),
        kern_core::ParamValue::Scalar(1_000),
    );

    assert!(schema.normalize(&incomplete).is_err());
}

#[test]
fn a_non_positive_speed_bound_is_refused() {
    // Built directly, because policy would never authorize it: the adapter must
    // refuse it on its own rather than trust its inputs.
    let request = NavigateRequest {
        destination_x_mm: 1_000,
        destination_y_mm: 0,
        yaw_mdeg: 0,
        max_speed_mm_s: 0,
    };
    assert_eq!(request.max_speed_mm_s, 0);

    let harness = support::Harness::new();
    let mut adapter = support::adapter(FakeNav2Backend::new());
    let mut governor = support::governor(harness.clock.clone(), &adapter);
    // Policy permits 0 mm/s (it is "at most 400"), so the refusal is the
    // adapter's, at the transport boundary, with nothing sent.
    let operation = support::operation(0);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &operation)
        .expect("authorized by policy and lease")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        kern_execution::ExecutionState::NotStarted(kern_execution::NotStartedReason::Rejected(
            kern_execution::RejectionReason::InvalidCommand
        ))
    );
    assert!(adapter.backend().sent.is_empty());
}

#[test]
fn a_command_error_names_what_was_wrong() {
    assert_eq!(
        CommandError::MissingParameter("yaw_mdeg").to_string(),
        "missing parameter yaw_mdeg"
    );
    assert_eq!(
        CommandError::WrongCapability.to_string(),
        "not a navigate command"
    );
}

/// The one construction that must fail closed.
#[test]
fn a_backend_that_cannot_bound_speed_is_refused_at_construction() {
    let backend = FakeNav2Backend::new().with_declaration(BackendDeclaration {
        speed_control: SpeedControl::None,
        confirms_cancellation: true,
        reports_terminal_results: true,
    });

    assert_eq!(
        Nav2Executor::new(backend, Nav2Config::default())
            .err()
            .expect("no speed control"),
        AdapterError::SpeedControlUnavailable
    );
}

#[test]
fn adapter_configuration_is_validated() {
    let config = Nav2Config {
        frame_id: String::from("map"),
        tracking_capacity: 0,
    };
    assert_eq!(
        Nav2Executor::new(FakeNav2Backend::new(), config)
            .err()
            .expect("zero capacity"),
        AdapterError::ZeroCapacity
    );

    let config = Nav2Config {
        frame_id: String::new(),
        tracking_capacity: 4,
    };
    assert_eq!(
        Nav2Executor::new(FakeNav2Backend::new(), config)
            .err()
            .expect("empty frame"),
        AdapterError::EmptyFrame
    );
}

#[test]
fn the_declaration_advertises_only_what_is_implemented() {
    use kern_execution::{Executor, LapseAction, ObservationOrdering};

    let adapter = support::adapter(FakeNav2Backend::new());
    let declaration = adapter.declaration();

    assert!(declaration
        .supported_lapse_actions
        .supports(LapseAction::Cancel));
    // Not implemented, therefore not advertised.
    assert!(!declaration
        .supported_lapse_actions
        .supports(LapseAction::Hold));
    assert!(!declaration
        .supported_lapse_actions
        .supports(LapseAction::Terminate));
    assert!(!declaration
        .supported_lapse_actions
        .supports(LapseAction::NoFurtherCommands));
    // Nav2 accepting a goal is not evidence the robot moved.
    assert!(!declaration.accept_implies_running);
    // Nav2 offers no field to carry a Kern identifier back.
    assert!(!declaration.echoes_execution_id);
    assert_eq!(declaration.ordering, ObservationOrdering::Sequenced);
}

#[test]
fn the_event_queue_is_bounded_and_reports_loss() {
    let mut queue = EventQueue::with_capacity(2);
    let operation = Nav2OperationId::from_uuid([1u8; 16]);

    for _ in 0..5 {
        queue.push(BackendEvent::Feedback { operation });
    }

    assert_eq!(queue.len(), 2);
    assert_eq!(queue.capacity(), 2);
    assert_eq!(queue.dropped(), 3);
    assert!(queue.lost());
    // Reported once, then cleared: one overflow is one loss report.
    assert!(queue.take_lost());
    assert!(!queue.take_lost());
    // The oldest events survive; the newest are the ones dropped.
    assert!(queue.pop().is_some());
    assert!(queue.pop().is_some());
    assert!(queue.pop().is_none());
}

#[test]
fn a_zero_capacity_queue_is_raised_to_one() {
    let queue = EventQueue::with_capacity(0);
    assert_eq!(queue.capacity(), 1);
    assert!(queue.is_empty());
}
