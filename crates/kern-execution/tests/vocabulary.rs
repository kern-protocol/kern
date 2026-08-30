//! Identity and naming: the pieces provenance is built from.

mod support;

use kern_execution::{
    AuthorityLapseReason, CommandDigest, ExecutionId, ExecutionIdError, ExecutionIdSource,
    ExecutionState, FailureClass, NotStartedReason, RejectionReason, SequentialExecutionIds,
    TerminalOutcome,
};
use support::{navigate_proposal, navigate_schema, operation};

#[test]
fn execution_identifiers_are_emitted_once_and_never_wrap() {
    let mut ids = SequentialExecutionIds::starting_at(u128::MAX - 1);

    assert_eq!(
        ids.next_execution_id(),
        Ok(ExecutionId::from_u128(u128::MAX - 1))
    );
    assert_eq!(
        ids.next_execution_id(),
        Ok(ExecutionId::from_u128(u128::MAX))
    );
    // Exhausted, and it stays exhausted rather than returning to the start.
    for _ in 0..3 {
        assert_eq!(ids.next_execution_id(), Err(ExecutionIdError::Exhausted));
    }
}

#[test]
fn a_default_source_starts_at_zero_rather_than_exhausted() {
    let mut ids = SequentialExecutionIds::default();
    assert_eq!(ids.next_execution_id(), Ok(ExecutionId::from_u128(0)));
}

/// Frozen: the digest names an operation, so changing the construction changes
/// what every stored provenance record refers to.
#[test]
fn the_command_digest_is_a_golden_vector() {
    let digest = CommandDigest::compute(&operation(400, "cafe")).expect("encodes");

    assert_eq!(
        digest.as_bytes(),
        &[
            0x85, 0x4a, 0x6e, 0x9e, 0x0a, 0x49, 0xc6, 0xc5, 0x40, 0x91, 0xb5, 0xd4, 0x09, 0xa4,
            0xb4, 0x08, 0xdd, 0xcd, 0x40, 0x4d, 0x9b, 0x2d, 0x8f, 0x46, 0x1a, 0xd8, 0x0d, 0x2c,
            0xa6, 0x9d, 0x5c, 0xb3,
        ]
    );
}

#[test]
fn the_command_digest_distinguishes_every_field() {
    let base = CommandDigest::compute(&operation(400, "cafe")).expect("encodes");

    assert_ne!(
        base,
        CommandDigest::compute(&operation(401, "cafe")).expect("encodes")
    );
    assert_ne!(
        base,
        CommandDigest::compute(&operation(400, "lobby")).expect("encodes")
    );
    // Identical inputs digest identically, which is what lets a host prove a
    // stored operation is the one that was authorized.
    assert_eq!(
        base,
        CommandDigest::compute(&operation(400, "cafe")).expect("encodes")
    );
}

#[test]
fn a_missing_optional_parameter_digests_differently_from_a_supplied_one() {
    let full = navigate_schema()
        .normalize(&navigate_proposal(400, "cafe"))
        .expect("schema-valid");
    let other = navigate_schema()
        .normalize(&navigate_proposal(400, "kitchen"))
        .expect("schema-valid");

    assert_ne!(
        CommandDigest::compute(&full).expect("encodes"),
        CommandDigest::compute(&other).expect("encodes")
    );
}

#[test]
fn terminal_states_are_terminal_and_not_started_reports_no_machine_result() {
    let terminal = [
        ExecutionState::Completed,
        ExecutionState::Failed(FailureClass::OperationFailed),
        ExecutionState::Cancelled,
        ExecutionState::NotStarted(NotStartedReason::Abandoned),
        ExecutionState::NotStarted(NotStartedReason::Rejected(RejectionReason::Busy)),
        ExecutionState::NotStarted(NotStartedReason::AuthorityLost(
            AuthorityLapseReason::LeaseExpired,
        )),
        ExecutionState::Disputed {
            first: TerminalOutcome::Completed,
            conflicting: TerminalOutcome::Cancelled,
        },
    ];
    for state in terminal {
        assert!(state.is_terminal(), "{state:?}");
    }

    let non_terminal = [
        ExecutionState::Prepared,
        ExecutionState::Submitted,
        ExecutionState::Running,
        ExecutionState::Unknown {
            phase: kern_execution::UnknownPhase::Result,
            last_known: kern_execution::LastKnown::Running,
        },
    ];
    for state in non_terminal {
        assert!(!state.is_terminal(), "{state:?}");
    }

    // Nothing ran, so there is no machine result to report.
    assert_eq!(
        ExecutionState::NotStarted(NotStartedReason::Abandoned).terminal_outcome(),
        None
    );
    assert_eq!(
        ExecutionState::Completed.terminal_outcome(),
        Some(TerminalOutcome::Completed)
    );
}

#[test]
fn every_liveness_failure_maps_to_a_lapse_reason() {
    use kern_enforcer::AuthorityStatusError;

    assert_eq!(
        AuthorityLapseReason::from(AuthorityStatusError::AuthorityMissing),
        AuthorityLapseReason::AuthorityMissing
    );
    assert_eq!(
        AuthorityLapseReason::from(AuthorityStatusError::Superseded),
        AuthorityLapseReason::Superseded
    );
    assert_eq!(
        AuthorityLapseReason::from(AuthorityStatusError::DeadlineExpired),
        AuthorityLapseReason::LeaseExpired
    );
    assert_eq!(
        AuthorityLapseReason::from(AuthorityStatusError::ClockWentBackwards),
        AuthorityLapseReason::ClockUntrusted
    );
}
