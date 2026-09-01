//! The conveyor adapter, offline.
//!
//! Deterministic and machine-free: command mapping, bounds, rejection, the
//! cancellation vocabulary, observation mapping, and what happens when the belt
//! stops being observable. No ROS, no simulator, no network.

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, ConstraintSet, DeviceId, EnforcerSessionId,
    Interval, IssuerId, KeyId, MonotonicDuration, ParamConstraint, ParamName, ParamValue,
    SubjectId, Symbol, SymbolSet, TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_execution::{
    CancelRequestOutcome, ExecutionGovernor, ExecutionState, Executor, ExecutorObservations,
    GovernorConfig, LapseAction, ObservationPoll, SequentialExecutionIds, StartupPolicy,
};
use kern_execution_conveyor::backend::{StartTransfer, StopSend};
use kern_execution_conveyor::{
    transfer_item_schema, BackendDeclaration, BackendEvent, ConveyorConfig, ConveyorExecutor,
    ConveyorOperationId, FakeConveyorBackend, SpeedControl, Station, DESTINATION_STATION,
    MAX_SPEED_MM_S, TRANSFER_ITEM,
};

const DEVICE: &str = "conveyor_01";
const SUBJECT: &str = "planner_a";
const ISSUER: &str = "issuer_dev";
const SEED: [u8; 32] = [7u8; 32];

fn config() -> ConveyorConfig {
    ConveyorConfig {
        stations: vec![
            Station {
                name: String::from("station_a"),
                position_mm: 0,
            },
            Station {
                name: String::from("station_b"),
                position_mm: 1_200,
            },
        ],
        tracking_capacity: 4,
    }
}

fn adapter(backend: FakeConveyorBackend) -> ConveyorExecutor<FakeConveyorBackend> {
    ConveyorExecutor::new(backend, config()).expect("a bounded backend and real stations")
}

struct Sequential(u64);

impl ChallengeSource for Sequential {
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.0.to_be_bytes());
        self.0 += 1;
        Ok(Challenge::from_bytes(bytes))
    }
}

/// The trusted control plane for this one machine.
fn authority() -> kern_policy::Authority {
    use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            DeviceId::new(DEVICE),
            transfer_item_schema().expect("valid"),
        )
        .expect("registered");
    let policy = Policy::new(
        PolicyId::new("conveyor_transfer"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(CapabilityName::new(TRANSFER_ITEM).expect("non-empty")),
        ConstraintSet::from_constraints([
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamConstraint::Numeric(Interval::between(1, 300).expect("ordered")),
            ),
            (
                ParamName::new(DESTINATION_STATION),
                ParamConstraint::Symbolic(
                    SymbolSet::allowed([Symbol::new("station_a"), Symbol::new("station_b")])
                        .expect("non-empty"),
                ),
            ),
        ]),
    )
    .expect("constrained");
    Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct"),
    )
}

fn proposal(station: &str, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(DEVICE),
        CapabilityName::new(TRANSFER_ITEM).expect("non-empty"),
    )
    .with_param(
        ParamName::new(DESTINATION_STATION),
        ParamValue::Symbol(Symbol::new(station)),
    )
    .with_param(
        ParamName::new(MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

fn authorized(station: &str, speed_mm_s: i64) -> Option<AuthorizedOperation> {
    let evaluation = authority().evaluate(&proposal(station, speed_mm_s)).ok()?;
    AuthorizedOperation::from_evaluation(evaluation)
}

struct Harness {
    store: EnforcerStore<TestMonotonicClock, Sequential>,
    issuer: LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>,
    clock: TestMonotonicClock,
}

impl Harness {
    fn new() -> Self {
        let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
        let signer = Ed25519Signer::from_seed(KeyId::new("dev-1"), SEED);
        let mut trust = TrustStore::new();
        trust
            .authorize(
                IssuerId::new(ISSUER),
                KeyId::new("dev-1"),
                signer.verifying_key_bytes(),
            )
            .expect("authorized");
        Self {
            store: EnforcerStore::new(
                EnforcerSessionId::from_bytes([0x11u8; 32]),
                trust,
                clock.clone(),
                Sequential(1),
                MonotonicDuration::from_millis(2_000),
                4,
                4,
            )
            .expect("valid"),
            issuer: LeaseIssuer::new(
                IssuerId::new(ISSUER),
                signer,
                TestClock::new(Timestamp::from_millis(1_700_000_000_000)),
                CountingNonces::new(),
                SequentialLeaseIds::starting_at(1),
            ),
            clock,
        }
    }

    fn install(&mut self, operation: &AuthorizedOperation, ttl_ms: u64) -> LeaseHandle {
        let ticket = self
            .store
            .mint_challenge(
                &IssuerId::new(ISSUER),
                operation.proposal().actor(),
                operation.proposal().device(),
                operation.proposal().capability(),
            )
            .expect("minted");
        let lease = self
            .issuer
            .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
            .expect("issued");
        let bytes = encode_v2(&lease).expect("encodes");
        self.store
            .install(&bytes)
            .expect("installs")
            .handle()
            .clone()
    }
}

fn governor(
    clock: TestMonotonicClock,
    adapter: &ConveyorExecutor<FakeConveyorBackend>,
) -> ExecutionGovernor<ConveyorOperationId, TestMonotonicClock, SequentialExecutionIds> {
    ExecutionGovernor::new(
        EnforcerSessionId::from_bytes([0x11u8; 32]),
        GovernorConfig {
            capacity: 4,
            journal_capacity: 64,
            lapse_action: LapseAction::Cancel,
            startup_policy: StartupPolicy::ReportOnly,
            observation_budget: 8,
        },
        clock,
        SequentialExecutionIds::starting_at(1),
        adapter.declaration(),
    )
    .expect("valid")
}

// ------------------------------------------------------------- construction

#[test]
fn a_backend_that_cannot_bound_speed_is_refused() {
    let backend = FakeConveyorBackend::new().with_declaration(BackendDeclaration {
        speed_control: SpeedControl::None,
        confirms_cancellation: true,
        reports_terminal_results: true,
    });
    assert_eq!(
        ConveyorExecutor::new(backend, config()).map(|_| ()),
        Err(kern_execution_conveyor::AdapterError::SpeedControlUnavailable)
    );
}

#[test]
fn a_conveyor_with_no_stations_is_refused() {
    let empty = ConveyorConfig {
        stations: Vec::new(),
        ..config()
    };
    assert_eq!(
        ConveyorExecutor::new(FakeConveyorBackend::new(), empty).map(|_| ()),
        Err(kern_execution_conveyor::AdapterError::NoStations)
    );
}

#[test]
fn duplicate_stations_are_refused() {
    let duplicated = ConveyorConfig {
        stations: vec![
            Station {
                name: String::from("station_a"),
                position_mm: 0,
            },
            Station {
                name: String::from("station_a"),
                position_mm: 900,
            },
        ],
        ..config()
    };
    assert!(matches!(
        ConveyorExecutor::new(FakeConveyorBackend::new(), duplicated).map(|_| ()),
        Err(kern_execution_conveyor::AdapterError::DuplicateStation(_))
    ));
}

// ------------------------------------------------------------ command mapping

#[test]
fn an_authorized_transfer_reaches_the_belt_with_its_bound() {
    let mut harness = Harness::new();
    let operation = authorized("station_b", 200).expect("policy authorizes it");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeConveyorBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("current authority permits it")
        .submit(&harness.store, &mut adapter);

    assert!(receipt.executor_invoked());
    let started = &adapter.backend().started;
    assert_eq!(started.len(), 1);
    // 1200 mm becomes 1.2 m, and 200 mm/s becomes 0.2 m/s. The integer bound
    // policy granted is what the belt is told.
    assert!((started[0].target_m - 1.2).abs() < 1e-9);
    assert!((started[0].max_speed_m_s - 0.2).abs() < 1e-9);
}

#[test]
fn a_station_the_adapter_has_no_position_for_is_refused_before_the_belt() {
    // Policy is deliberately widened to permit the symbol, so the *adapter's*
    // own refusal is what this test observes. An adapter that invented a
    // position for an unknown name would convert a configuration gap into
    // motion.
    use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            DeviceId::new(DEVICE),
            transfer_item_schema().expect("valid"),
        )
        .expect("registered");
    let policy = Policy::new(
        PolicyId::new("wide"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(CapabilityName::new(TRANSFER_ITEM).expect("non-empty")),
        ConstraintSet::from_constraints([(
            ParamName::new(MAX_SPEED_MM_S),
            ParamConstraint::Numeric(Interval::between(1, 300).expect("ordered")),
        )]),
    )
    .expect("constrained");
    let wide = Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct"),
    );
    let evaluation = wide
        .evaluate(&proposal("station_c", 200))
        .expect("well-formed");
    let operation = AuthorizedOperation::from_evaluation(evaluation).expect("authorized");

    let mut harness = Harness::new();
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeConveyorBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("authority permits it")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(kern_execution::NotStartedReason::Rejected(
            kern_execution::RejectionReason::InvalidCommand
        ))
    );
    assert!(
        adapter.backend().started.is_empty(),
        "the belt was commanded"
    );
}

#[test]
fn policy_refuses_a_forbidden_station_and_an_excessive_speed() {
    assert!(
        authorized("station_c", 200).is_none(),
        "station_c is not granted"
    );
    assert!(
        authorized("station_b", 900).is_none(),
        "900 mm/s is not granted"
    );
    assert!(authorized("station_b", 0).is_none(), "zero is not granted");
    assert!(
        authorized("station_b", -50).is_none(),
        "negative is not granted"
    );
    assert!(
        authorized("station_b", 300).is_some(),
        "the ceiling is granted"
    );
    assert!(authorized("station_b", 1).is_some(), "the floor is granted");
}

#[test]
fn a_second_concurrent_transfer_is_refused_as_busy() {
    let mut harness = Harness::new();
    let operation = authorized("station_b", 200).expect("authorized");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeConveyorBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);
    let second = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        second.state(),
        ExecutionState::NotStarted(kern_execution::NotStartedReason::Rejected(
            kern_execution::RejectionReason::Busy
        ))
    );
    assert_eq!(adapter.backend().started.len(), 1);
}

// ------------------------------------------------------- observation mapping

#[test]
fn backend_events_map_to_the_execution_states_they_are_evidence_for() {
    use kern_execution::{FailureClass, ObservedReport};
    let operation = ConveyorOperationId::from_u64(1);
    let cases = [
        (BackendEvent::Moving { operation }, ObservedReport::Running),
        (
            BackendEvent::Arrived { operation },
            ObservedReport::Completed,
        ),
        (
            BackendEvent::Faulted { operation },
            ObservedReport::Failed(FailureClass::OperationFailed),
        ),
        (
            BackendEvent::Stopped { operation },
            ObservedReport::Cancelled,
        ),
    ];
    for (event, expected) in cases {
        let mut adapter = adapter(FakeConveyorBackend::new());
        adapter.backend_mut().emit(event);
        let ObservationPoll::Observation(observation) = adapter.poll_observation() else {
            panic!("expected an observation for {event:?}");
        };
        assert_eq!(observation.report, expected);
        assert_eq!(observation.operation, operation);
    }
}

#[test]
fn a_lost_link_is_reported_as_disconnected_and_never_as_a_result() {
    let mut adapter = adapter(FakeConveyorBackend::new());
    adapter.backend_mut().disconnect();
    assert_eq!(adapter.poll_observation(), ObservationPoll::Disconnected);
}

// ------------------------------------------------------ cancellation vocabulary

#[test]
fn every_stop_reply_maps_to_its_own_cancellation_outcome() {
    use kern_execution::AuthorityLapseReason;
    let operation = ConveyorOperationId::from_u64(1);
    let cases = [
        (StopSend::Accepted, CancelRequestOutcome::Accepted),
        (
            StopSend::AlreadyTerminal,
            CancelRequestOutcome::AlreadyTerminal,
        ),
        (StopSend::Rejected, CancelRequestOutcome::Rejected),
        // Doubt is doubt. A request the adapter cannot confirm arrived is never
        // reported as one that was taken.
        (StopSend::Unknown, CancelRequestOutcome::Unknown),
        (StopSend::Disconnected, CancelRequestOutcome::Unknown),
    ];
    for (reply, expected) in cases {
        let mut adapter = adapter(FakeConveyorBackend::new().script_stop(reply));
        assert_eq!(
            adapter.on_authority_lapse(
                &operation,
                LapseAction::Cancel,
                AuthorityLapseReason::LeaseExpired
            ),
            expected,
            "{reply:?}"
        );
    }
}

#[test]
fn a_lapse_action_the_adapter_cannot_perform_is_unsupported() {
    use kern_execution::AuthorityLapseReason;
    let mut adapter = adapter(FakeConveyorBackend::new());
    assert_eq!(
        adapter.on_authority_lapse(
            &ConveyorOperationId::from_u64(1),
            LapseAction::Terminate,
            AuthorityLapseReason::LeaseExpired
        ),
        CancelRequestOutcome::Unsupported
    );
    assert!(adapter.backend().stopped.is_empty());
}

#[test]
fn an_expired_lease_stops_the_belt_and_the_confirmation_is_separate() {
    let mut harness = Harness::new();
    let operation = authorized("station_b", 200).expect("authorized");
    let handle = harness.install(&operation, 5_000);
    let mut adapter = adapter(FakeConveyorBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);
    let execution = receipt.execution_id();
    let belt = adapter.backend().started.len();
    assert_eq!(belt, 1);

    let goal = ConveyorOperationId::from_u64(1);
    adapter
        .backend_mut()
        .emit(BackendEvent::Moving { operation: goal });
    governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(
        governor.record(execution).expect("recorded").execution(),
        ExecutionState::Running
    );

    harness.clock.advance(6_000);
    governor.tick_observed(&harness.store, &mut adapter);
    let record = governor.record(execution).expect("recorded");
    assert!(
        record.authority().is_lapsed(),
        "authority should have lapsed"
    );
    assert_eq!(
        record.execution(),
        ExecutionState::Running,
        "asking is not stopping: the belt may still be moving"
    );
    assert_eq!(adapter.backend().stopped, vec![goal]);

    adapter
        .backend_mut()
        .emit(BackendEvent::Stopped { operation: goal });
    governor.tick_observed(&harness.store, &mut adapter);
    assert_eq!(
        governor.record(execution).expect("recorded").execution(),
        ExecutionState::Cancelled,
        "only the executor's own report makes it cancelled"
    );
}

#[test]
fn a_lost_start_acknowledgement_stays_unknown() {
    let mut harness = Harness::new();
    let operation = authorized("station_b", 200).expect("authorized");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeConveyorBackend::new().script_start(StartTransfer::Unknown));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);

    assert!(receipt.state().is_unknown(), "{:?}", receipt.state());
    assert!(receipt.executor_invoked());
}
