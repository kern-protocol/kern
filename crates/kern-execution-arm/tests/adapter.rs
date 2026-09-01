//! The arm adapter, offline.
//!
//! Deterministic and machine-free: command mapping, bounds, rejection, the
//! cancellation vocabulary, observation mapping, and what happens when the arm
//! stops being observable. No ROS, no simulator, no network.

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, ConstraintSet, DeviceId, EnforcerSessionId,
    IssuerId, KeyId, MonotonicDuration, ParamConstraint, ParamName, ParamValue, SubjectId, Symbol,
    SymbolSet, TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_execution::{
    CancelRequestOutcome, ExecutionGovernor, ExecutionState, Executor, ExecutorObservations,
    GovernorConfig, LapseAction, ObservationPoll, SequentialExecutionIds, StartupPolicy,
};
use kern_execution_arm::backend::{StartMotion, StopSend};
use kern_execution_arm::{
    pick_and_place_schema, ArmConfig, ArmExecutor, ArmOperationId, ArmPose, BackendDeclaration,
    BackendEvent, FakeArmBackend, WorkspaceControl, Zone, DESTINATION_ZONE, PICK_AND_PLACE,
    SOURCE_ZONE,
};

const DEVICE: &str = "robotic_arm_01";
const SUBJECT: &str = "planner_a";
const ISSUER: &str = "issuer_dev";
const SEED: [u8; 32] = [7u8; 32];

fn config() -> ArmConfig {
    ArmConfig {
        zones: vec![
            Zone {
                name: String::from("pickup_zone"),
                pose: ArmPose {
                    shoulder_rad: -0.6,
                    elbow_rad: 1.1,
                },
            },
            Zone {
                name: String::from("serving_tray"),
                pose: ArmPose {
                    shoulder_rad: 0.7,
                    elbow_rad: 0.9,
                },
            },
        ],
        tracking_capacity: 4,
    }
}

fn adapter(backend: FakeArmBackend) -> ArmExecutor<FakeArmBackend> {
    ArmExecutor::new(backend, config()).expect("a confined backend and real zones")
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

fn zones() -> ParamConstraint {
    ParamConstraint::Symbolic(
        SymbolSet::allowed([Symbol::new("pickup_zone"), Symbol::new("serving_tray")])
            .expect("non-empty"),
    )
}

fn authority() -> kern_policy::Authority {
    use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            DeviceId::new(DEVICE),
            pick_and_place_schema().expect("valid"),
        )
        .expect("registered");
    let policy = Policy::new(
        PolicyId::new("arm_handling"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(CapabilityName::new(PICK_AND_PLACE).expect("non-empty")),
        ConstraintSet::from_constraints([
            (ParamName::new(SOURCE_ZONE), zones()),
            (ParamName::new(DESTINATION_ZONE), zones()),
        ]),
    )
    .expect("constrained");
    Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct"),
    )
}

fn proposal(source: &str, destination: &str) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(DEVICE),
        CapabilityName::new(PICK_AND_PLACE).expect("non-empty"),
    )
    .with_param(
        ParamName::new(SOURCE_ZONE),
        ParamValue::Symbol(Symbol::new(source)),
    )
    .with_param(
        ParamName::new(DESTINATION_ZONE),
        ParamValue::Symbol(Symbol::new(destination)),
    )
}

fn authorized(source: &str, destination: &str) -> Option<AuthorizedOperation> {
    let evaluation = authority().evaluate(&proposal(source, destination)).ok()?;
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
    adapter: &ArmExecutor<FakeArmBackend>,
) -> ExecutionGovernor<ArmOperationId, TestMonotonicClock, SequentialExecutionIds> {
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
fn a_backend_that_would_leave_the_workspace_is_refused() {
    let backend = FakeArmBackend::new().with_declaration(BackendDeclaration {
        workspace_control: WorkspaceControl::Unbounded,
        confirms_cancellation: true,
        reports_terminal_results: true,
    });
    assert_eq!(
        ArmExecutor::new(backend, config()).map(|_| ()),
        Err(kern_execution_arm::AdapterError::WorkspaceControlUnavailable)
    );
}

#[test]
fn an_arm_with_no_zones_is_refused() {
    let empty = ArmConfig {
        zones: Vec::new(),
        ..config()
    };
    assert_eq!(
        ArmExecutor::new(FakeArmBackend::new(), empty).map(|_| ()),
        Err(kern_execution_arm::AdapterError::NoZones)
    );
}

// ------------------------------------------------------------ command mapping

#[test]
fn an_authorized_motion_reaches_the_arm_as_the_two_configured_poses() {
    let mut harness = Harness::new();
    let operation = authorized("pickup_zone", "serving_tray").expect("authorized");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeArmBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("current authority permits it")
        .submit(&harness.store, &mut adapter);

    assert!(receipt.executor_invoked());
    let started = &adapter.backend().started;
    assert_eq!(started.len(), 1);
    // The poses come from trusted configuration. No joint angle was ever
    // carried by a proposal, a lease, or a policy.
    assert!((started[0].source.shoulder_rad + 0.6).abs() < 1e-9);
    assert!((started[0].destination.shoulder_rad - 0.7).abs() < 1e-9);
}

#[test]
fn policy_refuses_a_zone_outside_the_authorized_set() {
    assert!(
        authorized("pickup_zone", "maintenance_bay").is_none(),
        "an unlisted destination is not granted"
    );
    assert!(
        authorized("maintenance_bay", "serving_tray").is_none(),
        "an unlisted source is not granted"
    );
    assert!(authorized("pickup_zone", "serving_tray").is_some());
    assert!(authorized("serving_tray", "pickup_zone").is_some());
}

#[test]
fn a_zone_the_adapter_has_no_pose_for_is_refused_before_the_arm() {
    // Policy widened to permit any symbol, so the adapter's own refusal is what
    // this observes: an adapter that invented a pose for an unknown name would
    // convert a configuration gap into motion.
    use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
    let mut registry = CapabilityRegistry::new();
    registry
        .register(
            DeviceId::new(DEVICE),
            pick_and_place_schema().expect("valid"),
        )
        .expect("registered");
    let wide_zones = ParamConstraint::Symbolic(
        SymbolSet::allowed([
            Symbol::new("pickup_zone"),
            Symbol::new("serving_tray"),
            Symbol::new("maintenance_bay"),
        ])
        .expect("non-empty"),
    );
    let policy = Policy::new(
        PolicyId::new("wide"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(CapabilityName::new(PICK_AND_PLACE).expect("non-empty")),
        ConstraintSet::from_constraints([
            (ParamName::new(SOURCE_ZONE), wide_zones.clone()),
            (ParamName::new(DESTINATION_ZONE), wide_zones),
        ]),
    )
    .expect("constrained");
    let wide = Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct"),
    );
    let evaluation = wide
        .evaluate(&proposal("pickup_zone", "maintenance_bay"))
        .expect("well-formed");
    let operation = AuthorizedOperation::from_evaluation(evaluation).expect("authorized");

    let mut harness = Harness::new();
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeArmBackend::new());
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
        "the arm was commanded"
    );
}

#[test]
fn a_motion_from_a_zone_to_itself_is_refused() {
    use kern_execution::SemanticCommand;
    let _ = std::marker::PhantomData::<SemanticCommand<'_>>;
    let operation = authorized("pickup_zone", "pickup_zone");
    // Policy permits both symbols, so the refusal comes from the adapter's own
    // command reader.
    assert!(operation.is_some(), "policy permits the pair");

    let mut harness = Harness::new();
    let operation = operation.expect("authorized");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeArmBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);

    assert_eq!(
        receipt.state(),
        ExecutionState::NotStarted(kern_execution::NotStartedReason::Rejected(
            kern_execution::RejectionReason::InvalidCommand
        ))
    );
    assert!(adapter.backend().started.is_empty());
}

// ------------------------------------------------------- observation mapping

#[test]
fn backend_events_map_to_the_execution_states_they_are_evidence_for() {
    use kern_execution::{FailureClass, ObservedReport};
    let operation = ArmOperationId::from_u64(1);
    let cases = [
        (BackendEvent::Moving { operation }, ObservedReport::Running),
        (
            BackendEvent::Placed { operation },
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
        let mut adapter = adapter(FakeArmBackend::new());
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
    let mut adapter = adapter(FakeArmBackend::new());
    adapter.backend_mut().disconnect();
    assert_eq!(adapter.poll_observation(), ObservationPoll::Disconnected);
}

// ------------------------------------------------------ cancellation vocabulary

#[test]
fn every_stop_reply_maps_to_its_own_cancellation_outcome() {
    use kern_execution::AuthorityLapseReason;
    let operation = ArmOperationId::from_u64(1);
    let cases = [
        (StopSend::Accepted, CancelRequestOutcome::Accepted),
        (
            StopSend::AlreadyTerminal,
            CancelRequestOutcome::AlreadyTerminal,
        ),
        (StopSend::Rejected, CancelRequestOutcome::Rejected),
        (StopSend::Unknown, CancelRequestOutcome::Unknown),
        (StopSend::Disconnected, CancelRequestOutcome::Unknown),
    ];
    for (reply, expected) in cases {
        let mut adapter = adapter(FakeArmBackend::new().script_stop(reply));
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
fn an_expired_lease_stops_the_arm_and_the_confirmation_is_separate() {
    let mut harness = Harness::new();
    let operation = authorized("pickup_zone", "serving_tray").expect("authorized");
    let handle = harness.install(&operation, 5_000);
    let mut adapter = adapter(FakeArmBackend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);
    let execution = receipt.execution_id();
    let goal = ArmOperationId::from_u64(1);

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
    assert!(record.authority().is_lapsed());
    assert_eq!(
        record.execution(),
        ExecutionState::Running,
        "asking is not stopping: the arm may still be moving"
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
    let operation = authorized("pickup_zone", "serving_tray").expect("authorized");
    let handle = harness.install(&operation, 10_000);
    let mut adapter = adapter(FakeArmBackend::new().script_start(StartMotion::Unknown));
    let mut governor = governor(harness.clock.clone(), &adapter);

    let receipt = governor
        .prepare(&harness.store, &handle, operation.proposal())
        .expect("permitted")
        .submit(&harness.store, &mut adapter);

    assert!(receipt.state().is_unknown(), "{:?}", receipt.state());
}
