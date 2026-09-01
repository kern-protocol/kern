//! Three machines, three capabilities, three authorities.
//!
//! The claim under test is narrow and precise:
//!
//! > Authority for one machine does not automatically authorize another machine
//! > or another capability.
//!
//! Not that any of these machines is safe. Not that the arrangement is
//! certified. Only that a lease is scoped to a slot, and that the slot is
//! `(issuer, subject, device, capability)` rather than "the planner may operate
//! robots".
//!
//! Deterministic and offline: fake backends, an injected clock, no ROS, no
//! network.

use kern_ai::DeviceRouter;
use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, DeviceId, EnforcerSessionId, IssuerId, KeyId,
    MonotonicDuration, NormalizedActionProposal, ParamName, ParamValue, SubjectId, Symbol,
    TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{
    ChallengeSource, EnforcementError, EnforcerStore, EntropyError, LeaseHandle, TrustStore,
};
use kern_eval::world::{self, ARM, CAFE_ROBOT, CONVEYOR, ISSUER, SUBJECT};
use kern_execution::{
    ExecutionGovernor, ExecutionState, Executor, GovernorConfig, LapseAction,
    SequentialExecutionIds, StartupPolicy,
};
use kern_execution_arm::{
    ArmConfig, ArmExecutor, ArmOperationId, ArmPose, FakeArmBackend, Zone, DESTINATION_ZONE,
    PICK_AND_PLACE, SOURCE_ZONE,
};
use kern_execution_conveyor::{
    ConveyorConfig, ConveyorExecutor, ConveyorOperationId, FakeConveyorBackend, Station,
    DESTINATION_STATION, TRANSFER_ITEM,
};
use kern_execution_nav2::{
    FakeNav2Backend, Nav2Config, Nav2Executor, Nav2OperationId, DESTINATION_X_MM, DESTINATION_Y_MM,
    MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
use kern_policy::RegistryError;

const SEED: [u8; 32] = [7u8; 32];
const SESSION: [u8; 32] = [0x11u8; 32];

struct Sequential(u64);

impl ChallengeSource for Sequential {
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.0.to_be_bytes());
        self.0 += 1;
        Ok(Challenge::from_bytes(bytes))
    }
}

struct Host {
    store: EnforcerStore<TestMonotonicClock, Sequential>,
    issuer: LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>,
    clock: TestMonotonicClock,
}

impl Host {
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
                EnforcerSessionId::from_bytes(SESSION),
                trust,
                clock.clone(),
                Sequential(1),
                MonotonicDuration::from_millis(2_000),
                8,
                8,
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

    /// Mints, issues, and installs — the only way a handle comes to exist.
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

fn authorize(proposal: &ActionProposal) -> Option<AuthorizedOperation> {
    let authority = world::world("workspace").expect("the workspace world");
    let evaluation = authority.evaluate(proposal).ok()?;
    AuthorizedOperation::from_evaluation(evaluation)
}

fn navigate(x_mm: i64, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(CAFE_ROBOT),
        CapabilityName::new(NAVIGATE).expect("non-empty"),
    )
    .with_param(ParamName::new(DESTINATION_X_MM), ParamValue::Scalar(x_mm))
    .with_param(ParamName::new(DESTINATION_Y_MM), ParamValue::Scalar(0))
    .with_param(ParamName::new(YAW_MDEG), ParamValue::Scalar(0))
    .with_param(
        ParamName::new(MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

fn transfer(station: &str, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(CONVEYOR),
        CapabilityName::new(TRANSFER_ITEM).expect("non-empty"),
    )
    .with_param(
        ParamName::new(DESTINATION_STATION),
        ParamValue::Symbol(Symbol::new(station)),
    )
    .with_param(
        ParamName::new(kern_execution_conveyor::MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

fn pick(source: &str, destination: &str) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(ARM),
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

fn cafe_adapter() -> Nav2Executor<FakeNav2Backend> {
    Nav2Executor::new(FakeNav2Backend::new(), Nav2Config::default()).expect("bounds speed")
}

fn conveyor_adapter() -> ConveyorExecutor<FakeConveyorBackend> {
    ConveyorExecutor::new(
        FakeConveyorBackend::new(),
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
        },
    )
    .expect("real stations")
}

fn arm_adapter() -> ArmExecutor<FakeArmBackend> {
    ArmExecutor::new(
        FakeArmBackend::new(),
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
        },
    )
    .expect("real zones")
}

fn governor<O: Clone + Eq, E: Executor<OperationId = O>>(
    clock: TestMonotonicClock,
    adapter: &E,
    start: u128,
) -> ExecutionGovernor<O, TestMonotonicClock, SequentialExecutionIds> {
    ExecutionGovernor::new(
        EnforcerSessionId::from_bytes(SESSION),
        GovernorConfig {
            capacity: 4,
            journal_capacity: 64,
            lapse_action: LapseAction::Cancel,
            startup_policy: StartupPolicy::ReportOnly,
            observation_budget: 8,
        },
        clock,
        SequentialExecutionIds::starting_at(start),
        adapter.declaration(),
    )
    .expect("valid")
}

// ------------------------------------------------------ the routing matrix

#[test]
fn each_machine_registers_only_its_own_capability() {
    let authority = world::world("workspace").expect("the workspace world");
    let registry = authority.registry();

    // What each machine does expose.
    for (device, capability) in [
        (CAFE_ROBOT, NAVIGATE),
        (CONVEYOR, TRANSFER_ITEM),
        (ARM, PICK_AND_PLACE),
    ] {
        assert!(
            registry
                .resolve(
                    &DeviceId::new(device),
                    &CapabilityName::new(capability).expect("non-empty")
                )
                .is_ok(),
            "{device} should expose {capability}"
        );
    }

    // And every crossed pair. These fail at the registry, before any policy is
    // consulted: an unknown operation, not a forbidden one.
    for (device, capability) in [
        (CAFE_ROBOT, PICK_AND_PLACE),
        (CAFE_ROBOT, TRANSFER_ITEM),
        (CONVEYOR, NAVIGATE),
        (CONVEYOR, PICK_AND_PLACE),
        (ARM, NAVIGATE),
        (ARM, TRANSFER_ITEM),
    ] {
        assert!(
            matches!(
                registry.resolve(
                    &DeviceId::new(device),
                    &CapabilityName::new(capability).expect("non-empty")
                ),
                Err(RegistryError::UnknownCapability { .. })
            ),
            "{device} must not expose {capability}"
        );
    }
}

#[test]
fn a_model_cannot_name_a_machine_the_host_did_not_route() {
    let router = world::workspace_router();
    assert!(router.resolve(CAFE_ROBOT).is_some());
    assert!(router.resolve(CONVEYOR).is_some());
    assert!(router.resolve(ARM).is_some());

    // Anything else resolves to nothing at all. `DeviceId::new` accepts any
    // string, so this is the boundary that stops model text from naming a
    // machine nobody configured.
    for invented in [
        "forklift_02",
        "cafe_robot ",
        "CAFE_ROBOT",
        "../conveyor_01",
        "",
    ] {
        assert!(
            router.resolve(invented).is_none(),
            "`{invented}` must not resolve"
        );
    }

    // An empty router routes nothing, which is the right answer for a host that
    // never expected a target.
    assert!(DeviceRouter::new().resolve(CAFE_ROBOT).is_none());
}

// -------------------------------------------------- cross-device lease misuse

/// Every crossed pairing of a machine's authority against another machine's
/// operation.
#[test]
fn authority_for_one_machine_authorizes_no_other_machine() {
    let mut host = Host::new();

    let cafe = authorize(&navigate(6_000, 250)).expect("authorized");
    let conveyor = authorize(&transfer("station_b", 200)).expect("authorized");
    let arm = authorize(&pick("pickup_zone", "serving_tray")).expect("authorized");

    let cafe_handle = host.install(&cafe, 30_000);
    let conveyor_handle = host.install(&conveyor, 30_000);
    let arm_handle = host.install(&arm, 30_000);

    let operations: [(&str, &LeaseHandle, &NormalizedActionProposal); 3] = [
        ("cafe", &cafe_handle, cafe.proposal()),
        ("conveyor", &conveyor_handle, conveyor.proposal()),
        ("arm", &arm_handle, arm.proposal()),
    ];

    for (holder, handle, _) in operations.iter() {
        for (subject, _, operation) in operations.iter() {
            let result = host.store.enforce(handle, operation);
            if holder == subject {
                assert_eq!(result, Ok(()), "{holder} authority over its own operation");
            } else {
                // The slot is (issuer, subject, device, capability). A handle
                // for another device resolves to authority whose device field
                // does not match, and the mismatch is caught before any
                // parameter is looked at.
                assert_eq!(
                    result,
                    Err(EnforcementError::DeviceMismatch),
                    "{holder} authority must not cover the {subject} operation"
                );
            }
        }
    }
}

#[test]
fn a_misused_handle_never_reaches_an_executor() {
    let mut host = Host::new();
    let cafe = authorize(&navigate(6_000, 250)).expect("authorized");
    let conveyor = authorize(&transfer("station_b", 200)).expect("authorized");
    let cafe_handle = host.install(&cafe, 30_000);

    let adapter = conveyor_adapter();
    let mut belt = governor(host.clock.clone(), &adapter, 1);

    // `prepare` enforces before it reserves anything. The refusal happens with
    // no execution identifier drawn and no adapter call made.
    let refused = belt.prepare(&host.store, &cafe_handle, conveyor.proposal());
    assert!(
        refused.is_err(),
        "the cafe handle must not prepare a transfer"
    );
    drop(refused);
    assert!(
        adapter.backend().started.is_empty(),
        "the belt was commanded under another machine's authority"
    );
}

// ------------------------------------------------------------- concurrency

#[test]
fn three_machines_run_concurrently_with_independent_authority() {
    let mut host = Host::new();

    let cafe = authorize(&navigate(6_000, 250)).expect("authorized");
    let conveyor = authorize(&transfer("station_b", 200)).expect("authorized");
    let arm = authorize(&pick("pickup_zone", "serving_tray")).expect("authorized");

    let cafe_handle = host.install(&cafe, 5_000);
    let conveyor_handle = host.install(&conveyor, 60_000);
    let arm_handle = host.install(&arm, 60_000);

    // Three leases, three artifacts. Nothing is shared.
    assert_ne!(cafe_handle.lease_id(), conveyor_handle.lease_id());
    assert_ne!(conveyor_handle.lease_id(), arm_handle.lease_id());
    assert_ne!(cafe_handle.artifact(), conveyor_handle.artifact());
    assert_ne!(conveyor_handle.artifact(), arm_handle.artifact());
    assert_ne!(cafe_handle.slot(), conveyor_handle.slot());
    assert_ne!(conveyor_handle.slot(), arm_handle.slot());

    let mut cafe_exec = cafe_adapter();
    let mut belt_exec = conveyor_adapter();
    let mut arm_exec = arm_adapter();
    // Three governors, one per machine: the operation identity of a Nav2 goal,
    // a belt transfer, and an arm motion are three different types, and the
    // type system keeps them from being confused.
    let mut cafe_gov = governor(host.clock.clone(), &cafe_exec, 100);
    let mut belt_gov = governor(host.clock.clone(), &belt_exec, 200);
    let mut arm_gov = governor(host.clock.clone(), &arm_exec, 300);

    let cafe_run = cafe_gov
        .prepare(&host.store, &cafe_handle, cafe.proposal())
        .expect("permitted")
        .submit(&host.store, &mut cafe_exec);
    let belt_run = belt_gov
        .prepare(&host.store, &conveyor_handle, conveyor.proposal())
        .expect("permitted")
        .submit(&host.store, &mut belt_exec);
    let arm_run = arm_gov
        .prepare(&host.store, &arm_handle, arm.proposal())
        .expect("permitted")
        .submit(&host.store, &mut arm_exec);

    assert!(cafe_run.executor_invoked());
    assert!(belt_run.executor_invoked());
    assert!(arm_run.executor_invoked());
    assert_ne!(cafe_run.execution_id(), belt_run.execution_id());
    assert_ne!(belt_run.execution_id(), arm_run.execution_id());

    // Each machine received exactly its own command, and nothing else.
    assert_eq!(cafe_exec.backend().sent.len(), 1);
    assert_eq!(belt_exec.backend().started.len(), 1);
    assert_eq!(arm_exec.backend().started.len(), 1);

    // ---- selective lapse: only the cafe lease expires --------------------
    cafe_exec
        .backend_mut()
        .emit(kern_execution_nav2::backend::BackendEvent::Feedback {
            operation: Nav2OperationId::from_uuid([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        });
    belt_exec
        .backend_mut()
        .emit(kern_execution_conveyor::BackendEvent::Moving {
            operation: ConveyorOperationId::from_u64(1),
        });
    arm_exec
        .backend_mut()
        .emit(kern_execution_arm::BackendEvent::Moving {
            operation: ArmOperationId::from_u64(1),
        });
    cafe_gov.tick_observed(&host.store, &mut cafe_exec);
    belt_gov.tick_observed(&host.store, &mut belt_exec);
    arm_gov.tick_observed(&host.store, &mut arm_exec);

    host.clock.advance(6_000);
    cafe_gov.tick_observed(&host.store, &mut cafe_exec);
    belt_gov.tick_observed(&host.store, &mut belt_exec);
    arm_gov.tick_observed(&host.store, &mut arm_exec);

    let cafe_record = cafe_gov.record(cafe_run.execution_id()).expect("recorded");
    let belt_record = belt_gov.record(belt_run.execution_id()).expect("recorded");
    let arm_record = arm_gov.record(arm_run.execution_id()).expect("recorded");

    assert!(
        cafe_record.authority().is_lapsed(),
        "the cafe lease should have expired"
    );
    assert!(
        !belt_record.authority().is_lapsed(),
        "the conveyor lease must be unaffected"
    );
    assert!(
        !arm_record.authority().is_lapsed(),
        "the arm lease must be unaffected"
    );

    // Only the cafe robot was asked to stop.
    assert!(!cafe_exec.backend().cancelled.is_empty());
    assert!(belt_exec.backend().stopped.is_empty());
    assert!(arm_exec.backend().stopped.is_empty());

    // The other two are still running, still authorized.
    assert_eq!(belt_record.execution(), ExecutionState::Running);
    assert_eq!(arm_record.execution(), ExecutionState::Running);
}

#[test]
fn expiring_the_conveyor_lease_leaves_the_other_two_current() {
    let mut host = Host::new();
    let cafe = authorize(&navigate(6_000, 250)).expect("authorized");
    let conveyor = authorize(&transfer("station_b", 200)).expect("authorized");
    let arm = authorize(&pick("pickup_zone", "serving_tray")).expect("authorized");

    let cafe_handle = host.install(&cafe, 60_000);
    let conveyor_handle = host.install(&conveyor, 5_000);
    let arm_handle = host.install(&arm, 60_000);

    host.clock.advance(6_000);

    assert!(
        host.store.check_authority(&conveyor_handle).is_err(),
        "the conveyor lease should have expired"
    );
    assert_eq!(
        host.store.check_authority(&cafe_handle),
        Ok(()),
        "the cafe lease must be unaffected"
    );
    assert_eq!(
        host.store.check_authority(&arm_handle),
        Ok(()),
        "the arm lease must be unaffected"
    );
}

// --------------------------------------------------------------- the policies

#[test]
fn each_machine_has_its_own_bounds() {
    // The cafe robot's ceiling is not the conveyor's, and neither of them is a
    // general grant. A single collapsed policy could not express this.
    assert!(authorize(&navigate(6_000, 400)).is_some(), "cafe ceiling");
    assert!(authorize(&navigate(6_000, 401)).is_none(), "cafe over");
    assert!(
        authorize(&transfer("station_b", 300)).is_some(),
        "belt ceiling"
    );
    assert!(
        authorize(&transfer("station_b", 301)).is_none(),
        "belt over"
    );
    assert!(
        authorize(&navigate(40_000, 250)).is_none(),
        "outside the corridor"
    );
    assert!(
        authorize(&transfer("station_c", 200)).is_none(),
        "an unlisted station"
    );
    assert!(
        authorize(&pick("pickup_zone", "maintenance_bay")).is_none(),
        "an unlisted zone"
    );
}

#[test]
fn the_speed_floor_closes_the_phase_eight_gap() {
    // Phase 8 recorded that an upper-bound-only policy authorizes a zero or
    // negative speed, which the adapter then refuses one layer lower. The
    // heterogeneous worlds bound speed from both ends, in the policy.
    for speed in [0, -1, -500, i64::MIN] {
        assert!(
            authorize(&navigate(6_000, speed)).is_none(),
            "cafe speed {speed} must not be granted"
        );
        assert!(
            authorize(&transfer("station_b", speed)).is_none(),
            "conveyor speed {speed} must not be granted"
        );
    }
    assert!(
        authorize(&navigate(6_000, 1)).is_some(),
        "the floor is granted"
    );
    assert!(authorize(&transfer("station_b", 1)).is_some());
}
