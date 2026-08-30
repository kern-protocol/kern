//! The full deterministic pipeline for the navigate capability: policy,
//! issuance, installation, governor, adapter, fake backend. No ROS, no clock
//! that is not injected.
#![allow(dead_code)]

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, ChallengeTicket, ConstraintSet, DeviceId,
    EnforcerSessionId, Interval, IssuerId, KeyId, MonotonicDuration, NormalizedActionProposal,
    ParamConstraint, ParamName, ParamValue, SubjectId, TestClock, TestMonotonicClock, Timestamp,
    Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_execution::{
    ExecutionGovernor, GovernorConfig, LapseAction, SequentialExecutionIds, StartupPolicy,
};
use kern_execution_nav2::{
    navigate_schema, FakeNav2Backend, Nav2Config, Nav2Executor, Nav2OperationId, DESTINATION_X_MM,
    DESTINATION_Y_MM, MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

pub const DEV_SEED: [u8; 32] = [7u8; 32];
pub const SESSION_BYTES: [u8; 32] = [0x11u8; 32];
pub const ISSUED_AT_MS: u64 = 1_700_000_000_000;
pub const CHALLENGE_TTL_MS: u64 = 2_000;
pub const LEASE_TTL_MS: u64 = 5_000;
pub const START_UPTIME_MS: u64 = 1_000;
/// The policy ceiling, millimetres per second.
pub const POLICY_MAX_SPEED_MM_S: i64 = 400;

pub type Store = EnforcerStore<TestMonotonicClock, SequentialChallenges>;
pub type Issuer = LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>;
pub type Governor = ExecutionGovernor<Nav2OperationId, TestMonotonicClock, SequentialExecutionIds>;
pub type Adapter = Nav2Executor<FakeNav2Backend>;

pub fn capability() -> CapabilityName {
    CapabilityName::new(NAVIGATE).expect("valid")
}

pub fn issuer_id() -> IssuerId {
    IssuerId::new("issuer_dev")
}

pub fn session() -> EnforcerSessionId {
    EnforcerSessionId::from_bytes(SESSION_BYTES)
}

pub fn subject() -> SubjectId {
    SubjectId::new("planner_a")
}

pub fn device() -> DeviceId {
    DeviceId::new("cafe_bot_01")
}

fn bounded(lower: i64, upper: i64) -> ParamConstraint {
    ParamConstraint::Numeric(Interval::between(lower, upper).expect("ordered bounds"))
}

/// `navigate` on this device, bounded to 400 mm/s and a 10 m box.
pub fn control_plane() -> Authority {
    let mut registry = CapabilityRegistry::new();
    registry
        .register(device(), navigate_schema().expect("well-formed schema"))
        .expect("registered");

    let policy = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(subject()),
        Selector::Exactly(device()),
        Selector::Exactly(capability()),
        ConstraintSet::from_constraints([
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamConstraint::at_most(POLICY_MAX_SPEED_MM_S),
            ),
            (ParamName::new(DESTINATION_X_MM), bounded(-10_000, 10_000)),
            (ParamName::new(DESTINATION_Y_MM), bounded(-10_000, 10_000)),
            (ParamName::new(YAW_MDEG), bounded(-180_000, 180_000)),
        ]),
    )
    .expect("constrained policy");

    Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct ids"),
    )
}

pub fn navigate_proposal(x_mm: i64, y_mm: i64, yaw_mdeg: i64, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(subject(), device(), capability())
        .with_param(ParamName::new(DESTINATION_X_MM), ParamValue::Scalar(x_mm))
        .with_param(ParamName::new(DESTINATION_Y_MM), ParamValue::Scalar(y_mm))
        .with_param(ParamName::new(YAW_MDEG), ParamValue::Scalar(yaw_mdeg))
        .with_param(
            ParamName::new(MAX_SPEED_MM_S),
            ParamValue::Scalar(speed_mm_s),
        )
}

pub fn authorized(x_mm: i64, y_mm: i64, yaw_mdeg: i64, speed_mm_s: i64) -> AuthorizedOperation {
    let evaluation = control_plane()
        .evaluate(&navigate_proposal(x_mm, y_mm, yaw_mdeg, speed_mm_s))
        .expect("well-formed request");
    AuthorizedOperation::from_evaluation(evaluation).expect("policy authorized it")
}

/// A normalized navigate operation. 4 m ahead, 1.2 m across, quarter turn.
pub fn operation(speed_mm_s: i64) -> NormalizedActionProposal {
    authorized(4_000, 1_200, 90_000, speed_mm_s)
        .proposal()
        .clone()
}

pub fn operation_at(
    x_mm: i64,
    y_mm: i64,
    yaw_mdeg: i64,
    speed_mm_s: i64,
) -> NormalizedActionProposal {
    authorized(x_mm, y_mm, yaw_mdeg, speed_mm_s)
        .proposal()
        .clone()
}

pub fn issuer() -> Issuer {
    LeaseIssuer::new(
        issuer_id(),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(0xAB),
    )
}

pub fn trust_store() -> TrustStore {
    let mut trust = TrustStore::new();
    trust
        .authorize(
            issuer_id(),
            KeyId::new("dev-1"),
            Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED).verifying_key_bytes(),
        )
        .expect("authorized");
    trust
}

pub fn store_for(clock: TestMonotonicClock) -> Store {
    EnforcerStore::new(
        session(),
        trust_store(),
        clock,
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    )
    .expect("valid configuration")
}

/// Store, clock, issuer, and installed navigate authority.
pub struct Harness {
    pub store: Store,
    pub clock: TestMonotonicClock,
    pub issuer: Issuer,
    pub handle: LeaseHandle,
}

impl Harness {
    pub fn new() -> Self {
        Self::with_ttl(LEASE_TTL_MS)
    }

    pub fn with_ttl(ttl_ms: u64) -> Self {
        let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
        let mut store = store_for(clock.clone());
        let mut issuer = issuer();
        let handle = install(&mut store, &mut issuer, POLICY_MAX_SPEED_MM_S, ttl_ms);
        Self {
            store,
            clock,
            issuer,
            handle,
        }
    }

    /// Installs a newer generation into the same slot.
    pub fn supersede(&mut self) -> LeaseHandle {
        install(
            &mut self.store,
            &mut self.issuer,
            POLICY_MAX_SPEED_MM_S,
            LEASE_TTL_MS,
        )
    }
}

pub fn install(
    store: &mut Store,
    issuer: &mut Issuer,
    speed_mm_s: i64,
    ttl_ms: u64,
) -> LeaseHandle {
    let ticket = store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability())
        .expect("minted");
    let lease = issuer
        .issue_v2(
            &authorized(4_000, 1_200, 90_000, speed_mm_s),
            Ttl::from_millis(ttl_ms),
            &ticket,
        )
        .expect("issued");
    let bytes = encode_v2(&lease).expect("encodes");
    store.install(&bytes).expect("installs").handle().clone()
}

pub fn adapter(backend: FakeNav2Backend) -> Adapter {
    Nav2Executor::new(backend, Nav2Config::default()).expect("the fake backend bounds speed")
}

pub fn governor(clock: TestMonotonicClock, adapter: &Adapter) -> Governor {
    use kern_execution::Executor;
    ExecutionGovernor::new(
        session(),
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
    .expect("valid configuration")
}

/// A deterministic challenge source, for tests only.
#[derive(Clone, Debug, Default)]
pub struct SequentialChallenges {
    next: u64,
}

impl SequentialChallenges {
    pub fn starting_at(start: u64) -> Self {
        Self { next: start }
    }
}

impl ChallengeSource for SequentialChallenges {
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.next.to_be_bytes());
        self.next = self.next.wrapping_add(1);
        Ok(Challenge::from_bytes(bytes))
    }
}

/// Unused import anchor for the ticket type.
pub fn _ticket_type(_: &ChallengeTicket) {}
