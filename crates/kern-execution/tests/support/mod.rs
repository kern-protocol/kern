//! A deterministic pipeline — policy, issuance, installation — plus a scriptable
//! executor adapter with fault injection. Every input is fixed.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::Challenge;
use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, ChallengeTicket, ConstraintSet, DeviceId,
    EnforcerSessionId, IssuerId, KeyId, MonotonicDuration, NormalizedActionProposal,
    ParamConstraint, ParamDomain, ParamName, ParamSpec, ParamValue, SubjectId, Symbol, SymbolSet,
    TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_execution::{
    AuthorityLapseReason, CancelRequestOutcome, ExecutionGovernor, ExecutionId,
    ExecutionObservation, Executor, ExecutorDeclaration, ExecutorObservations, ExecutorQuery,
    ExecutorReconcile, GovernorConfig, LapseAction, LapseActionSet, ObservationOrdering,
    ObservationPoll, QueryOutcome, ReconcileOutcome, SemanticCommand, SequentialExecutionIds,
    StartupPolicy, SubmitOutcome,
};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

pub const DEV_SEED: [u8; 32] = [7u8; 32];
pub const SESSION_BYTES: [u8; 32] = [0x11u8; 32];
pub const OTHER_SESSION_BYTES: [u8; 32] = [0x22u8; 32];
pub const ISSUED_AT_MS: u64 = 1_700_000_000_000;
pub const CHALLENGE_TTL_MS: u64 = 2_000;
pub const LEASE_TTL_MS: u64 = 5_000;
pub const START_UPTIME_MS: u64 = 1_000;

pub type Issuer = LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>;
pub type Store = EnforcerStore<TestMonotonicClock, SequentialChallenges>;
pub type Governor = ExecutionGovernor<u64, TestMonotonicClock, SequentialExecutionIds>;

pub fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

pub fn capability(name: &str) -> CapabilityName {
    CapabilityName::new(name).expect("valid capability name")
}

pub fn issuer_id() -> IssuerId {
    IssuerId::new("issuer_dev")
}

pub fn session() -> EnforcerSessionId {
    EnforcerSessionId::from_bytes(SESSION_BYTES)
}

pub fn other_session() -> EnforcerSessionId {
    EnforcerSessionId::from_bytes(OTHER_SESSION_BYTES)
}

pub fn subject() -> SubjectId {
    SubjectId::new("planner_a")
}

pub fn device() -> DeviceId {
    DeviceId::new("cafe_bot_01")
}

pub fn navigate_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        capability("navigate"),
        [
            (
                param("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
        ],
    )
    .expect("well-formed schema")
}

pub fn control_plane() -> Authority {
    let mut registry = CapabilityRegistry::new();
    registry
        .register(device(), navigate_schema())
        .expect("registered");

    let allowed = SymbolSet::allowed([Symbol::new("cafe"), Symbol::new("lobby")])
        .expect("non-empty allow-list");
    let navigate = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(subject()),
        Selector::Exactly(device()),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([
            (param("max_speed"), ParamConstraint::at_most(500)),
            (param("destination"), ParamConstraint::Symbolic(allowed)),
        ]),
    )
    .expect("constrained policy");

    Authority::new(
        registry,
        PolicySet::from_policies([navigate]).expect("distinct ids"),
    )
}

pub fn navigate_proposal(speed: i64, destination: &str) -> ActionProposal {
    ActionProposal::new(subject(), device(), capability("navigate"))
        .with_param(
            param("destination"),
            ParamValue::Symbol(Symbol::new(destination)),
        )
        .with_param(param("max_speed"), ParamValue::Scalar(speed))
}

pub fn authorized(speed: i64, destination: &str) -> AuthorizedOperation {
    let evaluation = control_plane()
        .evaluate(&navigate_proposal(speed, destination))
        .expect("well-formed request");
    AuthorizedOperation::from_evaluation(evaluation).expect("policy authorized it")
}

pub fn operation(speed: i64, destination: &str) -> NormalizedActionProposal {
    authorized(speed, destination).proposal().clone()
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

pub fn dev_verifying_key() -> [u8; 32] {
    Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED).verifying_key_bytes()
}

pub fn trust_store() -> TrustStore {
    let mut trust = TrustStore::new();
    trust
        .authorize(issuer_id(), KeyId::new("dev-1"), dev_verifying_key())
        .expect("authorized");
    trust
}

pub fn store_for(session: EnforcerSessionId, clock: TestMonotonicClock) -> Store {
    EnforcerStore::new(
        session,
        trust_store(),
        clock,
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    )
    .expect("valid configuration")
}

/// A store, its clock, an issuer, and installed navigate authority.
pub struct Harness {
    pub store: Store,
    pub clock: TestMonotonicClock,
    pub issuer: Issuer,
    pub handle: LeaseHandle,
}

impl Harness {
    pub fn new() -> Self {
        let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
        let mut store = store_for(session(), clock.clone());
        let mut issuer = issuer();
        let handle = install(&mut store, &mut issuer, 400, "cafe", LEASE_TTL_MS);
        Self {
            store,
            clock,
            issuer,
            handle,
        }
    }

    /// Installs a newer generation into the same slot, superseding the current
    /// one.
    pub fn supersede(&mut self, speed: i64) -> LeaseHandle {
        install(
            &mut self.store,
            &mut self.issuer,
            speed,
            "cafe",
            LEASE_TTL_MS,
        )
    }
}

pub fn install(
    store: &mut Store,
    issuer: &mut Issuer,
    speed: i64,
    destination: &str,
    ttl_ms: u64,
) -> LeaseHandle {
    let ticket = mint(store);
    let lease = issuer
        .issue_v2(
            &authorized(speed, destination),
            Ttl::from_millis(ttl_ms),
            &ticket,
        )
        .expect("issued");
    let bytes = encode_v2(&lease).expect("encodes");
    store.install(&bytes).expect("installs").handle().clone()
}

pub fn mint(store: &mut Store) -> ChallengeTicket {
    store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability("navigate"))
        .expect("minted")
}

pub fn declaration() -> ExecutorDeclaration {
    ExecutorDeclaration {
        supported_lapse_actions: LapseActionSet::none()
            .with(LapseAction::Cancel)
            .with(LapseAction::Hold),
        accept_implies_running: false,
        confirms_cancellation: true,
        reports_terminal_results: true,
        echoes_execution_id: false,
        ordering: ObservationOrdering::Unordered,
    }
}

pub fn config() -> GovernorConfig {
    GovernorConfig {
        capacity: 4,
        journal_capacity: 64,
        lapse_action: LapseAction::Cancel,
        startup_policy: StartupPolicy::LapseDiscovered,
        observation_budget: 16,
    }
}

pub fn governor_with(
    clock: TestMonotonicClock,
    config: GovernorConfig,
    declaration: ExecutorDeclaration,
) -> Governor {
    ExecutionGovernor::new(
        session(),
        config,
        clock,
        SequentialExecutionIds::starting_at(1),
        declaration,
    )
    .expect("valid configuration")
}

pub fn governor(clock: TestMonotonicClock) -> Governor {
    governor_with(clock, config(), declaration())
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

/// A scriptable executor adapter.
///
/// Every fault the contract admits can be injected: rejection, lost
/// acknowledgement, disconnection, unknown cancellation, out-of-order and
/// contradictory reports, and refusal to enumerate.
pub struct TestExecutor {
    declaration: ExecutorDeclaration,
    next_operation: u64,
    submit_script: VecDeque<SubmitOutcome<u64>>,
    pub submit_calls: Vec<ExecutionId>,
    pub lapse_calls: Vec<(u64, LapseAction, AuthorityLapseReason)>,
    lapse_default: CancelRequestOutcome,
    lapse_overrides: BTreeMap<u64, CancelRequestOutcome>,
    polls: VecDeque<ObservationPoll<u64>>,
    queries: BTreeMap<u64, QueryOutcome<u64>>,
    reconcile: Option<ReconcileOutcome<u64>>,
}

impl TestExecutor {
    pub fn new() -> Self {
        Self {
            declaration: declaration(),
            next_operation: 100,
            submit_script: VecDeque::new(),
            submit_calls: Vec::new(),
            lapse_calls: Vec::new(),
            lapse_default: CancelRequestOutcome::Accepted,
            lapse_overrides: BTreeMap::new(),
            polls: VecDeque::new(),
            queries: BTreeMap::new(),
            reconcile: None,
        }
    }

    pub fn with_declaration(mut self, declaration: ExecutorDeclaration) -> Self {
        self.declaration = declaration;
        self
    }

    pub fn script_submit(mut self, outcome: SubmitOutcome<u64>) -> Self {
        self.submit_script.push_back(outcome);
        self
    }

    pub fn lapse_default(mut self, outcome: CancelRequestOutcome) -> Self {
        self.lapse_default = outcome;
        self
    }

    pub fn lapse_override(mut self, operation: u64, outcome: CancelRequestOutcome) -> Self {
        self.lapse_overrides.insert(operation, outcome);
        self
    }

    pub fn poll(mut self, poll: ObservationPoll<u64>) -> Self {
        self.polls.push_back(poll);
        self
    }

    pub fn query(mut self, operation: u64, outcome: QueryOutcome<u64>) -> Self {
        self.queries.insert(operation, outcome);
        self
    }

    pub fn reconcile(mut self, outcome: ReconcileOutcome<u64>) -> Self {
        self.reconcile = Some(outcome);
        self
    }

    pub fn submit_count(&self) -> usize {
        self.submit_calls.len()
    }

    pub fn lapse_count(&self) -> usize {
        self.lapse_calls.len()
    }
}

impl Executor for TestExecutor {
    type OperationId = u64;

    fn declaration(&self) -> ExecutorDeclaration {
        self.declaration
    }

    fn submit(&mut self, command: &SemanticCommand<'_>) -> SubmitOutcome<u64> {
        self.submit_calls.push(command.execution_id());
        match self.submit_script.pop_front() {
            Some(outcome) => outcome,
            None => {
                let operation = self.next_operation;
                self.next_operation += 1;
                SubmitOutcome::Accepted { operation }
            }
        }
    }

    fn on_authority_lapse(
        &mut self,
        operation: &u64,
        action: LapseAction,
        reason: AuthorityLapseReason,
    ) -> CancelRequestOutcome {
        self.lapse_calls.push((*operation, action, reason));
        self.lapse_overrides
            .get(operation)
            .copied()
            .unwrap_or(self.lapse_default)
    }
}

impl ExecutorObservations for TestExecutor {
    fn poll_observation(&mut self) -> ObservationPoll<u64> {
        self.polls.pop_front().unwrap_or(ObservationPoll::Idle)
    }
}

impl ExecutorQuery for TestExecutor {
    fn query(&mut self, operation: &u64) -> QueryOutcome<u64> {
        self.queries
            .get(operation)
            .cloned()
            .unwrap_or(QueryOutcome::Unknown)
    }
}

impl ExecutorReconcile for TestExecutor {
    fn reconcile_active_operations(&mut self) -> ReconcileOutcome<u64> {
        self.reconcile
            .clone()
            .unwrap_or(ReconcileOutcome::Unsupported)
    }
}

/// A report for one operation, with no sequence number.
pub fn observation(operation: u64, report: kern_execution::ObservedReport) -> ObservationPoll<u64> {
    ObservationPoll::Observation(ExecutionObservation {
        operation,
        report,
        sequence: None,
    })
}

/// A report carrying a sequence number.
pub fn sequenced(
    operation: u64,
    report: kern_execution::ObservedReport,
    sequence: u64,
) -> ObservationPoll<u64> {
    ObservationPoll::Observation(ExecutionObservation {
        operation,
        report,
        sequence: Some(sequence),
    })
}
