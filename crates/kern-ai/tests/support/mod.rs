//! The whole Phase 7 path, offline: proposal plane, registry, policy, issuance,
//! installation, governor, Nav2 adapter, fake backend.
//!
//! Every trust transition is a separate, named step in [`Pipeline::walk`]. There
//! is deliberately no `authorize_model_response` helper: the point of this
//! harness is that a reader can see normalization, evaluation, authorization,
//! challenge minting, issuance, installation, preparation, and submission
//! happen in that order, and can see exactly where a denied proposal stops.
#![allow(dead_code)]

use kern_ai::{
    CapabilityVocabulary, ConstraintFeedback, Instruction, ModelIdentity, NormalizationOutcome,
    PlanningRequest, PolicyOutcome, Proposal, ProposalRecord, RobotContext,
};
use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    CapabilityName, Challenge, ConstraintSet, DeviceId, EnforcerSessionId, Interval, IssuerId,
    KeyId, MonotonicDuration, NormalizedActionProposal, ParamConstraint, ParamName, PolicyDecision,
    SubjectId, TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, TrustStore};
use kern_execution::{
    ExecutionGovernor, ExecutionId, Executor, GovernorConfig, LapseAction, SequentialExecutionIds,
    StartupPolicy,
};
use kern_execution_nav2::{
    navigate_schema, FakeNav2Backend, Nav2Config, Nav2Executor, Nav2OperationId, DESTINATION_X_MM,
    DESTINATION_Y_MM, MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
use std::collections as alloc_map;

pub const DEV_SEED: [u8; 32] = [7u8; 32];
pub const SESSION_BYTES: [u8; 32] = [0x11u8; 32];
pub const ISSUED_AT_MS: u64 = 1_700_000_000_000;
pub const CHALLENGE_TTL_MS: u64 = 2_000;
pub const START_UPTIME_MS: u64 = 1_000;

/// The authority lifetime, chosen by trusted host configuration.
///
/// Not by the model, not by the provider, and not by anything reachable from
/// either. It is a constant here for the same reason it is a constant in the
/// Phase 6 harness: the TTL is a deployment decision.
pub const LEASE_TTL_MS: u64 = 5_000;

/// The demo world, matching the Phase 6 Gazebo corridor.
pub const POLICY_MAX_SPEED_MM_S: i64 = 400;
/// Longitudinal bound of the demo world, millimetres.
pub const WORLD_X_MM: (i64, i64) = (-7_000, 7_000);
/// Lateral bound of the demo world, millimetres.
pub const WORLD_Y_MM: (i64, i64) = (-1_000, 1_000);
/// Heading bound, millidegrees.
pub const WORLD_YAW_MDEG: (i64, i64) = (-180_000, 180_000);

pub type Store = EnforcerStore<TestMonotonicClock, SequentialChallenges>;
pub type Issuer = LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>;
pub type Governor = ExecutionGovernor<Nav2OperationId, TestMonotonicClock, SequentialExecutionIds>;
pub type Adapter = Nav2Executor<FakeNav2Backend>;

pub fn capability() -> CapabilityName {
    CapabilityName::new(NAVIGATE).expect("a non-empty literal")
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

fn bounded(bounds: (i64, i64)) -> ParamConstraint {
    ParamConstraint::Numeric(Interval::between(bounds.0, bounds.1).expect("ordered bounds"))
}

/// The trusted control plane: what `navigate` means, and who may request it
/// within what bounds.
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
            (ParamName::new(DESTINATION_X_MM), bounded(WORLD_X_MM)),
            (ParamName::new(DESTINATION_Y_MM), bounded(WORLD_Y_MM)),
            (ParamName::new(YAW_MDEG), bounded(WORLD_YAW_MDEG)),
        ]),
    )
    .expect("constrained policy");

    Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct ids"),
    )
}

/// The semantic world the model is allowed to know about.
pub const ROBOT_CONTEXT: &str = "\
The robot is a delivery base in a straight corridor.
Named places, in millimetres from the origin:
  station_a: x = -6000, y = 0
  origin:    x = 0,     y = 0
  station_b: x = 6000,  y = 0
The corridor runs along x. Staying near y = 0 keeps the robot in the corridor.";

pub fn vocabulary(authority: &Authority) -> CapabilityVocabulary {
    CapabilityVocabulary::from_registry(authority.registry(), &device()).expect("navigate exists")
}

pub fn planning_request(authority: &Authority, instruction: &str) -> PlanningRequest {
    PlanningRequest::new(
        subject(),
        device(),
        Instruction::new(instruction).expect("a bounded instruction"),
        RobotContext::new(ROBOT_CONTEXT).expect("a bounded context"),
        vocabulary(authority),
    )
}

pub fn fixture_model(name: &str) -> ModelIdentity {
    ModelIdentity::new("fixture", name)
}

/// What one walk down the authority pipeline actually did.
///
/// The counters exist so the denial tests can assert absence rather than infer
/// it: a denied proposal must leave every one of these at zero.
#[derive(Debug)]
pub struct Walk {
    /// The provenance record, with every stage it reached filled in.
    pub record: ProposalRecord,
    /// The normalized operation, if normalization succeeded.
    pub normalized: Option<NormalizedActionProposal>,
    /// The policy decision, if evaluation happened.
    pub decision: Option<PolicyDecision>,
    /// A human-readable reason for the refusal, if there was one.
    pub detail: Option<String>,
    /// How many challenges were minted for this proposal.
    pub challenges_minted: u32,
    /// How many leases were issued.
    pub leases_issued: u32,
    /// How many leases were installed.
    pub installs: u32,
    /// The execution allocated, if any.
    pub execution: Option<ExecutionId>,
    /// Whether the adapter was invoked at all.
    pub executor_invoked: bool,
}

impl Walk {
    /// True when nothing physical, and nothing authority-shaped, happened.
    pub fn is_inert(&self) -> bool {
        self.challenges_minted == 0
            && self.leases_issued == 0
            && self.installs == 0
            && self.execution.is_none()
            && !self.executor_invoked
            && self.record.artifact().is_none()
    }
}

/// The host: it holds the registry, the policy set, the signing key, the
/// enforcer, and the governor. The model holds none of them.
pub struct Pipeline {
    pub authority: Authority,
    pub store: Store,
    pub clock: TestMonotonicClock,
    pub issuer: Issuer,
    pub adapter: Adapter,
    pub governor: Governor,
}

impl Pipeline {
    pub fn new() -> Self {
        let clock = TestMonotonicClock::new(Uptime::from_millis(START_UPTIME_MS));
        let store = EnforcerStore::new(
            session(),
            trust_store(),
            clock.clone(),
            SequentialChallenges::starting_at(1),
            MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
            8,
            8,
        )
        .expect("valid configuration");

        let adapter =
            Nav2Executor::new(FakeNav2Backend::new(), Nav2Config::default()).expect("bounds speed");
        let governor = ExecutionGovernor::new(
            session(),
            GovernorConfig {
                capacity: 8,
                journal_capacity: 64,
                lapse_action: LapseAction::Cancel,
                startup_policy: StartupPolicy::ReportOnly,
                observation_budget: 8,
            },
            clock.clone(),
            SequentialExecutionIds::starting_at(1),
            adapter.declaration(),
        )
        .expect("valid configuration");

        Self {
            authority: control_plane(),
            store,
            clock,
            issuer: issuer(),
            adapter,
            governor,
        }
    }

    /// What the fake Nav2 backend has been asked to do, ever.
    pub fn goals_sent(&self) -> usize {
        self.adapter.backend().sent.len()
    }

    /// Every speed limit the adapter has applied or cleared, ever.
    pub fn speed_limits(&self) -> &[Option<f64>] {
        &self.adapter.backend().speed_limits
    }

    /// Walks one proposal down the pipeline, stopping wherever Kern stops it.
    ///
    /// ```text
    /// action present?      -> no: nothing to evaluate
    /// registry.resolve     -> unknown capability stops here
    /// schema.normalize     -> a malformed operation stops here
    /// authority.decide     -> a denial stops here
    /// AuthorizedOperation  -> the only input issuance accepts
    /// mint_challenge       -> the first authority-shaped act in the whole walk
    /// issue_v2 -> install  -> LeaseHandle
    /// prepare -> submit    -> the adapter, at last
    /// ```
    pub fn walk(&mut self, proposal: Proposal) -> Walk {
        let (mut record, action) = proposal.into_parts();
        let mut walk = Walk {
            normalized: None,
            decision: None,
            detail: None,
            challenges_minted: 0,
            leases_issued: 0,
            installs: 0,
            execution: None,
            executor_invoked: false,
            record: record.clone(),
        };

        // Stage 0: the model produced nothing to evaluate. No normalization is
        // recorded, because none was attempted.
        let Some(action) = action else {
            walk.record = record;
            return walk;
        };

        // Stage 1: what does this operation mean? Trusted configuration alone
        // answers, so a capability the model invented stops here.
        let schema = match self
            .authority
            .registry()
            .resolve(&action.device, &action.capability)
        {
            Ok(schema) => schema.clone(),
            Err(error) => {
                let detail = error.to_string();
                record
                    .record_normalization(NormalizationOutcome::Rejected(detail.clone()))
                    .expect("first normalization record");
                walk.detail = Some(detail);
                walk.record = record;
                return walk;
            }
        };

        // Stage 2: is the request well-formed for that meaning?
        let normalized = match schema.normalize(&action) {
            Ok(normalized) => normalized,
            Err(error) => {
                let detail = error.to_string();
                record
                    .record_normalization(NormalizationOutcome::Rejected(detail.clone()))
                    .expect("first normalization record");
                walk.detail = Some(detail);
                walk.record = record;
                return walk;
            }
        };
        record
            .record_normalization(NormalizationOutcome::Normalized)
            .expect("first normalization record");
        walk.normalized = Some(normalized.clone());

        // Stage 3: may this subject request it, under what bounds?
        let evaluation = self.authority.decide(normalized);
        let decision = evaluation.decision().clone();
        record
            .record_policy(PolicyOutcome::from_decision(&decision))
            .expect("normalization was recorded");
        walk.decision = Some(decision.clone());

        // Stage 4: only an authorization becomes an AuthorizedOperation. A
        // denial stops the walk here, before anything authority-shaped exists.
        let Some(operation) = AuthorizedOperation::from_evaluation(evaluation) else {
            let detail = denial_detail(
                &decision,
                walk.normalized
                    .as_ref()
                    .map(NormalizedActionProposal::params),
            );
            walk.detail = Some(detail);
            walk.record = record;
            return walk;
        };

        // Stage 5: freshness. This is the first act in the whole walk that
        // touches the enforcer.
        let ticket = self
            .store
            .mint_challenge(&issuer_id(), &subject(), &device(), &capability())
            .expect("challenge minted");
        walk.challenges_minted += 1;

        // Stage 6: issuance. The TTL is host configuration; nothing the model
        // said is an input to it.
        let lease = self
            .issuer
            .issue_v2(&operation, Ttl::from_millis(LEASE_TTL_MS), &ticket)
            .expect("issued");
        walk.leases_issued += 1;

        // Stage 7: verification and installation, at the edge.
        let bytes = encode_v2(&lease).expect("encodes");
        let handle = self
            .store
            .install(&bytes)
            .expect("installs")
            .handle()
            .clone();
        walk.installs += 1;
        record
            .record_authority(*handle.artifact())
            .expect("policy authorized it");

        // Stage 8: governed execution.
        let operation_proposal = operation.proposal().clone();
        let receipt = self
            .governor
            .prepare(&self.store, &handle, &operation_proposal)
            .expect("current authority permits it")
            .submit(&self.store, &mut self.adapter);
        walk.executor_invoked = receipt.executor_invoked();
        walk.execution = Some(receipt.execution_id());
        record
            .record_execution(receipt.execution_id())
            .expect("authority was recorded");

        walk.record = record;
        walk
    }

    /// Renders the demo view for a completed walk.
    pub fn render(&self, walk: &Walk, action: Option<&kern_core::ActionProposal>) -> String {
        kern_ai::render_proposal(&walk.record, action, walk.detail.as_deref())
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// A readable reason for a refusal, taken from the decision itself.
///
/// Rendered from the evaluator's own output. Kern never rewrites the proposal
/// to fit; it says what would have been grantable and stops.
pub fn denial_detail(
    decision: &PolicyDecision,
    params: Option<&alloc_map::BTreeMap<ParamName, kern_core::ParamValue>>,
) -> String {
    match decision {
        PolicyDecision::Authorized { .. } => "authorized".to_string(),
        PolicyDecision::Denied => "no policy grants this operation".to_string(),
        PolicyDecision::NotAuthorizedAsProposed { .. } => {
            let feedback = match params {
                Some(params) => ConstraintFeedback::violations(decision, params),
                None => ConstraintFeedback::from_decision(decision),
            };
            if feedback.is_empty() {
                "outside the grantable bounds".to_string()
            } else {
                feedback.to_text().replace('\n', "; ")
            }
        }
    }
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

/// A deterministic challenge source, for tests and the offline demo only.
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
