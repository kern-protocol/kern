//! A complete deterministic pipeline: policy -> authorization -> V2 issuance ->
//! installation. Every input is fixed.
#![allow(dead_code)]

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
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, TrustStore};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

pub const DEV_SEED: [u8; 32] = [7u8; 32];
pub const SESSION_BYTES: [u8; 32] = [0x11u8; 32];
pub const OTHER_SESSION_BYTES: [u8; 32] = [0x22u8; 32];
pub const ISSUED_AT_MS: u64 = 1_700_000_000_000;
pub const CHALLENGE_TTL_MS: u64 = 2_000;
pub const LEASE_TTL_MS: u64 = 5_000;

pub type Issuer = LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>;
pub type Store = EnforcerStore<TestMonotonicClock, SequentialChallenges>;

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

pub fn speak_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        capability("speak"),
        [(param("volume"), ParamSpec::required(ParamDomain::Scalar))],
    )
    .expect("well-formed schema")
}

pub fn control_plane() -> Authority {
    let mut registry = CapabilityRegistry::new();
    registry
        .register(device(), navigate_schema())
        .expect("registered");
    registry
        .register(device(), speak_schema())
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
    let speak = Policy::new(
        PolicyId::new("announcements"),
        Selector::Exactly(subject()),
        Selector::Exactly(device()),
        Selector::Exactly(capability("speak")),
        ConstraintSet::from_constraints([(param("volume"), ParamConstraint::at_most(50))]),
    )
    .expect("constrained policy");

    Authority::new(
        registry,
        PolicySet::from_policies([navigate, speak]).expect("distinct ids"),
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

pub fn authorized_speak(volume: i64) -> AuthorizedOperation {
    let proposal = ActionProposal::new(subject(), device(), capability("speak"))
        .with_param(param("volume"), ParamValue::Scalar(volume));
    let evaluation = control_plane().evaluate(&proposal).expect("well-formed");
    AuthorizedOperation::from_evaluation(evaluation).expect("authorized")
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

pub fn store_with(clock: TestMonotonicClock, trust: TrustStore) -> Store {
    EnforcerStore::new(
        session(),
        trust,
        clock,
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    )
    .expect("valid configuration")
}

pub fn store() -> (Store, TestMonotonicClock) {
    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    (store_with(clock.clone(), trust_store()), clock)
}

/// Mints a challenge for the navigate slot.
pub fn navigate_ticket(store: &mut Store) -> ChallengeTicket {
    store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability("navigate"))
        .expect("minted")
}

/// Issues V2 lease bytes answering a ticket.
pub fn lease_bytes(
    issuer: &mut Issuer,
    op: &AuthorizedOperation,
    ticket: &ChallengeTicket,
) -> Vec<u8> {
    lease_bytes_with_ttl(issuer, op, ticket, LEASE_TTL_MS)
}

pub fn lease_bytes_with_ttl(
    issuer: &mut Issuer,
    op: &AuthorizedOperation,
    ticket: &ChallengeTicket,
    ttl_ms: u64,
) -> Vec<u8> {
    let lease = issuer
        .issue_v2(op, Ttl::from_millis(ttl_ms), ticket)
        .expect("issued");
    encode_v2(&lease).expect("encodes")
}

/// A deterministic challenge source, for tests only.
///
/// Deliberately not shipped by `kern-enforcer`: it violates the
/// [`ChallengeSource`] contract on purpose, and a documentation warning is not a
/// safety boundary for a security-critical primitive. Integration tests
/// implement the public trait themselves, which is exactly what a real
/// deployment does.
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

/// A source that always fails, for exercising the fail-closed path.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailingChallenges;

impl ChallengeSource for FailingChallenges {
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError> {
        Err(EntropyError)
    }
}
