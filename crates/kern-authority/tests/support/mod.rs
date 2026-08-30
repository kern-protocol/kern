//! Shared fixture for the issuance tests. Deterministic in every input.
#![allow(dead_code)]

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, ConstraintSet, DeviceId, EnforcerSessionId,
    IssuerId, KeyId, ParamConstraint, ParamDomain, ParamName, ParamSpec, ParamValue, SubjectId,
    Symbol, SymbolSet, TestClock, Timestamp,
};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

pub const DEV_SEED: [u8; 32] = [7u8; 32];
pub const SESSION_BYTES: [u8; 32] = [0x11u8; 32];
pub const ISSUED_AT_MS: u64 = 1_700_000_000_000;
pub const FIRST_LEASE_ID: u128 = 0xAB;

pub fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

pub fn capability(name: &str) -> CapabilityName {
    CapabilityName::new(name).expect("valid capability name")
}

pub fn session() -> EnforcerSessionId {
    EnforcerSessionId::from_bytes(SESSION_BYTES)
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

pub fn authority() -> Authority {
    let mut registry = CapabilityRegistry::new();
    registry
        .register(DeviceId::new("cafe_bot_01"), navigate_schema())
        .expect("first registration");

    let allowed = SymbolSet::allowed([Symbol::new("cafe"), Symbol::new("lobby")])
        .expect("non-empty allow-list");
    let policy = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(SubjectId::new("planner_a")),
        Selector::Exactly(DeviceId::new("cafe_bot_01")),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([
            (param("max_speed"), ParamConstraint::at_most(500)),
            (param("destination"), ParamConstraint::Symbolic(allowed)),
        ]),
    )
    .expect("constrained policy");

    Authority::new(
        registry,
        PolicySet::from_policies([policy]).expect("distinct ids"),
    )
}

pub fn proposal(actor: &str, speed: i64, destination: &str) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(actor),
        DeviceId::new("cafe_bot_01"),
        capability("navigate"),
    )
    .with_param(
        param("destination"),
        ParamValue::Symbol(Symbol::new(destination)),
    )
    .with_param(param("max_speed"), ParamValue::Scalar(speed))
}

/// The canonical authorized operation used by the golden vectors.
pub fn authorized_operation() -> AuthorizedOperation {
    let evaluation = authority()
        .evaluate(&proposal("planner_a", 400, "cafe"))
        .expect("well-formed request");
    AuthorizedOperation::from_evaluation(evaluation).expect("policy authorized it")
}

pub type Issuer = LeaseIssuer<Ed25519Signer, TestClock, CountingNonces, SequentialLeaseIds>;

pub fn issuer() -> Issuer {
    LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(FIRST_LEASE_ID),
    )
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}
