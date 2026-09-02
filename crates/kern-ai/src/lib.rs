//! The untrusted AI proposal plane.
//!
//! ```text
//! natural-language instruction
//!   -> PlanningRequest        bounded, built from the trusted registry
//!   -> ProposalModel          a provider adapter, a fixture, or an attacker
//!   -> RawModelResponse       attacker-controlled bytes
//! ============================ KERN TRUST BOUNDARY ============================
//!   -> strict local parser    crate::parse, fail-closed
//!   -> ActionProposal         intent, carrying no authority
//!   -> CapabilitySchema::normalize          kern-core
//!   -> Authority::decide                    kern-policy
//!   -> AuthorizedOperation                  kern-authority
//!   -> mint_challenge -> issue_v2 -> install -> LeaseHandle   kern-enforcer
//!   -> prepare -> submit                    kern-execution
//!   -> Nav2, ROS 2, a robot
//! ```
//!
//! # The claim
//!
//! Kern does not make a model trustworthy. It makes model trust *insufficient*
//! for physical authority.
//!
//! A model may propose intent, a capability, semantic parameters, and an
//! explanation. It may not mint a lease, sign anything, choose a TTL, an
//! issuer, a key, a nonce, a challenge, a session, or an identifier, modify
//! policy, install authority, construct an `AuthorizedOperation`, a
//! `SignedLease`, a `LeaseHandle`, or a `SemanticCommand`, bypass schema
//! normalization or policy evaluation, or reach an executor, Nav2, or ROS.
//!
//! Those are not rules this crate enforces at runtime. They are consequences of
//! the types: [`ProposalModel`] takes a [`PlanningRequest`] and returns bytes or
//! a failure, and every one of the forbidden things is reachable only through a
//! constructor that lives in another crate and consumes something a model cannot
//! produce.
//!
//! # What this crate deliberately does not do
//!
//! It does not detect prompt injection, and it does not try to. Kern does not
//! need to determine whether a model is compromised before enforcing authority
//! boundaries on what that model proposes. A hostile instruction may well
//! convince a model to propose something outrageous; the containment argument
//! begins after that, and it does not depend on having noticed.
//!
//! So: Kern does not prevent prompt injection. Kern contains the physical
//! authority consequences of unauthorized model proposals.
//!
//! # What this crate does not contain
//!
//! No HTTP, no TLS, no JSON serializer, no async runtime, no provider SDK, no
//! credentials, and no knowledge of any particular provider. A provider lives
//! behind [`ProposalModel`], in a crate outside the workspace, for the same
//! reason the ROS bridge does.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bounds;
#[cfg(feature = "fake-models")]
pub mod fake;
pub mod json;
pub mod model;
pub mod observation;
pub mod parse;
pub mod plane;
pub mod prompt;
pub mod proposal;
pub mod provenance;
pub mod request;
pub mod view;

pub use json::{Json, JsonError, Number};
pub use model::{
    ModelIdentity, ModelOutcome, ProposalModel, ProviderFailure, RawModelResponse, ResponseDigest,
    ResponseTooLarge,
};
pub use observation::{
    observation_age_ms, resolve as resolve_observation, Admission, ConversionError,
    ObservationSnapshot, ObservationUnavailable, PoseKnowledge, PoseLedger, PoseObservation,
    SourceAgeError, SourceClock, SourceTime, WorldObservation,
};
pub use parse::{
    parse_response, ParseError, ParsedModelProposal, ProposedArgument, ProposedValue, NO_ACTION,
};
pub use plane::{Proposal, ProposalPlane, ReplanBudget, ReplanError};
pub use prompt::{response_schema, system_prompt, user_prompt};
pub use proposal::{to_action_proposal, DeviceRouter, ProposalError};
pub use provenance::{
    InstructionDigest, ModelInvocationId, NormalizationOutcome, PolicyOutcome, ProposalId,
    ProposalIdSource, ProposalOutcome, ProposalRecord, ProvenanceError, SequentialProposalIds,
};
pub use request::{
    CapabilityDescription, CapabilityVocabulary, ConstraintFeedback, Instruction, ParamDescription,
    PlanningRequest, RequestError, RobotContext,
};
pub use view::render_proposal;
