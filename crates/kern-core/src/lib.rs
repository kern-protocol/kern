//! Kern core domain vocabulary and authority algebra.
//!
//! This crate establishes the words the rest of the system reasons in, the
//! partial order those words induce on authority, and the schema validation
//! that turns a typed proposal into one authority evaluation will accept. It
//! contains no cryptography, no protocol encoding, no lease type, no
//! networking, and no executor integration.
//!
//! # The validation boundary
//!
//! ```text
//! raw request            outside this crate entirely
//!   -> ActionProposal            typed, NOT yet schema-checked
//!   -> NormalizedActionProposal  schema-checked, defaults applied
//!   -> authority evaluation
//! ```
//!
//! [`ConstraintSet::evaluate`] accepts only the normalized form, so no caller
//! can decide authority on a proposal that has not passed
//! [`CapabilitySchema::normalize`].
//!
//! # The authority ordering
//!
//! A [`ConstraintSet`] denotes the set of operations it permits.
//!
//! ```text
//! A <= B   iff   every operation permitted by A is also permitted by B
//! ```
//!
//! Read `A <= B` as "A grants no more authority than B".
//!
//! [`ConstraintSet::permits`] is the operational definition of that permitted
//! set. The [`PartialOrd`] implementation is the structural decision procedure
//! for the same relation, and [`ConstraintSet::meet`] is the greatest lower
//! bound under it. The three are required to agree; the property tests assert
//! that they do.
//!
//! The order is bounded:
//!
//! ```text
//! TOP    = ConstraintSet::unconstrained()   identity for meet
//! BOTTOM = ConstraintSet::no_authority()    absorbing element for meet
//! ```
//!
//! Composing policies can only preserve or reduce authority. That is the point
//! of the whole structure, and it is why `meet` never has a widening case.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod artifact;
pub mod challenge;
pub mod clock;
pub mod constraint;
pub mod constraint_set;
pub mod decision;
pub mod ids;
pub mod lease;
pub mod proposal;
pub mod schema;
pub mod wire;

pub use artifact::AuthorityArtifactId;
pub use challenge::{Challenge, ChallengeTicket};
pub use clock::{
    Clock, MonotonicClock, MonotonicDuration, TestClock, TestMonotonicClock, Timestamp, Ttl,
    TtlError, Uptime,
};
pub use constraint::{Interval, ParamConstraint, SymbolSet};
pub use constraint_set::ConstraintSet;
pub use decision::PolicyDecision;
pub use ids::{CapabilityName, DeviceId, InvalidId, ParamName, SubjectId, Symbol};
pub use lease::{
    EnforcerSessionId, IssuerId, KeyId, LeaseBody, LeaseBodyV2, LeaseId, Nonce, ProtocolVersion,
    Signature, SignedLease, SignedLeaseV2,
};
pub use proposal::{ActionProposal, ParamValue};
pub use schema::{
    CapabilitySchema, NormalizedActionProposal, ParamDomain, ParamSpec, Requirement,
    SchemaDefinitionError, SchemaError,
};
pub use wire::{DecodeError, EncodeError};

#[cfg(feature = "std")]
pub use clock::SystemClock;
