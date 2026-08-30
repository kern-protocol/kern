//! Capability resolution and authority evaluation.
//!
//! `kern-core` supplies the vocabulary and the algebra and decides nothing.
//! This crate decides: it resolves what a requested operation means, works out
//! which policies apply to it, composes their authority, and returns a
//! [`PolicyDecision`](kern_core::PolicyDecision).
//!
//! ```text
//! ActionProposal
//!   -> CapabilityRegistry     what does this operation mean
//!   -> CapabilitySchema       is the request well-formed
//!   -> NormalizedActionProposal
//!   -> applicable policies    who may request it
//!   -> ConstraintSet::meet    under what bounds
//!   -> PolicyDecision
//! ```
//!
//! Two failure kinds, deliberately not merged. A [`EvaluationError`] says the
//! request does not describe a real operation. A `PolicyDecision::Denied` says
//! it describes a real operation this subject may not perform.
//!
//! Everything here is synchronous, in-memory, and deterministic. No I/O, no
//! clocks, no async, no configuration parsing.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod evaluator;
pub mod policy;
pub mod registry;

pub use evaluator::{Authority, Evaluation, EvaluationError};
pub use policy::{Policy, PolicyError, PolicyId, PolicySet, PolicySetError, Selector};
pub use registry::{CapabilityRegistry, RegistryError};
