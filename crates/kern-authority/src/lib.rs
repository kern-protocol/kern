//! Lease issuance: turning an authorized decision into signed authority.
//!
//! Issuer side only. There is no verifier here, no trust store, no replay cache,
//! and no enforcer. Those belong to the edge, and to a later phase.
//!
//! ```text
//! Evaluation (Authorized)      from kern-policy, non-forgeable
//!   -> AuthorizedOperation     the only input issuance accepts
//!   -> LeaseBody               constraints copied from the decision
//!   -> canonical V1 bytes      kern-core::wire
//!   -> signing input           domain || version || length || body
//!   -> SignedLease
//! ```
//!
//! The chain matters more than any single link: the constraints in a signed
//! lease originate from a Phase 2 authorization or the lease does not exist.
//! Nothing in this crate accepts caller-supplied constraints.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod issuer;
pub mod lease_id;
pub mod nonce;
pub mod operation;
pub mod signer;

pub use issuer::{IssueError, LeaseIssuer};
pub use lease_id::{LeaseIdError, LeaseIdSource, SequentialLeaseIds};
pub use nonce::{CountingNonces, NonceError, NonceSource, Slot};
pub use operation::AuthorizedOperation;
pub use signer::{Ed25519Signer, SignError, Signer};
