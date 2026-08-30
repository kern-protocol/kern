//! Edge verification and installation.
//!
//! ```text
//! transmitted bytes
//!   -> framing, version check            no trust
//!   -> canonical decode                  no trust; cheap rejection before crypto
//!   -> issuer / key_id as lookup hints   no trust
//!   -> signature over the RAW bytes      the trust boundary
//!   -> VerifiedLease
//!   -> session, freshness, lifetime, supersession
//!   -> InstalledLease, owned by the store
//! ```
//!
//! Parsing before verification is allowed. Trusting before verification is not.
//!
//! One expensive verification per lease; the hot path performs comparisons only.
//!
//! Excluded here by design: networking, wall-clock synchronization, renewal,
//! revocation, persistent state of any kind, executor adapters, and anything
//! resembling physical safety. Correct authority is not safe motion.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod challenge;
pub mod error;
pub mod store;
pub mod trust;
pub mod verify;

pub use challenge::{ChallengeRecord, ChallengeSource, ChallengeState};
pub use error::{
    AuthorityStatusError, ConfigError, EnforcementError, EntropyError, InstallError, MintError,
};
pub use store::{EnforcerStore, Installed, InstalledLease, LeaseHandle, SlotKey};
pub use trust::{AuthorizeError, TrustError, TrustStore};
pub use verify::{verify_bytes, verify_parsed, VerifiedLease};
