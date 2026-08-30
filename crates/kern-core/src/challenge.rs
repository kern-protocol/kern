//! Per-request issuance challenges.
//!
//! A challenge is how an enforcer establishes that a lease was issued *now*,
//! for *this* authority slot, without any trusted wall clock. The enforcer mints
//! one, the issuer signs it into the lease body, and installation requires it to
//! match an outstanding local record.
//!
//! # What a challenge does and does not prove
//!
//! It prevents installation outside the lifetime of the specific outstanding
//! issuance challenge, without requiring synchronized wall clocks.
//!
//! It does not prevent delay in the abstract. An outstanding challenge with no
//! deadline could be answered arbitrarily late, so the bound comes from the
//! enforcer's local challenge lifetime — see the enforcer's challenge record.
//! No claim about freshness should exceed that sentence.

use core::fmt;

use crate::ids::{CapabilityName, DeviceId, SubjectId};
use crate::lease::{EnforcerSessionId, IssuerId};

/// A single-use random value minted by an enforcer for one issuance request.
///
/// Must come from a CSPRNG. Timestamps, counters, lease identifiers, nonces,
/// device identifiers, and deterministic PRNG output are all unacceptable in
/// production: a predictable challenge is one an attacker can have answered in
/// advance.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Challenge([u8; 32]);

impl Challenge {
    /// Wraps 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A live challenge is a freshness secret until it is answered.
        f.write_str("Challenge(..)")
    }
}

/// What an enforcer hands to an issuer to have a lease minted.
///
/// Every field is copied into the signed lease body, so a challenge establishes
/// freshness for **exactly one authority slot**. A challenge for
/// `robot_1 / navigate` can never establish freshness for `robot_1 / open_tray`
/// or for `robot_2 / navigate`.
///
/// The enforcer's local challenge deadline is deliberately absent: it is a local
/// acceptance bound measured on a monotonic clock the issuer neither owns nor
/// can read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeTicket {
    /// The issuer expected to answer. Lets a misrouted ticket be rejected
    /// before a lease is ever produced.
    pub issuer: IssuerId,
    /// The enforcer boot session this request belongs to.
    pub session: EnforcerSessionId,
    /// The single-use value to sign.
    pub challenge: Challenge,
    /// The subject authority is being requested for.
    pub subject: SubjectId,
    /// The device authority is being requested for.
    pub device: DeviceId,
    /// The capability authority is being requested for.
    pub capability: CapabilityName,
}
