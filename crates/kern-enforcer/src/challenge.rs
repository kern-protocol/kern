//! Challenge minting and lifecycle.

use kern_core::{
    CapabilityName, Challenge, DeviceId, EnforcerSessionId, IssuerId, SubjectId, Uptime,
};

use crate::error::EntropyError;

/// Supplies single-use challenge values.
///
/// The dependency-injection boundary for edge entropy. Callers supply the
/// implementation, and this crate deliberately ships none: a predictable
/// challenge is one an attacker can have answered in advance, which defeats the
/// mechanism entirely, so there is no default to fall into by accident.
///
/// # Contract
///
/// ```text
/// 32 bytes
/// cryptographically unpredictable
/// no deterministic generator
/// no timestamp, counter, nonce, or LeaseId fallback
/// entropy failure returns EntropyError
/// entropy failure NEVER degrades to weaker challenge generation
/// ```
///
/// The last line is the one that matters. An implementation that quietly
/// substitutes a counter when its entropy source is unavailable is worse than
/// one that fails, because the failure is invisible at exactly the moment the
/// guarantee stops holding.
///
/// Test implementations belong in test code, not here.
pub trait ChallengeSource {
    /// A fresh challenge.
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError>;
}

/// Whether a challenge may still establish freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeState {
    /// Never used. May still answer an installation.
    Outstanding,
    /// Spent on an installation. Never returns to outstanding.
    Consumed,
}

/// The enforcer's local record of one minted challenge.
///
/// Binds the complete authority slot, so a challenge establishes freshness for
/// exactly one slot: one minted for `robot_1 / navigate` can never establish
/// freshness for `robot_1 / open_tray`, for `robot_2 / navigate`, or for a lease
/// signed by a different issuer.
///
/// `issued_at` and `deadline` are local monotonic values. Neither is
/// transmitted, neither is signed, and the issuer neither owns nor can read that
/// clock.
#[derive(Clone, Debug)]
pub struct ChallengeRecord {
    pub(crate) issuer: IssuerId,
    pub(crate) session: EnforcerSessionId,
    pub(crate) challenge: Challenge,
    pub(crate) subject: SubjectId,
    pub(crate) device: DeviceId,
    pub(crate) capability: CapabilityName,
    pub(crate) issued_at: Uptime,
    pub(crate) deadline: Uptime,
    pub(crate) state: ChallengeState,
}

impl ChallengeRecord {
    /// The challenge value.
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// When this challenge was minted, in enforcer uptime.
    ///
    /// The anchor for the authority deadline of any lease it admits, so that
    /// delivery delay is charged against the lease's own lifetime.
    pub fn issued_at(&self) -> Uptime {
        self.issued_at
    }

    /// The local freshness bound.
    pub fn deadline(&self) -> Uptime {
        self.deadline
    }

    /// Whether it may still be answered.
    pub fn state(&self) -> ChallengeState {
        self.state
    }
}
