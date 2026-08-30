//! Lease identity.

use core::fmt;

use kern_core::LeaseId;

/// A lease identifier could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseIdError {
    /// The source has no identifiers left.
    Exhausted,
}

impl fmt::Display for LeaseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => f.write_str("lease identifier space exhausted"),
        }
    }
}

impl core::error::Error for LeaseIdError {}

/// Supplies lease identifiers.
///
/// # Uniqueness is the source's responsibility
///
/// A [`LeaseId`] value proves nothing about global uniqueness on its own, and
/// nothing downstream treats it as a security property. It is identity and
/// provenance; replay protection is [`kern_core::Nonce`]'s job.
///
/// That is not a licence to repeat one. A source that reissues an identifier
/// corrupts provenance, audit correlation, tracing, and any future reference to
/// a lease, even while signature security is untouched. Exhaustion is therefore
/// explicit rather than silent: a source that cannot produce a fresh identifier
/// must fail closed rather than wrap or saturate.
pub trait LeaseIdSource {
    /// The next identifier, or an error when the source is exhausted.
    fn next_lease_id(&mut self) -> Result<LeaseId, LeaseIdError>;
}

/// A deterministic counter, big-endian in the low bytes.
///
/// For tests and golden vectors. A deployment wants something with a real
/// uniqueness argument behind it.
///
/// Emits every value from its starting point through `u128::MAX` exactly once,
/// then reports [`LeaseIdError::Exhausted`] forever. It never wraps and never
/// saturates, so it cannot quietly repeat an identifier it has already issued.
#[derive(Clone, Debug)]
pub struct SequentialLeaseIds {
    /// The next value to emit, or `None` once `u128::MAX` has been emitted.
    next: Option<u128>,
}

impl SequentialLeaseIds {
    /// A source starting at `start`.
    pub fn starting_at(start: u128) -> Self {
        Self { next: Some(start) }
    }

    /// A source starting at zero.
    pub fn new() -> Self {
        Self::starting_at(0)
    }
}

impl Default for SequentialLeaseIds {
    /// A source starting at zero.
    ///
    /// Written out rather than derived: a derived `Default` would leave `next`
    /// as `None`, which is the *exhausted* state, so the default source would
    /// refuse to issue anything.
    fn default() -> Self {
        Self::starting_at(0)
    }
}

impl LeaseIdSource for SequentialLeaseIds {
    fn next_lease_id(&mut self) -> Result<LeaseId, LeaseIdError> {
        let current = self.next.ok_or(LeaseIdError::Exhausted)?;
        // `None` once the last value has been handed out, so the next call
        // fails rather than returning to the start.
        self.next = current.checked_add(1);
        Ok(LeaseId::from_bytes(current.to_be_bytes()))
    }
}
