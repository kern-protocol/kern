//! Execution identity.

use core::fmt;

/// Identifies one governed attempt at a physical effect.
///
/// # Identity, never authority
///
/// Holding an `ExecutionId` permits nothing. It names a record so that a
/// physical effect can later be traced to the authority that permitted it.
///
/// # Why this is not a [`LeaseId`](kern_core::LeaseId)
///
/// One lease governs many executions, so a lease identifier cannot tell them
/// apart. Lease identifiers are minted by the issuer, while executions are
/// prepared at the edge — possibly while the issuer is unreachable — so minting
/// executions into the issuer's namespace would risk collisions across issuers.
/// An execution outlives the lease artifact and the slot that authorized it, so
/// a key that disappears when the slot is reclaimed is a poor provenance key.
/// And a `LeaseId` appears inside signed bodies: an identifier that is both the
/// authority and the thing running invites code that treats an execution handle
/// as a credential.
///
/// # Uniqueness domain
///
/// One enforcer session. The global provenance key is the pair
/// `(EnforcerSessionId, ExecutionId)`. A session identifier is drawn afresh at
/// every boot, so no persistent counter is needed to avoid cross-boot reuse.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionId(u128);

impl ExecutionId {
    /// Wraps a raw identifier.
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// The underlying value.
    pub const fn as_u128(&self) -> u128 {
        self.0
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecutionId({})", self.0)
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An execution identifier could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionIdError {
    /// The source has no identifiers left.
    Exhausted,
}

impl fmt::Display for ExecutionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => f.write_str("execution identifier space exhausted"),
        }
    }
}

impl core::error::Error for ExecutionIdError {}

/// Supplies execution identifiers.
///
/// # Reuse corrupts provenance
///
/// Repeating an identifier makes two physical attempts indistinguishable in
/// every record, journal entry, and later reconciliation. Exhaustion is
/// therefore explicit: a source that cannot produce a fresh identifier must fail
/// closed rather than wrap or saturate.
pub trait ExecutionIdSource {
    /// The next identifier, or an error when the source is exhausted.
    fn next_execution_id(&mut self) -> Result<ExecutionId, ExecutionIdError>;
}

/// A deterministic counter.
///
/// Emits every value from its starting point through `u128::MAX` exactly once,
/// then reports [`ExecutionIdError::Exhausted`] forever. It never wraps and
/// never saturates.
#[derive(Clone, Debug)]
pub struct SequentialExecutionIds {
    /// The next value to emit, or `None` once `u128::MAX` has been emitted.
    next: Option<u128>,
}

impl SequentialExecutionIds {
    /// A source starting at `start`.
    pub fn starting_at(start: u128) -> Self {
        Self { next: Some(start) }
    }

    /// A source starting at zero.
    pub fn new() -> Self {
        Self::starting_at(0)
    }
}

impl Default for SequentialExecutionIds {
    /// A source starting at zero.
    ///
    /// Written out rather than derived: a derived `Default` would leave `next`
    /// as `None`, which is the *exhausted* state.
    fn default() -> Self {
        Self::starting_at(0)
    }
}

impl ExecutionIdSource for SequentialExecutionIds {
    fn next_execution_id(&mut self) -> Result<ExecutionId, ExecutionIdError> {
        let current = self.next.ok_or(ExecutionIdError::Exhausted)?;
        // `None` once the last value has been handed out, so the next call fails
        // rather than returning to the start.
        self.next = current.checked_add(1);
        Ok(ExecutionId::from_u128(current))
    }
}
